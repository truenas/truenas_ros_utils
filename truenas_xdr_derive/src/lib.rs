// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Derive macros for the `truenas_xdr` codec.
//!
//! RFC 4506 encodes an enum or a union's discriminant as the value written in
//! the specification, which need not be the variant's position. A stock
//! `#[derive(Serialize)]` encodes the declaration index, so a type with
//! discriminant gaps would go out wrong. These macros read the declared
//! `#[repr]` discriminants instead.
//!
//! - [`XdrEnum`] — a field-less enum, encoded as one `i32`.
//! - [`XdrUnion`] — a discriminated union, encoded as an `i32` discriminant
//!   followed by the active arm's fields. A void arm emits only the
//!   discriminant.
//!
//! Discriminants must be integer literals, explicit (`= 4`) or implicit
//! (`prev + 1`); a const-expression discriminant or a generic type is a
//! compile error.
//!
//! A union may borrow from the input. [`XdrUnion`] accepts lifetime
//! parameters, so an arm can hold a `&'a str` or a `VarOpaqueRef<'a>`. Type
//! and const parameters are still refused.
//!
//! A union may declare the default arm of RFC 4506 §4.15 by marking its last
//! variant `#[xdr(default)]`. That variant's first field holds the
//! discriminant, which is an `i32` or an [`XdrEnum`] type, and any further
//! fields are the arm's body. A value decoded through the default arm encodes
//! back to the same bytes. Encoding fails when the discriminant has an arm of
//! its own, because those bytes would decode as that other arm.
#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Data, DataEnum, DeriveInput, Expr, ExprLit, ExprUnary, Fields,
    GenericParam, Ident, Lifetime, LifetimeParam, Lit, UnOp, Variant,
    parse_macro_input,
};

/// Derive `Serialize`/`Deserialize` for a field-less enum, encoding it as its
/// declared `i32` discriminant.
#[proc_macro_derive(XdrEnum)]
pub fn derive_xdr_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_enum(input).unwrap_or_else(|e| e.to_compile_error().into())
}

/// Derive `Serialize`/`Deserialize` for a discriminated union, encoding it as
/// an `i32` discriminant followed by the active arm.
///
/// The last variant may be marked `#[xdr(default)]` to declare the default
/// arm. Its first field holds the discriminant and any further fields are the
/// arm's body.
#[proc_macro_derive(XdrUnion, attributes(xdr))]
pub fn derive_xdr_union(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_union(input).unwrap_or_else(|e| e.to_compile_error().into())
}

/// Parse a discriminant expression (`N` or `-N`) as an `i32`.
fn parse_disc(expr: &Expr) -> syn::Result<i32> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(li), ..
        }) => li.base10_parse::<i32>(),
        Expr::Unary(ExprUnary {
            op: UnOp::Neg(_),
            expr,
            ..
        }) => match &**expr {
            Expr::Lit(ExprLit {
                lit: Lit::Int(li), ..
            }) => Ok(-(li.base10_parse::<i32>()?)),
            other => Err(syn::Error::new_spanned(
                other,
                "expected an integer literal discriminant",
            )),
        },
        other => Err(syn::Error::new_spanned(
            other,
            "XdrEnum/XdrUnion needs an integer-literal discriminant, e.g. `= 4`",
        )),
    }
}

/// Every variant's `i32` discriminant: the explicit literal, else `prev + 1`.
fn discriminants(data: &DataEnum) -> syn::Result<Vec<i32>> {
    let mut next: i32 = 0;
    let mut out = Vec::with_capacity(data.variants.len());
    for v in &data.variants {
        let value = match &v.discriminant {
            Some((_, expr)) => parse_disc(expr)?,
            None => next,
        };
        out.push(value);
        next = value.checked_add(1).ok_or_else(|| {
            syn::Error::new_spanned(v, "discriminant overflows i32")
        })?;
    }
    Ok(out)
}

/// The wire layout is fixed per concrete type, so generics are rejected.
fn reject_generics(input: &DeriveInput) -> syn::Result<()> {
    if input.generics.params.is_empty() {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            &input.generics,
            "XdrEnum/XdrUnion does not support generic types",
        ))
    }
}

/// The lifetimes a union borrows for. A union may borrow from the input, so
/// lifetime parameters pass. The wire layout is fixed per concrete type, so
/// type and const parameters are refused. `'de` is refused because the
/// generated impl gives that name to the input.
fn union_lifetimes(input: &DeriveInput) -> syn::Result<Vec<Lifetime>> {
    let mut out = Vec::new();
    for param in &input.generics.params {
        match param {
            GenericParam::Lifetime(l) if l.lifetime.ident == "de" => {
                return Err(syn::Error::new_spanned(
                    l,
                    "XdrUnion names the input `'de`, rename this lifetime",
                ));
            }
            GenericParam::Lifetime(l) => out.push(l.lifetime.clone()),
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "XdrUnion supports lifetime parameters only",
                ));
            }
        }
    }
    Ok(out)
}

/// Whether a variant is marked `#[xdr(default)]`. Any other `xdr` argument is
/// refused, so a misspelling cannot pass as an ordinary arm.
fn is_default_arm(v: &Variant) -> syn::Result<bool> {
    let mut found = false;
    for attr in v.attrs.iter().filter(|a| a.path().is_ident("xdr")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("default") {
                found = true;
                Ok(())
            } else {
                Err(meta.error("unknown xdr argument, expected `default`"))
            }
        })?;
    }
    Ok(found)
}

/// Whether the union ends in a default arm. XDR writes the default arm last,
/// and an earlier one would shift the implicit discriminants of the arms
/// after it, so any other position is refused. The arm takes its discriminant
/// from the wire, so it needs a field to hold one and cannot declare its own.
fn has_default_arm(data: &DataEnum) -> syn::Result<bool> {
    let mut found = false;
    for (i, v) in data.variants.iter().enumerate() {
        if !is_default_arm(v)? {
            continue;
        }
        let refusal = if i + 1 != data.variants.len() {
            "the default arm must be the last variant"
        } else if v.discriminant.is_some() {
            "the default arm takes its discriminant from its first field \
             and cannot declare one"
        } else if v.fields.is_empty() {
            "the default arm needs a first field to hold the discriminant"
        } else {
            found = true;
            continue;
        };
        return Err(syn::Error::new_spanned(v, refusal));
    }
    Ok(found)
}

/// The encode arm and the decode arm for a union's default arm, with the
/// number of elements the arm reads. `owned` lists the discriminants that
/// have an arm of their own.
fn default_arm(
    name: &Ident,
    v: &Variant,
    owned: &[i32],
) -> (TokenStream2, TokenStream2, usize) {
    let ident = &v.ident;
    let n = v.fields.len();
    let binds: Vec<_> = (0..n).map(|i| format_ident!("__f{}", i)).collect();
    let (first, rest) = (&binds[0], &binds[1..]);
    // The same tokens bind the fields when encoding and build the value when
    // decoding.
    let shape = match &v.fields {
        Fields::Named(fields) => {
            let fnames = fields.named.iter().map(|f| &f.ident);
            quote! { #name::#ident { #( #fnames: #binds ),* } }
        }
        _ => quote! { #name::#ident( #(#binds),* ) },
    };
    let ser = quote! {
        #shape => {
            let __disc: i32 = ::truenas_xdr::__private::discriminant(#first)
                .map_err(<S::Error as ::serde::ser::Error>::custom)?;
            const __OWNED: &[i32] = &[ #(#owned),* ];
            if __OWNED.contains(&__disc) {
                return ::core::result::Result::Err(
                    <S::Error as ::serde::ser::Error>::custom(
                        ::std::format!(
                            "{} discriminant {} has an arm of its own",
                            ::core::stringify!(#name),
                            __disc,
                        ),
                    ),
                );
            }
            let mut tup = serializer.serialize_tuple(#n)?;
            ::serde::ser::SerializeTuple::serialize_element(
                &mut tup, &__disc,
            )?;
            #(
                ::serde::ser::SerializeTuple::serialize_element(
                    &mut tup, #rest,
                )?;
            )*
            ::serde::ser::SerializeTuple::end(tup)
        }
    };
    let de = quote! {
        other => {
            let #first = ::serde::Deserialize::deserialize(
                <i32 as ::serde::de::IntoDeserializer<'de, A::Error>>
                    ::into_deserializer(other),
            )?;
            #(
                let #rest =
                    ::serde::de::SeqAccess::next_element(&mut seq)?
                        .ok_or_else(|| {
                            <A::Error as ::serde::de::Error>::custom(
                                "missing XDR union field",
                            )
                        })?;
            )*
            ::core::result::Result::Ok(#shape)
        }
    };
    (ser, de, n)
}

fn enum_data<'a>(
    input: &'a DeriveInput,
    macro_name: &str,
) -> syn::Result<&'a DataEnum> {
    match &input.data {
        Data::Enum(d) => Ok(d),
        _ => Err(syn::Error::new_spanned(
            input,
            format!("{macro_name} can only be derived for enums"),
        )),
    }
}

fn expand_enum(input: DeriveInput) -> syn::Result<TokenStream> {
    reject_generics(&input)?;
    let name = &input.ident;
    let data = enum_data(&input, "XdrEnum")?;
    for v in &data.variants {
        if !matches!(v.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                v,
                "XdrEnum requires field-less variants; use XdrUnion for \
                 data-bearing ones",
            ));
        }
    }
    let discs = discriminants(data)?;
    let idents: Vec<_> = data.variants.iter().map(|v| &v.ident).collect();

    Ok(quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                let disc: i32 = match self {
                    #( #name::#idents => #discs, )*
                };
                serializer.serialize_i32(disc)
            }
        }
        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let disc =
                    <i32 as ::serde::Deserialize>::deserialize(deserializer)?;
                match disc {
                    #( #discs => ::core::result::Result::Ok(#name::#idents), )*
                    other => ::core::result::Result::Err(
                        <D::Error as ::serde::de::Error>::custom(
                            ::std::format!(
                                "unknown {} discriminant {}",
                                ::core::stringify!(#name),
                                other,
                            ),
                        ),
                    ),
                }
            }
        }
    }
    .into())
}

fn expand_union(input: DeriveInput) -> syn::Result<TokenStream> {
    let lifetimes = union_lifetimes(&input)?;
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    // `'de` outlives every lifetime the union borrows for, so a borrowed arm
    // can point into the input.
    let mut de_generics = input.generics.clone();
    let mut de = LifetimeParam::new(Lifetime::new("'de", Span::call_site()));
    de.bounds.extend(lifetimes.iter().cloned());
    de_generics.params.insert(0, GenericParam::Lifetime(de));
    let (de_impl_generics, _, _) = de_generics.split_for_impl();
    let name = &input.ident;
    let data = enum_data(&input, "XdrUnion")?;
    let discs = discriminants(data)?;
    let explicit = data.variants.len() - usize::from(has_default_arm(data)?);

    let mut ser_arms = Vec::new();
    let mut de_arms = Vec::new();
    // The deserializer is told the widest arm's element count; the visitor
    // reads only what the decoded discriminant calls for.
    let mut max_elems = 1usize;
    // What a discriminant with no arm of its own decodes to.
    let mut fallback = quote! {
        other => ::core::result::Result::Err(
            <A::Error as ::serde::de::Error>::custom(
                ::std::format!(
                    "unknown {} discriminant {}",
                    ::core::stringify!(#name),
                    other,
                ),
            ),
        ),
    };

    for (i, (v, &disc)) in data.variants.iter().zip(&discs).enumerate() {
        let ident = &v.ident;
        if i == explicit {
            let (ser, de, elems) = default_arm(name, v, &discs[..explicit]);
            ser_arms.push(ser);
            fallback = de;
            max_elems = max_elems.max(elems);
            continue;
        }
        match &v.fields {
            Fields::Unit => {
                ser_arms.push(quote! {
                    #name::#ident => {
                        let mut tup = serializer.serialize_tuple(1)?;
                        ::serde::ser::SerializeTuple::serialize_element(
                            &mut tup, &(#disc as i32),
                        )?;
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(
                    quote! { #disc => ::core::result::Result::Ok(#name::#ident), },
                );
            }
            Fields::Unnamed(fields) => {
                let n = fields.unnamed.len();
                max_elems = max_elems.max(1 + n);
                let binds: Vec<_> =
                    (0..n).map(|i| format_ident!("__f{}", i)).collect();
                ser_arms.push(quote! {
                    #name::#ident( #(#binds),* ) => {
                        let mut tup = serializer.serialize_tuple(1 + #n)?;
                        ::serde::ser::SerializeTuple::serialize_element(
                            &mut tup, &(#disc as i32),
                        )?;
                        #(
                            ::serde::ser::SerializeTuple::serialize_element(
                                &mut tup, #binds,
                            )?;
                        )*
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(quote! {
                    #disc => {
                        #(
                            let #binds =
                                ::serde::de::SeqAccess::next_element(&mut seq)?
                                    .ok_or_else(|| {
                                        <A::Error as ::serde::de::Error>::custom(
                                            "missing XDR union field",
                                        )
                                    })?;
                        )*
                        ::core::result::Result::Ok(#name::#ident( #(#binds),* ))
                    }
                });
            }
            Fields::Named(fields) => {
                let n = fields.named.len();
                max_elems = max_elems.max(1 + n);
                let fnames: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                let binds: Vec<_> =
                    (0..n).map(|i| format_ident!("__f{}", i)).collect();
                ser_arms.push(quote! {
                    #name::#ident { #( #fnames: #binds ),* } => {
                        let mut tup = serializer.serialize_tuple(1 + #n)?;
                        ::serde::ser::SerializeTuple::serialize_element(
                            &mut tup, &(#disc as i32),
                        )?;
                        #(
                            ::serde::ser::SerializeTuple::serialize_element(
                                &mut tup, #binds,
                            )?;
                        )*
                        ::serde::ser::SerializeTuple::end(tup)
                    }
                });
                de_arms.push(quote! {
                    #disc => {
                        #(
                            let #binds =
                                ::serde::de::SeqAccess::next_element(&mut seq)?
                                    .ok_or_else(|| {
                                        <A::Error as ::serde::de::Error>::custom(
                                            "missing XDR union field",
                                        )
                                    })?;
                        )*
                        ::core::result::Result::Ok(
                            #name::#ident { #( #fnames: #binds ),* }
                        )
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ::serde::Serialize
            for #name #ty_generics #where_clause
        {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                match self { #( #ser_arms )* }
            }
        }
        impl #de_impl_generics ::serde::Deserialize<'de>
            for #name #ty_generics #where_clause
        {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                struct __Visitor #impl_generics (
                    ::core::marker::PhantomData<( #( &#lifetimes (), )* )>,
                ) #where_clause;
                impl #de_impl_generics ::serde::de::Visitor<'de>
                    for __Visitor #ty_generics #where_clause
                {
                    type Value = #name #ty_generics;
                    fn expecting(
                        &self,
                        f: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        f.write_str(::core::concat!(
                            "XDR union ",
                            ::core::stringify!(#name),
                        ))
                    }
                    fn visit_seq<A: ::serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> ::core::result::Result<
                        #name #ty_generics,
                        A::Error,
                    > {
                        let tag: i32 =
                            ::serde::de::SeqAccess::next_element(&mut seq)?
                                .ok_or_else(|| {
                                    <A::Error as ::serde::de::Error>::custom(
                                        "missing XDR union discriminant",
                                    )
                                })?;
                        match tag {
                            #( #de_arms )*
                            #fallback
                        }
                    }
                }
                ::serde::Deserializer::deserialize_tuple(
                    deserializer,
                    #max_elems,
                    __Visitor(::core::marker::PhantomData),
                )
            }
        }
    }
    .into())
}

#[cfg(test)]
mod tests {
    //! The parsing and validation helpers work on `syn` types and never touch
    //! the `proc_macro` bridge, so they run outside the compiler. The
    //! token-building paths do not: `TokenStream::from` panics anywhere but in
    //! a macro expansion, which is why only the refusals — each of which
    //! returns before a token is built — are driven here. `truenas_xdr`'s
    //! `tests/derive.rs` covers what the macros expand to.
    use super::*;

    fn expr(src: &str) -> Expr {
        syn::parse_str::<Expr>(src).unwrap()
    }

    fn input(src: &str) -> DeriveInput {
        syn::parse_str::<DeriveInput>(src).unwrap()
    }

    fn data_enum(src: &str) -> DataEnum {
        match input(src).data {
            Data::Enum(d) => d,
            _ => panic!("not an enum"),
        }
    }

    #[test]
    fn a_discriminant_is_the_literal_written() {
        assert_eq!(parse_disc(&expr("5")).unwrap(), 5);
        assert_eq!(parse_disc(&expr("-3")).unwrap(), -3);
    }

    /// The macro cannot evaluate a const expression, so accepting one would
    /// encode a discriminant that is not the one written.
    #[test]
    fn a_non_literal_discriminant_is_refused() {
        assert!(parse_disc(&expr("SOME_CONST")).is_err());
        assert!(parse_disc(&expr("1 + 1")).is_err());
        assert!(parse_disc(&expr("-SOME_CONST")).is_err());
    }

    /// An implicit value is the previous plus one, and an explicit one may go
    /// backwards.
    #[test]
    fn discriminants_fill_in_and_refuse_overflow() {
        let d = data_enum("enum E { A = 4, B, C = -1 }");
        assert_eq!(discriminants(&d).unwrap(), vec![4, 5, -1]);
        // i32::MAX leaves no room for the next, which must be refused rather
        // than wrapped to i32::MIN.
        let over = data_enum("enum E { A = 2147483647, B }");
        assert!(discriminants(&over).is_err());
    }

    /// The layout is fixed per concrete type, so a parameter it could vary
    /// over has no encoding.
    #[test]
    fn a_generic_type_is_refused() {
        assert!(reject_generics(&input("enum E { A }")).is_ok());
        assert!(reject_generics(&input("enum E<T> { A }")).is_err());
        assert!(reject_generics(&input("struct S<'a> { x: &'a u8 }")).is_err());
    }

    /// This catches a type or const parameter being accepted, which has no
    /// fixed layout, and a `'de` that would collide with the generated impl.
    #[test]
    fn a_union_takes_lifetimes_and_no_other_parameter() {
        let two =
            union_lifetimes(&input("enum E<'a, 'b> { A(&'a str, &'b str) }"));
        assert_eq!(two.unwrap().len(), 2);
        assert!(union_lifetimes(&input("enum E { A }")).unwrap().is_empty());
        assert!(union_lifetimes(&input("enum E<T> { A(T) }")).is_err());
        assert!(
            union_lifetimes(&input("enum E<const N: usize> { A }")).is_err()
        );
        assert!(
            union_lifetimes(&input("enum E<'de> { A(&'de str) }")).is_err()
        );
    }

    fn union_refusal(src: &str) -> String {
        expand_union(input(src)).err().unwrap().to_string()
    }

    /// Each of these would otherwise compile into a union whose default arm
    /// sits where XDR does not put it, or cannot hold what it matched.
    #[test]
    fn a_misplaced_or_malformed_default_arm_is_refused() {
        let early = "enum E { #[xdr(default)] Other(i32), A = 1 }";
        assert!(union_refusal(early).contains("last variant"));
        let twice = "enum E { A = 1, #[xdr(default)] X(i32), \
                     #[xdr(default)] Y(i32) }";
        assert!(union_refusal(twice).contains("last variant"));
        let empty = "enum E { A = 1, #[xdr(default)] Other }";
        assert!(union_refusal(empty).contains("needs a first field"));
        let numbered = "enum E { A = 1, #[xdr(default)] Other(i32) = 9 }";
        assert!(union_refusal(numbered).contains("cannot declare one"));
    }

    /// A misspelled argument must not turn the default arm into an ordinary
    /// one that takes the next implicit discriminant.
    #[test]
    fn an_unknown_xdr_argument_is_refused() {
        let typo = "enum E { A = 1, #[xdr(defualt)] Other(i32) }";
        assert!(union_refusal(typo).contains("unknown xdr argument"));
    }

    #[test]
    fn a_non_enum_is_refused_by_name() {
        assert!(enum_data(&input("enum E { A }"), "XdrEnum").is_ok());
        // `.err()` drops the `&DataEnum`, which has no `Debug`.
        let err = enum_data(&input("struct S { x: u8 }"), "XdrUnion")
            .err()
            .unwrap();
        assert!(err.to_string().contains("XdrUnion"), "{err}");
    }

    /// A data-bearing variant is a union; encoding it as a bare `i32` would
    /// drop its fields.
    #[test]
    fn xdr_enum_refuses_a_data_bearing_variant() {
        let err = expand_enum(input("enum E { A, B(u8) }")).err().unwrap();
        assert!(err.to_string().contains("field-less"), "{err}");
    }
}
