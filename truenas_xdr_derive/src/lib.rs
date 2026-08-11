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
#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DataEnum, DeriveInput, Expr, ExprLit, ExprUnary, Fields, Lit, UnOp,
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
#[proc_macro_derive(XdrUnion)]
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
    reject_generics(&input)?;
    let name = &input.ident;
    let data = enum_data(&input, "XdrUnion")?;
    let discs = discriminants(data)?;

    let mut ser_arms = Vec::new();
    let mut de_arms = Vec::new();
    // The deserializer is told the widest arm's element count; the visitor
    // reads only what the decoded discriminant calls for.
    let mut max_elems = 1usize;

    for (v, &disc) in data.variants.iter().zip(&discs) {
        let ident = &v.ident;
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
        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                match self { #( #ser_arms )* }
            }
        }
        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                struct __Visitor;
                impl<'de> ::serde::de::Visitor<'de> for __Visitor {
                    type Value = #name;
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
                    ) -> ::core::result::Result<#name, A::Error> {
                        let tag: i32 =
                            ::serde::de::SeqAccess::next_element(&mut seq)?
                                .ok_or_else(|| {
                                    <A::Error as ::serde::de::Error>::custom(
                                        "missing XDR union discriminant",
                                    )
                                })?;
                        match tag {
                            #( #de_arms )*
                            other => ::core::result::Result::Err(
                                <A::Error as ::serde::de::Error>::custom(
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
                ::serde::Deserializer::deserialize_tuple(
                    deserializer, #max_elems, __Visitor,
                )
            }
        }
    }
    .into())
}
