// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! SipHash-2-4, the keyed hash that Jean-Philippe Aumasson and Daniel J.
//! Bernstein define in their paper on SipHash, in its version of 2012-07-27
//! (<http://cr.yp.to/siphash/siphash-20120727.pdf>).
//!
//! [`Key`] holds a key of 128 bits, and [`Key::hash`] gives the 64 bit
//! SipHash-2-4 of a byte string under it. Section 2 of the paper defines the
//! function, and Appendix A works one message through it.
//!
//! ```
//! use truenas_siphash::Key;
//!
//! // The key and the message of Appendix A.
//! let key = Key::new(core::array::from_fn(|i| i as u8));
//! let message: Vec<u8> = (0..15).collect();
//! assert_eq!(key.hash(&message), 0xa129_ca61_49be_45e5);
//! ```
//!
//! # Comparing a result
//!
//! A result used as a MAC is compared as one `u64`, never as eight bytes in
//! a slice. A comparison of slices may stop at the first byte that differs,
//! and the time it takes then tells the sender how much of a guess was
//! right.
//!
//! # Byte order
//!
//! A result is a number. Written out as bytes, the reference implementation
//! and its vectors put the least significant byte first.
//!
//! # The key
//!
//! A [`Key`] never prints its bytes, so a key held in a structure that
//! derives `Debug` does not reach a log. It is not zeroed when dropped.
#![forbid(unsafe_code)]

use core::fmt;

/// The words section 2 XORs the key into, which spell
/// "somepseudorandomlygeneratedbytes" in ASCII read big endian.
const INITIAL: [u64; 4] = [
    0x736f_6d65_7073_6575,
    0x646f_7261_6e64_6f6d,
    0x6c79_6765_6e65_7261,
    0x7465_6462_7974_6573,
];

/// The rounds of SipRound for each word of the message, the c of
/// SipHash-c-d.
const COMPRESSION_ROUNDS: usize = 2;

/// The rounds of SipRound once the message is in, the d of SipHash-c-d.
const FINALIZATION_ROUNDS: usize = 4;

/// A key of SipHash-2-4, kept as the state that section 2 starts from.
#[derive(Clone, Eq, PartialEq)]
pub struct Key {
    state: [u64; 4],
}

impl Key {
    /// The key whose 16 bytes are `bytes`, read as two little-endian words
    /// k0 and k1, as section 2 says.
    pub fn new(bytes: [u8; 16]) -> Key {
        let word = |half: &[u8]| {
            u64::from_le_bytes(half.try_into().expect("eight bytes"))
        };
        let (k0, k1) = (word(&bytes[..8]), word(&bytes[8..]));
        Key {
            state: [
                k0 ^ INITIAL[0],
                k1 ^ INITIAL[1],
                k0 ^ INITIAL[2],
                k1 ^ INITIAL[3],
            ],
        }
    }

    /// SipHash-2-4 of `data` under this key.
    pub fn hash(&self, data: &[u8]) -> u64 {
        let mut v = self.state;
        let (words, tail) = data.as_chunks::<8>();
        for word in words {
            compress(&mut v, u64::from_le_bytes(*word));
        }
        compress(&mut v, last_word(tail, data.len()));
        finalize(&mut v);
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key").finish_non_exhaustive()
    }
}

/// The last word of a message of `len` bytes, as section 2 builds it. The 0
/// to 7 bytes of `tail` come first, then null bytes, and the most
/// significant byte is `len` mod 256, which the cast keeps.
fn last_word(tail: &[u8], len: usize) -> u64 {
    let mut word = [0; 8];
    word[..tail.len()].copy_from_slice(tail);
    word[7] = len as u8;
    u64::from_le_bytes(word)
}

/// One word of the message, XORed into v3, then c rounds, then XORed into
/// v0.
fn compress(v: &mut [u64; 4], m: u64) {
    v[3] ^= m;
    for _ in 0..COMPRESSION_ROUNDS {
        sip_round(v);
    }
    v[0] ^= m;
}

/// The constant ff XORed into v2, then d rounds.
fn finalize(v: &mut [u64; 4]) {
    v[2] ^= 0xff;
    for _ in 0..FINALIZATION_ROUNDS {
        sip_round(v);
    }
}

/// SipRound as section 2 lays it out, each line its left column and then
/// its right.
fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[2] = v[2].wrapping_add(v[3]);
    v[1] = v[1].rotate_left(13);
    v[3] = v[3].rotate_left(16);
    v[1] ^= v[0];
    v[3] ^= v[2];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[1]);
    v[0] = v[0].wrapping_add(v[3]);
    v[1] = v[1].rotate_left(17);
    v[3] = v[3].rotate_left(21);
    v[1] ^= v[2];
    v[3] ^= v[0];
    v[2] = v[2].rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every state below is from Appendix A, written out from the paper, v0
    // to v3 left to right. Its key is the bytes 00 to 0f and its message
    // the bytes 00 to 0e.

    const INITIALIZED: [u64; 4] = [
        0x7469_6861_7371_6475,
        0x6b61_7f6d_656e_6665,
        0x6b7f_6261_6d67_7361,
        0x7b6b_696e_727e_6c7b,
    ];
    const FIRST_WORD: u64 = 0x0706_0504_0302_0100;
    const FIRST_WORD_IN_V3: [u64; 4] = [
        0x7469_6861_7371_6475,
        0x6b61_7f6d_656e_6665,
        0x6b7f_6261_6d67_7361,
        0x7c6d_6c6a_717c_6d7b,
    ];
    const TWO_ROUNDS: [u64; 4] = [
        0x4d07_749c_dd08_58e0,
        0x0d52_f6f6_2a4f_59a4,
        0x634c_b357_7b01_fd3d,
        0xa522_4d6f_55c7_d9c8,
    ];
    const FIRST_WORD_IN_V0: [u64; 4] = [
        0x4a01_7198_de0a_59e0,
        0x0d52_f6f6_2a4f_59a4,
        0x634c_b357_7b01_fd3d,
        0xa522_4d6f_55c7_d9c8,
    ];
    const LAST_WORD: u64 = 0x0f0e_0d0c_0b0a_0908;
    const LAST_WORD_AND_FF: [u64; 4] = [
        0x3c85_b3ab_6f55_be51,
        0x414f_c3fb_98ef_e374,
        0xccf1_3ea5_27b9_f442,
        0x5293_f5da_8400_8f82,
    ];
    const FINALIZED: [u64; 4] = [
        0xf6bc_d538_93fe_cff1,
        0x54b9_964c_7ea0_d937,
        0x1b38_329c_099b_b55a,
        0x1814_bb89_ad7b_e679,
    ];
    const RESULT: u64 = 0xa129_ca61_49be_45e5;

    fn message() -> Vec<u8> {
        (0..15).collect()
    }

    /// Catches a wrong constant, or a key read in the wrong byte order.
    #[test]
    fn initialization_gives_the_first_state_of_appendix_a() {
        let key = Key::new(core::array::from_fn(|i| i as u8));
        assert_eq!(key.state, INITIALIZED);
    }

    /// Catches a wrong rotation or step order in SipRound, and a word
    /// XORed into the wrong place.
    #[test]
    fn the_first_word_goes_through_each_state_of_appendix_a() {
        let mut v = INITIALIZED;
        v[3] ^= FIRST_WORD;
        assert_eq!(v, FIRST_WORD_IN_V3);
        sip_round(&mut v);
        sip_round(&mut v);
        assert_eq!(v, TWO_ROUNDS);
        v[0] ^= FIRST_WORD;
        assert_eq!(v, FIRST_WORD_IN_V0);
        let mut v = INITIALIZED;
        compress(&mut v, FIRST_WORD);
        assert_eq!(v, FIRST_WORD_IN_V0);
    }

    /// Catches a last word built wrong, the wrong count of compression
    /// rounds, and a constant other than ff.
    #[test]
    fn the_last_word_and_ff_give_the_next_state_of_appendix_a() {
        let message = message();
        assert_eq!(last_word(&message[8..], message.len()), LAST_WORD);
        let mut v = FIRST_WORD_IN_V0;
        compress(&mut v, LAST_WORD);
        v[2] ^= 0xff;
        assert_eq!(v, LAST_WORD_AND_FF);
    }

    /// Catches the wrong count of finalization rounds.
    #[test]
    fn finalization_gives_the_last_state_of_appendix_a() {
        let mut v = FIRST_WORD_IN_V0;
        compress(&mut v, LAST_WORD);
        finalize(&mut v);
        assert_eq!(v, FINALIZED);
        assert_eq!(v[0] ^ v[1] ^ v[2] ^ v[3], RESULT);
    }

    /// Catches a hash that walks the message in some other way.
    #[test]
    fn the_message_of_appendix_a_hashes_to_its_result() {
        let key = Key::new(core::array::from_fn(|i| i as u8));
        assert_eq!(key.hash(&message()), RESULT);
    }

    /// Section 2's example, the one byte ab parsed as 01000000000000ab.
    #[test]
    fn one_byte_is_the_word_section_2_gives() {
        assert_eq!(last_word(&[0xab], 1), 0x0100_0000_0000_00ab);
    }

    /// Section 2 parses an empty message as one word, which holds only the
    /// length 0.
    #[test]
    fn an_empty_message_is_one_word_of_nulls() {
        assert_eq!(last_word(&[], 0), 0);
    }

    /// Catches a length byte that does not wrap at 256, as section 2's
    /// "b mod 256" asks.
    #[test]
    fn the_length_byte_is_the_length_mod_256() {
        assert_eq!(last_word(&[], 256), 0);
        assert_eq!(last_word(&[1, 2, 3], 259), 0x0300_0000_0003_0201);
        assert_eq!(last_word(&[7; 7], 303), 0x2f07_0707_0707_0707);
    }
}
