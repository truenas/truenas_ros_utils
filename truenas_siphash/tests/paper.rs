// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Appendix A of the SipHash paper, through the public API. The crate's
//! unit tests follow each state of the appendix on the way.

use truenas_siphash::Key;

/// Catches any departure from section 2 that changes the one worked example
/// the paper gives, the key 00 to 0f and the message 00 to 0e.
#[test]
fn appendix_a_hashes_to_a129ca6149be45e5() {
    let key = Key::new(core::array::from_fn(|i| i as u8));
    let message: Vec<u8> = (0..15).collect();
    assert_eq!(key.hash(&message), 0xa129_ca61_49be_45e5);
}
