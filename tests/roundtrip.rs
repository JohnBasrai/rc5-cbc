//! Property-based round-trip test for RC5 block encryption.
//!
//! Instead of the old `encrypt_cbc` / `decrypt_cbc` helpers (which no longer
//! exist) we call the block functions directly.

use proptest::prelude::*;
use rc5_course::rc5::{decrypt, encrypt};

/// Strategy that produces a single RC5 block (two 32-bit words).
fn rc5_block() -> impl Strategy<Value = [u32; 2]> {
    (any::<u32>(), any::<u32>()).prop_map(|(a, b)| [a, b])
}

proptest! {
    #[test]
    fn round_trip_random(
        // 1‥200 random blocks of plaintext
        plaintext in prop::collection::vec(rc5_block(), 1..200),
        // exactly-16-byte secret key
        key in prop::collection::vec(any::<u8>(), 16),
    ) {
        let rounds = 12;

        // --- encrypt every block ---
        let ciphertext: Vec<[u32; 2]> =
            plaintext.iter()
                     .map(|&pt| encrypt::<u32>(pt, &key, rounds))
                     .collect();

        // --- decrypt back ---
        let decrypted: Vec<[u32; 2]> =
            ciphertext.iter()
                      .map(|&ct| decrypt::<u32>(ct, &key, rounds))
                      .collect();

        prop_assert_eq!(plaintext, decrypted);
    }
}
