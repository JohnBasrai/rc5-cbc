//! Verifies the RC5-32/12/16 test vector from Rivest (1994).

use rc5_course::rc5::{decrypt, encrypt};

/// Split a 64-bit value into the two 32-bit words RC5-32 operates on.
fn split_u64(v: u64) -> [u32; 2] {
    [(v >> 32) as u32, v as u32]
}

/// Join two 32-bit words back into a single `u64` (big-endian order).
fn join_u64(words: [u32; 2]) -> u64 {
    ((words[0] as u64) << 32) | (words[1] as u64)
}

#[test]
fn enc_dec_single() {
    // Canonical key/plaintext/ciphertext (RC5-32/12/16)
    let key: [u8; 16] = [
        0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE,
        0x91,
    ];

    // Rivest test-vector #2  (RC5-32/12/16, same 16-byte key)
    let plain: u64 = 0xEE_DB_A5_21_6D_8F_4B_15;
    let cipher: u64 = 0xAC_13_C0_F7_52_89_2B_5B;
    let rounds = 12;

    // --- encrypt ---
    let ct_words = encrypt::<u32>(split_u64(plain), &key, rounds);
    assert_eq!(join_u64(ct_words), cipher, "encrypt mismatch");

    // --- decrypt ---
    let dt_words = decrypt::<u32>(split_u64(cipher), &key, rounds);
    assert_eq!(join_u64(dt_words), plain, "decrypt mismatch");
}
