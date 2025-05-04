pub trait Word:
    Clone
    + Copy
    + num::traits::WrappingAdd
    + num::traits::WrappingSub
    + std::fmt::Debug
    + std::cmp::PartialEq
    + std::ops::BitAnd<Output = Self>
    + std::ops::AddAssign
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
    + std::ops::Shl<Output = Self>
    + std::ops::Shr<Output = Self>
{
    const ZERO: Self;
    const P: Self;
    const Q: Self;

    const BYTES: usize;

    fn from_u8(val: u8) -> Self;
    fn from_usize(val: usize) -> Self;
}

impl Word for u8 {
    const ZERO: Self = 0_u8;
    const P: Self = 0_u8;
    const Q: Self = 0_u8;

    const BYTES: usize = 1usize;

    fn from_u8(val: u8) -> Self {
        val
    }

    fn from_usize(val: usize) -> Self {
        val as u8
    }
}

impl Word for u32 {
    const ZERO: Self = 0_u32;
    const P: Self = 0xb7e15163_u32;
    const Q: Self = 0x9e3779b9_u32;

    const BYTES: usize = 4usize;

    fn from_u8(val: u8) -> Self {
        val as u32
    }

    fn from_usize(val: usize) -> Self {
        val as u32
    }
}

//
// Encryption
// A = A + S[0]
// B = B + S[1]
// for i = 1 to r:
//     A = ((A ^ B) << B) + S[2 * i]
//     B = ((B ^ A) << A) + S[2 * i + 1]
//
pub fn encrypt<W: Word>(pt: [W; 2], key: &[u8], rounds: usize) -> [W; 2] {
    let s = expand_key(key, rounds);

    let [mut a, mut b] = pt;

    a = a.wrapping_add(&s[0]);
    b = b.wrapping_add(&s[1]);
    for i in 1..=rounds {
        a = rotl(a ^ b, b).wrapping_add(&s[2 * i]);
        b = rotl(b ^ a, a).wrapping_add(&s[2 * i + 1]);
    }
    [a, b]
}

//
// Decryption
// for i = 2 * (r + 1) to 1:
//     B = (B - S[2 * i + 1] >> A) ^ A
//     A = (A - S[2 * i] >> B) ^ B
// B = B - S[1]
// A = A - S[0]
//
pub fn decrypt<W: Word>(ct: [W; 2], key: &[u8], rounds: usize) -> [W; 2] {
    let s = expand_key(key, rounds);

    let [mut a, mut b] = ct;

    for i in (1..=rounds).rev() {
        b = rotr(b.wrapping_sub(&s[2 * i + 1]), a) ^ a;
        a = rotr(a.wrapping_sub(&s[2 * i]), b) ^ b;
    }
    [a.wrapping_sub(&s[0]), b.wrapping_sub(&s[1])]
}

//
// w: word lengths in bytes
// r: encryption/decryption rounds
// b: original key length in bytes
//
// 1. Transform the original key in an array of words L array of bytes (u8) -> array of
//    Words (u8, u16, u32, .., u128)
//
// c = max(1, ceil(8*b/w))
// for i = b-1 to 0:
//     L[i/w] = (L[i/w] << 8) + key[i]
//
// 2. Initialize an array S
//
// S[0] = P
// for i = 1 to t:
//     S[i] = S[i-1] + Q
//
// 3. Mix S and L
// i = j = 0
// A = B = 0
// do 3 * max(t,c) times:
//    A = S[i] = (S[i] + A + B) << 3
//    B = L[j] = (L[j] + A + B) << (A + B)
//    i = (i + j) mod t
//    j = (i + j) mod c
//
// input: key: Vec<u8>
// output: S: Vec<W>
pub fn expand_key<W: Word>(key: &[u8], rounds: usize) -> Vec<W> {
    let w = W::BYTES * 8;
    let b = key.len();
    let t = 2 * (rounds + 1);

    // ceil(8*b/w) = (8 * b + (w - 1)) / w
    let tmp = (8 * b).div_ceil(w);
    let c = std::cmp::max(1, tmp);
    let mut key_l = vec![W::ZERO; c];

    for i in (0..b).rev() {
        let ix = i / W::BYTES;
        key_l[ix] = (key_l[ix] << W::from_u8(8u8)).wrapping_add(&W::from_u8(key[i]));
    }

    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i - 1].wrapping_add(&W::Q);
    }

    //
    // i = j = 0
    // A = B = 0
    // do 3 * max(t,c) times:
    //    A = S[i] = (S[i] + A + B) << 3
    //    B = L[j] = (L[j] + A + B) << (A + B)
    //    i = (i + 1) mod t
    //    j = (j + 1) mod c
    //
    let mut i = 0usize;
    let mut j = 0usize;
    let mut a = W::ZERO;
    let mut b = W::ZERO;
    let iters = 3 * std::cmp::max(t, c);

    for _ in 0..iters {
        key_s[i] = rotl(key_s[i].wrapping_add(&a.wrapping_add(&b)), W::from_u8(3u8));
        a = key_s[i];
        key_l[j] = rotl(key_l[j].wrapping_add(&a.wrapping_add(&b)), a.wrapping_add(&b));
        b = key_l[j]; //fix
        i = (i + 1) % t;
        j = (j + 1) % c;
    }

    key_s
}

pub fn rotl<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x << a) | (x >> (W::from_usize(w) - a))
    }
}

pub fn rotr<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x >> a) | (x << (W::from_usize(w) - a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_right_shift() {
        let a = 0x77u8; // 0111 0111

        assert_eq!(rotl(a, 1u8), 0xeeu8); // 1110 1110 = 0xee
        assert_eq!(rotl(a, 2u8), 0xddu8); // 1101 1101 = 0xdd
        assert_eq!(rotl(a, 7u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotl(a, 8u8), a);
        assert_eq!(rotl(a, 8u8 + 1u8), 0xeeu8);
        assert_eq!(rotl(a, 8u8 + 2u8), 0xddu8);
        assert_eq!(rotl(a, 8u8 + 7u8), 0xbbu8);
        assert_eq!(rotl(a, 2 * 8u8), a);
        assert_eq!(rotl(a, 5 * 8u8), a);

        assert_eq!(rotr(a, 1u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotr(a, 2u8), 0xddu8); // 1101 1101 = 0xdd
        assert_eq!(rotr(a, 7u8), 0xeeu8); // 1110 1110 = 0xee
        assert_eq!(rotr(a, 8u8), a);
        assert_eq!(rotr(a, 8u8 + 1u8), 0xbbu8);
        assert_eq!(rotr(a, 8u8 + 2u8), 0xddu8);
        assert_eq!(rotr(a, 8u8 + 7u8), 0xeeu8);
        assert_eq!(rotr(a, 2 * 8u8), a);
        assert_eq!(rotr(a, 5 * 8u8), a);
    }

    #[test]
    fn test_rivest_1() {
        let key = vec![
            0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let pt = [0x00000000_u32, 0x00000000];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xEEDBA521_u32, 0x6D8F4B15]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0x00000000_u32, 0x00000000]);
    }

    #[test]
    fn test_rivest_2() {
        let key = vec![
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        let pt = [0xEEDBA521_u32, 0x6D8F4B15];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xAC13C0F7_u32, 0x52892B5B]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xEEDBA521_u32, 0x6D8F4B15]);
    }

    #[test]
    fn test_rivest_3() {
        let key = vec![
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        let pt = [0xAC13C0F7_u32, 0x52892B5B];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xB7B3422F_u32, 0x92FC6903]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xAC13C0F7_u32, 0x52892B5B]);
    }

    #[test]
    fn test_rivest_4() {
        let key = vec![
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        let pt = [0xB7B3422F_u32, 0x92FC6903];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0xB278C165_u32, 0xCC97D184]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xB7B3422F_u32, 0x92FC6903]);
    }

    #[test]
    fn test_rivest_5() {
        let key = vec![
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        let pt = [0xB278C165_u32, 0xCC97D184];
        let rounds = 12;

        let ct = encrypt(pt, &key, rounds);
        assert_eq!(ct, [0x15E444EB_u32, 0x249831DA]);

        let pt = decrypt(ct, &key, rounds);
        assert_eq!(pt, [0xB278C165_u32, 0xCC97D184]);
    }
}
