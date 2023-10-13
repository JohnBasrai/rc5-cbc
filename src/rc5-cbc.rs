/*
  cargo run rc5-cbc -- [--enc/--dec] <input-path> <output-path> <secret-key>
*/

use rc5_course::{decrypt, encrypt, Word};
use std::env;
use std::fs;

enum Actions
{
    Encrypt,
    Decrypt,
}

fn main()
{
    let args: Vec<String> = env::args().collect();

    let option = match args[3].as_str()
    {
        "--enc" => Actions::Encrypt,
        "--dec" => Actions::Decrypt,
        _ => panic!("Bad argument as action, provide [--enc/--dec]"),
    };

    let input_path = args[4].as_str();
    let output_path = args[5].as_str();
    let key = Vec::from(args[6].as_bytes());
    let rounds = 12;

    let input = fs::read(input_path).expect(&format!("File {} couldn't be read", input_path));

    let output_data = match option
    {
        Actions::Encrypt => encrypt_cbc(&input, &key, rounds),
        Actions::Decrypt => decrypt_cbc(&input, &key, rounds),
    };

    fs::write(output_path, output_data);
}

fn encrypt_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, rounds: usize) -> Vec<u8>
{
    let mut plaintext = plaintext.clone();

    let pt_len = plaintext.len();
    let word_bytes = u32::BYTES;
    let chunk = 2 * word_bytes;

    let iters = (pt_len + (chunk - 1)) / chunk;
    plaintext.extend(vec![0u8; iters * chunk - pt_len]);

    let mut output = Vec::<u8>::new();
    let mut ct = [0u32; 2];

    for i in 0 .. iters
    {
        let a = u32::from_be_bytes(
            plaintext[i * chunk .. i * chunk + word_bytes]
                .try_into()
                .unwrap(),
        );
        let b = u32::from_be_bytes(
            plaintext[i * chunk + word_bytes .. i * chunk + 2 * word_bytes]
                .try_into()
                .unwrap(),
        );

        let pt = match i
        {
            0 => [a, b],
            _ => [a ^ ct[0], b ^ ct[1]],
        };

        ct = encrypt(pt, key, rounds);

        output.extend(ct[0].to_be_bytes());
        output.extend(ct[1].to_be_bytes());
    }

    output
}

fn decrypt_cbc(ciphertext: &Vec<u8>, key: &Vec<u8>, rounds: usize) -> Vec<u8>
{
    let ct_len = ciphertext.len();
    let word_bytes = u32::BYTES;
    let chunk = 2 * word_bytes;
    let iters = (ct_len + (chunk - 1)) / chunk;

    let mut output = Vec::<u8>::new();
    let mut ct_prev = [0u32; 2];

    for i in 0 .. iters
    {
        let a = u32::from_be_bytes(
            ciphertext[i * chunk .. i * chunk + word_bytes]
                .try_into()
                .unwrap(),
        );
        let b = u32::from_be_bytes(
            ciphertext[i * chunk + word_bytes .. i * chunk + 2 * word_bytes]
                .try_into()
                .unwrap(),
        );

        let ct = [a, b];

        let pt = decrypt(ct, key, rounds);

        let pt = match i
        {
            0 => pt,
            _ => [pt[0] ^ ct_prev[0], pt[1] ^ ct_prev[1]],
        };

        ct_prev = ct;

        output.extend(pt[0].to_be_bytes());
        output.extend(pt[1].to_be_bytes());
    }

    output
}
