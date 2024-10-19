use clap::{Parser, Subcommand};
use rc5::{decrypt, encrypt, Word};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
mod rc5;

// Usage: rc5-cbc --input <IN_PATH> --output <OUT_PATH> <COMMAND>

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
/// RC5 Symmetric Block Cipher in Rust
///
/// RC5 is a symmetric key block encryption algorithm designed by Ron Rivest in 1994. It
/// is notable for being simple, fast (on account of using only primitive computer
/// operations like XOR, shift, etc.)  and consumes less memory.  Making Rust an idle
/// language to implement it in.
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Input plaintext file
    #[arg(short, long, value_name = "IN_PATH")]
    input: PathBuf,

    /// Output ciphertext file
    #[arg(short, long, value_name = "OUT_PATH")]
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt,

    /// Decrypt a file
    Decrypt,
}

pub fn main() -> Result<()> {
    let args = Args::parse();
    args.command.execute(&args.input, &args.output)
}

impl Command {
    fn execute(&self, input_path: &std::path::Path, output_path: &std::path::Path) -> Result<()> {
        let mut line = String::new();
        let stdin = io::stdin();

        print!("\nPassphrase: ");
        let _ = io::stdout().flush();
        let _ = match stdin.lock().read_line(&mut line) {
            Ok(key) => key,
            Err(err) => {
                return Err(anyhow!("Could not read line:{}", err));
            }
        };
        let key = Vec::from(line.as_bytes());
        let rounds = 12;

        let input = match fs::read(input_path) {
            Ok(inp) => inp,
            Err(err) => {
                return Err(anyhow!("File {:?} couldn't be read:{}", input_path, err));
            }
        };
        let output = match self {
            Self::Encrypt => encrypt_cbc(&input, &key, rounds)?,
            Self::Decrypt => decrypt_cbc(&input, &key, rounds)?,
        };

        let _ = match fs::write(output_path, &output) {
            Ok(_) => {}
            Err(err) => {
                return Err(anyhow!("Error writing output file: {}", err));
            }
        };
        Ok(())
    }
}

fn encrypt_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, rounds: usize) -> Result<Vec<u8>> {
    let mut plaintext = plaintext.clone();

    let pt_len = plaintext.len();
    let word_bytes = u32::BYTES;
    let chunk = 2 * word_bytes;

    let iters = (pt_len + (chunk - 1)) / chunk;
    plaintext.extend(vec![0u8; iters * chunk - pt_len]);

    let mut output = Vec::<u8>::new();
    let mut ct = [0u32; 2];

    for i in 0..iters {
        let a = plaintext[i * chunk..i * chunk + word_bytes].try_into()?;
        let a = u32::from_be_bytes(a);

        let b = plaintext[i * chunk + word_bytes..i * chunk + 2 * word_bytes].try_into()?;
        let b = u32::from_be_bytes(b);

        let pt = match i {
            0 => [a, b],
            _ => [a ^ ct[0], b ^ ct[1]],
        };

        ct = encrypt(pt, key, rounds);

        output.extend(ct[0].to_be_bytes());
        output.extend(ct[1].to_be_bytes());
    }

    Ok(output)
}

fn decrypt_cbc(ciphertext: &Vec<u8>, key: &Vec<u8>, rounds: usize) -> Result<Vec<u8>> {
    let ct_len = ciphertext.len();
    let word_bytes = u32::BYTES;
    let chunk = 2 * word_bytes;
    let iters = (ct_len + (chunk - 1)) / chunk;

    let mut output = Vec::<u8>::new();
    let mut ct_prev = [0u32; 2];

    for i in 0..iters {
        let a = ciphertext[i * chunk..i * chunk + word_bytes].try_into()?;
        let a = u32::from_be_bytes(a);

        let b = ciphertext[i * chunk + word_bytes..i * chunk + 2 * word_bytes].try_into()?;
        let b = u32::from_be_bytes(b);

        let ct = [a, b];

        let pt = decrypt(ct, key, rounds);

        let pt = match i {
            0 => pt,
            _ => [pt[0] ^ ct_prev[0], pt[1] ^ ct_prev[1]],
        };

        ct_prev = ct;

        output.extend(pt[0].to_be_bytes());
        output.extend(pt[1].to_be_bytes());
    }

    Ok(output)
}
