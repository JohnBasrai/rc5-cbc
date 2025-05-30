# RC5 in Rust [![CI](https://github.com/JohnBasrai/rc5-cbc/actions/workflows/rust.yml/badge.svg)](https://github.com/JohnBasrai/rc5-cbc/actions/workflows/rust.yml)

RC5 is a symmetric-key block-cipher designed by Ron Rivest in 1994.  
It is notable for being simple and fast (it uses only primitive operations such as XOR and data-dependent rotations) and for its small memory footprint. Those properties make Rust an **ideal** language in which to implement it.

---

## Building the library & CLI

```console
# build an optimized release binary
$ cargo build --release
```
The CLI lives in `src/bin/rc5-cbc.rs` and is built automatically as the `rc5-cbc` binary.

---

## Usage

### Encrypt

```console
# replace <PLAINTEXT> with any file you want to protect
$ cargo run --release --bin rc5-cbc -- --input <PLAINTEXT> --output ciphertext.rc5 encrypt
Passphrase: ********
```

### Decrypt

```console
$ cargo run --release --bin rc5-cbc -- --input ciphertext.rc5 --output <DECRYPTED_OUT> decrypt
Passphrase: ********
```
## Running tests & lints

```console
# unit + integration + property tests
$ cargo test

# static analysis
$ cargo clippy --all-targets --all-features
```

All tests should pass and Clippy should emit no warnings.

---

## License

This project is licensed under the MIT License – see [`LICENSE`](LICENSE) for details.
