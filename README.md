# rc5-cbc
RC5 Symmetric Block Cipher in Rust

RC5 is a symmetric key block encryption algorithm designed by Ron Rivest in 1994. It is
notable for being simple, fast (on account of using only primitive computer operations
like XOR, shift, etc.) and consumes less memory.  Making Rust an idle language to
implement it in.

Rivest original paper is [The RC5 Encryption Algorithm](https://people.csail.mit.edu/rivest/pubs/Riv94.pdf)

## Usage
```
$ cargo build                                                                  
    Finished dev [unoptimized + debuginfo] target(s) in 0.01s
target/debug/rc5-cbc --input file.in --output file.out encrypt

Passphrase: Mary had a little lamb
$
```

## Help message
```
$ target/debug/rc5-cbc --help
RC5 Symmetric Block Cipher in Rust

Usage: rc5-cbc --input <IN_PATH> --output <OUT_PATH> <COMMAND>

Commands:
  encrypt  Encrypt a file
  decrypt  Decrypt a file
  help     Print this message or the help of the given subcommand(s)

Options:
  -i, --input <IN_PATH>    Input plaintext file
  -o, --output <OUT_PATH>  Output ciphertext file
  -h, --help               Print help
```
