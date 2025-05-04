use assert_cmd::Command;
use std::fs;

#[test]
fn cli_round_trip_file() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let plain = temp.path().join("plain.txt");
    let cipher = temp.path().join("cipher.bin");
    let out = temp.path().join("out.txt");
    fs::write(&plain, b"Hello RC5!")?;

    // encrypt
    Command::cargo_bin("rc5-cbc")?
        .args([
            "--input",
            plain.to_str().unwrap(),
            "--output",
            cipher.to_str().unwrap(),
            "encrypt",
        ])
        .write_stdin("pass\n") // passphrase prompt
        .assert()
        .success();

    // decrypt
    Command::cargo_bin("rc5-cbc")?
        .args([
            "--input",
            cipher.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "decrypt",
        ])
        .write_stdin("pass\n")
        .assert()
        .success();

    assert_eq!(fs::read(plain)?, fs::read(out)?);
    Ok(())
}
