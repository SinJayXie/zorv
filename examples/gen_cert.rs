//! Certificate generation helper tool (for development, not production code).
//!
//! Usage: cargo run --release --example gen_cert -- <cert_path> <key_path>
//!
//! Generates a self-signed certificate with rcgen 0.13 (SAN includes localhost and 127.0.0.1),
//! writing the PEM certificate and private key to the two files given on the command line.
//! The rcgen call style matches the #[cfg(test)] code in src/common/tls.rs.

use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gen_cert <cert_path> <key_path>");
        std::process::exit(2);
    }
    let cert_path = &args[1];
    let key_path = &args[2];

    // rcgen 0.13: CertificateParams::new / KeyPair::generate / self_signed all return Result.
    let cert_param = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .map_err(|e| anyhow::anyhow!("build cert params: {e}"))?;
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("generate key pair: {e}"))?;
    let cert = cert_param
        .self_signed(&key_pair)
        .map_err(|e| anyhow::anyhow!("self signed: {e}"))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("write cert {cert_path}: {e}"))?;
    fs::write(key_path, key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("write key {key_path}: {e}"))?;
    println!("cert -> {}", cert_path);
    println!("key  -> {}", key_path);
    Ok(())
}
