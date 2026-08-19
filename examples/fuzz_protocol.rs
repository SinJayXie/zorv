//! Deterministic protocol fuzz driver (no dependency on cargo-fuzz / nightly / libFuzzer).
//!
//! Usage (release mode is recommended for faster decoding):
//! ```sh
//! cargo run --release --example fuzz_protocol -- --iters 100000 --seed 0x5A3C
//! ```
//!
//! Random inputs are fed to `Frame::decode` and the handshake payload decoder; any panic is caught
//! and the crashing `--seed` is printed (reproducible with the same seed).
//!
//! Extra check: an anomalous memory allocation (huge pre-allocation caused by an oversized length header) is also treated as a failure.

use std::time::Instant;

use zorv::protocol::fuzz::{fuzz_protocol, Prng};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut iters: usize = 100_000;
    let mut seed: u64 = 0x5A3C;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args.get(i + 1).and_then(|s| s.parse().ok()).expect("--iters requires an integer");
                i += 2;
            }
            "--seed" => {
                seed = args
                    .get(i + 1)
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .expect("--seed requires a hex or decimal integer");
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: fuzz_protocol [--iters N] [--seed N]");
                std::process::exit(2);
            }
        }
    }

    // Verify PRNG determinism (compare two instances).
    let mut a = Prng::new(seed);
    let mut b = Prng::new(seed);
    for _ in 0..64 {
        if a.next_u64() != b.next_u64() {
            eprintln!("internal error: PRNG is not deterministic");
            std::process::exit(2);
        }
    }

    println!("fuzz start: seed={seed:#x} iters={iters}");
    let start = Instant::now();
    let result = std::panic::catch_unwind(|| fuzz_protocol(seed, iters));
    match result {
        Ok(executed) => {
            let secs = start.elapsed().as_secs_f64();
            println!(
                "fuzz OK: {executed} inputs, no panic ({:.3}s, {:.0} inputs/s)",
                secs,
                executed as f64 / secs.max(1e-9)
            );
        }
        Err(_) => {
            eprintln!("FUZZ CRASH: reproduce with: cargo run --release --example fuzz_protocol -- --seed {seed:#x} --iters {iters}");
            std::process::exit(1);
        }
    }
}
