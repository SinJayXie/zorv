//! End-to-end smoke test of the release binaries (for development, not production code).
//!
//! Usage: cargo run --release --example smoke -- [cert_path key_path]
//!
//! Flow:
//! 1. Spawn the release binaries `zorvd.exe` and `zorv.exe client` with a temporary toml config.
//! 2. Run an in-process echo TCP server (127.0.0.1:<echo_port>).
//! 3. Poll the proxy's public port, using a full echo round-trip as the tunnel readiness check.
//! 4. Assert the echo matches what was sent, then kill both children; exit code 0 means success.
//!
//! By default the certificate path is a temp file alongside target/release; it can be overridden via command-line arguments.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioListener, TcpStream};

/// Project root (compile-time constant), used to locate the release binaries and the default cert path.
fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

/// Grab a free port: bind 127.0.0.1:0, then drop and return the port number.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    l.local_addr().expect("local_addr").port()
}

/// Globally keeps the echo server's task handle alive to prevent it from being dropped early.
static ECHO_GUARD: OnceLock<tokio::task::JoinHandle<()>> = OnceLock::new();

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let root = PathBuf::from(manifest_dir());
    let release_dir = root.join("target").join("release");
    let zorvd_exe = release_dir.join("zorvd.exe");
    let zorv_exe = release_dir.join("zorv.exe");

    for p in [&zorvd_exe, &zorv_exe] {
        if !p.exists() {
            eprintln!("missing binary: {}", p.display());
            std::process::exit(3);
        }
    }

    // 1. Certificate paths: command-line arguments take priority, otherwise use temp files (generated beforehand via gen_cert).
    let args: Vec<String> = std::env::args().collect();
    let (cert_path, key_path) = if args.len() >= 3 {
        (PathBuf::from(&args[1]), PathBuf::from(&args[2]))
    } else {
        eprintln!("usage: smoke <cert_path> <key_path>");
        eprintln!("hint: cargo run --release --example gen_cert -- cert.pem key.pem first");
        std::process::exit(2);
    };
    let cert_str = cert_path.to_string_lossy().to_string();

    // 2. Pick ports: echo binds and keeps its socket first; tunnel/proxy use bind-then-drop for free ports.
    let echo_listener = TokioListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_listener.local_addr()?.port();
    ECHO_GUARD
        .set(tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        let (mut rd, mut wr) = tokio::io::split(stream);
                        let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    });
                }
            }
        }))
        .ok();

    let tunnel_port = free_port();
    let proxy_port = free_port();

    // 3. Write the temporary toml configs.
    let tmp = std::env::temp_dir();
    let uid = std::process::id();
    let zorvd_toml = tmp.join(format!("zorv_smoke_zorvd_{}.toml", uid));
    let zorv_toml = tmp.join(format!("zorv_smoke_zorv_{}.toml", uid));

    let zorvd_content = format!(
        r#"tunnel_addr = "127.0.0.1:{tunnel_port}"

[tls]
# Use single-quoted TOML literal strings so backslashes are not treated as escapes.
cert_file = '{cert_str}'
key_file  = '{key_str}'

[auth]
token = "smoke-token"

[[proxies]]
name      = "echo"
type      = "tcp"
listen    = "127.0.0.1:{proxy_port}"
client_id = "smoke-client"
target    = "127.0.0.1:{echo_port}"

[log]
level  = "info"
output = "stdout"
"#,
        tunnel_port = tunnel_port,
        cert_str = cert_str,
        key_str = key_path.to_string_lossy(),
        proxy_port = proxy_port,
        echo_port = echo_port,
    );
    let zorv_content = format!(
        r#"client_id = "smoke-client"
server_addr = "127.0.0.1:{tunnel_port}"

[auth]
token = "smoke-token"

[tls]
verify_cert = false

[[proxies]]
name = "echo"
type = "tcp"
target = "127.0.0.1:{echo_port}"

[reconnect]
initial_delay  = "1s"
max_delay      = "2s"
backoff_factor = 2.0
max_retries    = 3

[log]
level  = "info"
output = "stdout"
"#,
        tunnel_port = tunnel_port,
        echo_port = echo_port,
    );
    std::fs::write(&zorvd_toml, &zorvd_content)?;
    std::fs::write(&zorv_toml, &zorv_content)?;

    println!(
        "[smoke] echo=127.0.0.1:{} tunnel=127.0.0.1:{} proxy=127.0.0.1:{}",
        echo_port, tunnel_port, proxy_port
    );
    println!("[smoke] zorvd.toml = {}", zorvd_toml.display());
    println!("[smoke] zorv.toml  = {}", zorv_toml.display());

    // 4. Spawn the two binaries (children). stdout/stderr are inherited so logs appear in the current process.
    let mut server_child = Command::new(&zorvd_exe)
        .arg("-c")
        .arg(&zorvd_toml)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn zorvd: {e}"))?;
    let mut client_child = Command::new(&zorv_exe)
        .arg("client")
        .arg("-c")
        .arg(&zorv_toml)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn zorv: {e}"))?;

    // 5. Poll with a full echo round-trip as the tunnel readiness check (overall 10s window).
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    let payload = b"hello binary smoke\n";
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got: Vec<u8> = Vec::new();
    let mut ok = false;

    while Instant::now() < deadline {
        let attempt = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = TcpStream::connect(&proxy_addr).await?;
            conn.write_all(payload).await?;
            let mut buf = vec![0u8; payload.len()];
            conn.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await;

        match attempt {
            Ok(Ok(buf)) => {
                got = buf;
                ok = true;
                break;
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 6. Cleanup: kill and reap both children, remove the temporary toml files.
    let _ = server_child.kill();
    let _ = client_child.kill();
    let _ = server_child.wait();
    let _ = client_child.wait();
    let _ = std::fs::remove_file(&zorvd_toml);
    let _ = std::fs::remove_file(&zorv_toml);

    if !ok {
        eprintln!("[smoke] FAIL: tunnel not ready within 10s");
        std::process::exit(1);
    }
    if &got[..] != &payload[..] {
        eprintln!(
            "[smoke] FAIL: echo mismatch, got {:?} expected {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(payload)
        );
        std::process::exit(1);
    }

    println!(
        "[smoke] PASS: echo round-trip OK, got {:?}",
        String::from_utf8_lossy(&got)
    );
    Ok(())
}
