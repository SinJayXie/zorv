//! End-to-end integration tests for Zorv.
//!
//! Topology: external test connection → Server public port (proxy_pub) → tunnel → Client → local echo target.
//!
//! Flow:
//! 1. Generate a temporary self-signed certificate with rcgen (reusing the style from the `common::tls`
//!    tests), with SAN including "localhost" and "127.0.0.1".
//! 2. Start a local echo TCP target (writes back whatever it reads).
//! 3. Start the Server (tunnel + proxy listeners).
//! 4. Start the Client (dial + handshake to establish the tunnel).
//! 5. Connect externally to the Server's public proxy port, write data, and assert the echo comes back unchanged.
//!
//! The client uses verify_cert=false (self-signed certs are not verified; for testing only).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use zorv::client::Client;
use zorv::common::config::{
    AdminConfig, AuthConfig, ClientConfig, ClientTlsConfig, LogConfig, NotifyConfig,
    ObfuscationConfig, PerformanceConfig, ProxyConfig, ReconnectConfig, ServerConfig,
    ServerTlsConfig,
};
use zorv::server::Server;

/// Generate a self-signed certificate and private key (PEM).
///
/// Reuses the rcgen 0.13 call style from the `common::tls` tests:
/// `CertificateParams::new` / `KeyPair::generate` / `self_signed` all return `Result`.
fn generate_self_signed() -> (String, String) {
    let cert_param = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("build cert params");
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = cert_param.self_signed(&key_pair).expect("self signed");
    (cert.pem(), key_pair.serialize_pem())
}

/// Grab a free port: bind port 0, drop immediately, and return the port number.
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind free port");
    l.local_addr().expect("local_addr").port()
}

/// Global incrementing counter to keep temp cert filenames unique across runs.
static UNIQ: AtomicU64 = AtomicU64::new(0);

/// Poll: keep trying a full write → read-back round-trip until it succeeds or times out.
///
/// Returns whether a response matching what was sent arrived within the window.
async fn wait_echo(proxy_addr: &str, payload: &[u8], window: Duration) -> bool {
    let deadline = std::time::Instant::now() + window;
    while std::time::Instant::now() < deadline {
        let attempt = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = TcpStream::connect(proxy_addr).await?;
            conn.write_all(payload).await?;
            let mut buf = vec![0u8; payload.len()];
            conn.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await;
        match attempt {
            Ok(Ok(buf)) if buf.as_slice() == payload => return true,
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tcp_proxy_end_to_end() {
    // 1. Generate a temporary self-signed certificate and write it to a temp file.
    let (cert_pem, key_pem) = generate_self_signed();
    let uid = UNIQ.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let cert_path = std::env::temp_dir().join(format!("zorv_test_{}_{}.crt", uid, pid));
    let key_path = std::env::temp_dir().join(format!("zorv_test_{}_{}.key", uid, pid));
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");

    // 2. Pick ports: use bind-then-drop to find free ports for tunnel and proxy_pub.
    let tunnel_port = free_port().await;
    let proxy_pub_port = free_port().await;

    // 3. Start the echo target: bind first to get a real port, then spawn an accept loop to avoid port races.
    //    Echo semantics: write back whatever bytes are read from the connection (read half → write half).
    let echo_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let echo_port = echo_listener
        .local_addr()
        .expect("echo local_addr")
        .port();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let (mut rd, mut wr) = tokio::io::split(stream);
                    // Write back whatever is read until EOF.
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        }
    });

    // 4. Build the Server config (construct the struct directly to avoid another temp toml file).
    let server_cfg = ServerConfig {
        tunnel_addr: format!("127.0.0.1:{}", tunnel_port),
        tls: ServerTlsConfig {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        },
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        proxies: vec![ProxyConfig {
            name: "echo".to_string(),
            proxy_type: "tcp".to_string(),
            listen: Some(format!("127.0.0.1:{}", proxy_pub_port)),
            client_id: Some("test-client".to_string()),
            target: format!("127.0.0.1:{}", echo_port),
        }],
        performance: PerformanceConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig {
            padding: true,
            padding_max: 255,
            heartbeat_jitter: true,
        },
        admin: AdminConfig::default(),
        data_dir: std::env::temp_dir()
            .join(format!("zorv_data_{}_{}", uid, pid))
            .to_string_lossy()
            .to_string(),
        notify: NotifyConfig::default(),
    };

    // 5. Start the Server (run consumes self; terminate via abort).
    let server = Server::new(server_cfg, String::new());
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 6. Wait for the server listener to be ready.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 7. Build the Client config: verify_cert=false (self-signed certs are not verified).
    let client_cfg = ClientConfig {
        client_id: "test-client".to_string(),
        server_addr: format!("127.0.0.1:{}", tunnel_port),
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        tls: ClientTlsConfig {
            verify_cert: false,
            ca_file: None,
        },
        proxies: vec![ProxyConfig {
            name: "echo".to_string(),
            proxy_type: "tcp".to_string(),
            listen: None,
            client_id: None,
            target: format!("127.0.0.1:{}", echo_port),
        }],
        reconnect: ReconnectConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig {
            padding: true,
            padding_max: 255,
            heartbeat_jitter: true,
        },
    };

    // 8. Start the Client (run borrows &self).
    let client = Client::new(client_cfg);
    let client_task = tokio::spawn(async move {
        let _ = client.run().await;
    });

    // 9 + 10. Poll for a full echo round-trip.
    //
    // Note: a successful TCP connect alone does not prove the tunnel is ready — if the client has
    // not registered a session yet, the Server accepts the connection and closes it immediately
    // ("no tunnel session"). So use a successful write → read-back round-trip as the readiness check, retrying with backoff on failure, over an 8s window.
    let proxy_addr = format!("127.0.0.1:{}", proxy_pub_port);
    let payload = b"hello zorv tunnel\n";
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut got: Vec<u8> = Vec::new();

    while std::time::Instant::now() < deadline {
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
                break;
            }
            _ => {
                // Connection refused/closed/timeout/partial read: tunnel not ready yet, retry with backoff.
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 11. Clean up tasks and temp cert files.
    server_task.abort();
    client_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(
        &got[..],
        &payload[..],
        "echo round-trip failed: did not receive a matching response before timeout"
    );
}

/// UDP proxy end-to-end test.
///
/// Topology: external UDP datagram → Server public UDP port → tunnel UDP_DATAGRAM frame → Client
/// local UDP socket → local UDP echo target; the reply travels back along the same path.
///
/// UDP is connectionless, delivery is not guaranteed, and tunnel establishment has latency,
/// so poll with "send + 1s timeout receive + backoff retry" over a total window of 10s.
#[tokio::test(flavor = "multi_thread")]
async fn test_udp_proxy_end_to_end() {
    // 1. Generate a temporary self-signed certificate and write it to temp files.
    let (cert_pem, key_pem) = generate_self_signed();
    let uid = UNIQ.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let cert_path = std::env::temp_dir().join(format!("zorv_udp_test_{}_{}.crt", uid, pid));
    let key_path = std::env::temp_dir().join(format!("zorv_udp_test_{}_{}.key", uid, pid));
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");

    // 2. The tunnel is TCP; use bind-then-drop to find a free port.
    let tunnel_port = free_port().await;

    // 3. Public UDP proxy port: bind-then-drop to grab a free port (same idea as free_port in the TCP test).
    let udp_probe = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp probe");
    let udp_proxy_port = udp_probe.local_addr().expect("udp probe addr").port();
    drop(udp_probe);

    // 4. Start the UDP echo target: bind first to get a real port and keep the socket to avoid port races.
    //    Echo semantics: send_to back to the source address verbatim after receiving a datagram.
    let echo_socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp echo"),
    );
    let echo_addr = echo_socket.local_addr().expect("echo addr");
    {
        let echo_socket = Arc::clone(&echo_socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo_socket.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo_socket.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // 5. Build the Server config: target is the client-side local UDP echo address.
    let server_cfg = ServerConfig {
        tunnel_addr: format!("127.0.0.1:{}", tunnel_port),
        tls: ServerTlsConfig {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        },
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        proxies: vec![ProxyConfig {
            name: "udp-echo".to_string(),
            proxy_type: "udp".to_string(),
            listen: Some(format!("127.0.0.1:{}", udp_proxy_port)),
            client_id: Some("test-client".to_string()),
            target: echo_addr.to_string(),
        }],
        performance: PerformanceConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig::default(),
        admin: AdminConfig::default(),
        data_dir: std::env::temp_dir()
            .join(format!("zorv_udp_data_{}_{}", uid, pid))
            .to_string_lossy()
            .to_string(),
        notify: NotifyConfig::default(),
    };

    // 6. Start the Server.
    let server = Server::new(server_cfg, String::new());
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 7. Wait for the server listener to be ready.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 8. Build the Client config (verify_cert=false, target required).
    let client_cfg = ClientConfig {
        client_id: "test-client".to_string(),
        server_addr: format!("127.0.0.1:{}", tunnel_port),
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        tls: ClientTlsConfig {
            verify_cert: false,
            ca_file: None,
        },
        proxies: vec![ProxyConfig {
            name: "udp-echo".to_string(),
            proxy_type: "udp".to_string(),
            listen: None,
            client_id: None,
            target: echo_addr.to_string(),
        }],
        reconnect: ReconnectConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig::default(),
    };

    // 9. Start the Client.
    let client = Client::new(client_cfg);
    let client_task = tokio::spawn(async move {
        let _ = client.run().await;
    });

    // 10. External UDP round-trip check: send + timeout receive, backoff retry on failure, total window 10s.
    //
    // Datagrams are dropped while the tunnel is being established (UDP is connectionless),
    // so a response identical to what was sent is used as the readiness criterion.
    let client_udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    let proxy_addr = format!("127.0.0.1:{}", udp_proxy_port);
    let payload = b"hello zorv udp";
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut got: Vec<u8> = Vec::new();

    while std::time::Instant::now() < deadline {
        let _ = client_udp.send_to(payload, &proxy_addr).await;
        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(Duration::from_secs(1), client_udp.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = buf[..n].to_vec();
                break;
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 11. Clean up tasks and temp cert files.
    server_task.abort();
    client_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(
        &got[..],
        &payload[..],
        "UDP echo round-trip failed: did not receive a matching response before timeout"
    );
}

/// Client disconnect-reconnect end-to-end test.
///
/// Topology is the same as the TCP test. Phase A verifies the tunnel is ready, then aborts the
/// client (simulating a disconnect) and starts a new client with the same client_id (simulating
/// auto-reconnect), verifying proxy traffic is restored. Also regression-checks that old-session
/// cleanup (`manager.unregister_if_current`) does not mistakenly remove the reconnected session.
#[tokio::test(flavor = "multi_thread")]
async fn test_client_reconnect_restores_proxy() {
    // 1. Self-signed certificate and temp files.
    let (cert_pem, key_pem) = generate_self_signed();
    let uid = UNIQ.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let cert_path = std::env::temp_dir().join(format!("zorv_rec_test_{}_{}.crt", uid, pid));
    let key_path = std::env::temp_dir().join(format!("zorv_rec_test_{}_{}.key", uid, pid));
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");

    let tunnel_port = free_port().await;
    let proxy_pub_port = free_port().await;

    // 2. Echo target.
    let echo_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let echo_port = echo_listener.local_addr().expect("echo local_addr").port();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let (mut rd, mut wr) = tokio::io::split(stream);
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        }
    });

    // 3. Server config.
    let server_cfg = ServerConfig {
        tunnel_addr: format!("127.0.0.1:{}", tunnel_port),
        tls: ServerTlsConfig {
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
        },
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        proxies: vec![ProxyConfig {
            name: "echo".to_string(),
            proxy_type: "tcp".to_string(),
            listen: Some(format!("127.0.0.1:{}", proxy_pub_port)),
            client_id: Some("test-client".to_string()),
            target: format!("127.0.0.1:{}", echo_port),
        }],
        performance: PerformanceConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig::default(),
        admin: AdminConfig::default(),
        data_dir: std::env::temp_dir()
            .join(format!("zorv_rec_data_{}_{}", uid, pid))
            .to_string_lossy()
            .to_string(),
        notify: NotifyConfig::default(),
    };

    let server = Server::new(server_cfg, String::new());
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 4. Client config (one per phase A and phase C, via clone).
    let client_cfg = ClientConfig {
        client_id: "test-client".to_string(),
        server_addr: format!("127.0.0.1:{}", tunnel_port),
        auth: AuthConfig {
            token: "testtoken".to_string(),
            allowed_ips: None,
        },
        tls: ClientTlsConfig {
            verify_cert: false,
            ca_file: None,
        },
        proxies: vec![ProxyConfig {
            name: "echo".to_string(),
            proxy_type: "tcp".to_string(),
            listen: None,
            client_id: None,
            target: format!("127.0.0.1:{}", echo_port),
        }],
        reconnect: ReconnectConfig::default(),
        log: LogConfig::default(),
        obfuscation: ObfuscationConfig::default(),
    };
    let client2_cfg = client_cfg.clone();

    let proxy_addr = format!("127.0.0.1:{}", proxy_pub_port);
    let payload = b"hello reconnect\n";

    // 5. Phase A: start the first client and wait for the tunnel to be ready.
    let client = Client::new(client_cfg);
    let client_task = tokio::spawn(async move {
        let _ = client.run().await;
    });
    assert!(
        wait_echo(&proxy_addr, payload, Duration::from_secs(8)).await,
        "tunnel not ready on first attempt"
    );

    // 6. Phase B: abort the client to simulate a disconnect; wait a moment for the server to see EOF and clean up the old session.
    client_task.abort();
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 7. Phase C: reconnect with the same client_id and verify the proxy recovers.
    let client2 = Client::new(client2_cfg);
    let client_task2 = tokio::spawn(async move {
        let _ = client2.run().await;
    });
    assert!(
        wait_echo(&proxy_addr, payload, Duration::from_secs(8)).await,
        "proxy did not recover after reconnect (old-session cleanup may have removed the new session)"
    );

    // 8. Clean up tasks and temp files.
    client_task2.abort();
    server_task.abort();
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
