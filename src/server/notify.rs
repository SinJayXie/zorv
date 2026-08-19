//! Event notification: sends a JSON POST to the configured Webhook URL (e.g. client-offline alerts).
//!
//! Hand-written HTTP/1.1 with optional TLS (tokio-rustls), avoiding extra HTTP dependencies.
//! Note: the current certificate trust store does not include system root certificates, so https webhooks
//! use a connector that skips certificate verification (alert-only scenarios, no confidential data), and log a one-time warning.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::common::error::{Result, ZorvError};
use crate::common::tls::build_client_connector;

/// Connection stream: plain TCP or TLS.
enum WebStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl WebStream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WebStream::Plain(s) => s.read(buf).await,
            WebStream::Tls(s) => s.read(buf).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            WebStream::Plain(s) => s.write_all(buf).await,
            WebStream::Tls(s) => s.write_all(buf).await,
        }
    }
}

/// POSTs a JSON payload to a Webhook URL (supports http/https).
pub async fn post_json(url: &str, payload: &serde_json::Value) -> Result<()> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        ZorvError::Other(format!("invalid webhook url: {url}"))
    })?;
    let is_tls = scheme.eq_ignore_ascii_case("https");
    let (host_port, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>().unwrap_or(if is_tls { 443 } else { 80 }),
        ),
        None => (host_port, if is_tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(ZorvError::Other("invalid webhook host".into()));
    }

    let body = serde_json::to_vec(payload).map_err(|e| {
        ZorvError::Other(format!("serialize webhook payload failed: {e}"))
    })?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let tcp = TcpStream::connect((host, port)).await?;
    let mut stream = if is_tls {
        // Connector that skips certificate verification (see module docs)
        tracing::warn!(
            "webhook uses https without cert verification (no system root store): {}",
            url
        );
        let connector = build_client_connector(false, None)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| ZorvError::Tls("invalid webhook host".into()))?;
        WebStream::Tls(connector.connect(server_name, tcp).await?)
    } else {
        WebStream::Plain(tcp)
    };

    stream.write_all(&head.as_bytes()).await?;
    stream.write_all(&body).await?;
    // Simply read the response until the peer closes (reusing the TLS read path)
    let mut sink = [0u8; 256];
    loop {
        match stream.read(&mut sink).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Reads the request (300ms read timeout: post_json stops writing after the request is sent, so a timeout means the body is complete),
    /// then replies with an HTTP response and closes the connection, letting `post_json`'s read loop finish normally.
    async fn read_request_then_reply(mut sock: tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            match tokio::time::timeout(Duration::from_millis(300), sock.read(&mut tmp)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Locally simulates a Webhook receiver: returns the URL and the task handle that reads the request.
    async fn spawn_webhook_server() -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/hook");
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            read_request_then_reply(sock).await
        });
        (url, handle)
    }

    #[tokio::test]
    async fn post_json_sends_http_post() {
        let (url, handle) = spawn_webhook_server().await;
        let payload = serde_json::json!({"client_id": "c1", "event": "offline"});
        post_json(&url, &payload).await.unwrap();
        let received = handle.await.unwrap();
        assert!(received.starts_with("POST /hook HTTP/1.1"), "head={received}");
        assert!(received.contains("Content-Type: application/json"));
        assert!(received.contains(r#""client_id":"c1""#));
        assert!(received.contains(r#""event":"offline""#));
    }

    #[tokio::test]
    async fn post_json_uses_root_path_when_absent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            read_request_then_reply(sock).await
        });
        post_json(&url, &serde_json::json!({"a": 1})).await.unwrap();
        let received = handle.await.unwrap();
        assert!(received.starts_with("POST / HTTP/1.1"), "head={received}");
    }

    #[tokio::test]
    async fn post_json_rejects_invalid_url() {
        assert!(post_json("not-a-url", &serde_json::json!({})).await.is_err());
        assert!(post_json("http://", &serde_json::json!({})).await.is_err());
    }
}
