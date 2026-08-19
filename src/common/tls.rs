//! TLS 1.3 configuration builders (based on `tokio-rustls` 0.26 + `rustls` 0.23).
//!
//! - Server: loads a certificate/private key from PEM files and builds a
//!   `TlsAcceptor` that enforces TLS 1.3.
//! - Client: builds a `TlsConnector` with an optional custom CA, or skips
//!   certificate verification entirely (testing only).
//!
//! Verified API compatibility (rustls 0.23.43 / rustls-pemfile 2.2.0):
//! - `rustls::crypto::aws_lc_rs::default_provider().install_default()` installs the
//!   default crypto provider; repeated calls return Err (already installed), so the
//!   result is ignored with `let _ = ...`.
//! - `ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`
//!   restricts the protocol version to TLS 1.3.
//! - `rustls_pemfile::certs(&mut r)` returns `impl Iterator<Item = io::Result<...>>`;
//!   `rustls_pemfile::private_key(&mut r)` returns `io::Result<Option<...>>`.
//! - rustls 0.23.43 has no `dangerous_configuration` feature, so `.dangerous()` is
//!   always available. The skip-verification chain is
//!   `builder().dangerous().with_custom_certificate_verifier(v)` followed by
//!   `.with_no_client_auth()`.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::common::error::{Result, ZorvError};

/// Ensures the default crypto provider is installed.
///
/// rustls 0.23 requires a default provider (aws_lc_rs) to be installed before
/// building any configuration. Calling it more than once is safe: it returns
/// Err when already installed, which is discarded via `let _ =`.
fn ensure_crypto_provider() {
    // install_default returns Result<(), Arc<CryptoProvider>>.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A `ServerCertVerifier` that accepts every certificate.
///
/// **For testing/self-signed scenarios only**: production must verify
/// certificates to prevent man-in-the-middle attacks.
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    // NOTE: the return type must use `std::result::Result<_, rustls::Error>`
    // here, not the crate's `Result` alias (whose error type is ZorvError).
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Declare the supported signature schemes for handshake negotiation.
        // Covers the common RSA / ECDSA / Ed25519 schemes so the TLS 1.3 handshake
        // negotiates correctly.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Builds a server-side TLS 1.3 acceptor.
///
/// - `cert_file`: path to a PEM certificate chain (multiple certificates allowed,
///   the first one is the leaf).
/// - `key_file`: path to the PEM private key.
///
/// The returned `TlsAcceptor` only accepts TLS 1.3 and does not require a
/// client certificate.
pub fn build_server_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor> {
    ensure_crypto_provider();

    let cert_file = File::open(cert_file)
        .map_err(|e| ZorvError::Tls(format!("open cert file {}: {}", cert_file, e)))?;
    let key_file = File::open(key_file)
        .map_err(|e| ZorvError::Tls(format!("open key file {}: {}", key_file, e)))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    // rustls-pemfile 2.x: certs() returns an iterator of io::Result<CertificateDer>.
    // Collect with collect::<Result<Vec<_>, _>>() and map errors to ZorvError::Tls.
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ZorvError::Tls(format!("read certs: {}", e)))?;
    if certs.is_empty() {
        return Err(ZorvError::Tls(
            "no certificates found in cert file".to_string(),
        ));
    }

    // private_key() returns io::Result<Option<PrivateKeyDer>>: unwrap the outer
    // Result first, then handle the inner Option (None when the file has no key).
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| ZorvError::Tls(format!("read private key: {}", e)))?
        .ok_or_else(|| ZorvError::Tls("no private key found in key file".to_string()))?;

    // Force TLS 1.3 via builder_with_protocol_versions.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ZorvError::Tls(format!("{:?}", e)))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Builds a client-side TLS 1.3 connector.
///
/// - `verify_cert=true`: `ca_file` is required (webpki-roots / native-certs
///   dependencies are intentionally not pulled in). The CA is added to the root
///   store and verified normally.
/// - `verify_cert=false`: uses `InsecureVerifier` to skip all certificate
///   verification, **testing only**.
///
/// The protocol version is forced to TLS 1.3.
pub fn build_client_connector(verify_cert: bool, ca_file: Option<&str>) -> Result<TlsConnector> {
    ensure_crypto_provider();

    let config = if verify_cert {
        let ca_path = ca_file.ok_or_else(|| {
            ZorvError::Config("ca_file required when verify_cert=true".to_string())
        })?;

        let mut root_store = RootCertStore::empty();
        let ca_file = File::open(ca_path)
            .map_err(|e| ZorvError::Tls(format!("open ca file {}: {}", ca_path, e)))?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ZorvError::Tls(format!("read ca certs: {}", e)))?;
        if ca_certs.is_empty() {
            return Err(ZorvError::Tls(
                "no ca certificates found in ca file".to_string(),
            ));
        }
        for ca in ca_certs {
            root_store
                .add(ca)
                .map_err(|e| ZorvError::Tls(format!("add ca cert: {:?}", e)))?;
        }

        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // INSECURE: skip certificate verification, only for local testing with
        // self-signed certificates. Production must use verify_cert=true with a
        // trusted ca_file. rustls 0.23.43 enters DangerousClientConfigBuilder via
        // `.dangerous()`, then injects the custom verifier with
        // with_custom_certificate_verifier.
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke test: generate a self-signed certificate with rcgen and verify that
    // the acceptor/connector can be built. Handshake-level integration tests
    // live in the server/client module tests.

    fn generate_self_signed() -> (String, String) {
        // rcgen 0.13: CertificateParams::new returns Result,
        // KeyPair::generate returns Result, self_signed returns Result.
        let cert_param = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("build cert params");
        let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
        let cert = cert_param.self_signed(&key_pair).expect("self signed");
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        (cert_pem, key_pem)
    }

    #[test]
    fn build_acceptor_from_self_signed() {
        let tmp = std::env::temp_dir();
        let cert_path = tmp.join("zorv_test_cert.pem");
        let key_path = tmp.join("zorv_test_key.pem");
        let (cert_pem, key_pem) = generate_self_signed();
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        let cert_str = cert_path.to_string_lossy().to_string();
        let key_str = key_path.to_string_lossy().to_string();
        let acceptor = build_server_acceptor(&cert_str, &key_str);
        assert!(acceptor.is_ok(), "acceptor build failed: {:?}", acceptor.err());
    }

    #[test]
    fn build_connector_insecure() {
        let connector = build_client_connector(false, None);
        assert!(connector.is_ok(), "insecure connector: {:?}", connector.err());
    }

    #[test]
    fn build_connector_verify_requires_ca() {
        // verify_cert=true without ca_file → Config error
        let connector = build_client_connector(true, None);
        assert!(connector.is_err());
    }
}
