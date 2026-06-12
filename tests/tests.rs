use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls_tokio_postgres::MakeRustlsConnect;
use rustls_tokio_postgres::rustls::{
    ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};

const LOCALHOST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhv
c3QwIBcNMjAwMTAxMDAwMDAwWhgPMjA1MDAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABInhSYN5b4yOzkSX
k2c7oftCxotGTC6d882nVyps5rP1fht9yqjgGQdUObjGoOFlPdn63qglEqekns1W
Kj5uQ3SjdjB0MB0GA1UdDgQWBBTbFa3/qraJQQNOjJxSeLJdHDhABjAfBgNVHSME
GDAWgBTbFa3/qraJQQNOjJxSeLJdHDhABjAUBgNVHREEDTALgglsb2NhbGhvc3Qw
DAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIh
AP8bx2XukP276oeI/gZwOZjbygreJD3qx+JxUCNlCt4lAiBT1BDuUTppvX8jJN1k
BuPltBArIwLSR4Ox7x8P0+rGWw==
-----END CERTIFICATE-----
";

const LOCALHOST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1TpZB151cQcviPkh
NQWeCFlZ9x54txK3Y4MeTgosojKhRANCAASJ4UmDeW+Mjs5El5NnO6H7QsaLRkwu
nfPNp1cqbOaz9X4bfcqo4BkHVDm4xqDhZT3Z+t6oJRKnpJ7NVio+bkN0
-----END PRIVATE KEY-----
";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a self-signed certificate for `localhost` and return
/// (server_config, client_config).
fn test_tls_configs() -> Option<(rustls::ServerConfig, ClientConfig)> {
    let provider = test_crypto_provider()?;

    let cert_der = CertificateDer::from_pem_slice(LOCALHOST_CERT_PEM.as_bytes()).unwrap();
    let key_der = PrivateKeyDer::from_pem_slice(LOCALHOST_KEY_PEM.as_bytes()).unwrap();

    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let ca_cert_path = write_temp_ca_file(LOCALHOST_CERT_PEM);
    let client_config = rustls_tokio_postgres::config_from_ca_cert(&ca_cert_path).unwrap();
    std::fs::remove_file(ca_cert_path).unwrap();

    Some((server_config, client_config))
}

fn write_temp_ca_file(contents: impl AsRef<[u8]>) -> std::path::PathBuf {
    static NEXT_CA_FILE: AtomicUsize = AtomicUsize::new(0);

    let path = std::env::temp_dir().join(format!(
        "rustls-tokio-postgres-ca-{}-{}.pem",
        std::process::id(),
        NEXT_CA_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

fn config_no_verify() -> Option<ClientConfig> {
    test_crypto_provider()?;
    Some(rustls_tokio_postgres::config_no_verify())
}

#[cfg(feature = "aws-lc-rs")]
fn test_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider(),
    ))
}

#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
fn test_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::ring::default_provider(),
    ))
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
fn test_crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    None
}

macro_rules! require_config {
    () => {
        match config_no_verify() {
            Some(config) => config,
            None => return,
        }
    };
}

macro_rules! require_tls_configs {
    () => {
        match test_tls_configs() {
            Some(configs) => configs,
            None => return,
        }
    };
}

/// Spin up a TLS echo server on a random port. Returns the local address.
async fn start_echo_server(server_config: rustls::ServerConfig) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(stream).await.unwrap();
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = tls.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    tls.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });

    addr
}

// ---------------------------------------------------------------------------
// MakeRustlsConnect construction
// ---------------------------------------------------------------------------

#[test]
fn make_rustls_connect_new() {
    let config = require_config!();
    let _ = MakeRustlsConnect::new(config);
}

#[test]
fn make_rustls_connect_is_clone() {
    let config = require_config!();
    let a = MakeRustlsConnect::new(config);
    let _b = a.clone();
}

// ---------------------------------------------------------------------------
// make_tls_connect – hostname validation
// ---------------------------------------------------------------------------

#[test]
fn make_tls_connect_valid_dns() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_valid_domain() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "example.com");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_valid_subdomain() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "db.example.com");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_empty_hostname_fails() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    match MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "") {
        Ok(_) => panic!("empty hostname should fail"),
        Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
    }
}

#[test]
fn make_tls_connect_ip_address_succeeds() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "192.168.1.1");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_ipv6_succeeds() {
    let config = require_config!();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "::1");
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Config helpers – smoke tests
// ---------------------------------------------------------------------------

#[test]
fn config_no_verify_returns_usable_config() {
    let config = require_config!();
    let _ = MakeRustlsConnect::new(config);
}

#[test]
fn config_no_verify_selects_feature_provider() {
    if test_crypto_provider().is_none() {
        return;
    }

    let config = rustls_tokio_postgres::config_no_verify();
    let _ = MakeRustlsConnect::new(config);
}

#[test]
fn config_no_verify_reports_missing_crypto_provider() {
    if test_crypto_provider().is_some() {
        return;
    }

    let panic = std::panic::catch_unwind(rustls_tokio_postgres::config_no_verify)
        .expect_err("config unexpectedly succeeded without a crypto provider");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");

    assert!(message.contains("could not select a rustls CryptoProvider"));
}

#[test]
fn config_from_ca_cert_selects_feature_provider() {
    if test_crypto_provider().is_none() {
        return;
    }

    let ca_cert_path = write_temp_ca_file(LOCALHOST_CERT_PEM);

    let config = rustls_tokio_postgres::config_from_ca_cert(&ca_cert_path).unwrap();
    let _ = MakeRustlsConnect::new(config);
    std::fs::remove_file(ca_cert_path).unwrap();
}

#[cfg(feature = "webpki-roots")]
#[test]
fn config_webpki_roots_selects_feature_provider() {
    if test_crypto_provider().is_none() {
        return;
    }

    let config = rustls_tokio_postgres::config_webpki_roots();
    let _ = MakeRustlsConnect::new(config);
}

#[test]
fn config_from_ca_cert_rejects_invalid_cert_file() {
    let ca_cert_path = write_temp_ca_file("not a certificate");

    assert!(rustls_tokio_postgres::config_from_ca_cert(&ca_cert_path).is_err());
    std::fs::remove_file(ca_cert_path).unwrap();
}

// ---------------------------------------------------------------------------
// Full TLS handshake + data round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_handshake_and_echo() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect(tcp).await.unwrap();

    let payload = b"hello rustls-tokio-postgres";
    tls_stream.write_all(payload).await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn tls_handshake_multiple_messages() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect(tcp).await.unwrap();

    for i in 0..5 {
        let msg = format!("message number {i}");
        tls_stream.write_all(msg.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut buf = vec![0u8; msg.len()];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg.as_bytes());
    }
}

#[tokio::test]
async fn tls_stream_shutdown() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect(tcp).await.unwrap();

    tls_stream.write_all(b"bye").await.unwrap();
    tls_stream.flush().await.unwrap();
    tls_stream.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------
// TLS handshake with no_verify config against self-signed cert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_handshake_no_verify() {
    let (server_config, _) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let client_config = require_config!();
    let mut make = MakeRustlsConnect::new(client_config);
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect(tcp).await.unwrap();

    let payload = b"no verify works";
    tls_stream.write_all(payload).await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

// ---------------------------------------------------------------------------
// TLS handshake failure – wrong hostname
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_handshake_wrong_hostname_fails() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);
    let connector =
        MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "not-localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let result = connector.connect(tcp).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Channel binding returns without panicking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_stream_channel_binding() {
    use tokio_postgres::tls::TlsStream;

    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);
    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls_stream = TlsConnect::connect(connector, tcp).await.unwrap();

    let _binding = TlsStream::channel_binding(&tls_stream);
}

// ---------------------------------------------------------------------------
// Multiple connections from the same MakeRustlsConnect (Arc sharing)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_connections_from_same_make() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let mut make = MakeRustlsConnect::new(client_config);

    for i in 0u8..3 {
        let connector =
            MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost").unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = connector.connect(tcp).await.unwrap();

        let msg = [i; 4];
        tls_stream.write_all(&msg).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg);
    }
}

// ---------------------------------------------------------------------------
// Cloned MakeRustlsConnect works independently
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cloned_make_works() {
    let (server_config, client_config) = require_tls_configs!();
    let addr = start_echo_server(server_config).await;

    let make = MakeRustlsConnect::new(client_config);
    let mut make2 = make.clone();

    let connector = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make2, "localhost").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls_stream = connector.connect(tcp).await.unwrap();

    tls_stream.write_all(b"from clone").await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut buf = vec![0u8; 10];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"from clone");
}
