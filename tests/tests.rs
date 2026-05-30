use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls_tokio_postgres::MakeRustlsConnect;
use rustls_tokio_postgres::rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed certificate for `localhost` and return
/// (server_config, client_config).
fn test_tls_configs() -> (rustls::ServerConfig, ClientConfig) {
    install_test_crypto_provider();

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let ca_cert_path = write_temp_ca_file(cert.pem());
    let client_config = rustls_tokio_postgres::config_from_ca_cert(&ca_cert_path).unwrap();
    std::fs::remove_file(ca_cert_path).unwrap();

    (server_config, client_config)
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

fn config_no_verify() -> ClientConfig {
    install_test_crypto_provider();
    rustls_tokio_postgres::config_no_verify()
}

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
fn install_test_crypto_provider() {
    use std::sync::Once;

    static INSTALL_PROVIDER: Once = Once::new();
    INSTALL_PROVIDER.call_once(|| {
        rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("failed to install rustls crypto provider for tests");
    });
}

#[cfg(not(all(feature = "aws-lc-rs", feature = "ring")))]
fn install_test_crypto_provider() {}

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
    let config = config_no_verify();
    let _ = MakeRustlsConnect::new(config);
}

#[test]
fn make_rustls_connect_is_clone() {
    let config = config_no_verify();
    let a = MakeRustlsConnect::new(config);
    let _b = a.clone();
}

// ---------------------------------------------------------------------------
// make_tls_connect – hostname validation
// ---------------------------------------------------------------------------

#[test]
fn make_tls_connect_valid_dns() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_valid_domain() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "example.com");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_valid_subdomain() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "db.example.com");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_empty_hostname_fails() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    match MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "") {
        Ok(_) => panic!("empty hostname should fail"),
        Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
    }
}

#[test]
fn make_tls_connect_ip_address_succeeds() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "192.168.1.1");
    assert!(result.is_ok());
}

#[test]
fn make_tls_connect_ipv6_succeeds() {
    let config = config_no_verify();
    let mut make = MakeRustlsConnect::new(config);
    let result = MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "::1");
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Config helpers – smoke tests
// ---------------------------------------------------------------------------

#[test]
fn config_no_verify_returns_usable_config() {
    let config = config_no_verify();
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
    let (server_config, client_config) = test_tls_configs();
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
    let (server_config, client_config) = test_tls_configs();
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
    let (server_config, client_config) = test_tls_configs();
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
    let (server_config, _) = test_tls_configs();
    let addr = start_echo_server(server_config).await;

    let client_config = config_no_verify();
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
    let (server_config, client_config) = test_tls_configs();
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

    let (server_config, client_config) = test_tls_configs();
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
    let (server_config, client_config) = test_tls_configs();
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
    let (server_config, client_config) = test_tls_configs();
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
