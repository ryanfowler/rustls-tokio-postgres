use std::io;
use std::sync::Arc;

use rustls_tokio_postgres::rustls::ClientConfig;
use rustls_tokio_postgres::{MakeRustlsConnect, config_no_verify};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed certificate for `localhost` and return
/// (server_config, client_config).
fn test_tls_configs() -> (rustls::ServerConfig, ClientConfig) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = cert_params.self_signed(&key_pair).unwrap();

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, client_config)
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
// config_no_verify – smoke test
// ---------------------------------------------------------------------------

#[test]
fn config_no_verify_returns_usable_config() {
    let config = config_no_verify();
    let _ = MakeRustlsConnect::new(config);
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
