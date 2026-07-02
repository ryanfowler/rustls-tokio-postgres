use std::io;
use std::sync::Arc;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustls_tokio_postgres::MakeRustlsConnect;
use rustls_tokio_postgres::rustls::{
    ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect as _};

#[cfg(feature = "channel-binding")]
use tokio_postgres::tls::TlsStream as _;

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

fn data_path(c: &mut Criterion) {
    let Some((server_config, client_config)) = test_tls_configs() else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let addr = runtime.block_on(start_echo_server(server_config));

    let mut group = c.benchmark_group("data_path_round_trip");
    for size in [32usize, 1024, 16 * 1024, 256 * 1024] {
        group.throughput(Throughput::Bytes((size * 2) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let make = MakeRustlsConnect::new(client_config.clone());
            let payload = vec![0xa5; size];

            b.to_async(&runtime).iter_custom(|iters| {
                let mut make = make.clone();
                let payload = payload.clone();

                async move {
                    let connector =
                        MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost")
                            .expect("TLS connector");
                    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
                    let mut tls = connector.connect(tcp).await.expect("TLS handshake");
                    let mut read_buf = vec![0; size];

                    let started = Instant::now();
                    for _ in 0..iters {
                        tls.write_all(&payload).await.expect("TLS write");
                        tls.read_exact(&mut read_buf).await.expect("TLS read");
                    }
                    let elapsed = started.elapsed();
                    tls.shutdown().await.expect("TLS shutdown");
                    elapsed
                }
            });
        });
    }
    group.finish();

    #[cfg(feature = "channel-binding")]
    c.bench_function("data_path_channel_binding", |b| {
        let make = MakeRustlsConnect::new(client_config.clone());

        b.to_async(&runtime).iter_custom(|iters| {
            let mut make = make.clone();

            async move {
                let connector =
                    MakeTlsConnect::<TcpStream>::make_tls_connect(&mut make, "localhost")
                        .expect("TLS connector");
                let tcp = TcpStream::connect(addr).await.expect("TCP connect");
                let mut tls = connector.connect(tcp).await.expect("TLS handshake");

                let started = Instant::now();
                for _ in 0..iters {
                    let _binding = tls.channel_binding();
                }
                let elapsed = started.elapsed();
                tls.shutdown().await.expect("TLS shutdown");
                elapsed
            }
        });
    });
}

async fn start_echo_server(
    server_config: rustls_tokio_postgres::rustls::ServerConfig,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("local echo server address");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept echo client");
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let mut tls = acceptor.accept(stream).await.expect("accept TLS");
                let mut buf = vec![0; 256 * 1024];

                loop {
                    let n = match tls.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(err) => panic!("read echo payload: {err:?}"),
                    };
                    if n == 0 {
                        break;
                    }
                    tls.write_all(&buf[..n]).await.expect("write echo payload");
                }
            });
        }
    });

    addr
}

fn test_tls_configs() -> Option<(rustls_tokio_postgres::rustls::ServerConfig, ClientConfig)> {
    let provider = test_crypto_provider()?;

    let cert_der = CertificateDer::from_pem_slice(LOCALHOST_CERT_PEM.as_bytes()).unwrap();
    let key_der = PrivateKeyDer::from_pem_slice(LOCALHOST_KEY_PEM.as_bytes()).unwrap();

    let server_config =
        rustls_tokio_postgres::rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();

    let mut root_store = rustls_tokio_postgres::rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config =
        rustls_tokio_postgres::rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

    Some((server_config, client_config))
}

#[cfg(feature = "aws-lc-rs")]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider(),
    ))
}

#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::ring::default_provider(),
    ))
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    None
}

criterion_group!(benches, data_path);
criterion_main!(benches);
