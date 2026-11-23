//! Tests the documented panics and errors of the config helpers for crypto
//! provider problems.
//!
//! With the `aws-lc-rs` or `ring` feature, the tests install a process-wide
//! provider with no cipher suites. This provider is not compatible. Without
//! these features, the tests install no provider. These tests change
//! process-wide state, so they are in their own test binary.

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use std::sync::Once;

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use rustls_tokio_postgres::rustls::{self, crypto::CryptoProvider};

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
const BUILDER_ERROR: &str = "no usable cipher suites configured";

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
const CA_CERT_PEM: &str = "\
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

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn install_provider_without_cipher_suites() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        #[cfg(feature = "aws-lc-rs")]
        let provider = rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
        let provider = rustls_tokio_postgres::rustls::crypto::ring::default_provider();

        CryptoProvider {
            cipher_suites: Vec::new(),
            ..provider
        }
        .install_default()
        .expect("no other test installs a default provider");
    });
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn write_ca_file(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rustls-tokio-postgres-{name}-{}.pem",
        std::process::id()
    ));
    std::fs::write(&path, CA_CERT_PEM).unwrap();
    path
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn assert_builder_error(err: &rustls::Error) {
    assert!(
        matches!(err, rustls::Error::General(message) if message == BUILDER_ERROR),
        "unexpected error: {err:?}"
    );
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[test]
#[should_panic(expected = "failed to configure rustls client protocol versions")]
fn config_no_verify_panics_with_incompatible_provider() {
    install_provider_without_cipher_suites();
    rustls_tokio_postgres::config_no_verify();
}

#[cfg(all(feature = "webpki-roots", any(feature = "aws-lc-rs", feature = "ring")))]
#[test]
#[should_panic(expected = "failed to configure rustls client protocol versions")]
fn config_webpki_roots_panics_with_incompatible_provider() {
    install_provider_without_cipher_suites();
    rustls_tokio_postgres::config_webpki_roots();
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[test]
fn config_from_ca_cert_returns_tls_error_with_incompatible_provider() {
    install_provider_without_cipher_suites();

    let path = write_ca_file("incompatible-provider");
    let result = rustls_tokio_postgres::config_from_ca_cert(&path);
    std::fs::remove_file(&path).unwrap();

    match result {
        Err(rustls_tokio_postgres::CaCertError::Tls(err)) => assert_builder_error(&err),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[cfg(all(
    feature = "platform-verifier",
    any(feature = "aws-lc-rs", feature = "ring")
))]
#[test]
fn config_platform_verifier_returns_error_with_incompatible_provider() {
    install_provider_without_cipher_suites();
    match rustls_tokio_postgres::config_platform_verifier() {
        Err(err) => assert_builder_error(&err),
        Ok(_) => panic!("config unexpectedly succeeded"),
    }
}

#[cfg(all(feature = "native-roots", any(feature = "aws-lc-rs", feature = "ring")))]
#[test]
#[allow(deprecated)]
fn config_native_roots_returns_error_with_incompatible_provider() {
    use std::error::Error as _;

    install_provider_without_cipher_suites();
    let err =
        rustls_tokio_postgres::config_native_roots().expect_err("config unexpectedly succeeded");
    let source = err
        .source()
        .and_then(|source| source.downcast_ref::<rustls::Error>());
    assert_builder_error(source.expect("source is a rustls error"));
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
#[test]
#[should_panic(expected = "could not select a rustls CryptoProvider")]
fn config_no_verify_panics_without_provider() {
    rustls_tokio_postgres::config_no_verify();
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
#[test]
#[should_panic(expected = "could not select a rustls CryptoProvider")]
fn config_from_ca_cert_panics_without_provider_before_reading_file() {
    // The file does not exist. The provider check occurs first, so the
    // function panics and does not return a read error.
    let _ = rustls_tokio_postgres::config_from_ca_cert("/nonexistent/rustls-tokio-postgres.pem");
}

#[cfg(all(
    feature = "webpki-roots",
    not(any(feature = "aws-lc-rs", feature = "ring"))
))]
#[test]
#[should_panic(expected = "could not select a rustls CryptoProvider")]
fn config_webpki_roots_panics_without_provider() {
    rustls_tokio_postgres::config_webpki_roots();
}

#[cfg(all(
    feature = "platform-verifier",
    not(any(feature = "aws-lc-rs", feature = "ring"))
))]
#[test]
#[should_panic(expected = "could not select a rustls CryptoProvider")]
fn config_platform_verifier_panics_without_provider() {
    let _ = rustls_tokio_postgres::config_platform_verifier();
}
