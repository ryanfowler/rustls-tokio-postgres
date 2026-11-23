#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! A [`tokio_postgres`] TLS connector backed by [`rustls`].
//!
//! # Usage
//!
//! Prefer a verifying TLS configuration for normal application code. This crate
//! provides helpers for explicit CA certificate files, the platform verifier,
//! and the Mozilla WebPKI trust store behind optional features.
//!
//! ## TLS modes
//!
//! tokio-postgres accepts three `sslmode` values: `disable`, `prefer` and
//! `require`. It does not accept the libpq values `verify-ca` and
//! `verify-full`. The default is `prefer`.
//!
//! This crate does not decide whether to verify the server. The
//! [`rustls::ClientConfig`] decides. With a verifying TLS configuration, such
//! as one from [`config_from_ca_cert()`], every TLS connection verifies the
//! server certificate chain and the hostname. This is the same as libpq's
//! `verify-full` mode. With [`config_no_verify()`], the client does not verify
//! the certificate chain or the hostname.
//!
//! - **`require`**: The connection fails if the server does not support TLS.
//!   Use `require` with a verifying TLS configuration in production.
//! - **`prefer`**: If the server does not support TLS, the client continues
//!   without encryption. An attacker between the client and the server can make
//!   the server seem to refuse TLS. The client then sends all data in
//!   plaintext. With `password` or `md5` authentication, the plaintext data
//!   includes the password or its hash. `sslnegotiation=direct` does not accept
//!   `prefer`.
//! - **`disable`**: The client does not use TLS.
//!
//! A certificate error stops the connection to that host. If the config has
//! more than one host, the client then tries the next host. Under `prefer`, the
//! next host can connect without TLS.
//!
//! TLS needs a `host` value. If the config has only `hostaddr`, the TLS
//! handshake fails. Certificate verification uses the `host` value, not the
//! `hostaddr` value.
//!
//! ## Crypto providers
//!
//! Config helpers use an already-installed rustls
//! [`CryptoProvider`](rustls::crypto::CryptoProvider) when one exists. Otherwise
//! they choose AWS-LC-RS when this crate's `aws-lc-rs` feature is enabled, or
//! ring when only the `ring` feature is enabled. They do not install a
//! process-global provider.
//!
//! In custom-provider or no-provider builds, install a provider before using
//! these helpers.
//!
//! ## Direct SSL negotiation
//!
//! PostgreSQL 17 and later accept `sslnegotiation=direct`. This option needs
//! tokio-postgres 0.7.13 or later. In this mode, the client starts the TLS
//! handshake at once. The server then requires the ALPN protocol
//! [`POSTGRES_ALPN`].
//!
//! All config helpers in this crate set this ALPN protocol. If you build your
//! own [`rustls::ClientConfig`], set it yourself:
//!
//! ```rust
//! # fn set_alpn(mut config: rustls_tokio_postgres::rustls::ClientConfig) {
//! config.alpn_protocols = vec![rustls_tokio_postgres::POSTGRES_ALPN.to_vec()];
//! # }
//! ```
//!
//! The ALPN protocol does not affect the default `sslnegotiation=postgres`
//! mode. CI tests this mode with PostgreSQL 14, 16, 17 and 18.
//!
//! ## Platform verifier
//!
//! Enable the `platform-verifier` feature to use certificate verification
//! provided by the current platform.
//!
//! ```rust,no_run
//! # #[cfg(feature = "platform-verifier")]
//! # {
//! use rustls_tokio_postgres::{config_platform_verifier, MakeRustlsConnect};
//! use tokio_postgres::connect;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! static CONFIG: &str = "host=localhost user=postgres sslmode=require";
//!
//! let tls = MakeRustlsConnect::new(config_platform_verifier()?);
//!
//! let (client, connection) = connect(CONFIG, tls).await?;
//! tokio::spawn(async move {
//!     if let Err(err) = connection.await {
//!         eprintln!("postgres connection error: {err}");
//!     }
//! });
//!
//! Ok(())
//! # }
//! # }
//! ```
//!
//! ## WebPKI roots
//!
//! Enable the `webpki-roots` feature to use the trust anchors from the
//! `webpki-roots` crate.
//!
//! ```rust,no_run
//! # #[cfg(feature = "webpki-roots")]
//! # {
//! use rustls_tokio_postgres::{config_webpki_roots, MakeRustlsConnect};
//! use tokio_postgres::connect;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! static CONFIG: &str = "host=localhost user=postgres sslmode=require";
//!
//! let tls = MakeRustlsConnect::new(config_webpki_roots());
//!
//! let (client, connection) = connect(CONFIG, tls).await?;
//! tokio::spawn(async move {
//!     if let Err(err) = connection.await {
//!         eprintln!("postgres connection error: {err}");
//!     }
//! });
//!
//! Ok(())
//! # }
//! # }
//! ```
//!
//! ## CA certificate
//!
//! Use [`config_from_ca_cert()`] when a provider publishes a CA certificate file
//! or bundle for verifying its database servers.
//!
//! ```rust,no_run
//! use rustls_tokio_postgres::{config_from_ca_cert, MakeRustlsConnect};
//! use tokio_postgres::connect;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! static CONFIG: &str = "host=localhost user=postgres sslmode=require";
//!
//! let tls = MakeRustlsConnect::new(config_from_ca_cert("ca.pem")?);
//!
//! let (client, connection) = connect(CONFIG, tls).await?;
//! tokio::spawn(async move {
//!     if let Err(err) = connection.await {
//!         eprintln!("postgres connection error: {err}");
//!     }
//! });
//!
//! Ok(())
//! # }
//! ```
//!
//! ## Dangerous fallback: no certificate verification
//!
//! [`config_no_verify()`] is dangerous because it disables server certificate
//! and hostname verification. TLS still encrypts traffic, but the client no
//! longer knows whether it is connected to the intended PostgreSQL server,
//! which makes man-in-the-middle attacks possible.
//!
//! Use this only for local development, tests, or tightly controlled
//! environments where server identity is verified by another trusted mechanism.
//! Prefer `config_from_ca_cert()`, `config_platform_verifier()`,
//! `config_webpki_roots()`, or a custom [`rustls::ClientConfig`] with an
//! explicit root store for production systems.
//!
//! ### Mitigation: SCRAM channel binding
//!
//! If you must use [`config_no_verify()`], add `channel_binding=require` to the
//! connection string. With this option, tokio-postgres accepts only
//! SCRAM-SHA-256-PLUS authentication. Other authentication methods fail.
//!
//! SCRAM-SHA-256-PLUS binds the authentication to the server certificate that
//! the client received. An attacker between the client and the server that does
//! not have the server's private key must show a different certificate. The
//! real server then rejects the authentication, so the attacker cannot relay
//! the connection. The client also checks the SCRAM server signature. Only a
//! server that has the SCRAM verifier for the user can make this signature.
//!
//! This mitigation has limits:
//!
//! - The client sends its SCRAM proof before it checks the server signature. An
//!   attacker can collect this proof and guess the password offline. The
//!   attacker also sees the user name and the database name. Use a long, random
//!   password.
//! - An attacker that has the SCRAM verifier, for example from a database
//!   backup, can act as the server. The attacker can then read and change all
//!   queries and results.
//! - An attacker that has the server's private key can relay the connection.
//! - The server must use SCRAM-SHA-256 password authentication, and it must
//!   store the password as a SCRAM-SHA-256 verifier. Trust and certificate
//!   authentication fail.
//! - The server certificate must use a signature algorithm that supports
//!   channel binding. For example, an Ed25519 certificate fails with the error
//!   "server did not use channel binding".
//! - The `channel-binding` feature must be enabled. It is enabled by default.
//!
//! ```rust,no_run
//! use rustls_tokio_postgres::{config_no_verify, MakeRustlsConnect};
//! use tokio_postgres::connect;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! static CONFIG: &str =
//!     "host=localhost user=postgres sslmode=require channel_binding=require";
//!
//! let config = config_no_verify();
//!
//! let tls = MakeRustlsConnect::new(config);
//! let (client, connection) = connect(CONFIG, tls).await?;
//! tokio::spawn(async move {
//!     if let Err(err) = connection.await {
//!         eprintln!("postgres connection error: {err}");
//!     }
//! });
//!
//! Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - **aws-lc-rs**: enables rustls' AWS-LC-RS crypto provider. Enabled by default.
//! - **channel-binding**: enables TLS channel binding, if supported. Enabled by default.
//! - **fips**: enables rustls' AWS-LC-RS FIPS provider support.
//! - **logging**: enables rustls logging. Enabled by default.
//! - **native-roots**: deprecated alias for **platform-verifier**.
//! - **platform-verifier**: enables a helper function for creating a [`rustls::ClientConfig`] using the platform certificate verifier.
//! - **prefer-post-quantum**: enables rustls' post-quantum-preferred AWS-LC-RS key exchange ordering. Enabled by default.
//! - **ring**: enables rustls' ring crypto provider. Use `default-features = false` if you want ring without AWS-LC-RS.
//! - **tls12**: enables rustls TLS 1.2 support. Enabled by default.
//! - **webpki-roots**: enables a helper function for creating a [`rustls::ClientConfig`] using the webpki roots.

use std::{io, sync::Arc};

use rustls::{ClientConfig, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::MakeTlsConnect;

mod config;
mod connect;

pub use config::config_no_verify;
#[cfg(feature = "platform-verifier")]
pub use config::config_platform_verifier;
#[cfg(feature = "webpki-roots")]
pub use config::config_webpki_roots;
pub use config::{CaCertError, config_from_ca_cert};
#[cfg(feature = "native-roots")]
#[allow(deprecated)]
pub use config::{NativeRootsError, config_native_roots};
pub use rustls;
pub use tokio_postgres;

/// The ALPN protocol name for PostgreSQL connections.
///
/// PostgreSQL 17 and later require this protocol for connections that use
/// `sslnegotiation=direct`.
pub const POSTGRES_ALPN: &[u8] = b"postgresql";

/// A MakeTlsConnect implementation that uses rustls.
#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
    /// Construct a new `MakeRustlsConnect` instance with the provided [`ClientConfig`].
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> MakeTlsConnect<S> for MakeRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = connect::TlsStream<S>;
    type TlsConnect = connect::RustlsConnect;
    type Error = io::Error;

    /// Prepares a TLS connection to `hostname`.
    ///
    /// tokio-postgres calls this function for every connection, even when TLS
    /// is off. For a Unix socket or a `hostaddr`-only config, the hostname is
    /// empty. So this function does not fail for an invalid hostname. The
    /// handshake returns an [`io::Error`] of kind
    /// [`InvalidInput`](io::ErrorKind::InvalidInput).
    fn make_tls_connect(&mut self, hostname: &str) -> Result<Self::TlsConnect, Self::Error> {
        let server_name = ServerName::try_from(hostname)
            .map(|name| name.to_owned())
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid hostname {hostname:?} for TLS: {err}"),
                )
            });

        Ok(connect::RustlsConnect {
            config: self.config.clone(),
            server_name,
        })
    }
}
