#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! A [`tokio_postgres`] TLS connector backed by [`rustls`].
//!
//! # Example
//!
//! ```rust,no_run
//! use rustls_tokio_postgres::{config_no_verify, MakeRustlsConnect};
//! use tokio_postgres::{connect, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     static CONFIG: &str = "host=localhost user=postgres";
//!
//!     // This rustls config does not verify the server certificate.
//!     // You can construct your own rustls ClientConfig, or enable the
//!     // `native-roots` or `webpki-roots` features for other config helpers.
//!     let config = config_no_verify();
//!
//!     // Create the client with the TLS configuration.
//!     let tls = MakeRustlsConnect::new(config);
//!     let (_client, _conn) = connect(CONFIG, tls).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **aws-lc-rs**: enables rustls' AWS-LC-RS crypto provider. Enabled by default.
//! - **channel-binding**: enables TLS channel binding, if supported.
//! - **fips**: enables rustls' AWS-LC-RS FIPS provider support.
//! - **logging**: enables rustls logging. Enabled by default.
//! - **native-roots**: enables a helper function for creating a [`rustls::ClientConfig`] using the native roots of your OS.
//! - **prefer-post-quantum**: enables rustls' post-quantum-preferred AWS-LC-RS key exchange ordering. Enabled by default.
//! - **ring**: enables rustls' ring crypto provider. Use `default-features = false` if you want ring without AWS-LC-RS.
//! - **tls12**: enables rustls TLS 1.2 support. Enabled by default.
//! - **webpki-roots**: enables a helper function for creating a [`rustls::ClientConfig`] using the webpki roots.

use std::{io, sync::Arc};

use rustls::ClientConfig;
use rustls_pki_types::{InvalidDnsNameError, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::MakeTlsConnect;

mod config;
mod connect;

pub use config::config_no_verify;
#[cfg(feature = "webpki-roots")]
pub use config::config_webpki_roots;
#[cfg(feature = "native-roots")]
pub use config::{NativeRootsError, config_native_roots};
pub use rustls;
pub use tokio_postgres;

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

    fn make_tls_connect(&mut self, hostname: &str) -> Result<Self::TlsConnect, Self::Error> {
        let server_name = ServerName::try_from(hostname)
            .map_err(|e: InvalidDnsNameError| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
            .to_owned();

        Ok(connect::RustlsConnect {
            config: self.config.clone(),
            server_name,
        })
    }
}
