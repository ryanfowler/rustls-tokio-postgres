use std::{io, sync::Arc};

use rustls::ClientConfig;
use rustls_pki_types::{InvalidDnsNameError, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::tls::MakeTlsConnect;

mod config;
mod connect;

#[cfg(feature = "native-roots")]
pub use config::config_native_roots;
pub use config::config_no_verify;
pub use rustls;

/// A MakeTlsConnect implementation that uses rustls.
#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
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
