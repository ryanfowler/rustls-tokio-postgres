use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect};
use tokio_rustls::{TlsConnector, client::TlsStream as RustlsTlsStream};

/// Performs the TLS handshake.
pub struct RustlsConnect {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<S>;
    type Error = io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        let connector = TlsConnector::from(self.config);
        let server_name = self.server_name;
        Box::pin(async move {
            let inner = connector.connect(server_name, stream).await?;
            Ok(TlsStream(inner))
        })
    }
}

/// Wrap tokio-rustls' stream so we can implement tokio_postgres' TlsStream on a local type.
pub struct TlsStream<S>(RustlsTlsStream<S>);

impl<S> tokio_postgres::tls::TlsStream for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[cfg(feature = "channel-binding")]
    fn channel_binding(&self) -> ChannelBinding {
        let (_io, common) = self.0.get_ref();
        let der = match common.peer_certificates().and_then(|cs| cs.first()) {
            Some(c) => c.as_ref(), // DER bytes of leaf cert
            None => return ChannelBinding::none(),
        };
        ChannelBinding::tls_server_end_point(tls_server_end_point_digest(der))
    }

    #[cfg(not(feature = "channel-binding"))]
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

// Delegate AsyncRead methods to the inner stream.
impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

// Delegate AsyncWrite methods to the inner stream.
impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Compute RFC 5929 "tls-server-end-point" digest for the cert.
///
/// Rule: use the cert **signature** hash (SHA-256/384/512),
/// but if it's MD5 or SHA-1 (or unknown), fall back to SHA-256.
#[cfg(feature = "channel-binding")]
fn tls_server_end_point_digest(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_parser::{oid_registry::*, prelude::*, signature_algorithm::RsaSsaPssParams};

    // Parse the certificate so we can inspect the signature algorithm OID.
    let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
        // If parsing fails, conservative SHA-256 fallback (still deterministic).
        return Sha256::digest(cert_der).to_vec();
    };

    let sig_oid = &x509.signature_algorithm.algorithm;

    // RSASSA-PSS: OID 1.2.840.113549.1.1.10, hash is in parameters
    if sig_oid == &OID_PKCS1_RSASSAPSS {
        if let Some(params_any) = x509.signature_algorithm.parameters()
            && let Ok(pss) = RsaSsaPssParams::try_from(params_any)
        {
            let alg = pss.hash_algorithm_oid();
            if alg == &OID_NIST_HASH_SHA512 {
                return Sha512::digest(cert_der).to_vec();
            }
            if alg == &OID_NIST_HASH_SHA384 {
                return Sha384::digest(cert_der).to_vec();
            }
        }
        return Sha256::digest(cert_der).to_vec();
    }

    // RSA PKCS#1 v1.5 with SHA-2
    if sig_oid == &OID_PKCS1_SHA256WITHRSA {
        return Sha256::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_SHA384WITHRSA {
        return Sha384::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_SHA512WITHRSA {
        return Sha512::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_PKCS1_MD5WITHRSAENC || sig_oid == &OID_PKCS1_SHA1WITHRSA {
        return Sha256::digest(cert_der).to_vec();
    }

    // ECDSA with SHA-2
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA384 {
        return Sha384::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA512 {
        return Sha512::digest(cert_der).to_vec();
    }

    Sha256::digest(cert_der).to_vec()
}
