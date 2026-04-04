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
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
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
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
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
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA256 {
        return Sha256::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA384 {
        return Sha384::digest(cert_der).to_vec();
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA512 {
        return Sha512::digest(cert_der).to_vec();
    }

    Sha256::digest(cert_der).to_vec()
}

#[cfg(all(test, feature = "channel-binding"))]
mod tests {
    use super::tls_server_end_point_digest;
    use sha2::{Digest, Sha256, Sha384};

    #[test]
    fn digest_invalid_der_falls_back_to_sha256() {
        let garbage = b"not a valid certificate";
        let result = tls_server_end_point_digest(garbage);
        let expected = Sha256::digest(garbage).to_vec();
        assert_eq!(result, expected);
    }

    #[test]
    fn digest_ecdsa_sha256_cert() {
        // Generate an ECDSA P-256 cert (signs with ecdsa-with-SHA256).
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let result = tls_server_end_point_digest(der);
        let expected = Sha256::digest(der).to_vec();
        assert_eq!(result, expected);
        assert_eq!(result.len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn digest_ecdsa_sha384_cert() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let result = tls_server_end_point_digest(der);
        let expected = Sha384::digest(der).to_vec();
        assert_eq!(result, expected);
        assert_eq!(result.len(), 48); // SHA-384 = 48 bytes
    }

    #[test]
    fn digest_ed25519_cert_falls_back_to_sha256() {
        // Ed25519 is not in the explicit OID list, so should fall back to SHA-256.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let result = tls_server_end_point_digest(der);
        let expected = Sha256::digest(der).to_vec();
        assert_eq!(result, expected);
    }

    #[test]
    fn digest_is_deterministic() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let a = tls_server_end_point_digest(der);
        let b = tls_server_end_point_digest(der);
        assert_eq!(a, b);
    }
}
