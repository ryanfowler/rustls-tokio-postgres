use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{ClientConfig, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect};
use tokio_rustls::{
    TlsConnector,
    client::{Connect as RustlsHandshake, TlsStream as RustlsTlsStream},
};

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
    type Future = RustlsConnectFuture<S>;

    fn connect(self, stream: S) -> Self::Future {
        let connector = TlsConnector::from(self.config);
        let server_name = self.server_name;
        RustlsConnectFuture {
            inner: connector.connect(server_name, stream),
        }
    }
}

/// Future returned by [`RustlsConnect::connect`].
pub struct RustlsConnectFuture<S> {
    inner: RustlsHandshake<S>,
}

impl<S> Future for RustlsConnectFuture<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<S>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(TlsStream(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
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
        match tls_server_end_point_digest(der) {
            Some(digest) => ChannelBinding::tls_server_end_point(digest),
            None => ChannelBinding::none(),
        }
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
/// but if it's MD5 or SHA-1, fall back to SHA-256.
///
/// If the certificate cannot be parsed or the signature algorithm is unknown,
/// return `None` so callers can opt out of channel binding.
#[cfg(feature = "channel-binding")]
fn tls_server_end_point_digest(cert_der: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_parser::{oid_registry::*, prelude::*, signature_algorithm::RsaSsaPssParams};

    // Parse the certificate so we can inspect the signature algorithm OID.
    let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
        return None;
    };

    let sig_oid = &x509.signature_algorithm.algorithm;

    // RSASSA-PSS: OID 1.2.840.113549.1.1.10, hash is in parameters
    if sig_oid == &OID_PKCS1_RSASSAPSS {
        let params_any = x509.signature_algorithm.parameters()?;
        let pss = RsaSsaPssParams::try_from(params_any).ok()?;
        let alg = pss.hash_algorithm_oid();
        if alg == &OID_NIST_HASH_SHA512 {
            return Some(Sha512::digest(cert_der).to_vec());
        }
        if alg == &OID_NIST_HASH_SHA384 {
            return Some(Sha384::digest(cert_der).to_vec());
        }
        if alg == &OID_NIST_HASH_SHA256 || alg == &OID_HASH_SHA1 {
            return Some(Sha256::digest(cert_der).to_vec());
        }
        return None;
    }

    // RSA PKCS#1 v1.5 with SHA-2
    if sig_oid == &OID_PKCS1_SHA256WITHRSA {
        return Some(Sha256::digest(cert_der).to_vec());
    }
    if sig_oid == &OID_PKCS1_SHA384WITHRSA {
        return Some(Sha384::digest(cert_der).to_vec());
    }
    if sig_oid == &OID_PKCS1_SHA512WITHRSA {
        return Some(Sha512::digest(cert_der).to_vec());
    }
    if sig_oid == &OID_PKCS1_MD5WITHRSAENC
        || sig_oid == &OID_PKCS1_SHA1WITHRSA
        || sig_oid == &OID_SHA1_WITH_RSA
    {
        return Some(Sha256::digest(cert_der).to_vec());
    }

    // ECDSA with SHA-2
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA256 {
        return Some(Sha256::digest(cert_der).to_vec());
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA384 {
        return Some(Sha384::digest(cert_der).to_vec());
    }
    if sig_oid == &OID_SIG_ECDSA_WITH_SHA512 {
        return Some(Sha512::digest(cert_der).to_vec());
    }

    None
}

#[cfg(all(test, feature = "channel-binding"))]
mod tests {
    use super::tls_server_end_point_digest;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    const OID_HASH_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
    const OID_NIST_HASH_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    const OID_NIST_HASH_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    const OID_NIST_HASH_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
    const OID_PKCS1_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    const OID_PKCS1_SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
    const OID_PKCS1_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
    const OID_PKCS1_SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
    const OID_PKCS1_SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
    const OID_PKCS1_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];

    fn assert_digest<D: Digest>(der: &[u8], expected_len: usize) {
        let result = tls_server_end_point_digest(der).unwrap();
        let expected = D::digest(der).to_vec();
        assert_eq!(result, expected);
        assert_eq!(result.len(), expected_len);
    }

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(contents.len()));
        out.extend(contents);
        out
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 128 {
            return vec![len as u8];
        }

        let bytes = len.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("non-zero long-form DER length");
        let significant = &bytes[first_non_zero..];
        let mut out = vec![0x80 | significant.len() as u8];
        out.extend(significant);
        out
    }

    fn der_sequence(contents: &[u8]) -> Vec<u8> {
        der(0x30, contents)
    }

    fn der_null() -> Vec<u8> {
        der(0x05, &[])
    }

    fn der_integer_u8(value: u8) -> Vec<u8> {
        der(0x02, &[value])
    }

    fn der_utc_time(value: &[u8]) -> Vec<u8> {
        der(0x17, value)
    }

    fn der_bit_string(value: &[u8]) -> Vec<u8> {
        let mut contents = vec![0];
        contents.extend(value);
        der(0x03, &contents)
    }

    fn der_context_specific_constructed(tag: u8, contents: &[u8]) -> Vec<u8> {
        der(0xa0 | tag, contents)
    }

    fn der_oid(arcs: &[u64]) -> Vec<u8> {
        assert!(arcs.len() >= 2);
        assert!(arcs[0] <= 2);
        assert!(arcs[1] < 40 || arcs[0] == 2);

        let mut contents = Vec::new();
        encode_oid_arc(arcs[0] * 40 + arcs[1], &mut contents);
        for arc in &arcs[2..] {
            encode_oid_arc(*arc, &mut contents);
        }
        der(0x06, &contents)
    }

    fn encode_oid_arc(mut arc: u64, out: &mut Vec<u8>) {
        let mut encoded = [0u8; 10];
        let mut i = encoded.len();
        i -= 1;
        encoded[i] = (arc & 0x7f) as u8;
        arc >>= 7;

        while arc != 0 {
            i -= 1;
            encoded[i] = ((arc & 0x7f) as u8) | 0x80;
            arc >>= 7;
        }

        out.extend(&encoded[i..]);
    }

    fn algorithm_identifier(oid: &[u64], parameters: Option<Vec<u8>>) -> Vec<u8> {
        let mut contents = der_oid(oid);
        if let Some(parameters) = parameters {
            contents.extend(parameters);
        }
        der_sequence(&contents)
    }

    fn rsa_pkcs1_algorithm_identifier(oid: &[u64]) -> Vec<u8> {
        algorithm_identifier(oid, Some(der_null()))
    }

    fn rsa_pss_algorithm_identifier(hash_oid: &[u64]) -> Vec<u8> {
        let hash_algorithm = algorithm_identifier(hash_oid, None);
        let params = der_sequence(&der_context_specific_constructed(0, &hash_algorithm));
        algorithm_identifier(OID_PKCS1_RSASSA_PSS, Some(params))
    }

    fn cert_der_with_signature_algorithm(signature_algorithm: &[u8]) -> Vec<u8> {
        let spki_algorithm = algorithm_identifier(OID_PKCS1_RSA_ENCRYPTION, Some(der_null()));
        let mut spki_contents = spki_algorithm;
        spki_contents.extend(der_bit_string(&[]));
        let spki = der_sequence(&spki_contents);

        let mut validity_contents = der_utc_time(b"700101000000Z");
        validity_contents.extend(der_utc_time(b"700102000000Z"));
        let validity = der_sequence(&validity_contents);

        let mut tbs_contents = der_integer_u8(1);
        tbs_contents.extend(signature_algorithm);
        tbs_contents.extend(der_sequence(&[]));
        tbs_contents.extend(validity);
        tbs_contents.extend(der_sequence(&[]));
        tbs_contents.extend(spki);
        let tbs = der_sequence(&tbs_contents);

        let mut cert_contents = tbs;
        cert_contents.extend(signature_algorithm);
        cert_contents.extend(der_bit_string(&[]));
        der_sequence(&cert_contents)
    }

    #[test]
    fn digest_invalid_der_is_unsupported() {
        let garbage = b"not a valid certificate";
        let result = tls_server_end_point_digest(garbage);
        assert_eq!(result, None);
    }

    #[test]
    fn digest_ecdsa_sha256_cert() {
        // Generate an ECDSA P-256 cert (signs with ecdsa-with-SHA256).
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let result = tls_server_end_point_digest(der).unwrap();
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

        let result = tls_server_end_point_digest(der).unwrap();
        let expected = Sha384::digest(der).to_vec();
        assert_eq!(result, expected);
        assert_eq!(result.len(), 48); // SHA-384 = 48 bytes
    }

    #[test]
    fn digest_rsa_pkcs1_sha256_cert() {
        let signature_algorithm = rsa_pkcs1_algorithm_identifier(OID_PKCS1_SHA256_WITH_RSA);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_rsa_pkcs1_sha384_cert() {
        let signature_algorithm = rsa_pkcs1_algorithm_identifier(OID_PKCS1_SHA384_WITH_RSA);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha384>(&der, 48);
    }

    #[test]
    fn digest_rsa_pkcs1_sha512_cert() {
        let signature_algorithm = rsa_pkcs1_algorithm_identifier(OID_PKCS1_SHA512_WITH_RSA);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha512>(&der, 64);
    }

    #[test]
    fn digest_rsa_pss_sha256_cert() {
        let signature_algorithm = rsa_pss_algorithm_identifier(OID_NIST_HASH_SHA256);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_rsa_pss_sha384_cert() {
        let signature_algorithm = rsa_pss_algorithm_identifier(OID_NIST_HASH_SHA384);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha384>(&der, 48);
    }

    #[test]
    fn digest_rsa_pss_sha512_cert() {
        let signature_algorithm = rsa_pss_algorithm_identifier(OID_NIST_HASH_SHA512);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha512>(&der, 64);
    }

    #[test]
    fn digest_rsa_pss_sha1_cert_falls_back_to_sha256() {
        let signature_algorithm = rsa_pss_algorithm_identifier(OID_HASH_SHA1);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_sha1_cert_falls_back_to_sha256() {
        let signature_algorithm = rsa_pkcs1_algorithm_identifier(OID_PKCS1_SHA1_WITH_RSA);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_ed25519_cert_is_unsupported() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test.local".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().as_ref();

        let result = tls_server_end_point_digest(der);
        assert_eq!(result, None);
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
