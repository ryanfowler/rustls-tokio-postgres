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
        Pin::new(&mut self.inner).poll(cx).map(|r| r.map(TlsStream))
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
/// Rule: use the certificate signature hash, but if it is MD5 or SHA-1,
/// fall back to SHA-256.
///
/// If the certificate cannot be parsed or the signature algorithm is unknown,
/// return `None` so callers can opt out of channel binding.
#[cfg(feature = "channel-binding")]
fn tls_server_end_point_digest(cert_der: &[u8]) -> Option<Vec<u8>> {
    use md2::Md2;
    use md4::Md4;
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
    use sha3::{
        Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    use x509_parser::{
        asn1_rs::{Oid, oid},
        oid_registry::OID_PKCS1_RSASSAPSS,
        prelude::*,
        signature_algorithm::RsaSsaPssParams,
    };

    #[derive(Clone, Copy)]
    enum HashAlgorithm {
        Md2,
        Md4,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha512_224,
        Sha512_256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Shake128,
        Shake256,
    }

    fn hash_for_oid(oid: &Oid<'_>) -> Option<HashAlgorithm> {
        // RFC 5929 requires SHA-256 for MD5 and SHA-1 signatures.
        if oid == &oid!(1.2.840.113549.2.5) || oid == &oid!(1.3.14.3.2.26) {
            return Some(HashAlgorithm::Sha256);
        }

        [
            (oid!(2.16.840.1.101.3.4.2.4), HashAlgorithm::Sha224),
            (oid!(2.16.840.1.101.3.4.2.1), HashAlgorithm::Sha256),
            (oid!(2.16.840.1.101.3.4.2.2), HashAlgorithm::Sha384),
            (oid!(2.16.840.1.101.3.4.2.3), HashAlgorithm::Sha512),
            (oid!(2.16.840.1.101.3.4.2.5), HashAlgorithm::Sha512_224),
            (oid!(2.16.840.1.101.3.4.2.6), HashAlgorithm::Sha512_256),
            (oid!(2.16.840.1.101.3.4.2.7), HashAlgorithm::Sha3_224),
            (oid!(2.16.840.1.101.3.4.2.8), HashAlgorithm::Sha3_256),
            (oid!(2.16.840.1.101.3.4.2.9), HashAlgorithm::Sha3_384),
            (oid!(2.16.840.1.101.3.4.2.10), HashAlgorithm::Sha3_512),
        ]
        .into_iter()
        .find_map(|(candidate, hash)| (oid == &candidate).then_some(hash))
    }

    fn hash_for_signature_oid(oid: &Oid<'_>) -> Option<HashAlgorithm> {
        if oid == &oid!(1.2.840.113549.1.1.2) {
            return Some(HashAlgorithm::Md2);
        }
        if oid == &oid!(1.2.840.113549.1.1.3) {
            return Some(HashAlgorithm::Md4);
        }

        let sha256_fallback = [
            oid!(1.2.840.113549.1.1.4), // md5WithRSAEncryption
            oid!(1.2.840.113549.1.1.5), // sha1WithRSAEncryption
            oid!(1.3.14.3.2.29),        // sha1WithRSA (OIW)
            oid!(1.3.14.3.2.25),        // md5WithRSA (OIW)
            oid!(1.2.840.10040.4.3),    // dsa-with-sha1
            oid!(1.2.840.10045.4.1),    // ecdsa-with-SHA1
        ];
        if sha256_fallback.iter().any(|candidate| oid == candidate) {
            return Some(HashAlgorithm::Sha256);
        }

        let signatures = [
            (oid!(1.2.840.113549.1.1.14), HashAlgorithm::Sha224),
            (oid!(1.2.840.10045.4.3.1), HashAlgorithm::Sha224),
            (oid!(2.16.840.1.101.3.4.3.1), HashAlgorithm::Sha224),
            (oid!(1.2.840.113549.1.1.11), HashAlgorithm::Sha256),
            (oid!(1.2.840.10045.4.3.2), HashAlgorithm::Sha256),
            (oid!(2.16.840.1.101.3.4.3.2), HashAlgorithm::Sha256),
            (oid!(1.2.840.113549.1.1.12), HashAlgorithm::Sha384),
            (oid!(1.2.840.10045.4.3.3), HashAlgorithm::Sha384),
            (oid!(1.2.840.113549.1.1.13), HashAlgorithm::Sha512),
            (oid!(1.2.840.10045.4.3.4), HashAlgorithm::Sha512),
            (oid!(2.16.840.1.101.3.4.3.3), HashAlgorithm::Sha384),
            (oid!(2.16.840.1.101.3.4.3.4), HashAlgorithm::Sha512),
            (oid!(1.2.840.113549.1.1.15), HashAlgorithm::Sha512_224),
            (oid!(1.2.840.113549.1.1.16), HashAlgorithm::Sha512_256),
            (oid!(2.16.840.1.101.3.4.3.5), HashAlgorithm::Sha3_224),
            (oid!(2.16.840.1.101.3.4.3.9), HashAlgorithm::Sha3_224),
            (oid!(2.16.840.1.101.3.4.3.13), HashAlgorithm::Sha3_224),
            (oid!(2.16.840.1.101.3.4.3.6), HashAlgorithm::Sha3_256),
            (oid!(2.16.840.1.101.3.4.3.10), HashAlgorithm::Sha3_256),
            (oid!(2.16.840.1.101.3.4.3.14), HashAlgorithm::Sha3_256),
            (oid!(2.16.840.1.101.3.4.3.7), HashAlgorithm::Sha3_384),
            (oid!(2.16.840.1.101.3.4.3.11), HashAlgorithm::Sha3_384),
            (oid!(2.16.840.1.101.3.4.3.15), HashAlgorithm::Sha3_384),
            (oid!(2.16.840.1.101.3.4.3.8), HashAlgorithm::Sha3_512),
            (oid!(2.16.840.1.101.3.4.3.12), HashAlgorithm::Sha3_512),
            (oid!(2.16.840.1.101.3.4.3.16), HashAlgorithm::Sha3_512),
            (oid!(1.3.6.1.5.5.7.6.30), HashAlgorithm::Shake128),
            (oid!(1.3.6.1.5.5.7.6.31), HashAlgorithm::Shake256),
            (oid!(1.3.6.1.5.5.7.6.32), HashAlgorithm::Shake128),
            (oid!(1.3.6.1.5.5.7.6.33), HashAlgorithm::Shake256),
        ];
        signatures
            .into_iter()
            .find_map(|(candidate, hash)| (oid == &candidate).then_some(hash))
    }

    let (_, x509) = X509Certificate::from_der(cert_der).ok()?;
    let signature_algorithm = &x509.signature_algorithm;
    let hash = if signature_algorithm.algorithm == OID_PKCS1_RSASSAPSS {
        let params = signature_algorithm.parameters()?;
        let pss = RsaSsaPssParams::try_from(params).ok()?;
        let hash_oid = pss.hash_algorithm_oid();
        let mask = pss.mask_gen_algorithm().ok()?;
        if mask.mgf != oid!(1.2.840.113549.1.1.8) || &mask.hash != hash_oid {
            return None;
        }
        hash_for_oid(hash_oid)?
    } else {
        hash_for_signature_oid(&signature_algorithm.algorithm)?
    };

    Some(match hash {
        HashAlgorithm::Md2 => Md2::digest(cert_der).to_vec(),
        HashAlgorithm::Md4 => Md4::digest(cert_der).to_vec(),
        HashAlgorithm::Sha224 => Sha224::digest(cert_der).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(cert_der).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(cert_der).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(cert_der).to_vec(),
        HashAlgorithm::Sha512_224 => Sha512_224::digest(cert_der).to_vec(),
        HashAlgorithm::Sha512_256 => Sha512_256::digest(cert_der).to_vec(),
        HashAlgorithm::Sha3_224 => Sha3_224::digest(cert_der).to_vec(),
        HashAlgorithm::Sha3_256 => Sha3_256::digest(cert_der).to_vec(),
        HashAlgorithm::Sha3_384 => Sha3_384::digest(cert_der).to_vec(),
        HashAlgorithm::Sha3_512 => Sha3_512::digest(cert_der).to_vec(),
        HashAlgorithm::Shake128 => {
            let mut hash = Shake128::default();
            Update::update(&mut hash, cert_der);
            let mut digest = vec![0; 32];
            hash.finalize_xof().read(&mut digest);
            digest
        }
        HashAlgorithm::Shake256 => {
            let mut hash = Shake256::default();
            Update::update(&mut hash, cert_der);
            let mut digest = vec![0; 64];
            hash.finalize_xof().read(&mut digest);
            digest
        }
    })
}

#[cfg(all(test, feature = "channel-binding"))]
mod tests {
    use super::tls_server_end_point_digest;
    use md2::Md2;
    use md4::Md4;
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
    use sha3::{
        Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    const OID_HASH_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
    const OID_NIST_HASH_SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 4];
    const OID_NIST_HASH_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    const OID_NIST_HASH_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    const OID_NIST_HASH_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
    const OID_SIG_DSA_WITH_SHA1: &[u64] = &[1, 2, 840, 10040, 4, 3];
    const OID_SIG_DSA_WITH_SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 1];
    const OID_SIG_DSA_WITH_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 2];
    const OID_SIG_ECDSA_WITH_SHA1: &[u64] = &[1, 2, 840, 10045, 4, 1];
    const OID_SIG_ECDSA_WITH_SHA224: &[u64] = &[1, 2, 840, 10045, 4, 3, 1];
    const OID_SIG_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    const OID_SIG_ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
    const OID_SIG_ED25519: &[u64] = &[1, 3, 101, 112];
    const OID_PKCS1_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    const OID_PKCS1_MGF1: &[u64] = &[1, 2, 840, 113549, 1, 1, 8];
    const OID_PKCS1_SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
    const OID_PKCS1_SHA224_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 14];
    const OID_PKCS1_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
    const OID_PKCS1_SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
    const OID_PKCS1_SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
    const OID_PKCS1_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];

    type DigestCase<'a> = (&'a [u64], fn(&[u8]));

    fn assert_digest<D: Digest>(der: &[u8], expected_len: usize) {
        let result = tls_server_end_point_digest(der).unwrap();
        let expected = D::digest(der).to_vec();
        assert_eq!(result, expected);
        assert_eq!(result.len(), expected_len);
    }

    fn assert_shake<X: Default + Update + ExtendableOutput>(der: &[u8], expected_len: usize) {
        let mut hash = X::default();
        hash.update(der);
        let mut expected = vec![0; expected_len];
        hash.finalize_xof().read(&mut expected);
        assert_eq!(tls_server_end_point_digest(der).unwrap(), expected);
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
        rsa_pss_algorithm_identifier_with_mask(hash_oid, OID_PKCS1_MGF1, hash_oid)
    }

    fn rsa_pss_algorithm_identifier_with_mask(
        hash_oid: &[u64],
        mask_oid: &[u64],
        mask_hash_oid: &[u64],
    ) -> Vec<u8> {
        let hash_algorithm = algorithm_identifier(hash_oid, None);
        let mask_hash_algorithm = algorithm_identifier(mask_hash_oid, None);
        let mask_algorithm = algorithm_identifier(mask_oid, Some(mask_hash_algorithm));
        let mut params = der_context_specific_constructed(0, &hash_algorithm);
        params.extend(der_context_specific_constructed(1, &mask_algorithm));
        algorithm_identifier(OID_PKCS1_RSASSA_PSS, Some(der_sequence(&params)))
    }

    fn rsa_pss_algorithm_identifier_without_mask(hash_oid: &[u64]) -> Vec<u8> {
        let hash_algorithm = algorithm_identifier(hash_oid, None);
        let params = der_sequence(&der_context_specific_constructed(0, &hash_algorithm));
        algorithm_identifier(OID_PKCS1_RSASSA_PSS, Some(params))
    }

    fn rsa_pss_algorithm_identifier_with_defaults() -> Vec<u8> {
        algorithm_identifier(OID_PKCS1_RSASSA_PSS, Some(der_sequence(&[])))
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
    fn digest_new_sha2_signature_algorithms() {
        let cases: &[DigestCase<'_>] = &[
            (OID_PKCS1_SHA224_WITH_RSA, |der| {
                assert_digest::<Sha224>(der, 28)
            }),
            (OID_SIG_ECDSA_WITH_SHA1, |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (OID_SIG_ECDSA_WITH_SHA224, |der| {
                assert_digest::<Sha224>(der, 28)
            }),
            (OID_SIG_DSA_WITH_SHA1, |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (OID_SIG_DSA_WITH_SHA224, |der| {
                assert_digest::<Sha224>(der, 28)
            }),
            (OID_SIG_DSA_WITH_SHA256, |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 3], |der| {
                assert_digest::<Sha384>(der, 48)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 4], |der| {
                assert_digest::<Sha512>(der, 64)
            }),
            (&[1, 2, 840, 113549, 1, 1, 15], |der| {
                assert_digest::<Sha512_224>(der, 28)
            }),
            (&[1, 2, 840, 113549, 1, 1, 16], |der| {
                assert_digest::<Sha512_256>(der, 32)
            }),
        ];

        for (oid, assertion) in cases {
            let signature_algorithm = algorithm_identifier(oid, None);
            let der = cert_der_with_signature_algorithm(&signature_algorithm);
            assertion(&der);
        }
    }

    #[test]
    fn digest_rsa_pss_sha224_cert() {
        let signature_algorithm = rsa_pss_algorithm_identifier(OID_NIST_HASH_SHA224);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha224>(&der, 28);
    }

    #[test]
    fn digest_rsa_pss_sha3_cert() {
        let cases: &[DigestCase<'_>] = &[
            (&[2, 16, 840, 1, 101, 3, 4, 2, 7], |der| {
                assert_digest::<Sha3_224>(der, 28)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 2, 8], |der| {
                assert_digest::<Sha3_256>(der, 32)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 2, 9], |der| {
                assert_digest::<Sha3_384>(der, 48)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 2, 10], |der| {
                assert_digest::<Sha3_512>(der, 64)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 2, 5], |der| {
                assert_digest::<Sha512_224>(der, 28)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 2, 6], |der| {
                assert_digest::<Sha512_256>(der, 32)
            }),
        ];

        for (oid, assertion) in cases {
            let signature_algorithm = rsa_pss_algorithm_identifier(oid);
            let der = cert_der_with_signature_algorithm(&signature_algorithm);
            assertion(&der);
        }
    }

    #[test]
    fn digest_sha3_signature_algorithms() {
        let cases: &[DigestCase<'_>] = &[
            (&[2, 16, 840, 1, 101, 3, 4, 3, 5], |der| {
                assert_digest::<Sha3_224>(der, 28)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 9], |der| {
                assert_digest::<Sha3_224>(der, 28)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 13], |der| {
                assert_digest::<Sha3_224>(der, 28)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 6], |der| {
                assert_digest::<Sha3_256>(der, 32)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 10], |der| {
                assert_digest::<Sha3_256>(der, 32)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 14], |der| {
                assert_digest::<Sha3_256>(der, 32)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 7], |der| {
                assert_digest::<Sha3_384>(der, 48)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 11], |der| {
                assert_digest::<Sha3_384>(der, 48)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 15], |der| {
                assert_digest::<Sha3_384>(der, 48)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 8], |der| {
                assert_digest::<Sha3_512>(der, 64)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 12], |der| {
                assert_digest::<Sha3_512>(der, 64)
            }),
            (&[2, 16, 840, 1, 101, 3, 4, 3, 16], |der| {
                assert_digest::<Sha3_512>(der, 64)
            }),
        ];

        for (oid, assertion) in cases {
            let signature_algorithm = algorithm_identifier(oid, None);
            let der = cert_der_with_signature_algorithm(&signature_algorithm);
            assertion(&der);
        }
    }

    #[test]
    fn digest_ecdsa_sha256_cert() {
        let signature_algorithm = algorithm_identifier(OID_SIG_ECDSA_WITH_SHA256, None);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_ecdsa_sha384_cert() {
        let signature_algorithm = algorithm_identifier(OID_SIG_ECDSA_WITH_SHA384, None);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha384>(&der, 48);
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
    fn digest_rsa_pss_default_sha1_algorithms_fall_back_to_sha256() {
        let signature_algorithm = rsa_pss_algorithm_identifier_with_defaults();
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_rsa_pss_mixed_hashes_is_unsupported() {
        let signature_algorithm = rsa_pss_algorithm_identifier_without_mask(OID_NIST_HASH_SHA256);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_eq!(tls_server_end_point_digest(&der), None);
    }

    #[test]
    fn digest_rsa_pss_non_mgf1_mask_is_unsupported() {
        let signature_algorithm = rsa_pss_algorithm_identifier_with_mask(
            OID_NIST_HASH_SHA256,
            OID_PKCS1_RSA_ENCRYPTION,
            OID_NIST_HASH_SHA256,
        );
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_eq!(tls_server_end_point_digest(&der), None);
    }

    #[test]
    fn digest_sha1_cert_falls_back_to_sha256() {
        let signature_algorithm = rsa_pkcs1_algorithm_identifier(OID_PKCS1_SHA1_WITH_RSA);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_digest::<Sha256>(&der, 32);
    }

    #[test]
    fn digest_other_supported_fixed_signature_oids() {
        let cases: &[DigestCase<'_>] = &[
            (&[1, 2, 840, 113549, 1, 1, 2], |der| {
                assert_digest::<Md2>(der, 16)
            }),
            (&[1, 2, 840, 113549, 1, 1, 3], |der| {
                assert_digest::<Md4>(der, 16)
            }),
            (&[1, 2, 840, 113549, 1, 1, 4], |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (&[1, 3, 14, 3, 2, 29], |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (&[1, 3, 14, 3, 2, 25], |der| {
                assert_digest::<Sha256>(der, 32)
            }),
            (&[1, 2, 840, 10045, 4, 3, 4], |der| {
                assert_digest::<Sha512>(der, 64)
            }),
            (&[1, 3, 6, 1, 5, 5, 7, 6, 30], |der| {
                assert_shake::<Shake128>(der, 32)
            }),
            (&[1, 3, 6, 1, 5, 5, 7, 6, 31], |der| {
                assert_shake::<Shake256>(der, 64)
            }),
            (&[1, 3, 6, 1, 5, 5, 7, 6, 32], |der| {
                assert_shake::<Shake128>(der, 32)
            }),
            (&[1, 3, 6, 1, 5, 5, 7, 6, 33], |der| {
                assert_shake::<Shake256>(der, 64)
            }),
        ];

        for (oid, assertion) in cases {
            let signature_algorithm = algorithm_identifier(oid, None);
            let der = cert_der_with_signature_algorithm(&signature_algorithm);
            assertion(&der);
        }
    }

    #[test]
    fn digest_ed25519_cert_is_unsupported() {
        let signature_algorithm = algorithm_identifier(OID_SIG_ED25519, None);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        let result = tls_server_end_point_digest(&der);
        assert_eq!(result, None);
    }

    #[test]
    fn digest_unknown_signature_algorithm_is_unsupported() {
        let signature_algorithm = algorithm_identifier(&[1, 3, 6, 1, 4, 1, 55555, 1], None);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        assert_eq!(tls_server_end_point_digest(&der), None);
    }

    #[test]
    fn digest_is_deterministic() {
        let signature_algorithm = algorithm_identifier(OID_SIG_ECDSA_WITH_SHA256, None);
        let der = cert_der_with_signature_algorithm(&signature_algorithm);

        let a = tls_server_end_point_digest(&der);
        let b = tls_server_end_point_digest(&der);
        assert_eq!(a, b);
    }
}
