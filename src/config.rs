use std::sync::Arc;

use rustls::{
    ClientConfig, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};

/// Returns a rustls ClientConfig that uses root certificates from the
/// `rustls-native-certs` crate.
///
/// Requires the `native-roots` feature to be enabled.
#[cfg(feature = "native-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-roots")))]
pub fn config_native_roots() -> ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    let results = rustls_native_certs::load_native_certs();
    for cert in results.certs {
        let _ = root_store.add(cert);
    }

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Returns a rustls ClientConfig that uses root certificates from the
/// `webpki-roots` crate.
///
/// Requires the `webpki-roots` feature to be enabled.
#[cfg(feature = "webpki-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
pub fn config_webpki_roots() -> ClientConfig {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Returns a rustls ClientConfig that does not verify the server certificate.
pub fn config_no_verify() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopTlsVerifier {}))
        .with_no_client_auth()
}

#[derive(Debug)]
struct NoopTlsVerifier;

impl ServerCertVerifier for NoopTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        static SCHEMES: &[SignatureScheme] = &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];
        SCHEMES.to_vec()
    }
}
