use std::sync::Arc;

use rustls::{
    ClientConfig, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};

/// An error that may be returned when loading native root certificates.
#[cfg(feature = "native-roots")]
#[derive(Debug)]
pub struct NativeRootsError(Vec<rustls_native_certs::Error>);

#[cfg(feature = "native-roots")]
impl std::fmt::Display for NativeRootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to load native root certificates: ")?;
        for (i, err) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "native-roots")]
impl std::error::Error for NativeRootsError {}

/// Returns a rustls ClientConfig that uses root certificates from the
/// `rustls-native-certs` crate.
///
/// Returns an error if no certificates could be loaded. This can happen due to
/// file permission issues or missing certificate stores on the system.
///
/// Requires the `native-roots` feature to be enabled.
#[cfg(feature = "native-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-roots")))]
pub fn config_native_roots() -> Result<ClientConfig, NativeRootsError> {
    let mut root_store = rustls::RootCertStore::empty();
    let results = rustls_native_certs::load_native_certs();

    if results.certs.is_empty() && !results.errors.is_empty() {
        return Err(NativeRootsError(results.errors));
    }

    for cert in results.certs {
        let _ = root_store.add(cert);
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// Returns a rustls ClientConfig that uses root certificates from the
/// `webpki-roots` crate.
///
/// Requires the `webpki-roots` feature to be enabled.
#[cfg(feature = "webpki-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "webpki-roots")))]
pub fn config_webpki_roots() -> ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

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
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED448,
        ];
        SCHEMES.to_vec()
    }
}
