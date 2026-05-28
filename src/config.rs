use std::sync::Arc;

use rustls::{
    ClientConfig, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};

/// An error that may be returned when loading native root certificates.
#[cfg(feature = "native-roots")]
#[derive(Debug)]
pub struct NativeRootsError(NativeRootsErrorKind);

#[cfg(feature = "native-roots")]
#[derive(Debug)]
enum NativeRootsErrorKind {
    Load(Vec<rustls_native_certs::Error>),
    NoUsableRootsLoaded,
}

#[cfg(feature = "native-roots")]
impl NativeRootsError {
    fn load(errors: Vec<rustls_native_certs::Error>) -> Self {
        Self(NativeRootsErrorKind::Load(errors))
    }

    fn no_usable_roots_loaded() -> Self {
        Self(NativeRootsErrorKind::NoUsableRootsLoaded)
    }
}

#[cfg(feature = "native-roots")]
impl std::fmt::Display for NativeRootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            NativeRootsErrorKind::Load(errors) => {
                write!(f, "failed to load native root certificates")?;
                if errors.is_empty() {
                    return Ok(());
                }

                write!(f, ": ")?;
                for (i, err) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{err}")?;
                }
                Ok(())
            }
            NativeRootsErrorKind::NoUsableRootsLoaded => {
                write!(f, "no usable roots loaded from native certificate store")
            }
        }
    }
}

#[cfg(feature = "native-roots")]
impl std::error::Error for NativeRootsError {}

/// Returns a rustls ClientConfig that uses root certificates from the
/// `rustls-native-certs` crate.
///
/// Returns an error if no usable certificates could be loaded into the root
/// store. This can happen due to file permission issues, missing certificate
/// stores, or certificates that rustls rejects.
///
/// Requires the `native-roots` feature to be enabled.
#[cfg(feature = "native-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-roots")))]
pub fn config_native_roots() -> Result<ClientConfig, NativeRootsError> {
    let results = rustls_native_certs::load_native_certs();
    config_native_roots_from_parts(results.certs, results.errors)
}

#[cfg(feature = "native-roots")]
fn config_native_roots_from_parts(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    errors: Vec<rustls_native_certs::Error>,
) -> Result<ClientConfig, NativeRootsError> {
    let mut root_store = rustls::RootCertStore::empty();

    if certs.is_empty() && !errors.is_empty() {
        return Err(NativeRootsError::load(errors));
    }

    let mut added_roots = 0;
    for cert in certs {
        if root_store.add(cert).is_ok() {
            added_roots += 1;
        }
    }

    if added_roots == 0 {
        return Err(NativeRootsError::no_usable_roots_loaded());
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
///
/// # Dangerous
///
/// This disables server certificate and hostname verification. TLS traffic is
/// still encrypted, but the client no longer knows whether it is connected to
/// the intended PostgreSQL server, which makes man-in-the-middle attacks
/// possible.
///
/// Use this only for local development, tests, or tightly controlled
/// environments where server identity is verified by another trusted mechanism.
/// Prefer `config_native_roots`, `config_webpki_roots`, or a custom
/// [`ClientConfig`] with an explicit root store for production systems.
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

#[cfg(test)]
#[cfg(feature = "native-roots")]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::*;

    #[test]
    fn config_native_roots_errors_when_no_roots_are_available() {
        let err = match config_native_roots_from_parts(Vec::new(), Vec::new()) {
            Ok(_) => panic!("empty native root result should fail"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            "no usable roots loaded from native certificate store"
        );
    }

    #[test]
    fn config_native_roots_errors_when_all_roots_are_rejected() {
        let invalid_cert = CertificateDer::from(vec![0]);
        let err = match config_native_roots_from_parts(vec![invalid_cert], Vec::new()) {
            Ok(_) => panic!("native roots rejected by rustls should fail"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            "no usable roots loaded from native certificate store"
        );
    }

    #[test]
    fn config_native_roots_succeeds_when_at_least_one_root_is_added() {
        install_test_crypto_provider();

        let valid_cert = self_signed_cert_der();
        let invalid_cert = CertificateDer::from(vec![0]);

        assert!(config_native_roots_from_parts(vec![invalid_cert, valid_cert], Vec::new()).is_ok());
    }

    fn self_signed_cert_der() -> CertificateDer<'static> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        CertificateDer::from(cert.der().to_vec())
    }

    #[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
    fn install_test_crypto_provider() {
        use std::sync::Once;

        static INSTALL_PROVIDER: Once = Once::new();
        INSTALL_PROVIDER.call_once(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("failed to install rustls crypto provider for tests");
        });
    }

    #[cfg(not(all(feature = "aws-lc-rs", feature = "ring")))]
    fn install_test_crypto_provider() {}
}
