use std::{path::Path, sync::Arc};

use rustls::{
    ClientConfig, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{
        CertificateDer,
        pem::{Error as PemError, PemObject},
    },
};

/// An error returned when creating a [`ClientConfig`] from a CA certificate file.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaCertError {
    /// The CA certificate file could not be read or parsed as PEM.
    Pem(PemError),
    /// The file did not contain any PEM certificates.
    NoCertificates,
    /// A certificate could not be added to the root store.
    Tls(TlsError),
}

impl std::fmt::Display for CaCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem(err) => write!(f, "failed to read CA certificate file: {err}"),
            Self::NoCertificates => {
                write!(f, "CA certificate file did not contain any certificates")
            }
            Self::Tls(err) => write!(f, "failed to configure CA certificate: {err}"),
        }
    }
}

impl std::error::Error for CaCertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pem(err) => Some(err),
            Self::NoCertificates => None,
            Self::Tls(err) => Some(err),
        }
    }
}

impl From<PemError> for CaCertError {
    fn from(err: PemError) -> Self {
        Self::Pem(err)
    }
}

impl From<TlsError> for CaCertError {
    fn from(err: TlsError) -> Self {
        Self::Tls(err)
    }
}

/// An error returned by the deprecated `config_native_roots` helper.
#[cfg(feature = "native-roots")]
#[derive(Debug)]
pub struct NativeRootsError(TlsError);

#[cfg(feature = "native-roots")]
impl std::fmt::Display for NativeRootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to configure platform certificate verifier: {}",
            self.0
        )
    }
}

#[cfg(feature = "native-roots")]
impl std::error::Error for NativeRootsError {}

/// Returns a rustls ClientConfig that uses certificate verification provided by
/// the current platform.
///
/// On platforms with a native verifier, this uses the operating system's
/// certificate verification facilities. On other platforms, the
/// `rustls-platform-verifier` crate falls back to the best available WebPKI
/// verifier for that target.
///
/// Requires the `platform-verifier` feature to be enabled.
#[cfg(feature = "platform-verifier")]
#[cfg_attr(docsrs, doc(cfg(feature = "platform-verifier")))]
pub fn config_platform_verifier() -> Result<ClientConfig, TlsError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    Ok(ClientConfig::builder()
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// Returns a rustls ClientConfig that uses certificate verification provided by
/// the current platform.
///
/// Requires the `native-roots` feature to be enabled.
#[deprecated(note = "use config_platform_verifier() with the platform-verifier feature instead")]
#[cfg(feature = "native-roots")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-roots")))]
pub fn config_native_roots() -> Result<ClientConfig, NativeRootsError> {
    config_platform_verifier().map_err(NativeRootsError)
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

/// Returns a rustls ClientConfig that trusts CA certificates from a PEM file.
///
/// This is useful for services such as cloud database providers that publish a
/// CA certificate or bundle for verifying their database servers. Hostname
/// verification is still enabled; the certificates are used only as trust
/// anchors.
pub fn config_from_ca_cert(path: impl AsRef<Path>) -> Result<ClientConfig, CaCertError> {
    let mut root_store = rustls::RootCertStore::empty();
    let mut count = 0;

    for ca_cert in CertificateDer::pem_file_iter(path)? {
        root_store.add(ca_cert?)?;
        count += 1;
    }

    if count == 0 {
        return Err(CaCertError::NoCertificates);
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
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
/// Prefer `config_from_ca_cert`, `config_platform_verifier`,
/// `config_webpki_roots`, or a custom [`ClientConfig`] with an explicit root
/// store for production systems.
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
