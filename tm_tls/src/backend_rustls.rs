//! rustls backend — host testing and CI.
//!
//! Uses `tokio-rustls` + `webpki-roots` for full async TLS on Linux/macOS.
//! Fingerprint verification is implemented as a custom `ServerCertVerifier`
//! that checks the SHA-256 of the end-entity certificate DER.

use crate::{CertVerification, TlsConfig, TlsError};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct RustlsStream {
    inner: tokio_rustls::client::TlsStream<TcpStream>,
}

pub async fn connect(cfg: &TlsConfig<'_>) -> Result<RustlsStream, TlsError> {
    let tcp = TcpStream::connect((cfg.host, cfg.port)).await
        .map_err(|_| TlsError::Connect)?;

    let tls_config = build_rustls_config(&cfg.verification, cfg.alpn)?;
    let connector  = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(cfg.host.to_owned())
        .map_err(|_| TlsError::Connect)?;

    let stream = connector.connect(server_name, tcp).await
        .map_err(|e| TlsError::Handshake(e.raw_os_error().unwrap_or(-1)))?;

    Ok(RustlsStream { inner: stream })
}

fn build_rustls_config(
    verification: &CertVerification,
    alpn: &[&str],
) -> Result<rustls::ClientConfig, TlsError> {
    use rustls::ClientConfig;

    let mut config = match verification {
        CertVerification::FullChain => {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        CertVerification::Fingerprint(fp) => {
            let verifier = FingerprintVerifier::new(*fp);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
        #[cfg(any(test, feature = "insecure-no-verify"))]
        CertVerification::None => {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        }
    };

    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    Ok(config)
}

// ── Fingerprint verifier ───────────────────────────────────────────────────────

struct FingerprintVerifier {
    expected: [u8; 32],
}

impl FingerprintVerifier {
    fn new(expected: [u8; 32]) -> Self { Self { expected } }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let got: [u8; 32] = hasher.finalize().into();

        if got == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "fingerprint mismatch: expected {:?} got {:?}",
                hex(&self.expected), hex(&got)
            )))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ── No-verify (tests only) ────────────────────────────────────────────────────

#[cfg(any(test, feature = "insecure-no-verify"))]
struct NoVerifier;

#[cfg(any(test, feature = "insecure-no-verify"))]
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED25519]
    }
}

// ── RustlsStream I/O ─────────────────────────────────────────────────────────

impl RustlsStream {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        use tokio::io::AsyncReadExt;
        self.inner.read(buf).await.map_err(|_| TlsError::Io)
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        use tokio::io::AsyncWriteExt;
        self.inner.write_all(buf).await.map_err(|_| TlsError::Io)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
