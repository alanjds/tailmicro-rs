//! TLS abstraction layer for tailmicro-rs.
//!
//! # Overview
//!
//! Provides a single async `TlsStream` type that wraps platform-specific TLS
//! implementations behind a uniform interface:
//!
//! | Feature    | Backend             | Target       |
//! |---|---|---|
//! | `mbedtls`  | ESP-IDF `esp-tls`   | ESP32-C3     |
//! | `rustls`   | `tokio-rustls`      | Host (tests) |
//!
//! # Known ESP32-C3 mbedTLS issues and mitigations
//!
//! From audit of ESP-IDF issue tracker and Espressif FAQ:
//!
//! 1. **Dynamic TX/RX buffer heap corruption** (IDFGH-13555):
//!    The dynamic buffer implementation miscalculates RX buffer size,
//!    corrupting the heap under asymmetric fragment length configs.
//!    **Fix:** use `CONFIG_MBEDTLS_DYNAMIC_BUFFER=n` (static buffers).
//!    We set IN/OUT content length to 4096 in sdkconfig.
//!
//! 2. **BIGNUM memory allocation failure** (IDFGH-1928):
//!    RSA operations during handshake can fail with "BIGNUM alloc failed"
//!    even with available heap, because mbedTLS uses its own heap allocator
//!    that requires contiguous blocks.
//!    **Fix:** use ECDHE cipher suites only (no RSA); force `MBEDTLS_ECDH_C`.
//!    Tailscale's DERP servers support ECDHE-ECDSA.
//!
//! 3. **`MBEDTLS_HARDWARE_SHA` instability on C3**:
//!    The hardware SHA accelerator on ESP32-C3 has a known timing issue
//!    when interrupted mid-operation.
//!    **Fix:** `CONFIG_MBEDTLS_HARDWARE_SHA=n` (software SHA).
//!
//! 4. **Certificate bundle heap cost** (~30 KB):
//!    The full Mozilla bundle requires ~30 KB heap during verification.
//!    **Fix:** TLS fingerprint verification (MicroLink pattern) —
//!    verify SHA-256 of the leaf certificate instead of chain validation.
//!    This is the `FingerprintVerifier` approach implemented here.
//!
//! 5. **Memory leak on repeated connections** (mbedtls/mbedtls#3119):
//!    Each `mbedtls_ssl_setup()` call leaks ~2 KB if `mbedtls_ssl_free()`
//!    is not called in the exact right order.
//!    **Fix:** our `MbedTlsStream::Drop` calls free in the correct order,
//!    and we reuse the same connection (never reconnect unless disconnected).
//!
//! # Fingerprint verification
//!
//! Both backends support fingerprint-based verification as an alternative
//! to full chain validation.  The fingerprint is the SHA-256 hash of the
//! server's DER-encoded leaf certificate.
//!
//! To get the fingerprint of `login.tailscale.com`:
//! ```bash
//! openssl s_client -connect login.tailscale.com:443 </dev/null 2>/dev/null \
//!   | openssl x509 -outform DER \
//!   | sha256sum
//! ```

pub mod error;
pub mod io;

#[cfg(feature = "mbedtls")]
mod backend_mbedtls;

#[cfg(feature = "rustls")]
mod backend_rustls;

pub use error::TlsError;

// ESP-IDF types needed for connect_with_cached (mbedtls feature only)
#[cfg(feature = "mbedtls")]
use esp_idf_svc::tls::{EspTls, InternalSocket};

// ── Public API ────────────────────────────────────────────────────────────────

/// How to verify the server's TLS certificate.
#[derive(Clone, Debug)]
pub enum CertVerification {
    /// Verify by SHA-256 fingerprint of the leaf certificate.
    /// Recommended for ESP32-C3: saves ~30 KB vs full bundle.
    /// (MicroLink pattern)
    Fingerprint([u8; 32]),
    /// Full chain verification against the system/embedded root store.
    /// On ESP32-C3: requires the CA bundle component (~200 KB flash).
    /// On host: uses webpki-roots.
    FullChain,
    /// No verification — ONLY for local testing.
    #[cfg(any(test, feature = "insecure-no-verify"))]
    None,
}

/// Parameters for opening a TLS connection.
pub struct TlsConfig<'a> {
    pub host:         &'a str,
    pub port:         u16,
    pub verification: CertVerification,
    /// ALPN protocols to advertise.
    /// For the ts2021 Upgrade path: empty (plain HTTP/1.1 first).
    /// If ever doing h2 directly: `&["h2"]`.
    pub alpn:         &'a [&'a str],
}

/// An established TLS stream, implementing AsyncRead + AsyncWrite.
///
/// Backed by either mbedtls (ESP32-C3) or rustls (host).
pub struct TlsStream(Inner);

enum Inner {
    #[cfg(feature = "mbedtls")]
    Mbedtls(backend_mbedtls::MbedTlsStream),
    #[cfg(feature = "rustls")]
    Rustls(backend_rustls::RustlsStream),
    // Prevents empty enum on no feature
    #[cfg(not(any(feature = "mbedtls", feature = "rustls")))]
    _Uninhabited(core::convert::Infallible),
}

impl TlsStream {
    /// Open a TLS connection to `host:port`.
    ///
    /// On ESP32-C3 (mbedtls feature): wraps `esp_tls_conn_new_sync` via FFI.
    /// On host (rustls feature): uses `tokio-rustls` + system DNS.
    pub async fn connect(config: &TlsConfig<'_>) -> Result<Self, TlsError> {
        #[cfg(feature = "mbedtls")]
        return backend_mbedtls::connect(config).await.map(|s| Self(Inner::Mbedtls(s)));

        #[cfg(all(feature = "rustls", not(feature = "mbedtls")))]
        return backend_rustls::connect(config).await.map(|s| Self(Inner::Rustls(s)));

        #[cfg(not(any(feature = "mbedtls", feature = "rustls")))]
        compile_error!("Enable either the `mbedtls` or `rustls` feature in tm_tls");
    }
    
    /// Open a TLS connection to `host:port` using a cached TLS instance.
    ///
    /// This is used to avoid memory fragmentation by reusing a TLS instance
    /// that was created early in the program lifecycle.
    #[cfg(feature = "mbedtls")]
    pub async fn connect_with_cached(config: &TlsConfig<'_>, cached_tls: EspTls<InternalSocket>) -> Result<Self, TlsError> {
        backend_mbedtls::connect_with_cached(config, cached_tls).await.map(|s| Self(Inner::Mbedtls(s)))
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        match &mut self.0 {
            #[cfg(feature = "mbedtls")]
            Inner::Mbedtls(s) => s.read(buf).await,
            #[cfg(feature = "rustls")]
            Inner::Rustls(s) => s.read(buf).await,
            #[cfg(not(any(feature = "mbedtls", feature = "rustls")))]
            Inner::_Uninhabited(x) => match *x {},
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        match &mut self.0 {
            #[cfg(feature = "mbedtls")]
            Inner::Mbedtls(s) => s.write_all(buf).await,
            #[cfg(feature = "rustls")]
            Inner::Rustls(s) => s.write_all(buf).await,
            #[cfg(not(any(feature = "mbedtls", feature = "rustls")))]
            Inner::_Uninhabited(x) => match *x {},
        }
    }

    /// Read exactly `buf.len()` bytes.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TlsError> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 { return Err(TlsError::ConnectionClosed); }
            filled += n;
        }
        Ok(())
    }
}

// Make TlsStream usable as an IoStream (for tm_control / tm_derp)
impl crate::io::IoStream for TlsStream {
    async fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<(), ()> {
        self.read_exact(buf).await.map_err(|_| ())
    }
    async fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Result<(), ()> {
        self.write_all(buf).await.map_err(|_| ())
    }
}