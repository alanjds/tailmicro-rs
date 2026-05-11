#[derive(Debug)]
pub enum TlsError {
    /// TCP connection failed before TLS.
    Connect,
    /// TLS handshake failed. The inner i32 is the mbedTLS error code (negative).
    Handshake(i32),
    /// Certificate fingerprint mismatch.
    FingerprintMismatch { expected: [u8; 32], got: [u8; 32] },
    /// Connection closed cleanly during read/write.
    ConnectionClosed,
    /// I/O error after handshake.
    Io,
    /// Feature not compiled in.
    NotSupported,
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
