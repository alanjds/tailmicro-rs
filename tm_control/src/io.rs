//! Platform-independent async I/O trait.
//!
//! Declared locally (rather than depending on `tm_tls`) so `tm_control`
//! doesn't need to pull in TLS at all now that the control connection is
//! plain TCP. Mirrors the identical trait in `tm_derp::IoStream`.

pub trait IoStream {
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> impl core::future::Future<Output = Result<(), ()>> + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> impl core::future::Future<Output = Result<(), ()>> + 'a;
}

impl IoStream for tokio::net::TcpStream {
    async fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<(), ()> {
        tokio::io::AsyncReadExt::read_exact(self, buf).await.map(|_| ()).map_err(|e| { tracing::error!("TcpStream::read_exact failed: {:?} (wanted {} bytes)", e, buf.len()); })
    }
    async fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Result<(), ()> {
        tokio::io::AsyncWriteExt::write_all(self, buf).await.map_err(|e| { tracing::error!("TcpStream::write_all failed: {:?} ({} bytes)", e, buf.len()); })
    }
}
