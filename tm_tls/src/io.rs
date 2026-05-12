/// IoStream trait — shared between tm_tls and tm_control to avoid duplicate trait definitions.
/// 
/// This trait represents a minimal async I/O stream that can be used for TLS connections
/// and control plane communication.
pub trait IoStream: Send {
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
}