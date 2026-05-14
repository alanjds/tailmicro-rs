/// IoStream trait — shared between tm_tls and tm_control to avoid duplicate trait definitions.
/// 
/// This trait represents a minimal async I/O stream that can be used for TLS connections
/// and control plane communication.
/// 
/// NOTE: On ESP32-C3 with current_thread runtime, we don't need Send because only one
/// task runs at a time (cooperative multitasking). The trait is still marked with Send
/// for compatibility with multi-threaded runtimes, but implementations can opt out.
pub trait IoStream {
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
}
