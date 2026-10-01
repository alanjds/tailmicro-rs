//! Whole-buffer reads and writes over any `embedded-io-async` stream, with
//! the failure logged once here (kind and requested length) instead of at
//! every call site.

use crate::ControlError;
use embedded_io_async::{Read, Write};

pub(crate) async fn read_exact<S: Read>(s: &mut S, buf: &mut [u8]) -> Result<(), ControlError> {
    let want = buf.len();
    s.read_exact(buf).await.map_err(|e| {
        tracing::error!("read_exact failed: {:?} (wanted {} bytes)", e, want);
        ControlError::Io
    })
}

pub(crate) async fn write_all<S: Write>(s: &mut S, buf: &[u8]) -> Result<(), ControlError> {
    s.write_all(buf).await.map_err(|e| {
        tracing::error!("write_all failed: {:?} ({} bytes)", e, buf.len());
        ControlError::Io
    })
}
