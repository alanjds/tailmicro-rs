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

/// Read one byte, telling a clean end-of-stream (`Ok(None)`) apart from a
/// transport error (`Err`). A FIN with nothing read is a deliberate close by
/// the peer; a reset or timeout is the network misbehaving.
pub(crate) async fn read_byte_or_eof<S: Read>(s: &mut S) -> Result<Option<u8>, ControlError> {
    let mut b = [0u8; 1];
    match s.read(&mut b).await {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(b[0])),
        Err(e) => {
            tracing::error!("read failed: {:?} (wanted 1 byte)", e);
            Err(ControlError::Io)
        }
    }
}

pub(crate) async fn write_all<S: Write>(s: &mut S, buf: &[u8]) -> Result<(), ControlError> {
    s.write_all(buf).await.map_err(|e| {
        tracing::error!("write_all failed: {:?} ({} bytes)", e, buf.len());
        ControlError::Io
    })
}
