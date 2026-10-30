//! Host stub: no on-device lwIP exists off-target, so there is nothing to
//! inject into. Every call is a documented no-op/error so `tm_runtime`'s
//! call sites (which are NOT `cfg`-gated -- they call this API on every
//! target, per plan (a)'s host-build requirement) compile and behave
//! predictably on host `cargo test`/`cargo build`.

use super::{OutboundSender, TailnetError};

pub fn bring_up(_our_ip: [u8; 4], _outbound_tx: OutboundSender) -> Result<(), TailnetError> {
    Err(TailnetError::NotSupported)
}

pub fn set_address(_new_ip: [u8; 4]) -> Result<(), TailnetError> {
    Err(TailnetError::NotSupported)
}

pub fn inject_inbound(_payload: &[u8]) -> Result<(), TailnetError> {
    Err(TailnetError::NotSupported)
}
