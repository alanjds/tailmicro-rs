//! Shared packet buffer type for tailmicro's cross-actor channels.
//!
//! Every packet that crosses an `async_channel` between `tm_derp`,
//! `tm_runtime`'s event router, `tm_wg`, `tm_disco` and `tm_netstack` uses
//! this ONE buffer type with ONE capacity ([`PKT_CAP`]). Before this crate
//! existed each crate had its own size (1532 / 1500 / 256), so the router
//! had to copy every packet into a freshly boxed buffer of a different size
//! at each hop. Those alternating 1504/1536/260-byte alloc/free pairs were
//! fragmenting the ESP32-C3 heap (see `ALLOCATIONS.md`). With one type, the
//! router moves the buffer on instead of copying it.
//!
//! Leaf crate on purpose: it depends on nothing in the workspace, so every
//! packet-carrying crate (including `tm_netstack`, which depends on no other
//! `tm_*` crate) can use it.

/// Capacity of every channel-facing packet buffer.
///
/// The superset of all previous per-crate sizes: `tm_derp::MAX_DERP_PAYLOAD`
/// (1500 + 32), `tm_wg`'s 1500 and `tm_disco`'s 256.
pub const PKT_CAP: usize = 1500 + 32;

/// The storage behind a packet buffer.
pub type PktInner = heapless::Vec<u8, PKT_CAP>;

/// A boxed packet buffer, as moved through the inter-actor channels.
///
/// Boxed (a single pointer in the channel message) because
/// `async_channel`'s ring buffer reserves 31 slots per block and returns
/// each block by value, so an unboxed ~1.5 KB payload balloons the caller's
/// async stack frame (the ESP32-C3 stack overflow at `Runtime::join()`).
pub type PktBox = Box<PktInner>;

/// Allocate an empty [`PktBox`], built directly on the heap.
///
/// `Box::write(Box::new_uninit(), ..)` constructs the empty `Vec` in the
/// heap allocation instead of building a ~1.5 KB temporary on the stack and
/// copying it in (this matters on lwIP's 3 KB tcpip-thread stack).
pub fn new_box() -> PktBox {
    Box::write(Box::new_uninit(), heapless::Vec::new())
}

/// Allocate a [`PktBox`] holding a copy of `data`, or `None` if `data` is
/// longer than [`PKT_CAP`].
pub fn box_from_slice(data: &[u8]) -> Option<PktBox> {
    if data.len() > PKT_CAP {
        return None;
    }
    let mut b = new_box();
    // Cannot fail: length checked above.
    let _ = b.extend_from_slice(data);
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_roundtrip_and_cap() {
        let b = box_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert!(box_from_slice(&[0u8; PKT_CAP]).is_some());
        assert!(box_from_slice(&[0u8; PKT_CAP + 1]).is_none());
    }
}
