//! `Packet`: a fixed-capacity, no-heap replacement for `ts_packet::PacketMut`.
//!
//! Upstream `PacketMut` wraps `bytes::BytesMut`; its one load-bearing property
//! is cheap 16-byte header prepending (`grow_front`). `Packet` reproduces that
//! with a `heapless::Vec<u8, 1500>` plus a front offset, and implements
//! `aead::Buffer` so the AEAD in-place API works directly on it.
//!
//! Inner-MTU budget (plan correction #6): the 1500-byte buffer must hold the
//! 16-byte transport-data header + ciphertext + 16-byte AEAD tag, so 16 bytes
//! of front headroom are reserved and the inner plaintext is capped at
//! `1500 - 16 - 16 = 1468` bytes. Outbound plaintext is built at `front = 16`;
//! inbound wire packets at `front = 0`.

use aead::Buffer;

/// Total on-wire buffer capacity (bytes).
pub const CAPACITY: usize = 1500;
/// Reserved front headroom for the 16-byte transport-data header.
pub const HEADROOM: usize = 16;
/// Maximum inner (pre-encryption) plaintext size: 1500 - header - tag.
pub const MAX_INNER: usize = CAPACITY - HEADROOM - 16;

/// A WireGuard packet buffer with cheap front-prepend support.
#[derive(Clone)]
pub struct Packet {
    buf: heapless::Vec<u8, CAPACITY>,
    /// Offset of the start of the live region within `buf`.
    front: usize,
}

impl Packet {
    /// Allocate an outbound packet of `len` zero bytes of plaintext, with front
    /// headroom reserved for a transport header.
    pub fn new(len: usize) -> Self {
        let mut buf = heapless::Vec::new();
        buf.resize(HEADROOM + len, 0)
            .expect("packet length exceeds capacity");
        Self {
            buf,
            front: HEADROOM,
        }
    }

    /// Build an outbound plaintext packet from a slice, reserving front headroom.
    pub fn from_plaintext(data: &[u8]) -> Self {
        let mut buf = heapless::Vec::new();
        buf.resize(HEADROOM, 0).expect("headroom fits");
        buf.extend_from_slice(data)
            .expect("plaintext exceeds capacity");
        Self {
            buf,
            front: HEADROOM,
        }
    }

    /// Build a packet from raw received wire bytes (no headroom).
    pub fn from_wire(data: &[u8]) -> Self {
        let mut buf = heapless::Vec::new();
        buf.extend_from_slice(data).expect("wire packet exceeds capacity");
        Self { buf, front: 0 }
    }

    /// The live region as an immutable slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.front..]
    }

    /// The live region as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.front..]
    }

    /// Length of the live region.
    pub fn len(&self) -> usize {
        self.buf.len() - self.front
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Expose `n` additional bytes at the front (for header prepend).
    ///
    /// # Panics
    /// Panics if there is less than `n` bytes of front headroom.
    pub fn grow_front(&mut self, n: usize) {
        assert!(self.front >= n, "insufficient front headroom");
        self.front -= n;
    }

    /// Consume `n` bytes from the front of the live region.
    pub fn truncate_front(&mut self, n: usize) {
        self.front = core::cmp::min(self.front + n, self.buf.len());
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for Packet {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Buffer for Packet {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buf
            .extend_from_slice(other)
            .map_err(|_| aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.buf.truncate(self.front + len);
    }

    fn len(&self) -> usize {
        Packet::len(self)
    }

    fn is_empty(&self) -> bool {
        Packet::is_empty(self)
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for Packet {}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Packet(len={})", self.len())
    }
}

impl From<&[u8]> for Packet {
    /// Outbound plaintext semantics (reserves headroom). For inbound wire
    /// bytes use [`Packet::from_wire`].
    fn from(data: &[u8]) -> Self {
        Packet::from_plaintext(data)
    }
}
