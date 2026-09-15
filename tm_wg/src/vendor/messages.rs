//! WireGuard message wire structs (vendored from ts_tunnel, verbatim except
//! `SessionId::random`).
//!
//! Field offsets cross-checked against the plan's Part 2 tables:
//! Initiation 148, Response 92, CookieReply 64, TransportData header 16. All
//! fields are byte arrays or `Unaligned` zerocopy ints (alignment 1), so
//! `repr(C)` introduces no interior padding and the offsets are exact.

use core::fmt::{Debug, Formatter};

use rand::rngs::OsRng;
use rand_core::RngCore;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    byteorder::little_endian::{U32, U64},
};

#[repr(transparent)]
#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Copy,
    Clone,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    Unaligned,
    Hash,
)]
pub struct SessionId(U32);

impl SessionId {
    pub fn random() -> Self {
        // Vendored `rand::random()` → OsRng, matching tm_keys's RNG discipline.
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        SessionId(u32::from_ne_bytes(b).into())
    }
}

impl From<u32> for SessionId {
    fn from(v: u32) -> Self {
        SessionId(v.into())
    }
}

impl From<SessionId> for u32 {
    fn from(v: SessionId) -> Self {
        v.0.into()
    }
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct HandshakeInitiation {
    pub msg_type: MessageType,          // offset   0
    pub _reserved: [u8; 3],             // offset   1
    pub sender_id: SessionId,           // offset   4
    pub ephemeral_pub: [u8; 32],        // offset   8
    pub static_pub_sealed: [u8; 32 + 16], // offset  40 (32 pubkey + 16 tag)
    pub timestamp_sealed: [u8; 12 + 16],  // offset  88 (12 TAI64N + 16 tag)
    pub mac1: [u8; 16],                 // offset 116
    pub mac2: [u8; 16],                 // offset 132
}                                       // total  148

impl Default for HandshakeInitiation {
    fn default() -> Self {
        Self {
            msg_type: MessageType::HandshakeInitiation,
            _reserved: Default::default(),
            sender_id: Default::default(),
            ephemeral_pub: Default::default(),
            static_pub_sealed: [0; 32 + 16],
            timestamp_sealed: Default::default(),
            mac1: Default::default(),
            mac2: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct HandshakeResponse {
    pub msg_type: MessageType,   // offset  0
    pub _reserved: [u8; 3],      // offset  1
    pub sender_id: SessionId,    // offset  4
    pub receiver_id: SessionId,  // offset  8
    pub ephemeral_pub: [u8; 32], // offset 12
    pub auth_tag: [u8; 16],      // offset 44 (bare Poly1305 tag over empty plaintext)
    pub mac1: [u8; 16],          // offset 60
    pub mac2: [u8; 16],          // offset 76
}                                // total  92

impl Default for HandshakeResponse {
    fn default() -> Self {
        Self {
            msg_type: MessageType::HandshakeResponse,
            _reserved: Default::default(),
            sender_id: Default::default(),
            receiver_id: Default::default(),
            ephemeral_pub: Default::default(),
            auth_tag: Default::default(),
            mac1: Default::default(),
            mac2: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct TransportDataHeader {
    pub msg_type: MessageType,  // offset 0
    pub _reserved: [u8; 3],     // offset 1
    pub receiver_id: SessionId, // offset 4
    pub nonce: U64,             // offset 8 (le64 counter)
}                               // total 16

impl Debug for TransportDataHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportDataHeader")
            .field("msg_type", &self.msg_type)
            .field("receiver_id", &self.receiver_id)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl<'packet> TryFrom<&'packet [u8]> for &'packet TransportDataHeader {
    type Error = ();

    fn try_from(value: &'packet [u8]) -> Result<Self, Self::Error> {
        Ok(TransportDataHeader::try_ref_from_prefix(value)
            .map_err(|_| ())?
            .0)
    }
}

impl Default for TransportDataHeader {
    fn default() -> Self {
        Self {
            msg_type: MessageType::TransportData,
            _reserved: Default::default(),
            receiver_id: Default::default(),
            nonce: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct CookieReply {
    pub msg_type: MessageType,        // offset 0
    pub _reserved: [u8; 3],           // offset 1
    pub receiver_id: SessionId,       // offset 4
    pub nonce: [u8; 24],              // offset 8 (XChaCha20 nonce)
    pub cookie_sealed: [u8; 16 + 16], // offset 32 (16 cookie + 16 tag)
}                                     // total 64

impl Default for CookieReply {
    fn default() -> Self {
        Self {
            msg_type: MessageType::CookieReply,
            _reserved: Default::default(),
            receiver_id: Default::default(),
            nonce: Default::default(),
            cookie_sealed: Default::default(),
        }
    }
}

pub enum Message<'packet> {
    HandshakeInitiation(&'packet HandshakeInitiation),
    HandshakeResponse(&'packet HandshakeResponse),
    TransportDataHeader(&'packet TransportDataHeader),
    CookieReply(&'packet CookieReply),
}

impl<'packet> TryFrom<&'packet [u8]> for Message<'packet> {
    type Error = ();

    fn try_from(raw: &'packet [u8]) -> Result<Message<'packet>, Self::Error> {
        let Ok((msg_type, _)) = MessageType::try_ref_from_prefix(raw) else {
            return Err(());
        };

        match msg_type {
            MessageType::HandshakeInitiation => HandshakeInitiation::try_ref_from_bytes(raw)
                .map(Message::HandshakeInitiation)
                .map_err(|_| ()),
            MessageType::HandshakeResponse => HandshakeResponse::try_ref_from_bytes(raw)
                .map(Message::HandshakeResponse)
                .map_err(|_| ()),
            MessageType::TransportData => TransportDataHeader::try_ref_from_prefix(raw)
                .map(|(header, _)| Message::TransportDataHeader(header))
                .map_err(|_| ()),
            MessageType::CookieReply => CookieReply::try_ref_from_bytes(raw)
                .map(Message::CookieReply)
                .map_err(|_| ()),
        }
    }
}

impl Message<'_> {
    pub fn receiver_id(&self) -> Option<SessionId> {
        match self {
            Message::HandshakeInitiation(_) => None,
            Message::HandshakeResponse(resp) => Some(resp.receiver_id),
            Message::TransportDataHeader(data) => Some(data.receiver_id),
            Message::CookieReply(cookie) => Some(cookie.receiver_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::TryFromBytes;

    #[test]
    fn wire_sizes_match_offset_tables() {
        assert_eq!(size_of::<HandshakeInitiation>(), 148);
        assert_eq!(size_of::<HandshakeResponse>(), 92);
        assert_eq!(size_of::<CookieReply>(), 64);
        assert_eq!(size_of::<TransportDataHeader>(), 16);
    }

    #[test]
    fn initiation_field_offsets_round_trip() {
        let mut m = HandshakeInitiation {
            sender_id: SessionId::from(0x0102_0304),
            ephemeral_pub: [0xAA; 32],
            static_pub_sealed: [0xBB; 48],
            timestamp_sealed: [0xCC; 28],
            mac1: [0xDD; 16],
            mac2: [0xEE; 16],
            ..Default::default()
        };
        m._reserved = [0; 3];
        let b = m.as_bytes();
        assert_eq!(&b[0..4], &[1, 0, 0, 0]); // msg_type le32 == 1
        assert_eq!(&b[4..8], &0x0102_0304u32.to_le_bytes()); // sender_index le
        assert_eq!(&b[8..40], &[0xAA; 32]); // ephemeral
        assert_eq!(&b[40..88], &[0xBB; 48]); // encrypted_static
        assert_eq!(&b[88..116], &[0xCC; 28]); // encrypted_timestamp
        assert_eq!(&b[116..132], &[0xDD; 16]); // mac1
        assert_eq!(&b[132..148], &[0xEE; 16]); // mac2
        // Parse back.
        let parsed = HandshakeInitiation::try_ref_from_bytes(b).unwrap();
        assert_eq!(u32::from(parsed.sender_id), 0x0102_0304);
    }

    #[test]
    fn response_and_transport_offsets() {
        let r = HandshakeResponse {
            sender_id: SessionId::from(0x1111_1111),
            receiver_id: SessionId::from(0x2222_2222),
            ephemeral_pub: [0x33; 32],
            auth_tag: [0x44; 16],
            ..Default::default()
        };
        let b = r.as_bytes();
        assert_eq!(&b[0..4], &[2, 0, 0, 0]);
        assert_eq!(&b[4..8], &0x1111_1111u32.to_le_bytes());
        assert_eq!(&b[8..12], &0x2222_2222u32.to_le_bytes());
        assert_eq!(&b[12..44], &[0x33; 32]);
        assert_eq!(&b[44..60], &[0x44; 16]);

        let t = TransportDataHeader {
            receiver_id: SessionId::from(0xABCD_EF01),
            nonce: 0x0102_0304_0506_0708u64.into(),
            ..Default::default()
        };
        let b = t.as_bytes();
        assert_eq!(&b[0..4], &[4, 0, 0, 0]);
        assert_eq!(&b[4..8], &0xABCD_EF01u32.to_le_bytes());
        assert_eq!(&b[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
    }
}
