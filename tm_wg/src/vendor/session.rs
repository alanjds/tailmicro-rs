//! Established WireGuard transport sessions. Vendored from ts_tunnel's
//! `session.rs`, with two gaps filled that upstream leaves open (see
//! `docs/wg-dataplane-notes.md`):
//!   * RFC 6479 sliding-window replay protection on the receive session
//!     (upstream had `// TODO: nonce sliding window`), 128-counter window.
//!   * message-count rekey trigger + hard reject bounds on the transmit
//!     session, and an `is_initiator` flag threaded through session creation.
//! `PacketMut` is replaced with `super::packet::Packet`.

use core::fmt::{Debug, Formatter};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    little_endian::{U32, U64},
};

use super::messages::{SessionId, TransportDataHeader};
use super::packet::Packet;

type SessionKey = chacha20poly1305::Key;

// wireguard-go rekey/reject constants (Part 1 comparison).
/// After this many messages sent, the initiator should start a new handshake.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// After this many messages, sending/receiving must hard-stop.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(240);

/// RFC 6479 sliding-window replay filter, 128-counter window (~16 bytes).
///
/// Bit `i` of `bitmap` records whether counter `last - i` has been seen.
#[derive(Default)]
struct ReplayFilter {
    last: u64,
    bitmap: u128,
    seen_any: bool,
}

const REPLAY_WINDOW: u64 = 128;

impl ReplayFilter {
    /// Check `counter` against the window and, if fresh, record it.
    /// Returns true if the counter is acceptable (not a replay / not too old).
    fn accept(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.last = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.last {
            let shift = counter - self.last;
            if shift >= REPLAY_WINDOW {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1;
            self.last = counter;
            true
        } else {
            let diff = self.last - counter;
            if diff >= REPLAY_WINDOW {
                return false; // too old, outside window
            }
            let mask = 1u128 << diff;
            if self.bitmap & mask != 0 {
                return false; // replay
            }
            self.bitmap |= mask;
            true
        }
    }
}

/// A generator of monotonically increasing 64-bit nonces.
#[derive(Default)]
struct NonceGenerator {
    nonce: Mutex<u64>,
}

impl NonceGenerator {
    /// Reserve a batch of consecutive nonces. The reserved range is fully
    /// consumed even if the returned NonceIter isn't.
    fn batch(&self, num: usize) -> NonceIter {
        let mut nonce = self.nonce.lock().unwrap();
        let end = match nonce.checked_add(num as u64) {
            Some(end) => end,
            None => panic!("nonce exhausted"),
        };
        let ret = NonceIter { cur: *nonce, end };
        *nonce = end;
        ret
    }

    fn current(&self) -> u64 {
        *self.nonce.lock().unwrap()
    }
}
struct NonceIter {
    cur: u64,
    end: u64,
}

impl Iterator for NonceIter {
    type Item = Nonce;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = self.cur;
            self.cur += 1;
            Some(Nonce::from(ret))
        }
    }
}

/// A cryptographic nonce for use with ChaCha20Poly1305.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Nonce {
    _zero: U32,
    counter: U64,
}

impl From<U64> for Nonce {
    fn from(v: U64) -> Self {
        Nonce {
            counter: v,
            _zero: Default::default(),
        }
    }
}

impl From<u64> for Nonce {
    fn from(v: u64) -> Self {
        Self::from(U64::from(v))
    }
}

impl AsRef<chacha20poly1305::Nonce> for Nonce {
    fn as_ref(&self) -> &chacha20poly1305::Nonce {
        let array: &[u8] = self.as_bytes();
        array.into()
    }
}

/// Established session that can only send.
pub struct TransmitSession {
    cipher: ChaCha20Poly1305,
    nonce: NonceGenerator,
    id: SessionId,
    created: Instant,
    /// Whether we were the initiator of the handshake that produced this
    /// session. Required for the initiator-only last-minute time rekey.
    is_initiator: bool,
}

impl TransmitSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant, is_initiator: bool) -> Self {
        TransmitSession {
            cipher: ChaCha20Poly1305::new(&key),
            nonce: Default::default(),
            id,
            created: now,
            is_initiator,
        }
    }

    /// Encrypt a batch of packets in place, prepending each transport header.
    pub fn encrypt<'a, Into, Iter>(&self, packets: Into)
    where
        Iter: ExactSizeIterator<Item = &'a mut Packet>,
        Into: IntoIterator<Item = &'a mut Packet, IntoIter = Iter>,
    {
        let packets = packets.into_iter();
        let nonce = self.nonce.batch(packets.len());
        for (packet, nonce) in packets.zip(nonce) {
            self.cipher
                .encrypt_in_place(nonce.as_ref(), &[], packet)
                .unwrap();
            let header = TransportDataHeader {
                receiver_id: self.id,
                nonce: nonce.counter,
                ..Default::default()
            };
            packet.grow_front(size_of::<TransportDataHeader>());
            header.write_to_prefix(packet.as_mut()).unwrap();
        }
    }

    /// Number of messages sent (== next nonce value).
    pub fn sent_messages(&self) -> u64 {
        self.nonce.current()
    }

    /// Whether the transmit side is stale and in need of key rotation
    /// (time- or message-count-based).
    pub fn stale(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REKEY_AFTER_TIME
            || self.sent_messages() >= REKEY_AFTER_MESSAGES
            || (self.is_initiator && self.sent_messages() >= REJECT_AFTER_MESSAGES)
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REJECT_AFTER_TIME
            || self.sent_messages() >= REJECT_AFTER_MESSAGES
    }

    /// Test-only: force the message counter (we can't practically send 2^60
    /// packets to exercise the message-count rekey path otherwise).
    #[cfg(test)]
    fn force_sent(&self, n: u64) {
        *self.nonce.nonce.lock().unwrap() = n;
    }
}

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    id: SessionId,
    created: Instant,
    replay: ReplayFilter,
}

impl Debug for ReceiveSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ReceiveSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        ReceiveSession {
            cipher: ChaCha20Poly1305::new(&key),
            id,
            created: now,
            replay: ReplayFilter::default(),
        }
    }

    /// Decrypt wireguard transport data messages in place, returning those that
    /// decrypted successfully (and passed replay protection).
    pub fn decrypt(&mut self, mut packets: Vec<Packet>) -> Vec<Packet> {
        packets.retain_mut(|packet| self.decrypt_one(packet));
        packets
    }

    /// Decrypt a wireguard transport data message in place.
    #[must_use]
    pub fn decrypt_one(&mut self, pkt: &mut Packet) -> bool {
        let Ok((header, _)) = TransportDataHeader::try_ref_from_prefix(pkt.as_ref()) else {
            tracing::warn!("decode as transport packet failed");
            return false;
        };

        if header.receiver_id != self.id {
            tracing::error!("wrong receiver id");
            return false;
        }

        let counter = u64::from(header.nonce);
        if counter >= REJECT_AFTER_MESSAGES {
            tracing::warn!("nonce past reject bound");
            return false;
        }

        let nonce = Nonce::from(header.nonce);
        pkt.truncate_front(size_of::<TransportDataHeader>());

        let result = self.cipher.decrypt_in_place(nonce.as_ref(), &[], pkt);
        if let Err(e) = &result {
            tracing::error!(err = %e, "decryption failed");
            return false;
        }

        // Replay check only AFTER a valid AEAD tag, so a forged counter can't
        // poison the window (RFC 6479).
        if !self.replay.accept(counter) {
            // debug, not warn: with the LAN direct path a tailscaled peer
            // whose path trust lapsed sends every packet over both UDP and
            // DERP, so a duplicate per packet is normal then, and a line per
            // packet on the blocking UART throttles the data plane.
            tracing::debug!(counter, "replay / stale nonce rejected");
            return false;
        }
        true
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > REJECT_AFTER_TIME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::messages::Message;

    #[test]
    fn test_session() {
        let k: [u8; 32] = [7u8; 32];
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now, true);
        let mut recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"foobar";
        let mut pkt = [Packet::from_plaintext(CLEARTEXT)];

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38); // 16 header + 6 + 16 tag
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 0);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        let mut pkt = [Packet::from_plaintext(CLEARTEXT)];
        send.encrypt(&mut pkt);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(u64::from(msg.nonce), 1);
        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);
    }

    #[test]
    fn replay_rejects_duplicate() {
        let k: [u8; 32] = [9u8; 32];
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now, true);
        let mut recv = ReceiveSession::new(k.into(), session, now);

        // Two packets, counters 0 and 1.
        let mut a = [Packet::from_plaintext(b"aaaa")];
        send.encrypt(&mut a);
        let mut b = [Packet::from_plaintext(b"bbbb")];
        send.encrypt(&mut b);

        // First delivery of each is accepted.
        let a_wire = a[0].clone();
        let b_wire = b[0].clone();
        assert!(recv.decrypt_one(&mut a[0]));
        assert!(recv.decrypt_one(&mut b[0]));

        // Replaying counter 0 (already seen) is rejected.
        let mut a_again = [a_wire];
        assert!(!recv.decrypt_one(&mut a_again[0]));
        // Replaying counter 1 is rejected too.
        let mut b_again = [b_wire];
        assert!(!recv.decrypt_one(&mut b_again[0]));
    }

    #[test]
    fn replay_window_boundary() {
        let mut f = ReplayFilter::default();
        assert!(f.accept(0)); // first
        assert!(f.accept(200)); // jump forward
        assert!(!f.accept(200)); // dup
        assert!(f.accept(199)); // within window (200-199=1)
        assert!(f.accept(200 - 127)); // diff=127 < 128 -> within window, fresh -> accept
        assert!(!f.accept(200 - 127)); // now a replay
        assert!(!f.accept(200 - 128)); // diff=128 -> too old, rejected
        assert!(f.accept(150)); // fresh, within window (diff=50)
    }

    #[test]
    fn message_count_rekey_trigger() {
        let k: [u8; 32] = [3u8; 32];
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now, true);

        // Fresh session is not stale on message count.
        assert!(!send.stale(now));
        // At the rekey threshold, stale() fires (time still fresh).
        send.force_sent(REKEY_AFTER_MESSAGES);
        assert!(send.stale(now));
        assert!(!send.expired(now));
        // At the reject threshold, expired() fires.
        send.force_sent(REJECT_AFTER_MESSAGES);
        assert!(send.expired(now));
    }

    #[test]
    fn session_timers() {
        let k: [u8; 32] = [1u8; 32];
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now, true);
        let recv = ReceiveSession::new(k.into(), session, now);

        assert!(!send.stale(now));
        assert!(!send.stale(now + Duration::from_secs(100)));
        assert!(send.stale(now + Duration::from_secs(130)));

        assert!(!send.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(250)));

        assert!(!recv.expired(now + Duration::from_secs(130)));
        assert!(recv.expired(now + Duration::from_secs(250)));
    }
}
