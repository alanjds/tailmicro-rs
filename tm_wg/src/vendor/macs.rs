//! WireGuard MAC1/MAC2 (cookie) machinery. Vendored from ts_tunnel; only the
//! import paths changed (`ts_keys` → `super::keys`, `crate::` → `super::`).

use std::{ops::Add, time::Duration};

use tm_time::Instant;

use aead::{Aead, Payload, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest, digest::FixedOutput};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use super::keys::NodePublicKey;
use super::messages::CookieReply;

const MAC1_LABEL: &[u8] = b"mac1----";
const MAC2_LABEL: &[u8] = b"cookie--";
const COOKIE_ROTATION_TIME: Duration = Duration::from_secs(120);

type CookieMac = Blake2sMac<U16>;

pub type Mac = [u8; 16];

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct Mac1Trailer {
    mac1: Mac,
    mac2: Mac,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Mac2Trailer {
    mac2: Mac,
}

fn mac1_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC1_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

fn mac2_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC2_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

#[derive(Debug)]
struct Mac2Cookie {
    key: [u8; 16],
    expiry: Instant,
}

/// Computes MACs on outbound packets.
pub struct MACSender {
    mac1_key: [u8; 32],
    mac2_key: [u8; 32],
    cookie: Option<Mac2Cookie>,
}

impl MACSender {
    /// Create a MAC sender for the given peer.
    pub fn new(peer_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(peer_key),
            mac2_key: mac2_key(peer_key),
            cookie: None,
        }
    }

    /// Write packet MACs to the final 32 bytes of pkt. Returns the computed
    /// mac1 value. `mac1` covers `msg[0..len-32]`, `mac2` covers `msg[0..len-16]`.
    ///
    /// # Panics
    /// If pkt is smaller than 32 bytes.
    pub fn write_macs(&self, pkt: &mut [u8]) -> Mac {
        let (data, trailer) = Mac1Trailer::try_mut_from_suffix(pkt).unwrap();
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        m.finalize_into(trailer.mac1.as_mut_bytes().into());
        let ret = trailer.mac1;

        if let Some(mac2) = &self.cookie
            && mac2.expiry > Instant::now()
        {
            let (data, trailer) = Mac2Trailer::try_mut_from_suffix(pkt).unwrap();
            let mut m: CookieMac = blake2::digest::Mac::new_from_slice(&mac2.key).unwrap();
            blake2::digest::Mac::update(&mut m, data);
            m.finalize_into(trailer.mac2.as_mut_bytes().into());
        } else {
            trailer.mac2 = Default::default();
        }

        ret
    }

    /// Process a received cookie reply message. The last-sent handshake mac1 is
    /// the AAD for the cookie decryption.
    pub fn receive_cookie(&mut self, cookie: &CookieReply, handshake_mac: &Mac) {
        let cipher = XChaCha20Poly1305::new(&self.mac2_key.into());
        let msg = Payload {
            msg: &cookie.cookie_sealed,
            aad: handshake_mac,
        };
        let Ok(cookie) = cipher.decrypt(&cookie.nonce.into(), msg) else {
            return;
        };
        self.cookie = Some(Mac2Cookie {
            key: cookie.try_into().unwrap(),
            expiry: Instant::now().add(COOKIE_ROTATION_TIME),
        });
    }
}

/// Verifies MACs on inbound packets.
pub struct MACReceiver {
    mac1_key: [u8; 32],
}

impl MACReceiver {
    /// Creates a MAC receiver.
    pub fn new(my_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(my_key),
        }
    }

    /// Verifies packet MACs in the final 32 bytes of pkt.
    #[must_use]
    pub fn verify_macs(&self, pkt: &[u8]) -> bool {
        let Ok((data, trailer)) = Mac1Trailer::try_ref_from_suffix(pkt) else {
            return false;
        };
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        if blake2::digest::Mac::verify(m, &trailer.mac1.into()).is_err() {
            return false;
        }

        // We never generate cookie replies (no under-load DoS state on a
        // client), so a non-zero mac2 from a peer is rejected.
        if trailer.mac2 != Mac::default() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::keys::NodeKeyPair;

    #[test]
    fn mac1_write_then_verify() {
        // Sender MACs toward peer's key; receiver verifies with its own key.
        let peer = NodeKeyPair::new();
        let sender = MACSender::new(&peer.public);
        let receiver = MACReceiver::new(&peer.public);

        let mut pkt = [0u8; 148];
        pkt[0] = 1; // handshake initiation type
        let mac1 = sender.write_macs(&mut pkt);
        // mac1 lands at offset len-32 == 116.
        assert_eq!(&pkt[116..132], &mac1);
        // mac2 is all-zero (no cookie yet).
        assert_eq!(&pkt[132..148], &[0u8; 16]);
        assert!(receiver.verify_macs(&pkt));
    }

    #[test]
    fn tampered_packet_fails_mac1() {
        let peer = NodeKeyPair::new();
        let sender = MACSender::new(&peer.public);
        let receiver = MACReceiver::new(&peer.public);

        let mut pkt = [0u8; 148];
        pkt[0] = 1;
        sender.write_macs(&mut pkt);
        pkt[20] ^= 0xFF; // corrupt covered data
        assert!(!receiver.verify_macs(&pkt));
    }

    #[test]
    fn wrong_key_fails_mac1() {
        let peer = NodeKeyPair::new();
        let other = NodeKeyPair::new();
        let sender = MACSender::new(&peer.public);
        let receiver = MACReceiver::new(&other.public); // different key

        let mut pkt = [0u8; 148];
        pkt[0] = 1;
        sender.write_macs(&mut pkt);
        assert!(!receiver.verify_macs(&pkt));
    }

    #[test]
    fn nonzero_mac2_rejected() {
        let peer = NodeKeyPair::new();
        let sender = MACSender::new(&peer.public);
        let receiver = MACReceiver::new(&peer.public);

        let mut pkt = [0u8; 148];
        pkt[0] = 1;
        sender.write_macs(&mut pkt);
        pkt[132] = 1; // forge a non-zero mac2
        assert!(!receiver.verify_macs(&pkt));
    }
}
