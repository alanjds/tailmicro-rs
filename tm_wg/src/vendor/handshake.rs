//! WireGuard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake. Vendored from
//! ts_tunnel's `handshake.rs`, structurally edited (see
//! `docs/wg-dataplane-notes.md`, port decision #4):
//!   * `Handshake::Initiated` drops the `ts_time::Handle<Event>` field and the
//!     `crate::endpoint::Event` back-reference; the timeout is owned by the
//!     rewritten endpoint's per-peer timer, not embedded here.
//!   * `x25519_dalek::ReusableSecret::random()` → `random_from_rng(OsRng)`.
//!   * `ts_packet::PacketMut` → `super::packet::Packet`.
//!   * `TransmitSession::new` takes an `is_initiator` flag.

use std::time::Instant;

use aead::AeadInPlace;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::SimpleHkdf;
use rand::rngs::OsRng;
use zerocopy::{FromZeros, IntoBytes};

use super::{
    config::Psk,
    keys::{NodeKeyPair, NodePrivateKey, NodePublicKey},
    macs::{MACReceiver, MACSender, Mac},
    messages::*,
    packet::Packet,
    session::{ReceiveSession, TransmitSession},
    tai64n::TAI64N,
};

/// The symmetric session keys produced by a WireGuard handshake.
struct SessionKeys {
    initiator_to_responder: chacha20poly1305::Key,
    responder_to_initiator: chacha20poly1305::Key,
}

/// Test/vector seam: abstracts over the two x25519-dalek ephemeral secret
/// types so the mix-chain has a single source of truth. Production uses
/// `ReusableSecret` (whose scalar bytes deliberately can't leak); the
/// deterministic reference-vector emitters (`initiate_handshake_with_ephemeral`,
/// `ReceivedHandshake::respond_vector`) use `StaticSecret`, which *is*
/// constructible from a fixed scalar, so an independent Python oracle can
/// reproduce the exact wire bytes. Both call the same `build_*` cores below,
/// so a vector can never validate against stale handshake logic.
trait EphemeralSecret {
    fn public_key(&self) -> x25519_dalek::PublicKey;
    fn dh(&self, peer: &x25519_dalek::PublicKey) -> [u8; 32];
}

impl EphemeralSecret for x25519_dalek::ReusableSecret {
    fn public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self)
    }
    fn dh(&self, peer: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.diffie_hellman(peer).to_bytes()
    }
}

impl EphemeralSecret for x25519_dalek::StaticSecret {
    fn public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self)
    }
    fn dh(&self, peer: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.diffie_hellman(peer).to_bytes()
    }
}

/// Shared initiator mix-chain core (single source of truth for the initiation
/// wire bytes and post-initiation handshake state).
fn build_initiation<E: EphemeralSecret>(
    endpoint_static: NodePrivateKey,
    peer_static: NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
    ephemeral: &E,
) -> (HandshakeState, HandshakeInitiation) {
    let ephemeral_pub = ephemeral.public_key();
    let endpoint_static_pub = NodePublicKey::from(endpoint_static);

    let mut pkt = HandshakeInitiation {
        sender_id: session_id,
        ephemeral_pub: ephemeral_pub.to_bytes(),
        ..Default::default()
    };

    let ss = x25519_dalek::StaticSecret::from(endpoint_static)
        .diffie_hellman(&peer_static.into())
        .to_bytes();
    let handshake = HandshakeState::new(peer_static)
        .mix_hash(ephemeral_pub.as_bytes()) // e
        .mix_key(ephemeral_pub.as_bytes()) // e (extra mixing required by psk variant)
        .mix_key(&ephemeral.dh(&peer_static.into())) // es
        .encrypt(endpoint_static_pub.as_bytes(), &mut pkt.static_pub_sealed) // s
        .mix_key(&ss) // ss
        .encrypt(timestamp.as_bytes(), &mut pkt.timestamp_sealed); // payload

    (handshake, pkt)
}

/// The state of a partially processed handshake.
#[derive(Clone)]
struct HandshakeState {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher: Option<ChaCha20Poly1305>,
}

fn must_cipher(key: &[u8]) -> ChaCha20Poly1305 {
    assert_eq!(key.len(), 32);
    ChaCha20Poly1305::new_from_slice(key).unwrap()
}

fn must_hkdf2(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 64];
    kdf.expand(&[], &mut expanded).unwrap();
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..].try_into().unwrap(),
    )
}

fn must_hkdf3(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 96];
    kdf.expand(&[], &mut expanded).unwrap();
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..64].try_into().unwrap(),
        expanded[64..].try_into().unwrap(),
    )
}

impl HandshakeState {
    fn new(responder_static: NodePublicKey) -> HandshakeState {
        let init = Blake2s256::digest("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        HandshakeState {
            hash: init.into(),
            chaining_key: init.into(),
            cipher: None,
        }
        .mix_hash(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
        .mix_hash(responder_static.as_bytes())
    }

    /// MixHash() in the Noise spec.
    fn mix_hash(mut self, data: &[u8]) -> Self {
        let mut h = Blake2s256::new_with_prefix(self.hash);
        h.update(data);
        h.finalize_into(self.hash.as_mut_bytes().into());
        self
    }

    /// MixKey() in the Noise spec.
    fn mix_key(self, key: &[u8; 32]) -> HandshakeState {
        let (ck, k) = must_hkdf2(&self.chaining_key, key);
        HandshakeState {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
    }

    /// The `psk` handshake step (KDF3). Retained even though Tailscale's PSK is
    /// all zeros — the chaining key must still advance through it.
    fn mix_psk(self, psk: &Psk) -> HandshakeState {
        let (ck, h, k) = must_hkdf3(&self.chaining_key, psk.as_ref());
        HandshakeState {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
        .mix_hash(&h)
    }

    /// Split() in the Noise spec.
    fn finish(self) -> SessionKeys {
        let (k1, k2) = must_hkdf2(&self.chaining_key, &[]);
        SessionKeys {
            initiator_to_responder: chacha20poly1305::Key::from(k1),
            responder_to_initiator: chacha20poly1305::Key::from(k2),
        }
    }

    /// EncryptAndHash(). dst must be 16 bytes longer than cleartext.
    fn encrypt(mut self, cleartext: &[u8], dst: &mut [u8]) -> HandshakeState {
        assert_eq!(
            dst.len(),
            cleartext.len() + 16,
            "output slice provided to encrypt must be 16 bytes longer than the input"
        );
        let cipher = self.cipher.take().unwrap();
        cleartext.write_to_prefix(dst).unwrap();
        let nonce = [0; 12];
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), &self.hash, &mut dst[..cleartext.len()])
            .unwrap();
        tag.write_to_suffix(dst).unwrap();
        self.mix_hash(dst)
    }

    /// DecryptAndHash().
    fn decrypt(mut self, ciphertext: &[u8], dst: &mut [u8]) -> Option<HandshakeState> {
        assert_eq!(
            dst.len(),
            ciphertext.len() - 16,
            "output slice provided to decrypt must be 16 bytes shorter than the input"
        );
        let cipher = self.cipher.take().unwrap();
        ciphertext[..dst.len()].write_to(dst).unwrap();
        let nonce = [0; 12];
        cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &self.hash,
                dst,
                ciphertext[dst.len()..].into(),
            )
            .inspect_err(|e| {
                tracing::warn!(error = %e, "decryption failed");
            })
            .ok()?;
        Some(self.mix_hash(ciphertext))
    }
}

/// A partially completed incoming handshake.
pub struct ReceivedHandshake {
    send_id: SessionId,
    peer_ephemeral: x25519_dalek::PublicKey,
    peer_static: NodePublicKey,
    pub timestamp: TAI64N,
    handshake: HandshakeState,
}

impl ReceivedHandshake {
    /// Process a peer's handshake initiation message.
    pub fn new(
        pkt: &HandshakeInitiation,
        my_static: &NodeKeyPair,
        macs: &MACReceiver,
    ) -> Option<ReceivedHandshake> {
        if !macs.verify_macs(pkt.as_bytes()) {
            return None;
        };

        let peer_ephemeral = x25519_dalek::PublicKey::from(pkt.ephemeral_pub);
        let my_static_dalek = x25519_dalek::StaticSecret::from(my_static.private);
        let mut peer_static_bytes = [0; 32];
        let mut timestamp = TAI64N::new_zeroed();
        let handshake = HandshakeState::new(my_static.public)
            .mix_hash(&pkt.ephemeral_pub) // e
            .mix_key(&pkt.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(my_static_dalek.diffie_hellman(&peer_ephemeral).as_bytes()) // es (reversed: responder)
            .decrypt(&pkt.static_pub_sealed, &mut peer_static_bytes)? // s
            .mix_key(
                my_static_dalek
                    .diffie_hellman(&x25519_dalek::PublicKey::from(peer_static_bytes))
                    .as_bytes(),
            ) // ss
            .decrypt(&pkt.timestamp_sealed, timestamp.as_mut_bytes())?; // payload

        Some(ReceivedHandshake {
            handshake,
            timestamp,
            peer_static: NodePublicKey::from(peer_static_bytes),
            peer_ephemeral: x25519_dalek::PublicKey::from(pkt.ephemeral_pub),
            send_id: pkt.sender_id,
        })
    }

    /// Shared responder mix-chain core (single source of truth for the response
    /// wire bytes and derived session keys).
    fn build_response<E: EphemeralSecret>(
        &self,
        session_id: SessionId,
        psk: &Psk,
        ephemeral: &E,
    ) -> (SessionKeys, HandshakeResponse) {
        let my_ephemeral_pub = ephemeral.public_key();
        let mut response = HandshakeResponse {
            sender_id: session_id,
            receiver_id: self.send_id,
            ephemeral_pub: my_ephemeral_pub.to_bytes(),
            ..Default::default()
        };

        let session_keys = self
            .handshake
            .clone()
            .mix_hash(&my_ephemeral_pub.to_bytes()) // e
            .mix_key(&my_ephemeral_pub.to_bytes()) // e (extra mixing required by psk variant)
            .mix_key(&ephemeral.dh(&self.peer_ephemeral)) // ee
            .mix_key(&ephemeral.dh(&self.peer_static.into())) // se (reversed: responder)
            .mix_psk(psk) // psk
            .encrypt(&[], &mut response.auth_tag) // payload (empty; must encrypt to produce auth tag)
            .finish();

        (session_keys, response)
    }

    /// Finalize the handshake, producing a HandshakeResponse packet.
    pub fn respond(
        self,
        session_id: SessionId,
        psk: &Psk,
        macs: &MACSender,
        now: Instant,
    ) -> (SessionPair, Packet) {
        let my_ephemeral = x25519_dalek::ReusableSecret::random_from_rng(OsRng);
        let (session_keys, response) = self.build_response(session_id, psk, &my_ephemeral);

        // Responder: send = responder_to_initiator, recv = initiator_to_responder.
        let send = TransmitSession::new(
            session_keys.responder_to_initiator,
            self.send_id,
            now,
            false,
        );
        let recv = ReceiveSession::new(session_keys.initiator_to_responder, session_id, now);

        let mut pkt = Packet::from_wire(response.as_bytes());
        macs.write_macs(pkt.as_mut());
        (SessionPair { send, recv }, pkt)
    }

    /// Deterministic reference-vector emitter for the responder path. Returns
    /// `(initiator_to_responder, responder_to_initiator, response)` for a fixed
    /// responder ephemeral scalar, so an independent oracle can reproduce and
    /// verify the response bytes and both derived transport keys. Not used in
    /// production. Runs the same `build_response` core as `respond`.
    #[doc(hidden)]
    pub fn respond_vector(
        &self,
        session_id: SessionId,
        psk: &Psk,
        ephemeral_scalar: [u8; 32],
    ) -> (chacha20poly1305::Key, chacha20poly1305::Key, HandshakeResponse) {
        let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_scalar);
        let (keys, response) = self.build_response(session_id, psk, &ephemeral);
        (
            keys.initiator_to_responder,
            keys.responder_to_initiator,
            response,
        )
    }

    pub fn peer_static(&self) -> NodePublicKey {
        self.peer_static
    }
}

/// Generate a handshake initiation message for a peer.
pub fn initiate_handshake(
    endpoint_static: NodePrivateKey,
    peer_static: NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
) -> (SentHandshake, HandshakeInitiation) {
    let ephemeral = x25519_dalek::ReusableSecret::random_from_rng(OsRng);
    let (handshake, pkt) =
        build_initiation(endpoint_static, peer_static, session_id, timestamp, &ephemeral);

    let ret = SentHandshake {
        id: session_id,
        my_ephemeral: ephemeral,
        my_static: endpoint_static,
        handshake,
    };

    (ret, pkt)
}

/// Deterministic reference-vector emitter: identical to `initiate_handshake`
/// but with a caller-supplied ephemeral scalar, so an independent oracle can
/// reproduce the exact 148-byte initiation. Not used in production (which must
/// use a fresh random ephemeral). Runs the same `build_initiation` core, so it
/// exercises the real wire encoding, not a re-implementation.
#[doc(hidden)]
pub fn initiate_handshake_with_ephemeral(
    endpoint_static: NodePrivateKey,
    peer_static: NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
    ephemeral_scalar: [u8; 32],
) -> HandshakeInitiation {
    let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_scalar);
    let (_handshake, pkt) =
        build_initiation(endpoint_static, peer_static, session_id, timestamp, &ephemeral);
    pkt
}

/// A partially completed sent handshake.
pub struct SentHandshake {
    pub id: SessionId,
    my_ephemeral: x25519_dalek::ReusableSecret,
    my_static: NodePrivateKey,
    handshake: HandshakeState,
}

pub struct SessionPair {
    pub send: TransmitSession,
    pub recv: ReceiveSession,
}

/// A handshake with a peer.
pub(crate) enum Handshake {
    /// No handshake in progress.
    None,
    /// We are the initiator, awaiting a response. Second field is the last-sent
    /// mac1 (AAD for a possible cookie reply). The handshake timeout lives in
    /// the endpoint's per-peer timer, not here.
    Initiated(SentHandshake, Mac),
    /// We are the responder, awaiting an initial transport message to confirm
    /// the new session.
    Responded(Box<SessionPair>),
}

impl Handshake {
    pub(crate) fn is_active(&self) -> bool {
        !matches!(self, Handshake::None)
    }

    pub(crate) fn session_id(&self) -> Option<SessionId> {
        match self {
            Handshake::Initiated(handshake, ..) => Some(handshake.id),
            Handshake::Responded(tentative) => Some(tentative.recv.id()),
            Handshake::None => None,
        }
    }

    /// Respond to a peer's handshake initiation, switching to responder state.
    pub(crate) fn respond(
        &mut self,
        session_id: SessionId,
        handshake: ReceivedHandshake,
        psk: &Psk,
        cookie_sender: &MACSender,
        now: Instant,
    ) -> Packet {
        let (session, packet) = handshake.respond(session_id, psk, cookie_sender, now);
        *self = Handshake::Responded(Box::new(session));
        packet
    }

    /// Finish a handshake as the initiator, returning the established sessions.
    pub(crate) fn finish(
        &mut self,
        packet: &HandshakeResponse,
        psk: &Psk,
        cookies: &MACReceiver,
        now: Instant,
    ) -> Option<SessionPair> {
        let Handshake::Initiated(sent_handshake, ..) = self else {
            return None;
        };

        // The response must answer THIS outstanding initiation: its
        // `receiver_id` is the `sender_id` we chose for the init we are
        // completing. Without this guard a late DERP-relayed response to an
        // earlier (rotated-out) initiation would be run against the current
        // ephemeral, whose `ee`/`se` DH inputs no longer match -- deriving a
        // wrong key and failing the empty-payload AEAD tag (the live
        // `aead::Error`). Reject the mismatch cleanly instead.
        if packet.receiver_id != sent_handshake.id {
            tracing::debug!("handshake response does not match the outstanding initiation");
            return None;
        }

        if !cookies.verify_macs(packet.as_bytes()) {
            return None;
        };

        let peer_ephemeral = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let handshake = sent_handshake.handshake.clone();
        let session_keys = handshake
            .mix_hash(&packet.ephemeral_pub) // e
            .mix_key(&packet.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(
                sent_handshake
                    .my_ephemeral
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // ee
            .mix_key(
                x25519_dalek::StaticSecret::from(sent_handshake.my_static)
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // se
            .mix_psk(psk) // psk
            .decrypt(&packet.auth_tag, &mut Vec::new()) // payload (empty; verifies auth tag)
            .map(|handshake| handshake.finish())?;

        // Initiator: send = initiator_to_responder, recv = responder_to_initiator.
        let send = TransmitSession::new(
            session_keys.initiator_to_responder,
            packet.sender_id,
            now,
            true,
        );
        let recv = ReceiveSession::new(
            session_keys.responder_to_initiator,
            sent_handshake.id,
            now,
        );

        // Transition to None; the endpoint cancels the timeout by clearing its
        // own per-peer timer when the handshake completes.
        *self = Handshake::None;

        Some(SessionPair { send, recv })
    }

    /// Confirm a handshake as responder, using the provided ciphertext packets.
    pub(crate) fn confirm(
        &mut self,
        session_id: SessionId,
        packets: Vec<Packet>,
    ) -> Option<(SessionPair, Vec<Packet>)> {
        let Handshake::Responded(tentative) = self else {
            return None;
        };

        if tentative.recv.id() != session_id {
            return None;
        };

        let packets = tentative.recv.decrypt(packets);
        if packets.is_empty() {
            return None;
        }

        let Handshake::Responded(tentative) = std::mem::replace(self, Handshake::None) else {
            unreachable!();
        };

        Some((*tentative, packets))
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use super::*;

    #[test]
    fn test_handshake() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = Psk::random();

        // Peer A sends a handshake initiation...
        let a_mac_send = MACSender::new(&b_static.public);
        let a_mac_recv = MACReceiver::new(&a_static.public);
        let a_session = SessionId::random();
        let a_init_time = TAI64N::now();
        let (a_handshake, init_pkt) =
            initiate_handshake(a_static.private, b_static.public, a_session, a_init_time);

        let mut init_pkt = Packet::from_wire(init_pkt.as_bytes());
        let handshake_mac = a_mac_send.write_macs(init_pkt.as_mut());
        let mut a_handshake = Handshake::Initiated(a_handshake, handshake_mac);

        // Peer B receives it and responds
        let init_ref = HandshakeInitiation::try_ref_from_bytes(init_pkt.as_ref())
            .expect("init_pkt should be a valid handshake initiation message");
        let b_mac_send = MACSender::new(&a_static.public);
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let b_handshake = ReceivedHandshake::new(init_ref, &b_static, &b_mac_recv)
            .expect("peer B should successfully process A's handshake initiation");
        assert_eq!(b_handshake.peer_static, a_static.public);
        assert_eq!(b_handshake.timestamp, a_init_time);
        let b_session_id = SessionId::random();
        let (mut b_session, response_pkt) =
            b_handshake.respond(b_session_id, &psk, &b_mac_send, Instant::now());

        // Peer A receives response
        let response_ref = HandshakeResponse::try_ref_from_bytes(response_pkt.as_ref())
            .expect("response_pkt should be a valid handshake response message");
        let Some(mut a_session) =
            a_handshake.finish(response_ref, &psk, &a_mac_recv, Instant::now())
        else {
            panic!("failed to process handshake response from peer B");
        };

        // They can now communicate
        let a_plaintext = vec![Packet::from_plaintext(b"xyzzy")];
        let mut packets = a_plaintext.clone();
        a_session.send.encrypt(packets.iter_mut());
        let b_received = b_session.recv.decrypt(packets);
        assert_eq!(b_received, a_plaintext);

        let b_plaintext = vec![Packet::from_plaintext(b"plover")];
        let mut packets = b_plaintext.clone();
        b_session.send.encrypt(packets.iter_mut());
        let a_received = a_session.recv.decrypt(packets);
        assert_eq!(a_received, b_plaintext);
    }
}
