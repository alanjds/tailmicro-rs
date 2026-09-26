//! DISCO path-discovery — minimal responder for ESP32-C3.
//!
//! ## Scope
//!
//! Phase 1 implements only what is needed for peers to reach *us*:
//! - Decrypt incoming DISCO messages with NaCl `crypto_box`
//!   (Curve25519-XSalsa20-Poly1305, 24-byte nonce) under the disco key — the
//!   same primitive real Tailscale disco uses (and the same one DERP uses
//!   for its ClientInfo/ServerInfo handshake). NOT XChaCha20-Poly1305, which
//!   this module used until it was cross-checked against
//!   `tools/wg_validator/disco.py` (pynacl `Box`, interoperated with a real
//!   peer) and the authoritative `ts_disco_protocol::packet::Packet`
//!   (`crypto_box::SalsaBox`) — see docs/wg-dataplane-notes.md.
//! - Respond to `Ping` with `Pong` (mandatory — without this, peers cannot
//!   confirm we are alive and will not complete the WireGuard handshake).
//!
//! Active probing (`CallMeMaybe`, outbound `Ping`) is deferred to Phase 4
//! (direct path discovery).  For DERP-only operation, passive response is
//! sufficient.
//!
//! ## MicroLink patterns
//!
//! * **Peer allowlist** — only process DISCO from peers in our WG peer table.
//!   Prevents CPU waste on large tailnets where many peers probe us.
//! * **PONG rate-limiting** — max one PONG per peer per 100 ms.
//!   (Adapted from dj-oyu's MicroLink contribution.)
//!
//! ## Memory
//!
//! No heap allocation.  All state is in fixed-size arrays on the struct.
 
use arrayvec::ArrayVec;
use crypto_box::aead::Aead;
use tm_keys::DiscoPrivateKey;

// ── DISCO wire format ─────────────────────────────────────────────────────────

/// DISCO message magic: the literal `TS💬` (6 bytes) that prefixes every disco
/// datagram on the wire, ahead of the sender's 32-byte disco public key.
/// Value and framing cross-checked against `tools/wg_validator/disco.py`
/// (`MAGIC`, which interoperated with a real Tailscale peer) and the
/// authoritative `ts_disco_protocol`. Previously a placeholder
/// (`\xc0\xde\x00\x00\x00\x00`) that was never actually checked.
pub const DISCO_MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";

/// Length of the disco magic prefix.
pub const MAGIC_LEN: usize = 6;

/// Disco message version byte (`plaintext[1]`); currently always 0.
pub const VERSION: u8 = 0;

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_CALL_ME_MAYBE: u8 = 0x03;

pub const PING_LEN:    usize = 12;
pub const PONG_LEN:    usize = 12;
pub const NONCE_LEN:   usize = 24;
pub const TAG_LEN:     usize = 16;
pub const PUBKEY_LEN:  usize = 32;

// ── Peer allowlist ────────────────────────────────────────────────────────────
//
// From MicroLink: on large tailnets, every peer sends DISCO probes.
// We only respond to peers we have a WireGuard entry for.
//
// MAX_ALLOWED matches MAX_PEERS in tm_control.

const MAX_ALLOWED: usize = 8;

/// Rate-limit state per peer (from MicroLink / dj-oyu).
struct PeerRateLimit {
    key:          [u8; 32],
    last_pong_ms: u64,
}

// ── DiscoActor ────────────────────────────────────────────────────────────────

pub enum DiscoCmd {
    /// A raw UDP datagram that may be a DISCO message.
    /// src_ip + src_port identifies who sent it.
    MaybeDisco {
        src_ip:   [u8; 4],
        src_port: u16,
        /// The shared channel packet buffer (`tm_buf`), forwarded by the
        /// event router exactly as `tm_derp` filled it (no copy into a
        /// disco-specific size). Boxed, as every channel payload is, so the
        /// message stays pointer-sized in `async_channel`'s ring buffer.
        data:     tm_buf::PktBox,
    },
    /// Add a peer to the allowlist.
    AllowPeer([u8; 32]),
    /// Remove a peer from the allowlist.
    RemovePeer([u8; 32]),
    Shutdown,
}

pub enum DiscoEvent {
    /// A PONG to send back.  Caller routes this via UDP or DERP.
    SendPong {
        dst_ip:   [u8; 4],
        dst_port: u16,
        payload:  [u8; PONG_LEN],
    },
    /// A peer sent us a PING — useful for latency metrics.
    PingFrom([u8; 32]),
}

pub struct DiscoActor {
    our_disco_key: DiscoPrivateKey,
    allowed:       ArrayVec<PeerRateLimit, MAX_ALLOWED>,
}

impl DiscoActor {
    pub fn new(our_disco_key: DiscoPrivateKey) -> Self {
        Self {
            our_disco_key,
            allowed: ArrayVec::new(),
        }
    }

    pub async fn run(
        mut self,
        mut cmds:  async_channel::Receiver<DiscoCmd>,
        events:    async_channel::Sender<DiscoEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Ok(DiscoCmd::MaybeDisco { src_ip, src_port, data }) => {
                    if let Some(evt) = self.process(&src_ip, src_port, &data) {
                        let _ = events.send(evt).await;
                    }
                }
                Ok(DiscoCmd::AllowPeer(key)) => {
                    self.add_peer(key);
                }
                Ok(DiscoCmd::RemovePeer(key)) => {
                    self.remove_peer(&key);
                }
                Ok(DiscoCmd::Shutdown) | Err(_) => break,
            }
        }
    }

    fn add_peer(&mut self, key: [u8; 32]) {
        // No-op if already present; evict oldest if full (LRU-ish)
        if self.allowed.iter().any(|p| p.key == key) { return; }
        if self.allowed.is_full() {
            self.allowed.remove(0);
        }
        self.allowed.push(PeerRateLimit { key, last_pong_ms: 0 });
    }

    fn remove_peer(&mut self, key: &[u8; 32]) {
        self.allowed.retain(|p| &p.key != key);
    }

    fn process(
        &mut self,
        src_ip:   &[u8; 4],
        src_port: u16,
        data:     &[u8],
    ) -> Option<DiscoEvent> {
        // A DISCO packet on the wire is:
        //   magic(6)="TS💬" + sender_disco_pub(32) + nonce(24) + SalsaBox_ct
        // (cross-checked against tools/wg_validator/disco.py's `open_disco`,
        // which interoperated with a real peer). The magic MUST be present and
        // checked, and every subsequent field is offset by MAGIC_LEN — the
        // previous code omitted the magic entirely and read every field 6
        // bytes early.
        if data.len() < MAGIC_LEN + PUBKEY_LEN + NONCE_LEN + TAG_LEN + 1 {
            return None;
        }
        if &data[..MAGIC_LEN] != DISCO_MAGIC {
            return None;
        }

        let sender_key: [u8; 32] =
            data[MAGIC_LEN..MAGIC_LEN + PUBKEY_LEN].try_into().ok()?;

        // Allowlist check (MicroLink pattern)
        let peer_state = self.allowed.iter_mut().find(|p| p.key == sender_key)?;

        // NaCl crypto_box: X25519 key agreement (with the HSalsa20 subkey
        // derivation crypto_box specifies) + XSalsa20-Poly1305 seal, matching
        // tools/wg_validator/disco.py's `Box(...).decrypt(...)` (pynacl,
        // interoperated with a real peer) and the authoritative
        // `ts_disco_protocol::packet::Packet::decrypt_in_place`
        // (`crypto_box::SalsaBox`). `SalsaBox::new` does both the DH and the
        // subkey derivation; previously this fed the raw X25519 shared
        // secret straight into ChaCha20Poly1305 as a key, which is neither
        // the same cipher family nor the same key-derivation NaCl specifies.
        let sender_pub = crypto_box::PublicKey::from(sender_key);
        let our_secret = crypto_box::SecretKey::from(*self.our_disco_key.as_bytes());
        let bx = crypto_box::SalsaBox::new(&sender_pub, &our_secret);

        let nonce_start = MAGIC_LEN + PUBKEY_LEN;
        let ct_start = nonce_start + NONCE_LEN;
        let nonce_bytes: [u8; 24] = data[nonce_start..ct_start]
            .try_into().ok()?;
        let mut ciphertext = heapless::Vec::<u8, 256>::new();
        ciphertext.extend_from_slice(&data[ct_start..]).ok()?;

        let nonce = crypto_box::Nonce::from(nonce_bytes);
        let plaintext = bx.decrypt(&nonce, ciphertext.as_ref()).ok()?;

        if plaintext.is_empty() { return None; }

        // Disco plaintext framing: type(1) + version(1) + body.
        // For PING the body is tx_id(12) + sender_node_key(32); the tx_id
        // therefore begins at plaintext[2], NOT plaintext[1] (the version
        // byte). Echoing from [1] would have PONGed `version || tx_id[0..11]`,
        // which the peer rejects as not matching its PING.
        match plaintext[0] {
            MSG_PING if plaintext.len() >= 2 + PING_LEN => {
                // Rate-limit: max 1 PONG per 100 ms per peer
                // (simplified — real impl uses esp_timer_get_time()).
                // The clock is not injected yet (now_ms == 0); guard the
                // limiter on a real clock so a stubbed 0 does not (a) suppress
                // every PONG via `0 - last < 100`, nor (b) underflow-panic
                // once last_pong_ms > 0. saturating_sub is belt-and-braces.
                let now_ms = 0u64; // TODO: inject clock
                if now_ms != 0 && now_ms.saturating_sub(peer_state.last_pong_ms) < 100 {
                    return None;
                }
                peer_state.last_pong_ms = now_ms;

                // Build PONG — echo the PING transaction ID (plaintext[2..14]).
                let tx_id: [u8; PING_LEN] =
                    plaintext[2..2 + PING_LEN].try_into().ok()?;
                let mut pong = [0u8; PONG_LEN];
                pong.copy_from_slice(&tx_id);

                Some(DiscoEvent::SendPong {
                    dst_ip:   *src_ip,
                    dst_port: src_port,
                    payload:  pong,
                })
            }
            MSG_PONG => None, // We don't probe (phase 1), so ignore pongs
            _ => None,
        }
    }
}

// ── AEAD cross-check against tools/wg_validator/disco.py ────────────────────
//
// Bug 2 fix (disco/control-plane bring-up, Kanban t_c414048d): confirms the
// exact crypto_box::SalsaBox construction used by `process()` above
// byte-for-byte decrypts a payload sealed by pynacl's `nacl.public.Box`
// (what `disco.py` uses, and what interoperated with a real Tailscale peer).
// Vector generated by tools/wg_validator (fixed keys/nonce, not random) --
// see docs/wg-dataplane-notes.md for the generator script and its output.
#[cfg(test)]
mod aead_crosscheck {
    use crypto_box::aead::Aead;

    #[test]
    fn salsa_box_decrypts_pynacl_sealed_payload() {
        // sender_priv = 01..20, receiver_priv = 21..40 (hex), both fixed.
        let receiver_priv: [u8; 32] = {
            let mut b = [0u8; 32];
            for i in 0..32 { b[i] = 0x21 + i as u8; }
            b
        };
        let sender_pub: [u8; 32] = [
            0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8, 0xb7, 0x55, 0xdc, 0x1b,
            0x10, 0xe8, 0x6c, 0xb4, 0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed,
            0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
        ];
        let nonce_bytes: [u8; 24] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let ciphertext: [u8; 62] = [
            0x14, 0x65, 0x88, 0x31, 0x12, 0x21, 0x5b, 0x96, 0xeb, 0x3b, 0x39, 0x19,
            0x96, 0xb2, 0x6c, 0x2b, 0x45, 0x01, 0xa9, 0x00, 0xd7, 0xb9, 0xd5, 0x02,
            0x84, 0x40, 0xca, 0xeb, 0x86, 0x12, 0x8b, 0xa5, 0xad, 0x1d, 0x85, 0xbb,
            0xcf, 0xc5, 0xdb, 0xd0, 0x55, 0x63, 0xdd, 0x93, 0xee, 0xc0, 0x5d, 0x8d,
            0x3c, 0x24, 0x6d, 0x61, 0x63, 0xf8, 0xbe, 0xe4, 0xf0, 0xf5, 0x70, 0xb9,
            0x1d, 0x9b,
        ];
        let expected_plaintext: [u8; 46] = [
            0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
        ];

        // Exactly the construction in `DiscoActor::process`.
        let sender_pk = crypto_box::PublicKey::from(sender_pub);
        let our_secret = crypto_box::SecretKey::from(receiver_priv);
        let bx = crypto_box::SalsaBox::new(&sender_pk, &our_secret);
        let nonce = crypto_box::Nonce::from(nonce_bytes);
        let plaintext = bx.decrypt(&nonce, ciphertext.as_ref())
            .expect("SalsaBox failed to open a pynacl-sealed payload");

        assert_eq!(plaintext, expected_plaintext);
    }
}

// ── Framing: magic skip + PING tx_id offset (Bug 4) ─────────────────────────
//
// Reuses the same pynacl-sealed vector as aead_crosscheck (sealed by
// nacl.public.Box, the primitive tools/wg_validator/disco.py uses and that
// interoperated with a real Tailscale peer). Here we wrap it into a full
// on-the-wire disco datagram (magic || sender_pub || nonce || ct) and drive it
// through the real DiscoActor::process, asserting the emitted PONG echoes the
// TRUE 12-byte tx_id at plaintext[2..14] (`01..0c`). The pre-fix code — no
// magic skip, tx_id read at plaintext[1..13] — could not even locate the
// sender key past the magic, and would have echoed `00 01..0b`.
#[cfg(test)]
mod framing {
    use super::*;
    use tm_keys::DiscoPrivateKey;

    fn vector() -> ([u8; 32], [u8; 32], [u8; 24], [u8; 62]) {
        let mut receiver_priv = [0u8; 32];
        for i in 0..32 { receiver_priv[i] = 0x21 + i as u8; }
        let sender_pub: [u8; 32] = [
            0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8, 0xb7, 0x55, 0xdc, 0x1b,
            0x10, 0xe8, 0x6c, 0xb4, 0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed,
            0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
        ];
        let nonce: [u8; 24] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let ct: [u8; 62] = [
            0x14, 0x65, 0x88, 0x31, 0x12, 0x21, 0x5b, 0x96, 0xeb, 0x3b, 0x39, 0x19,
            0x96, 0xb2, 0x6c, 0x2b, 0x45, 0x01, 0xa9, 0x00, 0xd7, 0xb9, 0xd5, 0x02,
            0x84, 0x40, 0xca, 0xeb, 0x86, 0x12, 0x8b, 0xa5, 0xad, 0x1d, 0x85, 0xbb,
            0xcf, 0xc5, 0xdb, 0xd0, 0x55, 0x63, 0xdd, 0x93, 0xee, 0xc0, 0x5d, 0x8d,
            0x3c, 0x24, 0x6d, 0x61, 0x63, 0xf8, 0xbe, 0xe4, 0xf0, 0xf5, 0x70, 0xb9,
            0x1d, 0x9b,
        ];
        (receiver_priv, sender_pub, nonce, ct)
    }

    #[test]
    fn process_extracts_ping_tx_id_after_magic() {
        let (receiver_priv, sender_pub, nonce, ct) = vector();

        // Build the full on-the-wire datagram.
        let mut pkt: Vec<u8> = Vec::new();
        pkt.extend_from_slice(DISCO_MAGIC);
        pkt.extend_from_slice(&sender_pub);
        pkt.extend_from_slice(&nonce);
        pkt.extend_from_slice(&ct);

        let mut actor = DiscoActor::new(DiscoPrivateKey::from_bytes(receiver_priv));
        actor.add_peer(sender_pub); // allowlist the sender's disco key

        let evt = actor
            .process(&[10, 0, 0, 1], 41641, &pkt)
            .expect("process should emit a PONG for a valid PING");

        match evt {
            DiscoEvent::SendPong { payload, .. } => {
                // True tx_id is plaintext[2..14] == 0x01..=0x0c.
                let expected: [u8; PONG_LEN] =
                    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
                assert_eq!(payload, expected, "PONG must echo the true PING tx_id");
            }
            _ => panic!("expected SendPong"),
        }
    }

    #[test]
    fn process_rejects_wrong_magic() {
        let (receiver_priv, sender_pub, nonce, ct) = vector();
        let mut pkt: Vec<u8> = Vec::new();
        pkt.extend_from_slice(b"NOPES!"); // 6 bytes, not the disco magic
        pkt.extend_from_slice(&sender_pub);
        pkt.extend_from_slice(&nonce);
        pkt.extend_from_slice(&ct);

        let mut actor = DiscoActor::new(DiscoPrivateKey::from_bytes(receiver_priv));
        actor.add_peer(sender_pub);
        assert!(actor.process(&[10, 0, 0, 1], 41641, &pkt).is_none());
    }
}
