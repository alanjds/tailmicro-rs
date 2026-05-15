//! DISCO path-discovery — minimal responder for ESP32-C3.
//!
//! ## Scope
//!
//! Phase 1 implements only what is needed for peers to reach *us*:
//! - Decrypt incoming DISCO messages (XChaCha20-Poly1305 with disco key).
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
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, AeadCore, Key};
use tm_keys::{DiscoPrivateKey, DiscoPublicKey};

// ── DISCO wire format ─────────────────────────────────────────────────────────

/// DISCO message magic (first 6 bytes after the DISCO header).
pub const DISCO_MAGIC: &[u8; 6] = b"\xc0\xde\x00\x00\x00\x00"; // simplified

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
        data:     heapless::Vec<u8, 256>,
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
        // A DISCO packet starts with the sender's 32-byte disco public key,
        // followed by a 24-byte nonce, followed by the encrypted payload.
        if data.len() < PUBKEY_LEN + NONCE_LEN + TAG_LEN + 1 {
            return None;
        }

        let sender_key: [u8; 32] = data[..PUBKEY_LEN].try_into().ok()?;

        // Allowlist check (MicroLink pattern)
        let peer_state = self.allowed.iter_mut().find(|p| p.key == sender_key)?;

        // Derive shared secret: our private disco key × sender's public disco key
        let sender_pk = x25519_dalek::PublicKey::from(sender_key);
        let shared = self.our_disco_key.as_static_secret().diffie_hellman(&sender_pk);

        // Decrypt with XChaCha20-Poly1305 (24-byte nonce)
        let nonce_bytes: [u8; 24] = data[PUBKEY_LEN..PUBKEY_LEN + NONCE_LEN]
            .try_into().ok()?;
        let mut ciphertext = heapless::Vec::<u8, 256>::new();
        ciphertext.extend_from_slice(&data[PUBKEY_LEN + NONCE_LEN..]).ok()?;

        let shared_bytes: [u8; 32] = *shared.as_bytes();
        let key = chacha20poly1305::Key::from_slice(&shared_bytes);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;

        if plaintext.is_empty() { return None; }

        match plaintext[0] {
            MSG_PING if plaintext.len() >= 1 + PING_LEN => {
                // Rate-limit: max 1 PONG per 100 ms per peer
                // (simplified — real impl uses esp_timer_get_time())
                let now_ms = 0u64; // TODO: inject clock
                if now_ms - peer_state.last_pong_ms < 100 {
                    return None;
                }
                peer_state.last_pong_ms = now_ms;

                // Build PONG — echo the PING transaction ID
                let tx_id: [u8; PING_LEN] = plaintext[1..1+PING_LEN].try_into().ok()?;
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
