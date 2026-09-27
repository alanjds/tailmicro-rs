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
use rand::RngCore;
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
pub const NONCE_LEN:   usize = 24;
pub const TAG_LEN:     usize = 16;
pub const PUBKEY_LEN:  usize = 32;

/// Length of the `src_ipport` field in a PONG's plaintext body: an
/// IPv4-mapped IPv6 address (16 bytes, network order) + a port (2 bytes,
/// network order) -- the same `Endpoint` encoding the authoritative
/// `ts_disco_protocol::endpoint::Endpoint` uses. Bug 2 fix: the previous
/// PONG carried only the bare 12-byte tx_id and omitted this field
/// entirely, which is not a wire-valid PONG (a real peer's magicsock
/// expects `type(1)+version(1)+tx_id(12)+src_ipport(18)`).
pub const ENDPOINT_LEN: usize = 18;

/// Full plaintext PONG body: type(1) + version(1) + tx_id(12) + src_ipport(18).
pub const PONG_PLAINTEXT_LEN: usize = 2 + PING_LEN + ENDPOINT_LEN;

/// Size of a fully sealed, on-the-wire PONG datagram we send:
/// magic(6) + our_disco_pub(32) + nonce(24) + (plaintext(32) + AEAD tag(16)).
pub const SEALED_PONG_LEN: usize =
    MAGIC_LEN + PUBKEY_LEN + NONCE_LEN + PONG_PLAINTEXT_LEN + TAG_LEN;

/// Tailscale's "this came via DERP, not real UDP" convention for a PONG's
/// `src_ipport`: the magic IPv4 address `127.3.3.40` (same one
/// `tm_control::DERP_MAGIC_IP` publishes as a DERP-home endpoint hint) with
/// the port set to the DERP region the ping arrived on. Real Tailscale peers
/// recognize this address as "relayed via DERP region N", not a literal
/// loopback address.
const DERP_RELAY_MAGIC_IP_OCTETS: [u8; 4] = [127, 3, 3, 40];

/// Encode `src_ipport` (18 bytes: IPv4-mapped IPv6 address + port, both
/// network/big-endian order) for the DERP-relay convention above, at the
/// given `region`. Matches `ts_disco_protocol::endpoint::Endpoint`'s wire
/// layout: 8 big-endian u16 words (the last two carrying the IPv4 octets
/// via `::ffff:a.b.c.d` mapping) followed by a big-endian u16 port.
fn encode_derp_relay_src_ipport(region: u16, out: &mut [u8]) {
    debug_assert_eq!(out.len(), ENDPOINT_LEN);
    let [a, b, c, d] = DERP_RELAY_MAGIC_IP_OCTETS;
    out[..10].fill(0);
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = a;
    out[13] = b;
    out[14] = c;
    out[15] = d;
    out[16..18].copy_from_slice(&region.to_be_bytes());
}

// ── Peer allowlist ────────────────────────────────────────────────────────────
//
// From MicroLink: on large tailnets, every peer sends DISCO probes.
// We only respond to peers we have a WireGuard entry for.
//
// MAX_ALLOWED matches MAX_PEERS in tm_control.

const MAX_ALLOWED: usize = 8;

/// Rate-limit state per peer (from MicroLink / dj-oyu).
struct PeerRateLimit {
    key:       [u8; 32],
    /// Bug 2 fix: was a stubbed `now_ms` clock permanently at 0. A real
    /// monotonic instant (same primitive `tm_wg` already uses elsewhere in
    /// this workspace) means the 100 ms rate limit actually limits anything,
    /// instead of being permanently disabled by the `now_ms != 0` guard that
    /// existed only to avoid suppressing/underflowing on the stub.
    last_pong: Option<std::time::Instant>,
}

/// Minimum spacing between PONGs sent to the same peer.
const PONG_RATE_LIMIT: core::time::Duration = core::time::Duration::from_millis(100);

// ── DiscoActor ────────────────────────────────────────────────────────────────

pub enum DiscoCmd {
    /// A datagram that may be a DISCO message, arriving over DERP (today,
    /// the only transport this client has) or, in the future, direct UDP.
    MaybeDisco {
        /// Reserved for a future direct-UDP disco path; always `[0; 4]`
        /// today since every disco datagram currently arrives over DERP.
        src_ip:   [u8; 4],
        /// Reserved alongside `src_ip`; always `0` today.
        src_port: u16,
        /// The peer's node public key, as seen on the DERP frame that
        /// carried this datagram (`DerpEvent::PacketReceived::src_key`).
        /// Bug 2 fix: this used to not be forwarded at all (the router sent
        /// `src_ip: [0; 4]` and nothing else identifying the sender), which
        /// made it impossible to address a `SendPong` reply back to the
        /// right peer over DERP -- DERP routes by node key, not by IP.
        src_node_key: [u8; 32],
        /// The shared channel packet buffer (`tm_buf`), forwarded by the
        /// event router exactly as `tm_derp` filled it (no copy into a
        /// disco-specific size). Pointer-sized, as every channel payload is, so
        /// the message stays small in `async_channel`'s ring buffer.
        data:     tm_buf::PktBuf,
    },
    /// Add a peer to the allowlist.
    AllowPeer([u8; 32]),
    /// Remove a peer from the allowlist.
    RemovePeer([u8; 32]),
    /// Our current DERP home region, from the latest `MapUpdate`'s
    /// `tm_control::select_home_region`. Used only to fill a PONG's
    /// `src_ipport` with the `127.3.3.40:<region>` DERP-relay convention
    /// (see `encode_derp_relay_src_ipport`).
    SetHomeRegion(u16),
    Shutdown,
}

pub enum DiscoEvent {
    /// A fully sealed PONG datagram to send back to a peer over DERP.
    SendPong {
        /// The peer to address this to (DERP routes by node key).
        dst_node_key: [u8; 32],
        /// Wire-ready bytes: `magic || our_disco_pub || nonce || sealed(type=2,
        /// ver=0, tx_id, src_ipport)`. Hand this to `DerpCmd::SendPacket`
        /// as-is.
        payload: [u8; SEALED_PONG_LEN],
    },
    /// A peer sent us a PING — useful for latency metrics.
    PingFrom([u8; 32]),
}

pub struct DiscoActor {
    our_disco_key: DiscoPrivateKey,
    allowed:       ArrayVec<PeerRateLimit, MAX_ALLOWED>,
    /// See `DiscoCmd::SetHomeRegion`. Defaults to 0 (unknown) until the
    /// first `MapUpdate` tells us; a PONG sent before then just carries an
    /// uninformative region 0 in `src_ipport`, which is harmless (peers use
    /// `src_ipport` for endpoint-tracking heuristics, not as the sole path).
    home_region:   u16,
}

impl DiscoActor {
    pub fn new(our_disco_key: DiscoPrivateKey) -> Self {
        Self {
            our_disco_key,
            allowed: ArrayVec::new(),
            home_region: 0,
        }
    }

    pub async fn run(
        mut self,
        mut cmds:  async_channel::Receiver<DiscoCmd>,
        events:    async_channel::Sender<DiscoEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Ok(DiscoCmd::MaybeDisco { src_node_key, data, .. }) => {
                    if let Some(evt) = self.process(&src_node_key, &data) {
                        let _ = events.send(evt).await;
                    }
                }
                Ok(DiscoCmd::AllowPeer(key)) => {
                    self.add_peer(key);
                }
                Ok(DiscoCmd::RemovePeer(key)) => {
                    self.remove_peer(&key);
                }
                Ok(DiscoCmd::SetHomeRegion(rid)) => {
                    self.home_region = rid;
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
        self.allowed.push(PeerRateLimit { key, last_pong: None });
    }

    fn remove_peer(&mut self, key: &[u8; 32]) {
        self.allowed.retain(|p| &p.key != key);
    }

    fn process(
        &mut self,
        src_node_key: &[u8; 32],
        data:         &[u8],
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
                // Rate-limit: max 1 PONG per 100 ms per peer (MicroLink /
                // dj-oyu). Bug 2 fix: `last_pong_ms` used to be a stubbed
                // `now_ms = 0` clock, so this limiter was a permanent no-op.
                // `Instant::now()` is a real monotonic source (same
                // primitive `tm_wg` uses elsewhere in this workspace).
                let now = std::time::Instant::now();
                if let Some(last) = peer_state.last_pong {
                    if now.duration_since(last) < PONG_RATE_LIMIT {
                        return None;
                    }
                }
                peer_state.last_pong = Some(now);

                // Echo the PING transaction ID (plaintext[2..14]).
                let tx_id: [u8; PING_LEN] =
                    plaintext[2..2 + PING_LEN].try_into().ok()?;

                let mut nonce_bytes = [0u8; NONCE_LEN];
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                let wire = build_sealed_pong(
                    &self.our_disco_key,
                    self.home_region,
                    sender_key,
                    tx_id,
                    nonce_bytes,
                );

                Some(DiscoEvent::SendPong {
                    dst_node_key: *src_node_key,
                    payload: wire,
                })
            }
            MSG_PONG => None, // We don't probe (phase 1), so ignore pongs
            _ => None,
        }
    }
}

/// Build a fully sealed, on-the-wire PONG datagram.
///
/// Pulled out of [`DiscoActor::process`] as a free function (no `&self`, no
/// allowlist/rate-limit side effects) so the wire-format construction can be
/// unit-tested directly against a fixed-nonce vector from
/// `tools/wg_validator/disco.py`, matching this project's habit of
/// cross-checking crypto/wire-format code against an independent Python
/// reference before trusting it (see `aead_crosscheck` below, and
/// docs/wg-dataplane-notes.md).
///
/// Wire format:
///   plaintext = type(1)=MSG_PONG || version(1)=0 || tx_id(12) || src_ipport(18)
///   wire      = magic(6) || our_disco_pub(32) || nonce(24) || SalsaBox(plaintext)
///
/// `src_ipport` uses the `127.3.3.40:<home_region>` DERP-relay convention
/// (see [`encode_derp_relay_src_ipport`]): the PING arrived over DERP, not
/// real UDP, so there is no literal source address to report.
fn build_sealed_pong(
    our_disco_key: &DiscoPrivateKey,
    home_region:   u16,
    sender_pub:    [u8; 32],
    tx_id:         [u8; PING_LEN],
    nonce_bytes:   [u8; NONCE_LEN],
) -> [u8; SEALED_PONG_LEN] {
    let mut pong_plaintext = [0u8; PONG_PLAINTEXT_LEN];
    pong_plaintext[0] = MSG_PONG;
    pong_plaintext[1] = VERSION;
    pong_plaintext[2..2 + PING_LEN].copy_from_slice(&tx_id);
    encode_derp_relay_src_ipport(home_region, &mut pong_plaintext[2 + PING_LEN..]);

    // Same SalsaBox(our_priv, sender_pub) construction `process` uses to
    // decrypt a PING, just run in the encrypt direction -- exactly what
    // `tools/wg_validator/disco.py`'s `_seal` does with pynacl's
    // `Box.encrypt`.
    let bx = crypto_box::SalsaBox::new(
        &crypto_box::PublicKey::from(sender_pub),
        &crypto_box::SecretKey::from(*our_disco_key.as_bytes()),
    );
    let nonce = crypto_box::Nonce::from(nonce_bytes);
    let ciphertext = bx
        .encrypt(&nonce, pong_plaintext.as_ref())
        .expect("SalsaBox seal of a fixed 32-byte plaintext cannot fail");
    debug_assert_eq!(ciphertext.len(), PONG_PLAINTEXT_LEN + TAG_LEN);

    let our_pub = *our_disco_key.public().as_bytes();
    let mut wire = [0u8; SEALED_PONG_LEN];
    let mut off = 0;
    wire[off..off + MAGIC_LEN].copy_from_slice(DISCO_MAGIC);
    off += MAGIC_LEN;
    wire[off..off + PUBKEY_LEN].copy_from_slice(&our_pub);
    off += PUBKEY_LEN;
    wire[off..off + NONCE_LEN].copy_from_slice(&nonce_bytes);
    off += NONCE_LEN;
    wire[off..off + ciphertext.len()].copy_from_slice(&ciphertext);
    wire
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

        let peer_node_key = [0xAAu8; 32]; // arbitrary: the DERP-frame sender's node key
        let mut actor = DiscoActor::new(DiscoPrivateKey::from_bytes(receiver_priv));
        actor.add_peer(sender_pub); // allowlist the sender's disco key

        let evt = actor
            .process(&peer_node_key, &pkt)
            .expect("process should emit a PONG for a valid PING");

        match evt {
            DiscoEvent::SendPong { dst_node_key, payload } => {
                assert_eq!(dst_node_key, peer_node_key,
                    "PONG must be addressed back to the DERP frame's sender");
                // Sealed under a random nonce (process() draws it from
                // OsRng), so decrypt the payload we got back to check the
                // plaintext rather than comparing raw bytes. Uses the exact
                // same SalsaBox construction `process` used to decrypt the
                // PING (crypto_box DH is symmetric in its two public
                // arguments, so this is legitimate self-consistency, not a
                // tautology -- see the `pong_wire_matches_pynacl_reference`
                // crosscheck below for an external, non-self-referential
                // check of the same wire format).
                assert_eq!(payload.len(), SEALED_PONG_LEN);
                assert_eq!(&payload[..MAGIC_LEN], DISCO_MAGIC);
                let our_pub_in_wire = &payload[MAGIC_LEN..MAGIC_LEN + PUBKEY_LEN];
                let nonce_start = MAGIC_LEN + PUBKEY_LEN;
                let ct_start = nonce_start + NONCE_LEN;
                let nonce_bytes: [u8; NONCE_LEN] =
                    payload[nonce_start..ct_start].try_into().unwrap();

                let receiver_secret = crypto_box::SecretKey::from(receiver_priv);
                let sender_pub_key = crypto_box::PublicKey::from(sender_pub);
                assert_eq!(our_pub_in_wire, receiver_secret.public_key().as_bytes(),
                    "wire must carry our real disco pubkey, not the peer's");
                let bx = crypto_box::SalsaBox::new(&sender_pub_key, &receiver_secret);
                let nonce = crypto_box::Nonce::from(nonce_bytes);
                let plaintext = bx.decrypt(&nonce, &payload[ct_start..])
                    .expect("PONG ciphertext must decrypt under the same SalsaBox");

                assert_eq!(plaintext[0], MSG_PONG);
                assert_eq!(plaintext[1], VERSION);
                let expected_tx_id: [u8; PING_LEN] =
                    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
                assert_eq!(&plaintext[2..2 + PING_LEN], &expected_tx_id[..],
                    "PONG must echo the true PING tx_id");
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
        assert!(actor.process(&[0xAA; 32], &pkt).is_none());
    }
}

// ── PONG-sealing cross-check against tools/wg_validator/disco.py ───────────
//
// Bug 2 fix: unlike `framing::process_extracts_ping_tx_id_after_magic`
// (which decrypts with the SAME SalsaBox construction it is validating --
// useful for wiring but not for catching a shared encode/decode bug), this
// drives `build_sealed_pong` with a FIXED nonce and compares the emitted
// wire bytes byte-for-byte against a vector generated by pynacl's
// `nacl.public.Box.encrypt` (the same library `disco.py`'s `build_pong`
// uses), an independent implementation. See docs/wg-dataplane-notes.md for
// the generator script and its output.
#[cfg(test)]
mod pong_seal_crosscheck {
    use super::*;

    #[test]
    fn pong_wire_matches_pynacl_reference() {
        // Same fixed receiver_priv/sender_pub vector as `aead_crosscheck`
        // and `framing`.
        let mut receiver_priv = [0u8; 32];
        for i in 0..32 { receiver_priv[i] = 0x21 + i as u8; }
        let sender_pub: [u8; 32] = [
            0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8, 0xb7, 0x55, 0xdc, 0x1b,
            0x10, 0xe8, 0x6c, 0xb4, 0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed,
            0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
        ];
        let tx_id: [u8; PING_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce_bytes: [u8; NONCE_LEN] = {
            let mut n = [0u8; NONCE_LEN];
            for i in 0..NONCE_LEN { n[i] = (i + 1) as u8; }
            n
        };
        let home_region: u16 = 7;

        let wire = build_sealed_pong(
            &DiscoPrivateKey::from_bytes(receiver_priv),
            home_region,
            sender_pub,
            tx_id,
            nonce_bytes,
        );

        // Generated by tools/wg_validator/disco.py's underlying pynacl call
        // -- Box(receiver_priv, sender_pub).encrypt(plaintext, nonce) with
        // plaintext = 02 00 || tx_id(01..0c) || src_ipport (::ffff:127.3.3.40,
        // port=7, network order) and this exact fixed nonce. See the module
        // doc comment for the generator script.
        const EXPECTED_PONG_WIRE: [u8; SEALED_PONG_LEN] = [
            0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x58, 0x69, 0xaf, 0xf4, 0x50, 0x54,
            0x97, 0x32, 0xcb, 0xaa, 0xed, 0x5e, 0x5d, 0xf9, 0xb3, 0x0a, 0x6d, 0xa3,
            0x1c, 0xb0, 0xe5, 0x74, 0x2b, 0xad, 0x5a, 0xd4, 0xa1, 0xa7, 0x68, 0xf1,
            0xa6, 0x7b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x9e, 0x67, 0xd0, 0xa7, 0x67, 0xf4, 0x22, 0x22, 0x93, 0x8e,
            0x1c, 0x8c, 0x1d, 0x0e, 0xdc, 0x5c, 0x46, 0x01, 0xa9, 0x00, 0xd7, 0xb9,
            0xd5, 0x02, 0x84, 0x40, 0xca, 0xeb, 0x86, 0x12, 0xb9, 0x96, 0x99, 0x28,
            0xb3, 0x8c, 0xf7, 0xfc, 0xe1, 0xeb, 0x96, 0xa1, 0x9c, 0xaf, 0xad, 0xa9,
            0x1f, 0xc9,
        ];

        assert_eq!(wire, EXPECTED_PONG_WIRE,
            "sealed PONG wire bytes must match the independent pynacl reference");
    }
}
