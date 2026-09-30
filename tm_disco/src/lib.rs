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
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use tm_keys::DiscoPrivateKey;

// ── TEMPORARY instrumentation (round 6, ALLOCATIONS.md "Fix plan: DERP TLS
// handshake heap collapse" -> Step 4) ──────────────────────────────────────
//
// Same probe pattern as `tm_derp::heap_probe_blocks` (not reused directly to
// avoid adding a tm_disco -> tm_derp dependency for a temporary debug aid).
// Device-only; no-ops on host builds. Remove once Step 4 is resolved, or
// promote to a shared crate if it proves broadly useful.
#[inline(never)]
pub(crate) fn heap_probe_blocks(tag: &str) {
    #[cfg(target_os = "espidf")]
    unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        tracing::info!(
            "DiscoActor heap-blocks [{}]: total_free={} largest_free={} \
             free_blocks={} allocated_blocks={} total_blocks={}",
            tag, info.total_free_bytes, info.largest_free_block,
            info.free_blocks, info.allocated_blocks, info.total_blocks,
        );
    }
    #[cfg(not(target_os = "espidf"))]
    tracing::info!("DiscoActor heap-blocks [{}]: (host build; probe is device-only)", tag);
}

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
/// network/big-endian order) for a literal IPv4 endpoint. Matches
/// `ts_disco_protocol::endpoint::Endpoint`'s wire layout: 8 big-endian u16
/// words (the last two carrying the IPv4 octets via `::ffff:a.b.c.d`
/// mapping) followed by a big-endian u16 port.
///
/// Step 1 (LAN-direct-path plan): generalized from the DERP-only
/// `encode_derp_relay_src_ipport` (which now just calls this with the
/// `127.3.3.40:<region>` magic address) so a real direct-UDP PONG can carry
/// the peer's actual observed LAN address instead.
fn encode_src_ipport(addr: SocketAddrV4, out: &mut [u8]) {
    debug_assert_eq!(out.len(), ENDPOINT_LEN);
    let [a, b, c, d] = addr.ip().octets();
    out[..10].fill(0);
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = a;
    out[13] = b;
    out[14] = c;
    out[15] = d;
    out[16..18].copy_from_slice(&addr.port().to_be_bytes());
}

/// Encode `src_ipport` for the DERP-relay convention: the magic address
/// `127.3.3.40` with the port set to the DERP region. Kept as a thin
/// wrapper over `encode_src_ipport` so DERP-relayed PONGs keep their exact
/// existing wire output (byte-for-byte, per `pong_wire_matches_pynacl_reference`).
fn encode_derp_relay_src_ipport(region: u16, out: &mut [u8]) {
    let addr = SocketAddrV4::new(Ipv4Addr::from(DERP_RELAY_MAGIC_IP_OCTETS), region);
    encode_src_ipport(addr, out);
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
    disco_key: [u8; 32],
    /// The netmap's node key paired with `disco_key`. Needed so a UDP PING
    /// claiming a node key can be checked against the pairing the control
    /// plane actually gave us (Step 1: `AllowPeer` becomes
    /// `{ disco_key, node_key }`) -- DERP already authenticates the sender's
    /// node key via TLS+relay auth, but raw UDP does not, so this is the
    /// only thing standing between "some peer" and "any host on the LAN
    /// claiming to be that peer".
    node_key:  [u8; 32],
    /// Bug 2 fix: was a stubbed `now_ms` clock permanently at 0. A real
    /// monotonic instant (same primitive `tm_wg` already uses elsewhere in
    /// this workspace) means the 100 ms rate limit actually limits anything,
    /// instead of being permanently disabled by the `now_ms != 0` guard that
    /// existed only to avoid suppressing/underflowing on the stub.
    ///
    /// Step 1 bug fix: this used to be ONE `last_pong` shared across every
    /// transport. tailscaled sends its DERP and UDP PINGs back-to-back as
    /// part of normal direct-path probing, so the second path's PONG was
    /// silently suppressed by the first -- usually the UDP one, which is
    /// the one that actually matters for establishing a direct path.
    /// Split per path so a DERP PONG and a UDP PONG to the same peer within
    /// 100 ms of each other are both allowed.
    last_pong_derp: Option<Instant>,
    last_pong_udp:  Option<Instant>,
    /// The NaCl box (X25519 shared key + HSalsa20 subkey) for this peer's
    /// disco key, computed on its first authenticated-looking datagram and
    /// reused. ALLOCATIONS.md Step 9: `SalsaBox::new` is a full X25519
    /// scalar multiplication, about 46 ms on this CPU, and a PING used to
    /// pay for it twice (open, then seal the PONG). tailscaled caches the
    /// same way (`magicsock` `sharedKey`). Keyed by `disco_key`, so a
    /// rotated key is a new entry and never reuses a stale box.
    shared: Option<crypto_box::SalsaBox>,
}

/// Minimum spacing between PONGs sent to the same peer, per path (see
/// `PeerRateLimit::last_pong_derp`/`last_pong_udp` above).
const PONG_RATE_LIMIT: Duration = Duration::from_millis(100);

/// Minimum spacing between *decrypt attempts* (the expensive X25519 DH in
/// `crypto_box::SalsaBox::new`, several ms on this CPU) from the same
/// source IP, for UDP disco datagrams only. Over DERP, only already-
/// authenticated tailnet nodes can reach us at all (DERP relay itself gates
/// that), but over raw UDP any host on the LAN can spam disco-shaped
/// packets and force repeated expensive DH operations -- a DoS surface
/// DERP-only operation never had. This check runs BEFORE the allowlist
/// lookup/decrypt, keyed by source IP alone (not by claimed disco key,
/// which is attacker-controlled and public anyway), so it bounds cost even
/// against a flood of packets each claiming a different (real) peer.
const UDP_DECRYPT_RATE_LIMIT: Duration = Duration::from_millis(100);

/// Max distinct source IPs tracked by the pre-decrypt UDP rate limiter.
/// Small and FIFO-evicted, same pattern as the peer allowlist -- this is a
/// cheap cap on CPU/attack surface, not a precise per-host quota.
const MAX_UDP_RATE_IPS: usize = 8;

// ── DiscoActor ────────────────────────────────────────────────────────────────

/// Which transport a disco datagram arrived on (Step 1, LAN-direct-path
/// plan). Replaces the old `MaybeDisco { src_ip, src_port, src_node_key }`
/// trio, which could only ever represent the DERP case (`src_ip`/`src_port`
/// were always `[0;4]`/`0` reserved placeholders).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoSrc {
    /// Arrived over DERP. `node_key` is the peer's node public key, as seen
    /// on the DERP frame that carried this datagram
    /// (`DerpEvent::PacketReceived::src_key`) -- DERP routes/authenticates
    /// by node key, so this is trustworthy without any extra check.
    Derp { node_key: [u8; 32] },
    /// Arrived over direct UDP, from this observed peer address. Unlike the
    /// DERP case, UDP gives no authenticated node key for the sender --
    /// only what the plaintext PING body claims -- so callers must verify
    /// that claim against the netmap's disco-key/node-key pairing
    /// (`AllowPeer`) before trusting it. See `DiscoActor::process`.
    Udp(SocketAddrV4),
}

pub enum DiscoCmd {
    /// A datagram that may be a DISCO message, arriving over DERP or direct
    /// UDP (`src` distinguishes which).
    MaybeDisco {
        /// The shared channel packet buffer (`tm_buf`), forwarded by the
        /// event router exactly as the transport actor filled it (no copy
        /// into a disco-specific size). Pointer-sized, as every channel
        /// payload is, so the message stays small in `async_channel`'s ring
        /// buffer.
        src:  DiscoSrc,
        data: tm_buf::PktBuf,
    },
    /// Add a peer to the allowlist. Step 1: carries both keys (the router
    /// already has both from the netmap at the call site) so a UDP PING's
    /// claimed node key can be checked against the disco key's real
    /// pairing -- see `DiscoSrc::Udp`.
    AllowPeer { disco_key: [u8; 32], node_key: [u8; 32] },
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
    /// A fully sealed PONG datagram to send back to a peer over direct UDP
    /// (Step 1). `dst` is the peer's observed UDP source address -- the
    /// same address this PONG's `src_ipport` field carries, per real
    /// tailscaled's expectation: it tells the peer what address WE saw them
    /// send from, so it can confirm the round trip. Step 2 wires this to a
    /// real `tokio::net::UdpSocket::try_send_to`.
    SendPongUdp {
        dst:     SocketAddrV4,
        payload: [u8; SEALED_PONG_LEN],
    },
    /// A peer's disco PING was authenticated (node-key/disco-key pairing
    /// checked) over direct UDP from `addr`. Emitted alongside
    /// `SendPongUdp` so callers can eventually track "this peer has a
    /// working direct path" (Step 4's `WgCmd::DirectPathSeen` in the full
    /// plan; this round only emits the event).
    DirectPathSeen { node_key: [u8; 32], addr: SocketAddrV4 },
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
    /// Pre-decrypt rate limit state, keyed by UDP source IP only (see
    /// `UDP_DECRYPT_RATE_LIMIT`). Empty/unused for DERP-sourced disco.
    udp_ip_rate:   ArrayVec<(Ipv4Addr, Instant), MAX_UDP_RATE_IPS>,
    /// Our disco public key, derived once. Deriving it is itself an X25519
    /// base-point multiplication, which every PONG used to repeat.
    our_disco_pub: [u8; 32],
}

impl DiscoActor {
    pub fn new(our_disco_key: DiscoPrivateKey) -> Self {
        let our_disco_pub = *our_disco_key.public().as_bytes();
        Self {
            our_disco_key,
            our_disco_pub,
            allowed: ArrayVec::new(),
            home_region: 0,
            udp_ip_rate: ArrayVec::new(),
        }
    }

    pub async fn run(
        mut self,
        mut cmds:  async_channel::Receiver<DiscoCmd>,
        events:    async_channel::Sender<DiscoEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Ok(DiscoCmd::MaybeDisco { src, data }) => {
                    let udp = matches!(src, DiscoSrc::Udp(_));
                    if udp {
                        tm_buf::lat::stamp(tm_buf::lat::Hop::DiscoIn);
                    }
                    for evt in self.process(&src, &data) {
                        let pong = udp && matches!(evt, DiscoEvent::SendPongUdp { .. });
                        let _ = events.send(evt).await;
                        if pong {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::DiscoOut);
                        }
                    }
                }
                Ok(DiscoCmd::AllowPeer { disco_key, node_key }) => {
                    heap_probe_blocks("run: before AllowPeer/add_peer");
                    self.add_peer(disco_key, node_key);
                    heap_probe_blocks("run: after AllowPeer/add_peer");
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

    fn add_peer(&mut self, disco_key: [u8; 32], node_key: [u8; 32]) {
        // Already present: refresh the paired node_key (a peer's node key
        // is stable in practice, but this keeps the allowlist honest if the
        // netmap ever re-pairs it) rather than no-op.
        if let Some(p) = self.allowed.iter_mut().find(|p| p.disco_key == disco_key) {
            p.node_key = node_key;
            return;
        }
        if self.allowed.is_full() {
            self.allowed.remove(0);
        }
        self.allowed.push(PeerRateLimit {
            disco_key,
            node_key,
            last_pong_derp: None,
            last_pong_udp: None,
            shared: None,
        });
    }

    fn remove_peer(&mut self, key: &[u8; 32]) {
        self.allowed.retain(|p| &p.disco_key != key);
    }

    /// Pre-decrypt per-source-IP rate limit for UDP disco datagrams (Step
    /// 1's DoS mitigation, see `UDP_DECRYPT_RATE_LIMIT`). Returns `true` if
    /// this IP is allowed to proceed to the expensive decrypt path right
    /// now (and records the attempt), `false` if it must be dropped.
    fn check_udp_ip_rate(&mut self, ip: Ipv4Addr) -> bool {
        let now = Instant::now();
        if let Some(entry) = self.udp_ip_rate.iter_mut().find(|(a, _)| *a == ip) {
            if now.duration_since(entry.1) < UDP_DECRYPT_RATE_LIMIT {
                return false;
            }
            entry.1 = now;
            return true;
        }
        if self.udp_ip_rate.is_full() {
            self.udp_ip_rate.remove(0);
        }
        self.udp_ip_rate.push((ip, now));
        true
    }

    fn process(
        &mut self,
        src:  &DiscoSrc,
        data: &[u8],
    ) -> ArrayVec<DiscoEvent, 2> {
        let mut out = ArrayVec::new();

        // A DISCO packet on the wire is:
        //   magic(6)="TS💬" + sender_disco_pub(32) + nonce(24) + SalsaBox_ct
        // (cross-checked against tools/wg_validator/disco.py's `open_disco`,
        // which interoperated with a real peer). The magic MUST be present and
        // checked, and every subsequent field is offset by MAGIC_LEN — the
        // previous code omitted the magic entirely and read every field 6
        // bytes early.
        if data.len() < MAGIC_LEN + PUBKEY_LEN + NONCE_LEN + TAG_LEN + 1 {
            return out;
        }
        if &data[..MAGIC_LEN] != DISCO_MAGIC {
            return out;
        }

        // Step 1 DoS mitigation: over UDP, any host on the LAN can send a
        // disco-shaped packet claiming any (public, netmap-visible) disco
        // key, forcing an expensive X25519 DH below even though the AEAD
        // tag will never verify. Gate on source IP BEFORE that DH, not on
        // the (attacker-controlled) claimed sender key. Over DERP this
        // isn't needed: only already-authenticated tailnet nodes can reach
        // us at all.
        if let DiscoSrc::Udp(addr) = src {
            if !self.check_udp_ip_rate(*addr.ip()) {
                return out;
            }
        }

        let sender_key: [u8; 32] = match data[MAGIC_LEN..MAGIC_LEN + PUBKEY_LEN].try_into() {
            Ok(k) => k,
            Err(_) => return out,
        };

        // Allowlist check (MicroLink pattern)
        let peer_state = match self.allowed.iter_mut().find(|p| p.disco_key == sender_key) {
            Some(p) => p,
            None => return out,
        };
        let peer_node_key = peer_state.node_key;

        // NaCl crypto_box: X25519 key agreement (with the HSalsa20 subkey
        // derivation crypto_box specifies) + XSalsa20-Poly1305 seal, matching
        // tools/wg_validator/disco.py's `Box(...).decrypt(...)` (pynacl,
        // interoperated with a real peer) and the authoritative
        // `ts_disco_protocol::packet::Packet::decrypt_in_place`
        // (`crypto_box::SalsaBox`). `SalsaBox::new` does both the DH and the
        // subkey derivation; previously this fed the raw X25519 shared
        // secret straight into ChaCha20Poly1305 as a key, which is neither
        // the same cipher family nor the same key-derivation NaCl specifies.
        //
        // The box is cached per allowlisted peer (see `PeerRateLimit::shared`):
        // only the first datagram from a peer pays for the DH. The
        // pre-decrypt IP rate limit above still bounds a flood, and a
        // flood claiming an allowlisted key costs one DH per key, total.
        let our_disco_key = &self.our_disco_key;
        let bx = peer_state.shared.get_or_insert_with(|| {
            crypto_box::SalsaBox::new(
                &crypto_box::PublicKey::from(sender_key),
                &crypto_box::SecretKey::from(*our_disco_key.as_bytes()),
            )
        });

        let nonce_start = MAGIC_LEN + PUBKEY_LEN;
        let ct_start = nonce_start + NONCE_LEN;
        let nonce_bytes: [u8; 24] = match data[nonce_start..ct_start].try_into() {
            Ok(n) => n,
            Err(_) => return out,
        };
        let mut ciphertext = heapless::Vec::<u8, 256>::new();
        if ciphertext.extend_from_slice(&data[ct_start..]).is_err() {
            return out;
        }

        let nonce = crypto_box::Nonce::from(nonce_bytes);
        heap_probe_blocks("process: before bx.decrypt (Aead::decrypt allocates a Vec)");
        let plaintext = match bx.decrypt(&nonce, ciphertext.as_ref()) {
            Ok(p) => p,
            Err(_) => return out,
        };
        heap_probe_blocks("process: after bx.decrypt");

        if plaintext.is_empty() { return out; }

        // Disco plaintext framing: type(1) + version(1) + body.
        // For PING the body is tx_id(12) + sender_node_key(32); the tx_id
        // therefore begins at plaintext[2], NOT plaintext[1] (the version
        // byte). Echoing from [1] would have PONGed `version || tx_id[0..11]`,
        // which the peer rejects as not matching its PING.
        match plaintext[0] {
            MSG_PING if plaintext.len() >= 2 + PING_LEN => {
                // Step 1: a UDP PING's claimed node key (the body after
                // tx_id: tx_id(12) + sender_node_key(32)) must match the
                // netmap's disco-key/node-key pairing for this peer, or the
                // packet is dropped silently. This is a real security
                // property: DERP already guarantees peer identity via
                // TLS+relay auth, so a DERP-sourced PING needs no extra
                // check here, but raw UDP doesn't authenticate the sender
                // at all -- without this, one tailnet peer could spoof
                // another's disco key over UDP.
                if let DiscoSrc::Udp(_) = src {
                    if plaintext.len() < 2 + PING_LEN + PUBKEY_LEN {
                        return out; // too short to carry a claimed node key
                    }
                    let claimed_node_key: [u8; 32] = plaintext
                        [2 + PING_LEN..2 + PING_LEN + PUBKEY_LEN]
                        .try_into()
                        .expect("slice is exactly 32 bytes");
                    if claimed_node_key != peer_node_key {
                        return out; // spoofed/mismatched node key: drop
                    }
                }

                // Rate-limit: max 1 PONG per 100 ms per (peer, path).
                // Bug 2 fix: `last_pong_ms` used to be a stubbed `now_ms =
                // 0` clock, so this limiter was a permanent no-op.
                // `Instant::now()` is a real monotonic source (same
                // primitive `tm_wg` uses elsewhere in this workspace).
                // Step 1 bug fix: was keyed per-peer only, so back-to-back
                // DERP+UDP PINGs from tailscaled's normal direct-path
                // probing suppressed the second (usually UDP, the one that
                // matters) PONG. Now keyed per (peer, path) via separate
                // `last_pong_derp`/`last_pong_udp` fields.
                let now = Instant::now();
                let last_pong = match src {
                    DiscoSrc::Derp { .. } => &mut peer_state.last_pong_derp,
                    DiscoSrc::Udp(_) => &mut peer_state.last_pong_udp,
                };
                if let Some(last) = *last_pong {
                    if now.duration_since(last) < PONG_RATE_LIMIT {
                        return out;
                    }
                }
                *last_pong = Some(now);

                // Echo the PING transaction ID (plaintext[2..14]).
                let tx_id: [u8; PING_LEN] = match plaintext[2..2 + PING_LEN].try_into() {
                    Ok(t) => t,
                    Err(_) => return out,
                };

                heap_probe_blocks("process: before OsRng nonce + build_sealed_pong");
                let mut nonce_bytes = [0u8; NONCE_LEN];
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

                match src {
                    DiscoSrc::Derp { node_key } => {
                        let wire = seal_pong(
                            bx,
                            self.our_disco_pub,
                            PongSrc::Derp(self.home_region),
                            tx_id,
                            nonce_bytes,
                        );
                        heap_probe_blocks("process: after build_sealed_pong (SalsaBox seal done)");
                        let _ = out.try_push(DiscoEvent::SendPong {
                            dst_node_key: *node_key,
                            payload: wire,
                        });
                    }
                    DiscoSrc::Udp(addr) => {
                        // Real tailscaled expects `src_ipport` here to be
                        // the peer's OWN observed address (`dst`, this same
                        // `addr`) -- it tells the peer what address WE saw
                        // them send from, so it can confirm the round trip
                        // and trust the direct path.
                        let wire = seal_pong(
                            bx,
                            self.our_disco_pub,
                            PongSrc::Udp(*addr),
                            tx_id,
                            nonce_bytes,
                        );
                        heap_probe_blocks("process: after build_sealed_pong (SalsaBox seal done)");
                        let _ = out.try_push(DiscoEvent::SendPongUdp {
                            dst: *addr,
                            payload: wire,
                        });
                        let _ = out.try_push(DiscoEvent::DirectPathSeen {
                            node_key: peer_node_key,
                            addr: *addr,
                        });
                    }
                }
                out
            }
            MSG_PONG => out, // We don't probe (phase 1), so ignore pongs
            _ => out,
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
/// `src_ipport` is either the `127.3.3.40:<home_region>` DERP-relay
/// convention (see [`encode_derp_relay_src_ipport`]), when the PING arrived
/// over DERP and there is no literal source address to report, or (Step 1)
/// the peer's real observed UDP address, when it arrived over direct UDP.
#[derive(Clone, Copy)]
enum PongSrc {
    Derp(u16),
    Udp(SocketAddrV4),
}

#[cfg(test)]
fn build_sealed_pong(
    our_disco_key: &DiscoPrivateKey,
    src_ipport:    PongSrc,
    sender_pub:    [u8; 32],
    tx_id:         [u8; PING_LEN],
    nonce_bytes:   [u8; NONCE_LEN],
) -> [u8; SEALED_PONG_LEN] {
    // Same SalsaBox(our_priv, sender_pub) construction `process` uses to
    // decrypt a PING, just run in the encrypt direction -- exactly what
    // `tools/wg_validator/disco.py`'s `_seal` does with pynacl's
    // `Box.encrypt`.
    let bx = crypto_box::SalsaBox::new(
        &crypto_box::PublicKey::from(sender_pub),
        &crypto_box::SecretKey::from(*our_disco_key.as_bytes()),
    );
    seal_pong(&bx, *our_disco_key.public().as_bytes(), src_ipport, tx_id, nonce_bytes)
}

/// [`build_sealed_pong`] with the peer's box and our public key already
/// computed, i.e. without any X25519 operation (ALLOCATIONS.md Step 9).
fn seal_pong(
    bx:          &crypto_box::SalsaBox,
    our_pub:     [u8; 32],
    src_ipport:  PongSrc,
    tx_id:       [u8; PING_LEN],
    nonce_bytes: [u8; NONCE_LEN],
) -> [u8; SEALED_PONG_LEN] {
    let mut pong_plaintext = [0u8; PONG_PLAINTEXT_LEN];
    pong_plaintext[0] = MSG_PONG;
    pong_plaintext[1] = VERSION;
    pong_plaintext[2..2 + PING_LEN].copy_from_slice(&tx_id);
    match src_ipport {
        PongSrc::Derp(region) => encode_derp_relay_src_ipport(region, &mut pong_plaintext[2 + PING_LEN..]),
        PongSrc::Udp(addr) => encode_src_ipport(addr, &mut pong_plaintext[2 + PING_LEN..]),
    }

    let nonce = crypto_box::Nonce::from(nonce_bytes);
    let ciphertext = bx
        .encrypt(&nonce, pong_plaintext.as_ref())
        .expect("SalsaBox seal of a fixed 32-byte plaintext cannot fail");
    debug_assert_eq!(ciphertext.len(), PONG_PLAINTEXT_LEN + TAG_LEN);

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
        actor.add_peer(sender_pub, peer_node_key); // allowlist the sender's disco+node key

        let mut evts = actor.process(&DiscoSrc::Derp { node_key: peer_node_key }, &pkt);
        assert_eq!(evts.len(), 1, "a DERP PING should emit exactly one PONG event");
        let evt = evts.pop().expect("process should emit a PONG for a valid PING");

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
        actor.add_peer(sender_pub, [0xAA; 32]);
        assert!(actor.process(&DiscoSrc::Derp { node_key: [0xAA; 32] }, &pkt).is_empty());
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
            PongSrc::Derp(home_region),
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

    /// Step 1: same construction, but with a REAL literal UDP endpoint in
    /// `src_ipport` (`PongSrc::Udp`) instead of the `127.3.3.40:<region>`
    /// DERP-relay convention. Vector generated by
    /// `tools/wg_validator/gen_udp_pong_vector.py`, output committed at
    /// `tools/wg_validator/udp_pong_vector.txt` -- same fixed
    /// `receiver_priv`/`sender_pub` fixture as every other test in this
    /// file, same fixed-nonce technique as
    /// `pong_wire_matches_pynacl_reference` above, just addressed to
    /// `::ffff:192.168.15.139` port 41641 (the plan's own example) instead
    /// of a DERP region.
    #[test]
    fn udp_pong_wire_matches_pynacl_reference() {
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
        let peer_addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 15, 139), 41641);

        let wire = build_sealed_pong(
            &DiscoPrivateKey::from_bytes(receiver_priv),
            PongSrc::Udp(peer_addr),
            sender_pub,
            tx_id,
            nonce_bytes,
        );

        // tools/wg_validator/udp_pong_vector.txt, EXPECTED_UDP_PONG_WIRE.
        const EXPECTED_UDP_PONG_WIRE: [u8; SEALED_PONG_LEN] = [
            0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x58, 0x69, 0xaf, 0xf4, 0x50, 0x54,
            0x97, 0x32, 0xcb, 0xaa, 0xed, 0x5e, 0x5d, 0xf9, 0xb3, 0x0a, 0x6d, 0xa3,
            0x1c, 0xb0, 0xe5, 0x74, 0x2b, 0xad, 0x5a, 0xd4, 0xa1, 0xa7, 0x68, 0xf1,
            0xa6, 0x7b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x80, 0x45, 0x54, 0xec, 0x98, 0xdf, 0x49, 0x81, 0xc7, 0xef,
            0x0f, 0x41, 0xeb, 0xc7, 0x92, 0xa3, 0x46, 0x01, 0xa9, 0x00, 0xd7, 0xb9,
            0xd5, 0x02, 0x84, 0x40, 0xca, 0xeb, 0x86, 0x12, 0xb9, 0x96, 0x99, 0x28,
            0xb3, 0x8c, 0xf7, 0xfc, 0xe1, 0xeb, 0x96, 0xa1, 0x23, 0x04, 0xa1, 0x0a,
            0xbd, 0x67,
        ];

        assert_eq!(wire, EXPECTED_UDP_PONG_WIRE,
            "sealed UDP PONG wire bytes must match the independent pynacl reference");
    }
}

// ── Step 1: node-key/disco-key pairing + per-(peer,path) rate limiting ─────
//
// Unlike the crosscheck modules above (which validate against an external
// pynacl vector), these tests exercise `DiscoActor::process` end to end
// against wire bytes this module seals itself (a fresh, test-local disco
// keypair for the "peer" side, so both halves of the crypto_box DH are
// known here -- no dependency on the fixed pynacl vector's sender_pub,
// whose matching private key was never generated in Rust).
#[cfg(test)]
mod udp_security {
    use super::*;
    use crypto_box::aead::Aead;

    /// Seal a disco PING datagram exactly as a peer would, but under our
    /// own control of the peer's secret key (so we can build arbitrary
    /// plaintexts, e.g. a spoofed node key).
    fn build_sealed_ping(
        our_disco_pub:    [u8; 32],
        peer_secret:      &crypto_box::SecretKey,
        tx_id:            [u8; PING_LEN],
        claimed_node_key: Option<[u8; 32]>,
        nonce_bytes:      [u8; NONCE_LEN],
    ) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.push(MSG_PING);
        plaintext.push(VERSION);
        plaintext.extend_from_slice(&tx_id);
        if let Some(nk) = claimed_node_key {
            plaintext.extend_from_slice(&nk);
        }
        let bx = crypto_box::SalsaBox::new(
            &crypto_box::PublicKey::from(our_disco_pub),
            peer_secret,
        );
        let nonce = crypto_box::Nonce::from(nonce_bytes);
        let ciphertext = bx.encrypt(&nonce, plaintext.as_slice())
            .expect("SalsaBox seal of a small plaintext cannot fail");

        let mut wire = Vec::new();
        wire.extend_from_slice(DISCO_MAGIC);
        wire.extend_from_slice(peer_secret.public_key().as_bytes());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);
        wire
    }

    fn receiver_key() -> DiscoPrivateKey {
        let mut b = [0u8; 32];
        for i in 0..32 { b[i] = 0x61 + i as u8; }
        DiscoPrivateKey::from_bytes(b)
    }

    fn peer_secret() -> crypto_box::SecretKey {
        crypto_box::SecretKey::from([0x42u8; 32])
    }

    /// Step 1 security property: a UDP PING claiming a node key that does
    /// NOT match the netmap's disco-key/node-key pairing (`AllowPeer`) must
    /// be dropped silently -- not answered with a PONG. Over DERP this
    /// check is unnecessary (DERP authenticates the sender's node key via
    /// TLS+relay auth), but raw UDP has no such authentication, so without
    /// this check one tailnet peer could claim another's identity.
    #[test]
    fn udp_ping_with_mismatched_node_key_is_dropped() {
        let receiver = receiver_key();
        let mut actor = DiscoActor::new(receiver.clone());

        let peer_sk = peer_secret();
        let peer_pub = *peer_sk.public_key().as_bytes();
        let real_node_key = [0x11u8; 32];
        let spoofed_node_key = [0x22u8; 32]; // does NOT match real_node_key
        actor.add_peer(peer_pub, real_node_key);

        let tx_id: [u8; PING_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce_bytes: [u8; NONCE_LEN] = [7u8; NONCE_LEN];
        let wire = build_sealed_ping(
            *receiver.public().as_bytes(),
            &peer_sk,
            tx_id,
            Some(spoofed_node_key),
            nonce_bytes,
        );

        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 41641);
        let evts = actor.process(&DiscoSrc::Udp(addr), &wire);
        assert!(evts.is_empty(),
            "a UDP PING claiming a node key that doesn't match the disco key's \
             netmap pairing must be dropped silently, not answered");
    }

    /// ALLOCATIONS.md Step 9: the per-peer box is cached, so later PINGs
    /// skip the X25519 DH. Every PONG, first and cached, must still open
    /// under the peer's own independently computed box, and the cache must
    /// not let a forged PING through.
    #[test]
    fn cached_box_pongs_open_and_forgeries_still_fail() {
        let receiver = receiver_key();
        let mut actor = DiscoActor::new(receiver.clone());
        let peer_sk = peer_secret();
        let peer_pub = *peer_sk.public_key().as_bytes();
        let node_key = [0x11u8; 32];
        actor.add_peer(peer_pub, node_key);
        let peer_box = crypto_box::SalsaBox::new(
            &crypto_box::PublicKey::from(*receiver.public().as_bytes()),
            &peer_sk,
        );
        for (i, ip) in [5u8, 6, 7].iter().enumerate() {
            let tx_id = [i as u8 + 1; PING_LEN];
            let wire = build_sealed_ping(*receiver.public().as_bytes(), &peer_sk, tx_id, Some(node_key), [i as u8; NONCE_LEN]);
            // A fresh source IP per PING sidesteps the 100 ms pre-decrypt limit.
            let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, *ip), 41641);
            let evts = actor.process(&DiscoSrc::Udp(addr), &wire);
            let pong = match evts.first() {
                Some(DiscoEvent::SendPongUdp { payload, .. }) => *payload,
                _ => panic!("PING {} not answered", i),
            };
            assert_eq!(&pong[MAGIC_LEN..MAGIC_LEN + PUBKEY_LEN], receiver.public().as_bytes());
            let n = crypto_box::Nonce::from(<[u8; NONCE_LEN]>::try_from(&pong[MAGIC_LEN + PUBKEY_LEN..MAGIC_LEN + PUBKEY_LEN + NONCE_LEN]).unwrap());
            let pt = peer_box.decrypt(&n, &pong[MAGIC_LEN + PUBKEY_LEN + NONCE_LEN..]).expect("PONG opens under the peer's box");
            assert_eq!(pt[0], MSG_PONG);
            assert_eq!(&pt[2..2 + PING_LEN], &tx_id);
            std::thread::sleep(std::time::Duration::from_millis(110));
        }
        assert!(actor.allowed[0].shared.is_some());
        // Same claimed disco key, sealed by someone else: must not open.
        let forger = crypto_box::SecretKey::from([0x43u8; 32]);
        let mut wire = build_sealed_ping(*receiver.public().as_bytes(), &forger, [9; PING_LEN], Some(node_key), [9; NONCE_LEN]);
        wire[MAGIC_LEN..MAGIC_LEN + PUBKEY_LEN].copy_from_slice(&peer_pub);
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 41641);
        assert!(actor.process(&DiscoSrc::Udp(addr), &wire).is_empty());
    }

    /// The matching-node-key counterpart: a UDP PING whose claimed node key
    /// DOES match the allowlisted pairing must be answered with both a
    /// `SendPongUdp` and a `DirectPathSeen` event.
    #[test]
    fn udp_ping_with_matching_node_key_is_answered() {
        let receiver = receiver_key();
        let mut actor = DiscoActor::new(receiver.clone());

        let peer_sk = peer_secret();
        let peer_pub = *peer_sk.public_key().as_bytes();
        let real_node_key = [0x11u8; 32];
        actor.add_peer(peer_pub, real_node_key);

        let tx_id: [u8; PING_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce_bytes: [u8; NONCE_LEN] = [7u8; NONCE_LEN];
        let wire = build_sealed_ping(
            *receiver.public().as_bytes(),
            &peer_sk,
            tx_id,
            Some(real_node_key),
            nonce_bytes,
        );

        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 41641);
        let evts = actor.process(&DiscoSrc::Udp(addr), &wire);
        assert_eq!(evts.len(), 2,
            "a correctly-claimed UDP PING must emit SendPongUdp + DirectPathSeen");
        assert!(matches!(evts[0], DiscoEvent::SendPongUdp { dst, .. } if dst == addr));
        assert!(matches!(evts[1], DiscoEvent::DirectPathSeen { node_key, addr: a }
            if node_key == real_node_key && a == addr));
    }

    /// Step 1 bug fix: the 100ms PONG rate limit used to be keyed per peer
    /// only, so tailscaled's back-to-back DERP+UDP PINGs (normal
    /// direct-path probing) suppressed the second path's PONG -- usually
    /// the UDP one, the one that matters for establishing a direct path.
    /// A DERP PONG and a UDP PONG to the same peer within 100ms of each
    /// other must both go out.
    #[test]
    fn derp_and_udp_pongs_to_same_peer_within_100ms_both_go_out() {
        let receiver = receiver_key();
        let mut actor = DiscoActor::new(receiver.clone());

        let peer_sk = peer_secret();
        let peer_pub = *peer_sk.public_key().as_bytes();
        let node_key = [0x33u8; 32];
        actor.add_peer(peer_pub, node_key);

        // DERP PING: body is tx_id only (no claimed node key needed --
        // DERP already authenticates the sender).
        let tx_id: [u8; PING_LEN] = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let derp_nonce: [u8; NONCE_LEN] = [1u8; NONCE_LEN];
        let derp_wire = build_sealed_ping(
            *receiver.public().as_bytes(),
            &peer_sk,
            tx_id,
            None,
            derp_nonce,
        );
        let derp_evts = actor.process(&DiscoSrc::Derp { node_key }, &derp_wire);
        assert_eq!(derp_evts.len(), 1, "DERP PING should produce one SendPong");
        assert!(matches!(derp_evts[0], DiscoEvent::SendPong { .. }));

        // Immediately after (same process invocation, no sleep -- this is
        // exactly the back-to-back timing that triggered the bug), a UDP
        // PING to the SAME peer over a DIFFERENT path must also be
        // answered, not suppressed by the DERP PONG's rate-limit entry.
        let udp_nonce: [u8; NONCE_LEN] = [2u8; NONCE_LEN];
        let udp_wire = build_sealed_ping(
            *receiver.public().as_bytes(),
            &peer_sk,
            tx_id,
            Some(node_key),
            udp_nonce,
        );
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 41641);
        let udp_evts = actor.process(&DiscoSrc::Udp(addr), &udp_wire);
        assert_eq!(udp_evts.len(), 2,
            "a UDP PONG to the same peer within 100ms of a DERP PONG must \
             still go out (per-(peer,path) rate limiting, not per-peer)");
        assert!(matches!(udp_evts[0], DiscoEvent::SendPongUdp { .. }));
    }
}
