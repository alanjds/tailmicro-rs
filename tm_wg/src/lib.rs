//! WireGuard data-plane actor.
//!
//! The crypto core is vendored from `tailscale-rs`'s `ts_tunnel` crate (see
//! `mod vendor` and `docs/wg-dataplane-notes.md`); the endpoint is rewritten
//! against `ArrayVec` for bounded, no-heap operation (see `mod endpoint`).
//! There is no longer any C FFI: the fabricated `wireguard-lwip` externs and
//! the `wireguard_stub` cfg are gone.
//!
//! The actor owns a single-threaded [`WgEndpoint`], drives handshake/rekey/
//! keepalive from its own ~400ms tick (crypto stays off the socket-read path),
//! demuxes disco traffic ahead of the WireGuard parser, and models the
//! transport endpoint as a Rust [`Endpoint`] enum (no 127.3.3.40 fake-IP hack).

pub mod endpoint;
// `pub` so the vendored types that appear in `endpoint`'s public signatures
// (Packet, PeerId, PeerConfig, NodePublicKey, ...) are reachable. These are
// vendored library types; exposing them is harmless.
pub mod vendor;

use tm_control::{MapState, PeerInfo};

pub use endpoint::{Endpoint, MAX_PEERS, WgEndpoint};
use endpoint::RecvOut;
use vendor::config::{PeerConfig, PeerId, Psk};
use vendor::keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use vendor::packet::Packet;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Actor tick period. Mirrors MicroLink's `wireguardif_periodic()` ~400ms
/// discipline; drives handshake retry, rekey, and keepalive off the latency
/// path.
const TICK: Duration = Duration::from_millis(400);

// ── Message types ─────────────────────────────────────────────────────────────

pub enum WgCmd {
    /// Apply a fresh MapState — add new peers, remove gone ones.
    ///
    /// Boxed: `async_channel`'s unbounded ring buffer reserves 31 slots per
    /// block and returns each block by value, so an unboxed ~1.5KB variant here
    /// balloons the caller's stack frame. See the tailmicro-rs commit fixing
    /// the ESP32-C3 stack overflow at `Runtime::join()`'s `tokio::join!` entry.
    ApplyMap(Box<MapState<MAX_PEERS, 4>>),
    /// Route an incoming WireGuard packet received from DERP.
    InboundPacket {
        src_key: [u8; 32],
        payload: Box<heapless::Vec<u8, 1500>>,
    },
    Shutdown,
}

pub enum WgEvent {
    /// An outbound WireGuard packet to send via DERP.
    OutboundPacket {
        dst_key: [u8; 32],
        payload: Box<heapless::Vec<u8, 1500>>,
    },
    /// A decrypted inbound payload, destined for the local netstack.
    InboundDecrypted {
        src_key: [u8; 32],
        payload: Box<heapless::Vec<u8, 1500>>,
    },
    /// A WireGuard handshake completed with the given peer node key.
    PeerHandshook([u8; 32]),
}

// ── WgActor ───────────────────────────────────────────────────────────────────

pub struct WgActor {
    endpoint: WgEndpoint,
    /// Never-evicted peer (MicroLink: priority_peer). Retained for API
    /// compatibility; the fixed `MAX_PEERS` table currently rejects overflow
    /// rather than LRU-evicting.
    priority_peer: Option<[u8; 32]>,
}

impl WgActor {
    /// Create the actor from the node's WireGuard (node) private key.
    pub fn new(node_priv: [u8; 32], priority_peer: Option<[u8; 32]>) -> Self {
        let kp = NodeKeyPair::from_private(NodePrivateKey(node_priv));
        Self {
            endpoint: WgEndpoint::new(kp),
            priority_peer,
        }
    }

    pub async fn run(
        mut self,
        cmds: async_channel::Receiver<WgCmd>,
        events: async_channel::Sender<WgEvent>,
    ) {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                cmd = cmds.recv() => {
                    match cmd {
                        Ok(WgCmd::ApplyMap(map)) => self.apply_map(&map, &events).await,
                        Ok(WgCmd::InboundPacket { src_key, payload }) => {
                            self.on_inbound(src_key, &payload, &events).await;
                        }
                        Ok(WgCmd::Shutdown) | Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    self.on_tick(&events).await;
                }
            }
        }
    }

    async fn apply_map(&mut self, map: &MapState<MAX_PEERS, 4>, events: &async_channel::Sender<WgEvent>) {
        // Remove peers no longer present.
        let mut to_remove: heapless::Vec<PeerId, MAX_PEERS> = heapless::Vec::new();
        for i in 0..MAX_PEERS {
            // Walk current peers by re-querying; collect ids absent from map.
            if let Some(id) = self.endpoint_peer_ids().get(i).copied() {
                let key = self.endpoint.peer_key(id).map(|k| k.to_bytes());
                if let Some(key) = key {
                    if !map.peers.iter().any(|p| p.node_key == key) {
                        let _ = to_remove.push(id);
                    }
                }
            }
        }
        for id in to_remove {
            self.endpoint.remove_peer(id);
        }

        // Add new peers and proactively initiate a handshake to each.
        for peer in &map.peers {
            if self.endpoint.peer_id_by_key(&peer.node_key).is_some() {
                continue;
            }
            let cfg = PeerConfig {
                key: NodePublicKey::from_bytes(peer.node_key),
                // Tailscale's PSK is 32 zero bytes.
                psk: Psk::zero(),
            };
            let ep = Self::endpoint_for(peer);
            if let Some(id) = self.endpoint.add_peer(cfg, ep) {
                let now = Instant::now();
                if let Some(pkt) = self.endpoint.initiate(id, now, now_unix()) {
                    self.emit_to_peer(id, pkt, events).await;
                }
            } else {
                tracing::warn!(hostname = %peer.hostname, "peer table full; not adding peer");
            }
        }
    }

    fn endpoint_peer_ids(&self) -> heapless::Vec<PeerId, MAX_PEERS> {
        // Reconstruct ids by scanning known node keys via public accessors.
        // (Kept simple; the endpoint owns the authoritative table.)
        let mut ids: heapless::Vec<PeerId, MAX_PEERS> = heapless::Vec::new();
        for id in 1..=(MAX_PEERS as u32 * 4) {
            let pid = PeerId(id);
            if self.endpoint.peer_key(pid).is_some() {
                let _ = ids.push(pid);
            }
            if ids.is_full() {
                break;
            }
        }
        ids
    }

    fn endpoint_for(peer: &PeerInfo) -> Endpoint {
        Endpoint::Derp {
            region_id: peer.derp_region,
            node_key: peer.node_key,
        }
    }

    async fn on_inbound(
        &mut self,
        src_key: [u8; 32],
        payload: &heapless::Vec<u8, 1500>,
        events: &async_channel::Sender<WgEvent>,
    ) {
        // Primary disco demux happens at the runtime edge; recv_one also
        // sniffs the WireGuard type byte defensively.
        let from = Endpoint::Derp {
            region_id: 0,
            node_key: src_key,
        };
        let out = self.endpoint.recv_one(payload, from, Instant::now());
        self.drain_recv(src_key, out, events).await;
    }

    async fn on_tick(&mut self, events: &async_channel::Sender<WgEvent>) {
        let now = Instant::now();
        // next_event is advisory; we always tick, and only act on due timers.
        let outbound = self.endpoint.dispatch(now, now_unix());
        for (id, pkt) in outbound {
            self.emit_to_peer(id, pkt, events).await;
        }
    }

    async fn drain_recv(&self, src_key: [u8; 32], out: RecvOut, events: &async_channel::Sender<WgEvent>) {
        let dst_key = out
            .peer
            .and_then(|id| self.endpoint.peer_key(id))
            .map(|k| k.to_bytes())
            .unwrap_or(src_key);

        for pkt in out.to_peer {
            let _ = events
                .send(WgEvent::OutboundPacket {
                    dst_key,
                    payload: pkt_to_box(&pkt),
                })
                .await;
        }
        for pkt in out.decrypted {
            let _ = events
                .send(WgEvent::InboundDecrypted {
                    src_key: dst_key,
                    payload: pkt_to_box(&pkt),
                })
                .await;
        }
        if out.handshook {
            let _ = events.send(WgEvent::PeerHandshook(dst_key)).await;
        }
    }

    async fn emit_to_peer(&self, id: PeerId, pkt: Packet, events: &async_channel::Sender<WgEvent>) {
        if let Some(key) = self.endpoint.peer_key(id) {
            let _ = events
                .send(WgEvent::OutboundPacket {
                    dst_key: key.to_bytes(),
                    payload: pkt_to_box(&pkt),
                })
                .await;
        }
    }

    // Kept so callers/tests can inspect the never-evict setting.
    pub fn priority_peer(&self) -> Option<[u8; 32]> {
        self.priority_peer
    }
}

fn pkt_to_box(pkt: &Packet) -> Box<heapless::Vec<u8, 1500>> {
    let mut v: heapless::Vec<u8, 1500> = heapless::Vec::new();
    let _ = v.extend_from_slice(pkt.as_slice());
    Box::new(v)
}

/// Current Unix time in seconds, but only if the clock looks synced
/// (> 1_700_000_000 == pre-SNTP boot clock filtered out), matching the
/// control-key-pinning discipline in `src/config.rs`.
fn now_unix() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .filter(|&s| s > 1_700_000_000)
}
