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
    // Boxed: `WgEndpoint` is ~28 KB (fixed peer table + session state). Kept
    // by value it was embedded — and duplicated — inside the `run()` async
    // state machine, ballooning that future to ~90 KB. `Box::pin`-ing the
    // future at spawn time then tried to build all ~90 KB on the ESP32-C3's
    // 32 KB main-task stack, hitting a Guru Meditation stack-protection fault
    // in Runtime::join. Boxing the endpoint keeps only an 8-byte pointer in
    // the future. See docs/wg-dataplane-notes.md.
    //
    // LAZY (`Option`): the ~28 KB endpoint is not allocated at construction but
    // on first use (the first `ApplyMap`/inbound packet). Runtime::join builds
    // all actors up front, so an eager endpoint took ~28 KB out of the heap
    // BEFORE the control plane even connected — dropping the largest contiguous
    // block to ~69 KB, too small to also buffer the live ~40 KB netmap during
    // the control read (confirmed live: a concurrent "12100 bytes failed" OOM
    // abort while our map buffer held the last big block). Deferring the
    // allocation until `apply_map` — which runs only AFTER the control plane
    // has parsed the netmap and freed its buffer — keeps that ~28 KB free
    // exactly when the map read needs it. See docs/wg-dataplane-notes.md.
    endpoint: Option<Box<WgEndpoint>>,
    /// Node keypair, retained so the endpoint can be built lazily on first use.
    kp: NodeKeyPair,
    /// Never-evicted peer (MicroLink: priority_peer). Retained for API
    /// compatibility; the fixed `MAX_PEERS` table currently rejects overflow
    /// rather than LRU-evicting.
    priority_peer: Option<[u8; 32]>,
}

impl WgActor {
    /// Create the actor from the node's WireGuard (node) private key. The
    /// heavy `WgEndpoint` is allocated lazily (see `endpoint`), not here.
    pub fn new(node_priv: [u8; 32], priority_peer: Option<[u8; 32]>) -> Self {
        let kp = NodeKeyPair::from_private(NodePrivateKey(node_priv));
        Self {
            endpoint: None,
            kp,
            priority_peer,
        }
    }

    /// Get the endpoint, allocating (and boxing) it on first use. `new_boxed`
    /// builds+boxes in its own `#[inline(never)]` frame to keep the ~28 KB off
    /// this caller's stack.
    fn endpoint(&mut self) -> &mut WgEndpoint {
        if self.endpoint.is_none() {
            tracing::info!("WgActor: allocating WgEndpoint (~28 KB) on first use");
            self.endpoint = Some(WgEndpoint::new_boxed(self.kp));
        }
        self.endpoint.as_mut().unwrap()
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
                        // Box::pin the per-command handlers so their (multi-KB)
                        // futures are heap-allocated on demand instead of being
                        // inlined into this `run()` state machine. Without this
                        // the `run` future embeds on_inbound/apply_map/on_tick
                        // by value (~90 KB total) and building it on the 32 KB
                        // main-task stack faults. See docs/wg-dataplane-notes.md.
                        Ok(WgCmd::ApplyMap(map)) => Box::pin(self.apply_map(&map, &events)).await,
                        Ok(WgCmd::InboundPacket { src_key, payload }) => {
                            Box::pin(self.on_inbound(src_key, &payload, &events)).await;
                        }
                        Ok(WgCmd::Shutdown) | Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    Box::pin(self.on_tick(&events)).await;
                }
            }
        }
    }

    async fn apply_map(&mut self, map: &MapState<MAX_PEERS, 4>, events: &async_channel::Sender<WgEvent>) {
        // Materialize the endpoint now (first ApplyMap). This is the ~28 KB
        // allocation deferred from construction; it runs only after the control
        // plane has already parsed and freed its netmap buffer.
        self.endpoint();

        // Remove peers no longer present.
        let mut to_remove: heapless::Vec<PeerId, MAX_PEERS> = heapless::Vec::new();
        for i in 0..MAX_PEERS {
            // Walk current peers by re-querying; collect ids absent from map.
            if let Some(id) = self.endpoint_peer_ids().get(i).copied() {
                let key = self.endpoint().peer_key(id).map(|k| k.to_bytes());
                if let Some(key) = key {
                    if !map.peers.iter().any(|p| p.node_key == key) {
                        let _ = to_remove.push(id);
                    }
                }
            }
        }
        for id in to_remove {
            self.endpoint().remove_peer(id);
        }

        // Add new peers and proactively initiate a handshake to each.
        for peer in &map.peers {
            if self.endpoint().peer_id_by_key(&peer.node_key).is_some() {
                continue;
            }
            let cfg = PeerConfig {
                key: NodePublicKey::from_bytes(peer.node_key),
                // Tailscale's PSK is 32 zero bytes.
                psk: Psk::zero(),
            };
            let ep = Self::endpoint_for(peer);
            if let Some(id) = self.endpoint().add_peer(cfg, ep) {
                let now = Instant::now();
                if let Some(pkt) = self.endpoint().initiate(id, now, now_unix()) {
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
        let Some(endpoint) = self.endpoint.as_deref() else {
            return ids; // no endpoint yet -> no peers
        };
        for id in 1..=(MAX_PEERS as u32 * 4) {
            let pid = PeerId(id);
            if endpoint.peer_key(pid).is_some() {
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
        // Box the RecvOut (~12 KB of packet buffers) before it crosses the
        // `drain_recv` await boundary: kept by value it was held twice (as the
        // captured argument and a moved-out local) plus a multi-KB consuming
        // iterator, ~33 KB on the stack. Boxed, only an 8-byte pointer lives
        // in the future.
        let out = Box::new(self.endpoint().recv_one(payload, from, Instant::now()));
        self.drain_recv(src_key, out, events).await;
    }

    async fn on_tick(&mut self, events: &async_channel::Sender<WgEvent>) {
        // No endpoint yet means no peers/sessions, so nothing to dispatch — and
        // we must NOT allocate the ~28 KB endpoint just to service a timer tick
        // (that would defeat the lazy allocation). Skip until it exists.
        if self.endpoint.is_none() {
            return;
        }
        let now = Instant::now();
        // next_event is advisory; we always tick, and only act on due timers.
        // Box the dispatch output (ArrayVec of (PeerId, Packet), ~12 KB) so it
        // does not live as an owning iterator on the stack across the
        // emit_to_peer awaits; iterate by reference and clone each packet.
        let outbound = Box::new(self.endpoint().dispatch(now, now_unix()));
        for (id, pkt) in outbound.iter() {
            self.emit_to_peer(*id, pkt.clone(), events).await;
        }
    }

    async fn drain_recv(&self, src_key: [u8; 32], out: Box<RecvOut>, events: &async_channel::Sender<WgEvent>) {
        let dst_key = out
            .peer
            .and_then(|id| self.endpoint.as_deref().and_then(|ep| ep.peer_key(id)))
            .map(|k| k.to_bytes())
            .unwrap_or(src_key);

        // Iterate by reference: moving the ArrayVecs out would reintroduce the
        // multi-KB owning iterator on the stack that boxing `out` removed.
        for pkt in out.to_peer.iter() {
            let _ = events
                .send(WgEvent::OutboundPacket {
                    dst_key,
                    payload: pkt_to_box(pkt),
                })
                .await;
        }
        for pkt in out.decrypted.iter() {
            let _ = events
                .send(WgEvent::InboundDecrypted {
                    src_key: dst_key,
                    payload: pkt_to_box(pkt),
                })
                .await;
        }
        if out.handshook {
            let _ = events.send(WgEvent::PeerHandshook(dst_key)).await;
        }
    }

    async fn emit_to_peer(&self, id: PeerId, pkt: Packet, events: &async_channel::Sender<WgEvent>) {
        if let Some(key) = self.endpoint.as_deref().and_then(|ep| ep.peer_key(id)) {
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
