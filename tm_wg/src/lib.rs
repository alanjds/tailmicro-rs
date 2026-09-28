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
pub mod heapdiag;
// `pub` so the vendored types that appear in `endpoint`'s public signatures
// (Packet, PeerId, PeerConfig, NodePublicKey, ...) are reachable. These are
// vendored library types; exposing them is harmless.
pub mod vendor;

use tm_control::{MapState, PeerInfo};

pub use endpoint::{Endpoint, MAX_PEERS, WgEndpoint};
use endpoint::{DispatchOut, RecvOut};
use vendor::config::{PeerConfig, PeerId, Psk};
use vendor::keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use vendor::packet::Packet;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Actor tick period. Mirrors MicroLink's `wireguardif_periodic()` ~400ms
/// discipline; drives handshake retry, rekey, and keepalive off the latency
/// path.
const TICK: Duration = Duration::from_millis(400);

// Heap probe bracketing recv_one_into/drain_recv (round 6 of the
// tailmicro-rs heap-fragmentation investigation, ALLOCATIONS.md Step 5:
// root-causing the 20480-vs-8192 mismatch). Same pattern as
// `tm_disco::heap_probe_blocks` (not reused directly to avoid a cross-crate
// dependency for a temporary debug aid). Device-only; no-op on host builds.
// Remove once Step 5 is resolved.
#[inline(never)]
fn heap_probe_blocks(tag: &str) {
    #[cfg(target_os = "espidf")]
    unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        tracing::info!(
            "WgActor heap-blocks [{}]: total_free={} largest_free={} \
             free_blocks={} allocated_blocks={} total_blocks={}",
            tag, info.total_free_bytes, info.largest_free_block,
            info.free_blocks, info.allocated_blocks, info.total_blocks,
        );
    }
    #[cfg(not(target_os = "espidf"))]
    tracing::info!("WgActor heap-blocks [{}]: (host build; probe is device-only)", tag);
}

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
    ///
    /// `payload` is the shared channel packet buffer (`tm_buf`): the event
    /// router forwards the very buffer `tm_derp` filled, without copying.
    InboundPacket {
        src_key: [u8; 32],
        payload: tm_buf::PktBuf,
    },
    /// Encrypt and send an outbound transport (app-data) IP packet to a peer.
    ///
    /// The `payload` is a plaintext IP packet (e.g. an ICMP echo request); it is
    /// encrypted under the peer's active send session and emitted as a
    /// [`WgEvent::OutboundPacket`] for DERP relay. Boxed for the same
    /// stack-frame reason as the other multi-KB variants above.
    SendData {
        dst_key: [u8; 32],
        payload: tm_buf::PktBuf,
    },
    Shutdown,
}

pub enum WgEvent {
    /// An outbound WireGuard packet to send via DERP.
    OutboundPacket {
        dst_key: [u8; 32],
        payload: tm_buf::PktBuf,
    },
    /// A decrypted inbound payload, destined for the local netstack.
    InboundDecrypted {
        src_key: [u8; 32],
        payload: tm_buf::PktBuf,
    },
    /// A WireGuard handshake completed with the given peer node key.
    PeerHandshook([u8; 32]),
}

// ── WgActor ───────────────────────────────────────────────────────────────────

pub struct WgActor {
    // STATIC, not boxed (Step 5, ALLOCATIONS.md "Fix plan: DERP TLS
    // handshake heap collapse"): `WgEndpoint` is ~28 KB (fixed peer table +
    // session state). It used to be embedded by value inside the `run()`
    // async state machine, ballooning that future to ~90 KB; `Box::pin`-ing
    // the future at spawn time then tried to build all ~90 KB on the
    // ESP32-C3's 32 KB main-task stack, hitting a Guru Meditation
    // stack-protection fault in Runtime::join. Boxing the endpoint (heap)
    // fixed the stack problem by keeping only an 8-byte pointer in the
    // future; `WgEndpoint::new_static` (now, `.bss`) keeps the same
    // 8-byte-reference shape in the future *and* removes this ~6 KB
    // allocation from the heap entirely, closing its contribution to
    // fragmentation (same "fixed-size, single instance, held forever" shape
    // already applied to `tm_buf::PktBuf`). See docs/wg-dataplane-notes.md.
    //
    // LAZY (`Option`): the endpoint's *static storage* is reserved at link
    // time regardless, but the reference is only taken on first use (the
    // first `ApplyMap`/inbound packet), preserving the original ordering
    // reasoning below for the heap-backed version -- it no longer matters
    // for the endpoint itself (no heap competes with the netmap buffer now),
    // but the `Option` is kept as-is rather than restructured, since
    // `WgEndpoint::new_static` panics if called twice and `endpoint()`
    // already guards that via this `Option`.
    endpoint: Option<&'static mut WgEndpoint>,
    /// Reusable scratch buffer for `RecvOut` (~6 KB). STATIC, not boxed
    /// (Step 5): was `Box::new`'d fresh on first use and refilled in place
    /// thereafter; that per-call churn (before the refill-in-place fix) was
    /// the exact ~6 KB block behind the `memory allocation of 6052 bytes
    /// failed` heap fragmentation aborts. `endpoint::recv_out_static` now
    /// hands out a `.bss`-backed reference instead of a heap `Box`, removing
    /// even its one-time allocation from the heap. See ALLOCATIONS.md.
    recv_scratch: Option<&'static mut RecvOut>,
    /// Reusable scratch buffer for `dispatch()`'s output (~6 KB). STATIC,
    /// not boxed (Step 5), same rationale and mechanism as `recv_scratch`
    /// above, via `endpoint::dispatch_out_static`. Same fragmentation shape
    /// as `recv_scratch`, but on a periodic timer rather than per-packet, so
    /// it fires independently of (and can coincide with) any HTTP/data-plane
    /// traffic. See ALLOCATIONS.md.
    dispatch_scratch: Option<&'static mut DispatchOut>,
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
            recv_scratch: None,
            dispatch_scratch: None,
            kp,
            priority_peer,
        }
    }

    /// Get the endpoint, binding its static (`.bss`) storage on first use.
    /// `new_static` builds it in its own `#[inline(never)]` frame to keep it
    /// off this caller's stack. Size is ~6 KB since QUEUE_DEPTH = 0 dropped
    /// the inline per-peer packet queues (was ~28 KB, which OOM-aborted here
    /// on device, back when this was heap-`Box`-allocated).
    fn endpoint(&mut self) -> &mut WgEndpoint {
        if self.endpoint.is_none() {
            tracing::info!("WgActor: binding static WgEndpoint (~6 KB, .bss) on first use");
            self.endpoint = Some(WgEndpoint::new_static(self.kp));
        }
        self.endpoint.as_deref_mut().unwrap()
    }

    /// Take the persistent `RecvOut` scratch buffer, binding its static
    /// (`.bss`) storage on first use. Pair with [`Self::return_scratch`]
    /// once done so the reference is handed back (not left dangling in a
    /// local) for the next call.
    fn take_scratch(&mut self) -> &'static mut RecvOut {
        self.recv_scratch.take().unwrap_or_else(|| {
            tracing::info!("WgActor: binding static RecvOut scratch (~6 KB, .bss) on first use");
            endpoint::recv_out_static()
        })
    }

    /// Clear and return the scratch buffer taken via [`Self::take_scratch`].
    fn return_scratch(&mut self, out: &'static mut RecvOut) {
        out.reset();
        self.recv_scratch = Some(out);
    }

    /// Take the persistent `dispatch()` output scratch buffer, binding its
    /// static (`.bss`) storage on first use. Pair with
    /// [`Self::return_dispatch_scratch`] once done so the reference is
    /// handed back for the next tick.
    fn take_dispatch_scratch(&mut self) -> &'static mut DispatchOut {
        self.dispatch_scratch.take().unwrap_or_else(|| {
            tracing::info!("WgActor: binding static dispatch scratch (~6 KB, .bss) on first use");
            endpoint::dispatch_out_static()
        })
    }

    /// Clear and return the scratch buffer taken via
    /// [`Self::take_dispatch_scratch`].
    fn return_dispatch_scratch(&mut self, out: &'static mut DispatchOut) {
        out.clear();
        self.dispatch_scratch = Some(out);
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
                        Ok(WgCmd::SendData { dst_key, payload }) => {
                            Box::pin(self.on_send_data(dst_key, &payload, &events)).await;
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
        // Hand the channel packet-buffer pool (tm_buf) its static buffers
        // before per-packet traffic starts. They live in .bss, so this
        // allocates nothing; the first `acquire` would do it anyway -- this
        // just makes it explicit and logged. See ALLOCATIONS.md.
        let n = tm_buf::prewarm();
        if n > 0 {
            tracing::info!("WgActor: packet-buffer pool ready: {} static buffers ({} B each)", n, tm_buf::PKT_CAP);
        }

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
        payload: &[u8],
        events: &async_channel::Sender<WgEvent>,
    ) {
        // The channel buffer is PKT_CAP (1532) wide, but the vendored
        // `Packet::from_wire` panics on anything over its 1500-byte capacity.
        // A real WireGuard message never exceeds that; drop anything larger.
        if payload.len() > vendor::packet::CAPACITY {
            tracing::debug!("WgActor: dropping oversize inbound packet ({} bytes)", payload.len());
            return;
        }
        // Primary disco demux happens at the runtime edge; recv_one also
        // sniffs the WireGuard type byte defensively.
        let from = Endpoint::Derp {
            region_id: 0,
            node_key: src_key,
        };
        // Reuse the persistent RecvOut scratch buffer (~6 KB of inline packet
        // buffers) instead of `Box::new`-ing a fresh one per packet: that
        // per-call alloc/free churn on the hottest data-plane path was
        // fragmenting the heap (see `recv_scratch` doc comment and
        // ALLOCATIONS.md). Filling a heap-resident RecvOut still keeps those
        // 6 KB off the stack, same as before.
        let mut out = self.take_scratch();
        if heapdiag::ENABLED {
            heap_probe_blocks("on_inbound: before recv_one_into");
        }
        self.endpoint().recv_one_into(payload, from, Instant::now(), &mut out);
        let w = heapdiag::trace_begin("on_inbound: before drain_recv");
        self.drain_recv(src_key, &out, events).await;
        heapdiag::trace_end(w, "on_inbound: after drain_recv");
        self.return_scratch(out);
    }

    async fn on_send_data(
        &mut self,
        dst_key: [u8; 32],
        payload: &[u8],
        events: &async_channel::Sender<WgEvent>,
    ) {
        // `Packet::from_plaintext` panics past MAX_INNER (1500 - header -
        // tag). The netif MTU (1380) keeps real traffic well under it; guard
        // anyway now that the channel buffer is PKT_CAP (1532) wide.
        if payload.len() > vendor::packet::MAX_INNER {
            tracing::warn!("WgActor: dropping oversize outbound packet ({} bytes)", payload.len());
            return;
        }
        // No endpoint means no sessions; nothing to send (and we must not force
        // the ~28 KB lazy allocation for a stray send).
        if self.endpoint.is_none() {
            return;
        }
        // Same reuse discipline as on_inbound: the persistent scratch buffer
        // keeps its ~6 KB of inline packet buffers off the stack without
        // re-allocating on every send.
        let mut out = self.take_scratch();
        let sent = self
            .endpoint()
            .send_data(&dst_key, payload, Instant::now(), &mut out);
        if !sent {
            tracing::debug!("send_data queued (no active session yet) or dropped");
        }
        self.drain_recv(dst_key, &out, events).await;
        self.return_scratch(out);
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
        // Reuse the persistent dispatch scratch buffer instead of `Box::new`-ing
        // a fresh one every tick (see `dispatch_scratch` doc comment): keeps the
        // ~6 KB block off the stack (writing into the boxed slot in place) and,
        // once allocated, off the heap-churn path entirely. Iterate by
        // reference and clone each packet, same as before.
        let outbound = self.take_dispatch_scratch();
        *outbound = self.endpoint().dispatch(now, now_unix());
        for (id, pkt) in outbound.iter() {
            self.emit_to_peer(*id, pkt.clone(), events).await;
        }
        self.return_dispatch_scratch(outbound);
    }

    async fn drain_recv(&self, src_key: [u8; 32], out: &RecvOut, events: &async_channel::Sender<WgEvent>) {
        let dst_key = out
            .peer
            .and_then(|id| self.endpoint.as_deref().and_then(|ep| ep.peer_key(id)))
            .map(|k| k.to_bytes())
            .unwrap_or(src_key);

        // Iterate by reference: moving the ArrayVecs out would reintroduce the
        // multi-KB owning iterator on the stack that boxing `out` removed.
        for pkt in out.to_peer.iter() {
            send_diag(events, WgEvent::OutboundPacket {
                dst_key,
                payload: pkt_to_buf(pkt),
            }, "OutboundPacket").await;
        }
        for pkt in out.decrypted.iter() {
            send_diag(events, WgEvent::InboundDecrypted {
                src_key: dst_key,
                payload: pkt_to_buf(pkt),
            }, "InboundDecrypted").await;
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
                    payload: pkt_to_buf(&pkt),
                })
                .await;
        }
    }

    // Kept so callers/tests can inspect the never-evict setting.
    pub fn priority_peer(&self) -> Option<[u8; 32]> {
        self.priority_peer
    }
}

/// TEMPORARY (ALLOCATIONS.md Step 7): `events.send(ev).await`, but logs
/// whether the channel was full and how many times the send future returned
/// `Pending` (i.e. actually yielded to the executor, letting every other
/// task on this current-thread runtime run before the send completed).
async fn send_diag(events: &async_channel::Sender<WgEvent>, ev: WgEvent, what: &str) {
    if !heapdiag::ENABLED {
        let _ = events.send(ev).await;
        return;
    }
    let full_before = events.is_full();
    let len_before = events.len();
    let mut pendings = 0u32;
    let mut fut = core::pin::pin!(events.send(ev));
    let _ = core::future::poll_fn(|cx| match core::future::Future::poll(fut.as_mut(), cx) {
        core::task::Poll::Pending => {
            pendings += 1;
            core::task::Poll::Pending
        }
        r => r,
    })
    .await;
    tracing::info!(
        "WgActor send_diag {}: chan_len_before={} full_before={} pendings={}",
        what, len_before, full_before, pendings
    );
}

/// Copy a WireGuard `Packet` (1500-byte capacity) into a pooled channel
/// buffer (`tm_buf::PKT_CAP` = 1532, so it always fits). Once the pool is
/// warm this is a memcpy with no heap traffic; the buffer returns to the
/// pool when the event router is done with it.
fn pkt_to_buf(pkt: &Packet) -> tm_buf::PktBuf {
    let mut v = tm_buf::PktBuf::acquire();
    let _ = v.extend_from_slice(pkt.as_slice());
    v
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
