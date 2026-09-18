//! Runtime — wires all actors together.
//!
//! This is the equivalent of `ts_runtime` in tailscale-rs.  It owns the
//! actor handles and the channels between them.
//!
//! ## Key difference from ts_runtime
//!
//! `ts_runtime` uses `tokio::spawn` for each actor, creating multiple tasks
//! that Tokio schedules independently.  On ESP32-C3 with `current_thread`,
//! spawned tasks still work, but each `spawn` requires Tokio to allocate a
//! task descriptor on the heap.
//!
//! Here we offer two modes:
//! * `Runtime::spawn` (default, mirrors tailscale-rs API) — uses `tokio::spawn`
//! * `Runtime::join` (ESP32-C3 recommended) — uses `tokio::join!` inside a
//!   single task, avoiding per-task heap overhead.
//!
//! ## Channel implementation
//!
//! Uses `crossbeam::channel` instead of `tokio::sync::mpsc` for predictable
//! memory usage on ESP32-C3. Crossbeam channels use a pre-allocated ring buffer
//! with no dynamic heap allocation after initialization.
//!
//! All channels use a capacity of 2.  A backpressure of 2 messages × typical
//! message size (~1.5 KB for a packet) = ~3 KB maximum queued per channel.
//! This reduces memory usage for ESP32-C3 at the cost of lower throughput.
  
use tm_control::{ControlActor, ControlCmd, ControlEvent, Config as ControlConfig};
use tm_derp::{DerpActor, DerpCmd, DerpEvent, MAX_DERP_PAYLOAD};
use tm_disco::{DiscoActor, DiscoCmd, DiscoEvent};
use tm_wg::{WgActor, WgCmd, WgEvent};
use tm_keys::{NodeState, NodePublicKey};
use log::{info, debug, warn, error};
use async_channel;

/// FreeRTOS yield function for ESP32-C3 watchdog servicing.
/// Calls `vTaskDelay(50)` to yield the CPU and service the watchdog timer.
#[cfg(target_os = "espidf")]
pub async fn tokio_freertos_yield() {
    unsafe { esp_idf_sys::vTaskDelay(50) };
    tokio::task::yield_now().await;
}

#[cfg(target_os = "espidf")]
use esp_idf_sys;

/// A type-erased, heap-pinned actor future.
type BoxActorFut = core::pin::Pin<Box<dyn core::future::Future<Output = ()>>>;

/// Log the current largest-free-block / total-free heap, tagged.
///
/// `#[inline(never)]`: the `info!`/`heap_caps_*` format temporaries would
/// otherwise be reserved (once per call site, no slot reuse in the debug
/// build) inside the single `Runtime::join` poll frame. With ~15 heap-probe
/// call sites that alone pushed the frame well past the 32 KB main-task
/// stack. Kept in its own (reused) frame here instead. See
/// docs/wg-dataplane-notes.md.
#[cfg(target_os = "espidf")]
#[inline(never)]
fn log_heap(tag: &str) {
    unsafe {
        let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
        let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
        let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
        let total_free = esp_idf_sys::esp_get_free_heap_size();
        info!("Runtime::join() - heap [{}]: total_free={} bytes, largest_block: internal={} 8bit={} default={}", tag, total_free, free_internal, free_8bit, free_default);
    }
}
#[cfg(not(target_os = "espidf"))]
#[inline(never)]
fn log_heap(_tag: &str) {}

// ── Actor future boxing helpers ─────────────────────────────────────────────
//
// Each helper constructs one actor's `run()` future and moves it onto the
// heap (`Box::pin`), returning only an 8-byte pointer.
//
// Why `#[inline(never)]`, and why one function per actor: in the ESP32-C3
// debug build the compiler does NOT reuse stack slots, so if these
// `Box::pin(...)` expressions sat inline in `Runtime::join`, every actor's
// run-future temporary (built on the stack before `Box::new` copies it to
// the heap) would be reserved *simultaneously* in the single `join` poll
// frame, alongside the `tokio::join!` machinery and the event-router body.
// That summed to a ~55 KB frame -- larger than the 32 KB main-task stack --
// and faulted in `join`'s prologue (Guru Meditation, stack protection)
// before any actor ran. Building each future inside its own non-inlinable
// function keeps that transient in a frame that is freed on return, so
// `join` only ever holds the returned pointers. See
// docs/wg-dataplane-notes.md.

// Each helper also does the `Actor::new(..)` construction itself (rather
// than taking an already-built actor struct as a parameter). This matters
// for `WgActor`: `WgActor::new` builds a ~28 KB `WgEndpoint` on the stack
// before `Box`-ing it (see `tm_wg::WgActor::endpoint`'s doc comment). A
// plain (non-`#[inline(never)]`) constructor called from `join` was itself
// being MIR-inlined into `join` at this workspace's `opt-level = "z"` +
// `lto = true` dev profile, dragging that 28 KB stack temporary along with
// it -- this was the dominant contributor to the ~55 KB frame observed even
// after the event-router extraction and future-boxing alone. Keeping
// construction *and* future-building inside the same non-inlinable helper
// keeps both off `join`'s frame.

#[inline(never)]
fn spawn_control(
    config: ControlConfig,
    node_state: NodeState,
    rx: async_channel::Receiver<ControlCmd>,
    tx: async_channel::Sender<ControlEvent>,
) -> BoxActorFut {
    let actor = ControlActor::new(config, node_state);
    Box::pin(actor.run(rx, tx))
}

#[inline(never)]
fn spawn_derp(
    our_key: NodePublicKey,
    node_priv: [u8; 32],
    rx: async_channel::Receiver<DerpCmd>,
    tx: async_channel::Sender<DerpEvent>,
) -> BoxActorFut {
    let actor = DerpActor::new(our_key, node_priv);
    Box::pin(actor.run(rx, tx))
}

#[inline(never)]
fn spawn_disco(
    our_disco_key: tm_keys::DiscoPrivateKey,
    rx: async_channel::Receiver<DiscoCmd>,
    tx: async_channel::Sender<DiscoEvent>,
) -> BoxActorFut {
    let actor = DiscoActor::new(our_disco_key);
    Box::pin(actor.run(rx, tx))
}

#[inline(never)]
fn spawn_wg(
    node_priv: [u8; 32],
    priority_peer: Option<[u8; 32]>,
    rx: async_channel::Receiver<WgCmd>,
    tx: async_channel::Sender<WgEvent>,
) -> BoxActorFut {
    let actor = WgActor::new(node_priv, priority_peer);
    Box::pin(actor.run(rx, tx))
}

/// Log a received `ControlEvent::Error`. `#[inline(never)]` so its `Debug`
/// format temporary is not reserved inside `event_router_task`'s frame
/// alongside every other branch's temporaries (debug build: no stack-slot
/// reuse). Mirrors the rationale for `log_heap` above.
#[inline(never)]
fn log_control_error(e: &tm_control::ControlError) {
    error!("Runtime::join() - received ControlEvent::Error: {:?}", e);
}

/// Log a received `DerpEvent::Error`. See `log_control_error`.
#[inline(never)]
fn log_derp_error(e: &tm_derp::DerpError) {
    error!("Runtime::join() - received DerpEvent::Error: {:?}", e);
}

/// Internet checksum (RFC 1071): ones-complement sum of 16-bit words.
fn inet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a minimal ICMPv4 echo request (an IP packet: 20-byte IPv4 header +
/// 8-byte ICMP echo header, no payload) from `src` to `dst`. This is the
/// rung-6a elicitor: sent as WireGuard transport data, the peer's kernel
/// answers with an echo reply that returns as an inbound transport packet.
fn build_icmp_echo_request(src: [u8; 4], dst: [u8; 4], ident: u16, seq: u16) -> [u8; 28] {
    let mut pkt = [0u8; 28];
    // ── IPv4 header (20 bytes) ──
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes)
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // total length
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: don't fragment
    pkt[8] = 64; // TTL
    pkt[9] = 1; // protocol: ICMP
    // pkt[10..12] header checksum, filled below
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    let ip_csum = inet_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    // ── ICMP echo request (8 bytes) ──
    pkt[20] = 8; // type: echo request
    pkt[21] = 0; // code
    // pkt[22..24] ICMP checksum, filled below
    pkt[24..26].copy_from_slice(&ident.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    let icmp_csum = inet_checksum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
    pkt
}

/// The event-router loop, extracted to a top-level `async fn`.
///
/// This used to be an `async move { .. }` block declared as a local inside
/// `Runtime::join`. Even after that local was `Box::pin`-ed at the
/// `tokio::join!` call site, the block's body was still materialized as a
/// local variable in `join`'s own generator state (and, transitively, in
/// its poll stack frame) because it was constructed inline. Moving the loop
/// into its own top-level `async fn`, built off-frame via
/// `spawn_event_router` below (same pattern as the actor futures), is the
/// piece that actually keeps its large `tokio::select!` body -- four branches
/// each with heapless::Vec construction and multi-field `info!` calls -- out
/// of `join`'s frame.
async fn event_router_task(
    mut ctrl_ev_rx: async_channel::Receiver<ControlEvent>,
    mut derp_ev_rx: async_channel::Receiver<DerpEvent>,
    mut disco_ev_rx: async_channel::Receiver<DiscoEvent>,
    mut wg_ev_rx: async_channel::Receiver<WgEvent>,
    ctrl_tx3: async_channel::Sender<ControlCmd>,
    derp_tx2: async_channel::Sender<DerpCmd>,
    wg_tx2: async_channel::Sender<WgCmd>,
    disco_tx2: async_channel::Sender<DiscoCmd>,
    our_ip_tx: Option<OurIpSender>,
) {
    info!("Runtime::join() - event_router task started");
    // Rung-6a addressing state: our tailnet IPv4 and each peer's tailnet IPv4
    // keyed by node key, captured from MapUpdate. Used to synthesize the ICMP
    // echo request we drive through tm_wg after PeerHandshook so the peer
    // replies and an inbound transport packet becomes observable.
    let mut our_ip: [u8; 4] = [0; 4];
    let mut peer_ips: heapless::Vec<([u8; 32], [u8; 4]), 8> = heapless::Vec::new();
    loop {
        #[cfg(target_os = "espidf")]
        tokio_freertos_yield().await;
        tokio::select! {
            evt = ctrl_ev_rx.recv() => {
                match evt {
                    Ok(evt) => match evt {
                        ControlEvent::MapUpdate(map) => {
                            // Rung-3 evidence: MapResponse parsed, peers + DERPMap seen.
                            info!("Runtime::join() - MapUpdate: {} peers, {} DERP regions, our_ip={}.{}.{}.{}",
                                map.peers.len(), map.derp_regions.len(),
                                map.our_ip.0[0], map.our_ip.0[1], map.our_ip.0[2], map.our_ip.0[3]);
                            for r in map.derp_regions.iter() {
                                info!("Runtime::join()   DERP region {} ({}) host={}", r.region_id, r.region_code.as_str(), r.host.as_str());
                            }
                            for p in map.peers.iter() {
                                info!("Runtime::join()   peer {} derp_region={} online={} ip={}.{}.{}.{}",
                                    p.hostname.as_str(), p.derp_region, p.is_online,
                                    p.tailnet_ip.0[0], p.tailnet_ip.0[1], p.tailnet_ip.0[2], p.tailnet_ip.0[3]);
                            }
                            // Rung-4: bring up the DERP relay leg. Pick a target
                            // peer (first online, else first) and connect to the
                            // DERP region it is homed on, so the server can relay
                            // our WireGuard/disco traffic to it. A repeat Connect
                            // from a later map snapshot is ignored by the actor
                            // once a connection is up.
                            if let Some(target) =
                                map.peers.iter().find(|p| p.is_online).or_else(|| map.peers.first())
                            {
                                let rid = target.derp_region;
                                if let Some(region) =
                                    map.derp_regions.iter().find(|r| r.region_id == rid)
                                {
                                    let port = if region.port != 0 { region.port } else { 443 };
                                    info!("Runtime::join() - DERP connect -> region {} ({}) host={} port={} for peer {}",
                                        region.region_id, region.region_code.as_str(),
                                        region.host.as_str(), port, target.hostname.as_str());
                                    let _ = derp_tx2.send(DerpCmd::Connect {
                                        host: region.host.clone(),
                                        port,
                                        cert_fingerprint: None,
                                    }).await;
                                    #[cfg(target_os = "espidf")]
                                    tokio_freertos_yield().await;
                                }
                            }
                            // Capture addressing for rung-6a BEFORE the map is
                            // moved into ApplyMap.
                            our_ip = map.our_ip.0;
                            peer_ips.clear();
                            for p in map.peers.iter() {
                                let _ = peer_ips.push((p.node_key, p.tailnet_ip.0));
                            }
                            let _ = wg_tx2.send(WgCmd::ApplyMap(map)).await;
                        }
                        ControlEvent::OurIpAssigned(ip) => {
                            info!("Runtime::join() - received ControlEvent::OurIpAssigned: {}.{}.{}.{}", ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
                            #[cfg(target_os = "espidf")]
                            if let Some(ref tx) = our_ip_tx {
                                #[cfg(target_os = "espidf")]
                                tokio_freertos_yield().await;
                                let _ = tx.send(ip.to_ipv4()).await;
                            }
                        }
                        ControlEvent::KeyExpiry => {
                            let _ = ctrl_tx3.send(ControlCmd::Reauth).await;
                            #[cfg(target_os = "espidf")]
                            tokio_freertos_yield().await;
                        }
                        ControlEvent::Error(e) => {
                            log_control_error(&e);
                        }
                    }
                    Err(_) => {
                        info!("Runtime::join() - control event channel closed, breaking");
                        break;
                    }
                }
            }
            evt = derp_ev_rx.recv() => {
                match evt {
                    Ok(evt) => match evt {
                        DerpEvent::PacketReceived { src_key, payload } => {
                            // Demux disco vs WireGuard by the real wire
                            // discriminator: a disco datagram starts
                            // with the 6-byte "TS💬" magic; a WireGuard
                            // message starts with a type byte in 1..=4.
                            // (The previous `payload[0] == 0x6d` matched
                            // neither -- disco magic byte 0 is 0x54.)
                            let is_disco = payload.len() >= 6
                                && &payload[..6] == tm_disco::DISCO_MAGIC;
                            if is_disco {
                                let mut data = heapless::Vec::new();
                                let _ = data.extend_from_slice(&payload);
                                let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                    src_ip:   [0; 4],
                                    src_port: 0,
                                    data: Box::new(data),
                                }).await;
                                #[cfg(target_os = "espidf")]
                                tokio_freertos_yield().await;
                            } else {
                                let mut pkt = heapless::Vec::new();
                                let _ = pkt.extend_from_slice(&payload);
                                let _ = wg_tx2.send(WgCmd::InboundPacket {
                                    src_key: *src_key.as_bytes(),
                                    payload: Box::new(pkt),
                                }).await;
                                #[cfg(target_os = "espidf")]
                                tokio_freertos_yield().await;
                            }
                        }
                        DerpEvent::Connected => {
                            tracing::debug!("DERP connected");
                        }
                        DerpEvent::PingReceived => {}
                        DerpEvent::Disconnected => {
                            tracing::debug!("DERP disconnected");
                        }
                        DerpEvent::Error(e) => {
                            log_derp_error(&e);
                        }
                    }
                    Err(_) => {
                        info!("Runtime::join() - derp event channel closed, breaking");
                        break;
                    }
                }
            }
            // ── WireGuard data-plane events (previously dropped) ──────
            evt = wg_ev_rx.recv() => {
                match evt {
                    Ok(WgEvent::OutboundPacket { dst_key, payload }) => {
                        // The outbound WireGuard path: handshake
                        // initiations, keepalives and transport data
                        // leave tm_wg here and are handed to DERP for
                        // relay to the peer. (DERP transport is a stub
                        // today -- see docs/wg-dataplane-notes.md -- so
                        // these are dropped by the DerpActor for now;
                        // the wiring is correct and observable.)
                        info!("Runtime::join() - WgEvent::OutboundPacket {} bytes -> DERP peer {:02x}{:02x}..", payload.len(), dst_key[0], dst_key[1]);
                        let mut buf: heapless::Vec<u8, MAX_DERP_PAYLOAD> = heapless::Vec::new();
                        if buf.extend_from_slice(&payload).is_ok() {
                            let _ = derp_tx2.send(DerpCmd::SendPacket {
                                dst_key: NodePublicKey::from_bytes(dst_key),
                                payload: Box::new(buf),
                            }).await;
                        }
                        #[cfg(target_os = "espidf")]
                        tokio_freertos_yield().await;
                    }
                    Ok(WgEvent::InboundDecrypted { src_key, payload }) => {
                        // Decrypted inbound app data destined for the
                        // local netstack. tm_netstack has no on-device
                        // lwIP injection path yet (it is a stub), so we
                        // surface it here; this is the seam where a
                        // transport round-trip becomes observable.
                        info!("Runtime::join() - WgEvent::InboundDecrypted {} bytes from peer {:02x}{:02x}..", payload.len(), src_key[0], src_key[1]);
                    }
                    Ok(WgEvent::PeerHandshook(key)) => {
                        info!("Runtime::join() - WgEvent::PeerHandshook with peer {:02x}{:02x}..", key[0], key[1]);
                        // Rung-6a: now that a session is active, drive an ICMP
                        // echo request to the peer's tailnet IP. tailscaled/its
                        // kernel answers pings to its own tailnet address with
                        // no listening app, so the echo reply comes back as an
                        // inbound transport packet -> WgEvent::InboundDecrypted.
                        if let Some((_, dst_ip)) = peer_ips.iter().find(|(k, _)| *k == key) {
                            if our_ip != [0; 4] {
                                let echo = build_icmp_echo_request(our_ip, *dst_ip, 0x7361, 1);
                                info!("Runtime::join() - rung6a: sending ICMP echo {}.{}.{}.{} -> {}.{}.{}.{} ({} bytes) to peer {:02x}{:02x}..",
                                    our_ip[0], our_ip[1], our_ip[2], our_ip[3],
                                    dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
                                    echo.len(), key[0], key[1]);
                                let mut buf: heapless::Vec<u8, 1500> = heapless::Vec::new();
                                if buf.extend_from_slice(&echo).is_ok() {
                                    let _ = wg_tx2.send(WgCmd::SendData {
                                        dst_key: key,
                                        payload: Box::new(buf),
                                    }).await;
                                    #[cfg(target_os = "espidf")]
                                    tokio_freertos_yield().await;
                                }
                            } else {
                                info!("Runtime::join() - rung6a: our tailnet IP not yet known; skipping echo");
                            }
                        }
                    }
                    Err(_) => {
                        info!("Runtime::join() - wg event channel closed, breaking");
                        break;
                    }
                }
            }
            // ── DISCO events ──────────────────────────────────────────
            evt = disco_ev_rx.recv() => {
                match evt {
                    Ok(DiscoEvent::SendPong { payload, .. }) => {
                        // A wire-correct PONG must be sealed and
                        // addressed to the peer over DERP; that is
                        // gated on the DERP transport (stub). Surface
                        // it so a real PING-from-peer is observable.
                        info!("Runtime::join() - DiscoEvent::SendPong (tx_id {:02x}{:02x}..) [not relayed: DERP stub]", payload[0], payload[1]);
                    }
                    Ok(DiscoEvent::PingFrom(key)) => {
                        info!("Runtime::join() - DiscoEvent::PingFrom peer {:02x}{:02x}..", key[0], key[1]);
                    }
                    Err(_) => {
                        info!("Runtime::join() - disco event channel closed, breaking");
                        break;
                    }
                }
            }
        }
    }
    info!("Runtime::join() - event_router task exiting");
}

/// Build the event-router future off-frame. See `event_router_task` and the
/// `spawn_*` actor helpers above for why this must not be inlined into
/// `Runtime::join`.
#[inline(never)]
fn spawn_event_router(
    ctrl_ev_rx: async_channel::Receiver<ControlEvent>,
    derp_ev_rx: async_channel::Receiver<DerpEvent>,
    disco_ev_rx: async_channel::Receiver<DiscoEvent>,
    wg_ev_rx: async_channel::Receiver<WgEvent>,
    ctrl_tx3: async_channel::Sender<ControlCmd>,
    derp_tx2: async_channel::Sender<DerpCmd>,
    wg_tx2: async_channel::Sender<WgCmd>,
    disco_tx2: async_channel::Sender<DiscoCmd>,
    our_ip_tx: Option<OurIpSender>,
) -> BoxActorFut {
    Box::pin(event_router_task(
        ctrl_ev_rx, derp_ev_rx, disco_ev_rx, wg_ev_rx,
        ctrl_tx3, derp_tx2, wg_tx2, disco_tx2, our_ip_tx,
    ))
}

/// Channel capacity for all inter-actor queues.
/// Small = bounded memory, back-pressure propagates naturally.
/// Reduced from 4 to 2 to save memory on ESP32-C3.
const CHAN_CAP: usize = 2;

use std::net::Ipv4Addr;

/// Channel for receiving the Tailnet IPv4 address.
pub type OurIpReceiver = async_channel::Receiver<Ipv4Addr>;

/// Channel for sending the Tailnet IPv4 address.
pub type OurIpSender = async_channel::Sender<Ipv4Addr>;

pub struct RuntimeConfig {
    pub control:       ControlConfig,
    pub auth_key:      heapless::String<128>,
    pub node_state:    NodeState,
    pub priority_peer: Option<[u8; 32]>,
    pub our_ip_tx:     Option<OurIpSender>,
    /// Deadline for the control plane's bring-up phase only (see
    /// `tm_control::Config::connect_timeout`). `None` disables it. Plumbed
    /// into `ControlActor`'s `Config` at actor-construction time in
    /// `Runtime::join` below; NEVER applied to the streaming poll that
    /// follows bring-up, which always runs unbounded so the node stays
    /// online. See docs/wg-dataplane-notes.md "Bring-up timeout".
    pub connect_timeout: Option<core::time::Duration>,
}

pub struct Runtime {
    // Senders — held by Runtime so callers can send commands
    pub control_tx: async_channel::Sender<ControlCmd>,
    pub derp_tx:    async_channel::Sender<DerpCmd>,
    pub disco_tx:   async_channel::Sender<DiscoCmd>,
    pub wg_tx:      async_channel::Sender<WgCmd>,
}

impl Runtime {
    /// Run all actors within a single task using `tokio::join!`.
    ///
    /// This avoids per-task heap allocations that `tokio::spawn` incurs.
    /// All actors run cooperatively on the same stack.
    ///
    /// This is the recommended method for ESP32-C3.
    pub async fn join(mut config: RuntimeConfig) -> Self {
        tracing::debug!("Runtime::join() - starting actor runtime");

        // ── Channel allocation ──────────────────────────────────────────────
        // Heap probes routed through `log_heap` (see its doc comment): kept
        // out of this frame via #[inline(never)] so their format temporaries
        // do not accumulate here across ~15 call sites.
        log_heap("before channel allocation");

        tokio_freertos_yield().await;
        let (ctrl_tx,  ctrl_rx)  = async_channel::bounded::<ControlCmd>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after ControlCmd channel");

        let (ctrl_ev_tx, ctrl_ev_rx) = async_channel::bounded::<ControlEvent>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after ControlEvent channel");

        let (derp_tx,  derp_rx)  = async_channel::bounded::<DerpCmd>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after DerpCmd channel");

        let (derp_ev_tx, derp_ev_rx) = async_channel::bounded::<DerpEvent>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after DerpEvent channel");

        let (disco_tx, disco_rx) = async_channel::bounded::<DiscoCmd>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after DiscoCmd channel");

        let (disco_ev_tx, disco_ev_rx) = async_channel::bounded::<DiscoEvent>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after DiscoEvent channel");

        let (wg_tx,    wg_rx)    = async_channel::bounded::<WgCmd>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after WgCmd channel");

        let (wg_ev_tx, wg_ev_rx) = async_channel::bounded::<WgEvent>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after WgEvent channel");

        // ── Key extraction ───────────────────────────────────────────────────
        let our_pub = config.node_state.node_key.public();
        let disco_key = config.node_state.disco_key.clone();
        // WireGuard static key == the node key (captured before node_state is
        // moved into spawn_control below).
        let wg_priv = *config.node_state.node_key.as_bytes();
        let priority_peer = config.priority_peer;
        let our_ip_tx = config.our_ip_tx.take();
        log_heap("before actor construction");

        let ctrl_tx3 = ctrl_tx.clone();
        let ctrl_tx4 = ctrl_tx.clone();
        let derp_tx2  = derp_tx.clone();
        let wg_tx2    = wg_tx.clone();
        let disco_tx2 = disco_tx.clone();

        // ── Build every task's future off-frame ─────────────────────────────
        // Each actor is constructed AND its run() future built+boxed inside
        // its own #[inline(never)] spawn_* helper (see their doc comments
        // above). Neither the actor struct nor the future's build temporary
        // (notably WgActor::new's ~28 KB WgEndpoint) ever becomes a local in
        // this frame -- this is what keeps `join` under the 32 KB main-task
        // stack.
        tracing::debug!("Runtime::join() - preparing actor tasks");
        config.control.connect_timeout = config.connect_timeout;
        let control_task = spawn_control(config.control, config.node_state, ctrl_rx, ctrl_ev_tx);
        log_heap("after ControlActor spawn");
        let derp_task = spawn_derp(our_pub, wg_priv, derp_rx, derp_ev_tx);
        log_heap("after DerpActor spawn");
        let disco_task = spawn_disco(disco_key, disco_rx, disco_ev_tx);
        log_heap("after DiscoActor spawn");
        let wg_task = spawn_wg(wg_priv, priority_peer, wg_rx, wg_ev_tx);
        log_heap("after WgActor spawn");
        let event_router = spawn_event_router(
            ctrl_ev_rx, derp_ev_rx, disco_ev_rx, wg_ev_rx,
            ctrl_tx3, derp_tx2, wg_tx2, disco_tx2, our_ip_tx,
        );

        log_heap("before tokio::join! (all actors constructed)");

        tracing::debug!("Runtime::join() - sending ControlCmd::Start");
        let _ = ctrl_tx4.send(ControlCmd::Start { auth_key: config.auth_key.clone() }).await;

        tracing::debug!("Runtime::join() - joining actor tasks with tokio::join!");
        // Run all actors together. The event_router loop runs indefinitely until a channel error occurs.
        // The other tasks (control_task, derp_task, disco_task, wg_task) will complete when their channels close.
        tokio::join!(
            control_task,
            derp_task,
            disco_task,
            wg_task,
            event_router,
        );

        tracing::debug!("Runtime::join() - all tasks completed");
        Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }
    }

    /// Use tokio::spawn to run actors in separate tasks.
    /// This is the recommended method for ESP32-C3 when Runtime::join causes memory issues.
    #[cfg(not(target_os = "espidf"))]
    pub async fn spawn(mut config: RuntimeConfig) -> Self {
        let (ctrl_tx,  ctrl_rx)  = async_channel::bounded::<ControlCmd>(CHAN_CAP);
        let (ctrl_ev_tx, mut ctrl_ev_rx) = async_channel::bounded::<ControlEvent>(CHAN_CAP);

        let (derp_tx,  derp_rx)  = async_channel::bounded::<DerpCmd>(CHAN_CAP);
        let (derp_ev_tx, mut derp_ev_rx) = async_channel::bounded::<DerpEvent>(CHAN_CAP);

        let (disco_tx, disco_rx) = async_channel::bounded::<DiscoCmd>(CHAN_CAP);
        let (_disco_ev_tx, mut _disco_ev_rx) = async_channel::bounded::<DiscoEvent>(CHAN_CAP);

        let (wg_tx,    wg_rx)    = async_channel::bounded::<WgCmd>(CHAN_CAP);
        let (_wg_ev_tx, mut _wg_ev_rx) = async_channel::bounded::<WgEvent>(CHAN_CAP);

        // ── Spawn actors ──────────────────────────────────────────────────────

        let our_pub = config.node_state.node_key.public();
        let disco_key = config.node_state.disco_key.clone();
        // WireGuard static key == the node key (captured before node_state is
        // moved into ControlActor below).
        let wg_priv = *config.node_state.node_key.as_bytes();

        config.control.connect_timeout = config.connect_timeout;
        let control_actor = ControlActor::new(config.control, config.node_state);
        tokio::spawn(control_actor.run(ctrl_rx, ctrl_ev_tx));

        let derp_actor = DerpActor::new(our_pub, wg_priv);
        tokio::spawn(derp_actor.run(derp_rx, derp_ev_tx));

        let disco_actor = DiscoActor::new(disco_key);
        tokio::spawn(disco_actor.run(disco_rx, _disco_ev_tx));

        let wg_actor = WgActor::new(wg_priv, config.priority_peer);
        tokio::spawn(wg_actor.run(wg_rx, _wg_ev_tx));

        // ── Event router task ─────────────────────────────────────────────────
        //
        // A single task fans out events from the control actor to the other
        // actors.  This is the "message bus" from ts_runtime, simplified.
        //
        // On ESP32-C3 this is just another cooperatively-scheduled future —
        // no extra OS stack.

        let ctrl_tx3 = ctrl_tx.clone();
        let ctrl_tx4 = ctrl_tx.clone();
        let derp_tx2  = derp_tx.clone();
        let wg_tx2    = wg_tx.clone();
        let disco_tx2 = disco_tx.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    evt = ctrl_ev_rx.recv() => {
                        match evt {
                            Ok(evt) => match evt {
                                ControlEvent::MapUpdate(map) => {
                                    // Update WireGuard peers
                                    let _ = wg_tx2.send(WgCmd::ApplyMap(map)).await;
                                    // TODO: update DERP preferred region
                                }
                                ControlEvent::OurIpAssigned(ip) => {
                                    tracing::debug!("Tailnet IP: {:?}", ip.0);
                                }
                                ControlEvent::KeyExpiry => {
                                    let _ = ctrl_tx3.send(ControlCmd::Reauth).await; // trigger reauth
                                }
                                ControlEvent::Error(e) => {
                                    tracing::error!("Control error: {:?}", e);
                                }
                            }
                            Err(_) => {
                                tracing::debug!("Control event channel closed, breaking");
                                break;
                            }
                        }
                    }
                    evt = derp_ev_rx.recv() => {
                        match evt {
                            Ok(evt) => match evt {
                                DerpEvent::PacketReceived { src_key, payload } => {
                                    // Distinguish DISCO vs WireGuard by first byte
                                    if !payload.is_empty() && payload[0] == 0x6d {
                                        // DISCO magic prefix (simplified check)
                                        let mut data = heapless::Vec::new();
                                        let _ = data.extend_from_slice(&payload);
                                        let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                            src_ip:   [0; 4],  // from DERP src
                                            src_port: 0,
                                            data: Box::new(data),
                                        }).await;
                                    } else {
                                        // WireGuard packet
                                        let mut pkt = heapless::Vec::new();
                                        let _ = pkt.extend_from_slice(&payload);
                                        let _ = wg_tx2.send(WgCmd::InboundPacket {
                                            src_key: *src_key.as_bytes(),
                                            payload: Box::new(pkt),
                                        }).await;
                                    }
                                }
                                DerpEvent::Connected => {
                                    tracing::debug!("DERP connected");
                                }
                                DerpEvent::PingReceived => {}
                                DerpEvent::Disconnected => {
                                    tracing::debug!("DERP disconnected");
                                }
                                DerpEvent::Error(e) => {
                                    tracing::error!("DERP error: {:?}", e);
                                }
                            }
                            Err(_) => {
                                tracing::debug!("DERP event channel closed, breaking");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Start the control actor by sending a Start command (via clone)
        let _ = ctrl_tx4.send(ControlCmd::Start { auth_key: config.auth_key.clone() }).await;

        Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }
    }
}
