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
use tm_derp::{DerpActor, DerpCmd, DerpEvent};
use tm_disco::{DiscoActor, DiscoCmd, DiscoEvent};
use tm_wg::{WgActor, WgCmd, WgEvent};
use tm_keys::{NodeState, NodePublicKey};
use tm_netstack::tailnet;
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
        debug!("Runtime::join() - heap [{}]: total_free={} bytes, largest_block: internal={} 8bit={} default={}", tag, total_free, free_internal, free_8bit, free_default);
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

/// Bring up (first call) or re-address (subsequent calls with a changed IP)
/// the tailnet lwIP netif -- plan (a), docs/tailnet-http-lwip-netif-plan.md
/// item 4. Called from both `ControlEvent::MapUpdate` and
/// `ControlEvent::OurIpAssigned`, since either can be the first place a
/// given IP is observed depending on `ControlActor`'s event ordering; `*last`
/// makes repeat calls with the same IP (which MapUpdate's periodic streaming
/// poll will produce constantly) a no-op instead of retrying every time.
///
/// `netif_out_tx` is consumed by `tailnet::bring_up` on the first successful
/// (or attempted) call; `None` afterward routes through `set_address`
/// instead, which never needs the sender (device.rs keeps it in a
/// process-wide `OnceLock` set once at bring-up).
///
/// `#[inline(never)]`: matches every other helper in this file -- keeps this
/// branch's temporaries (and the `tailnet` crate's own call frame) off
/// `event_router_task`'s single `tokio::select!` poll frame.
#[inline(never)]
fn apply_tailnet_address(
    ip: [u8; 4],
    last: &mut Option<[u8; 4]>,
    netif_out_tx: &mut Option<tailnet::OutboundSender>,
) {
    if ip == [0; 4] {
        return; // not yet assigned
    }
    if *last == Some(ip) {
        return; // already applied (or already attempted) this exact address
    }
    let result = match netif_out_tx.take() {
        Some(tx) => tailnet::bring_up(ip, tx),
        None => tailnet::set_address(ip),
    };
    *last = Some(ip);
    match result {
        Ok(()) => {
            info!("Runtime::join() - tailnet netif address set to {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        }
        Err(tailnet::TailnetError::NotSupported) => {
            // Expected on host builds (no on-device lwIP to attach to); not
            // an error worth alarming about.
            debug!("Runtime::join() - tailnet netif not supported on this target");
        }
        Err(e) => {
            warn!("Runtime::join() - tailnet netif bring-up/set_address failed for {}.{}.{}.{}: {:?}", ip[0], ip[1], ip[2], ip[3], e);
        }
    }
}

/// Log an outbound netif packet whose destination IP matched no known peer
/// (i.e. `event_router_task`'s `ip_to_key` table, built from the last
/// `MapUpdate`, has no entry for it). `#[inline(never)]` for the same reason
/// as `log_control_error`; `last` collapses repeats to one log line per
/// distinct unresolved destination instead of one per dropped packet, per
/// the plan's item 3 ("log once, not once per packet, for storm-safety").
#[inline(never)]
fn log_unknown_netif_dest(dst_ip: [u8; 4], last: &mut Option<[u8; 4]>) {
    if *last == Some(dst_ip) {
        return;
    }
    *last = Some(dst_ip);
    warn!("Runtime::join() - tailnet netif output: no peer known for destination {}.{}.{}.{}, dropping", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
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

/// If `req` is an IPv4 ICMP echo request addressed to `our_ip`, build the
/// matching echo reply: source/destination swapped, ICMP type 8 -> 0, both
/// checksums recomputed, and ident/seq/data preserved. Returns `None` for
/// anything that is not such a request.
///
/// No longer called from `event_router_task`: now that `tm_netstack::tailnet`
/// gives the device a real lwIP netif (plan (a),
/// docs/tailnet-http-lwip-netif-plan.md), decrypted inbound packets are
/// handed to `tailnet::inject_inbound` instead, and lwIP's own ICMP handling
/// answers pings the same way it answers everything else on that netif. Kept
/// (dead-code-allowed) as the rung-6a elicitor's reply-side counterpart and
/// for anyone bisecting the pre-netif behavior; see the plan's "retiring the
/// hand-rolled ICMP responder" item.
#[allow(dead_code)]
fn build_icmp_echo_reply(req: &[u8], our_ip: [u8; 4]) -> Option<heapless::Vec<u8, 1500>> {
    if req.len() < 20 || req[0] >> 4 != 4 { return None; } // IPv4 only
    let ihl = (req[0] & 0x0f) as usize * 4;                // IPv4 header length
    if ihl < 20 || req.len() < ihl + 8 { return None; }
    if req[9] != 1 { return None; }                        // protocol: ICMP
    if req[16..20] != our_ip { return None; }              // addressed to us
    if req[ihl] != 8 { return None; }                      // ICMP type: echo request

    // Copy the whole packet, then mutate in place; length/ident/seq/data all
    // carry over unchanged from the request, as ping expects.
    let mut reply: heapless::Vec<u8, 1500> = heapless::Vec::new();
    reply.extend_from_slice(req).ok()?;

    // Swap source and destination IPv4 addresses.
    let mut src = [0u8; 4]; src.copy_from_slice(&reply[12..16]);
    let mut dst = [0u8; 4]; dst.copy_from_slice(&reply[16..20]);
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    // Recompute the IPv4 header checksum over the (variable-length) header.
    reply[10] = 0; reply[11] = 0;
    let ip_csum = inet_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Echo request (8) -> echo reply (0); recompute the ICMP checksum over the
    // whole ICMP message (header + any ping payload).
    reply[ihl] = 0;
    reply[ihl + 2] = 0; reply[ihl + 3] = 0;
    let icmp_csum = inet_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(reply)
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
    mut netif_out_rx: tailnet::OutboundReceiver,
    ctrl_tx3: async_channel::Sender<ControlCmd>,
    derp_tx2: async_channel::Sender<DerpCmd>,
    wg_tx2: async_channel::Sender<WgCmd>,
    disco_tx2: async_channel::Sender<DiscoCmd>,
    our_ip_tx: Option<OurIpSender>,
    mut netif_out_tx: Option<tailnet::OutboundSender>,
) {
    info!("Runtime::join() - event_router task started");
    // Rung-6a addressing state: our tailnet IPv4 and each peer's tailnet IPv4
    // keyed by node key, captured from MapUpdate. Used to synthesize the ICMP
    // echo request we drive through tm_wg after PeerHandshook so the peer
    // replies and an inbound transport packet becomes observable.
    let mut our_ip: [u8; 4] = [0; 4];
    let mut peer_ips: heapless::Vec<([u8; 32], [u8; 4]), 8> = heapless::Vec::new();
    // Reverse lookup for the tailnet netif's outbound path (plan (a) item
    // 3): destination tailnet IPv4 -> peer node key, so a packet lwIP wants
    // to send out the "wg0"-style netif can be routed to the right
    // WireGuard peer. Rebuilt from the same `MapUpdate` as `peer_ips`.
    let mut ip_to_key: heapless::Vec<([u8; 4], [u8; 32]), 8> = heapless::Vec::new();
    // Last tailnet IPv4 address applied (or attempted) on the on-device
    // netif, and the last outbound destination IP logged as unresolved --
    // see `apply_tailnet_address`/`log_unknown_netif_dest`.
    let mut netif_applied_ip: Option<[u8; 4]> = None;
    let mut last_unknown_dst: Option<[u8; 4]> = None;
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
                            // peer and connect to the DERP region it is homed on,
                            // so the server can relay our WireGuard/disco traffic
                            // to it. A repeat Connect from a later map snapshot is
                            // ignored by the actor once a connection is up.
                            //
                            // The target MUST be a peer whose home region is
                            // actually present in the DERPMap. A peer homed on
                            // region 0 (no DERP home -- e.g. a stale ghost of our
                            // own node, which sorts first in the peer list) has no
                            // resolvable region, and picking it made the connect
                            // silently no-op so DERP never came up. Prefer an
                            // online peer with a resolvable region, then fall back
                            // to any peer with one.
                            // Connect our DERP session to the SAME home region
                            // tm_control advertises as our PreferredDERP. Both
                            // sides call tm_control::select_home_region on this
                            // same netmap snapshot, so advertised == actual with
                            // no coordination and no hardcoded region. This is
                            // what makes us reachable after a reboot on a stable
                            // tailnet IP: without a stable advertised home, peers
                            // only reach us via disco caches that go stale and
                            // inbound dies. DERP servers mesh across regions, so
                            // a single home session still reaches peers homed
                            // elsewhere.
                            if let Some(rid) = tm_control::select_home_region(map.as_ref()) {
                                if let Some(region) =
                                    map.derp_regions.iter().find(|r| r.region_id == rid)
                                {
                                    let port = if region.port != 0 { region.port } else { 443 };
                                    info!("Runtime::join() - DERP connect -> home region {} ({}) host={} port={}",
                                        region.region_id, region.region_code.as_str(),
                                        region.host.as_str(), port);
                                    let _ = derp_tx2.send(DerpCmd::Connect {
                                        host: region.host.clone(),
                                        port,
                                        cert_fingerprint: None,
                                    }).await;
                                    #[cfg(target_os = "espidf")]
                                    tokio_freertos_yield().await;
                                }
                            }
                            // Capture addressing for rung-6a and the tailnet
                            // netif's outbound routing BEFORE the map is
                            // moved into ApplyMap.
                            our_ip = map.our_ip.0;
                            peer_ips.clear();
                            ip_to_key.clear();
                            for p in map.peers.iter() {
                                let _ = peer_ips.push((p.node_key, p.tailnet_ip.0));
                                let _ = ip_to_key.push((p.tailnet_ip.0, p.node_key));
                            }
                            apply_tailnet_address(our_ip, &mut netif_applied_ip, &mut netif_out_tx);
                            let _ = wg_tx2.send(WgCmd::ApplyMap(map)).await;
                        }
                        ControlEvent::OurIpAssigned(ip) => {
                            info!("Runtime::join() - received ControlEvent::OurIpAssigned: {}.{}.{}.{}", ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
                            // Not espidf-specific: `OurIpSender` is a plain
                            // `async_channel::Sender<Ipv4Addr>`, so this must
                            // fire on every target. It used to be gated to
                            // espidf only, which meant `Runtime::connect`'s
                            // readiness signal (and any host test of it)
                            // never fired on host — see
                            // docs/wg-dataplane-notes.md "Readiness-decoupled
                            // connect handle".
                            apply_tailnet_address(ip.0, &mut netif_applied_ip, &mut netif_out_tx);
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
                            // Both branches MOVE the buffer tm_derp filled
                            // on to the next actor: every channel shares
                            // one buffer type (tm_buf::PktBox), so there is
                            // no copy into a differently-sized re-box here.
                            // (tm_disco bounds the disco ciphertext itself.)
                            if is_disco {
                                let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                    src_ip:   [0; 4],
                                    src_port: 0,
                                    data: payload,
                                }).await;
                                #[cfg(target_os = "espidf")]
                                tokio_freertos_yield().await;
                            } else {
                                let _ = wg_tx2.send(WgCmd::InboundPacket {
                                    src_key: *src_key.as_bytes(),
                                    payload,
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
                        // Forward tm_wg's buffer to DERP as-is (same
                        // tm_buf::PktBox type on both channels): no copy.
                        let _ = derp_tx2.send(DerpCmd::SendPacket {
                            dst_key: NodePublicKey::from_bytes(dst_key),
                            payload,
                        }).await;
                        #[cfg(target_os = "espidf")]
                        tokio_freertos_yield().await;
                    }
                    Ok(WgEvent::InboundDecrypted { src_key, payload }) => {
                        // Decrypted inbound app data destined for the local
                        // netstack. Handed to the on-device lwIP tailnet
                        // netif (plan (a), docs/tailnet-http-lwip-netif-plan.md
                        // item 5) via `tcpip_input()`, which is safe to call
                        // from this (non-tcpip) task -- see
                        // tm_netstack::tailnet's module doc comment.
                        info!("Runtime::join() - WgEvent::InboundDecrypted {} bytes from peer {:02x}{:02x}..", payload.len(), src_key[0], src_key[1]);
                        unsafe {
                            debug!("Runtime::join() - heap after inbound-decrypted (before inject_inbound): total_free={} largest_internal={} largest_default={}",
                                esp_idf_sys::esp_get_free_heap_size(),
                                esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL),
                                esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT));
                        }
                        match tailnet::inject_inbound(payload.as_slice()) {
                            Ok(()) => {}
                            Err(tailnet::TailnetError::NotSupported) => {
                                // Expected on host builds; nothing to inject into.
                                debug!("Runtime::join() - tailnet netif not supported on this target; dropping inbound packet");
                            }
                            Err(e) => {
                                warn!("Runtime::join() - tailnet inject_inbound failed: {:?}", e);
                            }
                        }
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
                                if let Some(buf) = tm_buf::box_from_slice(&echo) {
                                    let _ = wg_tx2.send(WgCmd::SendData {
                                        dst_key: key,
                                        payload: buf,
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
            // ── Tailnet netif outbound packets (plan (a) item 3) ───────
            // lwIP's netif `output` callback (tm_netstack::tailnet::device)
            // handed this packet to us because it wants to send it out the
            // tailnet interface. Route it to the WireGuard peer that owns
            // its destination IP, if we know one.
            pkt = netif_out_rx.recv() => {
                match pkt {
                    Ok(tailnet::OutboundPacket { dst_ip, data }) => {
                        if let Some((_, dst_key)) = ip_to_key.iter().find(|(ip, _)| *ip == dst_ip) {
                            let _ = wg_tx2.send(WgCmd::SendData {
                                dst_key: *dst_key,
                                payload: data,
                            }).await;
                            #[cfg(target_os = "espidf")]
                            tokio_freertos_yield().await;
                        } else {
                            log_unknown_netif_dest(dst_ip, &mut last_unknown_dst);
                        }
                    }
                    Err(_) => {
                        info!("Runtime::join() - tailnet netif outbound channel closed, breaking");
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
    netif_out_rx: tailnet::OutboundReceiver,
    ctrl_tx3: async_channel::Sender<ControlCmd>,
    derp_tx2: async_channel::Sender<DerpCmd>,
    wg_tx2: async_channel::Sender<WgCmd>,
    disco_tx2: async_channel::Sender<DiscoCmd>,
    our_ip_tx: Option<OurIpSender>,
    netif_out_tx: Option<tailnet::OutboundSender>,
) -> BoxActorFut {
    Box::pin(event_router_task(
        ctrl_ev_rx, derp_ev_rx, disco_ev_rx, wg_ev_rx, netif_out_rx,
        ctrl_tx3, derp_tx2, wg_tx2, disco_tx2, our_ip_tx, netif_out_tx,
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

/// The still-pending data-plane future handed back by `Runtime::connect`.
///
/// Polling it is what keeps every actor (control, DERP, disco, WireGuard,
/// event router — including the deliberately unbounded streaming MapResponse
/// poll) alive; it resolves only once every actor's task ends, which during
/// normal operation is never. The caller MUST fold this into its own
/// `tokio::join!`/`tokio::try_join!` alongside its other work — NOT
/// `.await` it alone (that reproduces `Runtime::join`'s "never returns"
/// behavior) and NOT race it under an external `timeout`/`select!` that
/// would drop it (that reproduces the ephemeral-node-GC bug from card
/// t_0d32f11d: dropping this future drops every actor, closing the control
/// connection). See docs/wg-dataplane-notes.md "Readiness-decoupled connect
/// handle".
pub type Driver = core::pin::Pin<Box<dyn core::future::Future<Output = ()>>>;

/// `Runtime::connect` failed to reach readiness (`OurIpAssigned`) before the
/// data-plane future itself ended. In practice this means bring-up failed
/// or exceeded `RuntimeConfig::connect_timeout` — `ControlActor` emits
/// `ControlEvent::Error` and ends its task in that case, which (via the
/// event router closing in turn) drops the readiness sender and unblocks
/// this race with an `Err` rather than hanging forever. No retry here —
/// v2 follow-up, see docs/wg-dataplane-notes.md.
#[derive(Debug)]
pub struct ConnectError;

/// Race an arbitrary long-running "driver" future against a readiness
/// channel, WITHOUT ever dropping the driver.
///
/// This is the pure-async pattern `Runtime::connect` is built on: `driver`
/// is `&mut`-borrowed (never consumed), so if `ready_rx` fires first,
/// `driver` is left exactly where it was -- still pending, still fully
/// alive, no actor torn down -- for the caller to keep polling afterward.
/// If `driver` resolves first, or `ready_rx`'s sender is dropped before
/// sending, this returns `Err(())`.
///
/// Deliberately generic over `D`/`T` and free of any `tm_runtime` actor
/// type: this is the one piece of `connect`'s logic that has no
/// `esp-idf-sys`/`esp-idf-svc` dependency and so is host-unit-testable even
/// though the rest of this crate (and the `tailmicro` root crate that wraps
/// it) is not — see `tm_runtime`'s host-build note in
/// docs/wg-dataplane-notes.md "Readiness-decoupled connect handle".
pub async fn race_driver_vs_ready<T, D>(
    driver: &mut D,
    ready_rx: &async_channel::Receiver<T>,
) -> Result<T, ()>
where
    D: core::future::Future<Output = ()> + Unpin,
{
    tokio::select! {
        _ = driver => Err(()),
        recv = ready_rx.recv() => recv.map_err(|_| ()),
    }
}

impl Runtime {
    /// Shared actor/channel construction for both `join` and `connect`.
    ///
    /// Builds every actor and the event router exactly as before, sends the
    /// initial `ControlCmd::Start`, and returns the still-idle `Runtime`
    /// handle (its command senders are usable immediately — they don't
    /// depend on any actor having made progress) together with the combined
    /// `Driver` future, NOT yet polled to completion.
    #[inline(never)]
    async fn build(mut config: RuntimeConfig) -> (Self, Driver) {
        tracing::debug!("Runtime::build() - starting actor runtime");

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

        // Tailnet netif outbound-packet channel (plan (a) item 3): packets
        // lwIP's netif `output` callback wants sent out the tailnet
        // interface, drained by `event_router_task` and routed to a
        // WireGuard peer. Same capacity/backpressure philosophy as every
        // other inter-actor channel here.
        let (netif_out_tx, netif_out_rx) = async_channel::bounded::<tailnet::OutboundPacket>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after tailnet netif outbound channel");

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
            ctrl_ev_rx, derp_ev_rx, disco_ev_rx, wg_ev_rx, netif_out_rx,
            ctrl_tx3, derp_tx2, wg_tx2, disco_tx2, our_ip_tx, Some(netif_out_tx),
        );

        log_heap("before Driver construction (all actors constructed)");

        tracing::debug!("Runtime::build() - sending ControlCmd::Start");
        let _ = ctrl_tx4.send(ControlCmd::Start { auth_key: config.auth_key.clone() }).await;

        tracing::debug!("Runtime::build() - combining actor tasks into a single Driver future");
        // Run all actors together. The event_router loop runs indefinitely until a channel error occurs.
        // The other tasks (control_task, derp_task, disco_task, wg_task) will complete when their channels close.
        // Boxed (not returned as an opaque `impl Future`) so `Driver` is a
        // concrete, nameable type callers can hold across an `.await` point
        // (in `connect`'s readiness race) without it becoming part of any
        // caller's own generator state -- same off-frame-boxing discipline
        // as every `spawn_*` helper above.
        let driver: Driver = Box::pin(async move {
            tokio::join!(
                control_task,
                derp_task,
                disco_task,
                wg_task,
                event_router,
            );
            tracing::debug!("Runtime - all actor tasks completed");
        });

        (Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }, driver)
    }

    /// Run all actors within a single task using `tokio::join!`.
    ///
    /// This avoids per-task heap allocations that `tokio::spawn` incurs.
    /// All actors run cooperatively on the same stack.
    ///
    /// Never returns while the connection is up (the streaming MapResponse
    /// poll is deliberately unbounded so the node stays marked online) --
    /// prefer `Runtime::connect` for any caller that needs to do other work
    /// (e.g. run an HTTP server) concurrently with the data plane, since
    /// that other work can't proceed until this returns. See
    /// docs/wg-dataplane-notes.md "Readiness-decoupled connect handle".
    pub async fn join(config: RuntimeConfig) -> Self {
        let (runtime, driver) = Self::build(config).await;
        driver.await;
        runtime
    }

    /// Connect and return as soon as the tailnet IP is assigned
    /// (`ControlEvent::OurIpAssigned`), handing back the still-pending data
    /// plane `Driver` future for the caller to fold into its own
    /// `tokio::join!`/`tokio::try_join!`.
    ///
    /// Bring-up (TCP + Noise + register + publish, up to `OurIpAssigned`) is
    /// bounded by `RuntimeConfig::connect_timeout` inside `ControlActor`
    /// itself -- `connect` adds no timeout of its own. On a bring-up
    /// failure or timeout, `ControlActor::run` emits `ControlEvent::Error`
    /// and ends its task; that closes the control event channel, which ends
    /// the event router in turn, which drops the readiness sender created
    /// below -- so the race below resolves to `Err(ConnectError)` rather
    /// than hanging.
    ///
    /// Whichever caller-supplied `config.our_ip_tx` may have been set is
    /// overwritten here: `connect` owns the readiness channel it races
    /// against the driver, so it must be the one to construct and hold the
    /// sending half.
    pub async fn connect(mut config: RuntimeConfig) -> Result<(Self, Ipv4Addr, Driver), ConnectError> {
        let (our_ip_tx, our_ip_rx) = async_channel::bounded::<Ipv4Addr>(1);
        config.our_ip_tx = Some(our_ip_tx);

        let (runtime, mut driver) = Self::build(config).await;

        match race_driver_vs_ready(&mut driver, &our_ip_rx).await {
            Ok(ip) => Ok((runtime, ip, driver)),
            Err(()) => Err(ConnectError),
        }
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
                                        // DISCO magic prefix (simplified check).
                                        // Buffer forwarded as-is (tm_buf::PktBox).
                                        let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                            src_ip:   [0; 4],  // from DERP src
                                            src_port: 0,
                                            data: payload,
                                        }).await;
                                    } else {
                                        // WireGuard packet, forwarded as-is.
                                        let _ = wg_tx2.send(WgCmd::InboundPacket {
                                            src_key: *src_key.as_bytes(),
                                            payload,
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

// ── Tests ────────────────────────────────────────────────────────────────────
//
// NOTE: this crate cannot currently be `cargo test`-ed on host in this
// environment -- `tm_runtime`'s `[dependencies]` pull in `esp-idf-sys`/
// `esp-idf-svc` unconditionally (not `cfg`-gated to `target_os = "espidf"`),
// and `esp-idf-sys`'s build script refuses any non-espidf target outright
// ("Unsupported target 'x86_64-unknown-linux-gnu'"). Confirmed pre-existing
// (present before this change too, via `git stash` + rebuild on the prior
// commit) and NOT something this change introduces or fixes -- see
// docs/wg-dataplane-notes.md "Readiness-decoupled connect handle" for the
// note to the owner. These tests exercise the real `race_driver_vs_ready`
// used by `Runtime::connect` (not a re-implementation) and will run
// wherever this crate's build script preconditions are satisfied (a real
// ESP-IDF toolchain, or a future fix that `cfg`-gates the esp-idf deps).
#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    fn pending_forever() -> Pin<Box<dyn Future<Output = ()>>> {
        Box::pin(std::future::pending())
    }

    fn already_done() -> Pin<Box<dyn Future<Output = ()>>> {
        Box::pin(async {})
    }

    /// Readiness firing while the driver is still pending must win the
    /// race, and must NOT consume/drop the driver (it must still be usable
    /// -- here, still pending -- afterward).
    #[tokio::test]
    async fn readiness_wins_and_driver_survives() {
        let mut driver = pending_forever();
        let (tx1, rx1) = async_channel::bounded::<u32>(1);
        tx1.send(42).await.unwrap();
        assert_eq!(race_driver_vs_ready(&mut driver, &rx1).await, Ok(42));

        // `driver` must still be alive and pending -- proved by racing it a
        // second time: it only compiles/runs at all if the first call left
        // `driver` intact (never consumed it), and this second race must
        // resolve via the NEW channel (not via `driver` suddenly
        // completing), since `pending_forever()` never does.
        let (tx2, rx2) = async_channel::bounded::<u32>(1);
        tx2.send(7).await.unwrap();
        assert_eq!(race_driver_vs_ready(&mut driver, &rx2).await, Ok(7));
    }

    /// If the driver ends before readiness ever fires, that's a bring-up
    /// failure: the race must resolve to `Err`, not hang.
    #[tokio::test]
    async fn driver_ending_first_is_an_error() {
        let mut driver = already_done();
        let (_tx, rx) = async_channel::bounded::<u32>(1); // never sent to

        let result = race_driver_vs_ready(&mut driver, &rx).await;
        assert_eq!(result, Err(()));
    }

    /// The readiness sender being dropped (e.g. because whatever owned it
    /// -- the event router in `Runtime::connect`'s real usage -- ended
    /// after a bring-up error) must also resolve to `Err`, not hang, even
    /// if the driver itself is still (separately) pending.
    #[tokio::test]
    async fn dropped_sender_is_an_error() {
        let mut driver = pending_forever();
        let (tx, rx) = async_channel::bounded::<u32>(1);
        drop(tx);

        let result = race_driver_vs_ready(&mut driver, &rx).await;
        assert_eq!(result, Err(()));
    }
}
