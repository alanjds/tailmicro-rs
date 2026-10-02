//! Runtime — wires all actors together.
//!
//! This is the equivalent of `ts_runtime` in tailscale-rs.  It owns the
//! actor handles and the channels between them.
//!
//! ## Key difference from ts_runtime
//!
//! `ts_runtime` uses `tokio::spawn` for each actor. Here every actor is a
//! future folded into one `tokio::join!` inside the `Driver` returned by
//! `Runtime::connect`, so there is no per-task heap allocation and all actors
//! share one stack.
//!
//! ## Channel implementation
//!
//! Uses bounded `async_channel` channels (heap ring allocated once at build)
//! for predictable memory usage on ESP32-C3.
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
use log::{info, debug, trace, warn, error};
use async_channel;

/// FreeRTOS yield function for ESP32-C3 watchdog servicing.
/// Calls `vTaskDelay(50)` to yield the CPU and service the watchdog timer.
///
/// `vTaskDelay` blocks the whole FreeRTOS task, and with it every actor on
/// this `current_thread` runtime, for 50 ticks (50 ms at this project's
/// `CONFIG_FREERTOS_HZ=1000`). Fine at boot (`Runtime::build`); never on a
/// per-packet path, see [`RouterYield`].
#[cfg(target_os = "espidf")]
pub async fn tokio_freertos_yield() {
    freertos_yield_ticks(50).await;
}

/// Host stand-in: there is no FreeRTOS idle task or task watchdog to feed, so
/// only the cooperative yield remains (keeps the boot interleaving of the
/// device build).
#[cfg(not(target_os = "espidf"))]
pub async fn tokio_freertos_yield() {
    tokio::task::yield_now().await;
}

/// How long the event router may run without a gap before it hands the CPU
/// to FreeRTOS for one tick.
///
/// A `vTaskDelay` blocks the whole `current_thread` runtime, so doing it on
/// every router iteration (it was 50 ticks, then 1) put a floor of about one
/// tick under every hop: a ping echo crosses the router three times
/// (ALLOCATIONS.md Step 9). The yield exists only so the idle task and the
/// task watchdog (`CONFIG_ESP_TASK_WDT_TIMEOUT_S`, 30 s) get CPU during a
/// sustained burst; whenever the runtime parks in its reactor they already
/// do. lwIP's tcpip thread (priority 18) and the WiFi task (23) preempt this
/// task (priority 1) regardless.
#[cfg(target_os = "espidf")]
const ROUTER_BUSY_LIMIT: std::time::Duration = std::time::Duration::from_millis(10);

/// Yield policy for the event router: a tokio `yield_now` on every call so
/// sibling actors get a turn, plus one tick of FreeRTOS delay once the router
/// has gone [`ROUTER_BUSY_LIMIT`] without a gap longer than that limit
/// between calls (a longer gap means it was waiting, i.e. the runtime parked).
#[cfg(target_os = "espidf")]
struct RouterYield {
    last_call: std::time::Instant,
    busy_since: std::time::Instant,
}

#[cfg(target_os = "espidf")]
impl RouterYield {
    fn new() -> Self {
        let now = std::time::Instant::now();
        Self { last_call: now, busy_since: now }
    }

    async fn tick(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_call) > ROUTER_BUSY_LIMIT {
            self.busy_since = now;
        }
        self.last_call = now;
        if now.duration_since(self.busy_since) >= ROUTER_BUSY_LIMIT {
            freertos_yield_ticks(1).await;
            let after = std::time::Instant::now();
            self.busy_since = after;
            self.last_call = after;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(target_os = "espidf")]
async fn freertos_yield_ticks(ticks: u32) {
    let t0 = tm_buf::lat::now_us();
    unsafe { esp_idf_sys::vTaskDelay(ticks) };
    tm_buf::lat::note_yield(tm_buf::lat::now_us().wrapping_sub(t0));
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
/// build) inside the single `Runtime::build` poll frame. With ~15 heap-probe
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

// ── LAN-direct UDP socket (docs/lan-direct-path-plan.md, Steps 2 and 5) ─────
//
// Step 5 wires the whole path at once, as plan D4 requires: UDP disco goes to
// tm_disco (which answers PINGs with UDP PONGs), UDP WireGuard goes to tm_wg,
// tm_wg's `via: Some(addr)` sends leave through this socket (DERP on any
// error), and tm_control publishes our LAN endpoint. Answering PONGs without
// ingesting UDP WireGuard would black-hole every LAN peer that switches over,
// so none of these may exist without the others.

/// The bound LAN socket. A static rather than a `Box`: it lives for the whole
/// firmware lifetime, and the router (sends) and the receive task (receives)
/// both need it, so a shared `&'static` avoids any heap.
#[cfg(feature = "lan-direct")]
static LAN_SOCK: std::sync::OnceLock<tm_netstack::UdpSocket> = std::sync::OnceLock::new();

/// Counters for the receive loop and the router's direct sends; static so
/// they cost no heap and stay readable from anywhere (e.g. a status endpoint).
#[cfg(feature = "lan-direct")]
pub static LAN_UDP_STATS: tm_netstack::lan_udp::RxStats = tm_netstack::lan_udp::RxStats::new();

/// Whether an authenticated UDP disco PING (tm_disco's `DirectPathSeen`) is
/// allowed to point tm_wg's *sends* at the PING's source address. Off.
///
/// Plan D3(a) said yes. But a PING proves only that the peer reaches us, not
/// that we reach the peer; tailscaled itself (and MicroLink,
/// ml_wg_mgr.c `process_disco_pong`) adopts a path only on a PONG to its own
/// PING. Measured on hardware in Step 6: with this on, a one-way break (the
/// peer receives nothing we send over UDP) kept the device sending into the
/// break for the whole fault, because the peer re-probes our endpoint every
/// ~3 s while it has traffic. See the plan's Step 5/6 status.
///
/// tm_wg instead adopts a direct path from authenticated WireGuard received
/// over UDP (D3(b)), and holds sends on DERP while the peer is itself
/// sending over DERP (`tm_wg::endpoint::DERP_HOLDOFF`).
#[cfg(feature = "lan-direct")]
const DISCO_PING_SETS_SEND_PATH: bool = false;

/// Minimum free `tm_buf` pool buffers for the UDP task to take one (below
/// it, the task waits, up to `lan_udp::RX_WAIT_BUDGET`, then drops). The pool
/// is shared with DERP receive and the tailnet netif (`tm_buf::POOL_N`), and
/// `PktBuf::acquire` falls back to a ~1.5 KB heap allocation when it is
/// empty. Any LAN host can send to this socket, so it must neither cause
/// that heap churn nor take the last buffer from the DERP path.
#[cfg(feature = "lan-direct")]
const UDP_MIN_FREE_PKTBUFS: usize = 2;

/// Disco gets the second-to-last buffer too. A PING arrives every ~3 s per
/// peer, but each one that is dropped is a missing PONG, and tailscaled
/// stops trusting the direct path after 6.5 s without one: it then sends
/// over both paths, our DERP hold-off engages, and the path flaps. On
/// hardware (Step 6 soak) every flap coincided with PINGs lost to the
/// 2-buffer floor under curl load. The last buffer stays reserved.
#[cfg(feature = "lan-direct")]
const UDP_DISCO_MIN_FREE_PKTBUFS: usize = 1;

/// One heap line at a one-time event (bind), in the same shape as the other
/// `heap-blocks` probes, at info level so it survives the app's per-target
/// Info cap. Never called per packet.
#[cfg(feature = "lan-direct")]
#[inline(never)]
fn log_heap_blocks(tag: &str) {
    #[cfg(target_os = "espidf")]
    unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        info!(
            "lan-direct heap-blocks [{}]: total_free={} largest_free={} free_blocks={} allocated_blocks={}",
            tag, info.total_free_bytes, info.largest_free_block, info.free_blocks, info.allocated_blocks,
        );
    }
    #[cfg(not(target_os = "espidf"))]
    let _ = tag;
}

/// Bind the LAN UDP socket. Called from `Runtime::build` before any actor
/// runs, so its lwIP socket/netconn/pcb allocations happen before the DERP
/// TLS handshake fragments the heap (plan, "RAM/lwIP budget"). Any failure
/// is a warning and a DERP-only run, never an error (D5); the endpoint is
/// then not published either, since control only gets a port on success.
#[cfg(feature = "lan-direct")]
#[inline(never)]
fn bind_lan_udp() -> Option<&'static tm_netstack::UdpSocket> {
    log_heap_blocks("before UDP bind");
    match tm_netstack::lan_udp::bind_lan() {
        Ok((sock, fallback)) => {
            let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
            let sock = LAN_SOCK.get_or_init(|| sock);
            info!(
                "lan-direct: UDP socket bound on 0.0.0.0:{}{}",
                port,
                if fallback { " (41641 was taken)" } else { "" },
            );
            log_heap_blocks("after UDP bind");
            Some(sock)
        }
        Err(e) => {
            warn!("lan-direct: UDP bind failed ({:?}); running DERP-only", e);
            None
        }
    }
}

#[cfg(feature = "lan-direct")]
#[inline(never)]
fn spawn_udp(
    sock: &'static tm_netstack::UdpSocket,
    disco_tx: async_channel::Sender<DiscoCmd>,
    wg_tx: async_channel::Sender<WgCmd>,
) -> BoxActorFut {
    Box::pin(udp_rx_task(sock, disco_tx, wg_tx))
}

/// Where the UDP receive loop hands accepted datagrams: disco to tm_disco as
/// `DiscoSrc::Udp`, WireGuard to tm_wg as `Via::Udp`.
///
/// Unlike the event router, this task *awaits* room (pool floor, then
/// channel slot) instead of dropping, bounded by `RX_WAIT_BUDGET`
/// (ALLOCATIONS.md, "UDP receive waits instead of dropping"). That is
/// deadlock-free because nothing waits on this task: its consumers (tm_wg,
/// tm_disco) drain their command channels while blocked only on the event
/// router, which never awaits a full channel (`forward_or_drop`); and pool
/// buffers are returned by those actors, the router, tm_derp and lwIP's
/// tcpip thread, never by this task. While it waits it holds at most one
/// buffer, and lwIP's bounded recvmbox queues further datagrams.
///
/// The first datagram of each class is logged once at info level, the rest
/// at `trace!`, plus `rx_loop`'s coarse periodic counter line, so a flood
/// cannot turn into UART output (ALLOCATIONS.md Step 8, Fix 3).
#[cfg(feature = "lan-direct")]
struct UdpSink {
    disco_tx: async_channel::Sender<DiscoCmd>,
    wg_tx: async_channel::Sender<WgCmd>,
    first_disco: bool,
    first_wg: bool,
}

#[cfg(feature = "lan-direct")]
impl tm_netstack::lan_udp::RxSink for UdpSink {
    async fn deliver(&mut self, class: tm_netstack::lan_udp::RxClass, src: std::net::SocketAddrV4, data: &[u8]) {
        use tm_netstack::lan_udp::{forward_backpressured, RxClass, RX_WAIT_BUDGET};
        match class {
            RxClass::Disco => {
                tm_buf::lat::stamp(tm_buf::lat::Hop::UdpRxDisco);
                if self.first_disco {
                    self.first_disco = false;
                    info!("lan-direct: first UDP disco datagram from {} ({} B)", src, data.len());
                } else {
                    trace!("lan-direct: UDP disco {} B from {}", data.len(), src);
                }
                let r = forward_backpressured(&self.disco_tx, data, UDP_DISCO_MIN_FREE_PKTBUFS, RX_WAIT_BUDGET, |buf| {
                    DiscoCmd::MaybeDisco { src: tm_disco::DiscoSrc::Udp(src), data: buf }
                })
                .await;
                LAN_UDP_STATS.record(r, true);
            }
            RxClass::WireGuard => {
                if data[0] == 4 {
                    tm_buf::lat::stamp(tm_buf::lat::Hop::UdpRxWg);
                }
                if self.first_wg {
                    self.first_wg = false;
                    info!("lan-direct: first UDP WireGuard datagram from {} (type {}, {} B)", src, data[0], data.len());
                } else {
                    trace!("lan-direct: UDP WireGuard type {} {} B from {}", data[0], data.len(), src);
                }
                let r = forward_backpressured(&self.wg_tx, data, UDP_MIN_FREE_PKTBUFS, RX_WAIT_BUDGET, |buf| {
                    WgCmd::InboundPacket { via: tm_wg::Via::Udp(src), payload: buf }
                })
                .await;
                LAN_UDP_STATS.record(r, false);
            }
            RxClass::Junk | RxClass::Tailnet => {}
        }
    }
}

/// The receive task: `rx_loop` over the LAN socket into a [`UdpSink`].
#[cfg(feature = "lan-direct")]
async fn udp_rx_task(
    sock: &'static tm_netstack::UdpSocket,
    disco_tx: async_channel::Sender<DiscoCmd>,
    wg_tx: async_channel::Sender<WgCmd>,
) {
    use tm_netstack::lan_udp::{rx_buf_static, rx_loop};
    // Prime the reactor's writable readiness before any PONG can be due.
    // tokio's `try_send_to` reports `WouldBlock` until the reactor has seen
    // the socket writable once, which would silently drop the first PONGs
    // (Step 2 status).
    if let Err(e) = sock.writable().await {
        warn!("lan-direct: UDP socket never became writable ({:?}); direct path off, DERP unaffected", e);
        return;
    }
    let buf = rx_buf_static();
    let mut sink = UdpSink { disco_tx, wg_tx, first_disco: true, first_wg: true };
    let err = rx_loop(sock, &mut buf[..], &LAN_UDP_STATS, &mut sink).await;
    warn!("lan-direct: UDP receive loop stopped ({:?}); direct path off, DERP unaffected", err);
}

/// Step 6.2 fault injection (`lan-direct-fault-test`, test builds only).
/// Returns true while the device's direct transmits must vanish: seconds
/// since the first direct send, modulo `CYCLE`, in `[BLOCK_FROM, BLOCK_TO)`. The send is reported as a
/// success, exactly like loss on the wire, so nothing on the device falls
/// back on its own; only the protocol's trust windows can recover.
#[cfg(feature = "lan-direct-fault-test")]
fn fault_tx_blocked() -> bool {
    const CYCLE: u64 = 300;
    const BLOCK_FROM: u64 = 150;
    const BLOCK_TO: u64 = 210;
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static LAST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    let t = START.get_or_init(std::time::Instant::now).elapsed().as_secs() % CYCLE;
    let blocked = (BLOCK_FROM..BLOCK_TO).contains(&t);
    if LAST.swap(blocked, core::sync::atomic::Ordering::Relaxed) != blocked {
        warn!("lan-direct FAULT TEST: direct UDP transmits now {}", if blocked { "DROPPED" } else { "restored" });
    }
    blocked
}
#[cfg(all(feature = "lan-direct", not(feature = "lan-direct-fault-test")))]
#[inline(always)]
fn fault_tx_blocked() -> bool {
    false
}

/// Send one WireGuard datagram straight to `addr`. `Err` hands the buffer
/// back so the caller can send the very same bytes over DERP instead (plan
/// Step 5: a transient `ENOMEM`/`WouldBlock` costs latency, not a packet).
#[cfg(feature = "lan-direct")]
fn send_wg_direct(addr: std::net::SocketAddrV4, payload: tm_buf::PktBuf) -> Result<(), tm_buf::PktBuf> {
    use core::sync::atomic::Ordering::Relaxed;
    let Some(sock) = LAN_SOCK.get() else {
        LAN_UDP_STATS.tx_fallback.fetch_add(1, Relaxed);
        return Err(payload);
    };
    let r = if fault_tx_blocked() { Ok(()) } else { sock.try_send_to(std::net::SocketAddr::V4(addr), payload.as_slice()) };
    match r {
        Ok(()) => {
            LAN_UDP_STATS.tx_wg.fetch_add(1, Relaxed);
            Ok(())
        }
        Err(e) => {
            let n = LAN_UDP_STATS.tx_fallback.fetch_add(1, Relaxed) + 1;
            if n.is_power_of_two() {
                warn!("lan-direct: direct send to {} failed ({:?}); sent via DERP (fallbacks so far: {})", addr, e, n);
            }
            Err(payload)
        }
    }
}

/// Send a sealed PONG back to the peer's observed UDP address. A failure is
/// only counted: the peer simply does not trust the path yet and keeps using
/// DERP, which is always safe.
#[cfg(feature = "lan-direct")]
#[inline(never)]
fn send_pong_direct(dst: std::net::SocketAddrV4, payload: &[u8]) {
    use core::sync::atomic::Ordering::Relaxed;
    let r = match LAN_SOCK.get() {
        Some(_) if fault_tx_blocked() => Ok(()),
        Some(sock) => sock.try_send_to(std::net::SocketAddr::V4(dst), payload),
        None => Err(tm_netstack::NetError::WouldBlock),
    };
    match r {
        Ok(()) => {
            if LAN_UDP_STATS.tx_pong.fetch_add(1, Relaxed) == 0 {
                info!("lan-direct: first UDP PONG sent to {}", dst);
            }
        }
        Err(e) => {
            let n = LAN_UDP_STATS.tx_pong_err.fetch_add(1, Relaxed) + 1;
            if n.is_power_of_two() {
                warn!("lan-direct: UDP PONG to {} failed ({:?}) (failures so far: {})", dst, e, n);
            }
        }
    }
}

/// Log a peer's send path only when it changes (DERP to direct, direct to
/// DERP, or a new direct address). This is the evidence for Step 6's
/// "OutboundPacket via udp" and for the fallback timing, without a line per
/// packet. `#[inline(never)]` keeps its temporaries off the router frame.
#[cfg(feature = "lan-direct")]
#[inline(never)]
fn log_path_change(
    last: &mut heapless::Vec<([u8; 32], Option<std::net::SocketAddrV4>), 8>,
    dst_key: &[u8; 32],
    via: Option<std::net::SocketAddrV4>,
) {
    let slot = match last.iter_mut().find(|(k, _)| k == dst_key) {
        Some((_, v)) => v,
        None => {
            // A peer's first packet: DERP is the silent default.
            if last.is_full() {
                last.remove(0);
            }
            let _ = last.push((*dst_key, None));
            &mut last.last_mut().unwrap().1
        }
    };
    if *slot == via {
        return;
    }
    *slot = via;
    match via {
        Some(a) => info!("lan-direct: OutboundPacket via udp {} for peer {:02x}{:02x}..", a, dst_key[0], dst_key[1]),
        None => info!("lan-direct: OutboundPacket via DERP again for peer {:02x}{:02x}.. (direct trust lapsed, or the peer is sending over DERP)", dst_key[0], dst_key[1]),
    }
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

/// Minimum spacing between router-initiated netmap refreshes. tm_control
/// applies its own gap too; this one keeps a flood of unroutable packets from
/// even queueing commands.
const MISS_REFRESH_GAP: core::time::Duration = core::time::Duration::from_secs(120);

/// Ask control for a fresh netmap because a packet had no route: the peer may
/// have joined after the last snapshot. `try_send`, never `send().await`:
/// the router must not stall its data plane on a full control queue, and a
/// dropped request is repeated by the next miss after the gap.
/// Returns whether a request was queued.
#[inline(never)]
fn request_refresh_on_miss(tx: &async_channel::Sender<ControlCmd>,
                           last: &mut Option<std::time::Instant>,
                           now: std::time::Instant) -> bool {
    if last.is_some_and(|t| now.saturating_duration_since(t) < MISS_REFRESH_GAP) {
        return false;
    }
    if tx.try_send(ControlCmd::Refresh).is_ok() {
        *last = Some(now);
        info!("Runtime::join() - unknown tailnet destination, asking control for a fresh netmap");
        true
    } else {
        false
    }
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

/// Router-side state of the `latency-trace` diagnostic (ALLOCATIONS.md
/// Step 9). Prints one line per ping, after the reply has been sent, and a
/// router summary every 10 s. Rate-limited so it cannot saturate the UART
/// (Step 8, Fix 3).
#[cfg(feature = "latency-trace")]
struct LatState {
    icmp_reply_pending: bool,
    last_line_us: u32,
    last_summary_us: u32,
}

#[cfg(feature = "latency-trace")]
impl LatState {
    fn new() -> Self {
        let now = tm_buf::lat::now_us();
        Self { icmp_reply_pending: false, last_line_us: now, last_summary_us: now }
    }

    /// True for the first `OutboundPacket` bigger than a keepalive after an
    /// ICMP echo reply left the netif: that is the encrypted reply.
    fn take_icmp_reply(&mut self, len: usize) -> bool {
        if self.icmp_reply_pending && len > 32 {
            self.icmp_reply_pending = false;
            tm_buf::lat::stamp(tm_buf::lat::Hop::RouterOutbound);
            return true;
        }
        false
    }

    #[inline(never)]
    fn on_iter(&mut self) {
        tm_buf::lat::note_router_iter();
        let now = tm_buf::lat::now_us();
        let dt = now.wrapping_sub(self.last_summary_us);
        if dt >= 10_000_000 {
            self.last_summary_us = now;
            let (iters, yield_us, yield_max) = tm_buf::lat::take_router_stats();
            info!(
                "lat router: {} iters in {} ms, blocked in vTaskDelay {} ms ({}%), max yield {} ms",
                iters, dt / 1000, yield_us / 1000, yield_us as u64 * 100 / dt as u64, yield_max / 1000,
            );
        }
    }

    #[inline(never)]
    fn report(&mut self, what: &str, hops: &[tm_buf::lat::Hop], direct: bool) {
        let now = tm_buf::lat::now_us();
        if now.wrapping_sub(self.last_line_us) < 300_000 {
            return;
        }
        self.last_line_us = now;
        match tm_buf::lat::chain(hops) {
            Some(d) => {
                // Milliseconds with one decimal: total, then each hop delta.
                let mut line: heapless::String<160> = heapless::String::new();
                for (i, us) in d.iter().enumerate() {
                    use core::fmt::Write;
                    let _ = write!(line, "{}{}.{}", if i == 1 { " |" } else { " " }, us / 1000, (us % 1000) / 100);
                }
                info!("lat {} {}:{}", what, if direct { "udp" } else { "derp" }, line.as_str());
            }
            None => {
                // Offsets from the first hop in ms; "-" = never stamped.
                let mut line: heapless::String<200> = heapless::String::new();
                for o in tm_buf::lat::offsets(hops).iter() {
                    use core::fmt::Write;
                    let _ = if *o == i32::MIN { write!(line, " -") } else { write!(line, " {}", o / 1000) };
                }
                info!("lat {} {}: chain refused, offsets ms:{}", what, if direct { "udp" } else { "derp" }, line.as_str());
            }
        }
        for h in hops {
            tm_buf::lat::clear(*h);
        }
    }
}

/// Hand a data-plane packet to an actor without ever blocking the event
/// router (ALLOCATIONS.md Step 7). The router is the only consumer of the
/// actors' event channels, and those actors (`WgActor` in particular, see
/// its `drain_recv`) block on sending *to* the router when their
/// `CHAN_CAP = 2` event channel is full. If the router in turn awaited a
/// full command channel of the same actor, both would wait on each other
/// forever -- observed on real hardware as the whole data plane (DERP
/// receive, WireGuard, the tailnet HTTP server) going silent while the
/// control plane kept running. Packets are droppable (TCP retransmits, WG
/// keepalives recur), so a full channel drops the packet instead; its
/// `PktBuf` returns to the pool on drop.
fn forward_or_drop<T>(tx: &async_channel::Sender<T>, msg: T, what: &str) {
    match tx.try_send(msg) {
        Ok(()) => {}
        Err(async_channel::TrySendError::Full(_)) => {
            let n = ROUTER_DROPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
            // Rate-limited: under load drops come in bursts, and a line per
            // drop on a blocking UART console slows the data plane further,
            // which causes more drops.
            if n.is_power_of_two() || n % 256 == 0 {
                warn!("Runtime::join() - {} channel full; dropped packet instead of blocking the router (drops so far: {})", what, n);
            }
        }
        Err(async_channel::TrySendError::Closed(_)) => {
            debug!("Runtime::join() - {} channel closed; packet dropped", what);
        }
    }
}

static ROUTER_DROPS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);


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
/// The per-peer facts the router needs to notice that a later snapshot changed
/// something about a peer it already knew.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerSnap {
    node_key: [u8; 32],
    disco_key: [u8; 32],
}

/// Bring tm_disco's allowlist from the previous snapshot (`known`) to `map`,
/// then record `map` as the new baseline. Only differences are sent: a peer
/// that is unchanged costs no command, so a periodic re-poll of a stable
/// tailnet is silent here.
///
/// `RemovePeer` is keyed by the old disco key. A peer whose disco key rotated
/// gets the old one removed first, otherwise the stale key would stay allowed
/// (and keep passing the node-key pairing check) until evicted by capacity.
#[inline(never)]
async fn sync_disco_allowlist(
    known: &mut heapless::Vec<PeerSnap, 8>,
    map: &tm_control::MapState,
    disco_tx: &async_channel::Sender<DiscoCmd>,
) {
    for old in known.iter() {
        if !map.peers.iter().any(|p| p.node_key == old.node_key) {
            info!("Runtime::join() - peer {:02x}{:02x}.. left the netmap; removing it from the disco allowlist", old.node_key[0], old.node_key[1]);
            let _ = disco_tx.send(DiscoCmd::RemovePeer(old.disco_key)).await;
        }
    }
    for p in map.peers.iter() {
        match known.iter().find(|o| o.node_key == p.node_key) {
            Some(o) if o.disco_key == p.disco_key => continue,
            Some(o) => {
                info!("Runtime::join() - peer {:02x}{:02x}.. rotated its disco key", p.node_key[0], p.node_key[1]);
                let _ = disco_tx.send(DiscoCmd::RemovePeer(o.disco_key)).await;
            }
            None => {}
        }
        let _ = disco_tx.send(DiscoCmd::AllowPeer { disco_key: p.disco_key, node_key: p.node_key }).await;
    }
    known.clear();
    for p in map.peers.iter() {
        let _ = known.push(PeerSnap { node_key: p.node_key, disco_key: p.disco_key });
    }
}

/// Rebuild the MagicDNS name table from a netmap. Out of the router's frame so
/// its table temporary does not grow `event_router_task`'s poll state.
#[inline(never)]
fn install_map_names(map: &tm_control::MapState) {
    use tm_netstack::names::NameTable;
    let n = &map.names;
    let mut table = NameTable::new();
    table.set_domain(n.suffix.as_str(), n.proxied);
    table.insert(n.self_label.as_str(), map.our_ip.0);
    for p in map.peers.iter() {
        // A node shared in from another tailnet has a different suffix and is
        // not answerable under ours.
        if p.name.suffix_hash == n.suffix_hash {
            table.insert(p.name.label.as_str(), p.tailnet_ip.0);
        }
    }
    info!("Runtime::join() - MagicDNS table: {} names, suffix '{}', proxied={}",
        table.len(), n.suffix.as_str(), n.proxied);
    tm_netstack::names::install(table);
}

async fn event_router_task(
    ctrl_ev_rx: async_channel::Receiver<ControlEvent>,
    derp_ev_rx: async_channel::Receiver<DerpEvent>,
    disco_ev_rx: async_channel::Receiver<DiscoEvent>,
    wg_ev_rx: async_channel::Receiver<WgEvent>,
    mut netif_out_rx: tailnet::OutboundReceiver,
    ctrl_tx3: async_channel::Sender<ControlCmd>,
    derp_tx2: async_channel::Sender<DerpCmd>,
    wg_tx2: async_channel::Sender<WgCmd>,
    disco_tx2: async_channel::Sender<DiscoCmd>,
    our_ip_tx: Option<OurIpSender>,
    mut netif_out_tx: Option<tailnet::OutboundSender>,
) {
    info!("Runtime::join() - event_router task started");
    tm_wg::heapdiag::install_alloc_failed_dump();
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
    // Peers of the previous snapshot, to diff the next one against.
    let mut known_peers: heapless::Vec<PeerSnap, 8> = heapless::Vec::new();
    let mut last_miss_refresh: Option<std::time::Instant> = None;
    // Belt-and-suspenders for the DERP reconnect fix (2026-09): DerpActor now
    // redials its own last target with backoff on a connection error, but
    // keeping the last-known-good target here too costs nothing and gives a
    // second, independent path back onto the data plane if a future change
    // to the actor's redial logic regresses -- see DerpEvent::Disconnected
    // below.
    let mut last_derp_target: Option<(heapless::String<64>, u16)> = None;
    // Last send path logged per peer; see `log_path_change`.
    #[cfg(feature = "lan-direct")]
    let mut last_via: heapless::Vec<([u8; 32], Option<std::net::SocketAddrV4>), 8> = heapless::Vec::new();
    #[cfg(feature = "latency-trace")]
    let mut lat = LatState::new();
    let mut ctrl_ev_rx = core::pin::pin!(ctrl_ev_rx);
    let mut derp_ev_rx = core::pin::pin!(derp_ev_rx);
    let mut disco_ev_rx = core::pin::pin!(disco_ev_rx);
    let mut wg_ev_rx = core::pin::pin!(wg_ev_rx);
    let mut netif_out_rx = core::pin::pin!(netif_out_rx);
    #[cfg(target_os = "espidf")]
    let mut ry = RouterYield::new();
    loop {
        #[cfg(target_os = "espidf")]
        ry.tick().await;
        #[cfg(feature = "latency-trace")]
        lat.on_iter();
        tokio::select! {
            evt = tm_buf::chan::recv_next(ctrl_ev_rx.as_mut()) => {
                match evt {
                    Ok(evt) => match evt {
                        ControlEvent::MapUpdate(map) => {
                            // Rung-3 evidence: MapResponse parsed, peers + DERPMap seen.
                            info!("Runtime::join() - MapUpdate: {} peers, {} DERP regions, our_ip={}.{}.{}.{}",
                                map.peers.len(), map.derp_regions.len(),
                                map.our_ip.0[0], map.our_ip.0[1], map.our_ip.0[2], map.our_ip.0[3]);
                            install_map_names(map.as_ref());
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
                                    last_derp_target = Some((region.host.clone(), port));
                                    let _ = derp_tx2.send(DerpCmd::Connect {
                                        host: region.host.clone(),
                                        port,
                                        cert_fingerprint: None,
                                    }).await;
                                    #[cfg(target_os = "espidf")]
                                    ry.tick().await;
                                }
                                // Bug 2 fix: keep tm_disco's peer allowlist in
                                // sync with the netmap. Without this, every
                                // inbound PING is dropped by `DiscoActor::process`
                                // (the allowlist gate) because nothing outside
                                // tm_disco's own tests ever populated it --
                                // `tailscale ping` against this node could never
                                // succeed. Also tell tm_disco our current home
                                // region, needed to fill a PONG's src_ipport
                                // (the `127.3.3.40:<region>` DERP-relay
                                // convention) with something meaningful.
                                let _ = disco_tx2.send(DiscoCmd::SetHomeRegion(rid)).await;
                                #[cfg(target_os = "espidf")]
                                ry.tick().await;
                            }
                            // Keep tm_disco's allowlist equal to this snapshot:
                            // AllowPeer for new peers (Step 1 of the LAN-direct
                            // plan: it carries both keys so a UDP PING's claimed
                            // node key can be checked against the real pairing),
                            // RemovePeer for gone ones, both for a re-keyed one.
                            sync_disco_allowlist(&mut known_peers, map.as_ref(), &disco_tx2).await;
                            #[cfg(target_os = "espidf")]
                            ry.tick().await;
                            #[cfg(feature = "lan-direct")]
                            last_via.retain(|(k, _)| map.peers.iter().any(|p| p.node_key == *k));
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
                                ry.tick().await;
                                let _ = tx.send(ip.to_ipv4()).await;
                            }
                        }
                        ControlEvent::KeyExpiry => {
                            let _ = ctrl_tx3.send(ControlCmd::Reauth).await;
                            #[cfg(target_os = "espidf")]
                            ry.tick().await;
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
            evt = tm_buf::chan::recv_next(derp_ev_rx.as_mut()) => {
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
                            // one buffer type (tm_buf::PktBuf), so there is
                            // no copy into a differently-sized re-box here.
                            // (tm_disco bounds the disco ciphertext itself.)
                            if is_disco {
                                // Bug 2 fix: forward the peer's real DERP
                                // frame sender (their node key) instead of
                                // the placeholder `[0; 4]` -- without it,
                                // `DiscoActor` has no way to address a PONG
                                // back to the peer over DERP (DERP routes by
                                // node key, not IP). Step 1 (LAN-direct-path
                                // plan): `MaybeDisco` now carries a
                                // `DiscoSrc` distinguishing DERP from direct
                                // UDP; this router only ever sees DERP frames
                                // today (Step 2 adds a UDP receive loop).
                                forward_or_drop(&disco_tx2, DiscoCmd::MaybeDisco {
                                    src: tm_disco::DiscoSrc::Derp { node_key: *src_key.as_bytes() },
                                    data: payload,
                                }, "DiscoCmd::MaybeDisco");
                                #[cfg(target_os = "espidf")]
                                ry.tick().await;
                            } else {
                                forward_or_drop(&wg_tx2, WgCmd::InboundPacket {
                                    via: tm_wg::Via::Derp { src_key: *src_key.as_bytes() },
                                    payload,
                                }, "WgCmd::InboundPacket");
                                #[cfg(target_os = "espidf")]
                                ry.tick().await;
                            }
                        }
                        DerpEvent::Connected => {
                            tracing::debug!("DERP connected");
                        }
                        DerpEvent::PingReceived => {}
                        DerpEvent::Disconnected => {
                            // Raised from debug to info (2026-09 DERP-reconnect
                            // fix): a DERP drop used to be visible only in
                            // debug builds. DerpActor itself now redials with
                            // backoff; this is a belt-and-suspenders nudge in
                            // case that ever regresses -- re-sending the same
                            // last-known-good Connect target here is harmless
                            // even while the actor is already redialing on its
                            // own (a repeat Connect to an already-connecting
                            // actor is a no-op).
                            if let Some((host, port)) = last_derp_target.clone() {
                                info!("Runtime::join() - DERP disconnected; nudging reconnect to {}:{}", host.as_str(), port);
                                let _ = derp_tx2.send(DerpCmd::Connect {
                                    host,
                                    port,
                                    cert_fingerprint: None,
                                }).await;
                            } else {
                                info!("Runtime::join() - DERP disconnected (no known target yet)");
                            }
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
            evt = tm_buf::chan::recv_next(wg_ev_rx.as_mut()) => {
                match evt {
                    // `via` is tm_wg's trusted direct path for this peer
                    // (`WgEndpoint::path_for`), or None for DERP.
                    Ok(WgEvent::OutboundPacket { dst_key, payload, via }) => {
                        #[cfg(feature = "latency-trace")]
                        let icmp_reply = lat.take_icmp_reply(payload.len());
                        // Handshakes, keepalives and transport data leave
                        // tm_wg here. With lan-direct, a trusted direct path
                        // goes out the LAN socket and any send error puts the
                        // same buffer on DERP instead; everything else goes
                        // to DERP exactly as before.
                        #[cfg(feature = "lan-direct")]
                        log_path_change(&mut last_via, &dst_key, via);
                        #[cfg(feature = "lan-direct")]
                        let payload = match via {
                            Some(addr) => match send_wg_direct(addr, payload) {
                                Ok(()) => None,
                                Err(p) => Some(p),
                            },
                            None => Some(payload),
                        };
                        #[cfg(feature = "latency-trace")]
                        if icmp_reply {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::UdpTxWg);
                            lat.report("icmp", &tm_buf::lat::ICMP_CHAIN, via.is_some());
                        }
                        #[cfg(not(feature = "lan-direct"))]
                        let payload = { let _ = via; Some(payload) };
                        if let Some(payload) = payload {
                            trace!("Runtime::join() - WgEvent::OutboundPacket {} bytes -> DERP peer {:02x}{:02x}..", payload.len(), dst_key[0], dst_key[1]);
                            // Forward tm_wg's buffer to DERP as-is (same
                            // tm_buf::PktBuf type on both channels): no copy.
                            forward_or_drop(&derp_tx2, DerpCmd::SendPacket {
                                dst_key: NodePublicKey::from_bytes(dst_key),
                                payload,
                            }, "DerpCmd::SendPacket");
                        }
                        #[cfg(target_os = "espidf")]
                        ry.tick().await;
                    }
                    Ok(WgEvent::InboundDecrypted { src_key, payload }) => {
                        // Decrypted inbound app data destined for the local
                        // netstack. Handed to the on-device lwIP tailnet
                        // netif (plan (a), docs/tailnet-http-lwip-netif-plan.md
                        // item 5) via `tcpip_input()`, which is safe to call
                        // from this (non-tcpip) task -- see
                        // tm_netstack::tailnet's module doc comment.
                        trace!("Runtime::join() - WgEvent::InboundDecrypted {} bytes from peer {:02x}{:02x}..", payload.len(), src_key[0], src_key[1]);
                        #[cfg(target_os = "espidf")]
                        if tm_wg::heapdiag::ENABLED { unsafe {
                            let pool = tm_buf::stats();
                            debug!("Runtime::join() - heap after inbound-decrypted (before inject_inbound): total_free={} largest_internal={} largest_default={} pktbuf_pool: free={} allocs={} frees={}",
                                esp_idf_sys::esp_get_free_heap_size(),
                                esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL),
                                esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT),
                                pool.free, pool.allocs, pool.frees);
                        } }
                        let echo_req = tm_buf::lat::ENABLED && tm_buf::lat::is_icmp_echo(payload.as_slice(), 8);
                        if echo_req {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::RouterInbound);
                        }
                        let w = tm_wg::heapdiag::trace_begin("router: before inject_inbound");
                        let inj = tailnet::inject_inbound(payload.as_slice());
                        tm_wg::heapdiag::trace_end(w, "router: after inject_inbound");
                        if echo_req {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::Injected);
                        }
                        match inj {
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
                                if let Some(buf) = tm_buf::PktBuf::from_slice(&echo) {
                                    forward_or_drop(&wg_tx2, WgCmd::SendData {
                                        dst_key: key,
                                        payload: buf,
                                    }, "WgCmd::SendData");
                                    #[cfg(target_os = "espidf")]
                                    ry.tick().await;
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
            evt = tm_buf::chan::recv_next(disco_ev_rx.as_mut()) => {
                match evt {
                    Ok(DiscoEvent::SendPong { dst_node_key, payload }) => {
                        // Bug 2 fix: `tm_disco` now hands back a fully
                        // sealed, wire-ready PONG datagram (magic ||
                        // our_disco_pub || nonce || SalsaBox(...)) -- this
                        // used to be logged and dropped ("[not relayed: DERP
                        // stub]"), stale wording from before the DERP relay
                        // existed. Forward it to the peer over DERP exactly
                        // like any other outbound payload: DERP routes by
                        // node key, which `tm_disco` now receives from the
                        // router (see `DerpEvent::PacketReceived` above)
                        // instead of the placeholder `[0; 4]`.
                        info!("Runtime::join() - DiscoEvent::SendPong -> DERP peer {:02x}{:02x}..", dst_node_key[0], dst_node_key[1]);
                        if let Some(buf) = tm_buf::PktBuf::from_slice(&payload) {
                            forward_or_drop(&derp_tx2, DerpCmd::SendPacket {
                                dst_key: NodePublicKey::from_bytes(dst_node_key),
                                payload: buf,
                            }, "DerpCmd::SendPacket");
                            #[cfg(target_os = "espidf")]
                            ry.tick().await;
                        } else {
                            warn!("Runtime::join() - sealed PONG ({} bytes) did not fit tm_buf::PktBuf; dropped", payload.len());
                        }
                    }
                    Ok(DiscoEvent::SendPongUdp { dst, payload }) => {
                        // tm_disco authenticated a UDP PING (disco key on the
                        // netmap allowlist, node key matching its pairing) and
                        // sealed a PONG for the address it came from. Reply
                        // from the same socket, which is what lets the peer
                        // trust this path (plan D2).
                        tm_buf::lat::stamp(tm_buf::lat::Hop::RouterPong);
                        #[cfg(feature = "lan-direct")]
                        send_pong_direct(dst, &payload);
                        #[cfg(feature = "latency-trace")]
                        {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::UdpTxPong);
                            lat.report("disco", &tm_buf::lat::DISCO_CHAIN, true);
                        }
                        #[cfg(not(feature = "lan-direct"))]
                        { let _ = (dst, payload); }
                    }
                    Ok(DiscoEvent::DirectPathSeen { node_key, addr }) => {
                        // See `DISCO_PING_SETS_SEND_PATH` for why this is
                        // switchable. tm_wg also adopts the path on its own
                        // from authenticated UDP WireGuard.
                        #[cfg(feature = "lan-direct")]
                        if DISCO_PING_SETS_SEND_PATH {
                            forward_or_drop(&wg_tx2, WgCmd::DirectPathSeen { node_key, addr }, "WgCmd::DirectPathSeen");
                        }
                        trace!("Runtime::join() - DiscoEvent::DirectPathSeen peer {:02x}{:02x}.. at {}", node_key[0], node_key[1], addr);
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
            pkt = tm_buf::chan::recv_next(netif_out_rx.as_mut()) => {
                match pkt {
                    Ok(tailnet::OutboundPacket { dst_ip, data }) => {
                        #[cfg(feature = "latency-trace")]
                        if tm_buf::lat::is_icmp_echo(data.as_slice(), 0) {
                            tm_buf::lat::stamp(tm_buf::lat::Hop::RouterNetif);
                            lat.icmp_reply_pending = true;
                        }
                        if let Some((_, dst_key)) = ip_to_key.iter().find(|(ip, _)| *ip == dst_ip) {
                            forward_or_drop(&wg_tx2, WgCmd::SendData {
                                dst_key: *dst_key,
                                payload: data,
                            }, "WgCmd::SendData");
                            #[cfg(target_os = "espidf")]
                            ry.tick().await;
                        } else {
                            log_unknown_netif_dest(dst_ip, &mut last_unknown_dst);
                            request_refresh_on_miss(&ctrl_tx3, &mut last_miss_refresh, std::time::Instant::now());
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

/// Capacity of the `WgCmd` channel (router -> WG actor). Step 11 of
/// ALLOCATIONS.md widened it to 4 because the router's `forward_or_drop`
/// lost inbound packets when it was full. Since Step 12 the UDP receive
/// task, which carries most inbound WireGuard packets, waits for room
/// instead of going through a drop (`lan_udp::forward_backpressured`), and
/// at 2 the back-to-back connect stall stayed fixed, so it is back to
/// `CHAN_CAP`. Kept as its own constant to tune from the router's
/// "channel full" drop counters.
const WG_CMD_CHAN_CAP: usize = 2;

/// Capacity of the tailnet netif outbound channel (lwIP tcpip thread ->
/// router), wider than `CHAN_CAP`. The producer is lwIP's `output` callback,
/// which runs on the tcpip thread and cannot wait, so a full channel is a
/// lost outbound TCP segment (`tailnet::OUTBOUND_DROPS`). The tcpip thread
/// (priority 18) emits a connection's SYN-ACK, ACKs, response and FIN in
/// bursts faster than the router (priority 1, one event per iteration)
/// drains them; at 2 slots about one packet per back-to-back HTTP
/// connection was lost, and a lost SYN-ACK costs the client a ~1 s SYN
/// retransmit (ALLOCATIONS.md Step 12). The slots hold a small
/// `OutboundPacket` by value; the bytes are in `tm_buf`. Past
/// `tailnet::OUTBOUND_HEAP_DEPTH` queued packets, the callback queues only
/// pool buffers, so the extra depth never holds heap-fallback buffers.
const NETIF_OUT_CHAN_CAP: usize = 8;

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
    /// Actor/channel construction for `connect`.
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

        let (wg_tx,    wg_rx)    = async_channel::bounded::<WgCmd>(WG_CMD_CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after WgCmd channel");

        let (wg_ev_tx, wg_ev_rx) = async_channel::bounded::<WgEvent>(CHAN_CAP);
        tokio_freertos_yield().await;
        log_heap("after WgEvent channel");

        // Tailnet netif outbound-packet channel (plan (a) item 3): packets
        // lwIP's netif `output` callback wants sent out the tailnet
        // interface, drained by `event_router_task` and routed to a
        // WireGuard peer. Wider than `CHAN_CAP`; see `NETIF_OUT_CHAN_CAP`.
        let (netif_out_tx, netif_out_rx) = async_channel::bounded::<tailnet::OutboundPacket>(NETIF_OUT_CHAN_CAP);
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
        // LAN-direct (Step 2): bind before the control actor exists, hence
        // before the DERP TLS handshake it eventually triggers.
        #[cfg(feature = "lan-direct")]
        let udp_task: BoxActorFut = match bind_lan_udp() {
            Some(sock) => {
                // Control derives the LAN endpoint from the actual bound
                // port, which is not 41641 if bind_lan fell back to port 0.
                config.control.lan_udp_port = sock.local_addr().ok().map(|a| a.port());
                spawn_udp(sock, disco_tx.clone(), wg_tx.clone())
            }
            None => Box::pin(async {}),
        };
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
            #[cfg(not(feature = "lan-direct"))]
            tokio::join!(
                control_task,
                derp_task,
                disco_task,
                wg_task,
                event_router,
            );
            #[cfg(feature = "lan-direct")]
            tokio::join!(
                control_task,
                derp_task,
                disco_task,
                wg_task,
                event_router,
                udp_task,
            );
            tracing::debug!("Runtime - all actor tasks completed");
        });

        (Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }, driver)
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

    /// A miss queues one `Refresh`, further misses inside the gap queue
    /// nothing, and a full control queue is not an error and does not start
    /// the gap (the next miss may retry).
    #[test]
    fn miss_refresh_is_rate_limited_and_never_blocks() {
        let (tx, rx) = async_channel::bounded::<ControlCmd>(1);
        let t0 = std::time::Instant::now();
        let mut last = None;
        assert!(request_refresh_on_miss(&tx, &mut last, t0));
        assert!(matches!(rx.try_recv(), Ok(ControlCmd::Refresh)));
        assert!(!request_refresh_on_miss(&tx, &mut last, t0 + core::time::Duration::from_secs(119)));
        assert!(rx.try_recv().is_err());
        assert!(request_refresh_on_miss(&tx, &mut last, t0 + MISS_REFRESH_GAP));
        // Queue full (the Refresh above was not drained): dropped, gap not restarted.
        let gap_start = last;
        assert!(!request_refresh_on_miss(&tx, &mut last, t0 + MISS_REFRESH_GAP * 2));
        assert_eq!(last, gap_start);
    }

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

    // ── Router: later snapshots change routing, allowlist, WG and names ──────

    fn key32(seed: u8) -> [u8; 32] { [seed; 32] }

    fn peer(seed: u8, disco: u8, label: &str, hash: u16) -> tm_control::PeerInfo {
        let mut name = tm_control::PeerName::default();
        name.label.push_str(label).unwrap();
        name.suffix_hash = hash;
        tm_control::PeerInfo {
            node_key: key32(seed),
            disco_key: key32(disco),
            tailnet_ip: tm_control::TailnetIp([100, 64, 0, seed]),
            prefix_len: 32,
            hostname: heapless::String::new(),
            name,
            derp_region: 1,
            is_online: true,
        }
    }

    fn snapshot(peers: &[tm_control::PeerInfo], hash: u16) -> ControlEvent {
        let mut m = tm_control::MapState {
            our_ip: tm_control::TailnetIp([100, 64, 0, 1]),
            peers: Default::default(),
            derp_regions: Default::default(),
            names: Default::default(),
        };
        m.names.self_label.push_str("me").unwrap();
        m.names.suffix.push_str("tn.ts.net").unwrap();
        m.names.suffix_hash = hash;
        m.names.proxied = true;
        for p in peers { m.peers.push(p.clone()); }
        ControlEvent::MapUpdate(Box::new(m))
    }

    async fn within<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(core::time::Duration::from_secs(5), f).await.expect("router did not respond")
    }

    /// A MapUpdate after the first one must: allow and route a peer that
    /// joined late (allowlist, `ip_to_key`, WG snapshot, MagicDNS), and for a
    /// peer that left, send `RemovePeer` with its disco key, stop routing its
    /// address (a lookup miss asks control for a refresh) and drop its name.
    /// A re-keyed peer swaps its disco key; an unchanged snapshot sends no
    /// disco command at all.
    #[tokio::test(flavor = "current_thread")]
    async fn later_snapshots_add_remove_and_rekey_peers() {
        let hash = tm_control::suffix_hash("tn.ts.net");
        let (ctrl_ev_tx, ctrl_ev_rx) = async_channel::bounded::<ControlEvent>(2);
        let (_derp_ev_tx, derp_ev_rx) = async_channel::bounded::<DerpEvent>(2);
        let (_disco_ev_tx, disco_ev_rx) = async_channel::bounded::<DiscoEvent>(2);
        let (_wg_ev_tx, wg_ev_rx) = async_channel::bounded::<WgEvent>(2);
        let (netif_tx, netif_rx) = async_channel::bounded::<tailnet::OutboundPacket>(8);
        let (ctrl_tx, ctrl_rx) = async_channel::bounded::<ControlCmd>(4);
        let (derp_tx, _derp_rx) = async_channel::bounded::<DerpCmd>(8);
        let (wg_tx, wg_rx) = async_channel::bounded::<WgCmd>(16);
        let (disco_tx, disco_rx) = async_channel::bounded::<DiscoCmd>(16);

        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
            let router = tokio::task::spawn_local(event_router_task(
                ctrl_ev_rx, derp_ev_rx, disco_ev_rx, wg_ev_rx, netif_rx,
                ctrl_tx, derp_tx, wg_tx, disco_tx, None, None,
            ));

            // The WG ApplyMap is sent after every disco command of a snapshot,
            // so once it arrives the disco queue holds that snapshot's commands.
            async fn applied(wg_rx: &async_channel::Receiver<WgCmd>) -> Vec<[u8; 32]> {
                match within(wg_rx.recv()).await.unwrap() {
                    WgCmd::ApplyMap(m) => m.peers.iter().map(|p| p.node_key).collect(),
                    _ => panic!("expected ApplyMap"),
                }
            }
            fn disco_cmds(rx: &async_channel::Receiver<DiscoCmd>) -> Vec<(&'static str, [u8; 32])> {
                let mut v = Vec::new();
                while let Ok(c) = rx.try_recv() {
                    match c {
                        DiscoCmd::AllowPeer { disco_key, .. } => v.push(("allow", disco_key)),
                        DiscoCmd::RemovePeer(k) => v.push(("remove", k)),
                        DiscoCmd::SetHomeRegion(_) => {}
                        _ => panic!("unexpected disco command"),
                    }
                }
                v
            }
            async fn send_to(tx: &async_channel::Sender<tailnet::OutboundPacket>, ip: u8) {
                tx.send(tailnet::OutboundPacket { dst_ip: [100, 64, 0, ip], data: tm_buf::PktBuf::from_slice(&[0u8; 20]).unwrap() }).await.unwrap();
            }
            async fn routed_to(wg_rx: &async_channel::Receiver<WgCmd>) -> [u8; 32] {
                match within(wg_rx.recv()).await.unwrap() {
                    WgCmd::SendData { dst_key, .. } => dst_key,
                    _ => panic!("expected SendData"),
                }
            }

            let a = peer(2, 12, "alpha", hash);
            let b = peer(3, 13, "bravo", hash);
            let c = peer(4, 14, "charlie", hash);

            // 1. First snapshot: A and B.
            ctrl_ev_tx.send(snapshot(&[a.clone(), b.clone()], hash)).await.unwrap();
            assert_eq!(applied(&wg_rx).await, vec![key32(2), key32(3)]);
            assert_eq!(disco_cmds(&disco_rx), vec![("allow", key32(12)), ("allow", key32(13))]);
            send_to(&netif_tx, 3).await;
            assert_eq!(routed_to(&wg_rx).await, key32(3));
            assert_eq!(tm_netstack::names::resolve("bravo.tn.ts.net"), Some([100, 64, 0, 3].into()));

            // 2. B left, C joined late.
            ctrl_ev_tx.send(snapshot(&[a.clone(), c.clone()], hash)).await.unwrap();
            assert_eq!(applied(&wg_rx).await, vec![key32(2), key32(4)]);
            assert_eq!(disco_cmds(&disco_rx), vec![("remove", key32(13)), ("allow", key32(14))],
                "RemovePeer carries the removed peer's disco key; only the new peer is allowed");
            send_to(&netif_tx, 3).await; // B's old address: no route any more
            send_to(&netif_tx, 4).await; // C: routable
            assert_eq!(routed_to(&wg_rx).await, key32(4), "B's address must not route; C's must");
            assert!(matches!(ctrl_rx.try_recv(), Ok(ControlCmd::Refresh)), "a miss asks control for a refresh");
            assert_eq!(tm_netstack::names::resolve("bravo.tn.ts.net"), None, "removed peer's name is gone");
            assert_eq!(tm_netstack::names::resolve("charlie.tn.ts.net"), Some([100, 64, 0, 4].into()), "new peer resolves");

            // 3. A rotates its disco key: old removed, new allowed.
            let a2 = peer(2, 22, "alpha", hash);
            ctrl_ev_tx.send(snapshot(&[a2.clone(), c.clone()], hash)).await.unwrap();
            applied(&wg_rx).await;
            assert_eq!(disco_cmds(&disco_rx), vec![("remove", key32(12)), ("allow", key32(22))]);

            // 4. Nothing changed: the allowlist is not touched.
            ctrl_ev_tx.send(snapshot(&[a2, c], hash)).await.unwrap();
            applied(&wg_rx).await;
            assert!(disco_cmds(&disco_rx).is_empty());

            drop(ctrl_ev_tx);
            let _ = within(router).await;
        }).await;
    }
}
