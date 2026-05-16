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
use log::{info, debug, warn, error};
use async_channel;

/// FreeRTOS yield function for ESP32-C3 watchdog servicing.
/// Calls `vTaskDelay(50)` to yield the CPU and service the watchdog timer.
#[cfg(target_os = "espidf")]
pub fn freertos_yield() {
    unsafe { esp_idf_sys::vTaskDelay(50) };
}

#[cfg(target_os = "espidf")]
use esp_idf_sys;

/// Channel capacity for all inter-actor queues.
/// Small = bounded memory, back-pressure propagates naturally.
/// Reduced from 4 to 2 to save memory on ESP32-C3.
const CHAN_CAP: usize = 2;

#[cfg(target_os = "espidf")]
use esp_idf_svc::tls::{EspTls, InternalSocket};

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
    /// Cached TLS instance for reuse (ESP32-C3 only).
    #[cfg(target_os = "espidf")]
    pub cached_tls:    Option<EspTls<InternalSocket>>,
    /// Channel to receive the assigned Tailnet IP address.
    #[cfg(target_os = "espidf")]
    pub our_ip_tx:     Option<OurIpSender>,
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
        
        // ── Log heap before channel allocation ──────────────────────────────────
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                let free_all = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_SPIRAM | esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT);
                tracing::debug!("Runtime::join() - heap before channel allocation: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default, {} bytes total largest", free_internal, free_8bit, free_default, free_all);
            }
        }
        
        tracing::debug!("Runtime::join() - allocating ControlCmd channel");
        #[cfg(target_os = "espidf")]
        freertos_yield();
        let (ctrl_tx,  ctrl_rx)  = async_channel::bounded::<ControlCmd>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after ControlCmd channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }
        tracing::debug!("Runtime::join() - allocating ControlEvent channel");
        let (ctrl_ev_tx, mut ctrl_ev_rx) = async_channel::bounded::<ControlEvent>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after ControlEvent channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating DerpCmd channel");
        let (derp_tx,  derp_rx)  = async_channel::bounded::<DerpCmd>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DerpCmd channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating DerpEvent channel");
        let (derp_ev_tx, mut derp_ev_rx) = async_channel::bounded::<DerpEvent>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DerpEvent channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating DiscoCmd channel");
        let (disco_tx, disco_rx) = async_channel::bounded::<DiscoCmd>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DiscoCmd channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating DiscoEvent channel");
        let (_disco_ev_tx, mut _disco_ev_rx) = async_channel::bounded::<DiscoEvent>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DiscoEvent channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating WgCmd channel");
        let (wg_tx,    wg_rx)    = async_channel::bounded::<WgCmd>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after WgCmd channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - allocating WgEvent channel");
        let (_wg_ev_tx, mut _wg_ev_rx) = async_channel::bounded::<WgEvent>(CHAN_CAP);
        #[cfg(target_os = "espidf")]
        freertos_yield();

        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after WgEvent channel: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        let our_pub = config.node_state.node_key.public();
        tracing::debug!("Runtime::join() - node key extracted (32 bytes)");
        let disco_key = config.node_state.disco_key.clone();
        tracing::debug!("Runtime::join() - disco key extracted (32 bytes)");
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap before ControlActor: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - creating ControlActor");
        #[cfg(target_os = "espidf")]
        let control_actor = if let Some(cached_tls) = config.cached_tls.take() {
            tracing::debug!("Runtime::join() - ControlActor: using cached TLS");
            ControlActor::new_with_tls(config.control, config.node_state, cached_tls)
        } else {
            tracing::debug!("Runtime::join() - ControlActor: no cached TLS");
            ControlActor::new(config.control, config.node_state)
        };
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after ControlActor: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        #[cfg(not(target_os = "espidf"))]
        let control_actor = ControlActor::new(config.control, config.node_state);

        tracing::debug!("Runtime::join() - creating DerpActor");
        let derp_actor = DerpActor::new(our_pub);
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DerpActor: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - creating DiscoActor");
        let disco_actor = DiscoActor::new(disco_key);
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after DiscoActor: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - creating WgActor");
        let wg_actor = WgActor::new(config.priority_peer);
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap after WgActor: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - cloning sender channels");
        let ctrl_tx3 = ctrl_tx.clone();
        let ctrl_tx4 = ctrl_tx.clone();
        let derp_tx2  = derp_tx.clone();
        let wg_tx2    = wg_tx.clone();
        let disco_tx2 = disco_tx.clone();

        info!("Runtime::join() - creating event_router task");
        let event_router = async move {
            info!("Runtime::join() - event_router task started");
            loop {
                #[cfg(target_os = "espidf")]
                freertos_yield();
                tokio::select! {
                    evt = ctrl_ev_rx.recv() => {
                        match evt {
                            Ok(evt) => match evt {
                                ControlEvent::MapUpdate(map) => {
                                    info!("Runtime::join() - received ControlEvent::MapUpdate");
                                    let _ = wg_tx2.send(WgCmd::ApplyMap(map)).await;
                                }
                                ControlEvent::OurIpAssigned(ip) => {
                                    info!("Runtime::join() - received ControlEvent::OurIpAssigned: {}.{}.{}.{}", ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
                                    #[cfg(target_os = "espidf")]
                                    if let Some(ref tx) = config.our_ip_tx {
                                        #[cfg(target_os = "espidf")]
                                        freertos_yield();
                                        let _ = tx.send(ip.to_ipv4()).await;
                                    }
                                }
                                ControlEvent::KeyExpiry => {
                                    let _ = ctrl_tx3.send(ControlCmd::Reauth).await;
                                    #[cfg(target_os = "espidf")]
                                    freertos_yield();
                                }
                                ControlEvent::Error(e) => {
                                    error!("Runtime::join() - received ControlEvent::Error: {:?}", e);
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
                                    if !payload.is_empty() && payload[0] == 0x6d {
                                        let mut data = heapless::Vec::new();
                                        let _ = data.extend_from_slice(&payload);
                                        let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                            src_ip:   [0; 4],
                                            src_port: 0,
                                            data,
                                        }).await;
                                        #[cfg(target_os = "espidf")]
                                        freertos_yield();
                                    } else {
                                        let mut pkt = heapless::Vec::new();
                                        let _ = pkt.extend_from_slice(&payload);
                                        let _ = wg_tx2.send(WgCmd::InboundPacket {
                                            src_key: *src_key.as_bytes(),
                                            payload: pkt,
                                        }).await;
                                        #[cfg(target_os = "espidf")]
                                        freertos_yield();
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
                                    error!("Runtime::join() - received DerpEvent::Error: {:?}", e);
                                }
                            }
                            Err(_) => {
                                info!("Runtime::join() - derp event channel closed, breaking");
                                break;
                            }
                        }
                    }
                }
            }
            info!("Runtime::join() - event_router task exiting");
        };

        tracing::debug!("Runtime::join() - preparing actor tasks");
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        let control_task = control_actor.run(ctrl_rx, ctrl_ev_tx);
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        let derp_task = derp_actor.run(derp_rx, derp_ev_tx);
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        let disco_task = disco_actor.run(disco_rx, _disco_ev_tx);
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        let wg_task = wg_actor.run(wg_rx, _wg_ev_tx);
        #[cfg(target_os = "espidf")]
        freertos_yield();
        
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                let free_internal = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
                let free_8bit = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT);
                let free_default = esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_DEFAULT);
                tracing::debug!("Runtime::join() - heap before tokio::join!: {} bytes contiguous internal, {} bytes contiguous 8bit, {} bytes contiguous default", free_internal, free_8bit, free_default);
            }
        }

        tracing::debug!("Runtime::join() - sending ControlCmd::Start");
        #[cfg(target_os = "espidf")]
        freertos_yield();
        let _ = ctrl_tx4.send(ControlCmd::Start { auth_key: config.auth_key.clone() }).await;
        #[cfg(target_os = "espidf")]
        freertos_yield();

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

    /// Deprecated: use Runtime::join instead for ESP32-C3.
    ///
    /// This method uses tokio::spawn which allocates heap for each task.
    /// For memory-constrained ESP32-C3, use Runtime::join instead.
    #[cfg(not(target_os = "espidf"))]
    #[deprecated(note = "Use Runtime::join for ESP32-C3 to avoid task heap allocations")]
    pub async fn spawn(config: RuntimeConfig) -> Self {
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

        let control_actor = ControlActor::new(config.control, config.node_state);
        tokio::spawn(control_actor.run(ctrl_rx, ctrl_ev_tx));

        let derp_actor = DerpActor::new(our_pub);
        tokio::spawn(derp_actor.run(derp_rx, derp_ev_tx));

        let disco_actor = DiscoActor::new(disco_key);
        tokio::spawn(disco_actor.run(disco_rx, _disco_ev_tx));

        let wg_actor = WgActor::new(config.priority_peer);
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
                    }
                    evt = derp_ev_rx.recv() => {
                        match evt {
                            DerpEvent::PacketReceived { src_key, payload } => {
                                // Distinguish DISCO vs WireGuard by first byte
                                if !payload.is_empty() && payload[0] == 0x6d {
                                    // DISCO magic prefix (simplified check)
                                    let mut data = heapless::Vec::new();
                                    let _ = data.extend_from_slice(&payload);
                                    let _ = disco_tx2.send(DiscoCmd::MaybeDisco {
                                        src_ip:   [0; 4],  // from DERP src
                                        src_port: 0,
                                        data,
                                    }).await;
                                } else {
                                    // WireGuard packet
                                    let mut pkt = heapless::Vec::new();
                                    let _ = pkt.extend_from_slice(&payload);
                                    let _ = wg_tx2.send(WgCmd::InboundPacket {
                                        src_key: *src_key.as_bytes(),
                                        payload: pkt,
                                    }).await;
                                }
                            }
                            DerpEvent::Connected => {
                                tracing::debug!("DERP connected");
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Start the control actor by sending a Start command (via clone)
        let _ = ctrl_tx4.send(ControlCmd::Start { auth_key: config.auth_key.clone() }).await;

        Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }
    }
}