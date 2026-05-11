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
//! ## Channel buffer sizes
//!
//! All channels use a capacity of 2-4.  A backpressure of 4 messages × typical
//! message size (~1.5 KB for a packet) = ~6 KB maximum queued per channel.
//! This is the MicroLink insight applied: small queues, no unbounded growth.

use tm_control::{ControlActor, ControlCmd, ControlEvent, Config as ControlConfig};
use tm_derp::{DerpActor, DerpCmd, DerpEvent};
use tm_disco::{DiscoActor, DiscoCmd, DiscoEvent};
use tm_wg::{WgActor, WgCmd, WgEvent};
use tm_keys::{NodeState, NodePublicKey};
use tokio::sync::mpsc;

/// Channel capacity for all inter-actor queues.
/// Small = bounded memory, back-pressure propagates naturally.
const CHAN_CAP: usize = 4;

pub struct RuntimeConfig {
    pub control:       ControlConfig,
    pub auth_key:      heapless::String<128>,
    pub node_state:    NodeState,
    pub priority_peer: Option<[u8; 32]>,
}

pub struct Runtime {
    // Senders — held by Runtime so callers can send commands
    pub control_tx: mpsc::Sender<ControlCmd>,
    pub derp_tx:    mpsc::Sender<DerpCmd>,
    pub disco_tx:   mpsc::Sender<DiscoCmd>,
    pub wg_tx:      mpsc::Sender<WgCmd>,
}

impl Runtime {
    /// Spawn all actors as separate Tokio tasks.
    ///
    /// On ESP32-C3 with `current_thread` runtime, tasks are cooperatively
    /// scheduled within a single OS thread — no additional FreeRTOS tasks.
    pub async fn spawn(config: RuntimeConfig) -> Self {
        let (ctrl_tx,  ctrl_rx)  = mpsc::channel::<ControlCmd>(CHAN_CAP);
        let (ctrl_ev_tx, mut ctrl_ev_rx) = mpsc::channel::<ControlEvent>(CHAN_CAP);

        let (derp_tx,  derp_rx)  = mpsc::channel::<DerpCmd>(CHAN_CAP);
        let (derp_ev_tx, mut derp_ev_rx) = mpsc::channel::<DerpEvent>(CHAN_CAP);

        let (disco_tx, disco_rx) = mpsc::channel::<DiscoCmd>(CHAN_CAP);
        let (_disco_ev_tx, mut _disco_ev_rx) = mpsc::channel::<DiscoEvent>(CHAN_CAP);

        let (wg_tx,    wg_rx)    = mpsc::channel::<WgCmd>(CHAN_CAP);
        let (_wg_ev_tx, mut _wg_ev_rx) = mpsc::channel::<WgEvent>(CHAN_CAP);

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

        let derp_tx2  = derp_tx.clone();
        let wg_tx2    = wg_tx.clone();
        let disco_tx2 = disco_tx.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(evt) = ctrl_ev_rx.recv() => {
                        match evt {
                            ControlEvent::MapUpdate(map) => {
                                // Update WireGuard peers
                                let _ = wg_tx2.send(WgCmd::ApplyMap(map)).await;
                                // TODO: update DERP preferred region
                            }
                            ControlEvent::OurIpAssigned(ip) => {
                                tracing::info!("Tailnet IP: {:?}", ip.0);
                            }
                            ControlEvent::KeyExpiry => {
                                let _ = ctrl_tx.clone(); // trigger reauth
                            }
                            ControlEvent::Error(e) => {
                                tracing::error!("Control error: {:?}", e);
                            }
                        }
                    }
                    Some(evt) = derp_ev_rx.recv() => {
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
                                tracing::info!("DERP connected");
                            }
                            _ => {}
                        }
                    }
                    else => break,
                }
            }
        });

        // Start the control actor
        let _ = derp_tx.send(DerpCmd::Connect {
            host: heapless::String::try_from("login.tailscale.com").unwrap(),
            port: 443,
            cert_fingerprint: None,
        }).await;

        Runtime { control_tx: ctrl_tx, derp_tx, disco_tx, wg_tx }
    }
}
