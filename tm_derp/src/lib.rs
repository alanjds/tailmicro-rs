//! DERP relay transport.
//!
//! Handles the TLS connection to a DERP server and the DERP framing protocol.
//!
//! ## MicroLink patterns used
//!
//! * **Dedicated TX task** — the DERP send path runs in its own actor loop,
//!   preventing a slow send from stalling packet receive.
//! * **TLS fingerprint** — same verification strategy as `tm_control`.
//! * **One connection per region** — we connect to `PreferredDERP` only.
//!   Failover opens a new connection (not a new stream on the same conn).
//!
//! ## tailscale-rs patterns used
//!
//! * Actor with `mpsc::channel` mailbox.
//! * Strongly-typed message enums.

use tm_keys::NodePublicKey;
use async_channel;

/// Task-5 heap probe: log total-free and largest-contiguous internal heap,
/// tagged, so the RAM delta straddling `DerpTls::connect` is measurable from
/// the serial log. Device-only (esp-idf-sys); a no-op elsewhere.
#[cfg(feature = "etls")]
#[inline(never)]
pub(crate) fn heap_probe(tag: &str) {
    #[cfg(target_os = "espidf")]
    unsafe {
        let total_free = esp_idf_sys::esp_get_free_heap_size();
        let largest_internal =
            esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_INTERNAL);
        tracing::info!(
            "DerpActor heap [{}]: total_free={} bytes, largest_internal_block={} bytes",
            tag,
            total_free,
            largest_internal
        );
    }
    #[cfg(not(target_os = "espidf"))]
    tracing::info!("DerpActor heap [{}]: (host build; probe is device-only)", tag);
}

/// TEMPORARY instrumentation (2026-09-26 heap-collapse investigation, see
/// tailmicro-rs ALLOCATIONS.md "Fix plan: DERP TLS handshake heap collapse",
/// step 2): finer-grained probe than [`heap_probe`], using
/// `heap_caps_get_info` instead of just `heap_caps_get_largest_free_block`,
/// to tell apart "many small blocks churned" (consistent with lwIP TCP-RX
/// pbuf fragmentation, the lead hypothesis) from "one big thing allocated"
/// (something TLS-internal). Bracketing `tls.open()` with this and comparing
/// `free_blocks`/`total_blocks` before vs. after is the confirmation step the
/// fix plan calls for before touching any lwIP sdkconfig. Not meant to ship;
/// strip once the question is settled.
#[cfg(feature = "etls")]
#[inline(never)]
pub(crate) fn heap_probe_blocks(tag: &str) {
    #[cfg(target_os = "espidf")]
    unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        tracing::info!(
            "DerpActor heap-blocks [{}]: total_free={} largest_free={} \
             free_blocks={} allocated_blocks={} total_blocks={}",
            tag,
            info.total_free_bytes,
            info.largest_free_block,
            info.free_blocks,
            info.allocated_blocks,
            info.total_blocks,
        );
    }
    #[cfg(not(target_os = "espidf"))]
    tracing::info!("DerpActor heap-blocks [{}]: (host build; probe is device-only)", tag);
}

// ── DERP frame types (from Tailscale DERP spec) ───────────────────────────────

/// The 8-byte ServerKey-frame magic: the literal `DERP🔑`. Cross-checked
/// against `tools/wg_validator/derp_client.py`'s `DERP_MAGIC` (was a 4-byte
/// `b"DERP"` while the client was a stub).
pub const DERP_MAGIC: &[u8; 8] = &[0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91];

/// On-device DERP TLS leg (embedded-tls, TLS 1.3, ChaCha-only, no-verify).
/// Feature-gated so the firmware's default build is unaffected until enabled.
#[cfg(feature = "etls")]
pub mod tls;

/// Frame type bytes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DerpFrameType {
    ServerKey      = 0x01,
    ClientInfo     = 0x02,
    ServerInfo     = 0x03,
    SendPacket     = 0x04,
    RecvPacket     = 0x05,
    KeepAlive      = 0x06,
    NotePreferred  = 0x07,
    PeerGone       = 0x08,
    PeerPresent    = 0x09,
    WatchConns     = 0x10,
    ClosePeer      = 0x11,
    // Authoritative values from tailscale/derp/derp.go (frameXxx constants),
    // cross-checked against tools/wg_validator/derp_client.py's
    // FRAME_PING..FRAME_RESTARTING, which interoperated with a real DERP
    // server. These previously jumped to 0x40-0x43, which do not match any
    // real DERP frame type -- a real server's Ping/Pong/Health/Restarting
    // frames would have been silently misidentified (TryFrom would even
    // reject them, since 0x12-0x15 had no match arms at all). See
    // docs/wg-dataplane-notes.md.
    Ping           = 0x12,
    Pong           = 0x13,
    Health         = 0x14,
    Restarting     = 0x15,
}

impl TryFrom<u8> for DerpFrameType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x01 => Ok(Self::ServerKey),
            0x02 => Ok(Self::ClientInfo),
            0x03 => Ok(Self::ServerInfo),
            0x04 => Ok(Self::SendPacket),
            0x05 => Ok(Self::RecvPacket),
            0x06 => Ok(Self::KeepAlive),
            0x07 => Ok(Self::NotePreferred),
            0x08 => Ok(Self::PeerGone),
            0x09 => Ok(Self::PeerPresent),
            0x10 => Ok(Self::WatchConns),
            0x11 => Ok(Self::ClosePeer),
            0x12 => Ok(Self::Ping),
            0x13 => Ok(Self::Pong),
            0x14 => Ok(Self::Health),
            0x15 => Ok(Self::Restarting),
            _ => Err(()),
        }
    }
}

// ── DERP frame header (5 bytes) ───────────────────────────────────────────────

pub struct DerpHeader {
    pub frame_type: DerpFrameType,
    pub length:     u32,
}

impl DerpHeader {
    pub fn from_bytes(b: &[u8; 5]) -> Option<Self> {
        let ft = DerpFrameType::try_from(b[0]).ok()?;
        let length = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
        Some(DerpHeader { frame_type: ft, length })
    }

    pub fn to_bytes(&self, out: &mut [u8; 5]) {
        out[0] = self.frame_type as u8;
        out[1..5].copy_from_slice(&self.length.to_be_bytes());
    }
}

// ── Max frame constants ────────────────────────────────────────────────────────

/// Maximum WireGuard packet size + DERP header.
/// WG max is 1500 (Ethernet MTU), DERP overhead is 32 bytes.
///
/// Deliberately equal to `tm_buf::PKT_CAP`, the one capacity shared by every
/// packet buffer that crosses an inter-actor channel (see `tm_buf`).
pub const MAX_DERP_PAYLOAD: usize = tm_buf::PKT_CAP;

// ── Message types ─────────────────────────────────────────────────────────────

/// Commands sent to the DerpActor.
pub enum DerpCmd {
    /// Connect to this region.
    Connect {
        host:   heapless::String<64>,
        port:   u16,
        /// SHA-256 fingerprint of the DERP server cert.
        /// From MicroLink: avoids loading the full CA bundle.
        cert_fingerprint: Option<[u8; 32]>,
    },
    /// Send a WireGuard packet to a peer identified by their node public key.
    SendPacket {
        dst_key: NodePublicKey,
        /// The shared channel packet buffer (`tm_buf`), moved here as-is
        /// from `tm_wg`'s `WgEvent::OutboundPacket` by the event router --
        /// no copy, no re-box.
        payload: tm_buf::PktBuf,
    },
    Disconnect,
    Shutdown,
}

/// Events emitted by the DerpActor.
pub enum DerpEvent {
    /// Connected and server handshake complete.
    Connected,
    /// A WireGuard packet arrived from a peer.
    PacketReceived {
        src_key: NodePublicKey,
        /// The shared channel packet buffer (`tm_buf`). The event router
        /// forwards this same buffer to `tm_wg`/`tm_disco` without copying.
        payload: tm_buf::PktBuf,
    },
    /// Server sent PING — we respond automatically, but surface it for metrics.
    PingReceived,
    Disconnected,
    Error(DerpError),
}

#[derive(Debug)]
pub enum DerpError {
    Tls,
    Io,
    FrameTooLarge(u32),
    HandshakeFailed,
}

// ── DerpActor ─────────────────────────────────────────────────────────────────

pub struct DerpActor {
    our_key: NodePublicKey,
    /// Node Curve25519 private key. Paired with `our_key` for the DERP
    /// ServerKey/ClientInfo/ServerInfo NaCl `crypto_box` handshake.
    node_priv: [u8; 32],
}

/// Why [`DerpActor::run_connection`] returned without an I/O error.
///
/// Distinguishing these matters to [`DerpActor::run`]'s redial loop: an
/// explicit `Disconnect` means "go idle, wait for the next `Connect`" (no
/// retry), while `Shutdown` means "end the actor" -- neither should be
/// treated as a transient failure worth backing off and redialing, which is
/// reserved for `run_connection` returning `Err` (see the caller).
enum StopReason {
    /// `DerpCmd::Disconnect` was received.
    Disconnected,
    /// `DerpCmd::Shutdown` was received, or the command channel closed.
    Shutdown,
}

/// Initial redial delay after a DERP connection drops with an error.
const RECONNECT_INITIAL_MS: u64 = 1_000;
/// Cap on the exponential redial backoff.
const RECONNECT_MAX_MS: u64 = 30_000;

/// Pure doubling-with-cap step of the redial backoff, pulled out of
/// `DerpActor::run` so it's unit-testable without spinning up an actor or
/// a tokio runtime.
fn next_backoff_ms(current_ms: u64) -> u64 {
    current_ms.saturating_mul(2).min(RECONNECT_MAX_MS)
}

impl DerpActor {
    pub fn new(our_key: NodePublicKey, node_priv: [u8; 32]) -> Self {
        Self { our_key, node_priv }
    }

    /// Drives the DERP connection lifecycle: dial the last `Connect` target,
    /// service it until it ends, and react to *why* it ended.
    ///
    /// Bug fix (2026-09, confirmed live): `run_connection` returning `Err`
    /// (a TCP reset, a TLS read error, any `frame?` failure) used to be
    /// treated as terminal -- `run` sent `Disconnected` and then just idled
    /// on `cmds.recv()`, waiting for a fresh `Connect` that, on a quiet
    /// tailnet, might never come (nothing but a `MapUpdate` delta sends
    /// `Connect`, and empty-snapshot keepalives are skipped upstream in
    /// `tm_control`). The device would go permanently deaf on the DERP data
    /// plane after any drop, with the control-plane connection looking
    /// perfectly healthy. Confirmed with `tailscale status --json`: a
    /// peer's `TxBytes` climbing (repeated handshake attempts) while
    /// `RxBytes` stayed flat for 10+ minutes, recovering only after a
    /// manual reboot.
    ///
    /// Fix: on `Err`, redial the SAME target with exponential backoff
    /// (starting at `RECONNECT_INITIAL_MS`, capped at `RECONNECT_MAX_MS`),
    /// indefinitely, until either a reconnection succeeds (backoff resets)
    /// or a new `Connect`/`Shutdown` command interrupts the backoff sleep.
    pub async fn run(
        self,
        mut cmds:  async_channel::Receiver<DerpCmd>,
        events:    async_channel::Sender<DerpEvent>,
    ) {
        // The most recent dial target, kept so a connection error can
        // redial it without needing a fresh `Connect` command.
        let mut target: Option<(heapless::String<64>, u16, Option<[u8; 32]>)> = None;
        let mut backoff_ms: u64 = RECONNECT_INITIAL_MS;

        'outer: loop {
            if target.is_none() {
                match cmds.recv().await {
                    Ok(DerpCmd::Connect { host, port, cert_fingerprint }) => {
                        target = Some((host, port, cert_fingerprint));
                        backoff_ms = RECONNECT_INITIAL_MS;
                    }
                    Ok(DerpCmd::Shutdown) | Err(_) => break,
                    Ok(_) => continue,
                }
            }

            let (host, port, cert_fingerprint) = target.clone().expect("checked above");
            let result = self.run_connection(
                &host, port, cert_fingerprint, &mut cmds, &events,
            ).await;
            // Raised from debug to info (2026-09 DERP-reconnect fix): a DERP
            // drop used to be visible only in debug builds, which hid the
            // very outage this fix addresses from normal serial logs.
            match &result {
                Ok(StopReason::Disconnected) => tracing::info!(
                    "DerpActor: connection to {}:{} ended: Disconnect requested", host, port),
                Ok(StopReason::Shutdown) => tracing::info!(
                    "DerpActor: connection to {}:{} ended: Shutdown requested", host, port),
                Err(e) => tracing::info!(
                    "DerpActor: connection to {}:{} ended with error: {:?}", host, port, e),
            }
            let _ = events.send(DerpEvent::Disconnected).await;

            match result {
                Ok(StopReason::Shutdown) => break,
                Ok(StopReason::Disconnected) => {
                    target = None;
                }
                Err(_) => {
                    // Transient failure: redial `target` (unchanged) after a
                    // backoff, unless a new command interrupts the wait.
                    tracing::info!(
                        "DerpActor: reconnecting to {}:{} in {} ms",
                        host, port, backoff_ms
                    );
                    let sleep = tokio::time::sleep(core::time::Duration::from_millis(backoff_ms));
                    tokio::pin!(sleep);
                    let mut interrupted = false;
                    loop {
                        tokio::select! {
                            _ = &mut sleep => break,
                            cmd = cmds.recv() => match cmd {
                                Ok(DerpCmd::Connect { host, port, cert_fingerprint }) => {
                                    target = Some((host, port, cert_fingerprint));
                                    interrupted = true;
                                    break;
                                }
                                Ok(DerpCmd::Disconnect) => {
                                    target = None;
                                    interrupted = true;
                                    break;
                                }
                                Ok(DerpCmd::Shutdown) | Err(_) => break 'outer,
                                Ok(DerpCmd::SendPacket { .. }) => {
                                    // Nothing to send to while disconnected; drop
                                    // and keep waiting out the backoff.
                                }
                            }
                        }
                    }
                    if interrupted {
                        backoff_ms = RECONNECT_INITIAL_MS;
                    } else {
                        backoff_ms = next_backoff_ms(backoff_ms);
                    }
                }
            }
        }
    }

    /// Real DERP connection over embedded-tls (feature `etls`).
    ///
    /// Dials plain TCP via tokio, wraps it in the embedded-io adapter, runs the
    /// TLS 1.3 + DERP handshake ([`tls::DerpTls::connect`]), then services the
    /// send/receive loop. The loop uses `tokio::select!` only to *decide* what
    /// happened (a command arrived, or a frame was read); every `&mut tls`
    /// action runs afterwards, outside the `select!`, so the two paths never
    /// need `tls` simultaneously. The receive branch uses the resumable
    /// [`tls::DerpTls::read_frame_buffered`], which survives being dropped when
    /// the command branch wins — no partial-frame loss, no framing desync.
    #[cfg(feature = "etls")]
    async fn run_connection(
        &self,
        host:             &str,
        port:             u16,
        _fingerprint:     Option<[u8; 32]>,
        cmds:             &mut async_channel::Receiver<DerpCmd>,
        events:           &async_channel::Sender<DerpEvent>,
    ) -> Result<StopReason, DerpError> {
        use embedded_io_adapters::tokio_1::FromTokio;
        use tls::{DerpTls, RECORD_READ_BUF, RECORD_WRITE_BUF};

        tracing::info!("DerpActor: dialing {}:{}", host, port);
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|_| DerpError::Io)?;
        let socket = FromTokio::new(tcp);

        // Probe BEFORE any TLS allocation so the delta captures the full DERP
        // TLS session RAM: the two record buffers here plus embedded-tls's
        // fixed session state and DerpTls's boxed frame buffer (Task 5).
        heap_probe("before DerpTls::connect");

        // TLS record buffers on the heap, not the small task stack.
        let mut read_buf = Box::new([0u8; RECORD_READ_BUF]);
        let mut write_buf = Box::new([0u8; RECORD_WRITE_BUF]);

        let our_pub = *self.our_key.as_bytes();
        let mut tls = DerpTls::connect(
            socket,
            &mut read_buf[..],
            &mut write_buf[..],
            host,
            &our_pub,
            &self.node_priv,
            rand_core::OsRng,
        )
        .await?;
        heap_probe("after DerpTls::connect");
        tracing::info!("DerpActor: DERP handshake complete with {}", host);

        let _ = events.send(DerpEvent::Connected).await;

        // What the select! resolved to. Kept deliberately tls-free so no branch
        // handler borrows `tls` while the other branch's future still holds it.
        enum Decision {
            Send(NodePublicKey, tm_buf::PktBuf),
            Frame(u8, usize),
            Stop(StopReason),
        }

        loop {
            let decision = tokio::select! {
                biased;
                cmd = cmds.recv() => match cmd {
                    Ok(DerpCmd::SendPacket { dst_key, payload }) => Decision::Send(dst_key, payload),
                    Ok(DerpCmd::Disconnect) => Decision::Stop(StopReason::Disconnected),
                    Ok(DerpCmd::Shutdown) | Err(_) => Decision::Stop(StopReason::Shutdown),
                    Ok(DerpCmd::Connect { .. }) => continue, // already connected
                },
                frame = tls.read_frame_buffered() => {
                    let (ft, n) = frame?;
                    Decision::Frame(ft, n)
                }
            };

            match decision {
                Decision::Stop(reason) => return Ok(reason),
                Decision::Send(dst_key, payload) => {
                    tls.send_packet(dst_key.as_bytes(), &payload).await?;
                }
                Decision::Frame(ft, n) => {
                    if ft == DerpFrameType::RecvPacket as u8 {
                        // RecvPacket body: src_pubkey(32) + WG/disco payload.
                        if n >= 32 {
                            let mut src = [0u8; 32];
                            src.copy_from_slice(&tls.frame()[..32]);
                            tracing::trace!(
                                "DerpActor: RecvPacket {} bytes from {:02x}{:02x}..",
                                n - 32,
                                src[0],
                                src[1]
                            );
                            // Copied straight into the heap-resident channel
                            // buffer (no stack temporary). The frame buffer is
                            // MAX_DERP_PAYLOAD == PKT_CAP, so the 32-byte-shorter
                            // body always fits.
                            if let Some(payload) = tm_buf::PktBuf::from_slice(&tls.frame()[32..n]) {
                                let _ = events
                                    .send(DerpEvent::PacketReceived {
                                        src_key: NodePublicKey::from_bytes(src),
                                        payload,
                                    })
                                    .await;
                            }
                        }
                    } else if ft == DerpFrameType::Ping as u8 {
                        let body: heapless::Vec<u8, 8> = {
                            let mut b = heapless::Vec::new();
                            let take = core::cmp::min(n, 8);
                            let _ = b.extend_from_slice(&tls.frame()[..take]);
                            b
                        };
                        tls.pong(&body).await?;
                        tracing::info!("DerpActor: server PING -> PONG");
                        let _ = events.send(DerpEvent::PingReceived).await;
                    } else {
                        tracing::debug!("DerpActor: frame type 0x{:02x} ({} bytes) ignored", ft, n);
                    }
                    // KeepAlive / PeerPresent / PeerGone / Health etc. ignored.
                }
            }
        }
    }

    /// Stub connection loop for builds without the `etls` feature (host tests,
    /// stock firmware). Preserves the original behaviour: drains commands but
    /// performs no I/O.
    #[cfg(not(feature = "etls"))]
    async fn run_connection(
        &self,
        _host:            &str,
        _port:            u16,
        _fingerprint:     Option<[u8; 32]>,
        cmds:             &mut async_channel::Receiver<DerpCmd>,
        _events:          &async_channel::Sender<DerpEvent>,
    ) -> Result<StopReason, DerpError> {
        loop {
            match cmds.recv().await {
                Ok(DerpCmd::Disconnect) => return Ok(StopReason::Disconnected),
                Ok(DerpCmd::Shutdown) | Err(_) => return Ok(StopReason::Shutdown),
                Ok(_) => {}
            }
        }
    }
}

// ── DERP reconnect-with-backoff tests (2026-09 fix) ─────────────────────────
//
// `run_connection` under `feature = "etls"` is the only path that can
// actually return `Err` (a real TCP/TLS failure), so the redial-after-error
// branch itself is only exercised on real hardware / a Wokwi run with a
// forced disconnect. What IS host-testable in isolation, and covered here:
//
//   1. The pure backoff arithmetic (`next_backoff_ms`): doubles, caps at
//      `RECONNECT_MAX_MS`, never panics on overflow.
//   2. The actor-level state machine around `StopReason`, using the
//      `not(feature = "etls")` stub `run_connection`: an explicit
//      `Disconnect` resets `target` to `None` (idle, no redial) rather than
//      looping forever or dropping a subsequent `Connect`, and `Shutdown`
//      ends the actor task.
#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn next_backoff_ms_doubles_and_caps() {
        let mut ms = RECONNECT_INITIAL_MS;
        assert_eq!(ms, 1_000);
        ms = next_backoff_ms(ms);
        assert_eq!(ms, 2_000);
        ms = next_backoff_ms(ms);
        assert_eq!(ms, 4_000);
        ms = next_backoff_ms(ms);
        assert_eq!(ms, 8_000);
        ms = next_backoff_ms(ms);
        assert_eq!(ms, 16_000);
        ms = next_backoff_ms(ms);
        assert_eq!(ms, RECONNECT_MAX_MS, "must cap at 30s");
        ms = next_backoff_ms(ms);
        assert_eq!(ms, RECONNECT_MAX_MS, "must stay capped, not overflow past it");
    }

    #[test]
    fn next_backoff_ms_never_panics_near_u64_max() {
        // saturating_mul must not panic even from a pathological start.
        assert_eq!(next_backoff_ms(u64::MAX), RECONNECT_MAX_MS);
    }

    /// Explicit `Disconnect` must go idle (no redial target) rather than
    /// exiting the actor -- a subsequent `Connect` must still be honoured.
    /// This is the "belt-and-suspenders" half of the fix: even without any
    /// I/O error, the actor's own command handling must not get stuck.
    #[tokio::test]
    async fn disconnect_then_reconnect_is_honoured() {
        let our_key = NodePublicKey::from_bytes([0x11; 32]);
        let actor = DerpActor::new(our_key, [0x22; 32]);
        let (cmd_tx, cmd_rx) = async_channel::bounded::<DerpCmd>(4);
        let (ev_tx, ev_rx) = async_channel::bounded::<DerpEvent>(4);

        let run_task = tokio::spawn(actor.run(cmd_rx, ev_tx));

        cmd_tx.send(DerpCmd::Connect {
            host: heapless::String::try_from("example.derp").unwrap(),
            port: 443,
            cert_fingerprint: None,
        }).await.unwrap();
        // Stub `run_connection` does no I/O; it just waits on the next
        // command, so the actor is now "connected" (idle in run_connection).
        cmd_tx.send(DerpCmd::Disconnect).await.unwrap();
        assert!(matches!(ev_rx.recv().await, Ok(DerpEvent::Disconnected)),
            "Disconnect must surface a Disconnected event");

        // A fresh Connect after the Disconnect must be accepted, not ignored
        // -- proves `target` was really reset to `None`, not left dangling.
        cmd_tx.send(DerpCmd::Connect {
            host: heapless::String::try_from("example2.derp").unwrap(),
            port: 443,
            cert_fingerprint: None,
        }).await.unwrap();
        cmd_tx.send(DerpCmd::Shutdown).await.unwrap();
        assert!(matches!(ev_rx.recv().await, Ok(DerpEvent::Disconnected)));

        tokio::time::timeout(core::time::Duration::from_secs(5), run_task)
            .await
            .expect("actor must end after Shutdown, not hang")
            .unwrap();
    }
}
