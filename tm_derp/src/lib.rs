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
//! * `IoStream` trait for platform-independent I/O.
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

impl DerpActor {
    pub fn new(our_key: NodePublicKey, node_priv: [u8; 32]) -> Self {
        Self { our_key, node_priv }
    }

    pub async fn run(
        self,
        mut cmds:  async_channel::Receiver<DerpCmd>,
        events:    async_channel::Sender<DerpEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Ok(DerpCmd::Connect { host, port, cert_fingerprint }) => {
                    let _ = self.run_connection(
                        &host, port, cert_fingerprint, &mut cmds, &events,
                    ).await;
                    let _ = events.send(DerpEvent::Disconnected).await;
                }
                Ok(DerpCmd::Shutdown) | Err(_) => break,
                Ok(_) => {}
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
    ) -> Result<(), DerpError> {
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
            rand::rngs::OsRng,
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
            Stop,
        }

        loop {
            let decision = tokio::select! {
                biased;
                cmd = cmds.recv() => match cmd {
                    Ok(DerpCmd::SendPacket { dst_key, payload }) => Decision::Send(dst_key, payload),
                    Ok(DerpCmd::Disconnect) | Ok(DerpCmd::Shutdown) | Err(_) => Decision::Stop,
                    Ok(DerpCmd::Connect { .. }) => continue, // already connected
                },
                frame = tls.read_frame_buffered() => {
                    let (ft, n) = frame?;
                    Decision::Frame(ft, n)
                }
            };

            match decision {
                Decision::Stop => return Ok(()),
                Decision::Send(dst_key, payload) => {
                    tls.send_packet(dst_key.as_bytes(), &payload).await?;
                }
                Decision::Frame(ft, n) => {
                    if ft == DerpFrameType::RecvPacket as u8 {
                        // RecvPacket body: src_pubkey(32) + WG/disco payload.
                        if n >= 32 {
                            let mut src = [0u8; 32];
                            src.copy_from_slice(&tls.frame()[..32]);
                            tracing::info!(
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
    ) -> Result<(), DerpError> {
        loop {
            match cmds.recv().await {
                Ok(DerpCmd::Disconnect) | Ok(DerpCmd::Shutdown) | Err(_) => return Ok(()),
                Ok(_) => {}
            }
        }
    }

    async fn send_packet_frame<S: crate::IoStream>(
        stream:  &mut S,
        dst_key: &NodePublicKey,
        payload: &[u8],
    ) -> Result<(), DerpError> {
        // Frame: type(1) + length(4) + dst_pubkey(32) + payload
        let body_len = 32 + payload.len();
        let mut hdr = [0u8; 5];
        DerpHeader {
            frame_type: DerpFrameType::SendPacket,
            length: body_len as u32,
        }.to_bytes(&mut hdr);

        stream.write_all(&hdr).await.map_err(|_| DerpError::Io)?;
        stream.write_all(dst_key.as_bytes()).await.map_err(|_| DerpError::Io)?;
        stream.write_all(payload).await.map_err(|_| DerpError::Io)?;
        Ok(())
    }

    async fn recv_frame<S: crate::IoStream>(
        stream:     &mut S,
        frame_buf:  &mut [u8; MAX_DERP_PAYLOAD],
    ) -> Result<(DerpFrameType, usize), DerpError> {
        let mut hdr_bytes = [0u8; 5];
        stream.read_exact(&mut hdr_bytes).await.map_err(|_| DerpError::Io)?;
        let hdr = DerpHeader::from_bytes(&hdr_bytes)
            .ok_or(DerpError::Io)?;

        if hdr.length as usize > frame_buf.len() {
            return Err(DerpError::FrameTooLarge(hdr.length));
        }
        let body_len = hdr.length as usize;
        stream.read_exact(&mut frame_buf[..body_len]).await
            .map_err(|_| DerpError::Io)?;

        Ok((hdr.frame_type, body_len))
    }
}

// ── IoStream (same trait as tm_control) ──────────────────────────────────────
// Defined here so tm_derp doesn't depend on tm_control.
// Platform code should implement this trait for their TLS type.

pub trait IoStream: Send {
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
}
