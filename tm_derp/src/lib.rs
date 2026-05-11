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

use arrayvec::ArrayVec;
use tm_keys::NodePublicKey;
use tokio::sync::mpsc;

// ── DERP frame types (from Tailscale DERP spec) ───────────────────────────────

const DERP_MAGIC: &[u8] = b"DERP";

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
    Ping           = 0x40,
    Pong           = 0x41,
    Health         = 0x42,
    Restarting     = 0x43,
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
            0x40 => Ok(Self::Ping),
            0x41 => Ok(Self::Pong),
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
pub const MAX_DERP_PAYLOAD: usize = 1500 + 32;

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
        /// Caller-owned buffer; actor copies out of it before returning.
        payload: heapless::Vec<u8, MAX_DERP_PAYLOAD>,
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
        /// Fixed-size buffer — no heap allocation per packet.
        payload: heapless::Vec<u8, MAX_DERP_PAYLOAD>,
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
}

impl DerpActor {
    pub fn new(our_key: NodePublicKey) -> Self {
        Self { our_key }
    }

    pub async fn run(
        self,
        mut cmds:  mpsc::Receiver<DerpCmd>,
        events:    mpsc::Sender<DerpEvent>,
    ) {
        loop {
            match cmds.recv().await {
                Some(DerpCmd::Connect { host, port, cert_fingerprint }) => {
                    let _ = self.run_connection(
                        &host, port, cert_fingerprint, &mut cmds, &events,
                    ).await;
                    let _ = events.send(DerpEvent::Disconnected).await;
                }
                Some(DerpCmd::Shutdown) | None => break,
                _ => {}
            }
        }
    }

    async fn run_connection(
        &self,
        host:             &str,
        port:             u16,
        fingerprint:      Option<[u8; 32]>,
        cmds:             &mut mpsc::Receiver<DerpCmd>,
        events:           &mpsc::Sender<DerpEvent>,
    ) -> Result<(), DerpError> {
        // Platform TLS connection injected here.
        // On host: tokio + rustls/native-tls
        // On ESP32-C3: esp-idf-svc EspTls with fingerprint verification
        //
        // Stub — platform impl follows in platform/ modules.
        //
        // After TLS:
        //   1. Write "DERP" magic
        //   2. Exchange ServerKey / ClientInfo / ServerInfo frames
        //   3. Enter send/receive select loop below

        // ── Main loop: send + receive in the same task ──
        // (MicroLink uses separate tasks for TX and RX, but Tokio's select!
        // achieves the same non-blocking behaviour in one task with less
        // memory — no extra stack for the TX task)
        loop {
            tokio::select! {
                cmd = cmds.recv() => {
                    match cmd {
                        Some(DerpCmd::SendPacket { dst_key, payload }) => {
                            // self.send_packet(stream, &dst_key, &payload).await?;
                        }
                        Some(DerpCmd::Disconnect) | None => return Ok(()),
                        _ => {}
                    }
                }
                // recv = self.recv_frame(stream) => {
                //     self.handle_frame(recv?, events).await?;
                // }
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

// Re-export IoStream so platform code can impl it for their TLS type
pub use crate::IoStream;

// ── IoStream (same trait as tm_control) ──────────────────────────────────────
// Defined here too so tm_derp doesn't depend on tm_control.

pub trait IoStream: Send {
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
    fn write_all<'a>(&'a mut self, buf: &'a [u8])
        -> impl core::future::Future<Output = Result<(), ()>> + 'a;
}
