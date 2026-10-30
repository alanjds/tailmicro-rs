//! Minimal HTTP/2 frame reader for the Tailscale control plane.
//!
//! # Design rationale
//!
//! The full `h2` crate pulls in ~50KB of code and expects to manage multiple
//! concurrent streams with dynamic flow-control windows.  For the Tailscale
//! control plane we only ever have **one long-lived stream** (the MapResponse
//! keep-alive poll).  This implementation handles exactly that and nothing
//! else, keeping code size and heap usage minimal.
//!
//! ## Memory model
//!
//! A single 4 KB frame buffer is kept on the stack of the calling task.
//! No heap allocation is required for frame parsing.  The H/2 connection
//! state (`H2State`) itself is < 64 bytes.
//!
//! ## What is implemented
//!
//! * Client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
//! * Sending `SETTINGS` (ack + our initial settings)
//! * Sending `HEADERS` frame (request)
//! * Sending `WINDOW_UPDATE` (connection + stream level)
//! * Reading `DATA` frames from stream 1
//! * Reading `HEADERS` / `SETTINGS` / `WINDOW_UPDATE` / `PING` frames
//!   (responds to PING, discards others after basic validation)
//! * Detecting END_STREAM
//!
//! ## What is NOT implemented (by design)
//!
//! * Server push
//! * Multiple streams
//! * HPACK dynamic table (we send literal headers only)
//! * CONTINUATION frames
//! * Priority frames

use core::fmt;

// ── Frame types ───────────────────────────────────────────────────────────────

const FRAME_DATA:          u8 = 0x0;
const FRAME_HEADERS:       u8 = 0x1;
const FRAME_SETTINGS:      u8 = 0x4;
const FRAME_PING:          u8 = 0x6;
const FRAME_GOAWAY:        u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

const FLAG_END_STREAM:  u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_ACK:         u8 = 0x1;
const FLAG_PADDED:      u8 = 0x8;

/// Maximum frame body we will accept from the server, and the value we send
/// in SETTINGS_MAX_FRAME_SIZE.
///
/// RFC 7540 SS6.5.2 fixes the legal range for this setting at
/// `[2^14, 2^24-1]` (16384..=16777215) and requires a PROTOCOL_ERROR
/// connection error for any value outside it — this used to be set to 4096,
/// which is below that minimum. The real control server enforced this: it
/// replied with `GoAway { error_code: 1 }` (PROTOCOL_ERROR) right after our
/// SETTINGS frame, before ever looking at the HEADERS/DATA that followed.
/// Confirmed root-caused with a Python reference client sending a
/// byte-for-byte copy of this crate's SETTINGS frame against the live
/// server (`GoAway` reproduced with 4096, cleared with 16384) before this
/// value was changed — see docs/noise-handshake-wire-format.md. Frame
/// buffers on our side are heap `Vec<u8>`s sized per-frame (not fixed stack
/// arrays), so raising this doesn't cost fixed memory; the server has no
/// obligation to actually send frames this large.
pub const MAX_FRAME_SIZE: u32 = 16384;

/// Our initial stream-level flow-control window. Independent of
/// MAX_FRAME_SIZE (no RFC-mandated minimum here), kept at the crate's
/// original frame-chunk size.
pub const INITIAL_WINDOW: u32 = 4096;

/// Connection-level window we advertise (32 KB total across all DATA frames).
pub const CONN_WINDOW: u32 = 32 * 1024;

// ── Client preface ────────────────────────────────────────────────────────────

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum H2Error {
    /// Peer sent a frame larger than MAX_FRAME_SIZE.
    FrameTooLarge(u32),
    /// Peer sent a frame for a stream we don't track.
    UnexpectedStream(u32),
    /// Peer sent GOAWAY.
    GoAway { last_stream: u32, error_code: u32 },
    /// I/O error from the underlying transport.
    Io,
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ── Frame header (9 bytes on wire) ────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub length:    u32,
    pub frame_type: u8,
    pub flags:     u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse from the 9-byte on-wire representation.
    pub fn from_bytes(b: &[u8; 9]) -> Self {
        let length    = (b[0] as u32) << 16 | (b[1] as u32) << 8 | (b[2] as u32);
        let frame_type = b[3];
        let flags     = b[4];
        let stream_id = u32::from_be_bytes([b[5] & 0x7f, b[6], b[7], b[8]]);
        FrameHeader { length, frame_type, flags, stream_id }
    }

    pub fn is_end_stream(&self) -> bool { self.flags & FLAG_END_STREAM != 0 }
    pub fn is_end_headers(&self) -> bool { self.flags & FLAG_END_HEADERS != 0 }
    pub fn is_ack(&self)        -> bool { self.flags & FLAG_ACK != 0 }
    pub fn is_padded(&self)     -> bool { self.flags & FLAG_PADDED != 0 }
}

// ── Frame builders (writes into caller-supplied stack buffers) ─────────────────

/// Write the SETTINGS frame announcing our constraints.
/// Returns the byte slice length written into `buf`.
pub fn write_settings(buf: &mut [u8; 24]) -> usize {
    // Frame header: length=12, type=SETTINGS, flags=0, stream=0
    buf[0..3].copy_from_slice(&[0, 0, 12]);          // length = 12 (2 settings × 6 bytes)
    buf[3] = FRAME_SETTINGS;
    buf[4] = 0;                                       // flags
    buf[5..9].copy_from_slice(&[0, 0, 0, 0]);         // stream 0

    // SETTINGS_MAX_FRAME_SIZE (0x5) = MAX_FRAME_SIZE
    buf[9..11].copy_from_slice(&0x0005u16.to_be_bytes());
    buf[11..15].copy_from_slice(&MAX_FRAME_SIZE.to_be_bytes());

    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = INITIAL_WINDOW
    buf[15..17].copy_from_slice(&0x0004u16.to_be_bytes());
    buf[17..21].copy_from_slice(&INITIAL_WINDOW.to_be_bytes());

    21
}

/// Write a SETTINGS ACK frame (9 bytes).
pub fn write_settings_ack(buf: &mut [u8; 9]) {
    buf[0..3].copy_from_slice(&[0, 0, 0]);   // length = 0
    buf[3] = FRAME_SETTINGS;
    buf[4] = FLAG_ACK;
    buf[5..9].copy_from_slice(&[0, 0, 0, 0]);
}

/// Write WINDOW_UPDATE for the connection (stream 0) or a specific stream.
pub fn write_window_update(buf: &mut [u8; 13], stream_id: u32, increment: u32) {
    buf[0..3].copy_from_slice(&[0, 0, 4]);
    buf[3] = FRAME_WINDOW_UPDATE;
    buf[4] = 0;
    buf[5..9].copy_from_slice(&stream_id.to_be_bytes());
    buf[9..13].copy_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
}

/// Write PING ACK (echoes the 8-byte payload).
pub fn write_ping_ack(buf: &mut [u8; 17], payload: &[u8; 8]) {
    buf[0..3].copy_from_slice(&[0, 0, 8]);
    buf[3] = FRAME_PING;
    buf[4] = FLAG_ACK;
    buf[5..9].copy_from_slice(&[0, 0, 0, 0]);
    buf[9..17].copy_from_slice(payload);
}

/// Write a HEADERS frame for a control-plane request (register or map poll).
///
/// Uses literal header encoding (HPACK static table entries only):
///   :method POST, :path <path>, :scheme https, :authority <host>,
///   content-type application/json, authorization <auth_token>
///
/// Returns bytes written into `buf`.  Caller must ensure buf ≥ 256 bytes.
pub fn write_map_request_headers(
    buf:        &mut [u8],
    stream_id:  u32,
    auth_token: &[u8],
    host:       &[u8],
    path:       &[u8],
) -> usize {
    // We pre-encode HPACK manually — no dynamic table, all literals.
    // This is verbose but predictable and allocates nothing.
    let mut pos = 9; // reserve space for the frame header

    // Helper: emit a literal header, never-indexed (0x10 prefix)
    macro_rules! lit {
        ($name:expr, $val:expr) => {{
            buf[pos] = 0x10; pos += 1;
            // name length
            let n = $name.len();
            buf[pos] = n as u8; pos += 1;
            buf[pos..pos+n].copy_from_slice($name); pos += n;
            // value length
            let v = $val.len();
            buf[pos] = v as u8; pos += 1;
            buf[pos..pos+v].copy_from_slice($val); pos += v;
        }};
    }

    // Static table indexed headers (faster, shorter)
    // :method POST = index 3
    buf[pos] = 0x83; pos += 1;
    // :scheme https = index 7
    buf[pos] = 0x87; pos += 1;
    // :path — literal with index :path (index 4, 0x44). This was previously
    // hardcoded to b"/ts2021" (the upgrade path, not a real request path),
    // so both the register and map requests always asked for /ts2021
    // regardless of the caller's actual `path` argument. The real server
    // accepted the HTTP/2 connection fine but rejected this at the
    // connection level (h2 GoAway, PROTOCOL_ERROR) - confirmed root-caused
    // and fixed via a Python h2-library reference request against the live
    // server before porting here; see docs/noise-handshake-wire-format.md.
    buf[pos] = 0x44; pos += 1;
    buf[pos] = path.len() as u8; pos += 1;
    buf[pos..pos+path.len()].copy_from_slice(path); pos += path.len();

    lit!(b":authority", host);
    lit!(b"content-type", b"application/json");
    lit!(b"authorization", auth_token);

    // Backfill the frame header now that we know the payload length
    let payload_len = pos - 9;
    buf[0] = (payload_len >> 16) as u8;
    buf[1] = (payload_len >> 8)  as u8;
    buf[2] =  payload_len        as u8;
    buf[3] = FRAME_HEADERS;
    buf[4] = FLAG_END_HEADERS;                       // no body, END_HEADERS
    buf[5..9].copy_from_slice(&stream_id.to_be_bytes());

    pos
}

// ── H/2 connection state ──────────────────────────────────────────────────────

/// Tiny connection bookkeeper.  Fits in < 64 bytes.
///
/// Flow-control credit is tracked per stream because the control connection
/// carries several streams at once (the long poll plus a re-poll): a single
/// shared counter would send the stream-level WINDOW_UPDATE for the wrong
/// stream and stall the other one at its 4096-byte window.
pub struct H2State {
    /// `(stream id, bytes consumed since the last stream WINDOW_UPDATE)`.
    /// Id 0 marks a free slot. Three slots cover the poll, one re-poll and
    /// the bring-up request in flight; a fourth concurrent stream evicts the
    /// oldest slot, which at worst delays one WINDOW_UPDATE.
    streams: [(u32, u32); 3],
    /// Bytes consumed at connection level.
    conn_consumed: u32,
}

impl H2State {
    pub fn new() -> Self {
        Self { streams: [(0, 0); 3], conn_consumed: 0 }
    }

    /// Record that we consumed `n` bytes of DATA payload on `stream_id`.
    /// Returns `(send_conn_wu, send_stream_wu)`: the increments to send back
    /// (the second one for `stream_id`), or 0 if no WINDOW_UPDATE is needed
    /// yet. The caller must invoke this exactly once per DATA frame;
    /// `parse_frame` does not.
    pub fn consumed(&mut self, stream_id: u32, n: u32) -> (u32, u32) {
        let slot = match self.streams.iter().position(|s| s.0 == stream_id) {
            Some(i) => i,
            None => {
                let i = self.streams.iter().position(|s| s.0 == 0).unwrap_or(0);
                self.streams[i] = (stream_id, 0);
                i
            }
        };
        self.streams[slot].1 += n;
        self.conn_consumed += n;

        let conn_wu = if self.conn_consumed >= CONN_WINDOW / 2 {
            let inc = self.conn_consumed;
            self.conn_consumed = 0;
            inc
        } else { 0 };

        let stream_wu = if self.streams[slot].1 >= INITIAL_WINDOW / 2 {
            let inc = self.streams[slot].1;
            self.streams[slot].1 = 0;
            inc
        } else { 0 };

        (conn_wu, stream_wu)
    }

    /// The stream ended: free its credit slot.
    pub fn stream_done(&mut self, stream_id: u32) {
        for s in self.streams.iter_mut().filter(|s| s.0 == stream_id) {
            *s = (0, 0);
        }
    }
}

// ── Outcome of reading a frame ─────────────────────────────────────────────────

/// What the caller should do after `read_frame` returns.
pub enum FrameAction<'a> {
    /// A slice of DATA payload.  Pass to your JSON parser.
    Data { payload: &'a [u8], end_stream: bool },
    /// Server sent SETTINGS — caller should send SETTINGS ACK.
    SendSettingsAck,
    /// Server sent PING — caller should send PING ACK with these 8 bytes.
    SendPingAck([u8; 8]),
    /// WINDOW_UPDATE / HEADERS response / other benign frame — nothing to do.
    Ignore,
    /// Server closed the connection cleanly.
    GoAway,
}

/// Parse a frame whose header has already been read.
///
/// `body` must be exactly `hdr.length` bytes. `expected_stream` is the
/// stream ID the caller is currently reading a response for (each HTTP/2
/// request opens its own, client-chosen, incrementing odd stream ID - this
/// used to be hardcoded to `1`, which only ever matched the *first* request
/// made on a connection. Sending a second request - e.g. `/machine/map` on
/// stream 3, right after `/machine/register` on stream 1 - made every DATA
/// frame of that second response fail with `UnexpectedStream`, confirmed
/// live against the real control server once registration itself started
/// succeeding. See docs/noise-handshake-wire-format.md.
pub fn parse_frame<'a>(
    hdr:   &FrameHeader,
    body:  &'a [u8],
    expected_stream: u32,
    _state: &mut H2State,
) -> Result<FrameAction<'a>, H2Error> {
    match hdr.frame_type {
        FRAME_DATA => {
            if hdr.stream_id != expected_stream {
                return Err(H2Error::UnexpectedStream(hdr.stream_id));
            }
            // Skip padding if flagged
            let payload = if hdr.is_padded() && !body.is_empty() {
                let pad_len = body[0] as usize;
                &body[1..body.len().saturating_sub(pad_len)]
            } else {
                body
            };
            Ok(FrameAction::Data { payload, end_stream: hdr.is_end_stream() })
        }

        FRAME_SETTINGS if !hdr.is_ack() => {
            // We ignore the server's setting values for simplicity.
            // A real implementation would honour INITIAL_WINDOW_SIZE changes.
            Ok(FrameAction::SendSettingsAck)
        }

        FRAME_PING if !hdr.is_ack() => {
            let mut payload = [0u8; 8];
            if body.len() >= 8 { payload.copy_from_slice(&body[..8]); }
            Ok(FrameAction::SendPingAck(payload))
        }

        FRAME_GOAWAY => {
            let last = if body.len() >= 4 {
                u32::from_be_bytes([body[0] & 0x7f, body[1], body[2], body[3]])
            } else { 0 };
            let code = if body.len() >= 8 {
                u32::from_be_bytes([body[4], body[5], body[6], body[7]])
            } else { 0 };
            Err(H2Error::GoAway { last_stream: last, error_code: code })
        }

        // HEADERS (response headers), WINDOW_UPDATE, SETTINGS ACK, unknown
        _ => Ok(FrameAction::Ignore),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Credit is per stream: bytes read on stream 7 must not make stream 9 send
    /// (or skip) its WINDOW_UPDATE, and each update names the stream whose
    /// bytes it replenishes.
    #[test]
    fn stream_credit_is_tracked_per_stream() {
        let mut h = H2State::new();
        let half = INITIAL_WINDOW / 2;
        assert_eq!(h.consumed(7, half - 1), (0, 0));
        // 9 has consumed nothing yet, so it must not release 7's credit.
        assert_eq!(h.consumed(9, 1), (0, 0));
        assert_eq!(h.consumed(7, 1), (0, half));
        assert_eq!(h.consumed(9, half - 1), (0, half));
    }

    /// The connection window is shared, so its update is driven by the sum.
    #[test]
    fn connection_credit_is_shared_across_streams() {
        let mut h = H2State::new();
        let mut conn_total = 0;
        for i in 0..40u32 {
            let (c, _) = h.consumed(7 + 2 * (i % 2), 1000);
            conn_total += c;
        }
        assert!(conn_total >= CONN_WINDOW / 2, "conn credit was never returned");
    }

    #[test]
    fn stream_done_frees_the_slot() {
        let mut h = H2State::new();
        h.consumed(9, 10);
        h.stream_done(9);
        // A new stream reusing the slot starts from zero.
        assert_eq!(h.consumed(11, INITIAL_WINDOW / 2 - 1), (0, 0));
    }
}
