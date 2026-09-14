//! Noise IK handshake for the Tailscale ts2021 control protocol.
//!
//! # Protocol sequence (from Tailscale Go source + headscale implementation)
//!
//! The control server's static Noise public key is no longer fetched over
//! the wire (there is no `/key` HTTP(S) round trip). It is supplied out of
//! band, pinned and signature-verified via `tm_control::pin` (see
//! `Config::control_pin`), before this handshake ever runs.
//!
//! The client's Noise IK init message is carried in the
//! `X-Tailscale-Handshake` HTTP header (base64-encoded), *not* the POST
//! body. This matches the real ts2021 server implementation
//! (`control/controlhttp/controlhttpserver/controlhttpserver.go`:
//! `acceptHTTP` unconditionally rejects a request with `400 missing
//! Tailscale handshake header` when that header is absent — there is no
//! body-based fallback). Verified live against
//! `controlplane.tailscale.com:80`, which returns `101 Switching
//! Protocols` for this exact framing.
//!
//! ```text
//! Client                                    Server (controlplane.tailscale.com)
//!   |                                           |
//!   |-- POST /ts2021 HTTP/1.1                   |  (1) upgrade request
//!   |   Upgrade: tailscale-control-protocol     |      Noise init message,
//!   |   X-Tailscale-Handshake: <base64 frame>   |      wire-framed (see below)
//!   |   Content-Length: 0                       |      and base64'd into a
//!   |                                           |      header, no body at all
//!   |<- HTTP/1.1 101 Switching Protocols ------ |  (2) upgrade accepted
//!   |   Upgrade: tailscale-control-protocol     |
//!   |                                           |
//!   |<- [optional: 5-byte EarlyNoise header     |  (3) EarlyNoise payload
//!   |    + JSON {NodeKey, ...}]                 |      (ignore if absent)
//!   |                                           |
//!   |<- <3-byte header + 48 bytes Noise IK      |  (4) Noise response message,
//!   |    response> ----------------------------|      also wire-framed
//!   |                                           |
//!   |   [Noise channel established]             |
//!   |                                           |
//!   |-- POST /machine/register (H/2 over Noise) |  (5) RegisterRequest JSON
//!   |<- RegisterResponse JSON                   |
//!   |                                           |
//!   |-- POST /machine/map (H/2 over Noise) ---- |  (6) MapRequest (long poll)
//!   |<- MapResponse JSON stream                 |      streaming H/2 DATA frames
//! ```
//!
//! # Noise IK instantiation
//!
//! The Tailscale controlbase package specifies:
//! - Pattern: **Noise_IK** (interactive, known static key)
//! - DH: **Curve25519**
//! - Cipher: **ChaCha20-Poly1305**
//! - Hash: **BLAKE2s**
//!
//! The `snow` crate supports all of these natively, *except* the prologue,
//! which we must set explicitly (see below) - `snow`'s default is empty.
//!
//! # Prologue and wire framing (see docs/noise-handshake-wire-format.md)
//!
//! Two things the Noise pattern name alone doesn't cover, both required for
//! the real server to accept the handshake, confirmed against
//! `tailscale/tailscale`'s `control/controlbase/handshake.go` and
//! `messages.go`:
//!
//! - **Prologue**: `"Tailscale Control Protocol v" + <cap_version>` (ASCII
//!   decimal) is mixed into the Noise hash state via `MixHash` right after
//!   `Initialize()`, before the IK pre-message. Without this, the
//!   initiator's and responder's hash states diverge from message 1 onward,
//!   so the server's decryption of our encrypted static key fails silently
//!   and it drops the connection with no response and no error - this was
//!   the "early eof" bug.
//! - **Message framing**: the base64 payload in `X-Tailscale-Handshake` is
//!   not the bare `NOISE_INIT_MSG_LEN`-byte Noise message. It's a
//!   `NOISE_INIT_FRAME_LEN`-byte `initiationMessage`: 2-byte cap_version
//!   (big-endian) + 1-byte type (`0x01`) + 2-byte payload length
//!   (big-endian) + the raw Noise payload. The server's reply is similarly
//!   wrapped in a `NOISE_RESP_FRAME_HEADER_LEN`-byte header (1-byte type
//!   `0x02` + 2-byte big-endian length) before the raw Noise response.
//!
//! # EarlyNoise payload
//!
//! The server may send a 5-byte framing header before the (wire-framed)
//! Noise response message.  The header is:
//! - Bytes 0-4: big-endian `u32` length (of the JSON payload) OR the
//!   literal bytes `\x00\x00\x00\x00\x00` meaning "no early payload"
//!
//! The `EarlyPayloadMagic` is checked via the first byte:
//! if `buf[0] == 0x00` AND `buf[1] == 0x00` AND len is < 4096, it is a
//! length-prefixed JSON; otherwise the bytes are the start of the
//! wire-framed Noise response (no early payload). This never actually
//! fires against `controlplane.tailscale.com` (its message-type byte for a
//! real response, `0x02`, never collides with the `0xFF` magic byte), but
//! is kept for servers that do send it.
//!
//! For our purposes (ESP32-C3 embedded client), the EarlyNoise payload
//! is informational only.  We skip it if present.

use snow::{Builder as NoiseBuilder, HandshakeState, TransportState};
use crate::{ControlError, NoiseError};
use tm_keys::MachinePrivateKey;

// ── Noise parameters ──────────────────────────────────────────────────────────

/// Noise pattern string matching Tailscale's controlbase implementation.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Size of the raw Noise handshake init message (the Noise protocol's own
/// bytes, before the wire-framing header below is added).
/// Fixed for Noise_IK_25519_ChaChaPoly_BLAKE2s's first message (-> e, es, s, ss):
/// e (32, raw ephemeral public key) + s (32 + 16 tag, encrypted static key)
/// + payload (0 + 16 tag, encrypted empty payload) = 32 + 48 + 16 = 96 bytes.
/// The previous value (80) omitted the empty payload's own AEAD tag, which
/// made snow::HandshakeState::write_message fail with Error::Input (output
/// buffer too small) on every real handshake attempt - confirmed via a
/// host-native run against the real control server (tm_control/examples/
/// host_handshake.rs), not caught by the ESP32-C3 stack-overflow debugging
/// this shared code path with, since that never got far enough to build the
/// init message before the stack fix.
pub const NOISE_INIT_MSG_LEN: usize = 96;

/// Size of the raw Noise handshake response message (the Noise protocol's
/// own bytes, after stripping the 3-byte wire-framing header below).
pub const NOISE_RESP_MSG_LEN: usize = 48;

/// Size of the `initiationMessage` wire frame actually carried, base64'd, in
/// the `X-Tailscale-Handshake` header: a 5-byte header (2-byte cap_version
/// big-endian, 1-byte message type, 2-byte payload length big-endian) plus
/// the `NOISE_INIT_MSG_LEN`-byte Noise payload. See
/// `control/controlbase/messages.go`'s `initiationMessage` in the real
/// tailscale/tailscale source - this framing (not just the bare Noise
/// payload) is required for the server to accept the handshake at all;
/// see docs/noise-handshake-wire-format.md for how this was found.
pub const NOISE_INIT_FRAME_LEN: usize = 5 + NOISE_INIT_MSG_LEN;

/// Size of the `responseMessage` wire frame's header (1-byte message type,
/// 2-byte payload length big-endian) that precedes the raw
/// `NOISE_RESP_MSG_LEN`-byte Noise response on the wire.
pub const NOISE_RESP_FRAME_HEADER_LEN: usize = 3;

/// Wire message types from `control/controlbase/messages.go`.
const MSG_TYPE_INITIATION: u8 = 1;
const MSG_TYPE_RESPONSE: u8 = 2;
const MSG_TYPE_ERROR: u8 = 3;

/// Maximum size of the EarlyNoise JSON payload we'll accept (to avoid alloc).
/// If the server sends something larger, we skip it.
const MAX_EARLY_NOISE_LEN: usize = 512;

/// 5-byte prefix that indicates an EarlyNoise payload is present.
/// From Tailscale Go source: `EarlyPayloadMagic = "\xff\xff\xff\xff\xff"`.
/// If the first byte is 0xFF, the next 4 bytes are a big-endian u32 length.
const EARLY_PAYLOAD_MAGIC_BYTE: u8 = 0xFF;

// ── Public API ────────────────────────────────────────────────────────────────

/// A completed Noise transport channel over which H/2 frames flow.
///
/// After handshake, all data is wrapped in Noise transport messages:
/// - Wire format: 2-byte big-endian length + encrypted payload + 16-byte tag
/// - Max payload per message: 65519 bytes (Noise max 65535 - 16 tag)
///
/// We use 4096-byte payloads (matching our H/2 frame size) for efficiency.
pub struct NoiseChannel {
    state: TransportState,
    /// Scratch buffer for Noise-framed writes, heap allocated.
    /// Size: 4096 payload + 16 tag + 2 length prefix = 4114 bytes.
    /// Boxed so this doesn't get folded into the caller's async state
    /// machine: `do_noise_handshake` is awaited inline (no spawn/Box::pin
    /// boundary) from `connect_and_poll`, and `NoiseChannel` stays alive
    /// there through the rest of the handshake and the map-poll loop, so
    /// an unboxed 4114-byte array here doubles up with `stream_map_response`'s
    /// own frame buffer inside one combined stack frame. On the ESP32-C3's
    /// 16000-byte main task stack that overflows; a live Wokwi run hit
    /// exactly this (Guru Meditation: Stack protection fault) before this
    /// field was boxed.
    write_buf: Box<[u8; 4114]>,
    /// Scratch buffer for Noise-framed reads, heap allocated (see write_buf).
    read_buf: Box<[u8; 4114]>,
    /// How many decrypted bytes are available in read_buf, starting at read_pos.
    read_avail: usize,
    read_pos:   usize,
}

impl NoiseChannel {
    /// Read exactly `n` bytes from the Noise channel into `out`.
    ///
    /// Handles message boundaries transparently — a single Noise message
    /// may be read in multiple calls, or a single call may consume multiple
    /// Noise messages (uncommon for our frame sizes).
    pub async fn read_exact<S: crate::IoStream>(
        &mut self,
        stream: &mut S,
        out:    &mut [u8],
    ) -> Result<(), ControlError> {
        let mut filled = 0;
        while filled < out.len() {
            if self.read_avail == 0 {
                self.fill_read_buf(stream).await?;
            }
            let take = (out.len() - filled).min(self.read_avail);
            out[filled..filled+take].copy_from_slice(
                &self.read_buf[self.read_pos..self.read_pos + take]
            );
            filled += take;
            self.read_pos   += take;
            self.read_avail -= take;
        }
        Ok(())
    }

    /// Write `data` to the Noise channel as one or more Noise messages.
    ///
    /// Fragments automatically if `data > 65519` bytes (won't happen for
    /// our use case — H/2 frames are ≤ 4096 bytes).
    pub async fn write_all<S: crate::IoStream>(
        &mut self,
        stream: &mut S,
        data:   &[u8],
    ) -> Result<(), ControlError> {
        // Noise transport message: 2-byte length + ciphertext + 16-byte tag
        let payload_max = self.write_buf.len() - 18; // 2 length + 16 tag
        let mut offset = 0;

        while offset < data.len() {
            let chunk_len = (data.len() - offset).min(payload_max);
            let chunk = &data[offset..offset + chunk_len];

            // Encrypt into write_buf[2..]
            let ciphertext_len = self.state
                .write_message(chunk, &mut self.write_buf[2..])
                .map_err(|_| ControlError::Noise(NoiseError::Encrypt))?;

            // Prepend 2-byte length (big-endian, per Tailscale wire format)
            let total = ciphertext_len as u16;
            self.write_buf[0] = (total >> 8) as u8;
            self.write_buf[1] =  total        as u8;

            stream.write_all(&self.write_buf[..2 + ciphertext_len]).await
                .map_err(|_| ControlError::Io)?;

            offset += chunk_len;
        }
        Ok(())
    }

    async fn fill_read_buf<S: crate::IoStream>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), ControlError> {
        // Read 2-byte length prefix
        let mut len_bytes = [0u8; 2];
        stream.read_exact(&mut len_bytes).await.map_err(|_| ControlError::Io)?;
        let msg_len = u16::from_be_bytes(len_bytes) as usize;

        if msg_len + 16 > self.read_buf.len() {
            return Err(ControlError::Noise(NoiseError::Decrypt));
        }

        // Read the ciphertext
        stream.read_exact(&mut self.read_buf[..msg_len]).await
            .map_err(|_| ControlError::Io)?;

        // Decrypt: read_message takes immutable input, mutable output
        // We need to copy input to a temporary buffer first to avoid borrow conflict
        let mut temp = [0u8; 4114];
        temp[..msg_len].copy_from_slice(&self.read_buf[..msg_len]);
        let plaintext_len = self.state
            .read_message(&temp[..msg_len], &mut self.read_buf[..])
            .map_err(|_| ControlError::Noise(NoiseError::Decrypt))?;

        self.read_avail = plaintext_len;
        self.read_pos   = 0;
        Ok(())
    }
}

// ── Handshake ─────────────────────────────────────────────────────────────────

/// Perform the full ts2021 Noise IK handshake.
///
/// Returns a `NoiseChannel` ready for H/2 traffic.
///
/// # Steps
/// 1. Build the Noise IK init message (client → server, embedded in POST body)
/// 2. Send the HTTP/1.1 Upgrade request with the init message as body
/// 3. Parse the 101 Switching Protocols response
/// 4. Handle optional EarlyNoise payload
/// 5. Read and process the Noise response message
/// 6. Transition to transport mode
    pub async fn do_noise_handshake<S: crate::IoStream>(
        stream:      &mut S,
        machine_key: &MachinePrivateKey,
        server_key:  &[u8; 32],   // from Config::control_pin (verified offline pin, not fetched)
        host:        &str,
        cap_version: u16,
    ) -> Result<NoiseChannel, ControlError> {
        tracing::debug!("do_noise_handshake() - starting Noise IK handshake with {}", host);

        // ── Step 1: Build Noise init message ──────────────────────────────────────

        tracing::debug!("do_noise_handshake() - Step 1: Building Noise IK init message");
        // Prologue: "Tailscale Control Protocol v<cap_version>", mixed into
        // the Noise hash state before anything else. Required for the
        // server's decryption of our message to succeed at all - see the
        // module doc comment and docs/noise-handshake-wire-format.md.
        let prologue = format!("Tailscale Control Protocol v{}", cap_version);
        let mut handshake = NoiseBuilder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(machine_key.as_bytes())
            .remote_public_key(server_key)
            .prologue(prologue.as_bytes())
            .build_initiator()
            .map_err(|e| { tracing::error!("build_initiator failed: {:?}", e); ControlError::Noise(NoiseError::Handshake) })?;

    let mut init_msg = [0u8; NOISE_INIT_MSG_LEN];
    let init_len = handshake.write_message(&[], &mut init_msg)
        .map_err(|e| { tracing::error!("write_message failed: {:?}", e); ControlError::Noise(NoiseError::Handshake) })?;

    // Wire-frame the raw Noise payload into the `initiationMessage` layout
    // the real server expects (see module doc comment): 2-byte cap_version
    // (BE) + 1-byte type (0x01) + 2-byte payload length (BE) + payload.
    let mut init_frame = [0u8; NOISE_INIT_FRAME_LEN];
    init_frame[0..2].copy_from_slice(&cap_version.to_be_bytes());
    init_frame[2] = MSG_TYPE_INITIATION;
    init_frame[3..5].copy_from_slice(&(init_len as u16).to_be_bytes());
    init_frame[5..5 + init_len].copy_from_slice(&init_msg[..init_len]);
    let init_payload = &init_frame[..5 + init_len];

    // ── Step 2: HTTP/1.1 Upgrade request ─────────────────────────────────────
    //
    // The wire-framed init message is base64-encoded into the
    // `X-Tailscale-Handshake` header. There is no body (Content-Length: 0)
    // — see the module doc comment for why.
    //
    // Wire format:
    //   POST /ts2021 HTTP/1.1\r\n
    //   Host: <host>\r\n
    //   Upgrade: tailscale-control-protocol\r\n
    //   Connection: upgrade\r\n
    //   Tailscale-Cap-Version: <cap_version>\r\n
    //   X-Tailscale-Handshake: <base64 of init_payload>\r\n
    //   Content-Length: 0\r\n
    //   \r\n

    let req = build_upgrade_request(host, cap_version, init_payload);
    tracing::debug!("do_noise_handshake() - request ({} bytes, init_payload {} bytes):\n{}", req.len(), init_payload.len(), req.as_str());
    stream.write_all(req.as_bytes()).await.map_err(|_| ControlError::Io)?;
    tracing::debug!("do_noise_handshake() - request write_all returned Ok");

    // ── Step 3: Parse 101 Switching Protocols ─────────────────────────────────

    read_101_response(stream).await?;

    // ── Step 4: Handle optional EarlyNoise payload, then the response frame ──
    //
    // The server may or may not send an EarlyNoise JSON payload before the
    // wire-framed Noise response message.  We detect it by peeking at the
    // first byte:
    // - 0xFF: EarlyNoise is present — read length, skip JSON, then read a
    //   fresh byte for the response frame's type field below.
    // - anything else: it's already the response frame's type byte.

    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await.map_err(|_| ControlError::Io)?;

    let msg_type = if first_byte[0] == EARLY_PAYLOAD_MAGIC_BYTE {
        // Read remaining 4 bytes of the 5-byte EarlyNoise header
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|_| ControlError::Io)?;
        let json_len = u32::from_be_bytes(len_buf) as usize;

        // Skip the JSON if it fits in our budget; otherwise drain byte-by-byte
        // to avoid allocating a large buffer
        if json_len <= MAX_EARLY_NOISE_LEN {
            let mut json_buf = [0u8; MAX_EARLY_NOISE_LEN];
            stream.read_exact(&mut json_buf[..json_len]).await
                .map_err(|_| ControlError::Io)?;
            // Could parse server node key from EarlyNoise here for future use
        } else {
            // Drain without buffering
            let mut drain = [0u8; 64];
            let mut remaining = json_len;
            while remaining > 0 {
                let take = remaining.min(drain.len());
                stream.read_exact(&mut drain[..take]).await
                    .map_err(|_| ControlError::Io)?;
                remaining -= take;
            }
        }

        // The response frame follows; read its type byte fresh.
        let mut type_byte = [0u8; 1];
        stream.read_exact(&mut type_byte).await.map_err(|_| ControlError::Io)?;
        type_byte[0]
    } else {
        first_byte[0]
    };

    // Read the remaining 2 bytes of the 3-byte response frame header
    // (message type already consumed above; this is the big-endian length).
    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await.map_err(|_| ControlError::Io)?;
    let resp_frame_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut noise_resp_buf = [0u8; NOISE_RESP_MSG_LEN];
    match msg_type {
        MSG_TYPE_RESPONSE => {
            if resp_frame_len != NOISE_RESP_MSG_LEN {
                tracing::error!("ts2021 response frame: unexpected length {} (want {})", resp_frame_len, NOISE_RESP_MSG_LEN);
                return Err(ControlError::Noise(NoiseError::Handshake));
            }
            stream.read_exact(&mut noise_resp_buf).await.map_err(|_| ControlError::Io)?;
        }
        MSG_TYPE_ERROR => {
            // msgTypeError: unauthenticated human-readable text, per the
            // real protocol - not encrypted/authenticated, hint only.
            let mut err_buf = [0u8; MAX_EARLY_NOISE_LEN];
            let take = resp_frame_len.min(err_buf.len());
            stream.read_exact(&mut err_buf[..take]).await.map_err(|_| ControlError::Io)?;
            tracing::error!("ts2021 server rejected handshake: {}", core::str::from_utf8(&err_buf[..take]).unwrap_or("<invalid utf8>"));
            return Err(ControlError::Noise(NoiseError::Handshake));
        }
        other => {
            tracing::error!("ts2021 response frame: unexpected message type {}", other);
            return Err(ControlError::Noise(NoiseError::Handshake));
        }
    }
    let noise_resp_start = &noise_resp_buf[..];

    // ── Step 5: Process Noise response ────────────────────────────────────────

    let mut resp_payload = [0u8; 64]; // Noise IK response payload (empty for ts2021)
    handshake.read_message(noise_resp_start, &mut resp_payload)
        .map_err(|e| { tracing::error!("read_message (noise response) failed: {:?}", e); ControlError::Noise(NoiseError::Handshake) })?;

    // ── Step 6: Transition to transport mode ──────────────────────────────────

    let transport = handshake.into_transport_mode()
        .map_err(|e| { tracing::error!("into_transport_mode failed: {:?}", e); ControlError::Noise(NoiseError::Handshake) })?;

        tracing::debug!("do_noise_handshake() - NoiseChannel created with heap-allocated buffers (2 x 4114 bytes = 8228 bytes)");
        Ok(NoiseChannel {
            state:      transport,
            write_buf:  Box::new([0u8; 4114]),
            read_buf:   Box::new([0u8; 4114]),
            read_avail: 0,
        read_pos:   0,
    })
}

// ── Helper: build the HTTP/1.1 Upgrade request string ─────────────────────────

/// Buffer size for the base64-encoded, wire-framed init message:
/// NOISE_INIT_FRAME_LEN (101) bytes encodes to ceil(101/3)*4 = 136 base64
/// chars. A little slack on top in case the frame ever grows again.
const BASE64_BUF_LEN: usize = 160;

/// Minimal base64 (standard alphabet, `=`-padded) encoder — avoids pulling
/// in a `base64` crate dependency for this one tens-of-bytes value.
fn base64_encode(input: &[u8]) -> heapless::String<BASE64_BUF_LEN> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out: heapless::String<BASE64_BUF_LEN> = heapless::String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        let _ = out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        let _ = out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        let _ = out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 0x3F) as usize] as char } else { '=' });
        let _ = out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn build_upgrade_request(host: &str, cap_version: u16, init_payload: &[u8]) -> heapless::String<512> {
    let b64 = base64_encode(init_payload);
    let mut s = heapless::String::new();
    let _ = s.push_str("POST /ts2021 HTTP/1.1\r\n");
    let _ = s.push_str("Host: ");
    let _ = s.push_str(host);
    let _ = s.push_str("\r\n");
    let _ = s.push_str("Upgrade: tailscale-control-protocol\r\n");
    let _ = s.push_str("Connection: upgrade\r\n");
    let _ = s.push_str("Tailscale-Cap-Version: ");
    let _ = s.push_str(&cap_version.to_string());
    let _ = s.push_str("\r\n");
    let _ = s.push_str("X-Tailscale-Handshake: ");
    let _ = s.push_str(&b64);
    let _ = s.push_str("\r\n");
    let _ = s.push_str("Content-Length: 0\r\n\r\n");
    s
}

// ── Helper: read and validate the 101 Switching Protocols response ─────────────
//
// We use httparse (already in our dependency tree via tm_h2 chain) to parse
// the HTTP/1.1 response headers.  The response body does NOT exist — the
// connection is immediately "hijacked" to the Noise stream.

async fn read_101_response<S: crate::IoStream>(
    stream: &mut S,
) -> Result<(), ControlError> {
    // Read until \r\n\r\n (end of HTTP response headers).
    // The response is short (~200 bytes); we buffer up to 512 bytes.
    let mut buf = [0u8; 512];
    let mut total = 0;

    loop {
        if total >= buf.len() {
            return Err(ControlError::Noise(NoiseError::Handshake));
        }
        let n = {
            // Read one byte at a time to avoid consuming Noise bytes
            // that immediately follow the \r\n\r\n boundary.
            let single = &mut [0u8; 1];
            stream.read_exact(single).await.map_err(|_| ControlError::Io)?;
            buf[total] = single[0];
            1
        };
        total += n;

        // Check for end-of-headers sentinel
        if total >= 4 && &buf[total-4..total] == b"\r\n\r\n" {
            break;
        }
    }

    // Validate status line
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&buf[..total]).map_err(|_| ControlError::Noise(NoiseError::Handshake))?;

    match resp.code {
        Some(101) => Ok(()),
        Some(code) => {
            tracing::error!("ts2021 upgrade rejected: HTTP {}", code);
            Err(ControlError::Noise(NoiseError::Handshake))
        }
        None => Err(ControlError::Noise(NoiseError::Handshake)),
    }
}

