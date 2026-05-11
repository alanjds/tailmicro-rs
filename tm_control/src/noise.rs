//! Noise IK handshake for the Tailscale ts2021 control protocol.
//!
//! # Protocol sequence (from Tailscale Go source + headscale implementation)
//!
//! ```text
//! Client                                    Server (login.tailscale.com)
//!   |                                           |
//!   |-- GET /key?v=<cap_version>  (HTTPS) ----> |  (1) fetch server public key
//!   |<- {"PublicKey":"<hex>", ...} ------------ |
//!   |                                           |
//!   |-- POST /ts2021 HTTP/1.1                   |  (2) upgrade request
//!   |   Upgrade: tailscale-control-protocol     |      embeds Noise init message
//!   |   Content-Length: 48                      |      in the body (ClientDeferred)
//!   |   <48 bytes Noise IK init message>        |
//!   |<- HTTP/1.1 101 Switching Protocols ------ |  (3) upgrade accepted
//!   |   Upgrade: tailscale-control-protocol     |
//!   |                                           |
//!   |<- [optional: 5-byte EarlyNoise header     |  (4) EarlyNoise payload
//!   |    + JSON {NodeKey, ...}]                 |      (ignore if absent)
//!   |                                           |
//!   |<- <48 bytes Noise IK response> ---------- |  (5) Noise response message
//!   |                                           |
//!   |   [Noise channel established]             |
//!   |                                           |
//!   |-- POST /machine/register (H/2 over Noise) |  (6) RegisterRequest JSON
//!   |<- RegisterResponse JSON                   |
//!   |                                           |
//!   |-- POST /machine/map (H/2 over Noise) ---- |  (7) MapRequest (long poll)
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
//! The `snow` crate supports all of these natively.
//!
//! # EarlyNoise payload
//!
//! The server may send a 5-byte framing header before the Noise response
//! message.  The header is:
//! - Bytes 0-4: big-endian `u32` length (of the JSON payload) OR the
//!   literal bytes `\x00\x00\x00\x00\x00` meaning "no early payload"
//!
//! The `EarlyPayloadMagic` is checked via the first byte:
//! if `buf[0] == 0x00` AND `buf[1] == 0x00` AND len is < 4096, it is a
//! length-prefixed JSON; otherwise the bytes are the start of the Noise
//! response message (no early payload).
//!
//! For our purposes (ESP32-C3 embedded client), the EarlyNoise payload
//! is informational only.  We skip it if present.

use snow::{Builder as NoiseBuilder, HandshakeState, TransportState};
use crate::{ControlError, NoiseError};
use tm_keys::MachinePrivateKey;

// ── Noise parameters ──────────────────────────────────────────────────────────

/// Noise pattern string matching Tailscale's controlbase implementation.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Size of the Noise handshake init message (sent by client in POST body).
/// Fixed for Noise IK with Curve25519: 32 (e) + 16 (s encrypted) + 16 (tag) = 64
/// Actually: prologue(0) + e(32) + es(0) + s(48) + ss(0) = 80 bytes
pub const NOISE_INIT_MSG_LEN: usize = 80;

/// Size of the Noise handshake response message (received from server).
pub const NOISE_RESP_MSG_LEN: usize = 48;

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
    /// Scratch buffer for Noise-framed writes (stack allocated).
    /// Size: 4096 payload + 16 tag + 2 length prefix = 4114 bytes.
    write_buf: [u8; 4114],
    /// Scratch buffer for Noise-framed reads.
    read_buf: [u8; 4114],
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

        // Decrypt in place
        let plaintext_len = self.state
            .read_message(&self.read_buf[..msg_len].to_vec(), &mut self.read_buf)
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
    server_key:  &[u8; 32],   // from /key?v=<n> pre-fetch
    host:        &str,
    cap_version: u16,
) -> Result<NoiseChannel, ControlError> {

    // ── Step 1: Build Noise init message ──────────────────────────────────────

    let mut handshake = NoiseBuilder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(machine_key.as_bytes())
        .remote_public_key(server_key)
        .build_initiator()
        .map_err(|_| ControlError::Noise(NoiseError::Handshake))?;

    let mut init_msg = [0u8; NOISE_INIT_MSG_LEN];
    let init_len = handshake.write_message(&[], &mut init_msg)
        .map_err(|_| ControlError::Noise(NoiseError::Handshake))?;
    let init_payload = &init_msg[..init_len];

    // ── Step 2: HTTP/1.1 Upgrade request ─────────────────────────────────────
    //
    // The Noise init message is sent as the POST body.
    // This is the "ClientDeferred" optimization: the init message is
    // piggybacked onto the HTTP upgrade request to save one RTT.
    //
    // Wire format:
    //   POST /ts2021 HTTP/1.1\r\n
    //   Host: <host>\r\n
    //   Upgrade: tailscale-control-protocol\r\n
    //   Connection: Upgrade\r\n
    //   Content-Length: <len>\r\n
    //   \r\n
    //   <init_payload bytes>

    let req = build_upgrade_request(host, cap_version, init_len);
    stream.write_all(req.as_bytes()).await.map_err(|_| ControlError::Io)?;
    stream.write_all(init_payload).await.map_err(|_| ControlError::Io)?;

    // ── Step 3: Parse 101 Switching Protocols ─────────────────────────────────

    read_101_response(stream).await?;

    // ── Step 4: Handle optional EarlyNoise payload ────────────────────────────
    //
    // The server may or may not send an EarlyNoise JSON payload before the
    // Noise response message.  We detect it by peeking at the first byte:
    // - 0xFF: EarlyNoise is present — read length, skip JSON
    // - anything else: first byte of the Noise response — include in processing

    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await.map_err(|_| ControlError::Io)?;

    let mut noise_resp_buf = [0u8; NOISE_RESP_MSG_LEN];
    let noise_resp_start;

    if first_byte[0] == EARLY_PAYLOAD_MAGIC_BYTE {
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

        // Now read the full Noise response
        stream.read_exact(&mut noise_resp_buf).await.map_err(|_| ControlError::Io)?;
        noise_resp_start = &noise_resp_buf[..];
    } else {
        // first_byte[0] is the first byte of the Noise response
        noise_resp_buf[0] = first_byte[0];
        stream.read_exact(&mut noise_resp_buf[1..]).await
            .map_err(|_| ControlError::Io)?;
        noise_resp_start = &noise_resp_buf[..];
    }

    // ── Step 5: Process Noise response ────────────────────────────────────────

    let mut resp_payload = [0u8; 64]; // Noise IK response payload (empty for ts2021)
    handshake.read_message(noise_resp_start, &mut resp_payload)
        .map_err(|_| ControlError::Noise(NoiseError::Handshake))?;

    // ── Step 6: Transition to transport mode ──────────────────────────────────

    let transport = handshake.into_transport_mode()
        .map_err(|_| ControlError::Noise(NoiseError::Handshake))?;

    Ok(NoiseChannel {
        state:      transport,
        write_buf:  [0u8; 4114],
        read_buf:   [0u8; 4114],
        read_avail: 0,
        read_pos:   0,
    })
}

// ── Helper: build the HTTP/1.1 Upgrade request string ─────────────────────────

fn build_upgrade_request(host: &str, cap_version: u16, body_len: usize) -> String {
    // Using a heapless::String would be cleaner but the format! output here
    // is only allocated once during connection setup (not in steady state).
    format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: Upgrade\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {body_len}\r\n\
         Tailscale-Cap-Version: {cap_version}\r\n\
         \r\n"
    )
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

// ── Pre-fetch server public key via /key?v=<n> ────────────────────────────────
//
// Before the Noise handshake, the client must fetch the server's Noise
// public key over plain HTTPS.  The response is JSON:
//   {"PublicKey":"<hex-encoded 32 bytes>"}
//
// We parse this with a minimal JSON extractor to avoid pulling in the full
// serde_json machinery for this one-time operation.

pub async fn fetch_server_key<S: crate::IoStream>(
    stream:      &mut S,
    host:        &str,
    cap_version: u16,
) -> Result<[u8; 32], ControlError> {
    // Send GET /key?v=<cap_version>
    let req = format!(
        "GET /key?v={cap_version} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await.map_err(|_| ControlError::Io)?;

    // Read response — short, fits in 512 bytes
    let mut buf = [0u8; 512];
    let mut total = 0;

    // Read until connection close (Content-Length not guaranteed)
    loop {
        if total >= buf.len() { break; }
        let single = &mut [0u8; 1];
        match stream.read_exact(single).await {
            Ok(()) => { buf[total] = single[0]; total += 1; }
            Err(_) => break, // EOF = connection closed
        }
    }

    let body = core::str::from_utf8(&buf[..total]).map_err(|_| ControlError::Json(crate::JsonError::InvalidUtf8))?;

    // Minimal extract: find "PublicKey":"<hex>"
    let key_hex = extract_json_string(body, "PublicKey")
        .ok_or(ControlError::Json(crate::JsonError::MissingField))?;

    if key_hex.len() != 64 {
        return Err(ControlError::Json(crate::JsonError::ParseError));
    }

    let mut key = [0u8; 32];
    for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(
            core::str::from_utf8(chunk).map_err(|_| ControlError::Json(crate::JsonError::ParseError))?,
            16
        ).map_err(|_| ControlError::Json(crate::JsonError::ParseError))?;
    }
    Ok(key)
}

/// Extract a JSON string value for a given key.
/// Minimal implementation — no alloc, no recursion, no escape handling.
/// Sufficient for the /key response which is a flat JSON object.
fn extract_json_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":\"", key); // e.g. "PublicKey":"
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}
