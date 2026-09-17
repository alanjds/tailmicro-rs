//! Tailscale control plane client (full implementation).
//!
//! # Memory usage notes
//!
//! The ControlActor uses approximately 6KB of heap memory:
//! - TCP connection: negligible (a plain socket, no TLS state)
//! - NoiseChannel buffers: ~8KB (2x 4114-byte arrays)
//! - H/2 state and buffers: ~1KB
//!
//! On ESP32-C3 with 320KB RAM total, this leaves ample room for other
//! operations. The actor is designed to run with Runtime::join() which
//! avoids per-task heap allocations, keeping the total memory footprint
//! reasonable.
pub mod noise;
pub mod map_serde;
pub mod pin;
mod io;

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};
use log::{debug, info};
use tm_h2::{
    FrameAction, FrameHeader, H2Error, H2State, MAX_FRAME_SIZE,
    write_settings, write_settings_ack, write_window_update,
    write_ping_ack, write_map_request_headers, CLIENT_PREFACE,
};
use tm_keys::NodeState;
use noise::{NoiseChannel, do_noise_handshake};
pub use io::IoStream;

// Max request size: body + headers (headers ~256 bytes)
const MAX_REQUEST_SIZE: usize = 4096 + 256;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailnetIp(pub [u8; 4]);
impl TailnetIp {
    pub fn to_ipv4(&self) -> core::net::Ipv4Addr { core::net::Ipv4Addr::from(self.0) }
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub node_key:    [u8; 32],
    pub disco_key:   [u8; 32],
    pub tailnet_ip:  TailnetIp,
    pub prefix_len:  u8,
    pub hostname:    heapless::String<64>,
    pub derp_region: u16,
    pub is_online:   bool,
}

#[derive(Clone, Debug)]
pub struct DerpRegion {
    pub region_id:   u16,
    pub region_code: heapless::String<8>,
    pub host:        heapless::String<64>,
    pub port:        u16,
    pub latency_ms:  u16,
}

pub struct MapState<const MAX_PEERS: usize = 8, const MAX_REGIONS: usize = 4> {
    pub our_ip:       TailnetIp,
    pub peers:        ArrayVec<PeerInfo, MAX_PEERS>,
    pub derp_regions: ArrayVec<DerpRegion, MAX_REGIONS>,
}

// ── Capability version ────────────────────────────────────────────────────────

/// Conservative version: avoids PeerChangesDelta (cap 72+).
pub const CAPABILITY_VERSION: u16 = 72;

/// HTTP/2 stream IDs for this connection's three requests. Each new
/// client-initiated HTTP/2 request must use its own, incrementing odd
/// stream ID (RFC 7540 SS5.1.1) - these are not interchangeable or reusable,
/// which is why parse_frame/WINDOW_UPDATE need the right one passed in
/// explicitly rather than assuming "1" everywhere. See
/// docs/noise-handshake-wire-format.md.
///
/// A third stream was added (disco/control-plane bring-up, Kanban
/// t_c414048d): a non-streaming ("write") MapRequest that actually
/// publishes Hostinfo/DiscoKey/Endpoints, sent before the existing
/// streaming poll — see `ControlActor::connect_and_poll`'s "Step 7.5" and
/// docs/wg-dataplane-notes.md Bug 3. The streaming poll's stream ID moved
/// from 3 to 5 to make room for it, matching
/// `tools/wg_validator/ts_control.py`'s stream ordering (register,
/// write-map, then the streaming poll).
const REGISTER_STREAM_ID: u32 = 1;
const MAP_PUBLISH_STREAM_ID: u32 = 3;
const MAP_STREAM_ID: u32 = 5;
/// Upper bound on a single length-prefixed MapResponse message. The real
/// non-streaming netmap for this device is tens of KB; a value larger than
/// this means the stream is desynced (seen live: a ~1.95 GB garbage prefix on
/// the Stream=true keepalive), so we bail rather than reserve_exact/OOM-abort.
const MAX_MAP_MSG: usize = 512 * 1024;

// ── Config ────────────────────────────────────────────────────────────────────

pub struct Config {
    pub control_host: &'static str,
    pub control_port: u16,
    /// The control server's Noise static public key, obtained and
    /// signature-verified via `pin::verify_pin_hex` (or equivalent) before
    /// this `Config` is constructed. There is no `/key` fetch anymore — this
    /// is the only source of the responder key used in the Noise IK
    /// handshake, so it is mandatory (no `Default` impl for `Config`: an
    /// all-zero sentinel here can't verify anything downstream).
    pub control_pin: [u8; 32],
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ControlError { Tls, Noise(NoiseError), Http, H2(H2Error), Json(JsonError),
                        PeerTableFull, RegistrationFailed, Io, Pin(pin::PinError) }
#[derive(Debug)]
pub enum NoiseError { Handshake, Decrypt, Encrypt }
#[derive(Debug)]
pub enum JsonError { InvalidUtf8, ParseError, MissingField }

impl From<H2Error> for ControlError { fn from(e: H2Error) -> Self { Self::H2(e) } }

// ── Actor messages ────────────────────────────────────────────────────────────

pub enum ControlCmd  { Start { auth_key: heapless::String<128> }, Reauth, Shutdown }
pub enum ControlEvent {
    // Boxed: async_channel's ring buffer (concurrent-queue) reserves 31 slots
    // per block and returns each block by value, so an unboxed MapState here
    // balloons the caller's combined async stack frame by 31x (see the
    // ESP32-C3 stack overflow at Runtime::join()'s tokio::join! entry, fixed
    // by boxing every oversized channel message payload across the workspace).
    MapUpdate(Box<MapState>), OurIpAssigned(TailnetIp), KeyExpiry, Error(ControlError),
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterRequest<'a> {
    version: u16, node_key: &'a str,
    // Option, not a bare &str: the real control server's Go-side type for
    // this field is `key.NodePublic` (a `"nodekey:<hex>"`-prefixed key),
    // whose UnmarshalText rejects an empty string. Always sending
    // `"OldNodeKey":""` (no key rotation in progress) made every
    // registration request fail with `500 Internal Server Error` - confirmed
    // root-caused in Python (a real `h2` client got a clean 200 once this
    // field was omitted instead of sent empty) before this fix; see
    // docs/noise-handshake-wire-format.md. `skip_serializing_if` omits the
    // field entirely rather than serializing `null`, matching the official
    // Rust client's own `Option<NodePublicKey>` + serde_with `is_default`
    // skip behavior for this same field.
    #[serde(skip_serializing_if = "Option::is_none")]
    old_node_key: Option<&'a str>,
    auth: RegisterAuth<'a>, hostinfo: HostInfo<'a>,
}
#[derive(Serialize)]
struct RegisterAuth<'a> { #[serde(rename="AuthKey")] auth_key: &'a str }
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HostInfo<'a> {
    // The real field name is "OS" (all-caps, tailcfg.Hostinfo.OS), not the
    // "Os" that #[serde(rename_all = "PascalCase")] would otherwise produce
    // from `os` - confirmed via the live control server's response and the
    // real tailcfg.go source. Explicit rename needed here specifically
    // because PascalCase-ing a lowercase field only ever capitalizes the
    // first letter.
    #[serde(rename = "OS")]
    os: &'a str,
    hostname: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterResponse {
    #[serde(default)] auth_url: Option<String>,
    #[serde(default)] node_key_expired: bool,
    #[serde(default)] machine_authorized: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MapRequest<'a> {
    version: u16, compress: &'a str, keep_alive: bool,
    node_key: &'a str, endpoints: &'a [&'a str], stream: bool,
    // Both added for the non-streaming "publish" MapRequest (disco/
    // control-plane bring-up, Bug 3): a Stream=true request is read-only on
    // the control server - cap version >= 68 ignores Hostinfo/DiscoKey/
    // Endpoints on it entirely (confirmed via tools/wg_validator/
    // ts_control.py against a live server: our disco key propagated to
    // peers as all-zeros from a streaming request). `skip_serializing_if`
    // keeps the existing streaming MapRequest call (which still passes
    // `None` for both) byte-identical to before this change - this struct
    // change is purely additive for the new publish call. Matches
    // ts_control.py::write_map's JSON body field-for-field.
    #[serde(skip_serializing_if = "Option::is_none")]
    disco_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfo<'a>>,
}


// ── ControlActor ─────────────────────────────────────────────────────────────

pub struct ControlActor {
    config: Config,
    node_state: NodeState,
}

impl ControlActor {
    pub fn new(config: Config, node_state: NodeState) -> Self {
        Self { config, node_state }
    }

    pub async fn run(mut self, mut cmds: async_channel::Receiver<ControlCmd>,
                     events: async_channel::Sender<ControlEvent>) {
        loop {
            match cmds.recv().await {
                Ok(ControlCmd::Start { ref auth_key }) => {
                    if let Err(e) = self.connect_and_poll(auth_key.as_str(), &events).await {
                        tracing::error!("Control error: {:?}", e);
                        let _ = events.send(ControlEvent::Error(e)).await;
                    }
                }
                Ok(ControlCmd::Shutdown) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    async fn connect_and_poll(&mut self, auth_key: &str,
                               events: &async_channel::Sender<ControlEvent>)
        -> Result<(), ControlError>
    {
        info!("Tailscale connect_and_poll starting");
        let host = self.config.control_host;
        let port = self.config.control_port;
        info!("Tailscale connecting to {}:{}", host, port);

        // The control server's Noise static key comes from the verified pin
        // (Config::control_pin) — no /key HTTP(S) pre-fetch anymore.
        info!("Tailscale Step 1: opening main connection");
        let mut main_conn = self.open_tcp(host, port).await?;
        info!("Tailscale Step 1: main TCP connection established");
        info!("Tailscale Step 2: doing Noise IK handshake");
        let mut noise = do_noise_handshake(
            &mut main_conn, &self.node_state.machine_key, &self.config.control_pin,
            host, CAPABILITY_VERSION,
        ).await?;
        info!("Tailscale Step 2: Noise IK handshake complete");

        // Step 5: H/2 preface + SETTINGS
        noise.write_all(&mut main_conn, CLIENT_PREFACE).await?;
        let mut settings_buf = [0u8; 24];
        let settings_len = write_settings(&mut settings_buf);
        noise.write_all(&mut main_conn, &settings_buf[..settings_len]).await?;

        // Step 6 & 7: RegisterRequest / RegisterResponse
        //
        // Each ~4.3KB request/response buffer below is wrapped in its own
        // block so it is dropped right after its last use, instead of
        // staying live (and folded into this async fn's state machine)
        // through every later await. Left unscoped, reg_req/reg_bytes/
        // map_req together added ~13KB to this function's state on top of
        // everything else, which is what blew the ESP32-C3's 16000-byte
        // main task stack (confirmed live: Guru Meditation stack protection
        // fault). print-type-sizes confirmed the fix: connect_and_poll's
        // state dropped from 19048 bytes to a few hundred.
        let node_key_hex = self.node_state.node_key.public().to_hex();
        let mut h2 = H2State::new();

        {
            let reg_body = serde_json::to_vec(&RegisterRequest {
                version: CAPABILITY_VERSION, node_key: node_key_hex.as_str(),
                old_node_key: None,
                auth: RegisterAuth { auth_key },
                hostinfo: HostInfo { os: "embedded", hostname: "esp32c3" },
            }).map_err(|_| ControlError::Json(JsonError::ParseError))?;

            info!("Tailscale Step 4: registering node");
            tracing::debug!("register request body: {}", core::str::from_utf8(&reg_body).unwrap_or("<invalid utf8>"));
            let reg_req = build_h2_post("/machine/register", host, REGISTER_STREAM_ID, &reg_body);
            noise.write_all(&mut main_conn, &reg_req).await?;
        }

        info!("Tailscale Step 4: reading registration response");
        {
            let reg_bytes = read_one_h2_body(&mut main_conn, &mut noise, &mut h2, REGISTER_STREAM_ID).await?;
            tracing::debug!("register response body: {}", core::str::from_utf8(&reg_bytes).unwrap_or("<invalid utf8>"));
            let reg: RegisterResponse = serde_json::from_slice(&reg_bytes)
                .map_err(|_| ControlError::Json(JsonError::ParseError))?;

            if reg.node_key_expired { return Err(ControlError::RegistrationFailed); }
            if let Some(url) = &reg.auth_url { tracing::warn!("Auth URL: {}", url); }
            info!("Tailscale Step 4: registration complete, node_key_expired={}, machine_authorized={}", reg.node_key_expired, reg.machine_authorized);
        }

        // Step 7.5 (new): publish Hostinfo/DiscoKey/Endpoints via a
        // non-streaming MapRequest before opening the streaming poll.
        //
        // A Stream=true MapRequest (below) is read-only on the control
        // server for cap version >= 68: Hostinfo/DiscoKey/Endpoints are
        // silently ignored on it, so without this step our disco key never
        // reaches peers (they see it as all-zeros) and real peers never
        // mark our endpoint active, so they drop our WireGuard handshake.
        // Hostinfo is also unconditionally required by the server (400
        // otherwise) on every MapRequest, streaming or not. Matches
        // tools/wg_validator/ts_control.py's write_map(), which published
        // successfully against the real control server. See
        // docs/wg-dataplane-notes.md Bug 3.
        //
        // Strictly additive: the streaming MapRequest immediately below is
        // unchanged except for its stream ID (3 -> 5, freed by this new
        // request taking stream 3).
        info!("Tailscale Step 7.5: publishing Hostinfo/DiscoKey/Endpoints (non-streaming MapRequest)");
        {
            let disco_key_hex = self.node_state.disco_key.public().to_hex();
            let publish_body = serde_json::to_vec(&MapRequest {
                version: CAPABILITY_VERSION, compress: "", keep_alive: false,
                node_key: node_key_hex.as_str(), endpoints: &[], stream: false,
                disco_key: Some(disco_key_hex.as_str()),
                hostinfo: Some(HostInfo { os: "embedded", hostname: "esp32c3" }),
            }).map_err(|_| ControlError::Json(JsonError::ParseError))?;

            let publish_req = build_h2_post("/machine/map", host, MAP_PUBLISH_STREAM_ID, &publish_body);
            noise.write_all(&mut main_conn, &publish_req).await?;
        }
        // Parse the publish response as the authoritative netmap. The
        // NON-streaming ("write") MapRequest returns a full MapResponse whose
        // body carries our IP, the peer list and the DERPMap - this is the
        // response `tools/wg_validator/ts_control.py::write_map` parses its
        // peers from. (The later Stream=true poll is a read-only keepalive that
        // returns an ~empty delta, so peers/DERPMap must come from here.) It is
        // a raw JSON body with an END_STREAM, so stream_map_response parses it
        // and returns at end_stream, emitting MapUpdate + OurIpAssigned.
        info!("Tailscale Step 7.5: reading + parsing publish MapResponse");
        self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, MAP_PUBLISH_STREAM_ID).await?;

        // Step 8 & 9: streaming MapRequest + streaming response
        {
            let map_body = serde_json::to_vec(&MapRequest {
                version: CAPABILITY_VERSION, compress: "", keep_alive: true,
                node_key: node_key_hex.as_str(), endpoints: &[], stream: true,
                disco_key: None, hostinfo: None,
            }).map_err(|_| ControlError::Json(JsonError::ParseError))?;

            let map_req = build_h2_post("/machine/map", host, MAP_STREAM_ID, &map_body);
            noise.write_all(&mut main_conn, &map_req).await?;
        }

        self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, MAP_STREAM_ID).await
    }

    async fn stream_map_response<S: IoStream>(
        &self, stream: &mut S, noise: &mut NoiseChannel,
        h2: &mut H2State, events: &async_channel::Sender<ControlEvent>,
        expected_stream: u32,
    ) -> Result<(), ControlError> {
        info!("Tailscale stream_map_response starting on stream {}", expected_stream);
        // Heap (Vec) not stack: this whole call chain is awaited inline with no
        // spawn/Box::pin boundary, so a stack-inline buffer folds into the
        // caller's combined async state machine and overflows the 16 KB main
        // task stack (confirmed via a live Guru Meditation stack fault).
        let mut frame_buf: Vec<u8> = Vec::new();
        // Both the non-streaming publish and the streaming poll frame each
        // MapResponse as a 4-byte-LE length prefix + JSON (per
        // tools/wg_validator/ts_control.py's read_full_body/read_stream_message
        // + write_map), which map_serde then parses. (The hand-rolled map_parser
        // mis-parsed the real server response and was removed; see map_serde.)
        //
        // Message reassembly state. Each MapResponse is `u32-LE length + JSON`.
        // We collect the 4-byte prefix first, then allocate the body buffer
        // exactly once at `mlen` via a FALLIBLE reserve and append body bytes
        // straight into it (appends never realloc, so peak transient == mlen).
        // The reserve is fallible so an over-budget map (the live map is ~40 KB
        // and, on a heap fragmented by the Noise handshake + actor tasks, may
        // not have a contiguous block that big — see the notes) is handled by a
        // graceful bail instead of an OOM abort/reboot-loop. NB: this only
        // guards OUR allocation; the map still needs to fit the live heap budget
        // to be delivered (rung 3). See docs/wg-dataplane-notes.md.
        let mut msg_body: Vec<u8> = Vec::new();
        let mut prefix = [0u8; 4];
        let mut prefix_have = 0usize;
        let mut cur_len: Option<usize> = None;
        let mut our_ip_sent = false;

        loop {
            let mut hdr_bytes = [0u8; 9];
            noise.read_exact(stream, &mut hdr_bytes).await?;
            let hdr = FrameHeader::from_bytes(&hdr_bytes);

            if hdr.length > MAX_FRAME_SIZE {
                return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length)));
            }
            let blen = hdr.length as usize;
            frame_buf.resize(blen, 0);
            noise.read_exact(stream, &mut frame_buf[..blen]).await?;
            debug!("Tailscale frame received: length={}, type={}", hdr.length, hdr.frame_type);

            match tm_h2::parse_frame(&hdr, &frame_buf[..blen], expected_stream, h2)? {
                FrameAction::Data { payload, end_stream } => {
                    debug!("Tailscale Data frame: payload_len={}, end_stream={}", payload.len(), end_stream);

                    // Proactive WINDOW_UPDATE (MicroLink technique). Stream-level
                    // update must target the stream the data arrived on.
                    let (cwu, swu) = h2.consumed(payload.len() as u32);
                    if cwu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,0,cwu); noise.write_all(stream,&b).await?; }
                    if swu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,expected_stream,swu); noise.write_all(stream,&b).await?; }

                    // Feed the payload through the prefix -> body state machine.
                    // A single frame may finish one message and begin the next
                    // (streaming poll), so drive it with a cursor.
                    let mut pos = 0usize;
                    while pos < payload.len() {
                        // Phase 1: collect the 4-byte LE length prefix.
                        if cur_len.is_none() {
                            while prefix_have < 4 && pos < payload.len() {
                                prefix[prefix_have] = payload[pos];
                                prefix_have += 1; pos += 1;
                            }
                            if prefix_have < 4 { break; }
                            let mlen = u32::from_le_bytes(prefix) as usize;
                            // Sanity cap: a desynced stream reads a garbage length
                            // (seen live as ~1.95 GB on the Stream=true keepalive)
                            // that would OOM-abort with_capacity. Bail gracefully;
                            // the netmap already came from the publish response.
                            if mlen > MAX_MAP_MSG {
                                info!("Tailscale stream_map_response: implausible message length {} on stream {}, ending", mlen, expected_stream);
                                return Ok(());
                            }
                            // One exact, FALLIBLE allocation for the whole body;
                            // the appends below never realloc, so peak transient
                            // == mlen. try_reserve_exact turns an over-budget map
                            // into a graceful bail instead of an OOM abort.
                            msg_body = Vec::new();
                            if msg_body.try_reserve_exact(mlen).is_err() {
                                info!("Tailscale stream_map_response: cannot allocate {} B for map body on stream {} (heap budget), ending", mlen, expected_stream);
                                return Ok(());
                            }
                            cur_len = Some(mlen);
                        }

                        // Phase 2: append body bytes up to the known length.
                        let want = cur_len.unwrap();
                        let take = core::cmp::min(want - msg_body.len(), payload.len() - pos);
                        msg_body.extend_from_slice(&payload[pos..pos + take]);
                        pos += take;
                        if msg_body.len() < want { break; }

                        // Complete message: parse + emit, then reset for the next.
                        match map_serde::parse::<8, 4>(&msg_body) {
                            Ok(map) => {
                                if !our_ip_sent && map.our_ip.0 != [0u8; 4] {
                                    our_ip_sent = true;
                                    info!("Tailscale OurIpAssigned event sent: {}.{}.{}.{}", map.our_ip.0[0], map.our_ip.0[1], map.our_ip.0[2], map.our_ip.0[3]);
                                    let _ = events.send(ControlEvent::OurIpAssigned(map.our_ip.clone())).await;
                                }
                                // Skip empty snapshots (the keepalive poll returns
                                // near-empty deltas that would clobber the netmap
                                // the publish response already delivered).
                                let non_empty = !map.peers.is_empty()
                                    || map.our_ip.0 != [0u8; 4]
                                    || !map.derp_regions.is_empty();
                                if non_empty {
                                    info!("Tailscale MapUpdate event sent ({} peers, {} DERP regions)", map.peers.len(), map.derp_regions.len());
                                    let _ = events.send(ControlEvent::MapUpdate(Box::new(map))).await;
                                } else {
                                    info!("Tailscale MapUpdate skipped (empty snapshot)");
                                }
                            }
                            Err(e) => { info!("Tailscale map_serde parse error: {:?}", e); }
                        }
                        // Free the body before reading the next message so two
                        // message buffers never coexist.
                        msg_body = Vec::new();
                        cur_len = None;
                        prefix_have = 0;
                    }

                    if end_stream { info!("Tailscale stream ended"); return Ok(()); }
                }
                FrameAction::SendSettingsAck => {
                    let mut a=[0u8;9]; write_settings_ack(&mut a); noise.write_all(stream,&a).await?;
                }
                FrameAction::SendPingAck(p) => {
                    let mut a=[0u8;17]; write_ping_ack(&mut a,&p); noise.write_all(stream,&a).await?;
                }
                FrameAction::GoAway => return Err(ControlError::H2(H2Error::GoAway{last_stream:0,error_code:0})),
                FrameAction::Ignore => {}
            }
        }
    }
}

// ── TCP opener ────────────────────────────────────────────────────────────────
//
// Plain TCP (port 80) — no TLS. `tokio::net::TcpStream` works identically on
// host and ESP-IDF, so there is no per-platform branch here.

impl ControlActor {
    async fn open_tcp(&self, host: &str, port: u16) -> Result<tokio::net::TcpStream, ControlError> {
        let s = tokio::net::TcpStream::connect((host, port)).await.map_err(|_| ControlError::Io)?;
        tracing::debug!("open_tcp: connected local={:?} peer={:?} nodelay={:?}", s.local_addr(), s.peer_addr(), s.nodelay());
        Ok(s)
    }
}

// ── H/2 request builder ───────────────────────────────────────────────────────

// Boxed return: an unboxed ArrayVec<u8, MAX_REQUEST_SIZE> (~4.3KB) returned
// by value here forces every caller to reserve a matching slot in its own
// stack frame to receive it, on top of anything the caller already holds.
// build_h2_post's own frame is a normal (non-async) call frame, released as
// soon as it returns, so building `out` on its own stack and moving it into
// a Box costs nothing extra there; the caller (connect_and_poll) only pays
// for a pointer. Confirmed via a live Wokwi stack-overflow at this call site
// after fixing the much larger tokio::join! frame bug (see connect_and_poll
// and read_one_h2_body's boxing for the same reasoning).
fn build_h2_post(path: &str, host: &str, stream_id: u32, body: &[u8]) -> Box<ArrayVec<u8, MAX_REQUEST_SIZE>> {
    let mut out: Box<ArrayVec<u8, MAX_REQUEST_SIZE>> = Box::new(ArrayVec::new());
    let mut hbuf = [0u8; 256];
    let hlen = write_map_request_headers(&mut hbuf, stream_id, b"", host.as_bytes(), path.as_bytes());
    for b in &hbuf[..hlen] { let _ = out.push(*b); }
    let blen = body.len() as u32;
    let _ = out.push(((blen>>16)&0xFF) as u8);
    let _ = out.push(((blen>>8)&0xFF) as u8);
    let _ = out.push((blen&0xFF) as u8);
    let _ = out.push(0x0); // DATA
    let _ = out.push(0x1); // END_STREAM
    let sb = stream_id.to_be_bytes();
    let _ = out.push(sb[0]);
    let _ = out.push(sb[1]);
    let _ = out.push(sb[2]);
    let _ = out.push(sb[3]);
    for b in body { let _ = out.push(*b); }
    out
}

async fn read_one_h2_body<S: IoStream>(
    stream: &mut S, noise: &mut NoiseChannel, h2: &mut H2State, expected_stream: u32,
) -> Result<Box<ArrayVec<u8, 4096>>, ControlError> {
    // Boxed: this local is live across every await in the loop below (it
    // accumulates the body across frames), so it's already part of this
    // async fn's flattened generator state (this whole call chain is awaited
    // inline, no spawn/Box::pin boundary). Returning it by value on top of
    // that also forces the caller (connect_and_poll) to reserve a second
    // 4096-byte slot to receive it. Boxing keeps it off the stack/state
    // entirely and makes the return just a pointer move. Confirmed via a
    // live Wokwi run: after fixing the tokio::join! 64KB frame bug, a
    // smaller (~8KB) stack overflow remained here and in build_h2_post's
    // by-value ArrayVec return, both fixed the same way.
    let mut body: Box<ArrayVec<u8, 4096>> = Box::new(ArrayVec::new());
    // Vec, not heapless::Vec: same reasoning as stream_map_response's
    // frame_buf (see comment there) — this local is live across every await
    // in the loop below, nested inline in the same unboxed call chain.
    let mut fb: Vec<u8> = Vec::new();
    loop {
        let mut hb = [0u8; 9];
        debug!("read_one_h2_body[{}]: awaiting frame header (body so far {} B)", expected_stream, body.len());
        noise.read_exact(stream, &mut hb).await?;
        let hdr = FrameHeader::from_bytes(&hb);
        debug!("read_one_h2_body[{}]: frame type={} flags={} stream={} len={}", expected_stream, hdr.frame_type, hdr.flags, hdr.stream_id, hdr.length);
        if hdr.length > MAX_FRAME_SIZE { return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length))); }
        let blen = hdr.length as usize;
        fb.resize(blen, 0);
        noise.read_exact(stream, &mut fb[..blen]).await?;
        match tm_h2::parse_frame(&hdr, &fb[..blen], expected_stream, h2)? {
            FrameAction::Data { payload, end_stream } => {
                // try_push, NOT push: arrayvec::push PANICS on overflow. The
                // register response fits in 4096 B, but the Step 7.5 publish
                // MapResponse is ~29 KB (live-measured) and its body is
                // intentionally discarded by the caller (only the round-trip /
                // END_STREAM matters), so silently dropping the overflow is
                // correct. Before the WINDOW_UPDATE fix above the server
                // stalled at 4096 B so this buffer never overflowed and the
                // panic was masked as a hang.
                for b in payload { let _ = body.try_push(*b); }
                debug!("read_one_h2_body[{}]: DATA payload={} end_stream={}", expected_stream, payload.len(), end_stream);
                // Flow control: without this, any response body over one
                // stream window (tm_h2::INITIAL_WINDOW = 4096) stalls forever.
                // The register response fits in one window so it never needed
                // it; the Step 7.5 publish MapResponse is ~29 KB (live-measured)
                // and hung here. Same accounting stream_map_response already
                // does. Stream-level update must target `expected_stream`
                // (this drains stream 1 for register, 3 for the publish).
                let (cwu, swu) = h2.consumed(payload.len() as u32);
                if cwu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,0,cwu); noise.write_all(stream,&b).await?; debug!("read_one_h2_body[{}]: sent conn WINDOW_UPDATE +{}", expected_stream, cwu); }
                if swu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,expected_stream,swu); noise.write_all(stream,&b).await?; debug!("read_one_h2_body[{}]: sent stream WINDOW_UPDATE +{}", expected_stream, swu); }
                if end_stream { info!("read_one_h2_body[{}]: END_STREAM, total {} B", expected_stream, body.len()); return Ok(body); }
            }
            FrameAction::SendSettingsAck => { debug!("read_one_h2_body[{}]: SETTINGS -> ack", expected_stream); let mut a=[0u8;9]; write_settings_ack(&mut a); noise.write_all(stream,&a).await?; }
            FrameAction::SendPingAck(p) => { debug!("read_one_h2_body[{}]: PING -> ack", expected_stream); let mut a=[0u8;17]; write_ping_ack(&mut a,&p); noise.write_all(stream,&a).await?; }
            FrameAction::GoAway => { info!("read_one_h2_body[{}]: GOAWAY", expected_stream); return Err(ControlError::H2(H2Error::GoAway{last_stream:0,error_code:0})); }
            FrameAction::Ignore => { debug!("read_one_h2_body[{}]: Ignore (type={})", expected_stream, hdr.frame_type); }
        }
    }
}
