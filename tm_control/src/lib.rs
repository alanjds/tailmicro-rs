//! Tailscale control plane client (full implementation).
//!
//! # Memory usage notes
//!
//! The ControlActor uses approximately 30KB of heap memory:
//! - TLS connection: ~24KB (esp-idf-svc EspTls internal state)
//! - NoiseChannel buffers: ~8KB (2x 4114-byte arrays)
//! - H/2 state and buffers: ~1KB
//!
//! On ESP32-C3 with 320KB RAM total, this leaves ~290KB for other operations.
//! The actor is designed to run with Runtime::join() which avoids per-task heap
//! allocations, keeping the total memory footprint reasonable.
pub mod noise;
pub mod map_parser;

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};
use tm_h2::{
    FrameAction, FrameHeader, H2Error, H2State, MAX_FRAME_SIZE,
    write_settings, write_settings_ack, write_window_update,
    write_ping_ack, write_map_request_headers, CLIENT_PREFACE,
};
use tm_keys::NodeState;
use map_parser::MapParser;
use noise::{NoiseChannel, do_noise_handshake, fetch_server_key};
use tm_tls::io::IoStream;

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

// ── Config ────────────────────────────────────────────────────────────────────

pub const TAILSCALE_CONTROL_FINGERPRINTS: &[[u8; 32]] = &[[0u8; 32]];

pub struct Config {
    pub control_host:      &'static str,
    pub control_port:      u16,
    pub cert_fingerprints: &'static [[u8; 32]],
}

impl Default for Config {
    fn default() -> Self {
        Self { control_host: "login.tailscale.com", control_port: 443,
               cert_fingerprints: TAILSCALE_CONTROL_FINGERPRINTS }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ControlError { Tls, Noise(NoiseError), Http, H2(H2Error), Json(JsonError),
                        PeerTableFull, RegistrationFailed, Io }
#[derive(Debug)]
pub enum NoiseError { Handshake, Decrypt, Encrypt }
#[derive(Debug)]
pub enum JsonError { InvalidUtf8, ParseError, MissingField }

impl From<H2Error> for ControlError { fn from(e: H2Error) -> Self { Self::H2(e) } }

// ── Actor messages ────────────────────────────────────────────────────────────

pub enum ControlCmd  { Start { auth_key: heapless::String<128> }, Reauth, Shutdown }
pub enum ControlEvent {
    MapUpdate(MapState), OurIpAssigned(TailnetIp), KeyExpiry, Error(ControlError),
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterRequest<'a> {
    version: u16, node_key: &'a str, old_node_key: &'a str,
    auth: RegisterAuth<'a>, hostinfo: HostInfo<'a>,
}
#[derive(Serialize)]
struct RegisterAuth<'a> { #[serde(rename="AuthKey")] auth_key: &'a str }
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HostInfo<'a> { os: &'a str, hostname: &'a str }

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
}

// Use tm_tls::io::IoStream instead of defining our own

// ── ControlActor ─────────────────────────────────────────────────────────────

pub struct ControlActor { config: Config, node_state: NodeState }

impl ControlActor {
    pub fn new(config: Config, node_state: NodeState) -> Self { Self { config, node_state } }

    pub async fn run(self, mut cmds: tokio::sync::mpsc::Receiver<ControlCmd>,
                     events: tokio::sync::mpsc::Sender<ControlEvent>) {
        loop {
            match cmds.recv().await {
                Some(ControlCmd::Start { ref auth_key }) => {
                    if let Err(e) = self.connect_and_poll(auth_key.as_str(), &events).await {
                        tracing::error!("Control error: {:?}", e);
                        let _ = events.send(ControlEvent::Error(e)).await;
                    }
                }
                Some(ControlCmd::Shutdown) | None => break,
                _ => {}
            }
        }
    }

    async fn connect_and_poll(&self, auth_key: &str,
                               events: &tokio::sync::mpsc::Sender<ControlEvent>)
        -> Result<(), ControlError>
    {
        let host = self.config.control_host;
        let port = self.config.control_port;

        // Step 1 & 2: fetch server Noise key over HTTPS
        let mut key_conn = open_tls(host, port, &self.config).await?;
        let server_noise_key = fetch_server_key(&mut key_conn, host, CAPABILITY_VERSION).await?;
        drop(key_conn);

        // Step 3 & 4: open long-lived connection + Noise IK
        let mut main_conn = open_tls(host, port, &self.config).await?;
        let mut noise = do_noise_handshake(
            &mut main_conn, &self.node_state.machine_key, &server_noise_key,
            host, CAPABILITY_VERSION,
        ).await?;
        tracing::info!("Noise IK handshake complete");

        // Step 5: H/2 preface + SETTINGS
        noise.write_all(&mut main_conn, CLIENT_PREFACE).await?;
        let mut settings_buf = [0u8; 24];
        let settings_len = write_settings(&mut settings_buf);
        noise.write_all(&mut main_conn, &settings_buf[..settings_len]).await?;

        // Step 6 & 7: RegisterRequest / RegisterResponse
        let node_key_hex = self.node_state.node_key.public().to_hex();
        let reg_body = serde_json::to_vec(&RegisterRequest {
            version: CAPABILITY_VERSION, node_key: node_key_hex.as_str(),
            old_node_key: "",
            auth: RegisterAuth { auth_key },
            hostinfo: HostInfo { os: "embedded", hostname: "esp32c3" },
        }).map_err(|_| ControlError::Json(JsonError::ParseError))?;

        let reg_req = build_h2_post("/machine/register", host, 1, &reg_body);
        noise.write_all(&mut main_conn, &reg_req).await?;

        let mut h2 = H2State::new();
        let reg_bytes = read_one_h2_body(&mut main_conn, &mut noise, &mut h2).await?;
        let reg: RegisterResponse = serde_json::from_slice(&reg_bytes)
            .map_err(|_| ControlError::Json(JsonError::ParseError))?;

        if reg.node_key_expired { return Err(ControlError::RegistrationFailed); }
        if let Some(url) = &reg.auth_url { tracing::warn!("Auth URL: {}", url); }
        tracing::info!("Registered. Authorized: {}", reg.machine_authorized);

        // Step 8 & 9: MapRequest + streaming response
        let map_body = serde_json::to_vec(&MapRequest {
            version: CAPABILITY_VERSION, compress: "", keep_alive: true,
            node_key: node_key_hex.as_str(), endpoints: &[], stream: true,
        }).map_err(|_| ControlError::Json(JsonError::ParseError))?;

        let map_req = build_h2_post("/machine/map", host, 3, &map_body);
        noise.write_all(&mut main_conn, &map_req).await?;

        self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events).await
    }

    async fn stream_map_response<S: IoStream>(
        &self, stream: &mut S, noise: &mut NoiseChannel,
        h2: &mut H2State, events: &tokio::sync::mpsc::Sender<ControlEvent>,
    ) -> Result<(), ControlError> {
        let mut frame_buf: heapless::Vec<u8, 4105> = heapless::Vec::new();
        let mut parser: MapParser<8, 4> = MapParser::new();
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

            match tm_h2::parse_frame(&hdr, &frame_buf[..blen], h2)? {
                FrameAction::Data { payload, end_stream } => {
                    let done = parser.feed(payload).map_err(ControlError::Json)?;

                    // Proactive WINDOW_UPDATE (MicroLink technique)
                    let (cwu, swu) = h2.consumed(payload.len() as u32);
                    if cwu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,0,cwu); noise.write_all(stream,&b).await?; }
                    if swu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,1,swu); noise.write_all(stream,&b).await?; }

                    if done || end_stream {
                        parser.finish();
                        if !our_ip_sent && parser.out.our_ip.0 != [0u8;4] {
                            our_ip_sent = true;
                            let _ = events.send(ControlEvent::OurIpAssigned(parser.out.our_ip.clone())).await;
                        }
                        let old = core::mem::replace(&mut parser, MapParser::new());
                        let _ = events.send(ControlEvent::MapUpdate(old.out)).await;
                        if end_stream { return Ok(()); }
                    }
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

// ── TLS opener ────────────────────────────────────────────────────────────────

async fn open_tls(host: &str, port: u16, config: &Config) -> Result<tm_tls::TlsStream, ControlError> {
    let fp = config.cert_fingerprints.first().copied().unwrap_or([0u8; 32]);
    let verification = if fp == [0u8; 32] {
        tm_tls::CertVerification::FullChain
    } else {
        tm_tls::CertVerification::Fingerprint(fp)
    };
    tm_tls::TlsStream::connect(&tm_tls::TlsConfig { host, port, verification, alpn: &[] })
        .await.map_err(|_| ControlError::Tls)
}

// ── H/2 request builder ───────────────────────────────────────────────────────

fn build_h2_post(path: &str, host: &str, stream_id: u32, body: &[u8]) -> ArrayVec<u8, MAX_REQUEST_SIZE> {
    let mut out = ArrayVec::new();
    let mut hbuf = [0u8; 256];
    let hlen = write_map_request_headers(&mut hbuf, stream_id, b"", host.as_bytes());
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
    stream: &mut S, noise: &mut NoiseChannel, h2: &mut H2State,
) -> Result<ArrayVec<u8, 4096>, ControlError> {
    let mut body: ArrayVec<u8, 4096> = ArrayVec::new();
    let mut fb: heapless::Vec<u8, 4105> = heapless::Vec::new();
    loop {
        let mut hb = [0u8; 9];
        noise.read_exact(stream, &mut hb).await?;
        let hdr = FrameHeader::from_bytes(&hb);
        if hdr.length > MAX_FRAME_SIZE { return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length))); }
        let blen = hdr.length as usize;
        fb.resize(blen, 0);
        noise.read_exact(stream, &mut fb[..blen]).await?;
        match tm_h2::parse_frame(&hdr, &fb[..blen], h2)? {
            FrameAction::Data { payload, end_stream } => {
                for b in payload { let _ = body.push(*b); }
                if end_stream { return Ok(body); }
            }
            FrameAction::SendSettingsAck => { let mut a=[0u8;9]; write_settings_ack(&mut a); noise.write_all(stream,&a).await?; }
            FrameAction::SendPingAck(p) => { let mut a=[0u8;17]; write_ping_ack(&mut a,&p); noise.write_all(stream,&a).await?; }
            FrameAction::GoAway => return Err(ControlError::H2(H2Error::GoAway{last_stream:0,error_code:0})),
            FrameAction::Ignore => {}
        }
    }
}
