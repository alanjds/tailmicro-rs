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
pub mod map_scalars;
pub mod map_stream;
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

/// The control connection's transport: tokio TCP seen through
/// `embedded-io-async`, the trait the Noise and H/2 code is written against.
type TokioStream = embedded_io_adapters::tokio_1::FromTokio<tokio::net::TcpStream>;

// Max request size: body + headers (headers ~256 bytes)
const MAX_REQUEST_SIZE: usize = 4096 + 256;

/// Cap for the small, fixed-shape JSON request bodies this crate sends
/// (`RegisterRequest`, `MapRequest`): a handful of short string fields, well
/// under 1KB in practice. See [`to_json_buf`].
const REQUEST_BODY_CAP: usize = 1024;

/// Serialize `value` into a fixed-capacity buffer instead of `serde_json::
/// to_vec`'s heap-growing `Vec<u8>`.
///
/// Each of this crate's request bodies (register / publish / republish /
/// keepalive-poll) is a small, fixed-shape struct of short string fields, so
/// a bounded buffer is a correctness-safe fit, not just an optimization: the
/// call sites are individually rare (once at registration, once or twice at
/// bring-up, once per stream reconnect), but each `Vec<u8>` grow-then-drop is
/// still a variable-sized heap allocation competing with the data plane's
/// fixed-size blocks for the same contiguous space (see ALLOCATIONS.md).
/// `write_all` on a `heapless::Vec` returns `Err` once the buffer is full
/// rather than growing, so an unexpectedly large body fails fast here
/// instead of silently reallocating.
fn to_json_buf<T: Serialize>(value: &T) -> Result<heapless::Vec<u8, REQUEST_BODY_CAP>, JsonError> {
    struct Buf(heapless::Vec<u8, REQUEST_BODY_CAP>);
    impl std::io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0
                .extend_from_slice(data)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "json request body overflow"))?;
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let mut buf = Buf(heapless::Vec::new());
    serde_json::to_writer(&mut buf, value).map_err(|_| JsonError::ParseError)?;
    Ok(buf.0)
}

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
/// Second non-streaming publish ("write") MapRequest: re-published with our
/// PreferredDERP + DERP-home endpoint once the first publish's response has
/// revealed the DERPMap and `select_home_region` has chosen our home region.
/// Standard Tailscale cold-boot pattern (write empty -> learn DERPMap ->
/// write again with endpoints). Its own odd, incrementing HTTP/2 stream id.
const MAP_REPUBLISH_STREAM_ID: u32 = 5;
const MAP_STREAM_ID: u32 = 7;
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
    /// Deadline for the bring-up phase only (TCP + Noise + register + the
    /// non-streaming publish MapRequest, i.e. everything up to and including
    /// `OurIpAssigned`). `None` disables the deadline. The streaming poll
    /// that follows bring-up NEVER gets a deadline — it must run unbounded
    /// (drain-and-discard, see `stream_map_response`) so the ephemeral node
    /// stays online. See docs/wg-dataplane-notes.md "Bring-up timeout".
    pub connect_timeout: Option<core::time::Duration>,
    /// Port of the runtime's bound LAN UDP socket (`lan-direct` feature),
    /// or `None` when there is none. With `Some`, bring-up derives the LAN
    /// endpoint `<control-socket local IPv4>:<port>` (plan D1). It is only
    /// advertised once `PUBLISH_LAN_ENDPOINT` is on (Step 5, D4), because
    /// peers must not be pointed at a socket that cannot answer yet.
    pub lan_udp_port: Option<u16>,
    /// Node name sent in every `Hostinfo`; control derives the MagicDNS name
    /// from it. Must satisfy [`valid_hostname`].
    pub hostname: &'static str,
    /// Services advertised in every `Hostinfo`. Informational only: the
    /// control server hands them to peers, nothing enforces them. At most
    /// [`MAX_SERVICES`] entries, see [`check_services`].
    pub services: &'static [Service],
}

/// Services are re-sent in each of the four Hostinfos, so their size is
/// bounded to keep the bodies inside [`REQUEST_BODY_CAP`].
pub const MAX_SERVICES: usize = 4;
pub const MAX_SERVICE_DESC: usize = 32;

/// Only the protocols Tailscale treats as plain informational entries. The
/// `peerapi*` pseudo-services are never sent: peers would act on them.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProto { Tcp, Udp }

/// One `tailcfg.Service` entry of `Hostinfo.Services`.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub proto: ServiceProto,
    pub port: u16,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub description: &'static str,
}

impl Service {
    pub const fn tcp(port: u16, description: &'static str) -> Self {
        Self { proto: ServiceProto::Tcp, port, description }
    }
    pub const fn udp(port: u16, description: &'static str) -> Self {
        Self { proto: ServiceProto::Udp, port, description }
    }
}

/// `Err` with the reason when `services` could overflow the request bodies
/// or carries an entry control would reject.
pub fn check_services(services: &[Service]) -> Result<(), &'static str> {
    if services.len() > MAX_SERVICES { return Err("too many services"); }
    for sv in services {
        if sv.port == 0 { return Err("service port 0"); }
        if sv.description.len() > MAX_SERVICE_DESC { return Err("service description too long"); }
    }
    Ok(())
}

/// A single lowercase DNS label: what control turns into the MagicDNS name.
pub fn valid_hostname(h: &str) -> bool {
    let b = h.as_bytes();
    !b.is_empty() && b.len() <= 63
        && b[0] != b'-' && b[b.len() - 1] != b'-'
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ControlError { Tls, Noise(NoiseError), Http, H2(H2Error), Json(JsonError),
                        PeerTableFull, RegistrationFailed, Io, Pin(pin::PinError),
                        /// The bring-up phase (TCP + Noise + register + publish, up
                        /// to `OurIpAssigned`) did not complete within
                        /// `Config::connect_timeout`. Never returned once bring-up
                        /// has succeeded — the streaming poll after it has no
                        /// deadline. See `ControlActor::connect_and_poll`.
                        Timeout }
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
/// Choose the DERP region this node uses as its home: the region it connects
/// its DERP session to AND advertises to peers as its `PreferredDERP`. Peers
/// relay inbound WireGuard/disco traffic to us via this region, so the value
/// the runtime connects to (see tm_runtime's DERP connect) MUST match the one
/// published here. Both sides call this same function on the same `MapState`
/// snapshot, so they agree with no coordination and nothing is hardcoded.
///
/// Selection, from the live netmap only (no static region number):
///   1. Among regions we actually have a DERP hostname for (present in the
///      DERPMap), prefer the one the most ONLINE peers are homed on, so relayed
///      traffic stays regional. Tie-break by lowest measured latency, then
///      lowest region id.
///   2. If no online peer is homed on a region we can reach, fall back to the
///      reachable region with the lowest measured latency, then lowest id.
/// Returns `None` only when the DERPMap carries no regions at all.
///
/// `latency_ms` is client-measured and may be 0/unset today (no netcheck yet),
/// in which case the tie-breaks collapse to lowest region id -- still fully
/// data-driven. A future netcheck pass populates latency and this starts
/// picking the nearest region automatically, with no change here.
pub fn select_home_region<const P: usize, const R: usize>(
    map: &MapState<P, R>,
) -> Option<u16> {
    let reachable = |rid: u16| map.derp_regions.iter().any(|r| r.region_id == rid);
    let latency_of = |rid: u16| {
        map.derp_regions
            .iter()
            .find(|r| r.region_id == rid)
            .map(|r| r.latency_ms)
            .unwrap_or(u16::MAX)
    };
    // Rank a reachable region by (online-peer count desc, latency asc, id asc).
    let score = |rid: u16| {
        let peers = map
            .peers
            .iter()
            .filter(|p| p.is_online && p.derp_region == rid)
            .count();
        // Sort key: more peers first (negate via Reverse), then lower latency,
        // then lower id. Returned so the max-by picks the best.
        (peers, core::cmp::Reverse(latency_of(rid)), core::cmp::Reverse(rid))
    };
    map.derp_regions
        .iter()
        .map(|r| r.region_id)
        .filter(|rid| reachable(*rid))
        .max_by_key(|rid| score(*rid))
}

/// Tailscale encodes "reach me via DERP region N" as the pseudo-endpoint
/// `127.3.3.40:N` (derpMagicIP). Published in MapRequest.Endpoints alongside
/// Hostinfo.NetInfo.PreferredDERP -- both together, matching the confirmed
/// recipe in tools/wg_validator/validate_live_tailnet.py.
pub const DERP_MAGIC_IP: &str = "127.3.3.40";

/// On since Step 5 of docs/lan-direct-path-plan.md (D4): once published,
/// peers start sending disco PINGs and WireGuard to the LAN endpoint, so it
/// went out in the same change as the UDP PONG and UDP WireGuard ingest.
/// It only has an effect when `Config::lan_udp_port` is `Some`, which
/// `tm_runtime` sets only with its `lan-direct` feature on and the socket
/// bound; otherwise publish #2 is byte-identical to the DERP-only body.
const PUBLISH_LAN_ENDPOINT: bool = true;

/// Plan D1: the LAN endpoint is the IPv4 address the control TCP socket is
/// bound to (the OS already picked the LAN-facing interface to reach the
/// internet), plus our UDP port. Rejected: IPv6 (the device's UDP socket is
/// v4-only), unspecified, loopback, and the tailnet range 100.64.0.0/10,
/// which would mean control went through our own tunnel and advertising it
/// would invite WireGuard-in-WireGuard.
pub fn lan_endpoint(local: std::net::SocketAddr, port: u16) -> Option<std::net::SocketAddrV4> {
    let std::net::SocketAddr::V4(v4) = local else { return None };
    let ip = *v4.ip();
    let o = ip.octets();
    let tailnet = o[0] == 100 && (o[1] & 0xC0) == 64;
    if ip.is_unspecified() || ip.is_loopback() || tailnet || port == 0 {
        return None;
    }
    Some(std::net::SocketAddrV4::new(ip, port))
}

/// Body of publish #2 (home-region re-publish). Factored out so the host
/// tests can pin it against ts_control.py's write_map and against the
/// DERP-only body. `lan_ep` goes first: tailscaled tries endpoints in
/// order, and the DERP magic entry is the fallback.
fn publish2_body(config: &Config, node_key_hex: &str, disco_key_hex: &str, region: u16,
                 lan_ep: Option<std::net::SocketAddrV4>)
    -> Result<heapless::Vec<u8, REQUEST_BODY_CAP>, JsonError>
{
    use core::fmt::Write as _;
    let mut home: heapless::String<24> = heapless::String::new();
    let _ = write!(home, "{}:{}", DERP_MAGIC_IP, region);
    let mut lan: heapless::String<24> = heapless::String::new();
    let derp_only;
    let both;
    let endpoints: &[&str] = match lan_ep {
        Some(ep) => {
            let _ = write!(lan, "{}", ep);
            both = [lan.as_str(), home.as_str()];
            &both
        }
        None => {
            derp_only = [home.as_str()];
            &derp_only
        }
    };
    to_json_buf(&MapRequest {
        version: CAPABILITY_VERSION, compress: "", keep_alive: false,
        node_key: node_key_hex, endpoints, stream: false,
        disco_key: Some(disco_key_hex),
        hostinfo: Some(host_info(config, Some(NetInfo { preferred_derp: region }))),
        omit_peers: false,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct NetInfo {
    // tailcfg.NetInfo.PreferredDERP is "PreferredDERP" (DERP all-caps); the
    // PascalCase rule would otherwise emit "PreferredDerp", so rename it
    // explicitly -- same reason as `os` -> "OS" below.
    #[serde(rename = "PreferredDERP")]
    preferred_derp: u16,
}

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
    // Shown by the admin console as client version / client name / machine.
    // Same convention as tailscale-rs: the crate version, an `App` tag that
    // tells this client from tailscaled, and the CPU architecture.
    #[serde(rename = "IPNVersion")]
    ipn_version: &'a str,
    app: &'a str,
    machine: &'a str,
    // Carries PreferredDERP (our home region) on the non-streaming publish
    // MapRequest; None on the register and streaming requests, where it is
    // either irrelevant or read-only. skip_serializing_if keeps those bodies
    // byte-identical to before this change.
    #[serde(rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    net_info: Option<NetInfo>,
    #[serde(skip_serializing_if = "<[Service]>::is_empty")]
    services: &'a [Service],
}

/// The one place a `Hostinfo` is built. Every request (register, both
/// publishes, the streaming poll) must carry the same values: headscale
/// replaces the stored Hostinfo from whichever request arrives last, so a
/// request with a different Services list flaps it to every peer.
fn host_info(config: &Config, net_info: Option<NetInfo>) -> HostInfo<'_> {
    HostInfo {
        os: "embedded", hostname: config.hostname,
        ipn_version: env!("CARGO_PKG_VERSION"), app: "tailmicro", machine: std::env::consts::ARCH,
        net_info, services: config.services,
    }
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
    // Serialized as "OmitPeers". On the Stream=true keepalive we set this true:
    // the control server then holds the long-poll open for online heartbeats
    // but does NOT send the (~34 KB) peer netmap. Receiving that netmap on a
    // held-open poll fragments the ~57 KB heap below DERP's ~6 KB TLS block and
    // OOM-aborts (observed live). We already have the authoritative netmap from
    // the non-streaming publish, so omitting it on the keepalive is free. Kept
    // out of the serialized body when false (skip_serializing_if) so the
    // publish request stays byte-identical.
    #[serde(skip_serializing_if = "is_false")]
    omit_peers: bool,
}

/// serde `skip_serializing_if` predicate for a plain bool field.
fn is_false(b: &bool) -> bool { !*b }


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
                        // No retry (v2 follow-up, see docs/wg-dataplane-notes.md
                        // "Bring-up timeout"): end run() so `events` is
                        // dropped and the closed channel cascades through
                        // the event router to `Runtime::connect`'s readiness
                        // race (our_ip_tx's sender lives inside the event
                        // router and is dropped once it sees this channel
                        // close), rather than leaving this task parked on
                        // `cmds.recv()` forever with no one left to send it
                        // another command.
                        break;
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
        // Bring-up (TCP + Noise + register + non-streaming publish, up to
        // and including OurIpAssigned) is the ONLY phase bounded by
        // `connect_timeout`. It is wrapped in `tokio::time::timeout` below
        // when a deadline is configured. The streaming poll that follows
        // (Step 8 & 9, further down this function) gets NO deadline: it
        // must run unbounded (drain-and-discard, already implemented in
        // `stream_map_response`) so the ephemeral node stays online. See
        // docs/wg-dataplane-notes.md "Bring-up timeout".
        let connect_timeout = self.config.connect_timeout;
        let bring_up = self.bring_up(auth_key, events);
        let (mut main_conn, mut noise, mut h2, node_key_hex) = match connect_timeout {
            Some(dur) => tokio::time::timeout(dur, bring_up).await.map_err(|_| {
                tracing::error!("Control bring-up exceeded connect_timeout ({:?})", dur);
                ControlError::Timeout
            })??,
            None => bring_up.await?,
        };

        // Step 8 & 9: streaming keepalive poll, kept alive across drops.
        //
        // OurIpAssigned has already fired (during bring-up), so from here this
        // never returns on success: it holds the streaming poll and, whenever
        // that poll ends, reconnects and reopens it. A returning poll is NOT a
        // graceful stop -- `Ok(())` means the server closed the stream and
        // `Err` means a poll/transport error -- and either way, if we simply
        // returned, `run()` would park on `cmds.recv()` forever and the node
        // would go stale (control plane "offline") within a minute. Reconnect
        // with capped backoff instead. The FIRST bring-up above is deliberately
        // outside this loop so its failure still propagates to Device::connect's
        // readiness race; every reconnect below is post-readiness.
        let mut backoff = core::time::Duration::from_secs(1);
        loop {
            // (Re)open the streaming keepalive request on the current
            // connection. Hostinfo is required by the control server on EVERY
            // MapRequest, streaming included: omitting it makes the server
            // answer the poll with `400 "Hostinfo required in MapRequest"` and
            // immediately close the stream, so the keepalive never holds and
            // the node goes stale even though the data plane stays up. See the
            // publish request above and Bug 3 in docs/wg-dataplane-notes.md.
            // DiscoKey/Endpoints are read-only on a Stream=true request
            // (cap >= 68) so they stay None; the authoritative values were
            // already published non-streaming during bring-up.
            let poll_res = async {
                let map_body = to_json_buf(&MapRequest {
                    version: CAPABILITY_VERSION, compress: "", keep_alive: true,
                    node_key: node_key_hex.as_str(), endpoints: &[], stream: true,
                    disco_key: None,
                    hostinfo: Some(host_info(&self.config, None)),
                    omit_peers: true,
                }).map_err(ControlError::Json)?;
                let map_req = build_h2_post("/machine/map", self.config.control_host, MAP_STREAM_ID, &map_body);
                noise.write_all(&mut main_conn, &map_req).await?;
                self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, MAP_STREAM_ID, true).await
            }.await;

            match poll_res {
                Ok(_) => tracing::warn!("Tailscale keepalive stream closed by server; reconnecting"),
                Err(e) => tracing::warn!("Tailscale keepalive stream error: {:?}; reconnecting", e),
            }

            // A dead keepalive stream usually means a dead connection, so
            // re-establish the whole thing (fresh TCP + Noise + register +
            // publish) rather than just re-issuing the request. Backoff caps at
            // 30s so a persistently failing control server is retried, not
            // hammered. bring-up failures here do NOT propagate (readiness is
            // already resolved); we just keep retrying.
            tokio::time::sleep(backoff).await;
            backoff = core::cmp::min(backoff.saturating_mul(2), core::time::Duration::from_secs(30));
            match self.bring_up(auth_key, events).await {
                Ok((c, n, h, _)) => {
                    main_conn = c; noise = n; h2 = h;
                    backoff = core::time::Duration::from_secs(1);
                    info!("Tailscale keepalive reconnected (bring-up ok)");
                }
                Err(e) => tracing::warn!("Tailscale keepalive reconnect bring-up failed: {:?}; will retry", e),
            }
        }
    }

    /// Bring-up only: TCP + Noise + register + the non-streaming publish
    /// MapRequest and its parse (which emits `MapUpdate` + `OurIpAssigned`
    /// via `stream_map_response`). No deadline is applied inside this
    /// function itself — the caller (`connect_and_poll`) wraps the call in
    /// `tokio::time::timeout` when `connect_timeout` is set.
    async fn bring_up(&mut self, auth_key: &str,
                       events: &async_channel::Sender<ControlEvent>)
        -> Result<(TokioStream, NoiseChannel, H2State, heapless::String<80>), ControlError>
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
            let reg_body = to_json_buf(&RegisterRequest {
                version: CAPABILITY_VERSION, node_key: node_key_hex.as_str(),
                old_node_key: None,
                auth: RegisterAuth { auth_key },
                hostinfo: host_info(&self.config, None),
            }).map_err(ControlError::Json)?;

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
            // Publish #1 (the "probe"): publish Hostinfo + DiscoKey with NO
            // endpoints/home yet. We cannot know our DERP home until the
            // response reveals the DERPMap, so this write's only job here is to
            // register the disco key and fetch the netmap. select_home_region
            // then runs on the parsed response and publish #2 (below) advertises
            // the chosen home. This is the standard Tailscale cold-boot order.
            let publish_body = to_json_buf(&MapRequest {
                version: CAPABILITY_VERSION, compress: "", keep_alive: false,
                node_key: node_key_hex.as_str(), endpoints: &[], stream: false,
                disco_key: Some(disco_key_hex.as_str()),
                hostinfo: Some(host_info(&self.config, None)),
                omit_peers: false,
            }).map_err(ControlError::Json)?;

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
        let home_region = self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, MAP_PUBLISH_STREAM_ID, true).await?;

        // Step 7.6 (new): re-publish with our DERP home so peers get a stable
        // relay path to us. Encoded two ways, together, per the confirmed
        // recipe in tools/wg_validator/validate_live_tailnet.py:
        //   - Endpoints = ["127.3.3.40:<region>"] (the derpMagicIP home hint)
        //   - Hostinfo.NetInfo.PreferredDERP = <region>
        // <region> comes from select_home_region on publish #1's netmap; the
        // runtime picks the same region from the same MapUpdate and connects
        // its DERP session there, so advertised == actual. Without this,
        // peers have no durable path to us and inbound dies once their disco
        // caches go stale (e.g. after we reboot on a now-stable tailnet IP).
        if let Some(region) = home_region {
            let disco_key_hex = self.node_state.disco_key.public().to_hex();
            let lan_ep = self.config.lan_udp_port.and_then(|port| {
                let ep = main_conn.inner().local_addr().ok().and_then(|la| lan_endpoint(la, port));
                match ep {
                    Some(ep) if PUBLISH_LAN_ENDPOINT => info!("lan-direct: publishing LAN endpoint {}", ep),
                    Some(ep) => info!("lan-direct: LAN endpoint {} computed, not published yet", ep),
                    None => tracing::warn!("lan-direct: control socket has no usable LAN IPv4; DERP-only"),
                }
                ep
            });
            let published_lan = if PUBLISH_LAN_ENDPOINT { lan_ep } else { None };
            info!("Tailscale Step 7.6: re-publishing with PreferredDERP={} endpoint={}:{}", region, DERP_MAGIC_IP, region);
            let republish_body = publish2_body(
                &self.config, node_key_hex.as_str(), disco_key_hex.as_str(), region, published_lan,
            ).map_err(ControlError::Json)?;
            let republish_req = build_h2_post("/machine/map", host, MAP_REPUBLISH_STREAM_ID, &republish_body);
            noise.write_all(&mut main_conn, &republish_req).await?;
            // Drain + parse the response (re-emits the authoritative netmap,
            // which is idempotent for the runtime: same IP -> netif no-op,
            // repeat DERP Connect ignored). Its own return value is unused.
            let _ = self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, MAP_REPUBLISH_STREAM_ID, false).await?;
        } else {
            tracing::warn!("Tailscale Step 7.6: no reachable DERP region in netmap; skipping home advertisement (inbound may be unreliable)");
        }

        // Bring-up complete: OurIpAssigned has been emitted. Hand the live
        // connection state back to `connect_and_poll`, which continues with
        // the UNBOUNDED streaming poll (Step 8 & 9) — no timeout applies
        // past this point.
        Ok((main_conn, noise, h2, node_key_hex))
    }

    /// Returns the DERP home region selected from the parsed netmap (via
    /// `select_home_region`), if this response carried a non-empty map. The
    /// caller re-publishes with this as its `PreferredDERP`; the runtime picks
    /// the same region from the same `MapUpdate`. `None` for empty responses
    /// (e.g. the keepalive poll), whose return value the caller ignores.
    async fn stream_map_response<S: embedded_io_async::Read + embedded_io_async::Write>(
        &self, stream: &mut S, noise: &mut NoiseChannel,
        h2: &mut H2State, events: &async_channel::Sender<ControlEvent>,
        expected_stream: u32, emit_events: bool,
    ) -> Result<Option<u16>, ControlError> {
        info!("Tailscale stream_map_response starting on stream {} (emit_events={})", expected_stream, emit_events);
        // Home region selected from the parsed netmap; returned to the caller.
        let mut home_region: Option<u16> = None;
        // Fixed-capacity scratch buffer (heapless, no heap allocation).
        //
        // Replaces the previous `Vec<u8>` that grew via `resize(blen, 0)` and
        // never shrank: once a frame length crossed 4096 the Vec doubled to
        // 8192 and OOM-aborted on the fragmented ESP32-C3 heap
        // ("memory allocation of 8192 bytes failed"). `INITIAL_WINDOW`
        // (see tm_h2) is 4096, so the control server is flow-control-limited
        // to <= 4096-byte DATA frames; a 4096 cap matches the real wire
        // contract and can never request more than 4096 contiguous bytes.
        // `read_exact` below overwrites the whole range, so we never zero-fill.
        const FRAME_BUF_CAP: usize = 4096;
        let mut frame_buf: heapless::Vec<u8, FRAME_BUF_CAP> = heapless::Vec::new();
        // Both the non-streaming publish and the streaming poll frame each
        // MapResponse as a 4-byte-LE length prefix + JSON (per
        // tools/wg_validator/ts_control.py's read_full_body/read_stream_message
        // + write_map), which `map_stream` parses incrementally.
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
        // Streaming (push) parse: the MapResponse body is fed to actson as the
        // decrypted DATA frames arrive, so the ~34-48 KB netmap is never held in
        // one contiguous allocation (which try_reserve_exact could not satisfy
        // on the fragmented heap, forcing us to discard the whole netmap and
        // lose the data plane). Only actson's ~1 KB feeder ring and the fixed
        // MapState are ever resident. See map_stream. `fed` counts body bytes
        // fed for the current message so we know when `mlen` is complete.
        let mut parser: Option<map_stream::MapStreamParser<8, 4>> = None;
        let mut fed = 0usize;
        let mut prefix = [0u8; 4];
        let mut prefix_have = 0usize;
        let mut cur_len: Option<usize> = None;
        let mut our_ip_sent = false;
        // The streaming keepalive poll (MAP_STREAM_ID) is a live HTTP/2 stream
        // the control server watches: per ts_control.py's start_keepalive_poll,
        // the server only keeps OUR node marked online while we keep draining
        // it. The non-streaming publish (MAP_PUBLISH_STREAM_ID) is a one-shot
        // snapshot that must still parse and return at end_stream, so only the
        // streaming caller gets drain-and-discard on a length desync below.
        let streaming = expected_stream == MAP_STREAM_ID;
        // Drain-and-discard the streaming keepalive body from the very first
        // byte: we deliberately never allocate or parse it.
        //
        // Once Hostinfo is included (see connect_and_poll), the server answers
        // the Stream=true poll with the FULL netmap first (~34 KB of JSON,
        // length-prefixed) and then holds the stream open for keepalives.
        // try_reserve_exact-ing that 34 KB on a device with ~65 KB free and a
        // ~40 KB DERP TLS connection to stand up next exhausts the heap and
        // aborts (observed live: "memory allocation of 6052 bytes failed" in
        // DerpTls::connect right after this poll). We do not need the streaming
        // netmap anyway: the authoritative snapshot (our IP, peers, DERPMap)
        // already came from the non-streaming publish during bring-up. So we
        // consume every byte, keep sending WINDOW_UPDATEs (flow control below),
        // and stay in the read loop so the server keeps us marked online, but
        // allocate nothing. Parsing streaming deltas (to pick up peers that
        // come online after boot) is the deferred v2 of card t_e34afeed.
        let mut discarding = streaming;

        loop {
            let mut hdr_bytes = [0u8; 9];
            noise.read_exact(stream, &mut hdr_bytes).await?;
            let hdr = FrameHeader::from_bytes(&hdr_bytes);

            if hdr.length > MAX_FRAME_SIZE {
                return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length)));
            }
            let blen = hdr.length as usize;
            if blen > FRAME_BUF_CAP {
                // Never allocate beyond the fixed cap; the server is
                // INITIAL_WINDOW-limited to <= 4096-byte DATA frames. Bail
                // gracefully (same as the MAX_FRAME_SIZE guard above) rather
                // than OOMing on a doubling allocation.
                return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length)));
            }
            // blen <= FRAME_BUF_CAP guaranteed above, so this never fails.
            let _ = frame_buf.resize(blen, 0);
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
                    let mut pos = if discarding { payload.len() } else { 0usize };
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
                                // Desynced/garbage length prefix. Discard the rest
                                // of the stream to end_stream (rather than return
                                // and orphan unread frames) so the connection stays
                                // byte-consistent for the next request. Applies to
                                // both the streaming keepalive (stay online) and the
                                // non-streaming publish.
                                info!("Tailscale stream_map_response: implausible message length {} on stream {}, discarding rest of stream", mlen, expected_stream);
                                discarding = true;
                                prefix_have = 0;
                                cur_len = None;
                                break;
                            }
                            // Start a fresh streaming parse for this message. No
                            // `mlen`-byte allocation happens here or below: body
                            // bytes are pushed into actson's bounded feeder as
                            // they arrive, so a netmap too large to buffer (a
                            // ~47 KB map on a fragmented ~57 KB heap, inflated by
                            // ephemeral ghost peers) still parses instead of
                            // forcing a discard that would drop the data plane.
                            parser = Some(map_stream::MapStreamParser::new());
                            fed = 0;
                            cur_len = Some(mlen);
                        }

                        // Phase 2: feed body bytes up to the known length.
                        let want = cur_len.unwrap();
                        let take = core::cmp::min(want - fed, payload.len() - pos);
                        if let Some(p) = parser.as_mut() {
                            // A feed error is recorded inside the parser and
                            // surfaced by finish(); we keep consuming every body
                            // byte regardless so the stream stays byte-consistent.
                            let _ = p.push(&payload[pos..pos + take]);
                        }
                        pos += take;
                        fed += take;
                        if fed < want { break; }

                        // Complete message: finish the parse + emit, then reset.
                        let parsed = parser.take().map(|p| p.finish());
                        match parsed {
                            Some(Ok(map)) => {
                                if emit_events && !our_ip_sent && map.our_ip.0 != [0u8; 4] {
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
                                    // Select our DERP home from the same snapshot
                                    // the runtime will get, so both agree (see
                                    // select_home_region). Computed before `map`
                                    // is moved into the event.
                                    if let Some(hr) = select_home_region(&map) {
                                        home_region = Some(hr);
                                    }
                                    if emit_events {
                                        info!("Tailscale MapUpdate event sent ({} peers, {} DERP regions, home_derp={:?})", map.peers.len(), map.derp_regions.len(), home_region);
                                        let _ = events.send(ControlEvent::MapUpdate(Box::new(map))).await;
                                    } else {
                                        // Publish #2 drain: parsed only to complete
                                        // the stream; the runtime already has this
                                        // netmap from publish #1, so re-emitting
                                        // would double OurIpAssigned/MapUpdate.
                                        info!("Tailscale MapResponse parsed, not re-emitted ({} peers, {} DERP regions, home_derp={:?})", map.peers.len(), map.derp_regions.len(), home_region);
                                    }
                                } else {
                                    info!("Tailscale MapUpdate skipped (empty snapshot)");
                                }
                            }
                            Some(Err(e)) => { info!("Tailscale map_stream parse error: {:?}", e); }
                            None => {} // unreachable: parser is Some for a non-discarding message
                        }
                        // Drop the parser before reading the next message so two
                        // parse states never coexist.
                        parser = None;
                        fed = 0;
                        cur_len = None;
                        prefix_have = 0;
                    }

                    if end_stream { info!("Tailscale stream ended"); return Ok(home_region); }
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
    async fn open_tcp(&self, host: &str, port: u16) -> Result<TokioStream, ControlError> {
        let s = tokio::net::TcpStream::connect((host, port)).await.map_err(|_| ControlError::Io)?;
        tracing::debug!("open_tcp: connected local={:?} peer={:?} nodelay={:?}", s.local_addr(), s.peer_addr(), s.nodelay());
        Ok(TokioStream::new(s))
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

async fn read_one_h2_body<S: embedded_io_async::Read + embedded_io_async::Write>(
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
    // Fixed-capacity scratch frame buffer (heapless, no heap allocation).
    //
    // Replaces the previous `Vec<u8>` that grew via `resize(blen, 0)` and
    // never shrank: once a frame length crossed 4096 the Vec doubled to 8192
    // and OOM-aborted on the fragmented ESP32-C3 heap
    // ("memory allocation of 8192 bytes failed"). `INITIAL_WINDOW`
    // (tm_h2) is 4096, so the server is flow-control-limited to <= 4096-byte
    // DATA frames; a 4096 cap matches the real wire contract and can never
    // request more than 4096 contiguous bytes. `read_exact` overwrites the
    // whole range, so we never zero-fill.
    const FB_CAP: usize = 4096;
    let mut fb: heapless::Vec<u8, FB_CAP> = heapless::Vec::new();
    loop {
        let mut hb = [0u8; 9];
        debug!("read_one_h2_body[{}]: awaiting frame header (body so far {} B)", expected_stream, body.len());
        noise.read_exact(stream, &mut hb).await?;
        let hdr = FrameHeader::from_bytes(&hb);
        debug!("read_one_h2_body[{}]: frame type={} flags={} stream={} len={}", expected_stream, hdr.frame_type, hdr.flags, hdr.stream_id, hdr.length);
        if hdr.length > MAX_FRAME_SIZE { return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length))); }
        let blen = hdr.length as usize;
        if blen > FB_CAP {
            // Never allocate beyond the fixed cap; the server is
            // INITIAL_WINDOW-limited to <= 4096-byte DATA frames. Bail
            // gracefully (same as the MAX_FRAME_SIZE guard above) rather
            // than OOMing on a doubling allocation.
            return Err(ControlError::H2(H2Error::FrameTooLarge(hdr.length)));
        }
        // blen <= FB_CAP guaranteed above, so this never fails.
        let _ = fb.resize(blen, 0);
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

// ── Tests ────────────────────────────────────────────────────────────────────
//
// Host-only: exercises `ControlActor::run` against a local `TcpListener`
// stand-in for the control server, so no real Noise/H2 handshake needs to
// complete. These only need bring-up (the Noise handshake read, which the
// stand-in server never answers) to hang long enough for `connect_timeout`
// to matter.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn leak_host(addr: std::net::SocketAddr) -> &'static str {
        Box::leak(addr.ip().to_string().into_boxed_str())
    }

    fn region(id: u16, latency_ms: u16) -> DerpRegion {
        DerpRegion {
            region_id: id,
            region_code: heapless::String::new(),
            host: heapless::String::new(),
            port: 443,
            latency_ms,
        }
    }

    fn peer(derp_region: u16, is_online: bool) -> PeerInfo {
        PeerInfo {
            node_key: [0u8; 32],
            disco_key: [0u8; 32],
            tailnet_ip: TailnetIp([0u8; 4]),
            prefix_len: 32,
            hostname: heapless::String::new(),
            derp_region,
            is_online,
        }
    }

    fn map_of(regions: &[DerpRegion], peers: &[PeerInfo]) -> MapState {
        let mut m = MapState { our_ip: TailnetIp([100, 64, 0, 1]), peers: ArrayVec::new(), derp_regions: ArrayVec::new() };
        for r in regions { m.derp_regions.push(r.clone()); }
        for p in peers { m.peers.push(p.clone()); }
        m
    }

    #[test]
    fn home_region_prefers_where_most_online_peers_live() {
        // Regions 1, 5, 9 all reachable. Online peers cluster on 5.
        let m = map_of(
            &[region(1, 0), region(5, 0), region(9, 0)],
            &[peer(5, true), peer(5, true), peer(9, true), peer(1, false)],
        );
        assert_eq!(select_home_region(&m), Some(5));
    }

    #[test]
    fn home_region_ignores_regions_we_cannot_reach() {
        // Most online peers are homed on region 12, but we have no DERP host
        // for it (not in the DERPMap), so it must not be chosen.
        let m = map_of(
            &[region(1, 30), region(2, 10)],
            &[peer(12, true), peer(12, true), peer(2, true)],
        );
        assert_eq!(select_home_region(&m), Some(2));
    }

    #[test]
    fn home_region_falls_back_to_lowest_latency_then_id_without_online_peers() {
        // No online peer homed on a reachable region -> lowest latency wins,
        // ties break to lowest id.
        let m = map_of(&[region(3, 50), region(7, 20), region(4, 20)], &[]);
        assert_eq!(select_home_region(&m), Some(4));
    }

    #[test]
    fn home_region_none_when_no_regions() {
        let m = map_of(&[], &[peer(5, true)]);
        assert_eq!(select_home_region(&m), None);
    }

    async fn run_once(config: Config) -> ControlEvent {
        let node_state = NodeState::generate();
        let actor = ControlActor::new(config, node_state);

        let (cmd_tx, cmd_rx) = async_channel::bounded::<ControlCmd>(2);
        let (ev_tx, ev_rx) = async_channel::bounded::<ControlEvent>(4);

        cmd_tx.send(ControlCmd::Start {
            auth_key: heapless::String::try_from("tskey-test").unwrap(),
        }).await.unwrap();
        cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        drop(cmd_tx);

        // `run()` itself must never hang past a reasonable outer bound: if
        // `connect_timeout` isn't actually enforced, this outer timeout is
        // what fails the test (rather than the test hanging forever).
        tokio::time::timeout(Duration::from_secs(5), actor.run(cmd_rx, ev_tx))
            .await
            .expect("ControlActor::run must return promptly, not hang");

        ev_rx.recv().await.expect("expected a ControlEvent")
    }

    /// Bring-up (the Noise handshake read) exceeding a tiny `connect_timeout`
    /// must yield `ControlEvent::Error(ControlError::Timeout)` and `run()`
    /// must return cleanly (no streamer exists yet, so nothing to tear down).
    #[tokio::test]
    async fn bring_up_timeout_emits_error_and_returns() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept the connection but never write a response: the Noise
        // handshake's read half hangs forever, so only `connect_timeout`
        // can end `bring_up`.
        tokio::spawn(async move {
            let (_sock, _peer) = listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let config = Config {
            control_host: leak_host(addr),
            control_port: addr.port(),
            control_pin: [0u8; 32],
            connect_timeout: Some(Duration::from_millis(50)),
            lan_udp_port: None,
            hostname: "esp32c3",
            services: &[],
        };

        match run_once(config).await {
            ControlEvent::Error(ControlError::Timeout) => {}
            ControlEvent::Error(_) => panic!("expected ControlError::Timeout, got a different ControlError"),
            _ => panic!("expected ControlEvent::Error, got a different ControlEvent"),
        }
    }

    /// `connect_timeout: None` must disable the deadline entirely: a
    /// bring-up failure in this mode must never surface as
    /// `ControlError::Timeout` (there is no deadline to exceed).
    #[tokio::test]
    async fn none_connect_timeout_disables_deadline() {
        // Bind then immediately drop, so nothing listens on this port and
        // the TCP connect fails fast (connection refused) rather than
        // hanging — proving absence of `ControlError::Timeout` isn't just
        // because the (nonexistent) deadline hasn't fired yet.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = Config {
            control_host: leak_host(addr),
            control_port: addr.port(),
            control_pin: [0u8; 32],
            connect_timeout: None,
            lan_udp_port: None,
            hostname: "esp32c3",
            services: &[],
        };

        match run_once(config).await {
            ControlEvent::Error(ControlError::Timeout) => {
                panic!("connect_timeout: None must never produce ControlError::Timeout");
            }
            ControlEvent::Error(_) => {} // any other connect error is expected
            _ => panic!("expected ControlEvent::Error"),
        }
    }

    // ── Step 3 of docs/lan-direct-path-plan.md: LAN endpoint, unpublished ──

    fn cfg(services: &'static [Service]) -> Config {
        Config {
            control_host: "localhost", control_port: 80, control_pin: [0u8; 32],
            connect_timeout: None, lan_udp_port: None, hostname: "esp32c3", services,
        }
    }

    const NODE_HEX: &str = "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const DISCO_HEX: &str = "discokey:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";

    /// With a LAN endpoint, publish #2 must carry the same fields and
    /// values as ts_control.py's write_map (the client that is known to
    /// publish endpoints successfully), per gen_publish2_lan_vector.py.
    /// Compared as parsed JSON: Python orders keys and spaces them
    /// differently, and the control server does not care about either.
    /// The only intended difference is Hostinfo.OS, which the Python probe
    /// hard-codes to "linux".
    #[test]
    fn publish2_with_lan_endpoint_matches_ts_control_write_map() {
        let lan = lan_endpoint("192.168.15.20:50000".parse().unwrap(), 41641);
        let body = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, 11, lan).unwrap();
        let ours: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut py: serde_json::Value = serde_json::from_str(include_str!(
            "../../tools/wg_validator/publish2_lan_body.json")).unwrap();
        assert_eq!(py["Hostinfo"]["OS"], "linux");
        py["Hostinfo"]["OS"] = "embedded".into();
        let mut ours = ours;
        // Identity fields the Python probe does not send.
        for k in ["IPNVersion", "App", "Machine"] {
            assert!(ours["Hostinfo"].as_object_mut().unwrap().remove(k).is_some(), "{k}");
        }
        assert_eq!(ours, py);
        assert_eq!(ours["Endpoints"][0], "192.168.15.20:41641", "LAN endpoint goes first");
    }

    /// With no LAN endpoint (feature off, filter rejected it, or publishing
    /// still switched off), the body must be exactly what bring_up sent
    /// before Step 3. The expected bytes are built the way the old inline
    /// code built them.
    #[test]
    fn publish2_without_lan_endpoint_is_byte_identical_to_derp_only() {
        let region = 11u16;
        let home_endpoint = format!("{}:{}", DERP_MAGIC_IP, region);
        let endpoints = [home_endpoint.as_str()];
        let old = to_json_buf(&MapRequest {
            version: CAPABILITY_VERSION, compress: "", keep_alive: false,
            node_key: NODE_HEX, endpoints: &endpoints, stream: false,
            disco_key: Some(DISCO_HEX),
            hostinfo: Some(host_info(&cfg(&[]), Some(NetInfo { preferred_derp: region }))),
            omit_peers: false,
        }).unwrap();
        let new = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, region, None).unwrap();
        assert_eq!(new.as_slice(), old.as_slice());
    }

    /// Step 5 turned this on together with UDP PONG and UDP WireGuard
    /// ingest (D4). Publishing still needs a bound port: with none (feature
    /// off, or bind failed) the endpoint cannot leak into the body.
    #[test]
    fn lan_endpoint_published_only_with_a_bound_port() {
        assert!(PUBLISH_LAN_ENDPOINT);
        let no_port: Option<u16> = None;
        let ep = no_port.and_then(|p| lan_endpoint("192.168.15.20:50000".parse().unwrap(), p));
        assert_eq!(ep, None);
    }

    #[test]
    fn lan_endpoint_filter_per_d1() {
        let f = |s: &str| lan_endpoint(s.parse().unwrap(), 41641);
        assert_eq!(f("100.64.1.2:1234"), None, "tailnet CGNAT range");
        assert_eq!(f("100.127.255.254:1234"), None, "top of 100.64/10");
        assert_eq!(f("127.0.0.1:1234"), None);
        assert_eq!(f("0.0.0.0:1234"), None);
        assert_eq!(f("[fd7a:115c:a1e0::1]:1234"), None, "v6 is out of scope");
        assert_eq!(f("192.168.15.20:1234"), Some("192.168.15.20:41641".parse().unwrap()));
        assert_eq!(f("8.8.4.4:1234"), Some("8.8.4.4:41641".parse().unwrap()), "public v4");
        assert_eq!(f("100.63.0.1:1234"), Some("100.63.0.1:41641".parse().unwrap()), "just below 100.64/10");
        assert_eq!(f("100.128.0.1:1234"), Some("100.128.0.1:41641".parse().unwrap()), "just above 100.64/10");
        assert_eq!(lan_endpoint("192.168.15.20:1".parse().unwrap(), 0), None, "port 0 is not reachable");
    }

    static ONE: [Service; 1] = [Service::tcp(80, "tasmolike HTTP")];
    static FOUR: [Service; 4] = [
        Service::tcp(80, "0123456789abcdef0123456789abcdef"),
        Service::tcp(443, "0123456789abcdef0123456789abcdef"),
        Service::udp(5353, "0123456789abcdef0123456789abcdef"),
        Service::tcp(8080, "0123456789abcdef0123456789abcdef"),
    ];

    #[test]
    fn hostinfo_reports_identity() {
        let body = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, 11, None).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["Hostinfo"]["IPNVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["Hostinfo"]["App"], "tailmicro");
        assert_eq!(v["Hostinfo"]["Machine"], std::env::consts::ARCH);
    }

    #[test]
    fn publish2_carries_hostname_and_services() {
        let c = Config { hostname: "kitchen-1", ..cfg(&ONE) };
        let body = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, None).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["Hostinfo"]["Hostname"], "kitchen-1");
        assert_eq!(v["Hostinfo"]["Services"],
                   serde_json::json!([{"Proto": "tcp", "Port": 80, "Description": "tasmolike HTTP"}]));
    }

    /// headscale replaces Hostinfo from any request, so all four must agree.
    #[test]
    fn every_request_carries_the_same_services() {
        let c = cfg(&ONE);
        let reg = to_json_buf(&RegisterRequest {
            version: CAPABILITY_VERSION, node_key: NODE_HEX, old_node_key: None,
            auth: RegisterAuth { auth_key: "tskey-auth-x" }, hostinfo: host_info(&c, None),
        }).unwrap();
        let poll = to_json_buf(&MapRequest {
            version: CAPABILITY_VERSION, compress: "", keep_alive: true,
            node_key: NODE_HEX, endpoints: &[], stream: true, disco_key: None,
            hostinfo: Some(host_info(&c, None)), omit_peers: true,
        }).unwrap();
        let pub2 = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, None).unwrap();
        let svc = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap()["Hostinfo"]["Services"].clone();
        assert!(!svc(&reg).is_null());
        assert_eq!(svc(&reg), svc(&poll));
        assert_eq!(svc(&reg), svc(&pub2));
    }

    #[test]
    fn max_services_fit_the_request_cap() {
        let c = Config { hostname: "a-63-char-label-0123456789-0123456789-0123456789-0123456789", ..cfg(&FOUR) };
        assert!(check_services(&FOUR).is_ok());
        let lan = lan_endpoint("192.168.15.20:50000".parse().unwrap(), 41641);
        let body = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, lan).unwrap();
        assert!(body.len() <= REQUEST_BODY_CAP);
        let reg = to_json_buf(&RegisterRequest {
            version: CAPABILITY_VERSION, node_key: NODE_HEX, old_node_key: Some(NODE_HEX),
            auth: RegisterAuth { auth_key: &"k".repeat(128) }, hostinfo: host_info(&c, None),
        }).unwrap();
        assert!(reg.len() <= REQUEST_BODY_CAP);
    }

    #[test]
    fn service_and_hostname_validation() {
        assert!(check_services(&[Service::tcp(0, "")]).is_err());
        assert!(check_services(&[Service::tcp(80, "0123456789abcdef0123456789abcdef0")]).is_err());
        assert!(check_services(&[Service::tcp(80, ""); MAX_SERVICES + 1]).is_err());
        assert!(valid_hostname("esp32c3") && valid_hostname("a-b"));
        for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"a".repeat(64)] {
            assert!(!valid_hostname(bad), "{bad}");
        }
    }
}
