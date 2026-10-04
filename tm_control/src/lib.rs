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
pub mod roster;
pub mod pin;
pub mod login;
pub mod rfc3339;
pub mod selfnode;
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
use roster::Roster;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_key:    [u8; 32],
    pub disco_key:   [u8; 32],
    pub tailnet_ip:  TailnetIp,
    pub prefix_len:  u8,
    pub hostname:    heapless::String<64>,
    /// MagicDNS identity from the peer's `Name` (not its `Hostinfo.Hostname`).
    pub name:        PeerName,
    pub derp_region: u16,
    pub is_online:   bool,
}

/// Longest MagicDNS label kept per peer. A longer label (a DNS label may be
/// 63) leaves the peer routable but not resolvable by name.
pub const MAX_NAME_LABEL: usize = 32;
/// Longest tailnet suffix kept (`tailnet-xyz.ts.net` is 18).
pub const MAX_NAME_SUFFIX: usize = 48;

/// A node's MagicDNS name reduced to what a name table needs: the first label
/// (lowercased) and a 16-bit hash of the suffix after it. Every node of one
/// tailnet shares the suffix, so it is stored once, in [`MapNames`], instead
/// of per peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerName {
    pub label:       heapless::String<MAX_NAME_LABEL>,
    pub suffix_hash: u16,
}

/// Self-node and `DNSConfig` data for MagicDNS.
#[derive(Clone, Debug, Default)]
pub struct MapNames {
    /// Our own label, from `Node.Name`.
    pub self_label: heapless::String<MAX_NAME_LABEL>,
    /// The tailnet suffix, no leading or trailing dot. Empty when the control
    /// server names nodes with a bare label (headscale with no `base_domain`).
    pub suffix: heapless::String<MAX_NAME_SUFFIX>,
    pub suffix_hash: u16,
    /// `DNSConfig.Proxied`: MagicDNS is on, so short names resolve.
    pub proxied: bool,
}

/// Split a node `Name` (`host.tailnet.ts.net.`, or just `host`) into its
/// lowercased first label and the suffix after it, with the trailing dot
/// dropped. The label is empty if it does not fit [`MAX_NAME_LABEL`].
pub fn split_node_name(name: &str) -> (heapless::String<MAX_NAME_LABEL>, &str) {
    let name = name.strip_suffix('.').unwrap_or(name);
    let (label, suffix) = name.split_once('.').unwrap_or((name, ""));
    let mut out = heapless::String::new();
    if label.len() <= MAX_NAME_LABEL {
        for c in label.chars() {
            let _ = out.push(c.to_ascii_lowercase());
        }
    }
    (out, suffix)
}

/// FNV-1a folded to 16 bits, over the lowercased bytes. Only used to tell a
/// peer in our tailnet's suffix from a node shared in from another tailnet.
pub fn suffix_hash(suffix: &str) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for b in suffix.bytes() {
        h = (h ^ u32::from(b.to_ascii_lowercase())).wrapping_mul(0x0100_0193);
    }
    ((h >> 16) ^ h) as u16
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
    pub names:        MapNames,
}

// ── Capability version ────────────────────────────────────────────────────────

/// Capability version we advertise. Cap 72 does NOT gate streamed deltas (the
/// comment here used to claim it avoids `PeerChangesDelta`): `OnlineChange` is
/// cap 16, `PeersChangedPatch` cap 33 (DERPRegion) and 36 (Key, DiscoKey,
/// Online), and cap 72 itself is only a UPnP fix. A cap-72 client therefore
/// receives `PeersChanged`, `PeersRemoved`, patches and online changes on a
/// streaming poll, and `map_stream` decodes all of them. The number is left
/// alone because lowering or raising it would change nothing we depend on.
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
///
/// Order on the wire is register (1), publish #1 (3), the streaming poll (5),
/// then publish #2 (7). Publish #2 comes AFTER the poll is open because the
/// DERPMap it needs to pick a home region now arrives as the poll's first
/// message (the publishes are `OmitPeers=true` "lite" requests that answer
/// with an empty 200). Stream ids must increase in the order requests are
/// opened (RFC 7540 5.1.1), so the poll takes 5 and publish #2 takes 7.
/// Fallback re-polls continue from 9.
const MAP_REPUBLISH_STREAM_ID: u32 = 7;
const MAP_STREAM_ID: u32 = 5;
const FIRST_REPOLL_STREAM_ID: u32 = 9;
/// Read watchdog on the streaming poll: if no frame of any kind arrives for
/// this long, the connection is treated as dead and re-established.
///
/// The server sends a keepalive MapResponse about every 50-59 s (headscale:
/// 50 s plus jitter; Tailscale control similar), so a healthy stream is never
/// silent for more than a minute. 90 s is that interval plus ~50% margin: a
/// single late keepalive does not cause a reconnect, while a half-open TCP
/// connection (AP dropped us, NAT mapping expired) is noticed within a
/// minute and a half instead of never. Without it the poll could sit on a
/// dead stream forever, and control would learn nothing about the tailnet.
const POLL_IDLE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(90);
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
    /// that follows bring-up gets no overall deadline — it must run
    /// unbounded so the ephemeral node stays online — only the
    /// idle-read watchdog `POLL_IDLE_TIMEOUT`. See docs/wg-dataplane-notes.md
    /// "Bring-up timeout".
    pub connect_timeout: Option<core::time::Duration>,
    /// How often to re-fetch the full netmap on the live connection (a
    /// non-streaming `OmitPeers=false` MapRequest on a fresh stream, parsed
    /// like the bring-up publish) so peers that joined, left or moved while
    /// the long poll is open are picked up. `None` disables the timer; the
    /// router's on-miss `ControlCmd::Refresh` still works. See
    /// [`DEFAULT_REFRESH_INTERVAL`].
    pub refresh_interval: Option<core::time::Duration>,
    /// Port of the runtime's bound LAN UDP socket (`lan-direct` feature),
    /// or `None` when there is none. With `Some`, bring-up derives the LAN
    /// endpoint `<control-socket local IPv4>:<port>` (plan D1). It is only
    /// advertised once `PUBLISH_LAN_ENDPOINT` is on (Step 5, D4), because
    /// peers must not be pointed at a socket that cannot answer yet.
    pub lan_udp_port: Option<u16>,
    /// Public node key this node is renewing from. When set, every register
    /// request carries it as `OldNodeKey`, so control swaps the key on the
    /// existing node (same machine key, name and IP) instead of adding a node.
    /// `None` omits the field.
    pub old_node_key: Option<tm_keys::NodePublicKey>,
    /// Whether an interactive login may be waited for. With `false` an
    /// `AuthURL` answer ends bring-up at once with `ControlError::LoginRequired`
    /// and publishes no URL, so a silent renewal never leaves the device
    /// waiting for an approval.
    pub login_allowed: bool,
    /// Node name sent in every `Hostinfo`; control derives the MagicDNS name
    /// from it. Must satisfy [`valid_hostname`].
    pub hostname: &'static str,
    /// Free-form platform description sent as `Hostinfo.OSVersion` (the admin
    /// console shows it as the OS version); empty omits it. See
    /// [`check_os_version`].
    pub os_version: heapless::String<MAX_OS_VERSION>,
    /// Services advertised in every `Hostinfo`. Informational only: the
    /// control server hands them to peers, nothing enforces them. At most
    /// [`MAX_SERVICES`] entries, see [`check_services`].
    pub services: &'static [Service],
}

/// Services are re-sent in each of the four Hostinfos, so their size is
/// bounded to keep the bodies inside [`REQUEST_BODY_CAP`].
pub const MAX_SERVICES: usize = 4;

/// Default for [`Config::refresh_interval`]. Each re-poll costs one full
/// netmap (about 30-48 KB received on the real tailnet), so 10 minutes is
/// roughly 4-7 MB/day: a safety net, not the primary update path.
pub const DEFAULT_REFRESH_INTERVAL: core::time::Duration = core::time::Duration::from_secs(600);
/// Minimum spacing between two re-polls, whatever triggered them. Bounds the
/// radio and heap cost of a router that keeps missing (a misconfigured peer
/// or a stray packet to an unknown tailnet address) and the load on control.
pub const MIN_REFRESH_GAP: core::time::Duration = core::time::Duration::from_secs(120);
/// A re-poll whose response has not finished this long after the request was
/// sent is abandoned, so one lost response cannot block every later re-poll.
/// How long a burst of netmap deltas is gathered before one snapshot goes to
/// the runtime. A snapshot costs a heap-allocated `MapState` and a router diff;
/// control can send several deltas back to back (a peer joining is a
/// `PeersChanged` plus patches), and the window is not extended by later
/// deltas so a steady trickle still publishes every `EMIT_COALESCE`.
const EMIT_COALESCE: core::time::Duration = core::time::Duration::from_millis(200);
const REFRESH_RESPONSE_DEADLINE: core::time::Duration = core::time::Duration::from_secs(60);
pub const MAX_SERVICE_DESC: usize = 32;
pub const MAX_OS_VERSION: usize = 48;

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

/// Copy `v` into a `Config::os_version` value; `Err` with the reason if it is
/// too long or has anything but printable ASCII.
pub fn check_os_version(v: &str) -> Result<heapless::String<MAX_OS_VERSION>, &'static str> {
    if !v.bytes().all(|c| (0x20..0x7f).contains(&c)) { return Err("os_version must be printable ASCII"); }
    heapless::String::try_from(v).map_err(|_| "os_version too long")
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
                        /// overall deadline (see `PollIdle` for its watchdog). See `ControlActor::connect_and_poll`.
                        Timeout,
                        /// The streaming poll received nothing at all (no DATA,
                        /// PING, WINDOW_UPDATE...) for `POLL_IDLE_TIMEOUT`: the
                        /// server's keepalives stopped, so the connection is
                        /// presumed half-open. The poll loop reconnects.
                        PollIdle,
                        /// The pinned control key is not the server's: the server
                        /// closed the connection without answering the Noise
                        /// initiation on two consecutive dials. See
                        /// `NoiseError::NoResponse` and [`login::control_key_rejected`].
                        ControlKeyRejected,
                        /// Control asked for an interactive login while
                        /// `Config::login_allowed` is false (a silent renewal
                        /// that cannot be done without a person). Also left in
                        /// [`login::refusal`].
                        LoginRequired,
                        /// Control reports the node key as expired and offers
                        /// no login URL. Renewing needs a new node key sent
                        /// with `Config::old_node_key`, this time with login
                        /// allowed. Also left in [`login::refusal`].
                        NodeKeyExpired }
#[derive(Debug)]
pub enum NoiseError {
    Handshake, Decrypt, Encrypt,
    /// The server closed the connection cleanly without answering the
    /// upgrade request. See `read_101_response`: this is how a wrong pinned
    /// control key presents, so `bring_up` confirms it once more and then
    /// reports [`ControlError::ControlKeyRejected`].
    NoResponse,
}
#[derive(Debug)]
pub enum JsonError { InvalidUtf8, ParseError, MissingField }

impl From<H2Error> for ControlError { fn from(e: H2Error) -> Self { Self::H2(e) } }

// ── Actor messages ────────────────────────────────────────────────────────────

pub enum ControlCmd  {
    Start { auth_key: heapless::String<128> },
    Reauth,
    Shutdown,
    /// Ask for a fresh full netmap soon (a re-poll on the live connection).
    /// Sent by the router when it cannot route to an address, in case a peer
    /// joined after the last map. Advisory: requests that arrive inside
    /// `MIN_REFRESH_GAP` of the previous re-poll collapse into one re-poll sent
    /// when the gap has passed.
    Refresh,
}
pub enum ControlEvent {
    // Boxed: async_channel's ring buffer (concurrent-queue) reserves 31 slots
    // per block and returns each block by value, so an unboxed MapState here
    // balloons the caller's combined async stack frame by 31x (see the
    // ESP32-C3 stack overflow at Runtime::join()'s tokio::join! entry, fixed
    // by boxing every oversized channel message payload across the workspace).
    MapUpdate(Box<MapState>), OurIpAssigned(TailnetIp), KeyExpiry, Error(ControlError),
    /// Control answered the registration with an interactive-login URL and
    /// the node is not authorized yet. Boxed for the same reason as
    /// `MapUpdate`: the channel's slot size is that of its largest variant,
    /// and an inline 160-byte string would be paid for in every slot. The
    /// same URL is readable via [`login::login_url`] until login completes,
    /// which is what an application blocked inside `Device::connect` uses.
    LoginRequired(Box<login::LoginUrl>),
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
    // Omitted when there is no key: that is how tailscaled itself asks for an
    // interactive login (and for a keyless resume), `Auth` being a nullable
    // pointer in tailcfg.RegisterRequest.
    #[serde(skip_serializing_if = "RegisterAuth::is_empty")]
    auth: RegisterAuth<'a>,
    hostinfo: HostInfo<'a>,
    // The AuthURL control handed out earlier. Sent on the register that
    // follows it, which control holds open until the user finishes logging in
    // (tailcfg.RegisterRequest.Followup).
    #[serde(skip_serializing_if = "str::is_empty")]
    followup: &'a str,
}
#[derive(Serialize)]
struct RegisterAuth<'a> { #[serde(rename="AuthKey")] auth_key: &'a str }
impl RegisterAuth<'_> {
    fn is_empty(&self) -> bool { self.auth_key.is_empty() }
}
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
/// `omit_peers` makes it a "lite" write: control applies Hostinfo/DiscoKey and
/// answers with an empty 200 instead of a netmap. The bring-up publishes are
/// lite (the netmap comes from the stream); a fallback re-poll is not.
fn publish1_body(config: &Config, node_key_hex: &str, disco_key_hex: &str, omit_peers: bool)
    -> Result<heapless::Vec<u8, REQUEST_BODY_CAP>, JsonError>
{
    to_json_buf(&MapRequest {
        version: CAPABILITY_VERSION, compress: "", keep_alive: false,
        node_key: node_key_hex, endpoints: &[], stream: false,
        disco_key: Some(disco_key_hex),
        hostinfo: Some(host_info(config, None)),
        omit_peers,
    })
}

/// What a re-poll must repeat from bring-up so it does not overwrite what we
/// published. A non-streaming `OmitPeers=false` MapRequest is a WRITE (the
/// server applies Hostinfo/DiscoKey/Endpoints from it; `ReadOnly` is
/// deprecated and always false at cap >= 68), so a re-poll that carried no
/// endpoints would erase our DERP-home hint at control. It therefore sends the
/// same body as publish #2 (or #1 when no DERP region was known).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublishCtx {
    region: Option<u16>,
    lan:    Option<std::net::SocketAddrV4>,
}

fn publish2_body(config: &Config, node_key_hex: &str, disco_key_hex: &str, region: u16,
                 lan_ep: Option<std::net::SocketAddrV4>, omit_peers: bool)
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
        omit_peers,
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
    // Shown by the admin console as client version / machine / OS version.
    // Same convention as tailscale-rs for the first two: the crate version
    // and the CPU architecture. (`App` is deliberately not sent: the console
    // does not show it and it only disambiguates tsnet programs.)
    #[serde(rename = "IPNVersion")]
    ipn_version: &'a str,
    machine: &'a str,
    #[serde(rename = "OSVersion", skip_serializing_if = "str::is_empty")]
    os_version: &'a str,
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
        ipn_version: env!("CARGO_PKG_VERSION"), machine: std::env::consts::ARCH,
        os_version: config.os_version.as_str(),
        net_info, services: config.services,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterResponse {
    // Explicit name: PascalCase would give "AuthUrl", but tailcfg spells it
    // "AuthURL" and serde matches field names case-sensitively, so without
    // this the URL was silently dropped.
    #[serde(rename = "AuthURL", default)] auth_url: Option<String>,
    // tailcfg.RegisterResponse.Error: non-empty means control refused.
    #[serde(default)] error: Option<String>,
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
    // Serialized as "OmitPeers" (left out when false). The bring-up publishes
    // set it so control answers with an empty 200 instead of a ~35-48 KB
    // netmap (a "lite" write). The streaming poll and the fallback re-poll
    // leave it false: the poll's first message is the full netmap, delivered
    // through the push parser straight into the bounded roster, and later
    // messages are small deltas.
    #[serde(skip_serializing_if = "is_false")]
    omit_peers: bool,
}

/// serde `skip_serializing_if` predicate for a plain bool field.
fn is_false(b: &bool) -> bool { !*b }


/// Body of `/machine/register`. `auth_key` and `followup` are each omitted
/// when empty: both empty is the keyless request (interactive login, or the
/// resume of an already-authorized node).
fn register_body(config: &Config, node_key_hex: &str, auth_key: &str, followup: &str)
    -> Result<heapless::Vec<u8, REQUEST_BODY_CAP>, JsonError>
{
    // Public key only: nothing secret reaches the body, which is never logged
    // anyway because it carries the auth key.
    let old_hex = config.old_node_key.as_ref().map(|k| k.to_hex());
    to_json_buf(&RegisterRequest {
        version: CAPABILITY_VERSION, node_key: node_key_hex,
        old_node_key: old_hex.as_deref(),
        auth: RegisterAuth { auth_key },
        hostinfo: host_info(config, None),
        followup,
    })
}

fn parse_register_response(body: &[u8]) -> Result<RegisterResponse, ControlError> {
    serde_json::from_slice(body).map_err(|_| ControlError::Json(JsonError::ParseError))
}

enum RegisterOutcome {
    /// Proceed to the map: authorized, or nothing for us to act on.
    Authorized,
    /// A human must open this URL.
    LoginNeeded(String),
}

fn classify_register(reg: &RegisterResponse) -> Result<RegisterOutcome, ControlError> {
    if let Some(e) = reg.error.as_deref().filter(|e| !e.is_empty()) {
        tracing::error!("control refused the registration: {}", e);
        return Err(ControlError::RegistrationFailed);
    }
    // An AuthURL wins even over NodeKeyExpired: control hands one out to let
    // an expired node log in again.
    if let Some(url) = reg.auth_url.as_deref().filter(|u| !u.is_empty()) {
        if !reg.machine_authorized {
            return Ok(RegisterOutcome::LoginNeeded(url.to_owned()));
        }
    }
    // Expired with no way to log in: rotating the node key (OldNodeKey) is
    // what would be needed, and that key belongs to the application's storage.
    if reg.node_key_expired { return Err(ControlError::NodeKeyExpired); }
    Ok(RegisterOutcome::Authorized)
}

/// A fresh AuthURL answer may only start a login wait when the app allows it;
/// a followup round is a wait the app already agreed to.
fn check_login_allowed(config: &Config, in_followup: bool) -> Result<(), ControlError> {
    if config.login_allowed || in_followup {
        return Ok(());
    }
    tracing::warn!("Tailscale login required but not allowed; giving up");
    Err(ControlError::LoginRequired)
}

/// The part of a control failure the app can read back from [`login::refusal`].
fn refusal_of(e: &ControlError) -> Option<login::Refusal> {
    match e {
        ControlError::LoginRequired => Some(login::Refusal::LoginRequired),
        ControlError::NodeKeyExpired => Some(login::Refusal::NodeKeyExpired),
        _ => None,
    }
}

/// Longest a single held-open followup request is waited on before it is
/// re-sent. Control ends its own hold well within this; the bound only keeps
/// a silently dead connection from stalling login forever.
const LOGIN_ROUND_MAX: core::time::Duration = core::time::Duration::from_secs(300);
/// Shortest spacing between login rounds (see `register_until_authorized`).
const LOGIN_MIN_ROUND: core::time::Duration = core::time::Duration::from_secs(5);
const LOGIN_RETRY_DELAY: core::time::Duration = core::time::Duration::from_secs(5);
/// Consecutive failed followups after which the URL is presumed dead and a
/// fresh registration (hence a fresh URL) is requested.
const LOGIN_FOLLOWUP_FAILURES: u8 = 3;

/// The readiness deadline of one bring-up, suspendable.
///
/// `connect_timeout` bounds how long the device may take to come online, but
/// a person approving a login in a browser takes minutes and is not a
/// failure. While login is pending the deadline is cleared, and when it ends
/// the full budget starts over for what remains (publish + first netmap).
struct ReadyGate {
    // A Mutex rather than a Cell so the actor's future stays `Send` (the host
    // examples spawn it); it is never held across an await.
    at: std::sync::Mutex<Option<tokio::time::Instant>>,
    budget: Option<core::time::Duration>,
    wake: tokio::sync::Notify,
}

impl ReadyGate {
    fn new(budget: Option<core::time::Duration>) -> Self {
        Self {
            at: std::sync::Mutex::new(budget.map(|d| tokio::time::Instant::now() + d)),
            budget,
            wake: tokio::sync::Notify::new(),
        }
    }
    fn get(&self) -> Option<tokio::time::Instant> { *self.at.lock().unwrap_or_else(|p| p.into_inner()) }
    fn set(&self, v: Option<tokio::time::Instant>) { *self.at.lock().unwrap_or_else(|p| p.into_inner()) = v; }
    fn pause(&self) { self.set(None); self.wake.notify_one(); }
    fn resume(&self) {
        self.set(self.budget.map(|d| tokio::time::Instant::now() + d));
        self.wake.notify_one();
    }
    fn deadline(&self) -> Option<tokio::time::Instant> { self.get() }
    /// Resolves when the (current) deadline passes; pends forever if there is none.
    async fn expired(&self) {
        loop {
            match self.get() {
                None => self.wake.notified().await,
                Some(at) => tokio::select! {
                    _ = tokio::time::sleep_until(at) => if self.get() == Some(at) { return },
                    _ = self.wake.notified() => {}
                },
            }
        }
    }
}

// ── ControlActor ─────────────────────────────────────────────────────────────

pub struct ControlActor {
    config: Config,
    node_state: NodeState,
    /// Read watchdog for the streaming poll (see `POLL_IDLE_TIMEOUT`).
    /// Overridable so tests need not wait 90 s.
    poll_idle_timeout: core::time::Duration,
}

/// After the link returns, control waits this long before trying to take the
/// heavy-dial exclusion. DERP notices the link within its 1 s poll and its
/// TLS handshake needs the largest contiguous heap block; control's ~8 KB
/// Noise buffers are held for the whole session and would fragment it. The
/// stagger makes DERP win the race deterministically instead of by luck.
const LINK_RESUME_STAGGER: core::time::Duration = core::time::Duration::from_secs(2);
/// Poll period while waiting for the heavy-dial exclusion.
const DIAL_POLL: core::time::Duration = core::time::Duration::from_millis(100);
/// Longest control waits for the exclusion before dialing anyway. DERP's
/// connect/handshake have no timeout of their own, so a hung handshake must
/// not be able to keep control offline forever.
const DIAL_WAIT_MAX: core::time::Duration = core::time::Duration::from_secs(20);

/// Take the process-wide heavy-dial exclusion (`tm_buf::link::try_dial`),
/// polling for at most `max_wait`. Returns `None` after the bound expires
/// (the caller proceeds unguarded rather than staying offline). Logs once
/// when it has to defer.
async fn acquire_dial_guard(max_wait: core::time::Duration) -> Option<tm_buf::link::DialGuard> {
    if let Some(g) = tm_buf::link::try_dial() {
        return Some(g);
    }
    info!("Tailscale control: another actor is dialing; deferring bring-up");
    let deadline = tokio::time::Instant::now() + max_wait;
    loop {
        tokio::time::sleep(DIAL_POLL).await;
        if let Some(g) = tm_buf::link::try_dial() {
            return Some(g);
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!("Tailscale control: dial exclusion still held after {:?}; proceeding anyway", max_wait);
            return None;
        }
    }
}

impl ControlActor {
    pub fn new(config: Config, node_state: NodeState) -> Self {
        Self { config, node_state, poll_idle_timeout: POLL_IDLE_TIMEOUT }
    }

    #[cfg(test)]
    fn with_poll_idle_timeout(mut self, d: core::time::Duration) -> Self {
        self.poll_idle_timeout = d;
        self
    }

    pub async fn run(mut self, cmds: async_channel::Receiver<ControlCmd>,
                     events: async_channel::Sender<ControlEvent>) {
        loop {
            match cmds.recv().await {
                Ok(ControlCmd::Start { ref auth_key }) => {
                    // A restart must not show the previous attempt's verdict.
                    login::clear_login_url();
                    login::set_control_key_rejected(false);
                    login::set_refusal(None);
                    if let Err(e) = self.connect_and_poll(auth_key.as_str(), &events, &cmds).await {
                        tracing::error!("Control error: {:?}", e);
                        login::set_refusal(refusal_of(&e));
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
                    // Ok means a Shutdown was received while polling.
                    break;
                }
                Ok(ControlCmd::Shutdown) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    async fn connect_and_poll(&mut self, auth_key: &str,
                               events: &async_channel::Sender<ControlEvent>,
                               cmds: &async_channel::Receiver<ControlCmd>)
        -> Result<(), ControlError>
    {
        // Readiness (TCP + Noise + register + lite publish + the stream's first
        // message, up to and including OurIpAssigned) is the ONLY phase bounded
        // by `connect_timeout`: `ready_deadline` covers both `bring_up` and the
        // wait for the first map, which now arrives on the stream (see
        // `PollCtl::ready_deadline`). After the IP is announced the poll runs
        // unbounded so the ephemeral node stays online; it does get a read
        // watchdog (`POLL_IDLE_TIMEOUT`): silence longer than the server's
        // keepalive interval means a dead connection and triggers a reconnect.
        // See docs/wg-dataplane-notes.md "Bring-up timeout".
        let budget = self.config.connect_timeout;
        let gate = ReadyGate::new(budget);
        // The netmap lives here for the life of the connection loop: the
        // stream's first message fills it, later deltas merge into it. Boxed
        // so the ~4 KB roster is not part of this future's state.
        let mut roster = Box::new(Roster::new());
        let bring_up = self.bring_up(auth_key, &mut roster, events, &gate);
        let (mut main_conn, mut noise, mut h2, node_key_hex, mut publish_ctx) = match budget {
            Some(dur) => tokio::select! {
                r = bring_up => r?,
                _ = gate.expired() => {
                    tracing::error!("Control bring-up exceeded connect_timeout ({:?})", dur);
                    return Err(ControlError::Timeout);
                }
            },
            None => bring_up.await?,
        };
        // After a login the deadline restarted (see `ReadyGate`), so the wait
        // for the first map below is bounded from there, not from the start.
        let mut ready_deadline = gate.deadline().zip(budget);

        // Poll loop, kept alive across drops.
        //
        // A returning poll is NOT a graceful stop -- `Ok(())` means the server
        // closed the stream and `Err` means a poll/transport error -- and
        // either way, if we simply returned, `run()` would park on
        // `cmds.recv()` forever and the node would go stale (control plane
        // "offline") within a minute. Reconnect with capped backoff instead.
        // Before the IP has been announced a failure is instead returned (as
        // bring-up failures always were), so Device::connect's readiness race
        // sees it; every reconnect after that is post-readiness.
        let mut backoff = core::time::Duration::from_secs(1);
        loop {
            let mut shutdown = false;
            let mut announced = false;
            let poll_res = async {
                // One re-poll controller per connection: re-poll stream IDs
                // restart at 9 with the fresh h2 state.
                let mut ctl = PollCtl::new(cmds, node_key_hex.as_str(), &publish_ctx,
                                           self.config.refresh_interval);
                ctl.announce_ip = true;
                ctl.pending_publish2 = true;
                ctl.ready_deadline = ready_deadline.map(|(at, _)| at);
                let r = self.stream_map_response(&mut main_conn, &mut noise, &mut h2, events, &mut roster, MAP_STREAM_ID, true,
                    Some(self.poll_idle_timeout), Some(&mut ctl)).await;
                shutdown = ctl.shutdown;
                announced = ctl.ip_announced;
                publish_ctx = ctl.publish;
                r
            }.await;
            if shutdown {
                info!("Tailscale control: shutdown requested, closing the poll");
                return Ok(());
            }
            if announced { ready_deadline = None; }
            if ready_deadline.is_some() {
                // Never reached readiness: report it instead of retrying.
                return Err(match poll_res {
                    Err(e) => e,
                    Ok(_) => ControlError::Io,
                });
            }

            match poll_res {
                Ok(_) => tracing::warn!("Tailscale poll stream closed by server; reconnecting"),
                Err(e) => tracing::warn!("Tailscale poll stream error: {:?}; reconnecting", e),
            }

            // A dead poll usually means a dead connection, so re-establish the
            // whole thing (fresh TCP + Noise + register + publish + stream)
            // rather than just re-issuing the request. Backoff caps at 30s so a
            // persistently failing control server is retried, not hammered.
            // Bring-up failures here do NOT propagate (readiness is already
            // resolved); we just keep retrying.
            if !tm_buf::link::is_up() {
                tracing::warn!("Tailscale control: link down; deferring reconnect until it returns");
                while !tm_buf::link::is_up() {
                    tokio::time::sleep(core::time::Duration::from_secs(1)).await;
                }
                backoff = core::time::Duration::from_secs(1);
                // Give DERP the first dial (see `LINK_RESUME_STAGGER`).
                tokio::time::sleep(LINK_RESUME_STAGGER).await;
            }
            tokio::time::sleep(backoff).await;
            backoff = core::cmp::min(backoff.saturating_mul(2), core::time::Duration::from_secs(30));
            // Held for the bring-up only, never the whole session. Dropped at
            // the end of the match arm scope, on error, or on cancellation.
            let dial_guard = acquire_dial_guard(DIAL_WAIT_MAX).await;
            let bring_up_res = self.bring_up(auth_key, &mut roster, events, &ReadyGate::new(None)).await;
            drop(dial_guard);
            match bring_up_res {
                Ok((c, n, h, _, pc)) => {
                    main_conn = c; noise = n; h2 = h; publish_ctx = pc;
                    backoff = core::time::Duration::from_secs(1);
                    info!("Tailscale poll reconnected (bring-up ok)");
                }
                Err(e) => tracing::warn!("Tailscale poll reconnect bring-up failed: {:?}; will retry", e),
            }
        }
    }

    /// Bring-up: TCP + Noise + register (with the interactive login, when
    /// control asks for one) + the lite publish, then the streaming poll
    /// request is written. The netmap (our IP, DERPMap, peers) is NOT
    /// read here: it is the poll's first message, handled by
    /// `stream_map_response` in poll mode. The caller bounds this call (and the
    /// wait for that first message) with `connect_timeout`, except that `gate`
    /// suspends the bound while a human is logging in.
    async fn bring_up(&mut self, auth_key: &str, roster: &mut Roster,
                      events: &async_channel::Sender<ControlEvent>, gate: &ReadyGate)
        -> Result<(TokioStream, NoiseChannel, H2State, heapless::String<80>, PublishCtx), ControlError>
    {
        info!("Tailscale connect_and_poll starting");
        // A new connection starts from an empty netmap: nothing carries over
        // from a previous session whose deltas we may have missed.
        roster.clear();
        let host = self.config.control_host;

        // Steps 1-7: connect and register, up to a machine-authorized node.
        let node_key_hex = self.node_state.node_key.public().to_hex();
        let (mut main_conn, mut noise, mut h2) =
            self.register_until_authorized(auth_key, node_key_hex.as_str(), events, gate).await?;

        // Step 7.5: publish Hostinfo/DiscoKey via a non-streaming MapRequest
        // before opening the streaming poll.
        //
        // A Stream=true MapRequest is read-only on the control server for cap
        // version >= 68: Hostinfo/DiscoKey/Endpoints are silently ignored on
        // it, so without this step our disco key never reaches peers (they see
        // it as all-zeros) and real peers never mark our endpoint active, so
        // they drop our WireGuard handshake. Hostinfo is also unconditionally
        // required by the server (400 otherwise) on every MapRequest. Matches
        // tools/wg_validator/ts_control.py's write_map(). See
        // docs/wg-dataplane-notes.md Bug 3.
        //
        // Publish #1 is a lite write (`OmitPeers=true`): control stores the
        // keys and answers with an empty 200, so no netmap is read here. The
        // netmap is the poll's first message. The lite response is awaited
        // before the poll opens so the disco key is registered before control
        // computes our netmap, and so a rejection surfaces as a bring-up error.
        info!("Tailscale Step 7.5: publishing Hostinfo/DiscoKey (lite MapRequest, OmitPeers=true)");
        {
            let disco_key_hex = self.node_state.disco_key.public().to_hex();
            let publish_body = publish1_body(&self.config, node_key_hex.as_str(), disco_key_hex.as_str(), true)
                .map_err(ControlError::Json)?;
            let publish_req = build_h2_post("/machine/map", host, MAP_PUBLISH_STREAM_ID, &publish_body);
            noise.write_all(&mut main_conn, &publish_req).await?;
        }
        {
            let body = read_one_h2_body(&mut main_conn, &mut noise, &mut h2, MAP_PUBLISH_STREAM_ID).await?;
            info!("Tailscale Step 7.5: lite publish answered ({} B body)", body.len());
        }

        // Our LAN endpoint for publish #2, computed here because it needs the
        // control socket's local address, which the poll loop does not have.
        let lan = self.config.lan_udp_port.and_then(|port| {
            let ep = main_conn.inner().local_addr().ok().and_then(|la| lan_endpoint(la, port));
            match ep {
                Some(ep) if PUBLISH_LAN_ENDPOINT => info!("lan-direct: publishing LAN endpoint {}", ep),
                Some(ep) => info!("lan-direct: LAN endpoint {} computed, not published yet", ep),
                None => tracing::warn!("lan-direct: control socket has no usable LAN IPv4; DERP-only"),
            }
            ep
        });
        let publish_ctx = PublishCtx { region: None, lan: if PUBLISH_LAN_ENDPOINT { lan } else { None } };

        // Step 8: open the streaming poll with `OmitPeers=false`. Its first
        // message is a full netmap (our IP, DERPMap, peers) and later messages
        // are deltas; the poll loop applies both. Hostinfo is required on every
        // MapRequest or the server answers 400 and closes the stream.
        // DiscoKey/Endpoints are read-only on a Stream=true request (cap >=
        // 68), so they stay None; the lite publishes carry them. Publish #2
        // (PreferredDERP + DERP-home endpoint) is sent by the poll loop once
        // that first netmap has revealed the DERPMap.
        {
            let map_body = to_json_buf(&MapRequest {
                version: CAPABILITY_VERSION, compress: "", keep_alive: true,
                node_key: node_key_hex.as_str(), endpoints: &[], stream: true,
                disco_key: None,
                hostinfo: Some(host_info(&self.config, None)),
                omit_peers: false,
            }).map_err(ControlError::Json)?;
            let map_req = build_h2_post("/machine/map", host, MAP_STREAM_ID, &map_body);
            noise.write_all(&mut main_conn, &map_req).await?;
        }

        Ok((main_conn, noise, h2, node_key_hex, publish_ctx))
    }

    /// Dial control and register until the node is machine-authorized,
    /// returning the live connection for the publish and the poll.
    ///
    /// An `AuthURL` answer means a human has to approve the node. The URL is
    /// published through [`login`] and `ControlEvent::LoginRequired`, then
    /// each following round is a fresh connection whose register carries the
    /// URL as `Followup`, which control holds open until login completes. A
    /// fresh connection per round (rather than a second stream on this one)
    /// keeps the fixed stream ids of the publish and the poll valid, and
    /// frees the ~8 KB of Noise buffers between rounds. None of this waiting
    /// counts against `connect_timeout` (see [`ReadyGate`]).
    async fn register_until_authorized(
        &mut self, auth_key: &str, node_key_hex: &str,
        events: &async_channel::Sender<ControlEvent>, gate: &ReadyGate,
    ) -> Result<(TokioStream, NoiseChannel, H2State), ControlError> {
        let mut no_response = 0u8;
        let mut failures = 0u8;
        loop {
            let followup = login::login_url();
            let started = tokio::time::Instant::now();
            // A spent key is not re-sent on a followup: the URL identifies the
            // pending login on its own.
            let key = if followup.is_some() { "" } else { auth_key };
            let round = self.register_round(key, followup.as_deref().unwrap_or(""), node_key_hex);
            let res = if followup.is_some() {
                match tokio::time::timeout(LOGIN_ROUND_MAX, round).await {
                    Ok(r) => r,
                    // The held-open request simply outlived our patience; ask again.
                    Err(_) => { debug!("login followup round timed out; asking again"); continue; }
                }
            } else {
                round.await
            };
            match res {
                Ok((conn, noise, h2, reg)) => match classify_register(&reg)? {
                    RegisterOutcome::Authorized => {
                        if followup.is_some() {
                            info!("Tailscale login approved");
                            gate.resume();
                        }
                        login::clear_login_url();
                        return Ok((conn, noise, h2));
                    }
                    RegisterOutcome::LoginNeeded(url) => {
                        // Free the Noise buffers before the next dial.
                        drop((conn, noise, h2));
                        // A silent attempt stops here: no URL is published and
                        // no followup is held open.
                        check_login_allowed(&self.config, followup.is_some())?;
                        gate.pause();
                        failures = 0;
                        if followup.as_deref() != Some(url.as_str()) {
                            if !login::set_login_url(&url) {
                                tracing::error!("auth URL is {} bytes, longer than {}", url.len(), login::LOGIN_URL_MAX);
                                return Err(ControlError::RegistrationFailed);
                            }
                            tracing::warn!("Tailscale login required: open {}", url);
                            if let Some(u) = login::login_url() {
                                let _ = events.send(ControlEvent::LoginRequired(Box::new(u))).await;
                            }
                        }
                        // A server that answers a followup at once instead of
                        // holding it would otherwise be polled in a hot loop.
                        tokio::time::sleep_until(started + LOGIN_MIN_ROUND).await;
                    }
                },
                Err(ControlError::Noise(NoiseError::NoResponse)) => {
                    // One clean close can be a load balancer; two in a row is a
                    // server that cannot read our initiation, i.e. a key mismatch.
                    no_response += 1;
                    if no_response >= 2 {
                        tracing::error!("control closed the Noise handshake twice without a reply: pinned control key rejected");
                        login::set_control_key_rejected(true);
                        return Err(ControlError::ControlKeyRejected);
                    }
                    tokio::time::sleep(core::time::Duration::from_millis(500)).await;
                }
                // Before any login started a failure is the caller's to handle,
                // exactly as before interactive login existed.
                Err(e) if followup.is_none() => return Err(e),
                Err(e) => {
                    failures += 1;
                    tracing::warn!("login followup failed ({:?}, {} in a row)", e, failures);
                    if failures >= LOGIN_FOLLOWUP_FAILURES {
                        // The URL may have expired server-side: forget it so the
                        // next round registers afresh and gets a new one.
                        login::clear_login_url();
                        failures = 0;
                    }
                    tokio::time::sleep(LOGIN_RETRY_DELAY).await;
                }
            }
        }
    }

    /// One dial: TCP + Noise + H/2 preface + a single `/machine/register`
    /// exchange. Split out (and kept off the caller's frame) so the request
    /// and response buffers are dropped before any following await.
    #[inline(never)]
    async fn register_round(&self, auth_key: &str, followup: &str, node_key_hex: &str)
        -> Result<(TokioStream, NoiseChannel, H2State, RegisterResponse), ControlError>
    {
        let host = self.config.control_host;
        let port = self.config.control_port;
        info!("Tailscale connecting to {}:{}", host, port);

        // The control server's Noise static key comes from the verified pin
        // (Config::control_pin), with no /key HTTP(S) pre-fetch anymore.
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
        let mut h2 = H2State::new();

        {
            let reg_body = register_body(&self.config, node_key_hex, auth_key, followup)
                .map_err(ControlError::Json)?;

            info!("Tailscale Step 4: registering node");
            // Not logged: the body carries the auth key.
            let reg_req = build_h2_post("/machine/register", host, REGISTER_STREAM_ID, &reg_body);
            noise.write_all(&mut main_conn, &reg_req).await?;
        }

        info!("Tailscale Step 4: reading registration response");
        let reg = {
            let reg_bytes = read_one_h2_body(&mut main_conn, &mut noise, &mut h2, REGISTER_STREAM_ID).await?;
            tracing::debug!("register response body: {}", core::str::from_utf8(&reg_bytes).unwrap_or("<invalid utf8>"));
            parse_register_response(&reg_bytes)?
        };
        info!("Tailscale Step 4: registration answered, node_key_expired={}, machine_authorized={}, auth_url={}",
              reg.node_key_expired, reg.machine_authorized, reg.auth_url.is_some());
        Ok((main_conn, noise, h2, reg))
    }

    /// Publish #2: once the poll's first netmap has revealed the DERPMap and
    /// `select_home_region` chose our home, advertise it (PreferredDERP plus
    /// the DERP-home and LAN endpoints) so peers get a stable relay path to
    /// us. A lite write (`OmitPeers=true`): control answers with an empty 200
    /// that the poll loop drops, and the netmap is not re-sent. The runtime
    /// picks the same region from the same `MapUpdate`, so advertised ==
    /// actual. Without this peers have no durable path to us and inbound dies
    /// once their disco caches go stale.
    #[inline(never)]
    async fn send_publish2<S: embedded_io_async::Read + embedded_io_async::Write>(
        &self, ctl: &mut PollCtl<'_>, region: u16, stream: &mut S, noise: &mut NoiseChannel,
    ) -> Result<(), ControlError> {
        let disco_hex = self.node_state.disco_key.public().to_hex();
        info!("Tailscale Step 7.6: publishing PreferredDERP={} endpoint={}:{} (lite)", region, DERP_MAGIC_IP, region);
        let body = publish2_body(&self.config, ctl.node_key_hex, disco_hex.as_str(), region, ctl.publish.lan, true)
            .map_err(ControlError::Json)?;
        let req = build_h2_post("/machine/map", self.config.control_host, MAP_REPUBLISH_STREAM_ID, &body);
        noise.write_all(stream, &req).await?;
        ctl.publish.region = Some(region);
        ctl.pending_publish2 = false;
        Ok(())
    }

    /// Send the fallback re-poll request on a fresh stream of the open
    /// connection. The body repeats what bring-up published (see
    /// `PublishCtx`), with `OmitPeers=false`, so the response is a full map
    /// for the same parser as the stream's first message.
    #[inline(never)]
    async fn send_refresh<S: embedded_io_async::Read + embedded_io_async::Write>(
        &self, ctl: &mut PollCtl<'_>, stream: &mut S, noise: &mut NoiseChannel,
    ) -> Result<(), ControlError> {
        let id = ctl.next_stream_id;
        let disco_hex = self.node_state.disco_key.public().to_hex();
        let body = match ctl.publish.region {
            Some(region) => publish2_body(&self.config, ctl.node_key_hex, disco_hex.as_str(), region, ctl.publish.lan, false),
            None => publish1_body(&self.config, ctl.node_key_hex, disco_hex.as_str(), false),
        }.map_err(ControlError::Json)?;
        let req = build_h2_post("/machine/map", self.config.control_host, id, &body);
        info!("Tailscale re-poll: requesting a fresh netmap on stream {}", id);
        noise.write_all(stream, &req).await?;
        let now = tokio::time::Instant::now();
        ctl.next_stream_id += 2;
        ctl.last_refresh = now;
        ctl.inflight = Some((id, now));
        ctl.cmd_pending = false;
        Ok(())
    }

    /// Returns the DERP home region selected from the latest published
    /// netmap snapshot (via `select_home_region`), if any. The caller
    /// re-publishes with this as its `PreferredDERP`; the runtime picks the
    /// same region from the same `MapUpdate`.
    ///
    /// Every message of every stream is decoded into `roster`, which is the
    /// one place the netmap lives; what reaches the runtime is always a whole
    /// snapshot of it. The streaming poll (stream 7) is parsed in
    /// `Mode::Delta`; the other streams carry full maps (`Mode::Full`). A
    /// stream-7 message we cannot decode is a missed delta, so it ends the poll
    /// with an error and the caller reconnects: silently continuing would let
    /// the roster drift from control's view with nothing to correct it.
    #[allow(clippy::too_many_arguments)]
    async fn stream_map_response<S: embedded_io_async::Read + embedded_io_async::Write>(
        &self, stream: &mut S, noise: &mut NoiseChannel,
        h2: &mut H2State, events: &async_channel::Sender<ControlEvent>,
        roster: &mut Roster,
        expected_stream: u32, emit_events: bool,
        idle_timeout: Option<core::time::Duration>,
        mut poll: Option<&mut PollCtl<'_>>,
    ) -> Result<Option<u16>, ControlError> {
        info!("Tailscale stream_map_response starting on stream {} (emit_events={})", expected_stream, emit_events);
        // Home region selected from the latest snapshot; returned to the caller.
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
        // Each MapResponse is `u32-LE length + JSON`. The body is fed to the
        // push parser as DATA frames arrive, so a ~34-48 KB netmap is never one
        // contiguous allocation (that could not be satisfied on the fragmented
        // heap, and discarding the map lost the data plane). Only the parser's
        // ~1 KB feeder ring and the fixed roster are resident.
        //
        // Two reassembly slots: the long poll (stream 7) and one other stream
        // (publish, or the single in-flight re-poll). Poll mode interleaves
        // their frames, and a message can span several of them.
        let mut slots = [Reasm::new(), Reasm::new()];
        // The poll connection already announced our IP during bring-up; a
        // re-poll must not announce it again.
        let mut our_ip_sent = poll.as_deref().is_some_and(|c| !c.announce_ip);

        let mut idle_at = idle_timeout.map(|d| tokio::time::Instant::now() + d);

        loop {
            // Poll mode only: between frames, flush a coalesced snapshot that
            // is due, start a due re-poll and, while the stream is quiet, wait
            // for a trigger instead of a frame. Nothing here runs mid-frame, and
            // a ready frame always wins over a timer (see `PollCtl::wait`).
            if let Some(ctl) = poll.as_deref_mut() {
                if ctl.ready_overdue(tokio::time::Instant::now()) {
                    tracing::error!("Control readiness exceeded connect_timeout: no netmap with a tailnet IP from the stream");
                    return Err(ControlError::Timeout);
                }
                if ctl.emit_due(tokio::time::Instant::now()) {
                    publish_snapshot(roster, events, emit_events, &mut home_region).await;
                    if ctl.pending_publish2 {
                        if let Some(region) = home_region {
                            self.send_publish2(ctl, region, stream, noise).await?;
                        }
                    }
                }
                if ctl.refresh_wanted(tokio::time::Instant::now(), h2) {
                    self.send_refresh(ctl, stream, noise).await?;
                    // Parse state belongs to the previous re-poll, if any.
                    slots[1].reset();
                }
                if ctl.shutdown { return Ok(home_region); }
                if noise.buffered() == 0 {
                    match ctl.wait(noise, stream, idle_at).await? {
                        Wake::Readable => {}
                        Wake::Other => continue,
                    }
                }
            }
            let mut hdr_bytes = [0u8; 9];
            read_exact_idle(noise, stream, &mut hdr_bytes, idle_timeout).await?;
            idle_at = idle_timeout.map(|d| tokio::time::Instant::now() + d);
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
            read_exact_idle(noise, stream, &mut frame_buf[..blen], idle_timeout).await?;
            debug!("Tailscale frame received: length={}, type={}", hdr.length, hdr.frame_type);

            // Poll mode multiplexes the long poll with at most one re-poll (and
            // may still see a late frame of an abandoned one), so any DATA
            // stream is acceptable there and is routed below. Everything else
            // reads exactly one stream and rejects frames for any other.
            let data_stream = if poll.is_some() { hdr.stream_id } else { expected_stream };

            // A re-poll that ends without DATA (an error status answered with
            // HEADERS+END_STREAM, or a reset) would otherwise stay in flight
            // until the deadline.
            if let Some(ctl) = poll.as_deref_mut() {
                let ends = (hdr.frame_type == FRAME_TYPE_HEADERS && hdr.is_end_stream())
                    || hdr.frame_type == FRAME_TYPE_RST_STREAM;
                if ends && ctl.finish_refresh(hdr.stream_id, h2) {
                    info!("Tailscale re-poll stream {} ended without a body (type {})", hdr.stream_id, hdr.frame_type);
                    slots[1].reset();
                    continue;
                }
                if ends && hdr.stream_id == MAP_STREAM_ID {
                    // The long poll was closed or reset by the server (an
                    // error status, or RST_STREAM): nothing more will come.
                    info!("Tailscale poll stream ended without a body (type {})", hdr.frame_type);
                    return Err(ControlError::Io);
                }
                if ends && hdr.frame_type == FRAME_TYPE_HEADERS {
                    // A lite publish's empty 200 (publish #2): headers only,
                    // nothing to read. Free its credit slot.
                    debug!("Tailscale stream {} answered with headers only", hdr.stream_id);
                    h2.stream_done(hdr.stream_id);
                    continue;
                }
            }

            match tm_h2::parse_frame(&hdr, &frame_buf[..blen], data_stream, h2)? {
                FrameAction::Data { payload, end_stream } => {
                    debug!("Tailscale Data frame: stream={}, payload_len={}, end_stream={}", data_stream, payload.len(), end_stream);

                    // Proactive WINDOW_UPDATE (MicroLink technique). Stream-level
                    // update must target the stream the data arrived on.
                    let (cwu, swu) = h2.consumed(data_stream, payload.len() as u32);
                    if cwu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,0,cwu); noise.write_all(stream,&b).await?; }
                    if swu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,data_stream,swu); noise.write_all(stream,&b).await?; }

                    let is_long_poll = data_stream == MAP_STREAM_ID;
                    // The other stream's message is half applied right now
                    // (poll mode interleaves frames). Publishing then would
                    // show the roster mid-replace, so the snapshot waits for
                    // that message to finish: the roster stays dirty, and
                    // whichever message ends last publishes.
                    let other_mid = slots[usize::from(is_long_poll)].parser.is_some();
                    let slot = &mut slots[usize::from(!is_long_poll)];
                    // In poll mode only the long poll and the in-flight re-poll
                    // are parsed; a stream we no longer track is skipped.
                    let parse_this = match poll.as_deref() {
                        Some(ctl) => is_long_poll || ctl.is_refresh_stream(data_stream),
                        None => true,
                    };
                    let mut pos = if slot.discarding || !parse_this { payload.len() } else { 0usize };
                    // Feed the payload through the prefix -> body state machine.
                    // A single frame may finish one message and begin the next.
                    while pos < payload.len() {
                        // Phase 1: collect the 4-byte LE length prefix.
                        if slot.cur_len.is_none() {
                            while slot.prefix_have < 4 && pos < payload.len() {
                                slot.prefix[slot.prefix_have] = payload[pos];
                                slot.prefix_have += 1; pos += 1;
                            }
                            if slot.prefix_have < 4 { break; }
                            let mlen = u32::from_le_bytes(slot.prefix) as usize;
                            // Sanity cap: a desynced stream reads a garbage length
                            // (seen live as ~1.95 GB on the Stream=true keepalive).
                            if mlen > MAX_MAP_MSG {
                                if is_long_poll {
                                    // The long poll cannot be resynced mid-stream.
                                    tracing::warn!("Tailscale poll: implausible message length {}; reconnecting", mlen);
                                    return Err(ControlError::Json(JsonError::ParseError));
                                }
                                // Discard the rest of the stream to end_stream
                                // (rather than return and orphan unread frames)
                                // so the connection stays byte-consistent for
                                // the next request.
                                info!("Tailscale stream_map_response: implausible message length {} on stream {}, discarding rest of stream", mlen, data_stream);
                                slot.discarding = true;
                                slot.prefix_have = 0;
                                break;
                            }
                            let mode = if is_long_poll { map_stream::Mode::Delta } else { map_stream::Mode::Full };
                            slot.parser = Some(map_stream::MapStreamParser::new(mode, roster));
                            slot.fed = 0;
                            slot.cur_len = Some(mlen);
                        }

                        // Phase 2: feed body bytes up to the known length.
                        let want = slot.cur_len.unwrap_or(0);
                        let take = core::cmp::min(want - slot.fed, payload.len() - pos);
                        if let Some(p) = slot.parser.as_mut() {
                            // A feed error is recorded inside the parser and
                            // surfaced by finish(); every body byte is still
                            // consumed so the stream stays byte-consistent.
                            let _ = p.push(&payload[pos..pos + take], roster);
                        }
                        pos += take;
                        slot.fed += take;
                        if slot.fed < want { break; }

                        // Complete message: finish the parse, then act on it.
                        let parsed = slot.parser.take().map(|p| p.finish(roster));
                        slot.reset_message();
                        // Before OurIpAssigned below, so an app woken by the
                        // connect already sees its key expiry.
                        roster.publish_self();
                        match parsed {
                            Some(Ok(())) => {
                                if emit_events && !our_ip_sent && roster.our_ip().0 != [0u8; 4] {
                                    our_ip_sent = true;
                                    if let Some(ctl) = poll.as_deref_mut() { ctl.ip_announced = true; }
                                    let ip = roster.our_ip().clone();
                                    info!("Tailscale OurIpAssigned event sent: {}.{}.{}.{}", ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
                                    let _ = events.send(ControlEvent::OurIpAssigned(ip)).await;
                                }
                                if other_mid {
                                    debug!("Tailscale snapshot deferred: another stream's message is mid-parse");
                                } else if roster.take_dirty() {
                                    match poll.as_deref_mut() {
                                        // Bursts of deltas collapse into one
                                        // snapshot, sent at the loop top.
                                        Some(ctl) => ctl.note_change(tokio::time::Instant::now()),
                                        None => publish_snapshot(roster, events, emit_events, &mut home_region).await,
                                    }
                                } else {
                                    debug!("Tailscale map message changed nothing (stream {})", data_stream);
                                }
                            }
                            Some(Err(e)) if is_long_poll || poll.is_none() => {
                                // A missed delta, or an unusable bring-up map.
                                tracing::warn!("Tailscale map_stream parse error on stream {}: {:?}", data_stream, e);
                                return Err(ControlError::Json(JsonError::ParseError));
                            }
                            Some(Err(e)) => {
                                // A re-poll is only a correction pass; the
                                // roster keeps what it had (a failed replace
                                // never sweeps). Whatever it did apply before
                                // failing is valid server data and goes out
                                // with the next snapshot.
                                tracing::warn!("Tailscale re-poll map parse error: {:?}", e);
                                if !other_mid && roster.take_dirty() {
                                    if let Some(ctl) = poll.as_deref_mut() { ctl.note_change(tokio::time::Instant::now()); }
                                }
                            }
                            None => {}
                        }
                    }

                    if end_stream {
                        match poll.as_deref_mut() {
                            Some(ctl) if data_stream != MAP_STREAM_ID => {
                                // A re-poll (or a stray stream) finished; the long
                                // poll carries on.
                                h2.stream_done(data_stream);
                                if ctl.finish_refresh(data_stream, h2) {
                                    slots[1].reset();
                                }
                                info!("Tailscale re-poll stream {} complete", data_stream);
                            }
                            _ => {
                                info!("Tailscale stream ended");
                                h2.stream_done(data_stream);
                                if poll.as_deref().is_some_and(|c| c.emit_pending()) {
                                    publish_snapshot(roster, events, emit_events, &mut home_region).await;
                                }
                                return Ok(home_region);
                            }
                        }
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

/// Reassembly state of one stream's `u32-LE length + JSON` messages.
struct Reasm {
    parser: Option<map_stream::MapStreamParser>,
    /// Body bytes of the current message fed so far.
    fed: usize,
    prefix: [u8; 4],
    prefix_have: usize,
    cur_len: Option<usize>,
    /// A re-poll or publish stream with a garbage length prefix: the rest of
    /// the stream is skipped to its end.
    discarding: bool,
}

impl Reasm {
    const fn new() -> Self {
        Self { parser: None, fed: 0, prefix: [0; 4], prefix_have: 0, cur_len: None, discarding: false }
    }
    /// Between messages of one stream.
    fn reset_message(&mut self) {
        self.parser = None; self.fed = 0; self.cur_len = None; self.prefix_have = 0;
    }
    /// A new stream takes over the slot.
    fn reset(&mut self) {
        self.reset_message();
        self.discarding = false;
    }
}

/// Send the roster's current snapshot to the runtime (and remember the DERP
/// home it implies). An empty roster is skipped so a content-free message
/// can never clobber a netmap the runtime already has.
async fn publish_snapshot(
    roster: &Roster, events: &async_channel::Sender<ControlEvent>,
    emit_events: bool, home_region: &mut Option<u16>,
) {
    if !roster.has_content() {
        info!("Tailscale MapUpdate skipped (empty snapshot)");
        return;
    }
    let map = roster.snapshot();
    // Select our DERP home from the same snapshot the runtime will get, so both
    // agree (see select_home_region).
    if let Some(hr) = select_home_region(&map) { *home_region = Some(hr); }
    if emit_events {
        info!("Tailscale MapUpdate event sent ({} peers, {} DERP regions, home_derp={:?})", map.peers.len(), map.derp_regions.len(), home_region);
        let _ = events.send(ControlEvent::MapUpdate(map)).await;
    } else {
        // Publish #2 drain: the runtime already has this netmap from publish
        // #1, so re-emitting would double OurIpAssigned/MapUpdate.
        info!("Tailscale MapResponse parsed, not re-emitted ({} peers, {} DERP regions, home_derp={:?})", map.peers.len(), map.derp_regions.len(), home_region);
    }
}

const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;

/// What woke the poll loop while it was waiting for the next frame.
enum Wake {
    /// A record is buffered; read the frame.
    Readable,
    /// A command or timer fired; loop to re-evaluate (`refresh_wanted`).
    Other,
}

/// Re-poll controller for one poll connection: decides when to fetch a fresh
/// full netmap on a new stream of the same HTTP/2 connection, and tracks that
/// one request until it finishes.
///
/// Why a second stream rather than a reconnect: a reconnect re-runs TCP,
/// Noise, register and two maps (the heavy phase ALLOCATIONS.md flags for the
/// fragmented heap), and control marks the node offline in between. A request
/// on the open connection costs one map and no handshake.
///
/// Head-of-line/window design: the re-poll's response is 30-48 KB behind a
/// 4096-byte stream window, so it arrives as 8-12 DATA frames, each released
/// by our per-stream WINDOW_UPDATE (`H2State` keeps one credit counter per
/// stream). The frame loop handles every frame the moment it is read,
/// whichever stream it belongs to, so long-poll keepalives interleave with the
/// re-poll's frames instead of queueing behind it, and the per-frame idle
/// watchdog keeps running. Only one re-poll is ever in flight.
pub(crate) struct PollCtl<'a> {
    cmds: &'a async_channel::Receiver<ControlCmd>,
    node_key_hex: &'a str,
    /// Copied in: publish #2 fills in `region` once the first netmap is known.
    publish: PublishCtx,
    interval: Option<core::time::Duration>,
    /// Rate limit and response deadline; fields (not constants) so tests can
    /// shrink them to milliseconds.
    min_gap: core::time::Duration,
    response_deadline: core::time::Duration,
    /// Next odd client stream ID (publish #2 is 7, so re-polls start at 9).
    next_stream_id: u32,
    /// When the last re-poll was sent, or when the connection came up (its
    /// bring-up just delivered a full map). Both the timer and the rate limit
    /// count from here.
    last_refresh: tokio::time::Instant,
    /// `(stream id, when sent)` of the re-poll awaiting its response.
    inflight: Option<(u32, tokio::time::Instant)>,
    /// A `ControlCmd::Refresh` arrived and has not been served yet. It is
    /// served as soon as the rate limit allows rather than dropped, so a miss
    /// shortly after boot still leads to a refresh.
    cmd_pending: bool,
    /// A `Shutdown` arrived (or the command channel closed).
    pub(crate) shutdown: bool,
    /// When the roster changes gathered since the last snapshot are due to be
    /// published. Set by the first change, never moved by later ones.
    emit_at: Option<tokio::time::Instant>,
    coalesce: core::time::Duration,
    /// A snapshot has been published on this connection. The first one is
    /// not delayed: it carries our IP and the DERPMap that bring-up waits for.
    published: bool,
    /// Announce `OurIpAssigned` from the stream's first netmap (production).
    /// Off by default so tests that only watch `MapUpdate`s are unchanged.
    announce_ip: bool,
    /// `OurIpAssigned` has been sent (readiness reached).
    ip_announced: bool,
    /// Send publish #2 as soon as the first snapshot yields a home region.
    pending_publish2: bool,
    /// Until `OurIpAssigned`, the poll fails with `Timeout` past this instant:
    /// `connect_timeout` still bounds readiness even though the first netmap
    /// now arrives on the unbounded poll rather than inside bring-up.
    ready_deadline: Option<tokio::time::Instant>,
}

impl<'a> PollCtl<'a> {
    pub(crate) fn new(cmds: &'a async_channel::Receiver<ControlCmd>, node_key_hex: &'a str,
                      publish: &PublishCtx, interval: Option<core::time::Duration>) -> Self {
        Self {
            cmds, node_key_hex, publish: *publish, interval,
            min_gap: MIN_REFRESH_GAP, response_deadline: REFRESH_RESPONSE_DEADLINE,
            next_stream_id: FIRST_REPOLL_STREAM_ID,
            last_refresh: tokio::time::Instant::now(),
            inflight: None, cmd_pending: false, shutdown: false,
            emit_at: None, coalesce: EMIT_COALESCE, published: false,
            announce_ip: false, ip_announced: false, pending_publish2: false,
            ready_deadline: None,
        }
    }

    fn is_refresh_stream(&self, id: u32) -> bool {
        matches!(self.inflight, Some((i, _)) if i == id)
    }

    /// The roster changed: schedule a snapshot unless one is already due.
    fn note_change(&mut self, now: tokio::time::Instant) {
        if self.emit_at.is_none() {
            let delay = if self.published { self.coalesce } else { core::time::Duration::ZERO };
            self.emit_at = Some(now + delay);
        }
    }

    /// `true` (once) when the gathered changes should be published now.
    fn emit_due(&mut self, now: tokio::time::Instant) -> bool {
        match self.emit_at {
            Some(t) if now >= t => { self.emit_at = None; self.published = true; true }
            _ => false,
        }
    }

    fn emit_pending(&self) -> bool { self.emit_at.is_some() }

    /// The earliest instant a time-based decision is due.
    fn next_timer(&self) -> Option<tokio::time::Instant> {
        let ready = self.ready_deadline.filter(|_| !self.ip_announced);
        [self.next_refresh_timer(), self.emit_at, ready].into_iter().flatten().min()
    }

    /// `true` once readiness is overdue (no `OurIpAssigned` by the deadline).
    fn ready_overdue(&self, now: tokio::time::Instant) -> bool {
        !self.ip_announced && self.ready_deadline.is_some_and(|d| now >= d)
    }

    fn next_refresh_timer(&self) -> Option<tokio::time::Instant> {
        match self.inflight {
            Some((_, sent)) => Some(sent + self.response_deadline),
            None => {
                let periodic = self.interval.map(|i| self.last_refresh + i);
                let on_cmd = self.cmd_pending.then(|| self.last_refresh + self.min_gap);
                match (periodic, on_cmd) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
        }
    }

    /// Abandon an overdue in-flight re-poll, then say whether a new one should
    /// be sent now.
    fn refresh_wanted(&mut self, now: tokio::time::Instant, h2: &mut H2State) -> bool {
        if let Some((id, sent)) = self.inflight {
            if now >= sent + self.response_deadline {
                tracing::warn!("Tailscale re-poll on stream {} got no complete response in {:?}; abandoning it", id, self.response_deadline);
                self.inflight = None;
                h2.stream_done(id);
            }
        }
        if self.inflight.is_some() { return false; }
        let gap_ok = now >= self.last_refresh + self.min_gap;
        let periodic = self.interval.is_some_and(|i| now >= self.last_refresh + i);
        (self.cmd_pending && gap_ok) || periodic
    }

    /// `true` if `id` was the in-flight re-poll (now finished).
    fn finish_refresh(&mut self, id: u32, h2: &mut H2State) -> bool {
        match self.inflight {
            Some((i, _)) if i == id => { self.inflight = None; h2.stream_done(id); true }
            _ => false,
        }
    }

    /// Wait for the next record, a command, a timer, or the idle deadline.
    /// `biased`: a record that is already readable always wins, so timers and
    /// commands are looked at only while the stream is quiet (and
    /// `refresh_wanted` covers a busy stream at the top of every frame).
    #[inline(never)]
    async fn wait<S: embedded_io_async::Read + embedded_io_async::Write>(
        &mut self, noise: &mut NoiseChannel, stream: &mut S,
        idle_at: Option<tokio::time::Instant>,
    ) -> Result<Wake, ControlError> {
        let timer_at = self.next_timer();
        tokio::select! {
            biased;
            r = noise.wait_readable(stream) => { r?; Ok(Wake::Readable) }
            cmd = self.cmds.recv() => {
                match cmd {
                    Ok(ControlCmd::Refresh) => self.cmd_pending = true,
                    Ok(ControlCmd::Shutdown) | Err(_) => self.shutdown = true,
                    // Start/Reauth have nothing to do on a live poll; they used
                    // to sit unread in the queue, now they are consumed.
                    Ok(_) => {}
                }
                Ok(Wake::Other)
            }
            _ = sleep_until_opt(timer_at) => Ok(Wake::Other),
            _ = sleep_until_opt(idle_at) => Err(ControlError::PollIdle),
        }
    }
}

async fn sleep_until_opt(t: Option<tokio::time::Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => core::future::pending::<()>().await,
    }
}

/// `noise.read_exact`, bounded by `idle` when set. On expiry the read is
/// cancelled mid-record, which leaves the Noise channel unusable; that is fine
/// because the only caller reacts to `PollIdle` by dropping the connection.
async fn read_exact_idle<S: embedded_io_async::Read + embedded_io_async::Write>(
    noise: &mut NoiseChannel, stream: &mut S, out: &mut [u8],
    idle: Option<core::time::Duration>,
) -> Result<(), ControlError> {
    match idle {
        Some(d) => tokio::time::timeout(d, noise.read_exact(stream, out))
            .await
            .map_err(|_| ControlError::PollIdle)?,
        None => noise.read_exact(stream, out).await,
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
                let (cwu, swu) = h2.consumed(expected_stream, payload.len() as u32);
                if cwu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,0,cwu); noise.write_all(stream,&b).await?; debug!("read_one_h2_body[{}]: sent conn WINDOW_UPDATE +{}", expected_stream, cwu); }
                if swu > 0 { let mut b=[0u8;13]; write_window_update(&mut b,expected_stream,swu); noise.write_all(stream,&b).await?; debug!("read_one_h2_body[{}]: sent stream WINDOW_UPDATE +{}", expected_stream, swu); }
                if end_stream { info!("read_one_h2_body[{}]: END_STREAM, total {} B", expected_stream, body.len()); h2.stream_done(expected_stream); return Ok(body); }
            }
            FrameAction::SendSettingsAck => { debug!("read_one_h2_body[{}]: SETTINGS -> ack", expected_stream); let mut a=[0u8;9]; write_settings_ack(&mut a); noise.write_all(stream,&a).await?; }
            FrameAction::SendPingAck(p) => { debug!("read_one_h2_body[{}]: PING -> ack", expected_stream); let mut a=[0u8;17]; write_ping_ack(&mut a,&p); noise.write_all(stream,&a).await?; }
            FrameAction::GoAway => { info!("read_one_h2_body[{}]: GOAWAY", expected_stream); return Err(ControlError::H2(H2Error::GoAway{last_stream:0,error_code:0})); }
            FrameAction::Ignore => {
                debug!("read_one_h2_body[{}]: Ignore (type={})", expected_stream, hdr.frame_type);
                // An empty 200 (a lite MapRequest's answer) is a HEADERS frame
                // carrying END_STREAM with no DATA at all.
                if hdr.frame_type == FRAME_TYPE_HEADERS && hdr.is_end_stream() && hdr.stream_id == expected_stream {
                    info!("read_one_h2_body[{}]: END_STREAM on headers, empty body", expected_stream);
                    h2.stream_done(expected_stream);
                    return Ok(body);
                }
            }
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

    /// The dial exclusion is process-wide and other tests may briefly hold it
    /// through a reconnect, so take it first (generous bound), then check the
    /// bounded wait: held -> `None` after ~max_wait; released -> `Some`.
    #[tokio::test]
    async fn dial_guard_wait_is_bounded_and_releases() {
        let held = acquire_dial_guard(core::time::Duration::from_secs(10)).await
            .expect("exclusion must free up");
        let t0 = std::time::Instant::now();
        let none = acquire_dial_guard(core::time::Duration::from_millis(300)).await;
        assert!(none.is_none(), "must give up while another holder is alive");
        assert!(t0.elapsed() >= core::time::Duration::from_millis(300));
        drop(held);
        let again = acquire_dial_guard(core::time::Duration::from_secs(10)).await;
        assert!(again.is_some(), "free after the holder drops");
    }
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
            name: PeerName::default(),
            derp_region,
            is_online,
        }
    }

    fn map_of(regions: &[DerpRegion], peers: &[PeerInfo]) -> MapState {
        let mut m = MapState { our_ip: TailnetIp([100, 64, 0, 1]), peers: ArrayVec::new(), derp_regions: ArrayVec::new(), names: MapNames::default() };
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

    /// `run()` clears and sets the process-wide `login` state, so tests that
    /// run the actor must not overlap.
    static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    async fn run_once(config: Config) -> ControlEvent {
        run_once_with_flag(config).await.0
    }

    /// The first event, and `login::control_key_rejected()` as `run()` left it.
    async fn run_once_with_flag(config: Config) -> (ControlEvent, bool) {
        let _serial = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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

        let ev = ev_rx.recv().await.expect("expected a ControlEvent");
        (ev, login::control_key_rejected())
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
            refresh_interval: None,
            lan_udp_port: None,
            old_node_key: None,
            login_allowed: true,
            hostname: "esp32c3",
            os_version: heapless::String::new(),
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
            refresh_interval: None,
            lan_udp_port: None,
            old_node_key: None,
            login_allowed: true,
            hostname: "esp32c3",
            os_version: heapless::String::new(),
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
            connect_timeout: None, refresh_interval: None, lan_udp_port: None, old_node_key: None, login_allowed: true, hostname: "esp32c3",
            os_version: heapless::String::new(), services,
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
        let body = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, 11, lan, false).unwrap();
        let ours: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut py: serde_json::Value = serde_json::from_str(include_str!(
            "../../tools/wg_validator/publish2_lan_body.json")).unwrap();
        assert_eq!(py["Hostinfo"]["OS"], "linux");
        py["Hostinfo"]["OS"] = "embedded".into();
        let mut ours = ours;
        // Identity fields the Python probe does not send.
        for k in ["IPNVersion", "Machine"] {
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
        let new = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, region, None, false).unwrap();
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
        let body = publish2_body(&cfg(&[]), NODE_HEX, DISCO_HEX, 11, None, false).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["Hostinfo"]["IPNVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["Hostinfo"]["Machine"], std::env::consts::ARCH);
        assert!(v["Hostinfo"].get("OSVersion").is_none(), "empty os_version is omitted");
        assert!(v["Hostinfo"].get("App").is_none());
        let c = Config { os_version: check_os_version("ESP32-C3 r0.4 tasmolike-rs 1.2.3").unwrap(), ..cfg(&[]) };
        let body = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, None, false).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["Hostinfo"]["OSVersion"], "ESP32-C3 r0.4 tasmolike-rs 1.2.3");
    }

    #[test]
    fn publish2_carries_hostname_and_services() {
        let c = Config { hostname: "kitchen-1", ..cfg(&ONE) };
        let body = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, None, false).unwrap();
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
            followup: "",
        }).unwrap();
        let poll = to_json_buf(&MapRequest {
            version: CAPABILITY_VERSION, compress: "", keep_alive: true,
            node_key: NODE_HEX, endpoints: &[], stream: true, disco_key: None,
            hostinfo: Some(host_info(&c, None)), omit_peers: true,
        }).unwrap();
        let pub2 = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, None, false).unwrap();
        let svc = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap()["Hostinfo"]["Services"].clone();
        assert!(!svc(&reg).is_null());
        assert_eq!(svc(&reg), svc(&poll));
        assert_eq!(svc(&reg), svc(&pub2));
    }

    #[test]
    fn max_services_fit_the_request_cap() {
        let c = Config {
            hostname: "a-63-char-label-0123456789-0123456789-0123456789-0123456789",
            os_version: check_os_version(&"v".repeat(MAX_OS_VERSION)).unwrap(),
            ..cfg(&FOUR)
        };
        assert!(check_services(&FOUR).is_ok());
        let lan = lan_endpoint("192.168.15.20:50000".parse().unwrap(), 41641);
        let body = publish2_body(&c, NODE_HEX, DISCO_HEX, 11, lan, false).unwrap();
        assert!(body.len() <= REQUEST_BODY_CAP);
        let reg = to_json_buf(&RegisterRequest {
            version: CAPABILITY_VERSION, node_key: NODE_HEX, old_node_key: Some(NODE_HEX),
            auth: RegisterAuth { auth_key: &"k".repeat(128) }, hostinfo: host_info(&c, None),
            followup: "",
        }).unwrap();
        assert!(reg.len() <= REQUEST_BODY_CAP);
    }

    #[test]
    fn service_and_hostname_validation() {
        assert!(check_services(&[Service::tcp(0, "")]).is_err());
        assert!(check_services(&[Service::tcp(80, "0123456789abcdef0123456789abcdef0")]).is_err());
        assert!(check_services(&[Service::tcp(80, ""); MAX_SERVICES + 1]).is_err());
        assert!(check_os_version(&"v".repeat(MAX_OS_VERSION + 1)).is_err());
        assert!(check_os_version("tab\there").is_err() && check_os_version("caf\u{e9}").is_err());
        assert!(valid_hostname("esp32c3") && valid_hostname("a-b"));
        for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"a".repeat(64)] {
            assert!(!valid_hostname(bad), "{bad}");
        }
    }

    // ── Interactive login ─────────────────────────────────────────────────────

    fn reg_json(auth_key: &str, followup: &str) -> serde_json::Value {
        let body = register_body(&cfg(&[]), NODE_HEX, auth_key, followup).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// No key and no followup is the keyless request: neither `Auth` nor
    /// `Followup` may appear (tailscaled omits both), and the empty
    /// `OldNodeKey` must stay omitted too (it made control answer 500).
    #[test]
    fn keyless_register_omits_auth_followup_and_old_node_key() {
        let v = reg_json("", "");
        let o = v.as_object().unwrap();
        assert_eq!(o["NodeKey"], NODE_HEX);
        assert_eq!(o["Version"], CAPABILITY_VERSION);
        for k in ["Auth", "Followup", "OldNodeKey"] {
            assert!(!o.contains_key(k), "{k} must be omitted");
        }
        assert!(o.contains_key("Hostinfo"));
    }

    /// A renewal names the key it replaces, as the public `nodekey:` form, and
    /// nothing else about the request changes; no private key is in the body.
    #[test]
    fn renewal_register_carries_the_old_node_key() {
        let old = tm_keys::NodePrivateKey::derive_from_seed(b"old", b"label").public();
        let c = Config { old_node_key: Some(old.clone()), ..cfg(&[]) };
        let body = register_body(&c, NODE_HEX, "tskey-auth-x", "").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["OldNodeKey"], old.to_hex().as_str());
        assert_eq!(v["NodeKey"], NODE_HEX);
        assert_eq!(v["Auth"], serde_json::json!({"AuthKey": "tskey-auth-x"}));
        let text = core::str::from_utf8(&body).unwrap();
        assert_eq!(text.matches("nodekey:").count(), 2, "only the two public keys");
        // Without a renewal the field stays omitted.
        assert!(reg_json("tskey-auth-x", "").get("OldNodeKey").is_none());
        // Also on the keyless and followup forms.
        let c = Config { old_node_key: Some(old.clone()), ..cfg(&[]) };
        let body = register_body(&c, NODE_HEX, "", "https://x/a/1").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["OldNodeKey"], old.to_hex().as_str());
    }

    /// The auth-key path is byte-for-byte what it was: `Auth.AuthKey`, no `Followup`.
    #[test]
    fn auth_key_register_body_is_unchanged() {
        let v = reg_json("tskey-auth-x", "");
        assert_eq!(v["Auth"], serde_json::json!({"AuthKey": "tskey-auth-x"}));
        assert!(v.get("Followup").is_none());
    }

    /// After an AuthURL the next register repeats the node key and carries the
    /// URL as `Followup`, without the (spent) key.
    #[test]
    fn followup_register_carries_the_url_and_no_auth() {
        let url = "https://login.tailscale.com/a/0123456789abc";
        let v = reg_json("", url);
        assert_eq!(v["Followup"], url);
        assert_eq!(v["NodeKey"], NODE_HEX);
        assert!(v.get("Auth").is_none());
        let max = "f".repeat(login::LOGIN_URL_MAX);
        let body = register_body(&cfg(&FOUR), NODE_HEX, "", &max).unwrap();
        assert!(body.len() <= REQUEST_BODY_CAP);
    }

    /// Verbatim shape of a keyless register answer from the real control
    /// server (captured live, URL id replaced): `AuthURL` set, not authorized.
    const LOGIN_RESPONSE: &str = r#"{"User":{"ID":0,"DisplayName":""},"Login":{"ID":0,"Provider":"","LoginName":"","DisplayName":""},"NodeKeyExpired":false,"MachineAuthorized":false,"AuthURL":"https://login.tailscale.com/a/0123456789abc","NodeKeySignature":null,"Error":""}"#;
    const AUTHORIZED_RESPONSE: &str = r#"{"User":{"ID":1,"DisplayName":"a"},"Login":{"ID":1,"Provider":"google","LoginName":"a@example.com","DisplayName":"a"},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","NodeKeySignature":null,"Error":""}"#;

    #[test]
    fn auth_url_response_asks_for_login() {
        let reg = parse_register_response(LOGIN_RESPONSE.as_bytes()).unwrap();
        assert!(!reg.machine_authorized && !reg.node_key_expired);
        match classify_register(&reg).unwrap() {
            RegisterOutcome::LoginNeeded(u) => assert_eq!(u, "https://login.tailscale.com/a/0123456789abc"),
            RegisterOutcome::Authorized => panic!("must ask for login"),
        }
    }

    #[test]
    fn authorized_response_proceeds_without_login() {
        let reg = parse_register_response(AUTHORIZED_RESPONSE.as_bytes()).unwrap();
        assert!(reg.machine_authorized);
        assert!(matches!(classify_register(&reg).unwrap(), RegisterOutcome::Authorized));
        // A keyless resume of an authorized node may omit every optional field.
        let reg = parse_register_response(br#"{"MachineAuthorized":true}"#).unwrap();
        assert!(matches!(classify_register(&reg).unwrap(), RegisterOutcome::Authorized));
    }

    #[test]
    fn refusals_and_expiry_are_not_logins() {
        let bad = |j: &str| classify_register(&parse_register_response(j.as_bytes()).unwrap());
        assert!(matches!(bad(r#"{"Error":"invalid key"}"#), Err(ControlError::RegistrationFailed)));
        // Expired with no URL to log in at: a distinct, recognizable error so
        // the app can start a renewal (see classify_register).
        assert!(matches!(bad(r#"{"NodeKeyExpired":true}"#), Err(ControlError::NodeKeyExpired)));
        // Expired but control offered a URL: that is a login.
        assert!(matches!(
            bad(r#"{"NodeKeyExpired":true,"AuthURL":"https://x/a/1"}"#),
            Ok(RegisterOutcome::LoginNeeded(_))
        ));
        assert!(parse_register_response(b"not json").is_err());
    }

    /// With login allowed (the default) an AuthURL starts the usual wait; with
    /// it off the same answer ends bring-up with `LoginRequired`, before any
    /// URL is published.
    #[test]
    fn login_not_allowed_ends_a_fresh_login_answer() {
        assert!(cfg(&[]).login_allowed, "default is to allow");
        assert!(check_login_allowed(&cfg(&[]), false).is_ok());
        let silent = Config { login_allowed: false, ..cfg(&[]) };
        assert!(matches!(check_login_allowed(&silent, false), Err(ControlError::LoginRequired)));
        assert!(check_login_allowed(&silent, true).is_ok(), "a followup is a wait already agreed to");
        // The AuthURL answer that triggers it (also on a rotation, with OldNodeKey).
        let reg = parse_register_response(LOGIN_RESPONSE.as_bytes()).unwrap();
        assert!(matches!(classify_register(&reg), Ok(RegisterOutcome::LoginNeeded(_))));
    }

    #[test]
    fn app_visible_refusal_follows_the_error() {
        use login::Refusal;
        assert_eq!(refusal_of(&ControlError::LoginRequired), Some(Refusal::LoginRequired));
        assert_eq!(refusal_of(&ControlError::NodeKeyExpired), Some(Refusal::NodeKeyExpired));
        assert_eq!(refusal_of(&ControlError::RegistrationFailed), None);
        assert_eq!(refusal_of(&ControlError::Io), None);
        let _serial = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        login::set_refusal(Some(Refusal::NodeKeyExpired));
        assert_eq!(login::refusal(), Some(Refusal::NodeKeyExpired));
        login::set_refusal(None);
        assert_eq!(login::refusal(), None);
    }

    /// A server that reads our Noise initiation, cannot decrypt it, and hangs
    /// up without a word (what the real one does for a wrong pinned key, see
    /// `read_101_response`): confirmed on a second dial, reported distinctly.
    #[tokio::test]
    async fn silent_close_twice_is_control_key_rejected() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dials = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let d = dials.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                d.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Read the upgrade request first: closing with it unread would
                // make the kernel send a reset, which is not what a server
                // that processed the initiation does.
                let mut buf = [0u8; 512];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                drop(sock); // clean FIN, no response
            }
        });
        let config = Config { control_host: leak_host(addr), control_port: addr.port(), ..cfg(&[]) };
        let (ev, flag) = run_once_with_flag(config).await;
        assert!(matches!(ev, ControlEvent::Error(ControlError::ControlKeyRejected)), "got a different event");
        assert!(flag, "the app-visible flag must be set");
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 2, "one confirming redial, no more");
    }

    /// A refused connection is a network problem, never a key verdict.
    #[tokio::test]
    async fn refused_connection_is_not_control_key_rejected() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let config = Config { control_host: leak_host(addr), control_port: addr.port(), ..cfg(&[]) };
        let (ev, flag) = run_once_with_flag(config).await;
        assert!(matches!(ev, ControlEvent::Error(ControlError::Io)), "got a different event");
        assert!(!flag);
    }

    /// The readiness deadline does not run while a login is pending, and
    /// restarts in full when it ends.
    #[tokio::test]
    async fn ready_gate_pauses_for_login_and_restarts_after() {
        let gate = ReadyGate::new(Some(Duration::from_millis(80)));
        gate.pause();
        assert!(tokio::time::timeout(Duration::from_millis(200), gate.expired()).await.is_err(),
                "paused gate must not expire");
        gate.resume();
        let t0 = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(2), gate.expired()).await.expect("must expire after resume");
        assert!(t0.elapsed() >= Duration::from_millis(70), "full budget restarts on resume");
        // No budget configured: never expires, pause/resume change nothing.
        let unbounded = ReadyGate::new(None);
        unbounded.resume();
        assert!(tokio::time::timeout(Duration::from_millis(100), unbounded.expired()).await.is_err());
        assert!(unbounded.deadline().is_none());
    }

    #[test]
    fn login_url_state_roundtrip_and_oversize() {
        let _serial = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        login::clear_login_url();
        assert!(login::login_url().is_none());
        assert!(login::set_login_url("https://login.tailscale.com/a/abc"));
        assert_eq!(login::login_url().unwrap().as_str(), "https://login.tailscale.com/a/abc");
        assert!(!login::set_login_url(&"u".repeat(login::LOGIN_URL_MAX + 1)));
        assert!(login::login_url().is_none(), "an oversize URL must not leave a stale or truncated one");
        login::clear_login_url();
    }

    // ── Mock control server over an in-memory Noise channel ───────────────────
    //
    // `NoiseChannel::test_pair` gives matching client/server channels, so the
    // real `stream_map_response` can be driven by hand-written H2 frames with
    // no handshake and no sockets.

    type MockStream = embedded_io_adapters::tokio_1::FromTokio<tokio::io::DuplexStream>;

    struct MockServer { noise: NoiseChannel, io: MockStream }

    impl MockServer {
        /// (client noise, client io, server)
        fn pair() -> (NoiseChannel, MockStream, MockServer) {
            let (cn, sn) = NoiseChannel::test_pair();
            let (c, s) = tokio::io::duplex(64 * 1024);
            (cn, MockStream::new(c), MockServer { noise: sn, io: MockStream::new(s) })
        }

        async fn frame(&mut self, ty: u8, flags: u8, stream: u32, body: &[u8]) {
            let mut f = Vec::with_capacity(9 + body.len());
            f.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            f.push(ty);
            f.push(flags);
            f.extend_from_slice(&stream.to_be_bytes());
            f.extend_from_slice(body);
            self.noise.write_all(&mut self.io, &f).await.unwrap();
        }

        /// One length-prefixed MapResponse as a single DATA frame.
        async fn map_msg(&mut self, stream: u32, json: &str, end_stream: bool) {
            let mut body = (json.len() as u32).to_le_bytes().to_vec();
            body.extend_from_slice(json.as_bytes());
            self.frame(0, if end_stream { 1 } else { 0 }, stream, &body).await;
        }
    }

    fn actor_for_tests() -> ControlActor {
        ControlActor::new(cfg(&[]), NodeState::generate())
    }

    /// A poll that receives nothing at all must end with `PollIdle` once the
    /// watchdog expires, instead of waiting forever on a half-open
    /// connection.
    #[tokio::test]
    async fn silent_poll_stream_trips_the_read_watchdog() {
        let (mut cn, mut cio, _server) = MockServer::pair();
        let (ev_tx, _ev_rx) = async_channel::bounded::<ControlEvent>(4);
        let actor = actor_for_tests();
        let mut h2 = H2State::new();
        let t0 = std::time::Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut Roster::new(), MAP_STREAM_ID, true,
                                      Some(Duration::from_millis(80)), None),
        ).await.expect("the watchdog must fire, not hang");
        assert!(matches!(r, Err(ControlError::PollIdle)), "got {:?}", r.map(|_| ()));
        assert!(t0.elapsed() >= Duration::from_millis(80));
    }

    /// Any frame (a keepalive here) restarts the deadline: three keepalives
    /// spaced inside the window keep the poll alive for longer than one
    /// window, and only the silence after them ends it.
    #[tokio::test]
    async fn keepalives_defer_the_watchdog() {
        let (mut cn, mut cio, mut server) = MockServer::pair();
        let (ev_tx, ev_rx) = async_channel::bounded::<ControlEvent>(4);
        let actor = actor_for_tests();
        let mut h2 = H2State::new();
        let feeder = async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(60)).await;
                server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await;
            }
            // Hold the server side open and silent: dropping it would be EOF.
            std::future::pending::<()>().await
        };
        let t0 = std::time::Instant::now();
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_millis(100)), None);
        let r = tokio::select! {
            r = poll => r,
            _ = feeder => unreachable!(),
        };
        assert!(matches!(r, Err(ControlError::PollIdle)));
        // 3 keepalives at 60 ms each, then a 100 ms silence.
        assert!(t0.elapsed() >= Duration::from_millis(270), "elapsed {:?}", t0.elapsed());
        assert!(ev_rx.try_recv().is_err(), "an empty keepalive must not emit a MapUpdate");
    }

    /// Without a watchdog (publishes) an idle stream is not an error: only
    /// the explicit outer timeout ends this read.
    #[tokio::test]
    async fn no_idle_timeout_means_no_watchdog() {
        let (mut cn, mut cio, _server) = MockServer::pair();
        let (ev_tx, _ev_rx) = async_channel::bounded::<ControlEvent>(4);
        let actor = actor_for_tests();
        let mut h2 = H2State::new();
        let r = tokio::time::timeout(
            Duration::from_millis(200),
            actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut Roster::new(), MAP_PUBLISH_STREAM_ID, true, None, None),
        ).await;
        assert!(r.is_err(), "no watchdog: the read must still be pending");
    }

    // ── Re-poll on the open poll connection ───────────────────────────────────

    impl MockServer {
        /// Next client frame: (type, flags, stream, body).
        async fn read_frame(&mut self) -> (u8, u8, u32, Vec<u8>) {
            let mut h = [0u8; 9];
            self.noise.read_exact(&mut self.io, &mut h).await.unwrap();
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let mut body = vec![0u8; len];
            self.noise.read_exact(&mut self.io, &mut body).await.unwrap();
            (h[3], h[4], u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]), body)
        }

        /// Read client frames until the request on `stream` arrives (HEADERS
        /// then DATA); returns the parsed JSON body. WINDOW_UPDATEs and other
        /// frames on the way are skipped.
        async fn read_request(&mut self, stream: u32) -> serde_json::Value {
            let mut saw_headers = false;
            loop {
                let (ty, _flags, sid, body) = self.read_frame().await;
                if sid != stream { continue; }
                match ty {
                    1 => saw_headers = true,
                    0 => {
                        assert!(saw_headers, "request body before its HEADERS");
                        return serde_json::from_slice(&body).unwrap();
                    }
                    _ => {}
                }
            }
        }
    }

    const PEER_A: &str = r#"{"Key":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","DiscoKey":"discokey:2021222324252627282920212223242526272829202122232425262728293031","Addresses":["100.64.0.2/32"],"DERP":"127.3.3.40:7","Online":true,"Hostinfo":{"Hostname":"peer-a"}}"#;
    const PEER_B: &str = r#"{"Key":"nodekey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","DiscoKey":"discokey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","Addresses":["100.64.0.3/32"],"DERP":"127.3.3.40:2","Online":true,"Hostinfo":{"Hostname":"peer-b"}}"#;

    fn map_json(peers: &[&str]) -> String {
        format!(r#"{{"Node":{{"Addresses":["100.64.0.1/32"]}},"Peers":[{}]}}"#, peers.join(","))
    }

    struct PollRig {
        cn: NoiseChannel, cio: MockStream, server: MockServer,
        ev_tx: async_channel::Sender<ControlEvent>, ev_rx: async_channel::Receiver<ControlEvent>,
        cmd_tx: async_channel::Sender<ControlCmd>, cmd_rx: async_channel::Receiver<ControlCmd>,
        actor: ControlActor, publish: PublishCtx,
    }

    impl PollRig {
        fn new() -> Self {
            let (cn, cio, server) = MockServer::pair();
            let (ev_tx, ev_rx) = async_channel::bounded(8);
            let (cmd_tx, cmd_rx) = async_channel::bounded(8);
            Self { cn, cio, server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor: actor_for_tests(),
                   publish: PublishCtx { region: Some(7), lan: None } }
        }
    }

    /// The timer sends a re-poll on stream 9 with the publish #2 body and
    /// `OmitPeers=false`; a response split across frames, with long-poll
    /// keepalives interleaved between them, is parsed into a MapUpdate; the
    /// next re-poll goes out on stream 11 and its different response changes
    /// the emitted MapUpdate; Shutdown then ends the poll cleanly.
    #[tokio::test]
    async fn timer_repoll_emits_each_new_map_and_interleaves_with_the_long_poll() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, Some(Duration::from_millis(40)));
        ctl.min_gap = Duration::from_millis(10);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            let req = server.read_request(9).await;
            // `false` fields are omitted from the JSON.
            assert!(req.get("OmitPeers").is_none_or(|v| v == false), "a re-poll must ask for peers");
            assert!(req.get("Stream").is_none_or(|v| v == false), "a re-poll is not streaming");
            assert!(req["DiscoKey"].as_str().unwrap().starts_with("discokey:"), "a re-poll is a write: it must repeat the DiscoKey");
            assert!(req["Endpoints"].as_array().is_some_and(|e| !e.is_empty()), "and the published DERP-home endpoint");
            // Response in two DATA frames with a long-poll keepalive between.
            let json = map_json(&[PEER_A]);
            let mut msg = (json.len() as u32).to_le_bytes().to_vec();
            msg.extend_from_slice(json.as_bytes());
            let (a, b) = msg.split_at(msg.len() / 2);
            server.frame(0, 0, 9, a).await;
            server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await;
            server.frame(0, 1, 9, b).await;
            let ev = ev_rx.recv().await.unwrap();
            match ev {
                ControlEvent::MapUpdate(m) => {
                    assert_eq!(m.peers.len(), 1);
                    assert_eq!(m.peers[0].hostname.as_str(), "peer-a");
                }
                _ => panic!("expected MapUpdate"),
            }
            // Second re-poll: a new stream, and a different map.
            let _ = server.read_request(11).await;
            server.map_msg(11, &map_json(&[PEER_A, PEER_B]), true).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 2, "the second MapResponse must change the update"),
                _ => panic!("expected MapUpdate"),
            }
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok(), "{:?}", r.map(|_| ()));
        assert!(ctl.shutdown);
    }

    /// A Refresh command inside the gap is deferred, not dropped, and two of
    /// them collapse into one re-poll sent only after the gap.
    #[tokio::test]
    async fn refresh_command_is_rate_limited_and_collapsed() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx: _ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.min_gap = Duration::from_millis(150);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            let t0 = std::time::Instant::now();
            cmd_tx.send(ControlCmd::Refresh).await.unwrap();
            cmd_tx.send(ControlCmd::Refresh).await.unwrap();
            let _ = server.read_request(9).await;
            assert!(t0.elapsed() >= Duration::from_millis(140), "sent {:?} after the command; the gap was ignored", t0.elapsed());
            server.map_msg(9, &map_json(&[PEER_A]), true).await;
            // Both commands were consumed by the first re-poll: no second one.
            let none = tokio::time::timeout(Duration::from_millis(400), server.read_request(11)).await;
            assert!(none.is_err(), "two Refresh commands must collapse into one re-poll");
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok());
    }

    fn with_id(peer: &str, id: u64) -> String {
        peer.replacen("{\"Key\"", &format!("{{\"ID\":{},\"Key\"", id), 1)
    }

    /// Streamed deltas on the long poll are merged into the roster and
    /// published as whole snapshots; a burst of them becomes ONE MapUpdate.
    #[tokio::test]
    async fn stream_deltas_merge_into_snapshots_and_bursts_coalesce() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.coalesce = Duration::from_millis(60);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let a = with_id(PEER_A, 1);
        let b = with_id(PEER_B, 2);
        let script = async {
            // The stream's first message is a whole map.
            server.map_msg(MAP_STREAM_ID, &map_json(&[&a]), false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 1),
                _ => panic!("expected MapUpdate"),
            }
            // A burst: an add, a DERP-home patch and a keepalive, back to back.
            server.map_msg(MAP_STREAM_ID, &format!(r#"{{"PeersChanged":[{}]}}"#, b), false).await;
            server.map_msg(MAP_STREAM_ID, r#"{"PeersChangedPatch":[{"NodeID":1,"DERPRegion":3}]}"#, false).await;
            server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => {
                    assert_eq!(m.peers.len(), 2, "the add is in the snapshot");
                    assert_eq!(m.peers[0].derp_region, 3, "and so is the patch, in the same one");
                    assert_eq!(m.peers[1].hostname.as_str(), "peer-b");
                }
                _ => panic!("expected MapUpdate"),
            }
            assert!(tokio::time::timeout(Duration::from_millis(300), ev_rx.recv()).await.is_err(),
                    "a burst must not produce a second MapUpdate");
            // Keepalives alone change nothing and publish nothing.
            server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await;
            assert!(tokio::time::timeout(Duration::from_millis(200), ev_rx.recv()).await.is_err());
            // An offline patch leaves the snapshot but needs no key from control.
            server.map_msg(MAP_STREAM_ID, r#"{"PeersChangedPatch":[{"NodeID":2,"Online":false}]}"#, false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 1),
                _ => panic!("expected MapUpdate"),
            }
            server.map_msg(MAP_STREAM_ID, r#"{"PeersChangedPatch":[{"NodeID":2,"Online":true}]}"#, false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 2, "back online with its old key and IP"),
                _ => panic!("expected MapUpdate"),
            }
            server.map_msg(MAP_STREAM_ID, r#"{"PeersRemoved":[1]}"#, false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 1),
                _ => panic!("expected MapUpdate"),
            }
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok(), "{:?}", r.map(|_| ()));
    }

    /// A stream message we cannot decode is a missed delta: the poll ends with
    /// an error so the caller reconnects and starts from a fresh map.
    #[tokio::test]
    async fn undecodable_or_oversize_stream_message_ends_the_poll() {
        for bad in [b"not json".to_vec(), (0xFFFF_FFFFu32).to_le_bytes().to_vec()] {
            let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx: _ev_rx, cmd_tx: _cmd_tx, cmd_rx, actor, publish } = PollRig::new();
            let mut h2 = H2State::new();
            let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
            let mut roster = Roster::new();
            let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                                 Some(Duration::from_secs(5)), Some(&mut ctl));
            let script = async {
                if bad.len() == 4 {
                    server.frame(0, 0, MAP_STREAM_ID, &bad).await;
                } else {
                    server.map_msg(MAP_STREAM_ID, std::str::from_utf8(&bad).unwrap(), false).await;
                }
            };
            let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
                .await.expect("poll hung");
            assert!(matches!(r, Err(ControlError::Json(_))), "{:?}", r.map(|_| ()));
        }
    }

    /// A broken re-poll response is only a failed correction: the roster keeps
    /// its peers and the long poll carries on.
    #[tokio::test]
    async fn broken_repoll_response_is_survivable() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.min_gap = Duration::from_millis(10);
        ctl.coalesce = Duration::from_millis(30);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            server.map_msg(MAP_STREAM_ID, &map_json(&[PEER_A]), false).await;
            let _ = ev_rx.recv().await.unwrap();
            cmd_tx.send(ControlCmd::Refresh).await.unwrap();
            let _ = server.read_request(9).await;
            server.map_msg(9, r#"{"Peers":[{"Key":"#, true).await;
            server.map_msg(MAP_STREAM_ID, &format!(r#"{{"PeersChanged":[{}]}}"#, with_id(PEER_B, 5)), false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 2, "PEER_A survived the broken re-poll"),
                _ => panic!("expected MapUpdate"),
            }
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok(), "{:?}", r.map(|_| ()));
    }

    const FIRST_MAP: &str = r#"{"Node":{"Addresses":["100.64.0.1/32"]},"DERPMap":{"Regions":{"7":{"RegionID":7,"RegionCode":"a","Nodes":[{"HostName":"d7.example"}]}}},"Peers":[PEERS]}"#;

    /// The stream's first message is the whole bring-up netmap: it announces
    /// our IP right away (not after the coalescing window), publishes the
    /// snapshot, and only then sends the lite publish #2 on stream 7 with the
    /// home region it implies. That publish's empty 200 (headers only) must
    /// not wedge the stream or leak a flow-control slot, and a fallback
    /// re-poll afterwards still gets a full body.
    #[tokio::test]
    async fn first_stream_message_announces_ip_then_sends_lite_publish2() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, .. } = PollRig::new();
        let mut h2 = H2State::new();
        let publish = PublishCtx { region: None, lan: None };
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.announce_ip = true;
        ctl.pending_publish2 = true;
        ctl.min_gap = Duration::from_millis(10);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            let t0 = std::time::Instant::now();
            server.map_msg(MAP_STREAM_ID, &FIRST_MAP.replace("PEERS", PEER_A), false).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::OurIpAssigned(ip) => assert_eq!(ip.0, [100, 64, 0, 1]),
                _ => panic!("the IP is announced first"),
            }
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => {
                    assert_eq!(m.peers.len(), 1);
                    assert_eq!(m.derp_regions.len(), 1);
                }
                _ => panic!("expected MapUpdate"),
            }
            assert!(t0.elapsed() < Duration::from_millis(150), "the first snapshot must not wait for the coalescing window");
            // Publish #2: lite, on the stream after the poll, naming region 7.
            let req = server.read_request(MAP_REPUBLISH_STREAM_ID).await;
            assert_eq!(req["OmitPeers"], true, "publish #2 is a lite write");
            assert!(req.get("Stream").is_none_or(|v| v == false));
            assert_eq!(req["Hostinfo"]["NetInfo"]["PreferredDERP"], 7);
            assert!(req["DiscoKey"].as_str().unwrap().starts_with("discokey:"));
            assert!(req["Endpoints"][0].as_str().unwrap().ends_with(":7"));
            // Its answer is an empty 200: HEADERS with END_STREAM, no DATA.
            server.frame(1, 0x5, MAP_REPUBLISH_STREAM_ID, &[0x88]).await;
            // The poll is unaffected, and publish #2 is sent only once.
            server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await;
            // A fallback re-poll is a full (OmitPeers=false) request again.
            cmd_tx.send(ControlCmd::Refresh).await.unwrap();
            let rp = server.read_request(FIRST_REPOLL_STREAM_ID).await;
            assert!(rp.get("OmitPeers").is_none_or(|v| v == false), "a re-poll asks for the full map");
            assert_eq!(rp["Hostinfo"]["NetInfo"]["PreferredDERP"], 7, "and repeats the published home");
            server.map_msg(FIRST_REPOLL_STREAM_ID, &FIRST_MAP.replace("PEERS", &format!("{},{}", PEER_A, PEER_B)), true).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => assert_eq!(m.peers.len(), 2),
                _ => panic!("expected MapUpdate, not a second OurIpAssigned"),
            }
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok(), "{:?}", r.map(|_| ()));
        assert!(ctl.ip_announced && !ctl.pending_publish2);
        assert_eq!(ctl.publish.region, Some(7));
    }

    /// `connect_timeout` still bounds readiness: a stream that never delivers
    /// a netmap with our IP fails with `Timeout`; once the IP is announced the
    /// same deadline no longer applies.
    #[tokio::test]
    async fn readiness_deadline_bounds_the_wait_for_the_first_map() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx: _cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.announce_ip = true;
        ctl.ready_deadline = Some(tokio::time::Instant::now() + Duration::from_millis(150));
        let mut roster = Roster::new();
        // Keepalives alone (no IP) must not satisfy readiness.
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async { server.map_msg(MAP_STREAM_ID, r#"{"KeepAlive":true}"#, false).await; };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(matches!(r, Err(ControlError::Timeout)), "{:?}", r.map(|_| ()));
        assert!(ev_rx.try_recv().is_err());

        // With the IP announced in time, silence past the deadline is fine.
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        ctl.announce_ip = true;
        ctl.ready_deadline = Some(tokio::time::Instant::now() + Duration::from_millis(150));
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            server.map_msg(MAP_STREAM_ID, &map_json(&[PEER_A]), false).await;
            assert!(matches!(ev_rx.recv().await.unwrap(), ControlEvent::OurIpAssigned(_)));
            tokio::time::sleep(Duration::from_millis(400)).await;
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok(), "{:?}", r.map(|_| ()));
    }

    /// A poll the server ends without a body (an error status answered with
    /// HEADERS+END_STREAM, or a reset) is an error: reconnect, don't idle on
    /// a dead stream until the watchdog.
    #[tokio::test]
    async fn poll_closed_without_a_body_is_an_error() {
        for (ty, flags) in [(1u8, 0x5u8), (3, 0)] {
            let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx: _ev_rx, cmd_tx: _c, cmd_rx, actor, publish } = PollRig::new();
            let mut h2 = H2State::new();
            let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
            let mut roster = Roster::new();
            let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                                 Some(Duration::from_secs(5)), Some(&mut ctl));
            let script = async { server.frame(ty, flags, MAP_STREAM_ID, &[0, 0, 0, 8]).await; };
            let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
                .await.expect("poll hung");
            assert!(r.is_err(), "type {}", ty);
        }
    }

    /// A re-poll whose response never completes is abandoned after the
    /// deadline, and a stray late frame from it is skipped without breaking the
    /// next one.
    #[tokio::test]
    async fn stuck_repoll_is_abandoned_and_the_next_one_works() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, Some(Duration::from_millis(30)));
        ctl.min_gap = Duration::from_millis(10);
        ctl.response_deadline = Duration::from_millis(80);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            let _ = server.read_request(9).await;
            // Half a message, then silence on stream 9.
            server.frame(0, 0, 9, &[200, 0, 0, 0, b'{']).await;
            let _ = server.read_request(11).await;
            // The abandoned stream's late tail must be ignored.
            server.frame(0, 1, 9, b"garbage").await;
            server.map_msg(11, &map_json(&[PEER_B]), true).await;
            match ev_rx.recv().await.unwrap() {
                ControlEvent::MapUpdate(m) => {
                    assert_eq!(m.peers.len(), 1);
                    assert_eq!(m.peers[0].hostname.as_str(), "peer-b");
                }
                _ => panic!("expected MapUpdate"),
            }
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok());
    }

    /// An error answer to the re-poll (HEADERS+END_STREAM, no body) frees the
    /// slot at once instead of holding it until the deadline.
    #[tokio::test]
    async fn repoll_rejected_without_body_frees_the_slot() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx: _ev_rx, cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, Some(Duration::from_millis(30)));
        ctl.min_gap = Duration::from_millis(10);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_secs(5)), Some(&mut ctl));
        let script = async {
            let _ = server.read_request(9).await;
            server.frame(1, 0x5, 9, &[0x88]).await; // HEADERS, END_STREAM|END_HEADERS
            // Well inside the 60 s default deadline: only the early free can explain this.
            let _ = server.read_request(11).await;
            cmd_tx.send(ControlCmd::Shutdown).await.unwrap();
        };
        let (r, ()) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(poll, script) })
            .await.expect("poll hung");
        assert!(r.is_ok());
    }

    /// With the timer off and no command, the long poll just waits (and the
    /// watchdog still applies) rather than re-polling.
    #[tokio::test]
    async fn no_timer_no_repoll_but_watchdog_still_applies() {
        let PollRig { mut cn, mut cio, mut server, ev_tx, ev_rx: _ev_rx, cmd_tx: _cmd_tx, cmd_rx, actor, publish } = PollRig::new();
        let mut h2 = H2State::new();
        let mut ctl = PollCtl::new(&cmd_rx, NODE_HEX, &publish, None);
        let mut roster = Roster::new();
        let poll = actor.stream_map_response(&mut cio, &mut cn, &mut h2, &ev_tx, &mut roster, MAP_STREAM_ID, true,
                                             Some(Duration::from_millis(150)), Some(&mut ctl));
        let script = async {
            let quiet = tokio::time::timeout(Duration::from_millis(100), server.read_frame()).await;
            assert!(quiet.is_err(), "nothing may be sent without a trigger");
            std::future::pending::<()>().await
        };
        let r = tokio::select! { r = poll => r, _ = script => unreachable!() };
        assert!(matches!(r, Err(ControlError::PollIdle)));
    }

    /// A timer or command wake-up while a record is half-received must not
    /// lose Noise framing (the cancel-safe wait is what the poll loop relies on).
    #[tokio::test]
    async fn wait_readable_survives_cancellation_mid_record() {
        let (mut cn, mut sn) = NoiseChannel::test_pair();
        let plain: Vec<u8> = (0..200u8).collect();
        // Capture the wire bytes of one record.
        let (w, r) = tokio::io::duplex(4096);
        let mut wio = MockStream::new(w);
        sn.write_all(&mut wio, &plain).await.unwrap();
        drop(wio);
        let mut wire = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut { r }, &mut wire).await.unwrap();
        // Feed it in small slices, cancelling wait_readable after each one.
        let (mut tx, rx) = tokio::io::duplex(4096);
        let mut crx = MockStream::new(rx);
        for chunk in wire.chunks(7) {
            tokio::io::AsyncWriteExt::write_all(&mut tx, chunk).await.unwrap();
            // Completes on the last slice, is cancelled mid-record before it.
            let _ = tokio::time::timeout(Duration::from_millis(5), cn.wait_readable(&mut crx)).await;
        }
        cn.wait_readable(&mut crx).await.unwrap();
        let mut got = vec![0u8; plain.len()];
        cn.read_exact(&mut crx, &mut got).await.unwrap();
        assert_eq!(got, plain);
    }
}
