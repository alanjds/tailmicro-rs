//! Streaming (push) MapResponse decoder.
//!
//! A buffer-and-parse decoder would need the whole de-prefixed JSON body
//! (tens of KB, ~48 KB when the tailnet is inflated by ephemeral ghost peers)
//! in one contiguous allocation. On the ESP32-C3's fragmented ~57 KB heap
//! that `try_reserve_exact` fails, and the stream_map reader would then have
//! to discard the whole netmap to stay online -- losing the peers/DERPMap
//! that the data plane needs.
//!
//! This module feeds the body to a push (event) JSON parser [`actson`] as the
//! decrypted H2 DATA frames arrive, extracting only the handful of fields the
//! netmap actually contributes and applying them straight to the
//! [`Roster`](crate::roster::Roster). Nothing but actson's ~1 KB feeder ring
//! and a few small scratch structs is ever held, so there is no `mlen`-byte
//! contiguous allocation to fail. The push model is required: bytes arrive
//! across `await` points in a cooperative single-task runtime, so a
//! pull/`from_reader` parser would block the executor.
//!
//! One parser handles every message shape, because the control server mixes
//! them on one stream: a full map (`Node`, `Peers`, `DERPMap`, `DNSConfig`),
//! and deltas (`PeersChanged` upserts, `PeersRemoved`, `PeersChangedPatch`,
//! `OnlineChange`, `KeepAlive`, `DERPMap`/`DNSConfig` re-sends). Per tailcfg,
//! an absent field means "unchanged", so each field present is applied and
//! nothing else is touched.
//!
//! Extraction rules: first-IPv4-wins, region id from the key or body, peers
//! kept whether online or not (the [`Roster`](crate::roster::Roster) decides
//! what a snapshot shows). `PeerSeenChange` is ignored: it only moves
//! `LastSeen`, which the data plane does not use.

use actson::feeder::PushJsonFeeder;
use actson::{JsonEvent, JsonParser};
use arrayvec::ArrayVec;

use crate::map_scalars::{hex_key, parse_derp_region, parse_ipv4, region_id_or};
use crate::roster::{PeerPatch, Roster, MAX_REGIONS};
use crate::{split_node_name, suffix_hash, DerpRegion, PeerInfo, PeerName, TailnetIp};

/// Where we are in the MapResponse document. One is pushed per open
/// object/array; `Skip` covers any subtree we do not read (PacketFilter,
/// Endpoints, ...), so nested containers inside it just stack more `Skip`s.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Root,
    Node,
    NodeAddresses,
    /// `Peers`: the complete list, which replaces the roster's.
    Peers,
    /// `PeersChanged`: upserts.
    PeersChanged,
    PeersRemoved,
    PatchList,
    Patch,
    /// `OnlineChange`: `{"<NodeID>": bool}`, keys are decimal strings.
    OnlineChange,
    Peer,
    PeerAddresses,
    PeerHostinfo,
    DnsConfig,
    DerpMap,
    Regions,
    Region,
    RegionNodes,
    RegionNode,
    Skip,
}

/// What a message is allowed to mean for peers it does not mention.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// A full netmap by contract (a non-streaming request with
    /// `OmitPeers=false`): anything the message does not list is gone, even
    /// if `Peers` is absent because the tailnet has no other nodes.
    Full,
    /// A stream message: fields present are applied, absent ones mean
    /// "unchanged". A non-empty `Peers` is still a full replace.
    Delta,
}

/// Fields of the peer object currently being read, committed on `EndObject`.
#[derive(Default)]
struct PeerScratch {
    id: u64,
    key: Option<[u8; 32]>,
    disco: [u8; 32],
    ip: Option<[u8; 4]>,
    /// From the legacy `"DERP":"127.3.3.40:<n>"` string.
    derp_legacy: u16,
    /// From `HomeDERP`, which current control servers send instead (a 72
    /// client is not offered it by Tailscale, but headscale sends it).
    home_derp: u16,
    online: Option<bool>,
    hostname: heapless::String<64>,
    name: PeerName,
}

/// Fields of the DERP region currently being read, committed on `EndObject`.
struct RegionScratch {
    rid: heapless::String<8>,
    region_id: Option<u16>,
    region_code: heapless::String<8>,
    host: heapless::String<64>,
}

/// Error surfaced by the streaming decoder. Both collapse to the same
/// caller-visible `JsonError::ParseError`, but are kept
/// distinct here for logging.
#[derive(Debug)]
pub enum StreamError {
    /// The JSON was malformed / actson rejected it.
    Parse,
    /// A field name or scalar was longer than we can hold (defensive; the real
    /// server never emits these). We do not grow, so the message is rejected.
    Overflow,
}

impl From<StreamError> for crate::JsonError {
    fn from(_: StreamError) -> Self {
        crate::JsonError::ParseError
    }
}

/// Incremental MapResponse parser. Create one per length-prefixed message,
/// [`push`](Self::push) each body chunk as it is decrypted, then
/// [`finish`](Self::finish) once exactly `mlen` bytes have been fed. All
/// three take the [`Roster`] the message applies to.
///
/// A message that fails part way has already applied the elements before the
/// failure (each is valid server data) but never sweeps: see
/// [`Roster::tick`].
pub struct MapStreamParser {
    parser: JsonParser<PushJsonFeeder>,
    stack: ArrayVec<Ctx, 16>,
    /// Field name seen most recently, consumed by the next value/container.
    pending: heapless::String<32>,
    have_pending: bool,
    /// Set when this message replaces the peer list; swept at `finish`.
    floor: Option<u32>,
    peer: PeerScratch,
    patch: PeerPatch,
    region: Option<RegionScratch>,
    /// DERP regions of this message's `DERPMap`, committed at `finish` so a
    /// half-read map never replaces a good one.
    staged: ArrayVec<DerpRegion, MAX_REGIONS>,
    /// Whether this message's `Node.Addresses` already supplied our IP.
    ip_set: bool,
    proxied_set: bool,
    /// Whether the open `Node` object carried a `KeyExpiry`.
    expiry_set: bool,
    /// Set once a fatal parse/overflow error is seen; further input is ignored
    /// and surfaced from `finish`.
    failed: Option<StreamError>,
}

impl MapStreamParser {
    pub fn new(mode: Mode, roster: &mut Roster) -> Self {
        Self {
            parser: JsonParser::new(PushJsonFeeder::new()),
            stack: ArrayVec::new(),
            pending: heapless::String::new(),
            have_pending: false,
            floor: (mode == Mode::Full).then(|| roster.tick()),
            peer: PeerScratch::default(),
            patch: PeerPatch::default(),
            region: None,
            staged: ArrayVec::new(),
            ip_set: false,
            proxied_set: false,
            expiry_set: false,
            failed: None,
        }
    }

    /// Feed one chunk of body bytes, draining every event the parser can emit
    /// from the bytes fed so far. Returns when the chunk is exhausted (the
    /// caller awaits the next frame) -- NOT when parsing is done; call
    /// [`finish`](Self::finish) for that.
    pub fn push(&mut self, chunk: &[u8], roster: &mut Roster) -> Result<(), StreamError> {
        if self.failed.is_some() {
            return Ok(()); // already dead; drain silently, report at finish
        }
        let mut i = 0usize;
        loop {
            match self.parser.next_event() {
                Ok(Some(JsonEvent::NeedMoreInput)) => {
                    if i >= chunk.len() {
                        return Ok(());
                    }
                    i += self.parser.feeder.push_bytes(&chunk[i..]);
                }
                Ok(Some(ev)) => {
                    if let Err(e) = self.handle(ev, roster) {
                        self.failed = Some(e);
                        return Ok(());
                    }
                }
                // Ok(None) mid-message would mean the top-level value closed
                // before we fed `mlen` bytes: treat as malformed.
                Ok(None) => {
                    self.failed = Some(StreamError::Parse);
                    return Ok(());
                }
                Err(_) => {
                    self.failed = Some(StreamError::Parse);
                    return Ok(());
                }
            }
        }
    }

    /// Mark the body complete and drain the trailing events. On success the
    /// message's replace (peer sweep, DERP regions) is applied; on failure
    /// the roster keeps what it had.
    pub fn finish(mut self, roster: &mut Roster) -> Result<(), StreamError> {
        self.parser.feeder.done();
        loop {
            match self.parser.next_event() {
                Ok(Some(JsonEvent::NeedMoreInput)) => break, // nothing left to feed
                Ok(Some(ev)) => {
                    if let Err(e) = self.handle(ev, roster) {
                        self.failed = Some(e);
                        break;
                    }
                }
                Ok(None) => break, // clean end of document
                Err(_) => {
                    self.failed = Some(StreamError::Parse);
                    break;
                }
            }
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        // An unterminated document (fewer bytes than the prefix promised the
        // parser could not close) is malformed, not a clean empty one.
        if !self.stack.is_empty() {
            return Err(StreamError::Parse);
        }
        roster.set_regions(&self.staged);
        if let Some(f) = self.floor {
            roster.sweep(f);
        }
        Ok(())
    }

    fn top(&self) -> Ctx {
        self.stack.last().copied().unwrap_or(Ctx::Root)
    }

    /// Take (and clear) the pending field name, if any.
    fn take_name(&mut self) -> Option<heapless::String<32>> {
        if self.have_pending {
            self.have_pending = false;
            Some(core::mem::take(&mut self.pending))
        } else {
            None
        }
    }

    fn handle(&mut self, ev: JsonEvent, roster: &mut Roster) -> Result<(), StreamError> {
        match ev {
            JsonEvent::FieldName => {
                let s = self.parser.current_str().map_err(|_| StreamError::Parse)?;
                let mut name: heapless::String<32> = heapless::String::new();
                // A field name longer than 32 bytes is not one we key on; keep a
                // truncated copy so the following value still gets consumed as
                // "some ignored field" rather than misattributed.
                let _ = name.push_str(&s[..floor_char_boundary(s, 32)]);
                self.pending = name;
                self.have_pending = true;
            }

            JsonEvent::StartObject | JsonEvent::StartArray => {
                let is_obj = ev == JsonEvent::StartObject;
                let name = self.take_name();
                let parent = self.top();
                let next = self.enter(is_obj, name.as_deref());
                match next {
                    Ctx::Peer => {
                        self.peer = PeerScratch::default();
                        // A non-empty `Peers` in a stream message is the
                        // complete list: start the replace at its first peer.
                        if parent == Ctx::Peers && self.floor.is_none() {
                            self.floor = Some(roster.tick());
                        }
                    }
                    Ctx::Patch => self.patch = PeerPatch::default(),
                    Ctx::NodeAddresses => self.ip_set = false,
                    Ctx::DnsConfig => self.proxied_set = false,
                    Ctx::Node => self.expiry_set = false,
                    Ctx::Region => {
                        // The Regions object is keyed by region-id; that key is the
                        // field name that introduced this object.
                        let rid = name.unwrap_or_default();
                        let mut r8: heapless::String<8> = heapless::String::new();
                        let _ = r8.push_str(&rid[..floor_char_boundary(&rid, 8)]);
                        self.region = Some(RegionScratch {
                            rid: r8,
                            region_id: None,
                            region_code: heapless::String::new(),
                            host: heapless::String::new(),
                        });
                    }
                    _ => {}
                }
                self.stack.try_push(next).map_err(|_| StreamError::Overflow)?;
            }

            JsonEvent::EndObject | JsonEvent::EndArray => {
                let closed = self.stack.pop().unwrap_or(Ctx::Root);
                self.have_pending = false; // any dangling name dies with the container
                match closed {
                    Ctx::Peer => {
                        let full = self.top() == Ctx::Peers;
                        self.commit_peer(full, roster);
                    }
                    Ctx::Patch => {
                        if !roster.patch(&self.patch) {
                            // Control says to ignore these; also what happens to a
                            // peer we never admitted (no IPv4, roster full).
                            log::debug!("netmap patch for unknown node id {}", self.patch.id);
                        }
                    }
                    Ctx::Region => self.commit_region(),
                    // The self Node is always sent whole and the zero time may
                    // be omitted, so no `KeyExpiry` in it means no expiry.
                    Ctx::Node => {
                        if !self.expiry_set {
                            roster.set_self_key_expiry(None);
                        }
                    }
                    Ctx::DnsConfig => {
                        // `Proxied` is omitted from the wire when false.
                        if !self.proxied_set {
                            roster.set_proxied(false);
                        }
                    }
                    _ => {}
                }
            }

            JsonEvent::ValueString => {
                // Copy out of the parser's buffer so `scalar_str` can borrow
                // `&mut self`. 128 bytes covers every field we key on (the
                // longest is `"discokey:" + 64 hex` = 73); longer values belong
                // to ignored fields and are truncated harmlessly.
                let mut buf: heapless::String<128> = heapless::String::new();
                {
                    let val = self.parser.current_str().map_err(|_| StreamError::Parse)?;
                    let _ = buf.push_str(&val[..floor_char_boundary(val, 128)]);
                }
                self.scalar_str(&buf, roster);
                self.have_pending = false;
            }

            JsonEvent::ValueInt => {
                // Decode lazily to avoid the generic call where it is not needed.
                match self.top() {
                    Ctx::Region if self.name_is("RegionID") => {
                        if let Ok(v) = self.parser.current_int::<u16>() {
                            if let Some(r) = self.region.as_mut() {
                                r.region_id = Some(v);
                            }
                        }
                    }
                    Ctx::Peer if self.name_is("ID") => {
                        self.peer.id = self.parser.current_int::<u64>().unwrap_or(0);
                    }
                    Ctx::Peer if self.name_is("HomeDERP") => {
                        self.peer.home_derp = self.parser.current_int::<u16>().unwrap_or(0);
                    }
                    Ctx::Patch if self.name_is("NodeID") => {
                        self.patch.id = self.parser.current_int::<u64>().unwrap_or(0);
                    }
                    Ctx::Patch if self.name_is("DERPRegion") => {
                        self.patch.derp_region = self.parser.current_int::<u16>().unwrap_or(0);
                    }
                    Ctx::PeersRemoved => {
                        if let Ok(id) = self.parser.current_int::<u64>() {
                            roster.remove(id);
                        }
                    }
                    _ => {}
                }
                self.have_pending = false;
            }

            JsonEvent::ValueTrue | JsonEvent::ValueFalse => {
                let v = ev == JsonEvent::ValueTrue;
                match self.top() {
                    Ctx::Peer if self.name_is("Online") => self.peer.online = Some(v),
                    Ctx::Patch if self.name_is("Online") => self.patch.online = Some(v),
                    Ctx::DnsConfig if self.name_is("Proxied") => {
                        self.proxied_set = true;
                        roster.set_proxied(v);
                    }
                    Ctx::OnlineChange if self.have_pending => {
                        if let Ok(id) = self.pending.as_str().parse::<u64>() {
                            roster.set_online(id, v);
                        }
                    }
                    // `KeepAlive` needs no action: its arrival already reset
                    // the caller's idle watchdog.
                    _ => {}
                }
                self.have_pending = false;
            }

            JsonEvent::ValueFloat | JsonEvent::ValueNull => {
                self.have_pending = false;
            }

            JsonEvent::NeedMoreInput => {}
        }
        Ok(())
    }

    /// True if the pending field name equals `n`.
    fn name_is(&self, n: &str) -> bool {
        self.have_pending && self.pending.as_str() == n
    }

    /// Compute the context entered by an object/array start given the current
    /// top and the field name that introduced it.
    fn enter(&self, is_obj: bool, name: Option<&str>) -> Ctx {
        match (self.top(), name, is_obj) {
            // First container in the document is the root object.
            (Ctx::Root, _, true) if self.stack.is_empty() => Ctx::Root,

            (Ctx::Root, Some("Node"), true) => Ctx::Node,
            (Ctx::Root, Some("Peers"), false) => Ctx::Peers,
            (Ctx::Root, Some("PeersChanged"), false) => Ctx::PeersChanged,
            (Ctx::Root, Some("PeersRemoved"), false) => Ctx::PeersRemoved,
            (Ctx::Root, Some("PeersChangedPatch"), false) => Ctx::PatchList,
            (Ctx::Root, Some("OnlineChange"), true) => Ctx::OnlineChange,
            (Ctx::Root, Some("DERPMap"), true) => Ctx::DerpMap,
            (Ctx::Root, Some("DNSConfig"), true) => Ctx::DnsConfig,

            (Ctx::Node, Some("Addresses"), false) => Ctx::NodeAddresses,

            (Ctx::Peers, _, true) | (Ctx::PeersChanged, _, true) => Ctx::Peer,
            (Ctx::PatchList, _, true) => Ctx::Patch,
            (Ctx::Peer, Some("Addresses"), false) => Ctx::PeerAddresses,
            (Ctx::Peer, Some("Hostinfo"), true) => Ctx::PeerHostinfo,

            (Ctx::DerpMap, Some("Regions"), true) => Ctx::Regions,
            (Ctx::Regions, _, true) => Ctx::Region,
            (Ctx::Region, Some("Nodes"), false) => Ctx::RegionNodes,
            (Ctx::RegionNodes, _, true) => Ctx::RegionNode,

            // Anything else is a subtree we do not read.
            _ => Ctx::Skip,
        }
    }

    /// Apply a string value at the current location.
    fn scalar_str(&mut self, val: &str, roster: &mut Roster) {
        match self.top() {
            Ctx::NodeAddresses => {
                if !self.ip_set {
                    if let Some(ip) = parse_ipv4(val) {
                        self.ip_set = true;
                        roster.set_our_ip(ip);
                    }
                }
            }
            Ctx::Node => {
                if self.name_is("Name") {
                    let (label, suffix) = split_node_name(val);
                    if roster.set_self_name(label, suffix) {
                        // `suffix` is borrowed from `val`, our scratch copy: the
                        // app hook gets it and nothing here keeps it.
                        crate::selfnode::announce_suffix(suffix);
                    }
                } else if self.name_is("KeyExpiry") {
                    // Unparseable: keep what we had rather than claim a state.
                    if let Ok(exp) = crate::rfc3339::parse_key_expiry(val) {
                        roster.set_self_key_expiry(exp);
                    }
                    self.expiry_set = true;
                }
            }
            Ctx::PeerAddresses => {
                if self.peer.ip.is_none() {
                    if let Some(ip) = parse_ipv4(val) {
                        self.peer.ip = Some(ip);
                    }
                }
            }
            Ctx::Peer => {
                if self.name_is("Key") {
                    self.peer.key = hex_key(val);
                } else if self.name_is("DiscoKey") {
                    self.peer.disco = hex_key(val).unwrap_or([0; 32]);
                } else if self.name_is("DERP") {
                    self.peer.derp_legacy = parse_derp_region(val).unwrap_or(0);
                } else if self.name_is("Name") {
                    let (label, suffix) = split_node_name(val);
                    self.peer.name = PeerName { label, suffix_hash: suffix_hash(suffix) };
                }
            }
            Ctx::Patch => {
                if self.name_is("Key") {
                    self.patch.key = hex_key(val);
                } else if self.name_is("DiscoKey") {
                    self.patch.disco_key = hex_key(val);
                }
            }
            Ctx::PeerHostinfo => {
                if self.name_is("Hostname") {
                    self.peer.hostname.clear();
                    let _ = self.peer.hostname.push_str(&val[..floor_char_boundary(val, 64)]);
                }
            }
            Ctx::Region => {
                if self.name_is("RegionCode") {
                    if let Some(r) = self.region.as_mut() {
                        r.region_code.clear();
                        let _ = r.region_code.push_str(&val[..floor_char_boundary(val, 8)]);
                    }
                }
            }
            Ctx::RegionNode => {
                if self.name_is("HostName") {
                    if let Some(r) = self.region.as_mut() {
                        if r.host.is_empty() {
                            let _ = r.host.push_str(&val[..floor_char_boundary(val, 64)]);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Upsert the scratch peer into the roster. A peer needs a key and an IPv4
    /// to be routable; one without is dropped. `Online` absent means
    /// "unknown": a peer we already hold keeps its state, a new one starts
    /// offline (the same rule the boot map always had).
    fn commit_peer(&mut self, in_full_list: bool, roster: &mut Roster) {
        let p = core::mem::take(&mut self.peer);
        let (Some(key), Some(ip)) = (p.key, p.ip) else {
            return;
        };
        let online = p.online.or_else(|| roster.online_of(p.id, &key)).unwrap_or(false);
        let info = PeerInfo {
            node_key: key,
            disco_key: p.disco,
            tailnet_ip: TailnetIp(ip),
            prefix_len: 32,
            hostname: p.hostname,
            name: p.name,
            derp_region: if p.home_derp != 0 { p.home_derp } else { p.derp_legacy },
            is_online: online,
        };
        let floor = if in_full_list { self.floor } else { None };
        roster.upsert(p.id, info, floor);
    }

    /// Stage the scratch region (host required; region id from the body or,
    /// failing that, the map key). Regions past `MAX_REGIONS` are dropped.
    fn commit_region(&mut self) {
        let Some(r) = self.region.take() else {
            return;
        };
        if self.staged.is_full() || r.host.is_empty() {
            return;
        }
        let region_id = region_id_or(r.rid.as_str(), r.region_id);
        let _ = self.staged.try_push(DerpRegion {
            region_id,
            region_code: r.region_code,
            host: r.host,
            port: 443,
            latency_ms: 0,
        });
    }
}

/// Largest index `<= max` that is a char boundary of `s`, so a truncating
/// slice cannot panic on multi-byte UTF-8 (a hostname may contain any).
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if s.len() <= max {
        return s.len();
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::{MapStreamParser, Mode, StreamError};
    use crate::roster::{Roster, MAX_PEERS, ROSTER_CAP};
    use crate::MapState;

    /// Feed `body` in `chunk`-byte slices, mirroring how H2 DATA frames arrive.
    fn feed(mode: Mode, r: &mut Roster, body: &str, chunk: usize) -> Result<(), StreamError> {
        let mut p = MapStreamParser::new(mode, r);
        for c in body.as_bytes().chunks(chunk) {
            p.push(c, r)?;
        }
        p.finish(r)
    }

    fn snap(r: &Roster) -> Box<MapState> {
        r.snapshot()
    }

    fn hexk(n: u8) -> String {
        format!("{:02x}", n).repeat(32)
    }

    /// Chunk sizes that put message splits inside keys, values, escapes and
    /// structural bytes: the parser must be boundary-independent.
    const CHUNKS: [usize; 8] = [1, 2, 3, 7, 13, 64, 500, 4096];

    /// Run `f` once per chunk size on a fresh roster seeded by `seed`.
    fn sweep(seed: &str, mode: Mode, body: &str, check: impl Fn(&mut Roster, usize)) {
        for chunk in CHUNKS {
            let mut r = Roster::new();
            if !seed.is_empty() {
                feed(Mode::Full, &mut r, seed, 4096).unwrap();
            }
            feed(mode, &mut r, body, chunk).unwrap_or_else(|e| panic!("chunk={} {:?}", chunk, e));
            check(&mut r, chunk);
        }
    }

    // -- Full map shapes -----------------------------------------------------
    //
    // The golden JSON below is CONSTRUCTED, not captured from a live server:
    // field names, nesting and omitempty behaviour follow tailcfg.go (Node,
    // PeerChange, MapResponse) and headscale's mapper/builder.go and
    // types/change/change.go as fetched into the investigation notes. No
    // wire capture of a delta stream was available. They are shaped to what
    // each server marshals: Tailscale sends the legacy "DERP" string to a
    // cap-72 client, headscale sends HomeDERP and Online as a pointer.

    // Real MapResponse shape, including nested skipped subtrees whose strings
    // carry structural bytes ({}[],).
    const JSON: &str = r#"{
        "Node": {"Addresses": ["100.64.0.1/32", "fd7a:115c::a/128"], "Hostinfo": {"Hostname": "me"}},
        "PacketFilter": [{"SrcIPs": ["100.64.0.0/10"], "DstPorts": [{"IP":"*","Ports":{"First":0,"Last":65535}}]}],
        "Peers": [
            {"Key":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
             "DiscoKey":"discokey:2021222324252627282920212223242526272829202122232425262728293031",
             "Addresses":["100.64.0.2/32","fd7a:115c::2/128"],
             "Endpoints":["1.2.3.4:41641","[fd7a:115c::2]:41641"],
             "DERP":"127.3.3.40:7","Online":true,"Hostinfo":{"Hostname":"peerhost"}}
        ],
        "DERPMap": {"Regions": {"7": {"RegionID":7,"RegionCode":"lax","Nodes":[{"HostName":"derp7.tailscale.com"}]}}}
    }"#;

    #[test]
    fn parses_real_shaped_response_all_chunk_sizes() {
        sweep("", Mode::Full, JSON, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.our_ip.0, [100, 64, 0, 1], "chunk={}", chunk);
            assert_eq!(m.peers.len(), 1, "chunk={}", chunk);
            assert_eq!(m.peers[0].tailnet_ip.0, [100, 64, 0, 2], "chunk={}", chunk);
            assert_eq!(m.peers[0].derp_region, 7, "chunk={}", chunk);
            assert!(m.peers[0].is_online, "chunk={}", chunk);
            assert_eq!(m.peers[0].hostname.as_str(), "peerhost", "chunk={}", chunk);
            assert_eq!(m.peers[0].node_key[0], 0x01, "chunk={}", chunk);
            assert_eq!(m.peers[0].node_key[31], 0x20, "chunk={}", chunk);
            assert_eq!(m.peers[0].disco_key[0], 0x20, "chunk={}", chunk);
            assert_eq!(m.derp_regions.len(), 1, "chunk={}", chunk);
            assert_eq!(m.derp_regions[0].region_id, 7, "chunk={}", chunk);
            assert_eq!(m.derp_regions[0].region_code.as_str(), "lax", "chunk={}", chunk);
            assert_eq!(m.derp_regions[0].host.as_str(), "derp7.tailscale.com", "chunk={}", chunk);
        });
    }

    // Offline / missing-Online peers are not in the snapshot, but an online
    // peer listed after them is.
    const JSON_MIXED_ONLINE: &str = r#"{
        "Node": {"Addresses": ["100.64.0.1/32"]},
        "Peers": [
            {"Key":"nodekey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "Addresses":["100.64.0.9/32"],"DERP":"127.3.3.40:1","Online":false,
             "Hostinfo":{"Hostname":"stale-offline"}},
            {"Key":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
             "Addresses":["100.64.0.2/32"],"DERP":"127.3.3.40:7","Online":true,
             "Hostinfo":{"Hostname":"live-online"}},
            {"Key":"nodekey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "Addresses":["100.64.0.3/32"],"DERP":"127.3.3.40:2",
             "Hostinfo":{"Hostname":"missing-online-field"}}
        ]
    }"#;

    #[test]
    fn only_online_peers_are_in_the_snapshot() {
        sweep("", Mode::Full, JSON_MIXED_ONLINE, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.peers.len(), 1, "chunk={}", chunk);
            assert_eq!(m.peers[0].hostname.as_str(), "live-online", "chunk={}", chunk);
            assert!(m.peers[0].is_online, "chunk={}", chunk);
            assert_eq!(r.len(), 3, "offline peers stay in the roster, chunk={}", chunk);
        });
    }

    const JSON_NAMES: &str = r#"{
        "Node": {"Name":"Me.Tailnet-XYZ.ts.net.","Addresses": ["100.64.0.1/32"],
                 "Hostinfo": {"Hostname": "me", "Name": "decoy"}},
        "DNSConfig": {"Proxied": true, "Domains": ["tailnet-xyz.ts.net"],
                      "Resolvers": [{"Addr": "100.100.100.100"}], "Proxied2": false},
        "Peers": [
            {"Key":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
             "Name":"bospill.tailnet-xyz.ts.net.",
             "Addresses":["100.64.0.2/32"],"DERP":"127.3.3.40:7","Online":true,
             "Hostinfo":{"Hostname":"BosPill-host","Name":"decoy"}},
            {"Key":"nodekey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "Name":"shared.other.ts.net.",
             "Addresses":["100.64.0.3/32"],"DERP":"127.3.3.40:2","Online":true},
            {"Key":"nodekey:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
             "Name":"a-label-that-is-far-too-long-for-the-table.tailnet-xyz.ts.net.",
             "Addresses":["100.64.0.4/32"],"DERP":"127.3.3.40:2","Online":true}
        ]
    }"#;

    #[test]
    fn captures_magicdns_names() {
        sweep("", Mode::Full, JSON_NAMES, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.names.self_label.as_str(), "me", "chunk={}", chunk);
            assert_eq!(m.names.suffix.as_str(), "Tailnet-XYZ.ts.net", "chunk={}", chunk);
            assert!(m.names.proxied, "chunk={}", chunk);
            assert_eq!(m.peers.len(), 3, "chunk={}", chunk);
            assert_eq!(m.peers[0].name.label.as_str(), "bospill", "chunk={}", chunk);
            assert_eq!(m.peers[0].name.suffix_hash, m.names.suffix_hash, "chunk={}", chunk);
            assert_eq!(m.peers[1].name.label.as_str(), "shared", "chunk={}", chunk);
            assert_ne!(m.peers[1].name.suffix_hash, m.names.suffix_hash, "chunk={}", chunk);
            assert_eq!(m.peers[2].name.label.as_str(), "", "chunk={}: over-long label dropped", chunk);
            assert_eq!(m.peers[0].hostname.as_str(), "BosPill-host", "chunk={}", chunk);
        });
    }

    #[test]
    fn bare_label_name_has_empty_suffix() {
        let json = r#"{"Node":{"Name":"solo","Addresses":["100.64.0.1/32"]},"DNSConfig":{"Proxied":false}}"#;
        let mut r = Roster::new();
        feed(Mode::Full, &mut r, json, 5).unwrap();
        let m = snap(&r);
        assert_eq!(m.names.self_label.as_str(), "solo");
        assert_eq!(m.names.suffix.as_str(), "");
        assert!(!m.names.proxied);
    }

    /// The self Node as Tailscale SaaS sends it (fields we skip included).
    fn ts_self(name: &str, expiry: &str) -> String {
        format!(
            r#"{{"ID":7,"StableID":"nSELF","Name":"{name}","User":5,
            "Key":"nodekey:{k}","KeyExpiry":"{expiry}","Machine":"mkey:{k}",
            "Addresses":["100.64.0.9/32","fd7a:115c:a1e0::9/128"],"Hostinfo":{{"Hostname":"tasmolike"}},
            "Created":"2026-01-01T00:00:00Z","MachineAuthorized":true}}"#,
            k = hexk(7),
        )
    }

    #[test]
    fn key_expiry_comes_from_the_self_node() {
        let name = "tasmolike-bfd518-5400.tailnet-xyz.ts.net.";
        let body = format!(r#"{{"KeepAlive":false,"Node":{},"DNSConfig":{{"Proxied":true}}}}"#,
                           ts_self(name, "2026-12-01T00:00:00.5Z"));
        sweep("", Mode::Full, &body, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_796_083_200), "chunk={}", chunk);
            assert_eq!(snap(r).names.self_label.as_str(), "tasmolike-bfd518-5400", "chunk={}", chunk);
        });
    }

    std::thread_local! {
        static SEEN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Per-thread, so parallel tests that parse a map do not see each other's
    /// calls (the hook itself is process-wide).
    fn record(suffix: &str) {
        SEEN.with(|s| s.borrow_mut().push(suffix.to_owned()));
    }

    #[test]
    fn suffix_hook_gets_our_suffix_once_per_connection_and_on_rename() {
        crate::selfnode::set_suffix_hook(Some(record));
        let map = |name: &str| format!(r#"{{"Node":{}}}"#, ts_self(name, "0001-01-01T00:00:00Z"));
        let take = || SEEN.with(|s| std::mem::take(&mut *s.borrow_mut()));
        for chunk in CHUNKS {
            take();
            let mut r = Roster::new();
            feed(Mode::Full, &mut r, &map("me.Tailnet-XYZ.ts.net."), chunk).unwrap();
            assert_eq!(take(), ["Tailnet-XYZ.ts.net"], "chunk={}: first map, case as sent, no dot", chunk);
            // The same suffix again (a re-poll, a Node delta) is not news.
            feed(Mode::Full, &mut r, &map("me.Tailnet-XYZ.ts.net."), chunk).unwrap();
            feed(Mode::Delta, &mut r, &map("me2.tailnet-xyz.ts.net."), chunk).unwrap();
            assert_eq!(take(), Vec::<String>::new(), "chunk={}", chunk);
            feed(Mode::Delta, &mut r, &map("me.other.ts.net."), chunk).unwrap();
            assert_eq!(take(), ["other.ts.net"], "chunk={}: renamed tailnet", chunk);
            // A new connection starts from an empty roster and announces again.
            r.clear();
            feed(Mode::Full, &mut r, &map("solo"), chunk).unwrap();
            assert_eq!(take(), [""], "chunk={}: bare label has an empty suffix", chunk);
            // A suffix tailmicro cannot keep is still handed out whole.
            let long = format!("{}.ts.net", "a".repeat(60));
            feed(Mode::Delta, &mut r, &map(&format!("me.{long}.")), chunk).unwrap();
            assert_eq!(take(), [long], "chunk={}", chunk);
            assert_eq!(snap(&r).names.suffix.as_str(), "", "chunk={}", chunk);
        }
        crate::selfnode::set_suffix_hook(None);
    }

    #[test]
    fn zero_key_expiry_means_none_and_a_later_map_overwrites() {
        let none = format!(r#"{{"Node":{}}}"#, ts_self("me.t.ts.net.", "0001-01-01T00:00:00Z"));
        sweep("", Mode::Full, &none, |r, chunk| {
            assert_eq!(r.self_key_expiry(), None, "chunk={}", chunk);
        });
        let seed = format!(r#"{{"Node":{}}}"#, ts_self("me.t.ts.net.", "2026-12-01T00:00:00Z"));
        sweep(&seed, Mode::Full, &none, |r, chunk| {
            assert_eq!(r.self_key_expiry(), None, "full map clears an expiry, chunk={}", chunk);
        });
        sweep(&none, Mode::Full, &seed, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_796_083_200), "chunk={}", chunk);
        });
    }

    #[test]
    fn key_expiry_follows_node_deltas_and_ignores_other_messages() {
        let seed = format!(r#"{{"Node":{},"Peers":[]}}"#, ts_self("me.t.ts.net.", "2026-12-01T00:00:00Z"));
        // A delta without a Node leaves the expiry alone.
        sweep(&seed, Mode::Delta, r#"{"DNSConfig":{"Proxied":true}}"#, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_796_083_200), "chunk={}", chunk);
        });
        // A peer's KeyExpiry is not ours.
        let peer = format!(r#"{{"PeersChanged":[{}]}}"#, ts_peer(10, 1, "100.64.0.10", 1, true));
        sweep(&seed, Mode::Delta, &peer, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_796_083_200), "chunk={}", chunk);
        });
        // A key renewed in the admin console arrives as a new Node.
        let renewed = format!(r#"{{"Node":{}}}"#, ts_self("me.t.ts.net.", "2027-06-01T00:00:00Z"));
        sweep(&seed, Mode::Delta, &renewed, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_811_808_000), "chunk={}", chunk);
        });
    }

    #[test]
    fn garbage_key_expiry_keeps_the_old_value() {
        let seed = format!(r#"{{"Node":{}}}"#, ts_self("me.t.ts.net.", "2026-12-01T00:00:00Z"));
        let bad = format!(r#"{{"Node":{}}}"#, ts_self("me.t.ts.net.", "soon"));
        sweep(&seed, Mode::Delta, &bad, |r, chunk| {
            assert_eq!(r.self_key_expiry(), Some(1_796_083_200), "chunk={}", chunk);
        });
    }

    #[test]
    fn publish_self_reaches_the_process_wide_status() {
        let mut r = Roster::new();
        let body = format!(r#"{{"Node":{}}}"#, ts_self("pub.t.ts.net.", "2026-12-01T00:00:00Z"));
        feed(Mode::Full, &mut r, &body, 64).unwrap();
        r.publish_self();
        assert_eq!(crate::selfnode::key_expiry(), Some(1_796_083_200));
    }

    #[test]
    fn split_and_hash_normalise_case_and_dot() {
        let (l, s) = crate::split_node_name("Host.Tail.ts.net.");
        assert_eq!((l.as_str(), s), ("host", "Tail.ts.net"));
        assert_eq!(crate::suffix_hash("Tail.ts.net"), crate::suffix_hash("tail.TS.net"));
        assert_ne!(crate::suffix_hash("a.ts.net"), crate::suffix_hash("b.ts.net"));
    }

    // -- Delta golden frames -------------------------------------------------

    /// A headscale-shaped peer as TailNode marshals it: `ID`, `HomeDERP` (no
    /// legacy string), `Online` as a bool, plus fields we skip.
    fn hs_peer(id: u64, k: u8, ip: &str, derp: u16, online: bool) -> String {
        format!(
            r#"{{"ID":{id},"StableID":"n{id}","Name":"host{id}.hs.example.","User":1,
            "Key":"nodekey:{k}","KeyExpiry":"0001-01-01T00:00:00Z","Machine":"mkey:{k}",
            "DiscoKey":"discokey:{d}","Addresses":["{ip}/32","fd7a:115c:a1e0::{id}/128"],
            "AllowedIPs":["{ip}/32"],"Endpoints":["10.0.0.{id}:41641"],"HomeDERP":{derp},
            "Hostinfo":{{"OS":"linux","Hostname":"host{id}","NetInfo":{{"PreferredDERP":{derp}}}}},
            "Created":"2024-01-01T00:00:00Z","Cap":106,"CapMap":{{"admin":[],"ssh":[]}},
            "Online":{online},"MachineAuthorized":true}}"#,
            k = hexk(k), d = hexk(k.wrapping_add(100)),
        )
    }

    /// The same peer as Tailscale SaaS sends a cap-72 client: legacy `DERP`.
    fn ts_peer(id: u64, k: u8, ip: &str, derp: u16, online: bool) -> String {
        format!(
            r#"{{"ID":{id},"StableID":"n{id}CNTRL","Name":"host{id}.tail1234.ts.net.","User":5,
            "Key":"nodekey:{k}","KeyExpiry":"2026-12-01T00:00:00Z","Machine":"mkey:{k}",
            "DiscoKey":"discokey:{d}","Addresses":["{ip}/32","fd7a:115c:a1e0::{id}/128"],
            "AllowedIPs":["{ip}/32"],"Endpoints":["10.0.0.{id}:41641"],"DERP":"127.3.3.40:{derp}",
            "Hostinfo":{{"OS":"linux","Hostname":"host{id}"}},"Created":"2024-01-01T00:00:00Z",
            "Online":{online},"LastSeen":"2026-09-30T10:00:00Z","MachineAuthorized":true}}"#,
            k = hexk(k), d = hexk(k.wrapping_add(100)),
        )
    }

    fn full_map(peers: &[String]) -> String {
        format!(
            r#"{{"KeepAlive":false,"Node":{{"ID":1,"Name":"me.hs.example.","Addresses":["100.64.0.1/32"]}},
            "DERPMap":{{"Regions":{{"1":{{"RegionID":1,"RegionCode":"a","Nodes":[{{"HostName":"d1.example"}}]}},
                                    "2":{{"RegionID":2,"RegionCode":"b","Nodes":[{{"HostName":"d2.example"}}]}}}}}},
            "DNSConfig":{{"Proxied":true}},"Peers":[{}]}}"#,
            peers.join(",")
        )
    }

    fn ids(r: &Roster) -> Vec<u8> {
        snap(r).peers.iter().map(|p| p.node_key[0]).collect()
    }

    #[test]
    fn full_map_reads_ids_home_derp_and_legacy_derp() {
        let body = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 2, true),
            ts_peer(20, 2, "100.64.0.20", 1, true),
        ]);
        sweep("", Mode::Full, &body, |r, chunk| {
            let m = snap(r);
            assert_eq!(ids(r), [1, 2], "chunk={}", chunk);
            assert_eq!(m.peers[0].derp_region, 2, "HomeDERP, chunk={}", chunk);
            assert_eq!(m.peers[1].derp_region, 1, "legacy DERP string, chunk={}", chunk);
            assert_eq!(m.peers[0].hostname.as_str(), "host10", "chunk={}", chunk);
            assert_eq!(m.derp_regions.len(), 2, "chunk={}", chunk);
        });
    }

    #[test]
    fn peers_changed_adds_and_updates_by_node_id() {
        let seed = full_map(&[hs_peer(10, 1, "100.64.0.10", 1, true)]);
        // 5 joins (sorts before 10); 10 moves to region 2 and gets a new IP.
        let delta = format!(
            r#"{{"PeersChanged":[{},{}]}}"#,
            hs_peer(5, 5, "100.64.0.5", 1, true),
            hs_peer(10, 1, "100.64.0.99", 2, true),
        );
        sweep(&seed, Mode::Delta, &delta, |r, chunk| {
            let m = snap(r);
            assert_eq!(ids(r), [5, 1], "ordered by NodeID, chunk={}", chunk);
            assert_eq!(m.peers[1].tailnet_ip.0, [100, 64, 0, 99], "chunk={}", chunk);
            assert_eq!(m.peers[1].derp_region, 2, "chunk={}", chunk);
            assert_eq!(m.our_ip.0, [100, 64, 0, 1], "untouched fields stay, chunk={}", chunk);
            assert_eq!(m.derp_regions.len(), 2, "chunk={}", chunk);
            assert!(r.take_dirty());
        });
    }

    #[test]
    fn peers_removed_drops_listed_ids_and_ignores_unknown() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 1, true),
            hs_peer(20, 2, "100.64.0.20", 1, true),
            hs_peer(30, 3, "100.64.0.30", 1, true),
        ]);
        sweep(&seed, Mode::Delta, r#"{"PeersRemoved":[20,999]}"#, |r, chunk| {
            assert_eq!(ids(r), [1, 3], "chunk={}", chunk);
        });
    }

    #[test]
    fn patch_changes_derp_keys_and_online() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 1, true),
            hs_peer(20, 2, "100.64.0.20", 1, true),
        ]);
        let new_key = hexk(0x77);
        let new_disco = hexk(0x88);
        let delta = format!(
            r#"{{"PeersChangedPatch":[
                {{"NodeID":10,"DERPRegion":2,"Endpoints":["1.2.3.4:5"],"LastSeen":"2026-10-01T00:00:00Z"}},
                {{"NodeID":20,"Key":"nodekey:{new_key}","DiscoKey":"discokey:{new_disco}",
                  "KeyExpiry":"2027-01-01T00:00:00Z","Cap":106,"CapMap":{{"x":[]}}}},
                {{"NodeID":777,"DERPRegion":9}}
            ]}}"#
        );
        sweep(&seed, Mode::Delta, &delta, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.peers[0].derp_region, 2, "chunk={}", chunk);
            assert_eq!(m.peers[0].node_key[0], 1, "chunk={}", chunk);
            assert_eq!(m.peers[1].node_key[0], 0x77, "chunk={}", chunk);
            assert_eq!(m.peers[1].disco_key[0], 0x88, "chunk={}", chunk);
            assert_eq!(m.peers[1].derp_region, 1, "DERPRegion absent means unchanged, chunk={}", chunk);
            assert_eq!(m.peers.len(), 2, "unknown id ignored, chunk={}", chunk);
        });
    }

    #[test]
    fn patch_online_false_removes_and_online_true_restores_with_only_an_id() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 3, true),
            hs_peer(20, 2, "100.64.0.20", 1, true),
        ]);
        for chunk in CHUNKS {
            let mut r = Roster::new();
            feed(Mode::Full, &mut r, &seed, 4096).unwrap();
            feed(Mode::Delta, &mut r, r#"{"PeersChangedPatch":[{"NodeID":10,"Online":false}]}"#, chunk).unwrap();
            assert_eq!(ids(&r), [2], "offline peer leaves the snapshot, chunk={}", chunk);
            assert_eq!(r.len(), 2, "but stays in the roster, chunk={}", chunk);
            feed(Mode::Delta, &mut r, r#"{"PeersChangedPatch":[{"NodeID":10,"Online":true}]}"#, chunk).unwrap();
            let m = snap(&r);
            assert_eq!(ids(&r), [1, 2], "chunk={}", chunk);
            assert_eq!(m.peers[0].derp_region, 3, "kept state is back, chunk={}", chunk);
            assert_eq!(m.peers[0].tailnet_ip.0, [100, 64, 0, 10], "chunk={}", chunk);
        }
    }

    #[test]
    fn online_change_uses_numeric_string_keys() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 1, true),
            hs_peer(20, 2, "100.64.0.20", 1, false),
        ]);
        sweep(&seed, Mode::Delta,
              r#"{"OnlineChange":{"10":false,"20":true,"31337":true,"x":true}}"#, |r, chunk| {
            assert_eq!(ids(r), [2], "chunk={}", chunk);
        });
    }

    #[test]
    fn peers_changed_without_online_keeps_what_we_knew() {
        let seed = full_map(&[hs_peer(10, 1, "100.64.0.10", 1, true)]);
        // A peer object with no Online field at all (control left it unknown).
        let unknown = r#"{"PeersChanged":[{"ID":10,"Key":"nodekey:KEY","Addresses":["100.64.0.10/32"],"HomeDERP":4},
                                          {"ID":11,"Key":"nodekey:KEY2","Addresses":["100.64.0.11/32"],"HomeDERP":4}]}"#
            .replace("KEY2", &hexk(9)).replace("KEY", &hexk(1));
        sweep(&seed, Mode::Delta, &unknown, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.peers.len(), 1, "known peer stays online, a new unknown one starts offline, chunk={}", chunk);
            assert_eq!(m.peers[0].derp_region, 4, "chunk={}", chunk);
            assert_eq!(r.len(), 2, "chunk={}", chunk);
        });
    }

    #[test]
    fn keepalive_changes_nothing() {
        let seed = full_map(&[hs_peer(10, 1, "100.64.0.10", 1, true)]);
        sweep(&seed, Mode::Delta, r#"{"KeepAlive":true}"#, |r, chunk| {
            r.take_dirty();
            assert_eq!(ids(r), [1], "chunk={}", chunk);
            assert_eq!(snap(r).derp_regions.len(), 2, "chunk={}", chunk);
        });
        // And a re-send of identical state is not a change either.
        let mut r = Roster::new();
        feed(Mode::Full, &mut r, &seed, 64).unwrap();
        r.take_dirty();
        feed(Mode::Delta, &mut r, &seed, 64).unwrap();
        assert!(!r.take_dirty(), "identical map must not dirty the roster");
        feed(Mode::Delta, &mut r, r#"{"KeepAlive":true}"#, 3).unwrap();
        assert!(!r.take_dirty());
    }

    #[test]
    fn derp_map_delta_replaces_regions_and_empty_is_ignored() {
        let seed = full_map(&[]);
        let delta = r#"{"DERPMap":{"HomeParams":{"RegionScore":{"1":1.5}},
            "Regions":{"3":{"RegionID":3,"RegionCode":"c","Nodes":[{"HostName":"d3.example","IPv4":"1.1.1.1"}]}}}}"#;
        sweep(&seed, Mode::Delta, delta, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.derp_regions.len(), 1, "chunk={}", chunk);
            assert_eq!(m.derp_regions[0].region_id, 3, "chunk={}", chunk);
            assert_eq!(m.derp_regions[0].host.as_str(), "d3.example", "chunk={}", chunk);
        });
        sweep(&seed, Mode::Delta, r#"{"DERPMap":{"Regions":{}}}"#, |r, chunk| {
            assert_eq!(snap(r).derp_regions.len(), 2, "empty DERPMap must not strand us, chunk={}", chunk);
        });
    }

    #[test]
    fn dns_config_and_node_deltas() {
        let seed = full_map(&[]);
        sweep(&seed, Mode::Delta, r#"{"DNSConfig":{"Domains":["x"]}}"#, |r, chunk| {
            assert!(!snap(r).names.proxied, "Proxied is omitted when false, chunk={}", chunk);
        });
        sweep(&seed, Mode::Delta,
              r#"{"Node":{"Name":"Renamed.hs.example.","Addresses":["fd7a::1/128","100.64.0.77/32"]}}"#, |r, chunk| {
            let m = snap(r);
            assert_eq!(m.our_ip.0, [100, 64, 0, 77], "chunk={}", chunk);
            assert_eq!(m.names.self_label.as_str(), "renamed", "chunk={}", chunk);
            assert!(m.names.proxied, "DNSConfig absent means unchanged, chunk={}", chunk);
        });
    }

    #[test]
    fn stream_peers_list_replaces_but_absent_peers_do_not() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 1, true),
            hs_peer(20, 2, "100.64.0.20", 1, true),
        ]);
        // A stream message with a non-empty Peers is a complete replace.
        let replace = format!(r#"{{"Peers":[{}]}}"#, hs_peer(20, 2, "100.64.0.20", 1, true));
        sweep(&seed, Mode::Delta, &replace, |r, chunk| {
            assert_eq!(ids(r), [2], "chunk={}", chunk);
        });
        // A stream message without Peers leaves them alone.
        sweep(&seed, Mode::Delta, r#"{"Node":{"Addresses":["100.64.0.1/32"]}}"#, |r, chunk| {
            assert_eq!(ids(r), [1, 2], "chunk={}", chunk);
        });
        // A full map by contract with no Peers means the tailnet is empty.
        sweep(&seed, Mode::Full, r#"{"Node":{"Addresses":["100.64.0.1/32"]}}"#, |r, chunk| {
            assert!(ids(r).is_empty(), "chunk={}", chunk);
            assert_eq!(r.len(), 0, "chunk={}", chunk);
        });
    }

    // -- Bounds --------------------------------------------------------------

    #[test]
    fn more_than_max_peers_keeps_the_first_eight_in_order() {
        let peers: Vec<String> = (1..=12u8)
            .map(|i| hs_peer(u64::from(i) * 10, i, &format!("100.64.0.{}", 100 + i), 1, true))
            .collect();
        let body = full_map(&peers);
        sweep("", Mode::Full, &body, |r, chunk| {
            assert_eq!(ids(r), (1..=MAX_PEERS as u8).collect::<Vec<_>>(), "chunk={}", chunk);
            assert_eq!(r.len(), 12, "all remembered (cap {}), chunk={}", ROSTER_CAP, chunk);
        });
    }

    #[test]
    fn roster_cap_overflow_drops_the_extra_peers_and_never_panics() {
        let peers: Vec<String> = (1..=24u8)
            .map(|i| hs_peer(u64::from(i), i, &format!("100.64.1.{}", i), 1, true))
            .collect();
        let mut r = Roster::new();
        feed(Mode::Full, &mut r, &full_map(&peers), 97).unwrap();
        assert_eq!(r.len(), ROSTER_CAP);
        assert_eq!(ids(&r), (1..=MAX_PEERS as u8).collect::<Vec<_>>());
    }

    #[test]
    fn replace_works_when_both_lists_fill_the_roster() {
        let a: Vec<String> = (1..=16u8).map(|i| hs_peer(u64::from(i), i, "100.64.0.9", 1, true)).collect();
        let b: Vec<String> = (101..=116u8).map(|i| hs_peer(u64::from(i), i, "100.64.0.8", 1, true)).collect();
        let mut r = Roster::new();
        feed(Mode::Full, &mut r, &full_map(&a), 4096).unwrap();
        feed(Mode::Full, &mut r, &full_map(&b), 4096).unwrap();
        assert_eq!(r.len(), ROSTER_CAP);
        assert_eq!(ids(&r)[0], 101, "the old list is gone, stale entries made room");
    }

    // -- Malformed input -----------------------------------------------------

    #[test]
    fn truncated_message_fails_and_sweeps_nothing() {
        let seed = full_map(&[
            hs_peer(10, 1, "100.64.0.10", 1, true),
            hs_peer(20, 2, "100.64.0.20", 1, true),
        ]);
        let whole = full_map(&[hs_peer(10, 1, "100.64.0.10", 1, true)]);
        for cut in [10, whole.len() / 2, whole.len() - 3] {
            let mut r = Roster::new();
            feed(Mode::Full, &mut r, &seed, 4096).unwrap();
            let res = feed(Mode::Full, &mut r, &whole[..cut], 64);
            assert!(res.is_err(), "cut={}", cut);
            assert_eq!(ids(&r), [1, 2], "a failed replace must not sweep, cut={}", cut);
        }
    }

    #[test]
    fn garbage_and_wrong_shapes_are_errors_not_panics() {
        for body in ["", "not json", "{", "[1,2,3]x", "{\"Peers\":[{\"ID\":}]}", "\u{0}\u{1}"] {
            let mut r = Roster::new();
            let res = feed(Mode::Delta, &mut r, body, 3);
            assert!(res.is_err(), "body {:?}", body);
        }
        // Valid JSON of the wrong shape is ignored field by field.
        let mut r = Roster::new();
        feed(Mode::Delta, &mut r,
             r#"{"PeersRemoved":"x","PeersChangedPatch":{"a":1},"OnlineChange":[1,2],"Peers":{"k":1},"ID":"zz"}"#, 5)
            .unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn nesting_beyond_the_stack_is_an_overflow_error() {
        let deep = format!(r#"{{"PacketFilter":{}1{}}}"#, "[".repeat(40), "]".repeat(40));
        let mut r = Roster::new();
        assert!(matches!(feed(Mode::Delta, &mut r, &deep, 7), Err(StreamError::Overflow)));
    }

    #[test]
    fn long_and_multibyte_strings_are_truncated_safely() {
        // 70 bytes of 2-byte chars: a cut at byte 64 is inside a char only if
        // the truncation is careless.
        let host = "\u{e9}".repeat(35);
        let long_key = "k".repeat(40);
        let body = format!(
            r#"{{"Peers":[{{"ID":1,"Key":"nodekey:{}","Addresses":["100.64.0.2/32"],"Online":true,
               "Hostinfo":{{"Hostname":"{}"}},"{}":1}}]}}"#,
            hexk(1), host, long_key,
        );
        let mut r = Roster::new();
        feed(Mode::Delta, &mut r, &body, 11).unwrap();
        let m = snap(&r);
        assert_eq!(m.peers.len(), 1);
        assert!(m.peers[0].hostname.len() <= 64);
        assert!(m.peers[0].hostname.chars().all(|c| c == '\u{e9}'));
    }

    #[test]
    fn peers_without_key_or_ipv4_are_not_admitted() {
        let body = r#"{"Peers":[
            {"ID":1,"Addresses":["100.64.0.2/32"],"Online":true},
            {"ID":2,"Key":"nodekey:KEY","Addresses":["fd7a::2/128"],"Online":true},
            {"ID":3,"Key":"nodekey:short","Addresses":["100.64.0.4/32"],"Online":true}]}"#
            .replace("KEY", &hexk(2));
        let mut r = Roster::new();
        feed(Mode::Delta, &mut r, &body, 9).unwrap();
        assert_eq!(r.len(), 0);
    }
}
