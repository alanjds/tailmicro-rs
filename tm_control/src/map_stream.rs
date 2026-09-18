//! Streaming (push) MapResponse decoder.
//!
//! The buffer-and-parse decoder in [`crate::map_serde`] needs the whole
//! de-prefixed JSON body (tens of KB, ~48 KB when the tailnet is inflated by
//! ephemeral ghost peers) in one contiguous allocation. On the ESP32-C3's
//! fragmented ~57 KB heap that `try_reserve_exact` fails, and the stream_map
//! reader then has to discard the whole netmap to stay online -- losing the
//! peers/DERPMap that the data plane needs (card t_e34afeed v2).
//!
//! This module feeds the body to a push (event) JSON parser [`actson`] as the
//! decrypted H2 DATA frames arrive, extracting only the handful of fields the
//! netmap actually contributes (our IP, online peers' key/disco/ip/derp/
//! hostname, and DERPMap regions) into a fixed-size [`MapState`]. Nothing but
//! actson's ~1 KB feeder ring and the fixed MapState is ever held, so there is
//! no `mlen`-byte contiguous allocation to fail. The push model is required:
//! bytes arrive across `await` points in a cooperative single-task runtime, so
//! a pull/`from_reader` parser would block the executor.
//!
//! The extraction rules mirror [`crate::map_serde::parse`] exactly (online-only
//! peers, first-IPv4-wins, region id from the key or body), and the shared
//! scalar decoders (`hex_key`, `parse_ipv4`, `parse_derp_region`,
//! `region_id_or`) are reused from there so the two decoders cannot drift.

use actson::feeder::PushJsonFeeder;
use actson::{JsonEvent, JsonParser};
use arrayvec::ArrayVec;

use crate::map_serde::{hex_key, parse_derp_region, parse_ipv4, region_id_or};
use crate::{DerpRegion, MapState, PeerInfo, TailnetIp};

/// Where we are in the MapResponse document. One is pushed per open
/// object/array; `Skip` covers any subtree we do not read (PacketFilter,
/// Endpoints, ...), so nested containers inside it just stack more `Skip`s.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Root,
    Node,
    NodeAddresses,
    Peers,
    Peer,
    PeerAddresses,
    PeerHostinfo,
    DerpMap,
    Regions,
    Region,
    RegionNodes,
    RegionNode,
    Skip,
}

/// Fields of the peer object currently being read, committed on `EndObject`.
#[derive(Default)]
struct PeerScratch {
    key: Option<[u8; 32]>,
    disco: [u8; 32],
    ip: Option<[u8; 4]>,
    derp_region: u16,
    online: Option<bool>,
    hostname: heapless::String<64>,
}

/// Fields of the DERP region currently being read, committed on `EndObject`.
struct RegionScratch {
    rid: heapless::String<8>,
    region_id: Option<u16>,
    region_code: heapless::String<8>,
    host: heapless::String<64>,
}

/// Error surfaced by the streaming decoder. Both collapse to the same
/// caller-visible `JsonError::ParseError` (map_serde parity), but are kept
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
/// [`finish`](Self::finish) once exactly `mlen` bytes have been fed.
pub struct MapStreamParser<const MAX_PEERS: usize, const MAX_REGIONS: usize> {
    parser: JsonParser<PushJsonFeeder>,
    stack: ArrayVec<Ctx, 16>,
    /// Field name seen most recently, consumed by the next value/container.
    pending: heapless::String<32>,
    have_pending: bool,
    out: MapState<MAX_PEERS, MAX_REGIONS>,
    peer: PeerScratch,
    region: Option<RegionScratch>,
    /// Set once a fatal parse/overflow error is seen; further input is ignored
    /// and surfaced from `finish`.
    failed: Option<StreamError>,
}

impl<const MAX_PEERS: usize, const MAX_REGIONS: usize> MapStreamParser<MAX_PEERS, MAX_REGIONS> {
    pub fn new() -> Self {
        Self {
            parser: JsonParser::new(PushJsonFeeder::new()),
            stack: ArrayVec::new(),
            pending: heapless::String::new(),
            have_pending: false,
            out: MapState {
                our_ip: TailnetIp([0; 4]),
                peers: ArrayVec::new(),
                derp_regions: ArrayVec::new(),
            },
            peer: PeerScratch::default(),
            region: None,
            failed: None,
        }
    }

    /// Feed one chunk of body bytes, draining every event the parser can emit
    /// from the bytes fed so far. Returns when the chunk is exhausted (the
    /// caller awaits the next frame) -- NOT when parsing is done; call
    /// [`finish`](Self::finish) for that.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), StreamError> {
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
                    if let Err(e) = self.handle(ev) {
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

    /// Mark the body complete, drain the trailing events, and return the
    /// accumulated [`MapState`].
    pub fn finish(mut self) -> Result<MapState<MAX_PEERS, MAX_REGIONS>, StreamError> {
        self.parser.feeder.done();
        loop {
            match self.parser.next_event() {
                Ok(Some(JsonEvent::NeedMoreInput)) => break, // nothing left to feed
                Ok(Some(ev)) => {
                    if let Err(e) = self.handle(ev) {
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
        match self.failed {
            Some(e) => Err(e),
            None => Ok(self.out),
        }
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

    fn handle(&mut self, ev: JsonEvent) -> Result<(), StreamError> {
        match ev {
            JsonEvent::FieldName => {
                let s = self.parser.current_str().map_err(|_| StreamError::Parse)?;
                let mut name: heapless::String<32> = heapless::String::new();
                // A field name longer than 32 bytes is not one we key on; keep a
                // truncated copy so the following value still gets consumed as
                // "some ignored field" rather than misattributed.
                let _ = name.push_str(&s[..s.len().min(32)]);
                self.pending = name;
                self.have_pending = true;
            }

            JsonEvent::StartObject | JsonEvent::StartArray => {
                let is_obj = ev == JsonEvent::StartObject;
                let name = self.take_name();
                let next = self.enter(is_obj, name.as_deref());
                if next == Ctx::Peer {
                    self.peer = PeerScratch::default();
                } else if next == Ctx::Region {
                    // The Regions object is keyed by region-id; that key is the
                    // field name that introduced this object.
                    let rid = name.unwrap_or_default();
                    let mut r8: heapless::String<8> = heapless::String::new();
                    let _ = r8.push_str(&rid[..rid.len().min(8)]);
                    self.region = Some(RegionScratch {
                        rid: r8,
                        region_id: None,
                        region_code: heapless::String::new(),
                        host: heapless::String::new(),
                    });
                }
                self.stack.try_push(next).map_err(|_| StreamError::Overflow)?;
            }

            JsonEvent::EndObject | JsonEvent::EndArray => {
                let closed = self.stack.pop().unwrap_or(Ctx::Root);
                self.have_pending = false; // any dangling name dies with the container
                match closed {
                    Ctx::Peer => self.commit_peer(),
                    Ctx::Region => self.commit_region(),
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
                    let _ = buf.push_str(&val[..val.len().min(128)]);
                }
                self.scalar_str(&buf);
                self.have_pending = false;
            }

            JsonEvent::ValueInt => {
                // Only RegionID is read as an int; decode lazily to avoid the
                // generic call where it is not needed.
                if self.top() == Ctx::Region && self.name_is("RegionID") {
                    if let Ok(v) = self.parser.current_int::<u16>() {
                        if let Some(r) = self.region.as_mut() {
                            r.region_id = Some(v);
                        }
                    }
                }
                self.have_pending = false;
            }

            JsonEvent::ValueTrue | JsonEvent::ValueFalse => {
                if self.top() == Ctx::Peer && self.name_is("Online") {
                    self.peer.online = Some(ev == JsonEvent::ValueTrue);
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
            (Ctx::Root, Some("DERPMap"), true) => Ctx::DerpMap,

            (Ctx::Node, Some("Addresses"), false) => Ctx::NodeAddresses,

            (Ctx::Peers, _, true) => Ctx::Peer,
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
    fn scalar_str(&mut self, val: &str) {
        match self.top() {
            Ctx::NodeAddresses => {
                if self.out.our_ip.0 == [0; 4] {
                    if let Some(ip) = parse_ipv4(val) {
                        self.out.our_ip = TailnetIp(ip);
                    }
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
                    self.peer.derp_region = parse_derp_region(val).unwrap_or(0);
                }
            }
            Ctx::PeerHostinfo => {
                if self.name_is("Hostname") {
                    self.peer.hostname.clear();
                    let _ = self.peer.hostname.push_str(&val[..val.len().min(64)]);
                }
            }
            Ctx::Region => {
                if self.name_is("RegionCode") {
                    if let Some(r) = self.region.as_mut() {
                        r.region_code.clear();
                        let _ = r.region_code.push_str(&val[..val.len().min(8)]);
                    }
                }
            }
            Ctx::RegionNode => {
                if self.name_is("HostName") {
                    if let Some(r) = self.region.as_mut() {
                        if r.host.is_empty() {
                            let _ = r.host.push_str(&val[..val.len().min(64)]);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Commit the scratch peer to the netmap, applying the same online-only /
    /// key+ip-required policy as [`crate::map_serde::parse`].
    fn commit_peer(&mut self) {
        let p = core::mem::take(&mut self.peer);
        if self.out.peers.is_full() {
            return;
        }
        if p.online != Some(true) {
            return; // online-only netmap (map_serde parity)
        }
        let (Some(key), Some(ip)) = (p.key, p.ip) else {
            return;
        };
        let _ = self.out.peers.try_push(PeerInfo {
            node_key: key,
            disco_key: p.disco,
            tailnet_ip: TailnetIp(ip),
            prefix_len: 32,
            hostname: p.hostname,
            derp_region: p.derp_region,
            is_online: true,
        });
    }

    /// Commit the scratch region to the netmap (host required; region id from
    /// the body or, failing that, the map key).
    fn commit_region(&mut self) {
        let Some(r) = self.region.take() else {
            return;
        };
        if self.out.derp_regions.is_full() || r.host.is_empty() {
            return;
        }
        let region_id = region_id_or(r.rid.as_str(), r.region_id);
        let _ = self.out.derp_regions.try_push(DerpRegion {
            region_id,
            region_code: r.region_code,
            host: r.host,
            port: 443,
            latency_ms: 0,
        });
    }
}

impl<const MAX_PEERS: usize, const MAX_REGIONS: usize> Default
    for MapStreamParser<MAX_PEERS, MAX_REGIONS>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::MapStreamParser;

    /// Feed `body` to the streaming parser in `chunk` byte slices, mirroring how
    /// H2 DATA frames arrive, and return the parsed MapState.
    fn parse_chunked<const P: usize, const R: usize>(
        body: &[u8],
        chunk: usize,
    ) -> super::MapState<P, R> {
        let mut p: MapStreamParser<P, R> = MapStreamParser::new();
        let mut i = 0;
        while i < body.len() {
            let end = (i + chunk).min(body.len());
            p.push(&body[i..end]).unwrap();
            i = end;
        }
        p.finish().unwrap()
    }

    // Same shape as map_serde's test (nested skipped subtrees whose strings
    // carry structural bytes), to prove parity with the buffer-and-parse path.
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
        // Vary the chunk boundary so message splits land inside keys, values,
        // escapes and structural bytes -- the streaming parser must be
        // boundary-independent.
        for chunk in [1usize, 2, 3, 7, 13, 64, 4096] {
            let m = parse_chunked::<8, 4>(JSON.as_bytes(), chunk);
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
        }
    }

    // Offline / missing-Online peers must not occupy an ArrayVec slot, and an
    // online peer listed after them must still be kept (map_serde parity).
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
    fn only_online_peers_are_kept() {
        for chunk in [1usize, 5, 64, 4096] {
            let m = parse_chunked::<8, 4>(JSON_MIXED_ONLINE.as_bytes(), chunk);
            assert_eq!(m.peers.len(), 1, "chunk={}", chunk);
            assert_eq!(m.peers[0].hostname.as_str(), "live-online", "chunk={}", chunk);
            assert!(m.peers[0].is_online, "chunk={}", chunk);
        }
    }

    // A peer set larger than MAX_PEERS must truncate to the online ones without
    // panicking (try_push on a full ArrayVec is a no-op).
    #[test]
    fn respects_max_peers_cap() {
        let m = parse_chunked::<1, 1>(JSON.as_bytes(), 8);
        assert_eq!(m.peers.len(), 1);
        assert_eq!(m.derp_regions.len(), 1);
    }
}
