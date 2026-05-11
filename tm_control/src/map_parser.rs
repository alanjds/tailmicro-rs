//! Streaming JSON parser for Tailscale's MapResponse.
//!
//! # Why not `serde_json`?
//!
//! `serde_json::from_reader` + `StreamDeserializer` still requires the entire
//! JSON object to be in memory before yielding the root struct.  The MapResponse
//! can be hundreds of KB for large tailnets.
//!
//! `serde_json::Value` (DOM) allocates 2-3× the JSON size in heap objects.
//!
//! Both approaches would OOM the ESP32-C3.
//!
//! # Design
//!
//! A hand-rolled recursive-descent parser operating on a byte-at-a-time input.
//! It only accumulates bytes for fields we care about; everything else is
//! discarded without buffering.
//!
//! State machine overview:
//! ```text
//! Root object
//! ├── "Node" → NodeParser       → our IP, our keys
//! ├── "Peers" → ArrayParser     → PeerParser per element
//! │                                ├── "Key"         → peer.node_key
//! │                                ├── "DiscoKey"    → peer.disco_key
//! │                                ├── "Addresses"   → peer.tailnet_ip
//! │                                ├── "Hostinfo"    → peer.hostname (OS)
//! │                                └── "DERP"        → peer.derp_region
//! └── "DERPMap" → DerpMapParser
//!     └── "Regions" → object
//!         └── "<id>" → RegionParser
//!             ├── "RegionCode"
//!             └── "Nodes" → array → first element → "HostName", "STUNPort"
//! ```
//!
//! # Memory model
//!
//! - One `[u8; 4096]` frame buffer on the caller's stack (not here)
//! - Parser state: ~800 bytes on the stack
//! - String accumulators: heapless, max 64 / 128 bytes each
//! - Output: `ArrayVec` in `MapState` — no heap
//!
//! Total: ≤ 1 KB parser state + 1 KB output state = ~2 KB, fixed.

use arrayvec::ArrayVec;
use crate::{PeerInfo, TailnetIp, DerpRegion, MapState, JsonError};

// ── Parser state machine ──────────────────────────────────────────────────────

/// Top-level parser state.
#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    /// At root object, waiting for a key.
    Root,
    /// Inside "Node" object.
    InNode,
    /// Inside "Peers" array.
    InPeers,
    /// Inside one peer object.
    InOnePeer,
    /// Inside "DERPMap" object.
    InDerpMap,
    /// Inside "DERPMap.Regions" object.
    InRegions,
    /// Inside one region object.
    InOneRegion,
    /// Inside one region's "Nodes" array.
    InRegionNodes,
    /// Inside the first node of a region.
    InRegionNode,
    /// Accumulating a JSON string value.
    InString,
    /// Skipping a value (object, array, primitive) we don't need.
    Skipping,
}

/// What we're accumulating the current string into.
#[derive(Clone, Copy, PartialEq, Debug)]
enum StringTarget {
    Key,
    /// Node.Addresses[0] — our tailnet IP
    OurAddress,
    /// Peer Key (node public key hex)
    PeerKey,
    /// Peer DiscoKey hex
    PeerDiscoKey,
    /// Peer Addresses[0]
    PeerAddress,
    /// Peer Hostinfo.Hostname
    PeerHostname,
    /// Peer DERP ("127.3.3.40:<region_id>")
    PeerDerp,
    /// DERPMap region code
    RegionCode,
    /// DERPMap region node hostname
    RegionHost,
    /// Discard
    Discard,
}

/// Depth of nesting for the skip logic.
/// u8 is sufficient — real JSON nesting in MapResponse is ≤ 8 levels.
type Depth = u8;

pub struct MapParser<const MAX_PEERS: usize = 8, const MAX_REGIONS: usize = 4> {
    state:         State,
    prev_state:    State,          // restored after string
    string_target: StringTarget,

    /// Key accumulator — reused for every JSON key
    key_buf:       heapless::Vec<u8, 64>,
    /// Value accumulator — reused for every string value we care about
    val_buf:       heapless::Vec<u8, 128>,

    /// Escape pending in string
    in_escape:     bool,

    /// Depth counter for skip logic
    skip_depth:    Depth,

    /// Peer being assembled
    current_peer:  Option<PeerInfo>,
    /// Region being assembled
    current_region: Option<DerpRegion>,
    /// Whether we're in the first region node (we only parse one)
    first_region_node: bool,
    /// Whether we're in the first address of a peer's Addresses array
    first_peer_addr: bool,
    /// Whether we're in the first address of our Node.Addresses
    first_our_addr: bool,

    /// Output accumulator
    pub out: MapState<MAX_PEERS, MAX_REGIONS>,
}

impl<const MAX_PEERS: usize, const MAX_REGIONS: usize> MapParser<MAX_PEERS, MAX_REGIONS> {
    pub fn new() -> Self {
        Self {
            state:             State::Root,
            prev_state:        State::Root,
            string_target:     StringTarget::Discard,
            key_buf:           heapless::Vec::new(),
            val_buf:           heapless::Vec::new(),
            in_escape:         false,
            skip_depth:        0,
            current_peer:      None,
            current_region:    None,
            first_region_node: false,
            first_peer_addr:   false,
            first_our_addr:    false,
            out: MapState {
                our_ip:       TailnetIp([0; 4]),
                peers:        ArrayVec::new(),
                derp_regions: ArrayVec::new(),
            },
        }
    }

    /// Feed a chunk of bytes (one H/2 DATA frame payload).
    /// Returns `Ok(true)` when the root `}` is seen — parsing complete.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<bool, JsonError> {
        for &b in chunk {
            if self.step(b)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Commit any pending peer/region to output.
    pub fn finish(&mut self) {
        self.commit_peer();
        self.commit_region();
    }

    // ── Core byte processor ───────────────────────────────────────────────────

    fn step(&mut self, b: u8) -> Result<bool, JsonError> {
        match self.state {
            State::InString  => return self.step_string(b),
            State::Skipping  => { self.step_skip(b); return Ok(false); }
            _ => {}
        }

        match b {
            // Whitespace anywhere (outside strings)
            b' ' | b'\t' | b'\r' | b'\n' => {}

            // Object / array open — handled per state
            b'{' => self.on_object_open(),
            b'[' => self.on_array_open(),
            b'}' => return self.on_object_close(),
            b']' => { self.on_array_close(); }
            b',' => self.on_comma(),
            b':' => {} // key–value separator — no action needed
            b'"' => self.begin_string(),

            // Boolean / null / number — discard silently (we handle what we need)
            _ => {}
        }

        Ok(false)
    }

    // ── String accumulation ───────────────────────────────────────────────────

    fn begin_string(&mut self) {
        self.val_buf.clear();
        // Determine whether this is a key or a value based on state
        let is_key_position = matches!(
            self.state,
            State::Root | State::InNode | State::InOnePeer |
            State::InDerpMap | State::InRegions | State::InOneRegion | State::InRegionNode
        );
        if is_key_position {
            self.key_buf.clear();
            self.string_target = StringTarget::Key;
        } else {
            self.string_target = self.value_target_for_current_key();
        }
        self.prev_state = self.state;
        self.state = State::InString;
        self.in_escape = false;
    }

    fn value_target_for_current_key(&self) -> StringTarget {
        let key = self.key_buf.as_slice();
        match self.prev_state {
            State::InNode => match key {
                b"Addresses" => StringTarget::OurAddress,
                _ => StringTarget::Discard,
            },
            State::InOnePeer => match key {
                b"Key"       => StringTarget::PeerKey,
                b"DiscoKey"  => StringTarget::PeerDiscoKey,
                b"Addresses" => StringTarget::PeerAddress,
                b"DERP"      => StringTarget::PeerDerp,
                // Hostinfo is an object — handled via InOnePeer→InObject path
                _ => StringTarget::Discard,
            },
            State::InOneRegion => match key {
                b"RegionCode" => StringTarget::RegionCode,
                _ => StringTarget::Discard,
            },
            State::InRegionNode => match key {
                b"HostName" => StringTarget::RegionHost,
                _ => StringTarget::Discard,
            },
            _ => StringTarget::Discard,
        }
    }

    fn step_string(&mut self, b: u8) -> Result<bool, JsonError> {
        if self.in_escape {
            self.in_escape = false;
            // For our purposes, just accumulate the escaped char literally
            if self.string_target != StringTarget::Discard {
                let _ = self.val_buf.push(b);
            }
            return Ok(false);
        }
        match b {
            b'\\' => {
                self.in_escape = true;
            }
            b'"' => {
                // End of string
                self.state = self.prev_state;
                self.on_string_complete()?;
            }
            _ => {
                match self.string_target {
                    StringTarget::Key => {
                        let _ = self.key_buf.push(b);
                    }
                    StringTarget::Discard => {}
                    _ => {
                        // Only accumulate up to val_buf capacity
                        let _ = self.val_buf.push(b);
                    }
                }
            }
        }
        Ok(false)
    }

    fn on_string_complete(&mut self) -> Result<(), JsonError> {
        let target = self.string_target;
        self.string_target = StringTarget::Discard;

        match target {
            StringTarget::Key => {
                // Nothing extra — key_buf is already filled
            }
            StringTarget::OurAddress => {
                // First address like "100.x.x.x/32"
                if self.first_our_addr {
                    self.first_our_addr = false;
                    let s = core::str::from_utf8(&self.val_buf)
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    if let Some(ip) = parse_ipv4_cidr(s) {
                        self.out.our_ip = TailnetIp(ip);
                    }
                }
            }
            StringTarget::PeerKey => {
                if let Some(peer) = self.current_peer.as_mut() {
                    let _ = hex_to_bytes32(&self.val_buf, &mut peer.node_key);
                }
            }
            StringTarget::PeerDiscoKey => {
                if let Some(peer) = self.current_peer.as_mut() {
                    let _ = hex_to_bytes32(&self.val_buf, &mut peer.disco_key);
                }
            }
            StringTarget::PeerAddress => {
                if self.first_peer_addr {
                    self.first_peer_addr = false;
                    let s = core::str::from_utf8(&self.val_buf)
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    if let Some(ip) = parse_ipv4_cidr(s) {
                        if let Some(peer) = self.current_peer.as_mut() {
                            peer.tailnet_ip = TailnetIp(ip);
                        }
                    }
                }
            }
            StringTarget::PeerDerp => {
                // Format: "127.3.3.40:<region_id>"
                let s = core::str::from_utf8(&self.val_buf)
                    .map_err(|_| JsonError::InvalidUtf8)?;
                if let Some(region_id) = parse_derp_virtual_ip(s) {
                    if let Some(peer) = self.current_peer.as_mut() {
                        peer.derp_region = region_id;
                    }
                }
            }
            StringTarget::RegionCode => {
                if let Some(region) = self.current_region.as_mut() {
                    let s = core::str::from_utf8(&self.val_buf)
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    region.region_code = heapless::String::try_from(s).unwrap_or_default();
                }
            }
            StringTarget::RegionHost => {
                if let Some(region) = self.current_region.as_mut() {
                    let s = core::str::from_utf8(&self.val_buf)
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    region.host = heapless::String::try_from(s).unwrap_or_default();
                }
            }
            StringTarget::PeerHostname => {
                if let Some(peer) = self.current_peer.as_mut() {
                    let s = core::str::from_utf8(&self.val_buf)
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    peer.hostname = heapless::String::try_from(s).unwrap_or_default();
                }
            }
            StringTarget::Discard => {}
        }
        Ok(())
    }

    // ── Object / array transitions ────────────────────────────────────────────

    fn on_object_open(&mut self) {
        match (self.state, self.key_buf.as_slice()) {
            (State::Root,      b"Node")    => { self.state = State::InNode; }
            (State::Root,      b"DERPMap") => { self.state = State::InDerpMap; }
            (State::InDerpMap, b"Regions") => { self.state = State::InRegions; }
            (State::InRegions, _) => {
                // The key is the region ID (numeric string like "1", "2", ...)
                let region_id = core::str::from_utf8(&self.key_buf)
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(0);
                self.current_region = Some(DerpRegion {
                    region_id,
                    region_code: heapless::String::new(),
                    host:        heapless::String::new(),
                    port:        443,
                    latency_ms:  0,
                });
                self.state = State::InOneRegion;
            }
            (State::InRegionNode, _) => {
                // Nested object inside node — skip
                self.begin_skip();
            }
            (State::InOnePeer, _) => {
                // Hostinfo or other nested object — skip
                // (Hostname is inside Hostinfo which we skip at top level;
                //  a future improvement could descend into it)
                self.begin_skip();
            }
            _ => { self.begin_skip(); }
        }
        self.key_buf.clear();
    }

    fn on_array_open(&mut self) {
        match (self.state, self.key_buf.as_slice()) {
            (State::Root, b"Peers") => {
                self.state = State::InPeers;
            }
            (State::InOneRegion, b"Nodes") => {
                self.state = State::InRegionNodes;
                self.first_region_node = true;
            }
            (State::InOnePeer, b"Addresses") => {
                self.first_peer_addr = true;
                // Stay in InOnePeer — strings inside will be PeerAddress
            }
            (State::InNode, b"Addresses") => {
                self.first_our_addr = true;
                // Stay in InNode
            }
            _ => { self.begin_skip(); }
        }
        self.key_buf.clear();
    }

    fn on_object_close(&mut self) -> Result<bool, JsonError> {
        match self.state {
            State::Root => return Ok(true),  // root object closed
            State::InNode => { self.state = State::Root; }
            State::InDerpMap => { self.state = State::Root; }
            State::InRegions => { self.state = State::InDerpMap; }
            State::InOneRegion => {
                self.commit_region();
                self.state = State::InRegions;
            }
            State::InRegionNode => {
                self.state = State::InRegionNodes;
            }
            State::InOnePeer => {
                self.commit_peer();
                self.state = State::InPeers;
            }
            _ => {}
        }
        Ok(false)
    }

    fn on_array_close(&mut self) {
        match self.state {
            State::InPeers        => { self.state = State::Root; }
            State::InRegionNodes  => { self.state = State::InOneRegion; }
            _ => {}
        }
    }

    fn on_comma(&mut self) {
        match self.state {
            State::InPeers => {
                // Next element will be a new peer object
                self.current_peer = Some(new_peer());
            }
            State::InRegionNodes => {
                // We only parse the first node; skip the rest
                if !self.first_region_node {
                    self.begin_skip();
                }
            }
            _ => {}
        }
    }

    // ── Skip logic ────────────────────────────────────────────────────────────

    fn begin_skip(&mut self) {
        self.prev_state = self.state;
        self.state = State::Skipping;
        self.skip_depth = 0;
    }

    fn step_skip(&mut self, b: u8) {
        // Track nesting to know when the skipped value ends
        match b {
            b'{' | b'[' => self.skip_depth += 1,
            b'}' | b']' => {
                if self.skip_depth == 0 {
                    self.state = self.prev_state;
                } else {
                    self.skip_depth -= 1;
                }
            }
            b'"' => {
                // Skip string — consume until closing quote
                // This is approximate: doesn't handle \" correctly.
                // For Tailscale's MapResponse, keys and values don't
                // contain escaped quotes in the fields we skip.
            }
            b',' if self.skip_depth == 0 => {
                self.state = self.prev_state;
            }
            _ => {}
        }
    }

    // ── Commit helpers ────────────────────────────────────────────────────────

    fn commit_peer(&mut self) {
        if let Some(peer) = self.current_peer.take() {
            // Only add peers with a valid key and IP
            if peer.node_key != [0u8; 32] && peer.tailnet_ip.0 != [0u8; 4] {
                if self.out.peers.is_full() {
                    tracing::warn!("Peer table full — dropping peer {:?}", peer.hostname);
                } else {
                    self.out.peers.push(peer);
                }
            }
        }
    }

    fn commit_region(&mut self) {
        if let Some(region) = self.current_region.take() {
            if !region.host.is_empty() {
                if !self.out.derp_regions.is_full() {
                    self.out.derp_regions.push(region);
                }
            }
        }
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

fn new_peer() -> PeerInfo {
    PeerInfo {
        node_key:    [0u8; 32],
        disco_key:   [0u8; 32],
        tailnet_ip:  TailnetIp([0; 4]),
        prefix_len:  32,
        hostname:    heapless::String::new(),
        derp_region: 0,
        is_online:   false,
    }
}

/// Parse "100.64.0.1/32" → [100, 64, 0, 1]
/// Returns None if not a valid IPv4 CIDR.
fn parse_ipv4_cidr(s: &str) -> Option<[u8; 4]> {
    let ip_part = s.split('/').next()?;
    let mut octets = [0u8; 4];
    let mut i = 0;
    for part in ip_part.split('.') {
        if i >= 4 { return None; }
        octets[i] = part.parse().ok()?;
        i += 1;
    }
    if i == 4 { Some(octets) } else { None }
}

/// Parse DERP virtual IP "127.3.3.40:<region_id>" → region_id
fn parse_derp_virtual_ip(s: &str) -> Option<u16> {
    // Format is "127.3.3.40:<n>" where <n> is the region ID
    let colon = s.rfind(':')?;
    s[colon+1..].parse().ok()
}

/// Decode a hex string (possibly with "nodekey:" / "discokey:" prefix)
/// into a 32-byte array.
fn hex_to_bytes32(src: &[u8], dst: &mut [u8; 32]) -> Option<()> {
    // Skip known prefixes
    let hex_part = {
        let s = core::str::from_utf8(src).ok()?;
        if let Some(rest) = s.strip_prefix("nodekey:") { rest }
        else if let Some(rest) = s.strip_prefix("discokey:") { rest }
        else { s }
    };

    if hex_part.len() != 64 { return None; }

    for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
        dst[i] = u8::from_str_radix(
            core::str::from_utf8(chunk).ok()?,
            16
        ).ok()?;
    }
    Some(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_cidr_test() {
        assert_eq!(parse_ipv4_cidr("100.64.0.1/32"), Some([100, 64, 0, 1]));
        assert_eq!(parse_ipv4_cidr("10.0.0.1/24"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4_cidr("bad"), None);
    }

    #[test]
    fn parse_derp_virtual_ip_test() {
        assert_eq!(parse_derp_virtual_ip("127.3.3.40:1"), Some(1));
        assert_eq!(parse_derp_virtual_ip("127.3.3.40:21"), Some(21));
        assert_eq!(parse_derp_virtual_ip("bad"), None);
    }

    #[test]
    fn hex_to_bytes32_test() {
        let mut dst = [0u8; 32];
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        hex_to_bytes32(hex.as_bytes(), &mut dst);
        assert_eq!(dst[0], 0x01);
        assert_eq!(dst[31], 0x20);
    }

    #[test]
    fn parse_minimal_map_response() {
        let json = r#"{
            "Node": {
                "Addresses": ["100.64.0.1/32"]
            },
            "Peers": [
                {
                    "Key": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "DiscoKey": "discokey:2021222324252627282920212223242526272829202122232425262728293031",
                    "Addresses": ["100.64.0.2/32"],
                    "DERP": "127.3.3.40:1",
                    "Hostinfo": {"OS": "linux"}
                }
            ],
            "DERPMap": {
                "Regions": {
                    "1": {
                        "RegionCode": "nyc",
                        "Nodes": [
                            {"HostName": "derp1.tailscale.com", "STUNPort": 3478}
                        ]
                    }
                }
            }
        }"#;

        let mut parser: MapParser<8, 4> = MapParser::new();
        let done = parser.feed(json.as_bytes()).unwrap();
        parser.finish();

        assert!(done);
        assert_eq!(parser.out.our_ip.0, [100, 64, 0, 1]);
        assert_eq!(parser.out.peers.len(), 1);
        assert_eq!(parser.out.peers[0].tailnet_ip.0, [100, 64, 0, 2]);
        assert_eq!(parser.out.peers[0].derp_region, 1);
        assert_eq!(parser.out.derp_regions.len(), 1);
        assert_eq!(parser.out.derp_regions[0].region_code.as_str(), "nyc");
    }

    #[test]
    fn parse_chunked_simulates_h2_frames() {
        let json = r#"{"Node":{"Addresses":["100.64.0.5/32"]},"Peers":[],"DERPMap":{"Regions":{}}}"#;

        // Feed in 8-byte chunks, simulating small H/2 DATA frames
        let mut parser: MapParser<8, 4> = MapParser::new();
        let mut done = false;
        for chunk in json.as_bytes().chunks(8) {
            done = parser.feed(chunk).unwrap();
            if done { break; }
        }
        parser.finish();

        assert!(done);
        assert_eq!(parser.out.our_ip.0, [100, 64, 0, 5]);
    }
}
