//! Buffer-and-parse MapResponse decoder (serde_json).
//!
//! The hand-rolled streaming `map_parser` (removed; see git history) was
//! found (live, 2026-09-16) to mis-parse the real control-server MapResponse:
//! its own unit tests failed on the committed code, and on device it extracted
//! 0 peers / 0 DERP regions / no IP from a 34 KB live response (root `{`
//! skipped the whole document; skip logic was not string-aware; array-element
//! strings were misclassified as keys). See docs/wg-dataplane-notes.md.
//!
//! For device bring-up the tailnet is small (one target peer) and the response
//! is tens of KB against ~120 KB free heap, so buffering the de-prefixed JSON
//! and parsing it with `serde_json` (already a dependency, borrowing `&str`
//! for the escape-free fields we read) is correct and far more robust. A very
//! large tailnet (hundreds of KB) would want the streaming approach fixed, but
//! that is out of scope for the data-plane bring-up.

use arrayvec::ArrayVec;
use serde::Deserialize;

use crate::{DerpRegion, MapState, PeerInfo, TailnetIp};

#[derive(Deserialize)]
struct MapResponse<'a> {
    #[serde(borrow, default, rename = "Node")]
    node: Option<NodeR<'a>>,
    #[serde(borrow, default, rename = "Peers")]
    peers: alloc_vec::Vec<PeerR<'a>>,
    #[serde(borrow, default, rename = "DERPMap")]
    derp_map: Option<DerpMapR<'a>>,
}

#[derive(Deserialize)]
struct NodeR<'a> {
    #[serde(borrow, default, rename = "Addresses")]
    addresses: alloc_vec::Vec<&'a str>,
}

#[derive(Deserialize)]
struct PeerR<'a> {
    #[serde(borrow, default, rename = "Key")]
    key: Option<&'a str>,
    #[serde(borrow, default, rename = "DiscoKey")]
    disco_key: Option<&'a str>,
    #[serde(borrow, default, rename = "Addresses")]
    addresses: alloc_vec::Vec<&'a str>,
    #[serde(borrow, default, rename = "DERP")]
    derp: Option<&'a str>,
    #[serde(default, rename = "Online")]
    online: Option<bool>,
    #[serde(borrow, default, rename = "Hostinfo")]
    hostinfo: Option<HostinfoR<'a>>,
}

#[derive(Deserialize)]
struct HostinfoR<'a> {
    #[serde(borrow, default, rename = "Hostname")]
    hostname: Option<&'a str>,
}

#[derive(Deserialize)]
struct DerpMapR<'a> {
    #[serde(borrow, default, rename = "Regions")]
    regions: alloc_map::Map<&'a str, RegionR<'a>>,
}

#[derive(Deserialize)]
struct RegionR<'a> {
    #[serde(default, rename = "RegionID")]
    region_id: Option<u16>,
    #[serde(borrow, default, rename = "RegionCode")]
    region_code: Option<&'a str>,
    #[serde(borrow, default, rename = "Nodes")]
    nodes: alloc_vec::Vec<NodeHostR<'a>>,
}

#[derive(Deserialize)]
struct NodeHostR<'a> {
    #[serde(borrow, default, rename = "HostName")]
    host_name: Option<&'a str>,
}

mod alloc_vec {
    pub use std::vec::Vec;
}
mod alloc_map {
    pub use std::collections::BTreeMap as Map;
}

/// Parse a full (de-prefixed) MapResponse JSON body into a [`MapState`].
pub fn parse<const MAX_PEERS: usize, const MAX_REGIONS: usize>(
    body: &[u8],
) -> Result<MapState<MAX_PEERS, MAX_REGIONS>, crate::JsonError> {
    let mr: MapResponse =
        serde_json::from_slice(body).map_err(|_| crate::JsonError::ParseError)?;

    let mut out: MapState<MAX_PEERS, MAX_REGIONS> = MapState {
        our_ip: TailnetIp([0; 4]),
        peers: ArrayVec::new(),
        derp_regions: ArrayVec::new(),
    };

    if let Some(node) = mr.node {
        if let Some(ip) = node.addresses.iter().find_map(|a| parse_ipv4(a)) {
            out.our_ip = TailnetIp(ip);
        }
    }

    for p in mr.peers {
        if out.peers.is_full() {
            break;
        }
        let (Some(key), Some(ip)) = (
            p.key.and_then(|k| hex_key(k)),
            p.addresses.iter().find_map(|a| parse_ipv4(a)),
        ) else {
            continue;
        };
        let disco = p.disco_key.and_then(|d| hex_key(d)).unwrap_or([0u8; 32]);
        let derp_region = p.derp.and_then(parse_derp_region).unwrap_or(0);
        let hostname = p
            .hostinfo
            .and_then(|h| h.hostname)
            .and_then(|s| heapless::String::try_from(s).ok())
            .unwrap_or_default();
        out.peers.push(PeerInfo {
            node_key: key,
            disco_key: disco,
            tailnet_ip: TailnetIp(ip),
            prefix_len: 32,
            hostname,
            derp_region,
            is_online: p.online.unwrap_or(false),
        });
    }

    if let Some(dm) = mr.derp_map {
        for (rid, region) in dm.regions {
            if out.derp_regions.is_full() {
                break;
            }
            let host = region
                .nodes
                .iter()
                .find_map(|n| n.host_name)
                .and_then(|s| heapless::String::try_from(s).ok())
                .unwrap_or_default();
            if host.is_empty() {
                continue;
            }
            let region_id = region_id_or(rid, region.region_id);
            let region_code = region
                .region_code
                .and_then(|s| heapless::String::try_from(s).ok())
                .unwrap_or_default();
            out.derp_regions.push(DerpRegion {
                region_id,
                region_code,
                host,
                port: 443,
                latency_ms: 0,
            });
        }
    }

    Ok(out)
}

fn region_id_or(key: &str, from_body: Option<u16>) -> u16 {
    from_body.unwrap_or_else(|| key.parse::<u16>().unwrap_or(0))
}

/// Decode a `"nodekey:<64 hex>"` / `"discokey:<64 hex>"` / bare-hex string to 32 bytes.
fn hex_key(s: &str) -> Option<[u8; 32]> {
    let hex = s.rsplit(':').next().unwrap_or(s);
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32 {
        out[i] = (hex_nib(b[2 * i])? << 4) | hex_nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn hex_nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse the first IPv4 out of `"100.64.0.1/32"` (skips IPv6 like `"fd7a::/128"`).
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let host = s.split('/').next().unwrap_or(s);
    if host.contains(':') {
        return None;
    }
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for o in octets.iter_mut() {
        *o = parts.next()?.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// Parse the region id out of a peer's DERP home `"127.3.3.40:<region>"`.
fn parse_derp_region(s: &str) -> Option<u16> {
    s.rsplit(':').next()?.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::parse;

    // Mirrors the real MapResponse shape incl. skipped subtrees whose string
    // values carry structural bytes ({}[],) that broke the streaming parser.
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
    fn parses_real_shaped_response() {
        let m = parse::<8, 4>(JSON.as_bytes()).unwrap();
        assert_eq!(m.our_ip.0, [100, 64, 0, 1]);
        assert_eq!(m.peers.len(), 1);
        assert_eq!(m.peers[0].tailnet_ip.0, [100, 64, 0, 2]);
        assert_eq!(m.peers[0].derp_region, 7);
        assert!(m.peers[0].is_online);
        assert_eq!(m.peers[0].hostname.as_str(), "peerhost");
        assert_eq!(m.peers[0].node_key[0], 0x01);
        assert_eq!(m.peers[0].disco_key[0], 0x20);
        assert_eq!(m.derp_regions.len(), 1);
        assert_eq!(m.derp_regions[0].region_id, 7);
        assert_eq!(m.derp_regions[0].region_code.as_str(), "lax");
        assert_eq!(m.derp_regions[0].host.as_str(), "derp7.tailscale.com");
    }
}
