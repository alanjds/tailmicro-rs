//! Scalar decoders for MapResponse string fields, shared by the streaming
//! parser in [`crate::map_stream`].

pub(crate) fn region_id_or(key: &str, from_body: Option<u16>) -> u16 {
    from_body.unwrap_or_else(|| key.parse::<u16>().unwrap_or(0))
}

/// Decode a `"nodekey:<64 hex>"` / `"discokey:<64 hex>"` / bare-hex string to 32 bytes.
pub(crate) fn hex_key(s: &str) -> Option<[u8; 32]> {
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
pub(crate) fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
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
pub(crate) fn parse_derp_region(s: &str) -> Option<u16> {
    s.rsplit(':').next()?.parse::<u16>().ok()
}
