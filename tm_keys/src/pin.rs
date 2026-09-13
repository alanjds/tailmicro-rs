//! Control-key pin verification.
//!
//! Verifies an offline-signed, Ed25519-signed blob that pins the Tailscale
//! control server's Noise static public key. This replaces the on-device
//! `/key` HTTP(S) fetch: the pin is generated once, off-device, by
//! `tools/gen_fingerprint.py` (which does the X.509-validated fetch and
//! signs the result), and is embedded into firmware at build time.
//!
//! Blob layout (109 bytes total), all integers little-endian:
//!
//! ```text
//! offset  len  field
//! 0       4    magic "TMPN"
//! 4       1    version (1)
//! 5       32   pinned Noise public key
//! 37      8    not_after (unix seconds)
//! 45      64   Ed25519 signature over bytes [0..45)
//! ```
//!
//! Pure and allocation-free: no ESP-IDF dependency, host-testable via
//! `cargo test -p tm_keys`.

use ed25519_dalek::{Signature, VerifyingKey};

pub const PIN_MAGIC: &[u8; 4] = b"TMPN";
pub const PIN_VERSION: u8 = 1;
/// 4 (magic) + 1 (version) + 32 (pubkey) + 8 (not_after)
pub const PIN_BODY_LEN: usize = 45;
/// Signed body plus the 64-byte Ed25519 signature.
pub const PIN_BLOB_LEN: usize = PIN_BODY_LEN + 64;
/// Length of the hex-encoded blob (two hex chars per byte).
pub const PIN_HEX_LEN: usize = PIN_BLOB_LEN * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    BadLength,
    BadMagic,
    BadVersion,
    PlaceholderVerifyKey,
    BadVerifyKey,
    BadSignature,
    Expired,
    BadHex,
}

/// Verify a control-key pin blob against `verify_key`.
///
/// Returns the pinned Noise public key on success. No part of the body
/// (pubkey or `not_after`) is trusted or returned before the Ed25519
/// signature check succeeds.
pub fn verify_pin(
    blob: &[u8],
    verify_key: &[u8; 32],
    now_unix: Option<u64>,
) -> Result<[u8; 32], PinError> {
    if blob.len() != PIN_BLOB_LEN {
        return Err(PinError::BadLength);
    }

    let body = &blob[..PIN_BODY_LEN];
    let sig_bytes = &blob[PIN_BODY_LEN..];

    if &body[0..4] != PIN_MAGIC.as_slice() {
        return Err(PinError::BadMagic);
    }
    if body[4] != PIN_VERSION {
        return Err(PinError::BadVersion);
    }

    // Guards an unconfigured/placeholder firmware build from ever trusting
    // an unsigned blob.
    if verify_key == &[0u8; 32] {
        return Err(PinError::PlaceholderVerifyKey);
    }

    let verifying_key =
        VerifyingKey::from_bytes(verify_key).map_err(|_| PinError::BadVerifyKey)?;

    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    // verify_strict (not verify): also rejects small-order/non-canonical
    // signatures, which matters for a security-critical pin check.
    verifying_key
        .verify_strict(body, &signature)
        .map_err(|_| PinError::BadSignature)?;

    // Only parse/return anything from the body after the signature has
    // been confirmed valid.
    let not_after = u64::from_le_bytes(body[37..45].try_into().unwrap());
    if let Some(now) = now_unix {
        if now >= not_after {
            return Err(PinError::Expired);
        }
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&body[5..37]);
    Ok(pubkey)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a hex-encoded pin blob (as printed by `gen_fingerprint.py` and
/// carried in the `TAILMICRO_CONTROL_PIN` env var). Trims ASCII whitespace
/// since `.env` files often carry a trailing newline.
pub fn decode_pin_hex(s: &str) -> Result<[u8; PIN_BLOB_LEN], PinError> {
    let trimmed = s.trim_matches(|c: char| c.is_ascii_whitespace());
    let bytes = trimmed.as_bytes();
    if bytes.len() != PIN_HEX_LEN {
        return Err(PinError::BadHex);
    }

    let mut out = [0u8; PIN_BLOB_LEN];
    for i in 0..PIN_BLOB_LEN {
        let hi = hex_nibble(bytes[i * 2]).ok_or(PinError::BadHex)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(PinError::BadHex)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Convenience wrapper: decode hex, then verify.
pub fn verify_pin_hex(
    s: &str,
    verify_key: &[u8; 32],
    now_unix: Option<u64>,
) -> Result<[u8; 32], PinError> {
    let blob = decode_pin_hex(s)?;
    verify_pin(&blob, verify_key, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture generated via:
    //   python3 tools/gen_fingerprint.py \
    //     --pubkey-hex 0101010101010101010101010101010101010101010101010101010101010101 \
    //     --key-file /tmp/test_signing_key1.bin --expiry-days 35
    // (the throwaway signing key lives outside the repo; --pubkey-hex is a
    // fake 32-byte fingerprint used purely as a test fixture)
    const PUBKEY: [u8; 32] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01,
    ];

    const VERIFY_KEY: [u8; 32] = [
        0xc4, 0xdc, 0x65, 0x3d, 0x2d, 0x75, 0xe1, 0x1e, 0x21, 0x6c, 0xd9, 0x20, 0xce, 0x00, 0xec,
        0x40, 0xbc, 0x3f, 0xff, 0x4c, 0xe6, 0x7c, 0x47, 0x94, 0xf5, 0xae, 0xc5, 0xbf, 0x2a, 0x65,
        0x8e, 0x73,
    ];

    const PIN_HEX: &str = "544d504e0101010101010101010101010101010101010101010101010101010101010101010c13d46a00000000c410148efdb41a6d9593518bc2728edb17691552ed43f5791918816ea91211e193f73d0c55678a179d3d22fdcb042e24dad92b19e013af2d463459ba91f3ca06";

    const NOT_AFTER: u64 = 1_792_283_404; // from --expiry-days 35 in the fixture

    // Second fixture, signed with a different key (different --key-file), for
    // the wrong_signer test.
    const VERIFY_KEY_2: [u8; 32] = [
        0xd3, 0x12, 0x02, 0xcd, 0x4e, 0x1e, 0xe2, 0x7a, 0xd5, 0x86, 0xc2, 0xea, 0xdf, 0x96, 0x34,
        0x80, 0xe8, 0x9a, 0xf5, 0x4e, 0x91, 0x16, 0x69, 0x58, 0x00, 0xbc, 0x78, 0x61, 0x5b, 0x3e,
        0xf7, 0x73,
    ];

    fn hex_to_blob(s: &str) -> [u8; PIN_BLOB_LEN] {
        decode_pin_hex(s).expect("fixture hex must decode")
    }

    #[test]
    fn happy_path() {
        let blob = hex_to_blob(PIN_HEX);
        let result = verify_pin(&blob, &VERIFY_KEY, None);
        assert_eq!(result, Ok(PUBKEY));
    }

    #[test]
    fn happy_path_not_expired() {
        let blob = hex_to_blob(PIN_HEX);
        let result = verify_pin(&blob, &VERIFY_KEY, Some(NOT_AFTER - 1_000_000));
        assert_eq!(result, Ok(PUBKEY));
    }

    #[test]
    fn expired() {
        let blob = hex_to_blob(PIN_HEX);
        let result = verify_pin(&blob, &VERIFY_KEY, Some(NOT_AFTER + 1));
        assert_eq!(result, Err(PinError::Expired));
    }

    #[test]
    fn bad_signature_bit_flip() {
        let mut blob = hex_to_blob(PIN_HEX);
        blob[PIN_BODY_LEN] ^= 0x01; // flip a bit in the signature region
        let result = verify_pin(&blob, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadSignature));
    }

    #[test]
    fn bad_pubkey_bit_flip() {
        let mut blob = hex_to_blob(PIN_HEX);
        blob[5] ^= 0x01; // flip a bit in the pubkey region (bytes 5..37)
        let result = verify_pin(&blob, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadSignature));
    }

    #[test]
    fn truncated() {
        let blob = hex_to_blob(PIN_HEX);
        let short = &blob[..PIN_BLOB_LEN - 1];
        let result = verify_pin(short, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadLength));
    }

    #[test]
    fn oversized() {
        let blob = hex_to_blob(PIN_HEX);
        let mut long = blob.to_vec();
        long.push(0u8);
        let result = verify_pin(&long, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadLength));
    }

    #[test]
    fn bad_magic() {
        let mut blob = hex_to_blob(PIN_HEX);
        blob[0..4].copy_from_slice(b"XXXX");
        let result = verify_pin(&blob, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadMagic));
    }

    #[test]
    fn bad_version() {
        let mut blob = hex_to_blob(PIN_HEX);
        blob[4] = 2;
        let result = verify_pin(&blob, &VERIFY_KEY, None);
        assert_eq!(result, Err(PinError::BadVersion));
    }

    #[test]
    fn placeholder_verify_key() {
        let blob = hex_to_blob(PIN_HEX);
        let result = verify_pin(&blob, &[0u8; 32], None);
        assert_eq!(result, Err(PinError::PlaceholderVerifyKey));
    }

    #[test]
    fn wrong_signer() {
        let blob = hex_to_blob(PIN_HEX);
        let result = verify_pin(&blob, &VERIFY_KEY_2, None);
        assert_eq!(result, Err(PinError::BadSignature));
    }

    #[test]
    fn hex_with_trailing_whitespace() {
        let hex_with_ws = alloc_string(PIN_HEX, "\n  ");
        let result = verify_pin_hex(&hex_with_ws, &VERIFY_KEY, None);
        assert_eq!(result, Ok(PUBKEY));
    }

    #[test]
    fn hex_wrong_length() {
        let too_short = &PIN_HEX[..PIN_HEX.len() - 2];
        assert_eq!(decode_pin_hex(too_short), Err(PinError::BadHex));

        let too_long = alloc_string(PIN_HEX, "ab");
        assert_eq!(decode_pin_hex(&too_long), Err(PinError::BadHex));
    }

    #[test]
    fn hex_invalid_chars() {
        let mut bad = PIN_HEX.to_string();
        bad.replace_range(0..1, "g");
        assert_eq!(decode_pin_hex(&bad), Err(PinError::BadHex));

        let mut bad2 = PIN_HEX.to_string();
        bad2.replace_range(0..1, "Z");
        assert_eq!(decode_pin_hex(&bad2), Err(PinError::BadHex));
    }

    fn alloc_string(base: &str, suffix: &str) -> String {
        let mut s = String::from(base);
        s.push_str(suffix);
        s
    }
}
