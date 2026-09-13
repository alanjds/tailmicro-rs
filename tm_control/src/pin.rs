//! Control-key pin verification (re-exported from `tm_keys::pin`).

pub use tm_keys::pin::{verify_pin, verify_pin_hex, decode_pin_hex, PinError, PIN_BLOB_LEN, PIN_BODY_LEN, PIN_HEX_LEN};

/// Ed25519 public key that signs control-key pin blobs.
/// PLACEHOLDER - replace with the PIN_VERIFY_KEY emitted by tools/gen_fingerprint.py.
/// An all-zero key is rejected at verify time (PinError::PlaceholderVerifyKey),
/// so an unconfigured build fails closed instead of trusting an unsigned blob.
pub const PIN_VERIFY_KEY: [u8; 32] = [0u8; 32];
