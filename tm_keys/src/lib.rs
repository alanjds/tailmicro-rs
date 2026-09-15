//! Tailscale cryptographic key types.
//!
//! Mirrors `ts_keys` from tailscale-rs but with `no_std`-friendly bounds.
//! Each key kind is a distinct newtype — you cannot accidentally pass a
//! `DiscoPublicKey` where a `NodePublicKey` is expected.

use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};

pub mod pin;

// ── Node key ─────────────────────────────────────────────────────────────────

/// The long-lived identity key of a Tailscale node.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodePrivateKey(pub(crate) StaticSecret);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePublicKey(pub(crate) [u8; 32]);

impl NodePrivateKey {
    pub fn generate() -> Self {
        // In ESP-IDF, getrandom is backed by esp_random()
        let secret = StaticSecret::random_from_rng(rand_core_shim());
        Self(secret)
    }

    pub fn public(&self) -> NodePublicKey {
        let pk: PublicKey = (&self.0).into();
        NodePublicKey(*pk.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl NodePublicKey {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    /// Hex-encoded, prefixed — matches Tailscale wire format.
    ///
    /// Capacity is 80, not the tighter 68 this used to be: `"nodekey:"` (8
    /// bytes) + 64 hex digits = 72 bytes, already over 68. The `core::fmt::write`
    /// calls below silently truncate on overflow (`let _ =` discards the
    /// `Err`), so the old capacity produced a real-looking but truncated
    /// 60-hex-digit (30-byte) key with no error anywhere - confirmed live:
    /// this is what made every `RegisterRequest.NodeKey` sent to the real
    /// control server malformed, which it rejected with a generic `500`.
    /// Root-caused by logging the exact request body sent from
    /// `connect_and_poll` and noticing the hex string was short. See
    /// docs/noise-handshake-wire-format.md.
    pub fn to_hex(&self) -> heapless::String<80> {
        let mut s = heapless::String::new();
        s.push_str("nodekey:").ok();
        for b in &self.0 {
            let _ = core::fmt::write(&mut s, format_args!("{:02x}", b));
        }
        s
    }
}

// ── Machine key (Noise IK) ────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct MachinePrivateKey(pub(crate) StaticSecret);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachinePublicKey(pub(crate) [u8; 32]);

impl MachinePrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand_core_shim()))
    }
    pub fn public(&self) -> MachinePublicKey {
        let pk: PublicKey = (&self.0).into();
        MachinePublicKey(*pk.as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; 32] { self.0.as_bytes() }
}

impl MachinePublicKey {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn to_hex(&self) -> heapless::String<80> {
        let mut s = heapless::String::new();
        s.push_str("mkey:").ok();
        for b in &self.0 {
            let _ = core::fmt::write(&mut s, format_args!("{:02x}", b));
        }
        s
    }
}

// ── Disco key ─────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoPrivateKey(pub(crate) StaticSecret);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoPublicKey(pub(crate) [u8; 32]);

impl DiscoPrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand_core_shim()))
    }
    pub fn public(&self) -> DiscoPublicKey {
        let pk: PublicKey = (&self.0).into();
        DiscoPublicKey(*pk.as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; 32] { self.0.as_bytes() }

    /// Reconstruct from raw 32-byte scalar bytes.
    ///
    /// Additive constructor mirroring `DiscoPublicKey::from_bytes`; used to
    /// rebuild a deterministic disco key from a fixed test vector (see the
    /// `tm_disco` framing test) and anywhere a persisted disco key is loaded.
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(StaticSecret::from(b)) }

    /// Returns a reference to the inner x25519 private key for Diffie-Hellman
    pub fn as_static_secret(&self) -> &StaticSecret {
        &self.0
    }
}

impl DiscoPublicKey {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn to_hex(&self) -> heapless::String<80> {
        let mut s = heapless::String::new();
        s.push_str("discokey:").ok();
        for b in &self.0 {
            let _ = core::fmt::write(&mut s, format_args!("{:02x}", b));
        }
        s
    }
}

// ── Persistent state (stored in NVS on ESP32) ─────────────────────────────────
//
// All keys that should survive a reboot.
// On ESP32-C3 these are written to NVS flash (~512 bytes total).
#[derive(Serialize, Deserialize)]
pub struct NodeState {
    pub node_key:    NodePrivateKey,
    pub machine_key: MachinePrivateKey,
    pub disco_key:   DiscoPrivateKey,
}

impl NodeState {
    /// Generate a fresh identity. Call once, then persist.
    pub fn generate() -> Self {
        Self {
            node_key:    NodePrivateKey::generate(),
            machine_key: MachinePrivateKey::generate(),
            disco_key:   DiscoPrivateKey::generate(),
        }
    }
}

// ── rand_core shim ────────────────────────────────────────────────────────────
// On ESP-IDF, getrandom is available via esp-idf-sys.
// On host (tests), uses OsRng.
fn rand_core_shim() -> impl rand_core::CryptoRng + rand_core::RngCore {
    // This compiles on both targets because getrandom's esp-idf feature
    // routes through esp_random().
    rand::rngs::OsRng
}
