//! Tailscale cryptographic key types.
//!
//! Mirrors `ts_keys` from tailscale-rs but with `no_std`-friendly bounds.
//! Each key kind is a distinct newtype — you cannot accidentally pass a
//! `DiscoPublicKey` where a `NodePublicKey` is expected.

use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};
use hkdf::Hkdf;
use sha2::Sha256;

pub mod pin;

/// Derive a 32-byte x25519 scalar from `seed` via HKDF-SHA256, domain
/// separated by `label`. Same `(seed, label)` always yields the same
/// bytes; a different seed or a different label yields a different key.
///
/// `seed` need not be secret (an eFuse MAC is public) -- HKDF here is used
/// for domain separation and uniform output, not for hiding the input.
fn derive_scalar(seed: &[u8], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

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

    /// Deterministically derive this key from `seed` (K2: stable per-chip
    /// identity, see docs/stable-node-identity-plan.md). `label` MUST be
    /// distinct per key kind so node/machine/disco keys differ even though
    /// they share the same chip seed -- see `NODE_KEY_LABEL`.
    pub fn derive_from_seed(seed: &[u8], label: &[u8]) -> Self {
        Self(StaticSecret::from(derive_scalar(seed, label)))
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

    /// See `NodePrivateKey::derive_from_seed`.
    pub fn derive_from_seed(seed: &[u8], label: &[u8]) -> Self {
        Self(StaticSecret::from(derive_scalar(seed, label)))
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

    /// See `NodePrivateKey::derive_from_seed`.
    pub fn derive_from_seed(seed: &[u8], label: &[u8]) -> Self {
        Self(StaticSecret::from(derive_scalar(seed, label)))
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

// Fixed domain-separation labels, one per key kind, so the same chip seed
// derives three DIFFERENT keys (K2). Bump the "-v1" suffix if the
// derivation ever needs to change and old identities must be invalidated.
const NODE_KEY_LABEL: &[u8] = b"tailmicro-node-key-v1";
const MACHINE_KEY_LABEL: &[u8] = b"tailmicro-machine-key-v1";
const DISCO_KEY_LABEL: &[u8] = b"tailmicro-disco-key-v1";

// Fixed seed used on non-espidf targets (host builds/tests) so derivation
// stays reproducible without real eFuse hardware. Never used on-device.
const HOST_TEST_CHIP_SEED: [u8; 6] = *b"HOSTID";

impl NodeState {
    /// Generate a fresh, random identity. Call once, then persist.
    pub fn generate() -> Self {
        Self {
            node_key:    NodePrivateKey::generate(),
            machine_key: MachinePrivateKey::generate(),
            disco_key:   DiscoPrivateKey::generate(),
        }
    }

    /// Deterministically derive a full identity (node/machine/disco keys)
    /// from a single chip-unique `seed`. The three keys are guaranteed to
    /// differ from each other (distinct HKDF labels) even though they
    /// share the same input. Same seed always yields the same identity.
    pub fn derive_from_seed(seed: &[u8]) -> Self {
        Self {
            node_key:    NodePrivateKey::derive_from_seed(seed, NODE_KEY_LABEL),
            machine_key: MachinePrivateKey::derive_from_seed(seed, MACHINE_KEY_LABEL),
            disco_key:   DiscoPrivateKey::derive_from_seed(seed, DISCO_KEY_LABEL),
        }
    }

    /// K2: stable per-chip identity (see docs/stable-node-identity-plan.md).
    /// On ESP-IDF, seeds the derivation from the ESP32-C3 factory eFuse MAC
    /// (`esp_efuse_mac_get_default`, 6 bytes, unique per chip and
    /// unaffected by NVS erase or reflash). On host, uses a fixed test seed
    /// so `cargo test -p tm_keys` is reproducible without hardware.
    pub fn derive_from_chip() -> Self {
        Self::derive_from_seed(&chip_seed())
    }
}

#[cfg(target_os = "espidf")]
fn chip_seed() -> [u8; 6] {
    let mut mac = [0u8; 6];
    // Safety: `mac` is a valid 6-byte buffer, matching what
    // `esp_efuse_mac_get_default` writes (the factory-programmed base MAC).
    unsafe {
        esp_idf_sys::esp_efuse_mac_get_default(mac.as_mut_ptr());
    }
    mac
}

#[cfg(not(target_os = "espidf"))]
fn chip_seed() -> [u8; 6] {
    HOST_TEST_CHIP_SEED
}

fn rand_core_shim() -> impl rand_core::CryptoRng + rand_core::RngCore {
    rand_core::OsRng
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_and_label_reproduce_the_same_key() {
        let a = NodePrivateKey::derive_from_seed(b"chip-seed-a", NODE_KEY_LABEL);
        let b = NodePrivateKey::derive_from_seed(b"chip-seed-a", NODE_KEY_LABEL);
        assert_eq!(a.public().as_bytes(), b.public().as_bytes());
    }

    #[test]
    fn different_seed_yields_a_different_key() {
        let a = NodePrivateKey::derive_from_seed(b"chip-seed-a", NODE_KEY_LABEL);
        let b = NodePrivateKey::derive_from_seed(b"chip-seed-b", NODE_KEY_LABEL);
        assert_ne!(a.public().as_bytes(), b.public().as_bytes());
    }

    #[test]
    fn different_label_yields_a_different_key_from_the_same_seed() {
        let node = NodePrivateKey::derive_from_seed(b"chip-seed-a", NODE_KEY_LABEL);
        let machine = MachinePrivateKey::derive_from_seed(b"chip-seed-a", MACHINE_KEY_LABEL);
        let disco = DiscoPrivateKey::derive_from_seed(b"chip-seed-a", DISCO_KEY_LABEL);
        assert_ne!(node.public().as_bytes(), machine.public().as_bytes());
        assert_ne!(node.public().as_bytes(), disco.public().as_bytes());
        assert_ne!(machine.public().as_bytes(), disco.public().as_bytes());
    }

    #[test]
    fn derive_from_chip_is_reproducible_on_host() {
        // On host (not espidf) this uses the fixed HOST_TEST_CHIP_SEED, so
        // two calls in the same process must produce the identical identity
        // -- this is the "same physical chip -> same identity" guarantee,
        // exercised here via the host fallback seed.
        let a = NodeState::derive_from_chip();
        let b = NodeState::derive_from_chip();
        assert_eq!(a.node_key.public().as_bytes(), b.node_key.public().as_bytes());
        assert_eq!(a.machine_key.public().as_bytes(), b.machine_key.public().as_bytes());
        assert_eq!(a.disco_key.public().as_bytes(), b.disco_key.public().as_bytes());

        // And node/machine/disco still differ from each other.
        assert_ne!(a.node_key.public().as_bytes(), a.machine_key.public().as_bytes());
        assert_ne!(a.node_key.public().as_bytes(), a.disco_key.public().as_bytes());
    }

    #[test]
    fn generate_still_produces_random_non_deterministic_keys() {
        let a = NodePrivateKey::generate();
        let b = NodePrivateKey::generate();
        assert_ne!(a.public().as_bytes(), b.public().as_bytes());
    }
}
