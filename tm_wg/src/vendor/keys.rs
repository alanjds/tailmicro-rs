//! Key-type bridge shim (`ts_keys` → `tm_wg`).
//!
//! The vendored `ts_tunnel` files `use ts_keys::{NodeKeyPair, NodePrivateKey,
//! NodePublicKey}`. `tm_keys` has no `NodeKeyPair`, and its `NodePrivateKey`
//! wraps a non-`Copy` `x25519_dalek::StaticSecret`, while the vendored code
//! copies these key types by value repeatedly. Rather than destabilize the
//! already-working control plane that depends on `tm_keys`, this shim provides
//! self-contained `Copy` newtypes over `[u8; 32]` with exactly the API the
//! vendored code needs. Conversion to/from `tm_control`'s `[u8; 32]` node keys
//! happens at the actor boundary in `lib.rs`.
//!
//! See `docs/wg-dataplane-notes.md`, port decision #1.

use rand_core::{OsRng, RngCore};

/// A node's long-lived X25519 private key (raw scalar bytes).
#[derive(Copy, Clone)]
pub struct NodePrivateKey(pub [u8; 32]);

/// A node's long-lived X25519 public key.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NodePublicKey(pub(crate) [u8; 32]);

/// A private/public keypair.
#[derive(Copy, Clone)]
pub struct NodeKeyPair {
    pub private: NodePrivateKey,
    pub public: NodePublicKey,
}

impl NodeKeyPair {
    /// Generate a fresh random keypair.
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let private = NodePrivateKey(bytes);
        let public = NodePublicKey::from(private);
        Self { private, public }
    }

    /// Build a keypair from an existing private key.
    pub fn from_private(private: NodePrivateKey) -> Self {
        Self {
            private,
            public: NodePublicKey::from(private),
        }
    }
}

impl Default for NodeKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl NodePrivateKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl NodePublicKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for NodePublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<NodePublicKey> for x25519_dalek::PublicKey {
    fn from(k: NodePublicKey) -> Self {
        x25519_dalek::PublicKey::from(k.0)
    }
}

impl From<NodePrivateKey> for x25519_dalek::StaticSecret {
    fn from(k: NodePrivateKey) -> Self {
        x25519_dalek::StaticSecret::from(k.0)
    }
}

impl From<NodePrivateKey> for NodePublicKey {
    fn from(k: NodePrivateKey) -> Self {
        let secret = x25519_dalek::StaticSecret::from(k.0);
        let public = x25519_dalek::PublicKey::from(&secret);
        NodePublicKey(*public.as_bytes())
    }
}

impl core::fmt::Debug for NodePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NodePublicKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}
