//! Peer configuration types. Vendored from ts_tunnel's `config.rs`; the
//! `Distribution<Psk>` impl (which needed rand 0.10's `RngExt`/`StandardUniform`)
//! is replaced by explicit `Psk::zero()` / `Psk::random()` constructors.

use rand::rngs::OsRng;
use rand_core::RngCore;

use super::keys::NodePublicKey;

/// A handle for a wireguard peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A wireguard symmetric pre-shared key.
#[derive(Copy, Clone)]
pub struct Psk([u8; 32]);

impl Psk {
    /// The all-zero PSK. Tailscale uses a 32-zero-byte PSK; the chain key must
    /// still advance through the KDF3 psk mix even though the value is zero.
    pub fn zero() -> Self {
        Psk([0u8; 32])
    }

    /// A random PSK (used by tests to exercise the psk mix).
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Psk(b)
    }
}

impl From<[u8; 32]> for Psk {
    fn from(bytes: [u8; 32]) -> Self {
        Psk(bytes)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Psk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// The cryptographic configuration for a wireguard peer.
pub struct PeerConfig {
    /// The peer's public key.
    pub key: NodePublicKey,
    /// The pre-shared key to use for the peer, for post-quantum resistance.
    pub psk: Psk,
}
