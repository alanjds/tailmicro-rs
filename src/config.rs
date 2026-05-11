use tm_keys::NodeState;
use crate::Error;

/// Configuration for a `Device`.
///
/// Mirrors `tailscale::Config` so examples are source-compatible.
pub struct Config {
    pub(crate) control_host: &'static str,
    pub(crate) control_port: u16,
    /// Path to key file (host only; on ESP32-C3 use NVS directly).
    pub(crate) key_file: Option<&'static str>,
}

impl Config {
    /// Minimal constructor — auth key provided separately to `Device::new`.
    pub fn new(_auth_key: &str) -> Self {
        Self::default()
    }

    /// Mirror of `tailscale::Config::default_with_key_file`.
    pub async fn default_with_key_file(path: &'static str) -> Result<Self, Error> {
        Ok(Self { key_file: Some(path), ..Default::default() })
    }

    pub(crate) async fn load_or_generate_keys(&self) -> Result<NodeState, Error> {
        // On ESP32-C3: read from NVS; generate + persist on first boot.
        // On host: read from key_file JSON; generate + write on first run.
        // Both paths are platform-specific — stubbed here.
        Ok(NodeState::generate())
    }

    pub(crate) fn control_config(&self) -> tm_control::Config {
        tm_control::Config {
            control_host:      self.control_host,
            control_port:      self.control_port,
            cert_fingerprints: tm_control::TAILSCALE_CONTROL_FINGERPRINTS,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_host: "login.tailscale.com",
            control_port: 443,
            key_file:     None,
        }
    }
}
