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
    /// The control server's Noise static public key, verified from a
    /// signed pin blob via `with_control_pin_hex`. All-zero until then,
    /// which `tm_control` cannot use to complete a Noise handshake — there
    /// is no path that produces a working `Config` without going through
    /// `with_control_pin_hex`.
    pub(crate) control_pin: [u8; 32],
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

    /// Verify a hex-encoded, Ed25519-signed control-key pin blob (as
    /// produced by `tools/gen_fingerprint.py`) and store the resulting
    /// Noise public key. This is the only way to produce a `Config`
    /// capable of actually connecting to the control plane.
    pub fn with_control_pin_hex(mut self, blob_hex: &str) -> Result<Self, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        // pre-2023 => ESP-IDF boot clock, SNTP not done yet; skip expiry check until synced
        let now = now.filter(|&s| s > 1_700_000_000);

        let pin = tm_control::pin::verify_pin_hex(blob_hex, &tm_control::pin::PIN_VERIFY_KEY, now)
            .map_err(Error::Pin)?;
        self.control_pin = pin;
        Ok(self)
    }

    pub(crate) async fn load_or_generate_keys(&self) -> Result<NodeState, Error> {
        // On ESP32-C3: read from NVS; generate + persist on first boot.
        // On host: read from key_file JSON; generate + write on first run.
        // Both paths are platform-specific — stubbed here.
        Ok(NodeState::generate())
    }

    pub(crate) fn control_config(&self) -> tm_control::Config {
        tm_control::Config {
            control_host: self.control_host,
            control_port: self.control_port,
            control_pin:  self.control_pin,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_host: "login.tailscale.com",
            control_port: 80,
            key_file:     None,
            control_pin:  [0u8; 32],
        }
    }
}
