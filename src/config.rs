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
    /// Deadline for control-plane bring-up only (TCP + Noise + register +
    /// publish, up to and including the tailnet IP being assigned). `None`
    /// (the default) disables it. Once bring-up succeeds, the streaming
    /// keepalive poll that follows runs unbounded regardless of this value
    /// — see `tm_control::Config::connect_timeout`.
    pub(crate) connect_timeout: Option<std::time::Duration>,
    /// How often the control connection re-fetches the full netmap while it
    /// is open. See `tm_control::Config::refresh_interval`.
    pub(crate) refresh_interval: Option<std::time::Duration>,
    pub(crate) hostname: &'static str,
    pub(crate) os_version: heapless::String<{ tm_control::MAX_OS_VERSION }>,
    pub(crate) services: &'static [tm_control::Service],
    pub(crate) magicdns: tm_netstack::names::MagicDns,
}

impl Config {
    /// Minimal constructor — auth key provided separately to `Device::connect`.
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

    /// Choose which tailnet names resolve on this device (see
    /// [`MagicDns`](tm_netstack::names::MagicDns)). Default
    /// `MagicDns::Full`: the FQDN, plus short names when the tailnet has
    /// MagicDNS on, and a tailnet name wins over the WiFi DNS server. The
    /// table is filled from the netmap, so it holds at most 8 peers and
    /// refreshes only when the control connection is re-established.
    pub fn with_magicdns(mut self, mode: tm_netstack::names::MagicDns) -> Self {
        self.magicdns = mode;
        self
    }

    /// Set the bring-up-only connect deadline (see `connect_timeout` field
    /// doc). The caller (e.g. the app's outer wrapper) is expected to use
    /// this INSTEAD OF an external `select!`/`timeout(..)` wrapped around
    /// `Device::connect(..)` — wrapping the whole `Device::connect` future in a
    /// dropping timeout races the streaming poll and, if it ever fires
    /// after bring-up, drops every actor and gets the ephemeral node
    /// garbage-collected off the tailnet. This deadline only ever bounds
    /// bring-up; the streaming poll after it is always unbounded.
    pub fn with_connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set how often the full netmap is re-fetched on the open control
    /// connection (default 10 minutes), so peers that joined, left or moved
    /// are picked up without a reconnect. `None` turns the timer off; a lookup
    /// of an unknown tailnet address still triggers a re-fetch, at most once
    /// every 2 minutes. Each re-fetch receives about 30-48 KB.
    pub fn with_refresh_interval(mut self, interval: Option<std::time::Duration>) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Node name announced to the control server, which derives the MagicDNS
    /// name from it (default `esp32c3`). A single lowercase DNS label.
    pub fn with_hostname(mut self, hostname: &'static str) -> Result<Self, Error> {
        if !tm_control::valid_hostname(hostname) {
            return Err(Error::InvalidConfig("hostname must be one lowercase DNS label (a-z, 0-9, '-')"));
        }
        self.hostname = hostname;
        Ok(self)
    }

    /// Platform description shown as the node's OS version in the admin
    /// console, e.g. `"ESP32-C3 r0.4 myapp 1.2.3"`. Printable ASCII, at most
    /// [`MAX_OS_VERSION`](tm_control::MAX_OS_VERSION) bytes.
    pub fn with_os_version(mut self, os_version: &str) -> Result<Self, Error> {
        self.os_version = tm_control::check_os_version(os_version).map_err(Error::InvalidConfig)?;
        Ok(self)
    }

    /// Services to advertise on the tailnet (e.g. `Service::tcp(80, "HTTP")`).
    /// They are informational: peers can see them, nothing enforces them.
    /// Sent with every control request, so a change needs a reconnect.
    pub fn with_services(mut self, services: &'static [tm_control::Service]) -> Result<Self, Error> {
        tm_control::check_services(services).map_err(Error::InvalidConfig)?;
        self.services = services;
        Ok(self)
    }

    pub(crate) async fn load_or_generate_keys(&self) -> Result<NodeState, Error> {
        // K2 (docs/stable-node-identity-plan.md): derive the node identity
        // deterministically from the chip's eFuse MAC via HKDF-SHA256, so
        // the SAME physical device always registers with the SAME identity
        // -- even across NVS erase and reflash, with nothing to persist.
        //
        // Root cause this replaces: this used to be `NodeState::generate()`,
        // called unconditionally on every `Device::connect()`. That's the
        // actual reason the node key churned every boot: the app layer
        // (tasmolike-rs's `TailscaleService::load_or_generate_keys`, which
        // reads/writes NVS) loaded or generated a key and logged "Loaded
        // existing Tailscale node keys" -- but never passed that key here.
        // `Device::connect` doesn't take a `NodeState` argument at all, so
        // the app's NVS round-trip was live but entirely disconnected from
        // what actually got registered with the control plane.
        let node_state = NodeState::derive_from_chip();
        tracing::info!(
            "Derived stable per-chip node identity, registering public key {}",
            node_state.node_key.public().to_hex()
        );
        Ok(node_state)
    }

    pub(crate) fn control_config(&self) -> tm_control::Config {
        tm_control::Config {
            control_host: self.control_host,
            control_port: self.control_port,
            control_pin:  self.control_pin,
            connect_timeout: self.connect_timeout,
            refresh_interval: self.refresh_interval,
            // Filled in by tm_runtime once (and if) its lan-direct UDP
            // socket is bound; the app config has no say in it.
            lan_udp_port: None,
            hostname: self.hostname,
            os_version: self.os_version.clone(),
            services: self.services,
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
            connect_timeout: None,
            refresh_interval: Some(tm_control::DEFAULT_REFRESH_INTERVAL),
            hostname:     "esp32c3",
            os_version:   heapless::String::new(),
            services:     &[],
            magicdns:     tm_netstack::names::MagicDns::default(),
        }
    }
}
