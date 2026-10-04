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
    pub(crate) dns_resolver: Option<tm_netstack::names::Resolver>,
    pub(crate) link_check: Option<fn() -> bool>,
    /// App-held random secret and generation for the node identity; see
    /// `with_identity_seed`. `None` falls back to the insecure MAC derivation.
    pub(crate) identity_seed: Option<([u8; 32], u32)>,
    /// Node key rotation counter; see `with_node_rotation`.
    pub(crate) node_rotation: u32,
    /// Rotation being renewed from; see `with_previous_node_rotation`.
    pub(crate) previous_node_rotation: Option<u32>,
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
        let now = tm_time::unix_secs();
        // pre-2023 => ESP-IDF boot clock, SNTP not done yet; skip expiry check until synced
        let now = now.filter(|&s| s > 1_700_000_000);

        let pin = tm_control::pin::verify_pin_hex(blob_hex, &tm_control::pin::PIN_VERIFY_KEY, now)
            .map_err(Error::Pin)?;
        self.control_pin = pin;
        Ok(self)
    }

    /// Use the control server's Noise public key directly, as fetched by the
    /// application (for example by the user's browser from
    /// `https://controlplane.tailscale.com/key?v=71`, whose TLS the browser
    /// checks). Unlike `with_control_pin_hex` nothing is signed here: whoever
    /// supplies the key is trusted to have obtained it over an authenticated
    /// channel. A wrong key does not connect; `Device::connect` then fails
    /// with `ControlError::ControlKeyRejected`.
    pub fn with_control_key(mut self, key: [u8; 32]) -> Self {
        self.control_pin = key;
        self
    }

    /// Supply the app's random 32-byte identity secret (generated on first
    /// boot and kept in the app's NVS) and a generation counter (use 0
    /// by default). The node, machine and disco keys are derived from the
    /// secret with the chip MAC as a per-device salt, so the public MAC alone
    /// reveals nothing. Bumping `generation` yields entirely new keys. Without
    /// this call the keys come from the MAC alone, which anyone on the LAN can
    /// compute, so apps should always call it.
    pub fn with_identity_seed(mut self, secret: [u8; 32], generation: u32) -> Self {
        self.identity_seed = Some((secret, generation));
        self
    }

    /// Renew the node key without becoming a new device. The counter changes
    /// only the node and disco keys; the machine key (and so the node entry,
    /// name and IP that control ties to it) stays. Rotation 0, the default,
    /// derives the same keys as before this existed. Needs
    /// `with_identity_seed`: the MAC-only fallback has no rotation.
    pub fn with_node_rotation(mut self, rotation: u32) -> Self {
        self.node_rotation = rotation;
        self
    }

    /// Mark this connect as a renewal from node rotation `prev` (the one the
    /// device registered with so far). Registration then sends the public key
    /// of that rotation as `OldNodeKey`, so control replaces the key on the
    /// existing node. Pair it with `with_node_rotation` set to the new counter.
    pub fn with_previous_node_rotation(mut self, prev: u32) -> Self {
        self.previous_node_rotation = Some(prev);
        self
    }

    /// Choose which tailnet names resolve on this device (see
    /// [`MagicDns`](tm_netstack::names::MagicDns)). Default
    /// `MagicDns::Full`: the FQDN, plus short names when the tailnet has
    /// MagicDNS on, and a tailnet name wins over the WiFi DNS server. The
    /// table is filled from the netmap, so it holds at most 8 peers and
    /// is rebuilt from every netmap snapshot (the boot map, then each periodic
    /// or on-miss re-fetch, see `with_refresh_interval`).
    pub fn with_magicdns(mut self, mode: tm_netstack::names::MagicDns) -> Self {
        self.magicdns = mode;
        self
    }

    /// Add an app resolver to the name lookup chain: MagicDNS first, then this,
    /// then the normal DNS server. It returns a
    /// [`Resolution`](tm_netstack::names::Resolution): an address, `NotFound`
    /// (the name is its own, so the lookup fails without asking the WiFi DNS
    /// server, as for an unanswered `.local` name), or `Pass`. It runs in the
    /// thread that called `getaddrinfo`, so it may block (keep a timeout) but
    /// cannot `.await`. Default: none.
    pub fn with_dns_resolver(mut self, resolver: tm_netstack::names::Resolver) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Tell tailmicro whether the network link is up. While `check` returns
    /// `false`, DERP and control park instead of redialing, which saves heap
    /// and CPU on a device whose WiFi is down, and they resume (with a fresh
    /// backoff) when it returns `true`. It runs about once a second while
    /// parked, so keep it cheap and non-blocking. Default: the link is
    /// assumed up.
    pub fn with_link_check(mut self, check: fn() -> bool) -> Self {
        self.link_check = Some(check);
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

    /// Public node key of `previous_node_rotation`, if a renewal is set and
    /// the identity seed exists (the MAC-only fallback has no rotation).
    fn old_node_key(&self) -> Option<tm_keys::NodePublicKey> {
        let prev = self.previous_node_rotation?;
        let (secret, generation) = self.identity_seed.as_ref()?;
        let st = NodeState::derive_from_secret_rotated(secret, &tm_keys::chip_mac(), *generation, prev);
        Some(st.node_key.public())
    }

    fn node_state(&self) -> NodeState {
        match &self.identity_seed {
            Some((secret, generation)) => {
                NodeState::derive_from_secret_rotated(
                    secret, &tm_keys::chip_mac(), *generation, self.node_rotation,
                )
            }
            None => {
                tracing::warn!(
                    "No identity seed set: node keys derive from the public chip MAC and can be forged from the LAN; call Config::with_identity_seed"
                );
                NodeState::derive_from_chip()
            }
        }
    }

    pub(crate) async fn load_or_generate_keys(&self) -> Result<NodeState, Error> {
        // The app used to load keys from NVS that never reached here, which
        // churned the node key every boot; the identity is now derived
        // deterministically (docs/stable-node-identity-plan.md).
        let node_state = self.node_state();
        tracing::info!(
            "Derived stable node identity, registering public key {}",
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
            old_node_key: self.old_node_key(),
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
            dns_resolver: None,
            link_check:   None,
            identity_seed: None,
            node_rotation: 0,
            previous_node_rotation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tm_netstack::names::Resolution;

    #[test]
    fn control_key_is_stored() {
        let c = Config::default();
        assert_eq!(c.control_pin, [0u8; 32]);
        let c = c.with_control_key([7u8; 32]);
        assert_eq!(c.control_pin, [7u8; 32]);
    }

    #[test]
    fn identity_seed_replaces_the_mac_only_default() {
        let key = |c: &Config| *c.node_state().node_key.public().as_bytes();
        let c = Config::default();
        let fallback = key(&c);
        let c = c.with_identity_seed([5u8; 32], 0);
        assert_eq!(c.identity_seed, Some(([5u8; 32], 0)));
        let g0 = key(&c);
        assert_ne!(g0, fallback);
        assert_eq!(g0, key(&Config::default().with_identity_seed([5u8; 32], 0)));
        assert_ne!(g0, key(&Config::default().with_identity_seed([5u8; 32], 1)));
    }

    #[test]
    fn node_rotation_changes_node_and_disco_but_not_machine_key() {
        let keys = |c: &Config| {
            let n = c.node_state();
            [*n.node_key.public().as_bytes(), *n.machine_key.public().as_bytes(),
             *n.disco_key.public().as_bytes()]
        };
        let base = Config::default().with_identity_seed([5u8; 32], 1);
        let r0 = keys(&base);
        // Rotation 0 is the default and must equal what the device derived before.
        assert_eq!(r0, keys(&Config::default().with_identity_seed([5u8; 32], 1).with_node_rotation(0)));
        let r1 = keys(&Config::default().with_identity_seed([5u8; 32], 1).with_node_rotation(1));
        assert_ne!(r0[0], r1[0]);
        assert_ne!(r0[2], r1[2]);
        assert_eq!(r0[1], r1[1]);
        let g2 = keys(&Config::default().with_identity_seed([5u8; 32], 2).with_node_rotation(1));
        assert!(r1.iter().zip(&g2).all(|(a, b)| a != b));
    }

    #[test]
    fn previous_rotation_names_the_old_node_key_in_the_control_config() {
        let seeded = || Config::default().with_identity_seed([5u8; 32], 1);
        assert!(seeded().control_config().old_node_key.is_none());
        let pub_of = |c: &Config| c.node_state().node_key.public();
        let old = pub_of(&seeded());
        let renewing = seeded().with_node_rotation(1).with_previous_node_rotation(0);
        let cc = renewing.control_config();
        assert!(cc.old_node_key == Some(old.clone()));
        assert!(pub_of(&renewing) != old, "the new key differs from the old one");
        // A chain: rotation 2 replaces rotation 1.
        let r1 = pub_of(&seeded().with_node_rotation(1));
        let cc = seeded().with_node_rotation(2).with_previous_node_rotation(1).control_config();
        assert!(cc.old_node_key == Some(r1));
        // No seed, no rotation.
        assert!(Config::default().with_previous_node_rotation(0).control_config().old_node_key.is_none());
    }

    #[test]
    fn link_check_and_dns_resolver_default_to_none_and_are_stored() {
        let c = Config::default();
        assert!(c.link_check.is_none() && c.dns_resolver.is_none());
        let c = c.with_link_check(|| false).with_dns_resolver(|_| Resolution::Pass);
        assert_eq!(c.link_check.map(|f| f()), Some(false));
        assert_eq!(c.dns_resolver.map(|f| f("x")), Some(Resolution::Pass));
    }
}
