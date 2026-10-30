//! `tailmicro` — Tailscale client optimised for ESP32-C3.
//!
//! Provides the same public API as the `tailscale` crate from `tailscale-rs`
//! so that examples and application code are source-compatible between the
//! two crates.
//!
//! ## Quick start (identical to tailscale-rs)
//!
//! ```no_run
//! # use std::error::Error;
//! # #[tokio::main(flavor = "current_thread")]   // <— current_thread on ESP32!
//! # async fn main() -> Result<(), Box<dyn Error>> {
//! let config = tailmicro::Config::new("tskey-auth-...")
//!     .with_control_pin_hex("<hex pin blob from tools/gen_fingerprint.py>")?;
//!
//! let (dev, driver) = tailmicro::Device::connect(
//!     &config,
//!     Some("tskey-auth-...".to_owned()),
//! ).await?;
//! println!("tailnet address: {}", dev.ipv4_addr());
//!
//! // `driver` runs the data plane: keep polling it alongside your own work.
//! tokio::join!(driver, async { /* your application */ });
//! # Ok(())
//! # }
//! ```
//!
//! ## ESP32-C3 runtime note
//!
//! Always use `current_thread` runtime on the ESP32-C3:
//!
//! ```rust,ignore
//! // In your esp-idf main:
//! let rt = tokio::runtime::Builder::new_current_thread()
//!     .enable_all()
//!     .build()?;
//! rt.block_on(async { tailmicro::Device::connect(...).await });
//! ```
//!
//! The `#[tokio::main]` macro defaults to `multi_thread` which spawns a
//! thread pool — fatal on a 400 KB SRAM device.
//!
//! ## Tracing to ESP-IDF logging
//!
//! On ESP-IDF, `tracing` crate with `features = ["log"]` bridges to the `log` crate.
//! The bridge is initialized by `EspLogger::initialize_default()` which is called
//! in the main application before any tailmicro code runs.

use std::net::Ipv4Addr;
use std::time::Duration;

pub use config::Config;
pub use error::Error;
pub use tm_netstack::names::{MagicDns, Resolution, Resolver};
pub use tm_control::{Service, ServiceProto, MAX_SERVICES, MAX_SERVICE_DESC};
pub use tm_control::login::{control_key_rejected, login_url, refusal, LoginUrl, Refusal, LOGIN_URL_MAX};
pub use tm_keys::NodeState;
pub use tm_runtime::{tokio_freertos_yield, OurIpReceiver, OurIpSender};

/// The data-plane future returned by [`Device::connect`]; the same type as
/// `tm_runtime::Driver`, re-exported so apps need not depend on `tm_runtime`
/// just to name it.
pub use tm_runtime::Driver;

pub mod config;
mod error;

/// Build the `Runtime::connect` future and move it onto the heap, off-frame.
///
/// `#[inline(never)]`: at this crate's `dev` profile (`opt-level = "z"`,
/// `lto = true`) the compiler MIR-inlines async fns across crate boundaries,
/// which folded `Runtime::connect`'s state machine (channels, actor structs,
/// boxed-future pointers) into the caller's and overflowed the 32 KB main
/// task stack (see docs/wg-dataplane-notes.md). A non-inlinable `Box::pin`
/// boundary leaves the caller holding only a 16-byte `Pin<Box<dyn Future>>`.
#[cfg(target_os = "espidf")]
#[inline(never)]
fn spawn_runtime_connect(
    rt_config: tm_runtime::RuntimeConfig,
) -> core::pin::Pin<Box<dyn core::future::Future<
        Output = Result<(tm_runtime::Runtime, Ipv4Addr, tm_runtime::Driver), tm_runtime::ConnectError>,
    >>>
{
    Box::pin(tm_runtime::Runtime::connect(rt_config))
}

/// Mirrors `tailscale::Device` exactly.
pub struct Device {
    runtime: tm_runtime::Runtime,
    our_ip: Ipv4Addr,
}

impl Device {
    /// Connect to the tailnet, returning as soon as the control plane
    /// assigns a tailnet IP (`ControlEvent::OurIpAssigned`) — bring-up is
    /// bounded internally by `Config::connect_timeout` (see
    /// `Config::with_connect_timeout`), so this never hangs past that
    /// deadline. `device.ipv4_addr()`/`is_connected()` work immediately on
    /// the returned `Device`.
    ///
    /// Hands back a `Driver` future alongside `Device`: the data plane
    /// (control, DERP, disco, WireGuard actors, including the deliberately
    /// unbounded streaming keepalive poll that keeps the node marked
    /// online) is NOT running unless `Driver` keeps being polled. The
    /// caller MUST fold it into its own `tokio::join!`/`tokio::try_join!`
    /// alongside whatever else it needs to run concurrently (e.g. an HTTP
    /// server) — never `.await` it alone (it then never returns, by
    /// design) and never wrap it in an external `timeout`/`select!` that
    /// could drop it (that reproduces the ephemeral-node-GC bug fixed by
    /// this contract change — see docs/wg-dataplane-notes.md
    /// "Readiness-decoupled connect handle").
    ///
    /// # Arguments
    /// * `config` - Tailscale configuration (must carry a verified control
    ///   pin — see `Config::with_control_pin_hex`)
    /// * `auth_key` - Auth key for Tailscale control plane. `None` or empty
    ///   selects interactive login: control answers with a URL, readable with
    ///   [`login_url`] from another task while this call stays pending (no
    ///   `connect_timeout` applies while it waits for the user), and the call
    ///   returns once the user has approved the device. An already-authorized
    ///   node needs neither a key nor a login.
    ///
    /// Fails with `Error::Control(ControlError::ControlKeyRejected)` when the
    /// pinned control key does not match the server, with
    /// `Error::Control(ControlError::LoginRequired)` when control wants a login
    /// and `Config::with_login_allowed(false)` forbids waiting for it, and with
    /// `Error::Control(ControlError::NodeKeyExpired)` when control says the node
    /// key expired and offers no login (renew it with `with_node_rotation` and
    /// `with_previous_node_rotation`, login allowed).
    pub async fn connect(
        config: &Config,
        auth_key: Option<String>,
    ) -> Result<(Self, Driver), Error> {
        tracing::debug!("Device::connect() - starting device initialization");

        tm_netstack::names::set_mode(config.magicdns);
        tm_netstack::names::set_resolver(config.dns_resolver);
        tm_buf::link::set_check(config.link_check);
        let node_state = config.load_or_generate_keys().await?;
        tracing::debug!("Device::connect() - keys loaded, node_state generated");

        let rt_config = tm_runtime::RuntimeConfig {
            control:       config.control_config(),
            auth_key:      auth_key
                .as_deref()
                .and_then(|s| heapless::String::try_from(s).ok())
                .unwrap_or_default(),
            node_state,
            priority_peer: None,
            // `Runtime::connect` owns and overwrites the readiness channel
            // itself (it races `Driver` against it internally) — nothing
            // to set here.
            our_ip_tx: None,
            connect_timeout: config.connect_timeout,
        };

        #[cfg(target_os = "espidf")]
        let result = spawn_runtime_connect(rt_config).await;

        #[cfg(not(target_os = "espidf"))]
        let result = tm_runtime::Runtime::connect(rt_config).await;

        let (runtime, our_ip, driver) = result.map_err(|_| {
            // The runtime only reports that bring-up failed; the control actor
            // leaves the reason of a key mismatch in `tm_control::login`.
            if control_key_rejected() {
                Error::Control(tm_control::ControlError::ControlKeyRejected)
            } else {
                match refusal() {
                    Some(Refusal::LoginRequired) => Error::Control(tm_control::ControlError::LoginRequired),
                    Some(Refusal::NodeKeyExpired) => Error::Control(tm_control::ControlError::NodeKeyExpired),
                    None => Error::NotConnected,
                }
            }
        })?;
        Ok((Self { runtime, our_ip }, driver))
    }

    /// Get this device's IPv4 tailnet address.
    ///
    /// Available immediately: `Device` (from `Device::connect`) only ever
    /// exists once the control plane has assigned one.
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.our_ip
    }

    /// Resolve a tailnet name (`bospill` or `bospill.<tailnet>.ts.net`) to
    /// its tailnet IPv4, from the netmap snapshot taken at the last control
    /// connect. `None` means the name is not a known tailnet name under the
    /// configured [`MagicDns`] mode; use your normal resolver for it. On the
    /// ESP32 the same table is consulted by lwIP's `getaddrinfo`, so
    /// `TcpStream::connect("bospill:8080")` needs no call to this.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        tm_netstack::names::resolve(name)
    }

    /// When this node's key expires, in unix seconds, as of the last netmap.
    /// `None` means it never expires (key expiry disabled for the node), or
    /// no netmap has been seen yet. The key is renewed by logging in again;
    /// the value follows later netmaps, so renewing in the admin console
    /// shows up without reconnecting.
    pub fn node_key_expiry(&self) -> Option<i64> {
        tm_control::selfnode::key_expiry()
    }

    /// The tailnet suffix of this node's name (`tailnet-xyz.ts.net`, no dots at
    /// the ends, case as control sent it), so an app can show the FQDN as
    /// `<label>.<suffix>`. A copy of the one stored by tailmicro, from the
    /// last netmap; empty when not yet known, when control names nodes with a
    /// bare label, or when it is longer than `MAX_NAME_SUFFIX` (48 bytes), as a
    /// longer suffix is dropped whole rather than truncated.
    pub fn tailnet_suffix(&self) -> heapless::String<{ tm_control::MAX_NAME_SUFFIX }> {
        tm_netstack::names::suffix()
    }

    /// Whether this device is connected to the tailnet.
    ///
    /// Always `true` for a `Device` obtained from `Device::connect` — its
    /// existence already implies `OurIpAssigned` fired. Whether the data
    /// plane is still actually running depends on whether the caller is
    /// still polling the paired `Driver` future.
    pub fn is_connected(&self) -> bool {
        self.our_ip != Ipv4Addr::UNSPECIFIED
    }

    /// Gracefully shut down all actors.
    pub async fn shutdown(self, _timeout: Option<Duration>) -> bool {
        true
    }
}

/// Socket types — same names and methods as `tailscale::netstack`.
pub mod netstack {
    pub use tm_netstack::{UdpSocket, TcpStream, TcpListener, NetError as Error};
}

/// Key types — same names as `tailscale::keys`.
pub mod keys {
    pub use tm_keys::{
        DiscoPrivateKey, DiscoPublicKey,
        MachinePrivateKey, MachinePublicKey,
        NodePrivateKey, NodePublicKey,
        NodeState,
    };
}

#[cfg(test)]
mod driver_reexport {
    /// `tailmicro::Driver` is the very type `Device::connect` hands back, so
    /// apps can swap `tm_runtime::Driver` for it with no other change.
    #[test]
    fn driver_is_the_runtime_driver() {
        fn same(d: tm_runtime::Driver) -> crate::Driver {
            d
        }
        let _ = same;
    }
}
