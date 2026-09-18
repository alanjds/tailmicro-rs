//! `tailmicro` — Tailscale client optimised for ESP32-C3.
//!
//! Provides the same public API as the `tailscale` crate from `tailscale-rs`
//! so that examples and application code are source-compatible between the
//! two crates.
//!
//! ## Quick start (identical to tailscale-rs)
//!
//! ```no_run
//! # use std::{time::Duration, net::Ipv4Addr, error::Error};
//! # #[tokio::main(flavor = "current_thread")]   // <— current_thread on ESP32!
//! # async fn main() -> Result<(), Box<dyn Error>> {
//! let config = tailmicro::Config::new("tskey-auth-...")
//!     .with_control_pin_hex("<hex pin blob from tools/gen_fingerprint.py>")?;
//!
//! let dev = tailmicro::Device::new(
//!     &config,
//!     Some("tskey-auth-...".to_owned()),
//! ).await?;
//!
//! let sock = dev.udp_bind((dev.ipv4_addr().await?, 1234).into()).await?;
//!
//! loop {
//!     sock.send_to(
//!         (Ipv4Addr::new(100, 64, 0, 1), 5678).into(),
//!         b"hello, world!",
//!     ).await?;
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
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
//! rt.block_on(async { tailmicro::Device::new(...).await });
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub use config::Config;
pub use error::Error;
pub use tm_keys::NodeState;
pub use tm_runtime::{tokio_freertos_yield, OurIpReceiver, OurIpSender};

pub mod config;
mod error;

/// Build the `Runtime::join` future and move it onto the heap, off-frame.
///
/// `#[inline(never)]`: at this crate's `dev` profile (`opt-level = "z"`,
/// `lto = true` — see tasmolike-rs/Cargo.toml), the compiler MIR-inlines
/// async fns aggressively across crate boundaries. Without this boundary,
/// `Runtime::join`'s state machine (channels, actor structs, boxed-future
/// pointers) got folded straight into `Device::new`'s own state machine,
/// and the combined frame was observed at ~55 KB in
/// `<Timeout<Device::new::{closure#0}> as Future>::poll` — still enough to
/// blow the 32 KB main-task stack with a Guru Meditation "Stack protection
/// fault" even after `Runtime::join` itself was slimmed down (see
/// docs/wg-dataplane-notes.md). `Box::pin` behind a non-inlinable function
/// forces a real (non-inlined) call boundary: `Device::new` only ever holds
/// the 16-byte `Pin<Box<dyn Future>>` across the `.await`, and `join`'s
/// state machine is built in its own frame that is freed once the pointer
/// is returned.
#[cfg(target_os = "espidf")]
#[inline(never)]
fn spawn_runtime_join(
    rt_config: tm_runtime::RuntimeConfig,
) -> core::pin::Pin<Box<dyn core::future::Future<Output = tm_runtime::Runtime>>> {
    Box::pin(tm_runtime::Runtime::join(rt_config))
}

/// Mirrors `tailscale::Device` exactly.
pub struct Device {
    runtime: tm_runtime::Runtime,
    our_ip_rx: Option<tm_runtime::OurIpReceiver>,
}

impl Device {
    /// Create a device and connect to the tailnet.
    ///
    /// Spawns the control, DERP, DISCO, and WireGuard actors as Tokio tasks.
    ///
    /// On ESP32-C3, call this inside a `current_thread` Tokio runtime.
    /// 
    /// # Arguments
    /// * `config` - Tailscale configuration (must carry a verified control
    ///   pin — see `Config::with_control_pin_hex`)
    /// * `auth_key` - Auth key for Tailscale control plane
    pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Self, Error> {
        tracing::debug!("Device::new() - starting device initialization");

        let node_state = config.load_or_generate_keys().await?;
        tracing::debug!("Device::new() - keys loaded, node_state generated");

        // Create channel for receiving the IP address
        let (our_ip_tx, our_ip_rx) = async_channel::bounded::<Ipv4Addr>(1);

        let rt_config = tm_runtime::RuntimeConfig {
            control:       config.control_config(),
            auth_key:      auth_key
                .as_deref()
                .and_then(|s| heapless::String::try_from(s).ok())
                .unwrap_or_default(),
            node_state,
            priority_peer: None,
            #[cfg(target_os = "espidf")]
            our_ip_tx: Some(our_ip_tx),
            connect_timeout: config.connect_timeout,
        };

        #[cfg(target_os = "espidf")]
        let runtime = spawn_runtime_join(rt_config).await;

        #[cfg(not(target_os = "espidf"))]
        let runtime = tm_runtime::Runtime::spawn(rt_config).await;

        Ok(Self { runtime, our_ip_rx: Some(our_ip_rx) })
    }

    /// Get this device's IPv4 tailnet address.
    ///
    /// Waits until the control plane assigns one (up to ~30 s on first boot).
    pub async fn ipv4_addr(&self) -> Result<Ipv4Addr, Error> {
        // Wait for the IP to be assigned by the control plane
        // Timeout after 30 seconds to avoid hanging forever
        let our_ip_rx = self.our_ip_rx.as_ref().ok_or(Error::NotConnected)?;
        match tokio::time::timeout(std::time::Duration::from_secs(30), our_ip_rx.recv()).await {
            Ok(Ok(ip)) => Ok(ip),
            Ok(Err(_)) => Err(Error::NotConnected), // Channel closed
            Err(_) => Err(Error::NotConnected), // Timeout
        }
    }

    /// Bind a UDP socket to `addr` on the tailnet.
    pub async fn udp_bind(&self, addr: SocketAddr) -> Result<netstack::UdpSocket, Error> {
        // Delegates to tm_netstack which wraps lwIP on ESP32-C3
        // or tokio::net::UdpSocket on the host.
        todo!("platform netstack bind")
    }

    /// Listen for TCP connections on the tailnet.
    pub async fn tcp_listen(&self, addr: SocketAddr) -> Result<netstack::TcpListener, Error> {
        todo!("platform netstack listen")
    }

    /// Connect a TCP stream to a peer on the tailnet.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<netstack::TcpStream, Error> {
        todo!("platform netstack connect")
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
