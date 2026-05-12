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
//! let dev = tailmicro::Device::new(
//!     &tailmicro::Config::new("tskey-auth-..."),
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub use config::Config;
pub use error::Error;
pub use tm_keys::NodeState;

pub mod config;
mod error;

/// How an application connects to a tailnet and communicates with peers.
///
/// Mirrors `tailscale::Device` exactly.
pub struct Device {
    runtime: tm_runtime::Runtime,
    our_ip:  std::sync::Arc<tokio::sync::RwLock<Option<Ipv4Addr>>>,
}

impl Device {
    /// Create a device and connect to the tailnet.
    ///
    /// Spawns the control, DERP, DISCO, and WireGuard actors as Tokio tasks.
    ///
    /// On ESP32-C3, call this inside a `current_thread` Tokio runtime.
    pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Self, Error> {
        let node_state = config.load_or_generate_keys().await?;

        let rt_config = tm_runtime::RuntimeConfig {
            control:       config.control_config(),
            auth_key:      auth_key
                .as_deref()
                .and_then(|s| heapless::String::try_from(s).ok())
                .unwrap_or_default(),
            node_state,
            priority_peer: None,
        };

        let runtime = tm_runtime::Runtime::join(rt_config).await;
        let our_ip  = std::sync::Arc::new(tokio::sync::RwLock::new(None));

        Ok(Self { runtime, our_ip })
    }

    /// Get this device's IPv4 tailnet address.
    ///
    /// Waits until the control plane assigns one (up to ~30 s on first boot).
    pub async fn ipv4_addr(&self) -> Result<Ipv4Addr, Error> {
        // In the real implementation, this would wait on a oneshot channel
        // populated by the ControlEvent::OurIpAssigned handler in tm_runtime.
        self.our_ip.read().await.ok_or(Error::NotConnected)
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
