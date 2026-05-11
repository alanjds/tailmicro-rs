//! Userspace socket abstraction.
//!
//! On ESP32-C3 we do NOT use smoltcp (which tailscale-rs uses via
//! ts_netstack_smoltcp).  The ESP-IDF already provides lwIP, and
//! WireGuard-lwip injects decrypted packets directly into the lwIP pipeline.
//! Adding smoltcp on top would waste ~20 KB of code and create a redundant
//! TCP/IP stack.
//!
//! Instead, this module wraps `esp-idf-svc`'s async socket API behind the
//! same `UdpSocket` / `TcpStream` / `TcpListener` types that tailscale-rs
//! exposes, keeping examples source-compatible.
//!
//! On the host (for tests), we delegate to `tokio::net`.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NetError {
    Io,
    AddrInUse,
    NotConnected,
}

// ── UdpSocket ─────────────────────────────────────────────────────────────────

/// A UDP socket bound to a tailnet address.
///
/// API mirrors `tailscale::netstack::UdpSocket` exactly so examples compile
/// against both tailmicro and tailscale-rs unchanged.
pub struct UdpSocket {
    inner: Inner,
}

#[cfg(not(target_os = "espidf"))]
struct Inner { sock: tokio::net::UdpSocket }

#[cfg(target_os = "espidf")]
struct Inner {
    // esp-idf-svc async UDP socket handle
    // Placeholder — concrete type from esp-idf-svc::io::asynch
    _marker: core::marker::PhantomData<()>,
}

impl UdpSocket {
    /// Send `buf` to `target`.
    pub async fn send_to(&self, target: SocketAddr, buf: &[u8]) -> Result<(), NetError> {
        #[cfg(not(target_os = "espidf"))]
        self.inner.sock.send_to(buf, target).await.map(|_| ()).map_err(|_| NetError::Io)?;
        Ok(())
    }

    /// Receive a datagram into `buf`.  Returns `(bytes_read, sender_addr)`.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        #[cfg(not(target_os = "espidf"))]
        return self.inner.sock.recv_from(buf).await.map_err(|_| NetError::Io);
        #[cfg(target_os = "espidf")]
        Err(NetError::Io)
    }
}

// ── TcpStream ─────────────────────────────────────────────────────────────────

pub struct TcpStream {
    #[cfg(not(target_os = "espidf"))]
    inner: tokio::net::TcpStream,
}

impl TcpStream {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        #[cfg(not(target_os = "espidf"))]
        {
            use tokio::io::AsyncReadExt;
            self.inner.read(buf).await.map_err(|_| NetError::Io)
        }
        #[cfg(target_os = "espidf")]
        Err(NetError::Io)
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), NetError> {
        #[cfg(not(target_os = "espidf"))]
        {
            use tokio::io::AsyncWriteExt;
            self.inner.write_all(buf).await.map_err(|_| NetError::Io)
        }
        #[cfg(target_os = "espidf")]
        Err(NetError::Io)
    }
}

// ── TcpListener ───────────────────────────────────────────────────────────────

pub struct TcpListener {
    #[cfg(not(target_os = "espidf"))]
    inner: tokio::net::TcpListener,
}

impl TcpListener {
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), NetError> {
        #[cfg(not(target_os = "espidf"))]
        {
            let (stream, addr) = self.inner.accept().await.map_err(|_| NetError::Io)?;
            Ok((TcpStream { inner: stream }, addr))
        }
        #[cfg(target_os = "espidf")]
        Err(NetError::Io)
    }
}
