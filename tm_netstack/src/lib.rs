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

/// The tailnet point-to-point lwIP netif (plan (a) --
/// `docs/tailnet-http-lwip-netif-plan.md`): gives the on-device lwIP stack a
/// netif for the node's tailnet IP so the existing `0.0.0.0:80` HTTP server
/// becomes reachable there with no application change.
pub mod tailnet;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    Io,
    AddrInUse,
    NotConnected,
    /// A non-blocking send found the socket's buffer full. For UDP this is
    /// a dropped datagram, not a failure of the socket.
    WouldBlock,
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::AddrInUse => NetError::AddrInUse,
            std::io::ErrorKind::WouldBlock => NetError::WouldBlock,
            std::io::ErrorKind::NotConnected => NetError::NotConnected,
            _ => NetError::Io,
        }
    }
}

// ── UdpSocket ─────────────────────────────────────────────────────────────────

/// A UDP socket: a thin wrapper over `tokio::net::UdpSocket` on both targets.
///
/// On ESP-IDF tokio's UDP goes through mio's `target_os = "espidf"` socket
/// path onto lwIP BSD sockets, exactly like the `TcpStream`s the control
/// plane and DERP already use (LAN-direct-path plan, Step 2).
pub struct UdpSocket {
    sock: tokio::net::UdpSocket,
}

impl UdpSocket {
    /// Bind synchronously and register with the current tokio reactor.
    ///
    /// Synchronous (std bind + `from_std`) rather than `tokio::net::UdpSocket::
    /// bind(..).await` so a caller can do it from an `#[inline(never)]` plain
    /// function at a chosen moment (before the DERP TLS handshake, per the
    /// plan's heap-ordering rule) without growing its own async frame. Must
    /// be called from inside a tokio runtime.
    pub fn bind_sync(addr: SocketAddr) -> Result<Self, NetError> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        let sock = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Self { sock })
    }

    /// Async bind (host convenience; same semantics as [`Self::bind_sync`]).
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Self { sock })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.sock.local_addr()?)
    }

    /// Send `buf` to `target`.
    pub async fn send_to(&self, target: SocketAddr, buf: &[u8]) -> Result<(), NetError> {
        self.sock.send_to(buf, target).await?;
        Ok(())
    }

    /// Wait until the socket is writable. tokio's `try_*` calls consult the
    /// reactor's cached readiness, which is unknown (so `WouldBlock`) until
    /// the reactor has reported the socket writable at least once; awaiting
    /// this once after bind primes it.
    pub async fn writable(&self) -> Result<(), NetError> {
        self.sock.writable().await?;
        Ok(())
    }

    /// Send without ever awaiting. UDP is best-effort: a full socket buffer
    /// is `Err(NetError::WouldBlock)`, i.e. a dropped datagram, and the
    /// caller decides whether to fall back (e.g. to DERP). Also
    /// `WouldBlock` before the reactor first reports the socket writable
    /// (see [`Self::writable`]).
    pub fn try_send_to(&self, target: SocketAddr, buf: &[u8]) -> Result<(), NetError> {
        self.sock.try_send_to(buf, target)?;
        Ok(())
    }

    /// Receive a datagram into `buf`.  Returns `(bytes_read, sender_addr)`.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        Ok(self.sock.recv_from(buf).await?)
    }
}

/// Underlay-LAN direct UDP path support (LAN-direct-path plan, Step 2).
pub mod lan_udp;

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
