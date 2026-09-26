//! Tailnet point-to-point (tun-style) lwIP netif.
//!
//! Gives the on-device lwIP stack a raw-IP netif that owns the node's
//! tailnet IPv4 address (`our_ip`, a `100.64.0.0/10` CGNAT address assigned
//! by the control plane). Once this netif is up, the app's existing
//! `0.0.0.0:80` tokio HTTP server -- which on ESP-IDF is backed by lwIP BSD
//! sockets -- starts accepting connections on the tailnet IP too, with zero
//! application-level change. See
//! `tailmicro-rs/docs/tailnet-http-lwip-netif-plan.md` (plan (a)) for the
//! full design and `docs/wg-dataplane-notes.md` for the surrounding
//! heap/stack constraints this module is written against.
//!
//! ## Threading (read this before touching `device.rs`)
//!
//! lwIP's core (PCBs, netif list, ...) is NOT thread-safe against concurrent
//! access from an arbitrary thread; on ESP-IDF it is single-owned by the
//! "tcpip" task. Two different techniques are used here depending on
//! direction:
//!
//! - **Inbound** (tokio task -> lwIP): `tcpip_input()` already does the
//!   thread hand-off internally (it posts the pbuf into the tcpip task's
//!   mailbox and returns immediately), so `inject_inbound` can be called
//!   directly from the tokio task.
//! - **Netif lifecycle** (`bring_up`/`set_address`, tokio task -> lwIP):
//!   `netif_add`/`netif_set_addr`/etc. are plain (non-thread-safe) lwIP
//!   calls, so they are wrapped in `tcpip_callback()` and the calling tokio
//!   task blocks (via a `std::sync::mpsc` rendezvous) until the tcpip task
//!   has run them. This is a one-shot, boot/reconnect-time operation (not
//!   per-packet), so a short synchronous wait on the single-threaded tokio
//!   runtime's one OS thread is an acceptable trade -- unlike a per-packet
//!   path, which would stall every other actor.
//! - **Outbound** (lwIP's tcpip thread -> tokio task): the netif `output`
//!   callback runs ON the tcpip thread and must never block it. It copies
//!   the packet into a plain buffer and hands it to the tokio side via
//!   `OutboundSender::try_send` (a synchronous, non-blocking, thread-safe
//!   call per `async_channel`'s API -- it does not require an executor).

/// Capacity of the outbound packet buffer: the workspace-wide channel packet
/// buffer capacity (`tm_buf::PKT_CAP`, 1532), shared by every crate that
/// moves packets between actors so the event router can forward buffers
/// instead of copying them into differently-sized ones.
pub const MAX_PACKET: usize = tm_buf::PKT_CAP;

/// Tailnet CIDR block (`100.64.0.0/10`, RFC 6598 CGNAT space) that Tailscale
/// assigns node addresses from. The netif's netmask is set to this block's
/// prefix (`255.192.0.0`) rather than `/32`, so that lwIP's `ip4_route`
/// network-match test (`dest & mask == our_ip & mask`) sends ALL tailnet
/// peer addresses out this one netif -- not just traffic to our own address.
/// See `ip4_route()` in `esp-idf/components/lwip/lwip/src/core/ipv4/ip4.c`.
pub const TAILNET_NETMASK: [u8; 4] = [255, 192, 0, 0];

/// lwIP netif MTU. `1500 - WireGuard transport overhead (32B header+tag) -
/// DERP framing headroom`, matching `tm_derp::MAX_DERP_PAYLOAD = 1500 + 32`
/// and rounded down for headroom so lwIP never advertises a TCP MSS that
/// would force IP fragmentation across the tunnel. See the plan's MTU note.
pub const MTU: u16 = 1380;

#[derive(Debug)]
pub enum TailnetError {
    /// This build target has no on-device lwIP to inject into (host build).
    NotSupported,
    /// An operation that requires the netif to be up was attempted before
    /// `bring_up` succeeded.
    NotUp,
    /// A raw lwIP call returned this non-`ERR_OK` `err_t`.
    Lwip(i8),
}

/// A raw IPv4 packet captured from the netif's `output` callback (i.e. lwIP
/// wants to send it out the tailnet interface), destined for whatever
/// `tm_runtime`'s dest-IP -> peer-node-key lookup decides to do with it
/// (normally `WgCmd::SendData`).
///
/// `data` is boxed for the same reason every other multi-KB inter-actor
/// message payload in this workspace is boxed (see `tm_wg::WgCmd`/`WgEvent`
/// and the ESP32-C3 stack-overflow fix documented in
/// docs/wg-dataplane-notes.md): `async_channel::Sender::send`/`try_send`
/// and `Receiver::recv` move the value by value through the caller's stack
/// frame, so an unboxed ~1.5KB payload here would reproduce that overflow
/// in `tm_runtime`'s event router.
pub struct OutboundPacket {
    /// Destination IPv4 address, read from bytes 16..20 of the IP header --
    /// no lwIP address-object conversion needed, these are already the wire
    /// bytes.
    pub dst_ip: [u8; 4],
    /// The shared channel packet buffer (`tm_buf`); the event router
    /// forwards it into `WgCmd::SendData` as-is.
    pub data: tm_buf::PktBox,
}

pub type OutboundSender = async_channel::Sender<OutboundPacket>;
pub type OutboundReceiver = async_channel::Receiver<OutboundPacket>;

#[cfg(target_os = "espidf")]
mod device;
#[cfg(target_os = "espidf")]
pub use device::{bring_up, inject_inbound, set_address};

#[cfg(not(target_os = "espidf"))]
mod host;
#[cfg(not(target_os = "espidf"))]
pub use host::{bring_up, inject_inbound, set_address};
