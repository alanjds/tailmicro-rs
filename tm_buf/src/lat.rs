//! Per-hop latency stamps for the LAN-direct round trip (ALLOCATIONS.md
//! "Step 9: LAN round-trip latency"). Off unless the `latency-trace`
//! feature is on; then every function below is an inlined no-op.
//!
//! It lives in `tm_buf` only because every crate on the data path (tm_wg,
//! tm_disco, tm_netstack, tm_runtime) already depends on it. Nothing here
//! allocates: each hop is one static `AtomicU32` holding the microsecond
//! clock of its most recent visit ("last writer wins"). With one ping in
//! flight on an otherwise idle device, the stamps of one round trip form a
//! chain that `chain_line` prints once, after the reply has left, so the
//! UART time never lands inside the measured interval. Under concurrent
//! traffic the chain can mix packets; `chain_line` refuses to print a chain
//! that is not monotonic, rather than print a wrong number.

/// Whether stamps are recorded at all.
pub const ENABLED: bool = cfg!(feature = "latency-trace");

/// The hops of the two round trips that `tailscale ping` exercises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Hop {
    // ICMP over WireGuard (`tailscale ping --icmp`, or any app data).
    /// UDP task read a WireGuard transport datagram.
    UdpRxWg,
    /// WgActor dequeued an `InboundPacket`.
    WgIn,
    /// WgActor decrypted an ICMP echo request (before emitting it).
    WgDecrypted,
    /// Router dequeued `InboundDecrypted` (ICMP echo request).
    RouterInbound,
    /// `tailnet::inject_inbound` returned.
    Injected,
    /// lwIP's netif output callback produced an ICMP echo reply.
    NetifOut,
    /// Router dequeued that reply from the netif channel.
    RouterNetif,
    /// WgActor dequeued the `SendData`.
    WgSendIn,
    /// WgActor encrypted it (before emitting `OutboundPacket`).
    WgEncrypted,
    /// Router dequeued the `OutboundPacket`.
    RouterOutbound,
    /// `try_send_to` returned for it.
    UdpTxWg,
    // Disco (`tailscale ping`, default).
    /// UDP task read a disco datagram.
    UdpRxDisco,
    /// DiscoActor dequeued it.
    DiscoIn,
    /// DiscoActor emitted the PONG event.
    DiscoOut,
    /// Router dequeued `SendPongUdp`.
    RouterPong,
    /// `try_send_to` returned for the PONG.
    UdpTxPong,
}

const N: usize = Hop::UdpTxPong as usize + 1;

#[cfg(feature = "latency-trace")]
mod imp {
    use super::N;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::Instant;

    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU32 = AtomicU32::new(0);
    pub static STAMPS: [AtomicU32; N] = [Z; N];
    static BASE: OnceLock<Instant> = OnceLock::new();

    /// Router loop accounting: iterations, and total / max microseconds the
    /// executor spent blocked in the FreeRTOS yield.
    pub static ROUTER_ITERS: AtomicU32 = AtomicU32::new(0);
    pub static YIELD_US: AtomicU64 = AtomicU64::new(0);
    pub static YIELD_MAX_US: AtomicU32 = AtomicU32::new(0);

    pub fn now_us() -> u32 {
        // Wraps after ~71 minutes; only differences are ever used.
        BASE.get_or_init(Instant::now).elapsed().as_micros() as u32
    }

    pub fn store(i: usize) {
        // 0 means "never stamped", so skip it.
        STAMPS[i].store(now_us().max(1), Ordering::Relaxed);
    }

    pub fn load(i: usize) -> u32 {
        STAMPS[i].load(Ordering::Relaxed)
    }
}

/// Record that `hop` happened now.
#[inline(always)]
pub fn stamp(hop: Hop) {
    #[cfg(feature = "latency-trace")]
    imp::store(hop as usize);
    #[cfg(not(feature = "latency-trace"))]
    let _ = hop;
}

/// Microsecond clock (0 when the feature is off).
#[inline(always)]
pub fn now_us() -> u32 {
    #[cfg(feature = "latency-trace")]
    return imp::now_us();
    #[cfg(not(feature = "latency-trace"))]
    0
}

/// Account one FreeRTOS yield of `us` microseconds in the router loop.
#[inline(always)]
pub fn note_yield(us: u32) {
    #[cfg(feature = "latency-trace")]
    {
        use std::sync::atomic::Ordering::Relaxed;
        imp::YIELD_US.fetch_add(us as u64, Relaxed);
        imp::YIELD_MAX_US.fetch_max(us, Relaxed);
    }
    #[cfg(not(feature = "latency-trace"))]
    let _ = us;
}

/// Count one router loop iteration.
#[inline(always)]
pub fn note_router_iter() {
    #[cfg(feature = "latency-trace")]
    imp::ROUTER_ITERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Take (and reset) the router counters: (iterations, total yield µs, max
/// single yield µs).
pub fn take_router_stats() -> (u32, u64, u32) {
    #[cfg(feature = "latency-trace")]
    {
        use std::sync::atomic::Ordering::Relaxed;
        return (
            imp::ROUTER_ITERS.swap(0, Relaxed),
            imp::YIELD_US.swap(0, Relaxed),
            imp::YIELD_MAX_US.swap(0, Relaxed),
        );
    }
    #[cfg(not(feature = "latency-trace"))]
    (0, 0, 0)
}

/// Deltas in microseconds between consecutive hops of `hops`, or `None` if
/// any hop is unstamped, the chain is not monotonic (mixed packets), or it
/// spans more than 5 s (stale). The first element is the total.
pub fn chain(hops: &[Hop]) -> Option<heapless::Vec<u32, 16>> {
    #[cfg(feature = "latency-trace")]
    {
        let mut out = heapless::Vec::new();
        let first = imp::load(hops[0] as usize);
        let last = imp::load(hops[hops.len() - 1] as usize);
        if first == 0 {
            return None;
        }
        let total = last.wrapping_sub(first);
        if total > 5_000_000 {
            return None;
        }
        out.push(total).ok()?;
        let mut prev = first;
        for h in &hops[1..] {
            let t = imp::load(*h as usize);
            let d = t.wrapping_sub(prev);
            if t == 0 || d > total {
                return None;
            }
            out.push(d).ok()?;
            prev = t;
        }
        return Some(out);
    }
    #[cfg(not(feature = "latency-trace"))]
    {
        let _ = hops;
        None
    }
}

/// The ICMP-over-WireGuard round trip, in order.
pub const ICMP_CHAIN: [Hop; 11] = [
    Hop::UdpRxWg,
    Hop::WgIn,
    Hop::WgDecrypted,
    Hop::RouterInbound,
    Hop::Injected,
    Hop::NetifOut,
    Hop::RouterNetif,
    Hop::WgSendIn,
    Hop::WgEncrypted,
    Hop::RouterOutbound,
    Hop::UdpTxWg,
];

/// The disco PING/PONG round trip, in order.
pub const DISCO_CHAIN: [Hop; 5] =
    [Hop::UdpRxDisco, Hop::DiscoIn, Hop::DiscoOut, Hop::RouterPong, Hop::UdpTxPong];

/// Whether an IPv4 packet is an ICMP echo request (`ty` 8) or reply (0).
#[inline(always)]
pub fn is_icmp_echo(pkt: &[u8], ty: u8) -> bool {
    if pkt.len() < 21 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    pkt.len() > ihl && pkt[ihl] == ty
}

/// Clear a hop so a later chain cannot reuse it.
pub fn clear(hop: Hop) {
    #[cfg(feature = "latency-trace")]
    imp::STAMPS[hop as usize].store(0, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(feature = "latency-trace"))]
    let _ = hop;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_echo_classification() {
        let mut p = [0u8; 28];
        p[0] = 0x45;
        p[9] = 1;
        p[20] = 8;
        assert!(is_icmp_echo(&p, 8));
        assert!(!is_icmp_echo(&p, 0));
        p[9] = 6;
        assert!(!is_icmp_echo(&p, 8));
        assert!(!is_icmp_echo(&p[..20], 8));
    }

    #[cfg(feature = "latency-trace")]
    #[test]
    fn chain_is_monotonic_or_none() {
        let hops = [Hop::UdpRxDisco, Hop::DiscoIn, Hop::DiscoOut];
        for h in hops {
            clear(h);
        }
        assert!(chain(&hops).is_none());
        for h in hops {
            stamp(h);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let d = chain(&hops).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0], d[1] + d[2]);
        // A later first hop (a mixed chain) is refused.
        std::thread::sleep(std::time::Duration::from_millis(2));
        stamp(Hop::UdpRxDisco);
        assert!(chain(&hops).is_none());
    }
}
