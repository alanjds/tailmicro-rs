//! Underlay-LAN UDP socket for the direct WireGuard path
//! (docs/lan-direct-path-plan.md, Step 2).
//!
//! This module owns the pieces of the direct path that do not depend on any
//! other actor, so they stay host-testable (`tm_runtime` itself cannot be
//! built for the host, see its test-module note):
//!
//! - [`bind_lan`]: bind `0.0.0.0:41641`, falling back to an ephemeral port.
//! - [`classify`]: the cheap, allocation-free demux of one received datagram.
//! - [`rx_loop`]: the receive loop, which reads into one caller-provided
//!   buffer (the static one from [`rx_buf_static`] on device), classifies,
//!   counts, and hands disco/WireGuard datagrams to a callback.
//!
//! The loop never allocates per datagram. Accepted datagrams are lent to the
//! callback as a slice of the receive buffer; a callback that needs to keep
//! one copies it into a `tm_buf::PktBuf`. Holding a pooled `PktBuf` across
//! `recv_from().await` instead would pin one of the four pool buffers
//! forever (plan, "RAM/lwIP budget").

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use crate::{NetError, UdpSocket};

/// Tailscale's conventional direct-path port. Only a preference: if it is
/// taken, [`bind_lan`] falls back to an ephemeral port, and whatever port is
/// actually bound is what gets published (Step 5).
pub const LAN_UDP_PORT: u16 = 41641;

/// Receive buffer size: the workspace packet-buffer capacity, so anything we
/// accept always fits a `tm_buf::PktBuf` without a length check downstream.
pub const RX_BUF_LEN: usize = tm_buf::PKT_CAP;

/// Disco magic, "TS💬". Duplicated from `tm_disco::DISCO_MAGIC` so this crate
/// does not depend on `tm_disco` for six bytes.
const DISCO_MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";

/// Smallest possible disco datagram: magic(6) + sender disco key(32) +
/// nonce(24) + NaCl box of at least type+version (2 + 16-byte tag).
pub const MIN_DISCO_LEN: usize = 6 + 32 + 24 + 2 + 16;

/// WireGuard message sizes (whitepaper section 5.4).
const WG_INIT_LEN: usize = 148;
const WG_RESP_LEN: usize = 92;
const WG_COOKIE_LEN: usize = 64;
/// Transport data: 16-byte header + ciphertext + 16-byte tag. An empty
/// payload (keepalive) is the minimum.
const WG_DATA_MIN_LEN: usize = 32;

/// How often [`rx_loop`] logs its counters (only when they changed). Kept
/// coarse on purpose: the console is a blocking 115200-baud UART and a
/// per-packet line would throttle the data plane (ALLOCATIONS.md Step 8,
/// "Fix 3").
pub const SUMMARY_PERIOD: Duration = Duration::from_secs(10);

/// Consecutive `recv_from` errors after which [`rx_loop`] gives up (and the
/// caller runs DERP-only). A single error is usually transient (lwIP
/// `ENOMEM` under load).
const MAX_CONSECUTIVE_ERRORS: u32 = 16;

/// What one received datagram is, decided before any crypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxClass {
    /// Sourced from the tailnet range (`100.64.0.0/10`). `0.0.0.0` also binds
    /// the tailnet netif, and WireGuard-in-WireGuard must be refused.
    Tailnet,
    /// Starts with the disco magic and is long enough to hold a sealed box.
    Disco,
    /// WireGuard message type 1..=4 with its reserved bytes zero and a
    /// length that fits the type.
    WireGuard,
    /// Anything else (including non-IPv4 sources and oversize datagrams).
    Junk,
}

/// True for `100.64.0.0/10`, the tailnet (CGNAT) range.
pub fn is_tailnet_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// Classify one datagram. Pure and allocation-free.
pub fn classify(src: SocketAddr, data: &[u8]) -> RxClass {
    let SocketAddr::V4(src) = src else {
        return RxClass::Junk; // Tier 1 is IPv4-only
    };
    if is_tailnet_ip(*src.ip()) {
        return RxClass::Tailnet;
    }
    if data.len() >= MIN_DISCO_LEN && data[..6] == DISCO_MAGIC[..] {
        return RxClass::Disco;
    }
    if is_plausible_wireguard(data) {
        return RxClass::WireGuard;
    }
    RxClass::Junk
}

fn is_plausible_wireguard(data: &[u8]) -> bool {
    if data.len() < 4 || data[1..4] != [0, 0, 0] {
        return false;
    }
    match data[0] {
        1 => data.len() == WG_INIT_LEN,
        2 => data.len() == WG_RESP_LEN,
        3 => data.len() == WG_COOKIE_LEN,
        4 => data.len() >= WG_DATA_MIN_LEN,
        _ => false,
    }
}

/// Receive counters. Atomics so a test (or a status endpoint) can read them
/// while the loop owns the socket; `const fn new` so they can be a `static`.
#[derive(Default)]
pub struct RxStats {
    pub disco: AtomicU32,
    pub wireguard: AtomicU32,
    pub junk: AtomicU32,
    pub tailnet: AtomicU32,
    pub errors: AtomicU32,
    /// Accepted datagrams dropped before reaching an actor because the
    /// shared packet pool was (nearly) empty; see `tm_runtime`'s UDP task.
    pub pool_drops: AtomicU32,
    /// WireGuard datagrams sent directly over this socket (Step 5).
    pub tx_wg: AtomicU32,
    /// WireGuard datagrams whose direct send failed and went to DERP instead.
    pub tx_fallback: AtomicU32,
    /// Disco PONGs sent over this socket, and ones whose send failed.
    pub tx_pong: AtomicU32,
    pub tx_pong_err: AtomicU32,
}

/// A plain copy of [`RxStats`] at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RxSnapshot {
    pub disco: u32,
    pub wireguard: u32,
    pub junk: u32,
    pub tailnet: u32,
    pub errors: u32,
    pub pool_drops: u32,
    pub tx_wg: u32,
    pub tx_fallback: u32,
    pub tx_pong: u32,
    pub tx_pong_err: u32,
}

impl RxStats {
    pub const fn new() -> Self {
        Self {
            disco: AtomicU32::new(0),
            wireguard: AtomicU32::new(0),
            junk: AtomicU32::new(0),
            tailnet: AtomicU32::new(0),
            errors: AtomicU32::new(0),
            pool_drops: AtomicU32::new(0),
            tx_wg: AtomicU32::new(0),
            tx_fallback: AtomicU32::new(0),
            tx_pong: AtomicU32::new(0),
            tx_pong_err: AtomicU32::new(0),
        }
    }

    pub fn snapshot(&self) -> RxSnapshot {
        RxSnapshot {
            disco: self.disco.load(Ordering::Relaxed),
            wireguard: self.wireguard.load(Ordering::Relaxed),
            junk: self.junk.load(Ordering::Relaxed),
            tailnet: self.tailnet.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            pool_drops: self.pool_drops.load(Ordering::Relaxed),
            tx_wg: self.tx_wg.load(Ordering::Relaxed),
            tx_fallback: self.tx_fallback.load(Ordering::Relaxed),
            tx_pong: self.tx_pong.load(Ordering::Relaxed),
            tx_pong_err: self.tx_pong_err.load(Ordering::Relaxed),
        }
    }

    fn count(&self, class: RxClass) {
        let c = match class {
            RxClass::Disco => &self.disco,
            RxClass::WireGuard => &self.wireguard,
            RxClass::Junk => &self.junk,
            RxClass::Tailnet => &self.tailnet,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bind the LAN socket on `0.0.0.0:41641`, or an ephemeral port if 41641 is
/// taken. Returns the socket and whether the fallback was used. Must run
/// inside a tokio runtime.
pub fn bind_lan() -> Result<(UdpSocket, bool), NetError> {
    let preferred = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LAN_UDP_PORT));
    match UdpSocket::bind_sync(preferred) {
        Ok(s) => Ok((s, false)),
        Err(first) => {
            log::warn!("lan-udp: bind 0.0.0.0:{} failed ({:?}); trying an ephemeral port", LAN_UDP_PORT, first);
            let any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            UdpSocket::bind_sync(any).map(|s| (s, true))
        }
    }
}

/// Hand out the one static (`.bss`) receive buffer. Same once-only pattern as
/// `tm_wg::endpoint::recv_out_static`: a single, forever-held buffer costs no
/// heap and cannot fragment it.
///
/// # Panics
/// Panics if called more than once (a second `&'static mut` would alias).
#[inline(never)]
pub fn rx_buf_static() -> &'static mut [u8; RX_BUF_LEN] {
    static TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static mut STORAGE: [u8; RX_BUF_LEN] = [0; RX_BUF_LEN];
    if TAKEN.swap(true, Ordering::AcqRel) {
        panic!("lan_udp::rx_buf_static called more than once");
    }
    // SAFETY: the swap above lets exactly one caller ever reach this point.
    unsafe { &mut *core::ptr::addr_of_mut!(STORAGE) }
}

/// Receive forever: classify each datagram, count it, and pass disco and
/// WireGuard datagrams (with their IPv4 source) to `on_packet`. Tailnet-
/// sourced and junk datagrams are counted and dropped here.
///
/// Returns only when the socket keeps failing ([`MAX_CONSECUTIVE_ERRORS`] in
/// a row); the caller then logs and carries on DERP-only.
pub async fn rx_loop<F>(sock: &UdpSocket, buf: &mut [u8], stats: &RxStats, mut on_packet: F) -> NetError
where
    F: FnMut(RxClass, SocketAddrV4, &[u8]),
{
    let mut summary = tokio::time::interval(SUMMARY_PERIOD);
    summary.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_logged = RxSnapshot::default();
    let mut consecutive_errors = 0u32;
    loop {
        tokio::select! {
            r = sock.recv_from(buf) => match r {
                Ok((n, src)) => {
                    consecutive_errors = 0;
                    // A datagram that filled the whole buffer may have been
                    // truncated by the stack; nothing legitimate is that big.
                    let class = if n >= buf.len() { RxClass::Junk } else { classify(src, &buf[..n]) };
                    stats.count(class);
                    if let (RxClass::Disco | RxClass::WireGuard, SocketAddr::V4(v4)) = (class, src) {
                        on_packet(class, v4, &buf[..n]);
                    }
                }
                Err(e) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        log_summary(stats.snapshot());
                        return e;
                    }
                    // Back off briefly so a persistent error cannot spin the
                    // single-threaded runtime.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            _ = summary.tick() => {
                let now = stats.snapshot();
                if now != last_logged {
                    last_logged = now;
                    log_summary(now);
                }
            }
        }
    }
}

/// The periodic counter line, with the heap numbers that matter for the
/// UDP-burst measurement (plan Step 2) on device. Its own frame so the
/// format temporaries stay off the loop's.
#[inline(never)]
fn log_summary(s: RxSnapshot) {
    #[cfg(target_os = "espidf")]
    let (largest, total) = unsafe {
        let mut info: esp_idf_sys::multi_heap_info_t = core::mem::zeroed();
        esp_idf_sys::heap_caps_get_info(&mut info, esp_idf_sys::MALLOC_CAP_INTERNAL);
        (info.largest_free_block, info.total_free_bytes)
    };
    #[cfg(not(target_os = "espidf"))]
    let (largest, total) = (0usize, 0usize);
    log::info!(
        "udp rx: disco={} wg={} junk={} tailnet={} err={} pool_drop={} | tx: wg={} fallback={} pong={} pong_err={} (heap largest_free={} total_free={})",
        s.disco, s.wireguard, s.junk, s.tailnet, s.errors, s.pool_drops,
        s.tx_wg, s.tx_fallback, s.tx_pong, s.tx_pong_err, largest, total,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn v4(a: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a), port))
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Generated by tools/wg_validator/gen_udp_demux_vectors.py (pynacl disco
    // PING with a fixed nonce; wg_spec.py handshake initiation with fixed
    // keys). The bytes, not the keys, are what matters here: the demux must
    // recognize real wire output of both protocols.
    const PING_HEX: &str = include_str!("../../tools/wg_validator/udp_demux_ping.hex");
    const WG_INIT_HEX: &str = include_str!("../../tools/wg_validator/udp_demux_wg_init.hex");

    #[test]
    fn classify_real_vectors() {
        let ping = hex(PING_HEX);
        let init = hex(WG_INIT_HEX);
        assert_eq!(init.len(), WG_INIT_LEN);
        let lan = v4([192, 168, 15, 70], 41641);
        assert_eq!(classify(lan, &ping), RxClass::Disco);
        assert_eq!(classify(lan, &init), RxClass::WireGuard);
    }

    #[test]
    fn classify_tailnet_source_wins_over_payload() {
        let ping = hex(PING_HEX);
        let init = hex(WG_INIT_HEX);
        for src in [[100, 64, 0, 1], [100, 101, 102, 103], [100, 127, 255, 254]] {
            assert_eq!(classify(v4(src, 41641), &ping), RxClass::Tailnet);
            assert_eq!(classify(v4(src, 41641), &init), RxClass::Tailnet);
        }
        // Just outside 100.64.0.0/10 on both sides.
        assert_eq!(classify(v4([100, 63, 255, 255], 1), &init), RxClass::WireGuard);
        assert_eq!(classify(v4([100, 128, 0, 0], 1), &init), RxClass::WireGuard);
    }

    #[test]
    fn classify_junk() {
        let lan = v4([192, 168, 15, 70], 5000);
        assert_eq!(classify(lan, b""), RxClass::Junk);
        assert_eq!(classify(lan, b"hello"), RxClass::Junk);
        // Disco magic but too short to hold a box.
        assert_eq!(classify(lan, &DISCO_MAGIC[..]), RxClass::Junk);
        // WG type byte with wrong length or nonzero reserved bytes.
        let mut init = hex(WG_INIT_HEX);
        assert_eq!(classify(lan, &init[..147]), RxClass::Junk);
        init[2] = 1;
        assert_eq!(classify(lan, &init), RxClass::Junk);
        assert_eq!(classify(lan, &[5, 0, 0, 0, 0, 0, 0, 0]), RxClass::Junk);
        // Minimal transport (keepalive) is WireGuard; one byte less is not.
        let mut ka = vec![0u8; WG_DATA_MIN_LEN];
        ka[0] = 4;
        assert_eq!(classify(lan, &ka), RxClass::WireGuard);
        assert_eq!(classify(lan, &ka[..WG_DATA_MIN_LEN - 1]), RxClass::Junk);
        // IPv6 sources are out of scope for Tier 1.
        let v6: SocketAddr = "[fe80::1]:41641".parse().unwrap();
        assert_eq!(classify(v6, &ka), RxClass::Junk);
    }

    /// End to end over real loopback UDP: the loop counts every class and
    /// hands only disco/WireGuard (with the right source) to the callback.
    #[tokio::test(flavor = "current_thread")]
    async fn rx_loop_demuxes_over_loopback() {
        let rx = UdpSocket::bind_sync(v4([127, 0, 0, 1], 0)).unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind_sync(v4([127, 0, 0, 1], 0)).unwrap();
        let tx_addr = match tx.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };

        let ping = hex(PING_HEX);
        let init = hex(WG_INIT_HEX);
        let oversize = vec![0u8; RX_BUF_LEN + 10];
        tx.writable().await.unwrap();
        tx.try_send_to(rx_addr, &ping).unwrap();
        tx.try_send_to(rx_addr, &init).unwrap();
        tx.try_send_to(rx_addr, b"junk").unwrap();
        tx.try_send_to(rx_addr, &oversize).unwrap();
        tx.try_send_to(rx_addr, &ping).unwrap();

        let stats = RxStats::new();
        let seen: Rc<RefCell<Vec<(RxClass, SocketAddrV4, usize)>>> = Rc::default();
        let seen2 = seen.clone();
        let mut buf = vec![0u8; RX_BUF_LEN];
        let run = rx_loop(&rx, &mut buf, &stats, move |c, src, d| seen2.borrow_mut().push((c, src, d.len())));
        let _ = tokio::time::timeout(Duration::from_millis(300), run).await;

        let s = stats.snapshot();
        assert_eq!(s, RxSnapshot { disco: 2, wireguard: 1, junk: 2, ..Default::default() });
        let seen = seen.borrow();
        assert_eq!(
            *seen,
            vec![
                (RxClass::Disco, tx_addr, ping.len()),
                (RxClass::WireGuard, tx_addr, init.len()),
                (RxClass::Disco, tx_addr, ping.len()),
            ]
        );
    }

    /// `try_send_to` must never await. Before the reactor has seen the
    /// socket writable it reports `WouldBlock` (a drop the caller falls back
    /// from, never an error that kills the path); after `writable()` it
    /// sends.
    #[tokio::test(flavor = "current_thread")]
    async fn try_send_to_never_blocks_and_reports_the_bound_port() {
        let s = UdpSocket::bind_sync(v4([127, 0, 0, 1], 0)).unwrap();
        let peer = UdpSocket::bind_sync(v4([127, 0, 0, 1], 0)).unwrap();
        assert_ne!(s.local_addr().unwrap().port(), 0);
        let first = s.try_send_to(peer.local_addr().unwrap(), b"x");
        assert!(matches!(first, Ok(()) | Err(NetError::WouldBlock)), "{first:?}");
        s.writable().await.unwrap();
        s.try_send_to(peer.local_addr().unwrap(), b"y").unwrap();
    }
}
