# Plan: Tokio and Embassy runtime backends

Branch `simplification-survey` at `e72f5cc`, 2026-10-01 (line numbers re-verified against `040d0d1` on 2026-10-02, see "Status" below). Plan; builds on `docs/investigation-runtime-agnostic.md` (called "the investigation"). Line numbers are at `e72f5cc`. "Verified" = read in source (local or GitHub via `gh api`) or measured; "inferred" = reasoned.

## Summary and recommendation

Make the actor shells generic over three small static traits (`Reactor` for time and yield, `Net` for TCP/DNS/UDP, `TailnetIf` for the packet netif), bundled per binary by a `Backend` trait. Pure cores stay non-generic; `Driver` stays a non-generic `Pin<Box<dyn Future>>`, so neither tasmolike nor an Embassy task ever names a backend type. Backends live in additive crates `tm_backend_tokio` (today's code moved, zero behavior change on ESP32) and `tm_backend_embassy`. The realistic first Embassy target is **host std** (embassy-executor `platform-std` + embassy-time `std` + embassy-net 0.9.1 over in-process links), proven equivalent to Tokio by a shared conformance suite and one end-to-end scenario run on both. Embassy on esp-hal C3 is a later, conditional phase (no_std work plus a non-lwIP netif). Cheap proof first: `tm_time` on tm_disco. Naming: `tm_runtime::Runtime` keeps its name (it mirrors upstream `ts_runtime::Runtime`, the coordinator, so tailmicro stays source-close to tailscale-rs); the new abstraction over the executor is the `Reactor` trait, so nothing clashes with Tokio's or Embassy's own "runtime".

## Architecture

```
tm_time      (new, no_std leaf) Instant(u64 us), global clock fns
tm_platform  (new, no_std+alloc) traits Reactor, Net, UdpTransport; combinators
                                 (timeout, Interval, Rotor; re-exports embassy-futures)
tm_buf, tm_keys, tm_h2           unchanged (tm_buf::lat uses tm_time)
tm_disco, tm_wg (cores)          non-generic, take `now: tm_time::Instant`
tm_wg::WgActor<R>, tm_derp::DerpActor<R,N>, tm_control::ControlActor<R,N>   generic shells
tm_netstack  lan_udp generic over <R, U: UdpTransport>; trait TailnetIf; lwIP netif stays (cfg espidf);
             the tokio UdpSocket moves out; host TcpStream/TcpListener todo!-stubs deleted
tm_runtime   trait Backend { Reactor, Net, Tailnet }; Runtime; RuntimeConfig; Driver; connect::<B>
tm_backend_tokio    TokioReactor, TokioNet, TokioUdp, TokioBackend (= Lwip netif on espidf, stub on host)
tm_backend_embassy  EmbassyReactor, EmbassyNet, EmbassyUdp, EmbassyBackend<T: TailnetIf>
tailmicro (root)    features: tokio (default), embassy; Device::connect (tokio) + Device::connect_with::<B>
tm_testnet (new, dev only) MemNet, ChanTailnet, fake control + DERP peers, scenario runner
```

Dependency direction: backends depend on `tm_runtime` (to `impl Backend`); `tm_runtime` never depends on a backend. All features are additive: one binary can link both backends (the equivalence tests do).

**Naming.** `tm_runtime::Runtime` (the command-sender handle, `tm_runtime/src/lib.rs`) and `RuntimeConfig` keep their names: upstream tailscale-rs has `ts_runtime::Runtime` as its coordinator, and no firmware change is needed. The executor-facing abstraction is `Reactor`:

| Item | Name | Firmware blast radius |
|---|---|---|
| `tm_runtime::Runtime`, `RuntimeConfig` | unchanged | none |
| `tm_runtime::Driver` | unchanged; also re-exported as `tailmicro::Driver` | optional: `src/main.rs:131`, `src/tailscale_rust.rs:182` may switch to `tailmicro::Driver` (2 lines) |
| crate `tm_runtime` | keep the name | none |
| `tokio_freertos_yield` | keep for now; host stand-in already committed (49c3cb2); later `B::Reactor::os_pause` | none (unused in tasmolike src) |
| new trait | `tm_platform::Reactor` (time, yield, os_pause) | none |
| bundle trait | `Backend` (keeps its name) | none |

**Public API for apps.**
```rust
// Tokio (default feature): unchanged for tasmolike.
let (device, driver) = tailmicro::Device::connect(&config, auth).await?;
// Any backend:
let (device, driver) = tailmicro::Device::connect_with::<EmbassyBackend<ChanTailnet>>(&config, auth, net).await?;
```
`Device` holds a `Runtime` (channels only) and stays non-generic. `tailmicro::netstack` (re-exports of Tokio `UdpSocket/TcpStream/TcpListener`, `src/lib.rs:169-170`) moves under `feature = "tokio"`.

## Trait definitions

```rust
// ---- tm_time (no_std) ----
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Instant(u64);                       // microseconds, arbitrary epoch
impl Instant {
    pub fn now() -> Self;                      // calls the installed clock
    pub const fn from_micros(us: u64) -> Self; pub const fn as_micros(self) -> u64;
    pub fn duration_since(self, earlier: Self) -> Duration;   // saturating
    pub fn elapsed(self) -> Duration;
    pub fn checked_add(self, d: Duration) -> Option<Self>;
}
// Add<Duration>, Sub<Duration>, Sub<Instant> = Duration
pub fn set_clock(now_us: fn() -> u64, unix_secs: fn() -> Option<u64>); // once, before connect
pub fn unix_secs() -> Option<u64>;
// feature "std": default clock = std::time::Instant/SystemTime (today's behavior on ESP32).
// Storage: two AtomicPtr fn pointers; load/store only, fine on riscv32imc (no CAS needed).
```

```rust
// ---- tm_platform ----
#[allow(async_fn_in_trait)]                    // single-threaded executors; no Send bounds wanted
pub trait Reactor: 'static {
    fn now() -> Instant { Instant::now() }
    async fn sleep_until(deadline: Instant);
    async fn sleep(d: Duration) { Self::sleep_until(Self::now() + d).await }
    /// Let sibling futures and the I/O driver run (Tokio: deferred wake, see investigation).
    async fn yield_now();
    /// Give the OS scheduler `ticks` (FreeRTOS vTaskDelay on ESP-IDF). Default: yield_now.
    async fn os_pause(_ticks: u32) { Self::yield_now().await }
}

pub struct Elapsed;
pub async fn timeout_at<R: Reactor, F: Future>(at: Instant, f: F) -> Result<F::Output, Elapsed>;
pub async fn timeout<R: Reactor, F: Future>(d: Duration, f: F) -> Result<F::Output, Elapsed>;
// both = embassy_futures::select(f, R::sleep_until(at)), future polled first like tokio

/// Tokio `MissedTickBehavior::Delay` semantics: first tick immediate; after a late tick the
/// next deadline is `now + period`, else `deadline + period`. Cancel-safe (state changes only
/// after the sleep completes). No heap (tokio's Interval boxes its Sleep).
pub struct Interval<R: Reactor> { next: Instant, period: Duration, _r: PhantomData<fn() -> R> }
impl<R: Reactor> Interval<R> { pub fn new(period: Duration) -> Self; pub async fn tick(&mut self) -> Instant; }

pub use embassy_futures::{select::{select, select3, select4, Either, Either3, Either4},
                          join::{join, join5, join_array}};

/// Fair N-way readiness: polls arms from a rotating start, deterministic round-robin.
pub struct Rotor<const N: usize> { start: u8 }
impl<const N: usize> Rotor<N> {
    pub fn poll<T>(&mut self, cx: &mut Context<'_>,
                   arm: impl FnMut(usize, &mut Context<'_>) -> Poll<T>) -> Poll<T>;
}

#[allow(async_fn_in_trait)]
pub trait Net: Clone + 'static {
    type Tcp: embedded_io_async::Read + embedded_io_async::Write;
    type Udp: UdpTransport + 'static;
    async fn resolve(&self, host: &str) -> Result<IpAddr, NetError>;           // first A record
    async fn connect_addr(&self, addr: SocketAddr) -> Result<Self::Tcp, NetError>;
    /// Default: IP literal -> connect_addr, else resolve + connect_addr.
    async fn connect_host(&self, host: &str, port: u16) -> Result<Self::Tcp, NetError>;
    /// One socket per process; the backend owns the 'static storage (statics cannot be generic).
    fn bind_udp(&self, addr: SocketAddrV4) -> Result<&'static Self::Udp, NetError>;
}

#[allow(async_fn_in_trait)]
pub trait UdpTransport {
    fn local_addr(&self) -> Result<SocketAddr, NetError>;
    async fn ready(&self) -> Result<(), NetError>;      // Tokio: writable() priming
    fn try_send_to(&self, to: SocketAddr, buf: &[u8]) -> Result<(), NetError>; // never awaits
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError>;
}
```

```rust
// ---- tm_netstack::tailnet ----   (OutboundPacket / TailnetError already live here)
pub trait TailnetIf: 'static {
    fn bring_up(our_ip: [u8; 4], out: OutboundSender) -> Result<(), TailnetError>;
    fn set_address(ip: [u8; 4]) -> Result<(), TailnetError>;
    fn inject_inbound(pkt: &[u8]) -> Result<(), TailnetError>;
}
// ---- tm_runtime ----
pub trait Backend: 'static { type Reactor: Reactor; type Net: Net; type Tailnet: TailnetIf; }
impl Runtime { pub async fn connect<B: Backend>(cfg: RuntimeConfig, net: B::Net)
                       -> Result<(Self, Ipv4Addr, Driver), ConnectError>; }
```

Randomness and critical sections stay out of the traits: `rand_core::OsRng` (10 sites) uses getrandom 0.2, which the platform satisfies (std on hosts, `register_custom_getrandom!` over the esp-hal RNG later); `critical-section` is chosen by the binary as today (tm_buf's heapless pool).

**Injection: static generics.**
- `dyn`: async methods need `Box<dyn Future>` per call. The router yields per event and WG ticks every 400 ms, so this means a heap alloc/free on the hot path, against the ALLOCATIONS "design principle". Rejected.
- Mutually exclusive cfg features: non-additive, and they would forbid the both-backends equivalence build. Rejected.
- Generics: a single instantiation per binary; the Tokio backend yields exactly today's future types, so frames do not change; the `#[inline(never)] spawn_*` + `Box::pin` boundaries (`tm_runtime/src/lib.rs` (the `spawn_*` helpers)) still erase types to `BoxActorFut`. Measured on host (x86_64, debug, tokio 1.53.1, scratch crate): `Sleep` 96 B, `Interval` 32 B (its `Sleep` is boxed: one heap alloc per interval), a sleep-vs-`recv()` fn using `tokio::select!` 160 B vs `embassy_futures::select` 128 B, `tokio::task::yield_now` 16 B vs embassy's 1 B. So the combinator swap should shrink frames slightly; `Interval<R>` holds the sleep inline (+~64 B per frame on x86_64, minus the box). riscv32 numbers are not measured.

## Call-site mapping

Spot-check corrections to the investigation's catalog (line drift since `11b6970` plus misses):
- tm_control (at `040d0d1`, after the netmap-refresh series): bring-up is `tokio::time::timeout_at(at, bring_up)` at **721** (a deadline, not a duration), backoff sleep at **781**, `open_tcp` `TcpStream::connect` at **1538**, `TokioStream` alias at **35**. The investigation's 464/519/929-931 and the plan's first-draft 553/608/1018 are both stale.
- tm_control **new time sites** (d4f126a..040d0d1): the poll loop keeps its deadlines as `tokio::time::Instant` (`PollControl` fields `last_refresh`, `inflight`, `emit_at`, `ready_deadline`, lines 1365-1391, plus 14 call sites at 714-1228), a 4-arm **biased** `tokio::select!` in `PollControl::wait` (1490: `noise.wait_readable`, `cmds.recv`, `sleep_until_opt(timer_at)`, `sleep_until_opt(idle_at)`), `sleep_until_opt` (1509, `tokio::time::sleep_until`) and `read_exact_idle` (1524, `tokio::time::timeout`). All of it moves to `R::now()`/`tm_time::Instant`, `R::sleep_until`, `timeout::<R>` and `select4` (argument order = bias) in phases 4-5. The `timeout`/`sleep_until` conversions need `tm_time::Instant` deadlines, so the `tokio::time::Instant` fields must change type together with the sleeps (phase 5, not phase 3).
- tm_derp connect is at **388**.
- **Missed:** `tm_runtime/src/lib.rs:1486-1516` (was 1384-1422 in the first draft) calls `tokio_freertos_yield()` (vTaskDelay(50) + yield) about 10 times in `build`, but it is defined only for `target_os = "espidf"` (39). Together with the unconditional esp-idf-sys/svc deps, that is why `tm_runtime` (and so the root crate) cannot build on host.
- **Missed:** `lan_udp.rs:518`, a test-only sleep.
- **Stale in ALLOCATIONS.md** ("Scheduling facts"): "`Runtime::spawn` uses `tokio::spawn`" is false; no spawn exists outside tests.

| Site | Today | New |
|---|---|---|
| tm_control/src/lib.rs:721 | `tokio::time::timeout_at(at, bring_up)` (`at` from `ready_deadline`) | `tm_platform::timeout_at::<R>(at, bring_up)` |
| tm_control/src/lib.rs:781 | `tokio::time::sleep(backoff)` | `R::sleep(backoff)` |
| tm_control/src/lib.rs:714-1228, 1365-1458 | `tokio::time::Instant` for `ready_deadline`, `emit_at`, `idle_at`, `last_refresh`, `inflight`, `note_change`... | `tm_time::Instant` via `R::now()` (phase 5; tests at 2434, 2450 too) |
| tm_control/src/lib.rs:1490-1511 | biased `select!` (readable, cmds, `sleep_until_opt` x2) | `select4` in the same order; `sleep_until_opt` = `R::sleep_until` or `pending()` |
| tm_control/src/lib.rs:1524 | `tokio::time::timeout(d, noise.read_exact)` | `timeout::<R>(d, ..)` |
| tm_control/src/lib.rs:35, 1538 | `FromTokio<TcpStream>`, `TcpStream::connect((host,port))` | `N::Tcp`, `self.net.connect_host(host, port)` |
| tm_derp/src/lib.rs:330-334 | `sleep` + `tokio::pin!` + `select!` in a loop | `let mut s = pin!(R::sleep(..)); loop { match select(s.as_mut(), recv_next(..)).await {..} }` |
| tm_derp/src/lib.rs:384-389 | `TcpStream::connect` + `FromTokio` | `self.net.connect_host(host, port)` |
| tm_derp/src/lib.rs:427 | `select! { biased; cmd, read_frame_buffered }` | `select(recv_next(..), tls.read_frame_buffered())` (argument order = biased; same drop of the resumable read) |
| tm_wg/src/lib.rs:243-247 | `interval(TICK)` + `Delay` + `select!` | `Interval::<R>::new(TICK)` + `select(recv_next, ticker.tick())` |
| ~~tm_wg lib.rs, endpoint.rs, vendor macs/session/handshake/tai64n~~ | `std::time::{Instant, SystemTime}` | **done (phase 3, 6b4fda7)**: `tm_time::Instant`, `tm_time::unix_secs()` |
| ~~tm_disco/src/lib.rs:391, 534~~ | `Instant::now()` inside `process` | **done (phase 1, d467386)**: `process(.., now)` |
| tm_netstack/src/lan_udp.rs:301-318 | `tokio::time::Instant`, `sleep(POOL_POLL)`, `timeout_at(d, tx.send)` | `R::now()`, `R::sleep`, `timeout_at::<R>(d, tx.send(msg))` (drop semantics identical: message and PktBuf recycled) |
| lan_udp.rs:379-405 | `interval` + `select!` + `sleep(50ms)` | `Interval<R>`, `select(sock.recv_from, summary.tick())`, `R::sleep` |
| tm_netstack/src/lib.rs:53-113 | `UdpSocket` over tokio | moves to `tm_backend_tokio::TokioUdp: UdpTransport`, code unchanged |
| tm_netstack/src/lib.rs:118-160 | `todo!` host TCP stubs | delete (survey R-01b) |
| tm_runtime/src/lib.rs:63-104 | `RouterYield` (espidf only; clock is `tm_time` since phase 3), `tokio::task::yield_now` (48, 94, 104), `vTaskDelay` (100) | `RouterYield<R>` on all targets; `R::yield_now()`, `R::os_pause(1)` |
| tm_runtime/src/lib.rs:1486-1516 | `tokio_freertos_yield()` | `B::Reactor::os_pause(50)` |
| tm_runtime/src/lib.rs:222, 295, 438, 465 | `static LAN_SOCK: OnceLock<tm_netstack::UdpSocket>` | `net.bind_udp(..) -> &'static N::Udp`, passed to router and `udp_rx_task` |
| tm_runtime/src/lib.rs:397 | `sock.writable()` priming | `sock.ready()` |
| tm_runtime/src/lib.rs:561-562, 1184 | `tailnet::{bring_up, set_address, inject_inbound}` | `B::Tailnet::...` |
| tm_runtime/src/lib.rs:913 | `tokio::select!` over 5 receivers (random start) | `poll_fn(|cx| rotor.poll(cx, |i, cx| match i { 0 => ctrl.as_mut().poll_next(cx).map(In::Ctrl), .. }))`, then `match` outside the poll |
| tm_runtime/src/lib.rs:1462 | `select!` driver vs ready | `select(ready_rx.recv(), driver)` (ready first: prefer Ok on a tie) |
| tm_runtime/src/lib.rs:1592, 1600 | two cfg'd `tokio::join!` | one `join_array([..])`; `udp_task` is `Box::pin(async {})` when off, as already done at 1459 |
| ~~tm_buf/src/lat.rs; tm_runtime; src/config.rs~~ | std clocks | **done (phase 3)** |

Tests (`#[tokio::test]`, `LocalSet`, `tokio::spawn`) stay Tokio and become the Tokio half of the conformance suite.

## Embassy backend

**Versions** (verified on GitHub `embassy-rs/embassy`, 2026-10-01). Pin released crates; `main` is mid-migration:

| Crate | Use | Notes |
|---|---|---|
| embassy-executor 0.10.0 | `platform-std`, `executor-thread` | CHANGELOG dated 2026-03-10; repo has no v0.10.0 git tag (latest tag v0.9.1). 0.10 renamed `arch-*` to `platform-*`, made spawn-token creation fallible, added `run_until` for std. Task pools are static on stable since 0.8 (no arena features). |
| embassy-time 0.5.1 | `std` (tests: `mock-driver`) | both pull `tick-hz-1_000_000` + queue-utils; `MockDriver::advance` exists |
| embassy-time-queue-utils 0.3.2 | via embassy-time | `generic-queue-*` disables integrated timers by default (0.3.2); the app chooses |
| embassy-futures 0.1.2 | combinators (also used by the Tokio build) | already in the firmware lockfile |
| embassy-sync 0.8.0 | only via embassy-net | firmware has 0.7.2 via esp-idf-svc; no conflict (Embassy crate is not in that build) |
| embassy-net 0.9.1 | `tcp, udp, dns, medium-ip, proto-ipv4, embedded-nal` | **smoltcp 0.13**. `main` switched to xarxa (unreleased, git rev, driver API changed): do not track main |
| embassy-net-driver-channel 0.4.0, embassy-net-tuntap 0.1.1 | test links / manual demo | both on embassy-net-driver 0.2 (compatible with 0.9.1) |
| embedded-io-async 0.7 | `Net::Tcp` | already used by tm_derp/tm_control |
| embedded-nal-async 0.9 | not used as our interface | no `&self` try-send (investigation) |

**UDP try-send is feasible (verified, embassy-net 0.9.1 `src/udp.rs:139-285`).** `recv_from(&self, ..)`, `send_to(&self, ..)` and `poll_send_to(&self, buf, ep, cx)` all take `&self`. So `try_send_to` = `poll_send_to` with `Context::from_waker(Waker::noop())`: `Pending` maps to `WouldBlock`. It registers a no-op send waker, which is harmless because nothing else awaits sends on that socket. This closes an open item from the investigation.

**Backend sketch.**
- `EmbassyReactor`: `sleep_until` = `embassy_time::Timer::at(Instant::from_micros(d.as_micros()))`; `yield_now` = `embassy_futures::yield_now`; `os_pause` = `yield_now`.
- `tm_time` clock = `embassy_time::Instant::now().as_micros()`, so mock time drives both timers and `now()` consistently.
- `EmbassyNet { stack: embassy_net::Stack<'static> }` (Copy).
- `resolve` = `DnsSocket::new(stack).query(host, DnsQueryType::A)`. No thread, unlike Tokio's `spawn_blocking`.
- `connect_addr` = `TcpClient` from a static `TcpClientState<2, TX, RX>` (two sockets: control and DERP; buffer sizes are a decision).
- `bind_udp` uses a `StaticCell` for the socket and its metadata/payload buffers.

**What the platform must supply:**
- an embassy-time driver (std, mock, or on esp-hal `esp-rtos` 0.4's `embassy` feature);
- a running embassy-net `Stack` plus its `Runner` task;
- getrandom (std, or custom on esp-hal);
- a global allocator: tailmicro needs `alloc` for `Box::pin` actor futures, `async-channel`, `Arc` maps, boxed TLS buffers (`tm_derp/src/lib.rs:399-400`) and serde_json;
- a `critical-section` impl;
- a `TailnetIf`.

**App on Embassy (host):**
```rust
#[embassy_executor::task] async fn net_task(mut r: embassy_net::Runner<'static, Dev>) -> ! { r.run().await }
#[embassy_executor::task] async fn tailnet_task(d: tailmicro::Driver) { d.await; log::error!("driver ended") }
#[embassy_executor::main]
async fn main(spawner: embassy_executor::Spawner) {
    let (stack, runner) = embassy_net::new(dev, cfg, RES.init(StackResources::new()), seed);
    spawner.spawn(net_task(runner).unwrap());          // 0.10: token creation is fallible (inferred form)
    stack.wait_config_up().await;
    tm_backend_embassy::install_clock();
    let (dev, driver) = tailmicro::Device::connect_with::<EmbassyBackend<ChanTailnet>>(
        &config, auth, EmbassyNet::new(stack)).await.unwrap();
    spawner.spawn(tailnet_task(driver).unwrap());
}
```
- **Task constraints.** `#[task]` fns must be non-generic with `'static` arguments and a statically sized future (pool storage is static). `Driver` is a 'static, non-generic fat pointer, so `tailnet_task` is tiny; every actor stays on the heap behind `Box::pin`, so the static pool does not grow with actor sizes. `Driver` is `!Send`, which is fine for the thread executor (the `Spawner` is thread-local).
- **Generic code is never a task.** `connect_with::<B>` is awaited inside `main`, not spawned.
- **async-channel** wakes through `Waker`s only, so it works under any executor (std feature on host; `portable-atomic` without std per the investigation).
- **Yield.** Embassy re-queues a self-woken task behind the tasks already queued, so the `net_task` runner still gets polled between router iterations (inferred from the executor design, not read in source).

**What stays std/alloc-dependent:**
- Today all crates are std: `std::net` types (switchable to `core::net`), `std::sync::OnceLock` (tm_netstack device.rs:34, tm_buf lat), `serde_json` with `std` (tm_control `to_writer`), `tracing` with `std`, `ed25519-dalek` `std`, getrandom.
- `heapless` and embedded-tls 0.19 are already no_std; `async-channel` needs alloc.
- So **Embassy on host std is the realistic first target**: it needs no no_std work.
- **Embassy on esp-hal C3** (esp-hal 1.2.0 released 2026-09-03; esp-radio 1.0.0-beta.1 with embassy-net-driver 0.2 support; esp-rtos 0.4 with embassy-executor 0.10; esp-alloc 0.11) additionally needs:
  - survey section 5's no_std conversion (or `std` via esp-idf, which defeats the purpose);
  - a `TailnetIf` that is not lwIP: a second embassy-net `Stack` over `embassy-net-driver-channel`, fed by WG;
  - a fresh port of tasmolike's HTTP server off axum.
- **`arch-wasm`** (`platform-wasm`) is deferred as decided.

## Test strategy (no new hardware)

1. **Reactor conformance suite.** In `tm_testnet`, as `async fn`s generic over `R: Reactor`, run on both executors:
   - `sleep_until` ordering;
   - `timeout` firing and not firing;
   - `Interval` Delay semantics: immediate first tick, late-tick re-arm, cancel safety;
   - `yield_now` lets a sibling run;
   - `Rotor` fairness: with 5 always-ready arms, each wins within 5 polls.
   - **Executors:** Tokio `current_thread` with `start_paused` (test-util, auto-advance) vs embassy-executor `platform-std` + embassy-time `mock-driver`, driven by a `run_until` loop that calls `MockDriver::advance` when idle. In both, `tm_time` reads the virtual clock.
2. **Net conformance**, generic over `N: Net`:
   - TCP echo by address and by hostname;
   - `try_send_to` never awaits and reports `WouldBlock`;
   - `recv_from` source address;
   - `bind_udp` twice gives an error.
   - Run it against `TokioNet` on loopback, against `EmbassyNet` with two in-process embassy-net stacks joined by `embassy-net-driver-channel` (no root, no TUN; a tiny DNS responder on the server stack), and against `MemNet` (executor-agnostic pipes over async-channel).
3. **Actor scenarios on both executors**, using `MemNet` + `ChanTailnet`:
   - port the existing two-node WG test (tm_wg/src/lib.rs:585-626, `LocalSet`);
   - DERP reconnect and backoff (tm_derp:558);
   - control bring-up timeout (tm_control:1238).
4. **End-to-end loopback.** Run two full `Driver`s (node A, node B) against a fake control server and a fake DERP server in-process:
   - the fake control is a snow Noise IK responder + `/ts2021` upgrade + minimal H/2 + canned register/MapResponse; it needs a test control-pin key hook;
   - the fake DERP is plaintext, via the `DerpConn<S>` split from the investigation's phase 5;
   - scenario: both get IPs, A→B WG handshake via DERP, 100 ICMP-sized packets each way through `ChanTailnet`, a DERP drop and reconnect, and disco PING/PONG over UDP.
   - Run it once on `TokioBackend<MemNet>` and once on `EmbassyBackend` (MemNet, then embassy-net links).
5. **What proves equivalence:**
   - (a) the same suites pass unmodified on both;
   - (b) the e2e scenario yields the same ordered milestone trace (ControlEvent/DerpEvent/WgEvent kinds tapped at the router), the same set of payloads delivered (per-direction set equality, since cross-actor interleaving may legitimately differ), and the same counters: pool `allocs=0`, router drops 0, `LAN_UDP_STATS`.
   - Byte-for-byte transcripts are not expected (nonces, timestamps).
6. **Optional manual milestone:** `examples/embassy_tuntap.rs` joins a real tailnet through embassy-net-tuntap (needs a TUN device).

## Phased plan

Host check (H): `cargo test --offline -p tm_control -p tm_derp -p tm_wg -p tm_disco -p tm_keys -p tm_buf` (+ crates noted). Firmware check (F): `cd ../tasmolike-rs && cargo check --offline`. **D** = on-device validation required: main-stack HWM (~7.4 KB free today), heap minimum and largest block, `latency-trace` RTT, router drop counters, Step-12 soak.

| # | Scope (one commit) | Files | Risk | Effort | Verify |
|---|---|---|---|---|---|
| 0 | (Host gating DONE in 49c3cb2: deps gated, host `tokio_freertos_yield` = `yield_now`, workspace builds and tests on host.) Trim Tokio features (investigation phase 0); `tokio::pin!` → `core::pin::pin!`; move tm_runtime's esp-idf deps under `cfg(target_os="espidf")`; add host `tokio_freertos_yield` = `yield_now` | */Cargo.toml, tm_derp lib.rs:331, tm_runtime lib.rs:39 | none on device (espidf deps identical) | S | H + `cargo test -p tm_runtime -p tailmicro` on host for the first time; F |
| 1 | **DONE (d467386).** **Proving step:** `tm_time` + tm_disco `process(.., now)`; tests stop sleeping 110 ms | new tm_time, tm_disco | low | S | H; F |
| 2 | **DONE (a4f43ff).** Re-export `tailmicro::Driver` (no renames: `Runtime` keeps its name) | src/lib.rs | none | S | H; F (tasmolike unchanged) |
| 3 | **DONE (6b4fda7).** `tm_time` everywhere else (tm_wg incl. vendor diff, tm_runtime, tm_buf lat, config.rs). tm_control and lan_udp keep `tokio::time::Instant` until phase 5 (they are tied to tokio sleeps) | tm_wg, tm_runtime, tm_buf, src | low | M | H; F; D smoke: handshake + PONG, `size -A` endpoint |
| 4 | Combinators: `join_array`, `select`, `Rotor` router, `Interval` (still calling tokio sleep inside) | tm_runtime, tm_derp, tm_wg, lan_udp, new tm_platform (combinators only) | **frame shapes change** | M | H; F; **D full** |
| 5 | `Reactor` trait + `tm_backend_tokio::TokioReactor`; generic `WgActor<R>`, `DerpActor<R>`, `ControlActor<R>`, lan_udp, `RouterYield<R>`; tm_runtime fixes `R = TokioReactor` internally | tm_platform, new tm_backend_tokio, shells | low | M | H (+ conformance suite on Tokio, virtual time); F; D soak + reconnect backoff |
| 6 | `Net`/`UdpTransport`/`TailnetIf`/`Backend`; `TokioNet` (today's connect + UdpSocket moved verbatim), `LwipTailnet`; `connect::<B>`, `Device::connect_with`; LAN_SOCK into the backend | tm_platform, tm_netstack, tm_runtime, tm_backend_tokio, src | low-medium (static socket ownership) | M | H (+ Net conformance on Tokio); F; D: control + DERP connect, LAN PONG, heap minima |
| 7 | `DerpConn<S>` split + pluggable control upgrade + test pin hook | tm_derp tls.rs, tm_control | medium (handshake code) | M | H transcript tests; D live DERP + control |
| 8 | `tm_testnet`: MemNet, ChanTailnet, fake control/DERP, e2e scenario on Tokio | new crate (dev-only) | none (test only) | L | H |
| 9 | `tm_backend_embassy` (host std) + run suites 1-4 on it + one example app (`examples/`, same source built against `tm_backend_tokio` and `tm_backend_embassy`; replaces porting tasmolike) | new crate, root `embassy` feature | none for firmware (not in its graph) | M-L | H on both backends; F unchanged |
| 10 | (Conditional) Embassy on esp-hal C3: no_std conversion, embassy-net tailnet netif, new firmware | many | high | L | new device bring-up |

**Exit criterion "Embassy backend works":** phase 9 green, meaning:
- the conformance suites and the e2e scenario pass under `EmbassyBackend` with both `MemNet` and two-stack embassy-net links, with the equivalence criteria (5a, 5b) against the Tokio run;
- `cargo tree` of tasmolike shows no embassy-time/executor;
- the ESP32 Tokio soak after phases 4-6 matches the Step-12 baselines.

## Status (2026-10-02)

Phases 0-3 are committed on `simplification-survey` (49c3cb2, d467386, a4f43ff, 6b4fda7).
- **tm_time as built:** `Instant(u64 us)`, `set_clock`, `unix_secs`, std default (epoch = first use, via `OnceLock`). Additions to the sketch: `checked_sub`, `AddAssign<Duration>`, `saturating_duration_since` (std spelling, used by vendored code). The clock is two `AtomicUsize` function pointers (0 = unset; load/store only). Without the `std` feature and without `set_clock`, `Instant::now()` panics.
- **`process(.., now)` reads the clock once per datagram in `DiscoActor::run`**, before the decrypt. The PONG rate-limit timestamp is therefore taken up to one X25519 (about 46 ms on the C3) earlier than before; the 100 ms limit is unchanged.
- **`TAI64N::now()`** (unused on the device path; the endpoint feeds `now_from_unix`) now returns whole seconds from `tm_time::unix_secs()`.
- **Phase 5 note:** `tokio::time::Instant` and `tm_time::Instant` are different types and clocks. `TokioReactor::sleep_until(deadline)` should be `tokio::time::sleep(deadline.duration_since(Self::now()))` and `TokioReactor::now()` should read the same clock the virtual-time tests advance (`set_clock` to tokio's paused clock in those tests), otherwise `start_paused` conformance tests and the production clock disagree.

## Risks

- **Phase 4 frame shapes.** ALLOCATIONS records frames overflowing the 32 KB main stack after innocuous refactors (MIR inlining at `opt-level="z"` + LTO). Keep `#[inline(never)]` + `Box::pin` boundaries and measure the HWM per phase.
- **Router fairness differs per backend.** Tokio keeps its random start, so the device is unchanged. Embassy and `tm_testnet` use the round-robin `Rotor`, which is deterministic and starvation-free, but its latency distribution differs: re-measure Step 9 RTT on the Embassy side, and keep the shared example app on both backends as the divergence check. A bug seen under overload on one backend may not reproduce on the other; reproduce it under `tm_testnet` first.
- **`yield_now` semantics differ.** Tokio defers the wake until after I/O polling; Embassy does not, though its net runner is a separate task. Equivalent only by argument; the e2e test under load is the check.
- **Generic `async fn` in traits** has no `Send` bounds. Fine for single-thread, but it forbids a multi-thread Tokio host backend later; that is acceptable by design.
- **Timer state.** `Interval<R>` puts a ~100 B sleep inline in the WG and lan_udp frames instead of on the heap.
- **Embassy upstream churn.** The xarxa migration on `main` changes `UdpSocket::bind` and the drivers. Pinning 0.9.1 ages fast. executor 0.10.0 has no git tag (unusual; check crates.io before pinning).
- **Fake control server effort.** It is a sizable test asset (Noise responder, H/2, map JSON, pin hook); a pin bypass must not leak into release builds (gate it behind `cfg(test)` or a test feature).
- **TCP buffers in .bss.** embassy-net TCP buffers (two sockets x (RX+TX)) are static RAM on a future C3 port. That trades heap for fixed RAM, like the PktBuf pool.
- **DNS divergence.** Tokio keeps `spawn_blocking` DNS (pthread per lookup, unmeasured); Embassy's DnsSocket does not. Equivalent results, different resource profile.

## Decisions for the maintainer

1. ~~Rename `Runtime`~~ Decided: keep `Runtime`; the trait is `Reactor`, the bundle stays `Backend`.
2. Crate names: `tm_platform`, `tm_backend_tokio`, `tm_backend_embassy`, `tm_time`, `tm_testnet` (or fold `tm_time` into `tm_platform`)?
3. Is `tokio` a default feature of `tailmicro` (zero firmware change), or explicit?
4. ~~Router fairness~~ Decided: fairness is per reactor. The contract is "no ready arm starves". The Tokio backend keeps tokio's `select!` (random start), so the device behaviour does not change. The Embassy backend and `tm_testnet` use the deterministic `Rotor` (embassy-futures `select` polls arms strictly in order and `no_std` has no RNG; the testnet needs reproducible runs). The shared example app runs on both backends to catch divergence under overload. How the router reaches the backend's primitive (a `Reactor` method or associated type) is a phase 4 detail; it must not grow the router future on the Tokio path.
5. Pin embassy-net 0.9.1 (smoltcp) now, or wait for a xarxa release?
6. Embassy target after host: esp-hal C3 (accepts no_std work + new netif + leaving lwIP/axum), another chip, or host only?
7. How much to invest in the fake control server (phase 8), versus actor-level suites only plus a manual tuntap run against the real tailnet?
8. Should the Tokio backend later replace `spawn_blocking` DNS with a non-threaded resolver (and WG's 400 ms tick with `sleep_until(next_event())`)?
9. TCP buffer sizes for `EmbassyNet` (control and DERP).

## Not verified

- No source was changed and nothing was built except a throwaway size probe (host x86_64 debug; riscv32 and release sizes not measured).
- The embassy-executor wake-ordering claim and the exact 0.10 `spawn` call form are inferred from the CHANGELOG, not read in source.
- Whether embassy-time `mock-driver` + `run_until` gives a clean auto-advance loop is not prototyped.
- That `tm_runtime` host-builds after phase 0 is inferred: the gating is clear, but other espidf-only symbols may surface.
- GitHub reads (`gh api`, `main` and tags, 2026-10-01):
  - embassy-rs/embassy: executor, time, time-queue-utils, sync, net and driver-channel CHANGELOG/Cargo.toml; `embassy-net/src/udp.rs` at tag `embassy-net-v0.9.1`;
  - esp-rs/esp-hal: crate versions and releases.
- crates.io was not consulted.
