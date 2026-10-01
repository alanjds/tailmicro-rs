# Investigation: making Tailmicro independent of Tokio

Branch `simplification-survey` at `11b6970`, 2026-10-01. Read-only: no source was changed. Line numbers refer to that commit. "Verified" means read in source, either local (`~/.cargo/registry`, `~/.cargo/git`) or on GitHub via `gh api`. "Inferred" means reasoned, not checked.

## Summary and recommendation

The Tokio surface is small: about 25 non-test call sites in 6 crates. `tm_disco` already has no Tokio code, and Tokio is used for only five things: timers, `select!`/`join!`, `yield_now`, `TcpStream::connect` and `UdpSocket`. Nothing is spawned, and `Driver` is already a plain `!Send` boxed future. So the decoupling is mechanical, with two exceptions where behavior can change:
- `yield_now`. Tokio's version defers the wake until after the I/O driver has been polled.
- `select!` fairness. The router's `select!` picks a random branch first each time.

**Go**, for phases 0 to 4. Each one is cheap and leaves the ESP32 build the same, because the Tokio backend reuses today's code. tasmolike keeps Tokio regardless (axum), so this saves no RAM or flash on the device. What it buys is portability and deterministic time in tests.

**No-go for now** on the actual Embassy and WASM backends until a product needs them. Embassy on the ESP32-C3 is blocked on the lwIP netif axis. Browser WASM is feasible only for a DERP-only subset.

Injection: static generics plus a global clock, not `dyn` and not mutually exclusive cfg features.

## Tokio touchpoint catalog (non-test code)

| Class | File:line | API |
|---|---|---|
| time | tm_control/src/lib.rs:464 | `tokio::time::timeout` (bring-up deadline) |
| time | tm_control/src/lib.rs:519 | `tokio::time::sleep` (reconnect backoff) |
| time | tm_derp/src/lib.rs:330-331 | `tokio::time::sleep` + `tokio::pin!` |
| time | tm_wg/src/lib.rs:242-243 | `tokio::time::interval(400 ms)`, `MissedTickBehavior::Delay` |
| time | tm_netstack/src/lan_udp.rs:301-318 | `tokio::time::Instant`, `sleep(POOL_POLL)`, `timeout_at(d, tx.send)` |
| time | tm_netstack/src/lan_udp.rs:379-380, 405 | `interval(SUMMARY_PERIOD)` + `Delay`, `sleep(50 ms)` |
| combinator | tm_runtime/src/lib.rs:810 | `tokio::select!` over 5 receivers (unbiased, so random start) |
| combinator | tm_runtime/src/lib.rs:1360 | `tokio::select!` (`race_driver_vs_ready`) |
| combinator | tm_runtime/src/lib.rs:1490, 1498 | `tokio::join!` of 5 or 6 `BoxActorFut` (the `Driver`) |
| combinator | tm_derp/src/lib.rs:334, 427 | `tokio::select!` (backoff vs cmd; `biased;` cmd vs `read_frame_buffered`) |
| combinator | tm_wg/src/lib.rs:246 | `tokio::select!` cmd vs ticker |
| combinator | tm_netstack/src/lan_udp.rs:384 | `tokio::select!` `recv_from` vs summary tick |
| yield | tm_runtime/src/lib.rs:86, 96 | `tokio::task::yield_now` (`RouterYield`, `freertos_yield_ticks`) |
| net TCP + DNS | tm_control/src/lib.rs:33, 929-931 | `tokio::net::TcpStream::connect((host, port))` → `FromTokio` |
| net TCP + DNS | tm_derp/src/lib.rs:384-389 | same, DERP leg |
| net UDP | tm_netstack/src/lib.rs:53-113 | `tokio::net::UdpSocket::{from_std, bind, send_to, writable, try_send_to, recv_from}` |
| net (host-only stubs) | tm_netstack/src/lib.rs:118-160 | `tokio::net::{TcpStream, TcpListener}`, `AsyncReadExt` (`todo!` APIs, survey R-01b) |
| io traits | tm_control/src/lib.rs:33; tm_derp/src/lib.rs:384 | `embedded_io_adapters::tokio_1::FromTokio` (the only Tokio type in signatures) |
| sync | none | No `tokio::sync` use anywhere. All channels are `async_channel`. |
| spawn | none | Only in tests (tm_control 1156, tm_derp 565, tm_wg 600-603 `LocalSet`) |
| macros/attrs | tests only | `#[tokio::test]` |

Tokio features enabled per crate (non-dev), with what is actually needed:

| Crate | Enabled | Actually needed |
|---|---|---|
| tm_control | `sync, io-util, net, time` | `net, time` (no `sync`/`io-util` use) |
| tm_derp | `sync, macros, time` (+`net` via `etls`) | `macros, time, net` |
| tm_disco | `sync` | **none**: the dependency is unused |
| tm_wg | `sync, time, macros` | `time, macros` |
| tm_runtime | `sync, rt, macros` | `rt` (`yield_now`), `macros` |
| tm_netstack | `net, io-util, time, macros` | `net, time, macros` (`io-util` only for the host stubs) |
| root `tailmicro` | none | none (docs only; `tokio_freertos_yield` re-export) |

Runtime-implicit dependencies:
- **Timer driver.** Every `tokio::time` future needs the app's runtime to be built with `enable_time` (tasmolike uses `enable_all`).
- **Reactor.** `UdpSocket::bind_sync` calls `from_std`, which registers with the current reactor, so it must run inside a runtime. `bind_lan`'s doc says so.
- **Writable priming.** `udp_rx_task` awaits `writable()` once because `try_send_to` reads cached readiness (tm_runtime/src/lib.rs:386).
- **DNS uses a thread.** Verified in tokio-1.53.1 `src/net/addr.rs:197-219`: `connect((&str, u16))` with a hostname resolves through `spawn_blocking`. On ESP-IDF that means a blocking-pool *pthread* per resolution, kept alive after the call. Control (`controlplane.tailscale.com`) and DERP (`derpN.tailscale.com`) are both hostnames. The pthread's stack is heap that ALLOCATIONS.md does not account for (inferred; not measured).
- **`yield_now` semantics.** Verified in tokio-1.53.1 `src/task/yield_now.rs`: it calls `context::defer(waker)`, so the wake happens only after the scheduler has polled the I/O and timer driver. The whole `Driver` is one Tokio task, so this is what lets lwIP readiness be observed between router iterations.
- **`std::time` (not Tokio, but runtime-adjacent):**
  - `Instant`: tm_wg/src/lib.rs:30 and 7 sites; endpoint.rs signatures; vendor `macs.rs:86, 112` (calls `Instant::now()` internally); `session.rs`; `handshake.rs`; tm_disco/src/lib.rs:36, 391, 534 (inside `process`); tm_runtime `RouterYield` (63-82, espidf only) and the fault test (409); tm_buf/src/lat.rs:65-81.
  - `SystemTime`: tm_wg `now_unix` (560); vendor `tai64n.rs:37, 117`; src/config.rs:42 (pin expiry).
  - Both **panic on `wasm32-unknown-unknown`** (std has no clock there).
- **Platform, not runtime.** `vTaskDelay`, heap probes, `std::sync::mpsc` in `tailnet/device.rs:301`, and `OnceLock` statics.

## Replacement options per class (with cost)

**Combinators.**
- `embassy-futures` 0.1.2 (verified locally) offers `select` … `select6`, `select_array`, `join` … `join5`, `join_array` and `yield_now`.
  - It is `no_std` with zero deps, and it is already in the firmware tree (esp-idf-svc depends on it unconditionally).
  - `select*` polls in argument order. That is exactly DERP's `biased;`.
  - `Driver` is six futures of the same type `BoxActorFut`, so `join_array([..; 6])` replaces both `join!` arms. That also removes the cfg-duplicated join (survey A-04).
- `futures-lite` 2.6.1: `or` is biased; `race` is random but pulls in `fastrand`.
- The router needs care. `tokio::select!` is unbiased (random start), and a biased `select5` could let a busy control or netif receiver starve the others. Best replacement: a hand-written `poll_fn` that polls the 5 `Stream`s from a rotating start index. It is about 25 lines, has no macro and no allocation, and gives deterministic fairness.
- `timeout` = `select(fut, sleep(d))`. Cost: none; the futures sit in place, as in Tokio.

**Time.** Three options:
- (a) **embassy-time 0.5.1** (verified Cargo.toml).
  - It has `std`, `wasm` and `mock-driver` drivers, and esp-idf-svc (rev dd79433, `src/timer.rs:393-513`, feature `embassy-time-driver`) ships an `esp_timer`-backed driver.
  - Under a non-Embassy executor it needs `embassy-time-queue-utils/generic-queue-N`; the default integrated queue requires embassy-executor wakers. The app has to choose N, and a library must not (verified, queue-utils Cargo.toml).
  - `Ticker::next` does `expires_at += period`. That is Tokio's `Burst`, not the `Delay` that tm_wg and lan_udp use.
  - On ESP32 this adds a second timer service (an `esp_timer` task waking Tokio from another thread). That is plausible, since lwIP's callback already wakes it cross-thread, but it is new and must be measured.
- (b) **A local `Rt` trait** with a Tokio backend that calls exactly today's functions. Zero change on ESP32.
- (c) **A global clock** for `now()`. The vendored WG code calls `Instant::now()` internally, so a value passed in by the shell does not cover every site. A `tm_time::Instant(u64 µs)` newtype plus a once-set `fn() -> u64` clock and a `fn() -> Option<u64>` Unix clock covers all three runtimes. On a host with std it can default to `std::time::Instant`.
- **Recommended:** (c) for `now`, and (b) for `sleep`/`sleep_until`/`yield_now`. The Embassy and WASM backends of (b) can use embassy-time internally.
- Interval semantics: implement `Delay` as `sleep_until(last + period)` with re-arm from `now`. Do not adopt `Ticker`.

**Yield.** It must be a backend method, not `embassy_futures::yield_now`:
- Tokio: `tokio::task::yield_now` (the defer semantics above).
- Embassy: `embassy_futures::yield_now`. The embassy-net runner is a separate task, so it still runs.
- Browser: it must yield to a *macrotask* (`setTimeout(0)`/`MessageChannel`). wasm-bindgen-futures schedules on the microtask queue, so a self-waking loop would starve WebSocket `onmessage` (inferred; not verified in source).
- The FreeRTOS `vTaskDelay` stays a platform hook.

**Net.**
- **embedded-nal-async** 0.9.0 (verified) has `TcpConnect` (by `SocketAddr`), `Dns` and `UdpStack`. But `UnconnectedUdp::send`/`receive_into` take `&mut self`, so one socket cannot be shared between the receive loop and the router. It also has no non-blocking `try_send`, which the router requires (it must never await, ALLOCATIONS Step 7).
- **embassy-net** implements only `TcpConnect` and `Dns`, behind feature `embedded-nal`. Its `UdpSocket` does not implement `UdpStack` (verified: `nal` appears only in `tcp.rs` and `dns.rs`).
- **edge-nal** 0.7.0 (ivmarkov/edge-net, active) adds `UdpSplit`, but its std implementation is async-io (a second reactor). Reject for ESP.
- **Recommended:** a small local `Net` trait:
  - `async fn connect(&self, host: &str, port: u16) -> Result<Self::Tcp>` with `Tcp: embedded_io_async::Read + Write`. DNS is folded in, which also suits WebSocket URLs.
  - A UDP socket trait: `fn try_send_to(&self, ..)`, `async fn recv_from(&self, ..)`, `async fn writable(&self)`.
  - The Tokio backend is today's `tm_netstack::UdpSocket` plus `FromTokio<TcpStream>`.
  - An Embassy backend can wrap embassy-net (`TcpClient`/`DnsSocket`, plus `UdpSocket::send_to` behind a `poll_once`-style try-send; not verified that this is possible without `&mut`).

**I/O traits.** `embedded-io-async` 0.7 is already adopted. The only Tokio leak is `type TokioStream` in tm_control/src/lib.rs:33, and that becomes the `Net::Tcp` associated type.

**Channels and sync.** `async-channel` 2.5.0 is runtime-agnostic. Without `std` it builds with `portable-atomic`, and it works on wasm. Keep it; embassy-sync static channels remain survey A-02 (orthogonal). `critical-section`/`portable-atomic` are already used by tm_buf.

**Spawning.** Not needed. `Driver` is `Pin<Box<dyn Future<Output = ()>>>` without `Send`:
- Tokio: polled inside the app's `try_join!`.
- Embassy: a non-generic `#[embassy_executor::task] async fn run(d: Driver)`. That needs `alloc`, which tailmicro already uses.
- Browser: `wasm_bindgen_futures::spawn_local`.

**Injection mechanism.**

| Option | Code size | Future/stack size | Heap | Ergonomics |
|---|---|---|---|---|
| Generic `R: Rt, N: Net` (static) | One instantiation per binary, so equal to today | Same concrete futures as today on Tokio | none | Type params on `run` fns and the `spawn_*` helpers; `#[inline(never)]` + `Box::pin` still work on generic fns, and `BoxActorFut` erases them |
| `dyn` traits | Smaller in theory | Async `dyn` methods need `Box<dyn Future>` **per sleep/connect** | Allocates per call, against ALLOCATIONS "design principle" | Easy |
| cfg features (`rt-tokio` / `rt-embassy`) | Equal to today | Equal | none | Mutually exclusive features are non-additive in Cargo, so two dependents can break each other; acceptable only inside a leaf "backend" crate |

Use generics on the shells, keep pure cores non-generic (`WgEndpoint`, disco `process`), and put backends in separate crates (`tm_rt_tokio`, later `tm_rt_embassy`, `tm_rt_wasm`) so features stay additive.

## WASM reality

- **Realistic scenario:** a browser on `wasm32-unknown-unknown` with wasm-bindgen. Tailscale ships exactly this: `cmd/tsconnect/wasm` is cited in `derp/derpserver/websocket.go`.
- **WASI:** possible in principle via wasi-sockets, but there is no reference client (not verified). Wasm-in-a-host just means the host supplies the `Net` trait.
- **DERP over WebSocket: verified.**
  - Client: `derp/derphttp/websocket.go` (build tag `js`) dials with subprotocol `"derp"`.
  - Server: `derp/derpserver/websocket.go` `AddWebSocketSupport` accepts `Upgrade: websocket` + `Sec-WebSocket-Protocol: derp` with `OriginPatterns: ["*"]`, compression off, then the normal `s.Accept`. `cmd/derper/derper.go:271` always wraps `/derp` with it.
  - The DERP binary framing runs unchanged over the WS byte stream. The browser does the TLS, so **embedded-tls and our HTTP `Upgrade: DERP` exchange drop out**.
  - That Tailscale-run DERP nodes run stock derper is inferred.
- **Control plane: client side verified.** `control/controlhttp/client_js.go` dials `wss://<host>/ts2021?X-Tailscale-Handshake=<base64 Noise init>` with subprotocol `tailscale-control-protocol`.
  - `controlhttpserver.go:53-164` accepts it (`OriginPatterns: ["*"]`).
  - Differences from our `noise.rs` path: the init goes in the query string instead of a header, and there is no `101` to parse (the browser handles it). Everything after it (Noise transport and H/2) is the same.
  - **Unknown:** whether the closed-source `controlplane.tailscale.com` uses this package. Strong evidence that it does: tsconnect, the browser SSH console, works against it. Not tested here.
- **UDP, disco over UDP, LAN-direct:** not available in browsers. Disco would be DERP-only, and `lan-direct` must be off (it is already a cargo feature).
- **Crypto:** RustCrypto and dalek are pure Rust and build for wasm32.
  - `rand_core` 0.6 → `getrandom` 0.2.17, which needs feature `js` on `wasm32-unknown-unknown` (verified, lib.rs:79-85). The app enables it.
  - embedded-tls is not needed.
- **Time:** `std::time::Instant`/`SystemTime` panic there, so the global clock (phase 1) is a hard prerequisite.
- **Workable browser subset:**
  - control register/map, DERP, WireGuard, and disco via DERP;
  - **no netstack**: the app gets raw IP packets, and needs smoltcp or similar to do TCP. That is the netstack axis.

## Embassy reality

- **Versions.** The released embassy-net 0.9.1 (tag, 2026-04-16) is smoltcp-based. `main` moved to embassy's own **xarxa** stack (git rev, Sept 2026, unreleased), so the API is in flux. It provides TCP/UDP/DNS sockets; `TcpClient` and `DnsSocket` implement embedded-nal-async 0.9 `TcpConnect`/`Dns` (feature `embedded-nal`).
- **Where Tailmicro plugs in.** A `tm_rt_embassy` backend:
  - `Rt` via embassy-time;
  - `Net` via embassy-net sockets with static rx/tx buffers;
  - `Driver` run as one task.
- **Embassy on ESP32-C3 means esp-hal plus the esp-wifi radio**, not ESP-IDF. That drops lwIP, so `tm_netstack::tailnet` (lwIP netif FFI) must be replaced. The natural fit is a second embassy-net `Stack` over `embassy-net-driver-channel` (crate exists in the repo), fed by WG.
- **The runtime-agnostic work does not depend on that.** Phases 0-5 are verifiable on ESP-IDF + Tokio and on host. Only phase 7 needs the netstack axis.
- **ESP-IDF specifics** (heapdiag, `vTaskDelay`, eFuse) stay behind `cfg(target_os = "espidf")` as today.

## Sans-IO assessment per actor

| Actor / seam | Today | Distance to sans-IO | Verdict |
|---|---|---|---|
| `WgEndpoint` (tm_wg/endpoint.rs) | `recv_one_into(raw, from, now, out)`, `send_data(.., now, out)`, `dispatch(now, now_unix)`, `next_event() -> Option<Instant>` | **Already sans-IO**, except vendor `macs.rs:86, 112` calling `Instant::now()` | Keep; the global clock fixes the rest. `WgActor` becomes a ~40-line shell; `sleep_until(next_event())` could replace the 400 ms tick (survey Q6) |
| Disco (`DiscoActor::process`) | Pure function of `(src, data)` plus internal `Instant::now()` (391, 534) | One parameter | Add `now`; the shell is `recv → process → send`, with no timers |
| DERP framing (`DerpTls::read_frame_buffered`, resumable header/body state) | Generic over `embedded_io_async`, but TLS, HTTP upgrade and DERP handshake are fused in `connect` (tls.rs:126-219) | Medium. embedded-tls has no sans-IO API, so the TLS part cannot be | Split into `DerpConn<S: Read + Write>` (handshake + framing over any stream) plus transport openers (etls+upgrade on device, WS in browser). The decoder could go sans-IO later; not needed |
| Control (Noise `NoiseChannel`, `do_noise_handshake`, tm_h2 codec, actson `map_stream` push parser) | Generic over `Read + Write`; codecs (tm_h2, map_stream) are already pure | Far: a long sequential protocol (TCP → upgrade → Noise → H/2 → register → stream → reconnect) | **Do not** state-machine it. Make the upgrade step pluggable (HTTP/1.1 header vs WS query) and keep async/await |
| Router (`event_router_task`) | Event → commands mapping mixed with logging, `try_send` and yields | Medium | Optional: extract `fn route(ev, &mut state) -> heapless::Vec<Cmd, N>` for host tests; the shell keeps select + yield |
| lan_udp (`classify`, `forward_backpressured`, `rx_loop`) | `classify` pure; the rest is timing policy | n/a | Generic over `Rt` + UDP trait |

Conclusion: sans-IO is the right shape **only where it already exists** (WG, disco, codecs). For control and DERP, trait injection is cheaper and keeps the stack-tuned async structure ALLOCATIONS.md depends on. A hybrid is the answer: pure cores plus thin generic shells.

## Phased plan

Each phase is a separate merge. Host check: `cargo test --offline -p tm_control -p tm_derp -p tm_wg -p tm_disco -p tm_keys -p tm_buf` in tailmicro-rs. Device check: `cd ../tasmolike-rs && cargo check --offline`.

| # | Phase | Effort / risk | Verification |
|---|---|---|---|
| 0 | Trim the Tokio manifests: remove tm_disco's unused `tokio` dependency; drop `sync` everywhere and `io-util` in tm_control; `tokio::pin!` → `core::pin::pin!` | S / none | host + check |
| 1 | **Design proof.** `tm_time` (leaf, `no_std`-ready): `Instant(u64 µs)`, `Duration` from core, global `now()`/`unix_secs()` set once (std default). Convert tm_disco first (`process(.., now)`; tests stop using `thread::sleep(110 ms)`, tm_disco/src/lib.rs:1089), then tm_wg endpoint, vendor and `now_unix`, and config.rs | S-M / low (vendored diff) | host; on device: handshake + disco PONG smoke, `RecvOut`/endpoint sizes unchanged (`size -A`) |
| 2 | Combinators: `join_array` for `Driver`; `embassy_futures::select` for DERP, WG, lan_udp and `race_driver_vs_ready`; rotating-fair `poll_fn` for the router | M / **[ALLOC]**: frame shapes change | host; **device**: main-stack HWM (now ~7.4 KB free), `latency-trace` RTT, router drop counters, Step-12 multi/soak |
| 3 | `Rt` trait (`sleep`, `sleep_until`, `yield_now`) in a `tm_rt` crate plus `tm_rt_tokio` that calls today's functions; make `WgActor`/`DerpActor`/`ControlActor::run`, lan_udp and `RouterYield` generic | M / low | host (a mock `Rt` enables virtual-time tests); **device**: 10-min soak, reconnect backoff |
| 4 | `Net` trait (TCP by host, shared UDP). The Tokio backend holds `FromTokio<TcpStream>` and `tm_netstack::UdpSocket`. Optionally replace `spawn_blocking` DNS with a non-threaded resolver later | M / low | host loopback tests; **device**: control + DERP connect, LAN-direct PONG, heap minima |
| 5 | Split `DerpTls` into `DerpConn<S>` plus an opener; make the control upgrade pluggable | M / medium (handshake code) | host transcript tests; **device**: live DERP + control |
| 6 | (Conditional) `tm_rt_wasm` browser PoC: WSS control + DERP, packets to JS | L | browser against a test tailnet; first answers the controlplane-WS question |
| 7 | (Conditional) `tm_rt_embassy` on esp-hal + embassy-net and a tailnet `driver-channel` netif | L / needs netstack axis | new device bring-up |

The cheapest step that proves the design is phase 1 on tm_disco alone. It touches one crate, has no Tokio in its code already, makes its rate-limit tests deterministic, and validates the global-clock pattern before the vendored WG code is touched. Phase 3 on `WgActor` (ticker + select) is the first proof of the `Rt` generic.

## Not worth doing

- `dyn` runtime traits: they allocate per sleep or connect.
- Mutually exclusive `rt-*` features in shared crates.
- embedded-nal-async or edge-nal as *our* UDP interface (no `&self` try-send).
- Removing Tokio from tasmolike: axum needs it.
- Moving ESP32 timers to embassy-time + esp_timer as an early step: it changes behavior without any payoff.
- Sans-IO rewrites of `ControlActor`, Noise or embedded-tls.
- A generic spawn abstraction: there is no spawn.
- Replacing async-channel for runtime reasons: it is already agnostic.

## Open questions

1. Is a browser or Embassy client an actual product goal? If not, stop after phase 4.
2. Does `controlplane.tailscale.com` accept `/ts2021` over WebSocket? This is inferred from tsconnect, not tested.
3. How much heap does each DNS `spawn_blocking` pthread cost on ESP-IDF (`CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT`), and how long does it live?
4. Should the WG 400 ms tick become `sleep_until(next_event())` once `Rt` exists? That needs a power measurement.
5. Embassy target: esp-hal C3, or other chips? xarxa's API stability decides when to start phase 7.

## Not verified

- Nothing was built or measured. Future-size claims, and the pthread stack cost, were not checked with `-Zprint-type-sizes`, `size -A` or heapdiag.
- The wasm-bindgen-futures microtask scheduling, embassy-net `UdpSocket` try-send feasibility, WASI sockets status, and whether Tailscale's hosted DERP and control servers run the open-source WS handlers are all inferred.
- GitHub reads were at `main` on 2026-10-01 for tailscale/tailscale, embassy-rs/embassy, rust-embedded-community/embedded-nal and ivmarkov/edge-net.
- The local sources read were tokio-1.53.1 (tasmolike actually patches tokio to git `master`; assumed equivalent for `yield_now` and `addr.rs`), embassy-futures-0.1.2, futures-lite-2.6.1, async-channel-2.5.0, getrandom-0.2.17 and esp-idf-svc rev dd79433.
