# Heap allocation notes

Working log of heap-allocation opportunities on the ESP32-C3 data plane
(~128 KB usable heap). Goal: fewer, same-sized, less-frequent allocations —
the device has plenty of *total* free memory most of the time, but crashes
with `memory allocation of N bytes failed` because repeated alloc/free of
differently-sized blocks on the hot path fragments the heap until no
contiguous block of the needed size remains.

Diagnosed 2026-09-24 from `/home/alanjds/tasmolike-serial.log`: the device
answers a couple of `/cm?cmnd=status+2` requests fine, then aborts. The
overwhelming majority of crashes across all boot sessions in that log are
`memory allocation of 6052 bytes failed` (14 of ~24 aborts) — 6052 B is the
exact size of `tm_wg::endpoint::RecvOut` (`2 * ArrayVec<Packet, OUT_CAP=2>`
i.e. `2 * 2 * 1500 B` + small fields).

## Fixed

- **`tm_wg::WgActor` — `RecvOut` re-boxed on every packet/send.**
  `on_inbound` and `on_send_data` did `Box::new(RecvOut::default())` on
  *every* inbound packet and every outbound send, then dropped it right
  after `drain_recv`. Combined with axum's own small variable-sized
  allocations per HTTP request, this was the main fragmentation driver.
  Fix: `WgActor` now owns a persistent `recv_scratch: Option<Box<RecvOut>>`,
  allocated once on first use (`take_scratch`/`return_scratch`, mirroring
  the existing lazy `WgEndpoint` pattern) and reset in place
  (`RecvOut::reset`) instead of freed and reallocated. Zero heap traffic on
  this path after the first packet/send.
  (`tm_wg/src/lib.rs`, `tm_wg/src/endpoint.rs`)

- **`tm_wg::WgActor::on_tick` — `dispatch()` output re-boxed every tick
  (~400 ms).** `Box::new(self.endpoint().dispatch(now, now_unix()))` boxed a
  fresh `ArrayVec<(PeerId, Packet), DISPATCH_CAP>` (`DISPATCH_CAP = 4` ->
  ~6 KB, same size class as `RecvOut`) every tick regardless of HTTP
  traffic, so it fired independently of (and could coincide with) any
  `status`-triggered churn. Fix: same scratch-reuse pattern as `RecvOut` —
  `WgActor` now owns `dispatch_scratch: Option<Box<DispatchOut>>`
  (`endpoint::DispatchOut` is a new public alias for the `dispatch()` return
  type so `lib.rs` can name it), taken/returned around each tick and
  overwritten in place (`*outbound = self.endpoint().dispatch(...)`) instead
  of boxed fresh. Verified on real hardware (2026-09-26): repeated `status 0`
  polling while the dataplane was active no longer produces `memory
  allocation of 6052 bytes failed` — that specific failure mode is gone.
  (`tm_wg/src/lib.rs`, `tm_wg/src/endpoint.rs`)

- **Cross-actor packet buffers — one size, forwarded instead of copied.**
  (Step 0 in the design record below; commit `8201cd3`.) Every channel
  that carries a packet (`DerpEvent::PacketReceived`, `DerpCmd::SendPacket`,
  `WgCmd::InboundPacket`/`SendData`, `WgEvent::OutboundPacket`/
  `InboundDecrypted`, `DiscoCmd::MaybeDisco`, `tailnet::OutboundPacket`)
  now uses the one buffer type from the new leaf crate `tm_buf`
  (`PKT_CAP = 1532`, the old `MAX_DERP_PAYLOAD`; previously 1532 / 1500 /
  256 depending on the crate). `tm_runtime::event_router_task` moves the
  buffer it received on to the next actor instead of copying it into a
  fresh box of a different size — in both the DERP -> wg/disco demux and
  the `WgEvent::OutboundPacket` -> `DerpCmd::SendPacket` hop (and in the
  `Runtime::spawn` router duplicate). Side fix: `tm_wg::on_inbound` /
  `on_send_data` now drop packets over `Packet::CAPACITY` / `MAX_INNER`
  instead of reaching the vendored `Packet` constructors' `expect()`
  panics, since the channel buffer is wider than the WireGuard one.
  (`tm_buf/`, `tm_derp/src/lib.rs`, `tm_runtime/src/lib.rs`,
  `tm_wg/src/lib.rs`, `tm_disco/src/lib.rs`, `tm_netstack/src/tailnet/`)

- **Cross-actor packet buffers — pooled `PktBuf` with RAII return.**
  (commits `d1607a8`, `b392722`; storage moved to a static `heapless`
  pool in `7e37f10`, `b72e7a3`.) The channel buffer is `tm_buf::PktBuf`,
  a two-word owner of one `PKT_CAP` buffer. Producers — `tm_derp`'s
  `RecvPacket` handling, `tm_wg::pkt_to_buf` (used by `drain_recv` and
  `emit_to_peer`), the lwIP netif output callback, the rung-6a ICMP echo —
  call `PktBuf::acquire()`/`from_slice()`; dropping the `PktBuf` returns
  the buffer.
  - *Storage.* `POOL_N = 4` buffers live in a `static [ObjectBlock<_>; 4]`
    (`.bss`, ~6 KB, not heap-allocated, though `.bss` is carved from the
    same internal DRAM, so it still shrinks the heap by that much) handed once to a
    `heapless::object_pool!` (heapless 0.9's lock-free, ABA-tagged Treiber
    stack). `acquire` pops one; `Drop` clears it and pushes it back. With
    the pool empty, `acquire` falls back to one counted heap `Box` (the old
    behavior, same size), freed on drop. `WgActor::apply_map` calls
    `tm_buf::prewarm()` (logs `packet-buffer pool ready: 4 static
    buffers`), which now allocates nothing; the first `acquire` would do
    the same.
  - *Why it replaced the first version* (`Mutex<heapless::Vec<Box<..>, 4>>`
    of heap boxes): the buffers no longer occupy heap at all (the heap
    boxes were carved at `prewarm` time, mid-heap), and there is no
    hand-written locking; the pool is `heapless`'s code.
  - *Atomics.* riscv32imc has no native 64-bit atomics, which heapless's
    32-bit tagged-pointer CAS needs, so the workspace `heapless` is now
    `0.9` with `default-features = false, features =
    ["portable-atomic-critical-section"]` (`tm_tls` switched to
    `heapless.workspace = true`), and `tm_buf` enables
    `critical-section/std` (a `std::sync::Mutex`-backed impl). That is
    correct across FreeRTOS threads — lwIP's tcpip thread is a producer —
    unlike `unsafe-assume-single-core`. Nothing else in the firmware
    registers a `critical-section` impl (esp-idf-hal's `critical-section`
    feature is off), so there is no duplicate-symbol conflict. heapless 0.8
    remains in the tree only for the esp-idf crates.
  - *Deviations from the "use `box_pool!`" plan.* `object_pool!` instead:
    `BoxPool::alloc(value)` takes the new value by value, i.e. a ~1.5 KB
    stack temporary per acquire, and one producer runs on lwIP's 3 KB
    tcpip stack; an object pool recycles the initialized buffer in place
    ("reuse, just clear it" is exactly our semantics). The one remaining
    `unsafe` is creating the single `&'static mut` to the static block
    array that `manage` needs, guarded by an `AtomicBool` swap so it runs
    once (`static_cell` would remove it but is not in the offline
    registry).
  - *Counters.* The router's "heap after inbound-decrypted" debug line
    prints `pktbuf_pool: free= allocs= frees=`. `allocs` now counts only
    fallback heap allocations: it should stay **0**; growth means more
    than `POOL_N` packets were in flight at once.
  - **Verified: builds/tests** — host `cargo test` for `tm_buf` (pool
    lifecycle: managed once, reuse returns a cleared pooled buffer with no
    allocation, exhaustion falls back and frees on drop, `from_slice`
    bounds, `size_of::<PktBuf>() <= 4 words`), `tm_wg` (24), `tm_disco`
    (3), `tm_derp --features etls`, `tm_netstack` pass; the tailmicro
    crates cross-compile for `riscv32imc-esp-espidf`, and the combined
    `tasmolike-rs` firmware builds and links against this tree. (A plain
    `cargo build --workspace` on host fails before and after: `tm_tls`
    needs a backend feature and `tm_runtime` pulls `esp-idf-sys`.)
  - **Hardware (2026-09-26): partial.** Flashed to the ESP32-C3: boots,
    logs `packet-buffer pool ready: 4 static buffers (1532 B each)`,
    connects DERP, completes WireGuard handshakes with both peers through
    the pool, and ran ~5 min with no `memory allocation of`, `abort` or
    reset. The 60-request `status 0` stress test could **not** run: after
    reboot the dev host's packets never reached the node over DERP (no
    `RecvPacket` on the node, although the host's tailscaled showed a fresh
    handshake and kept transmitting). The previous firmware (Mutex-pool
    build) reflashed behaves identically, so this is the known
    stale-peer-state issue, not this change; the fix
    (restart the host's tailscaled) would have dropped the tailnet-routed
    SSH session. So the `pktbuf_pool` counters under load are still to be
    confirmed.
  - **`POOL_N` A/B, 4 vs 8 (hardware, 2026-09-26): kept 4.** `5513261`
    raised it to 8 on the mistaken premise that static buffers are free of
    heap cost. They are not: `.bss` shares internal DRAM with the heap.
    Real-traffic runs (`status 0` requests from bospill over DERP; same
    tree, including the `tm_derp` heap probes):

    | | `POOL_N = 4` | `POOL_N = 8` |
    |---|---|---|
    | Boot free heap / largest block (after `WgActor` spawn) | ~95100 / 86016 | ~89030 / 77824 |
    | Boots with inbound traffic | 4 | 1 (2 more boots got none: the bospill stall, seen at both sizes) |
    | First accepted HTTP conn -> `memory allocation of 8192 bytes failed` | 4 of 4 | 1 of 1 |
    | Heap just before the crash, total free / largest block | 36.3/14.3, 16.6/7.7, 30.8/13.3, 37.7/15.4 KB | 30.7/13.3 KB |
    | `pktbuf_pool` during traffic | `free` 0-3, `allocs` up to 4 (1 live fallback at crash time) | `free` 4-7, `allocs=0` |

    So: the 8192-byte crash (hyper's per-connection buffer vs heap
    fragmentation, not fixable from this repo) happens at both sizes with
    similar pre-crash headroom. 8 did not delay or prevent it. 4 **does**
    overflow during a connection burst (so "4 is always enough" is also
    false). But the fallback costs ~1.5 KB transiently, versus 6 KB of heap
    permanently at 8. 4 is the better trade for the heap. If the fallback
    churn itself becomes a concern, 6 (~peak in flight seen) is the
    untested middle ground.

## Verified on real hardware, but not the whole story

2026-09-26: flashed to the ESP32-C3 on `/dev/ttyACM0` and hammered
`/cm?cmnd=status+0` (~1 req/s) while DERP/WireGuard traffic was live. The
6052-byte failure is confirmed gone. In its place, two *different*
allocations now fail under the same load, each observed twice in a 90 s
window:

- **`memory allocation of 16384 bytes failed`**, immediately after `axum::serve:
  connection <addr> accepted` — before any application code runs. This is
  axum/hyper's own per-connection buffer, in `tasmolike-rs`'s dependency
  tree, not this repo.
- **`memory allocation of 3148 bytes failed`**, mid-way through
  `tasmota_compat::cm_status` building `StatusNET` (right after the efuse
  reads `command_status::status_net` does for the MAC address) — in
  `tasmolike-rs`, not this repo.

In both cases the heap-debug line logged 20-50 ms earlier
(`tm_runtime::event_router_task`'s "heap after inbound-decrypted") showed a
largest free block of 18-24 KB — comfortably enough for either allocation.
The dataplane's bursty alloc/free churn between that log line and the actual
allocation attempt is enough to eat the headroom. **Conclusion: fixing
individual fixed-size allocation sites one at a time (as above) reduces
which failure you hit, but does not fix the underlying contention** — the
WireGuard/DERP dataplane and the HTTP/status layer are fighting over the
same fragmented heap, and on this device any allocation of a few KB or more,
anywhere in the system, can lose that fight at the wrong instant. A durable
fix needs either: reserving a dedicated memory pool per subsystem so they
stop competing, capping axum to a buffer size that reliably fits, or moving
the remaining hot-path variable-size allocations (see `tm_control` and
`tasmolike-rs` items below) to fixed-capacity buffers too, shrinking the
window where "not enough contiguous space" can happen at all.

## Fixed (mechanical, doesn't touch the crashes above)

- **`tm_control` — `serde_json::to_vec` for `RegisterRequest` / `MapRequest`
  bodies.** All four call sites (register, publish, republish, keepalive
  poll) now serialize into a fixed-capacity `heapless::Vec<u8,
  REQUEST_BODY_CAP=768>` via a new `to_json_buf` helper
  (`serde_json::to_writer` + a `std::io::Write` shim over the heapless
  buffer), instead of a heap-growing `Vec<u8>`. Required adding
  `serde_json`'s `"std"` feature to `tm_control/Cargo.toml` (the workspace
  default is `alloc`-only, which doesn't expose `to_writer`) — costs flash,
  not RAM. These calls are rare (register once, republish once after
  DERP-home selection, periodic map polls) so this doesn't move the needle
  on the crashes above, but it's a real fixed-vs-variable-size win with no
  downside. Verified on real hardware: builds and runs, no regression.
  (`tm_control/src/lib.rs`, `tm_control/Cargo.toml`)

## Not fixable from this repo

- **`tasmolike-rs` (app) — axum/Tasmota JSON status handling.** Confirmed
  by the 2026-09-26 hardware test above: the 16384 B axum connection
  buffer and the 3148 B `tasmota_compat::cm_status` allocation are the
  other half of the contention. The packet-pipeline items that used to be
  listed alongside this one (`tm_derp` re-boxing, the router's
  copy-and-re-box, `tm_wg::pkt_to_box`) are now fixed — see "Fixed".

## Fix plan: DERP TLS handshake heap collapse

Follow-up to the "Verified on real hardware, but not the whole story"
section above: that section blamed the per-request 8192 B hyper-buffer
failure on generic "bursty churn" eating an 18-24 KB headroom. Finer
instrumentation (2026-09-26, commit `89cf1cf`, `heap_probe()` calls added
at every step inside `tm_derp::tls::DerpTls::connect`) narrowed down where
a big chunk of that headroom actually goes *before* any HTTP request ever
arrives: establishing the DERP TLS session itself.

### 1. Problem statement

`largest_internal` (the biggest contiguous free heap block) collapses by
~30 KB in one step, entirely inside the single `tls.open().await` call
(the TLS 1.3 ClientHello/ServerHello/EncryptedExtensions/
Certificate/CertificateVerify/Finished exchange) — e.g. 45056 -> 14336 B
in one hardware run, 40960 -> 17408 B in another. `total_free` only drops
~12-13 KB across the same call, so most of the 30 KB is not consumed, it
is stranded: freed back to the allocator but never recombined into one
block again, because the long-lived `DerpTls` state (the two record
buffers, `frame_buf`) ends up sitting in the address range afterward and
pins the fragments apart. Everything after the handshake (HTTP Upgrade,
ServerKey, ClientInfo, ServerInfo) is flat to within a few hundred bytes —
the damage is 100% inside `tls.open()`.

This sets a **floor of ~14-19 KB largest_internal for the entire lifetime
of the DERP connection** (it never recovers; only a reboot resets it).
That floor is what makes the pre-existing "hyper's 8192 B per-connection
buffer fails" crash (see "Verified on real hardware..." above) so easy to
hit: the dataplane's normal per-request churn only has to eat another
6-11 KB, not 18-24 KB, to lose the race. Fixing this collapse doesn't fix
the hyper-buffer crash by itself, but it substantially widens the margin
that crash currently has to close.

### 2. Lead hypothesis and a cheap way to confirm it first

**Hypothesis**: lwIP's TCP-receive path allocates pbufs from the general
heap (not a dedicated pool) for the several TCP segments the ~4.4 KB
server `Certificate` handshake record arrives in, and that burst of
differently-sized alloc/free pairs (one per segment: partial MSS chunks,
not a clean 1500 B multiple) during the single `tls.open()` call is what
fragments the heap. `embedded-tls` itself was checked against its
vendored 0.19.0 source and is heapless-bounded throughout (`heapless::Vec`
/ `String` with fixed const generics in `key_schedule.rs`, `pki.rs`,
`webpki.rs`, `der_certificate.rs`, `connection.rs` — no unbounded `Vec` or
`Box` on the handshake path), so it is very unlikely to be the direct
fragmenter; the TCP layer underneath it is the remaining suspect that
actually touches the heap during that window.

**What would need to be true for this hypothesis**: ESP-IDF's lwIP is
configured with `PBUF_POOL` sized too small/using `PBUF_RAM`
(heap-`malloc`-backed) for the TCP receive path on this build, so
segments larger than the static pool's slot size (or all of them, if the
memory type is configured as `PBUF_RAM`) come from the general heap
instead of a fixed-size, coalescing-immune static pool. `CONFIG_LWIP_*`
sdkconfig options control this: `CONFIG_LWIP_PBUF_POOL_SIZE` (buffer
count for `PBUF_POOL`), the actual allocator lwIP calls
(`pbuf_alloc(PBUF_RAW, len, PBUF_POOL)` for TCP receive normally goes
through `memp` typically, but the ESP-IDF lwIP port has a "dynamic" mode
routing this through system `malloc` for the TCP MSS-sized RX pbufs — needs
checking against the exact sdkconfig this build uses).

**Cheap way to confirm/rule out before touching sdkconfig** (no lwIP
changes, ~1 evening):
- Add `heap_caps_get_info(&info, MALLOC_CAP_INTERNAL)` (not just
  `heap_caps_get_largest_free_block`) probes bracketing `tls.open()`, and
  compare `total_allocated_bytes` / `total_blocks` before vs. after — a
  large jump in `total_blocks` with only a modest jump in
  `total_allocated_bytes` would confirm many small transient allocations
  happened (fragmentation signature), independent of *what* allocated
  them.
- Instrument (temporarily) `esp_get_free_heap_size()` at a much finer
  grain than "before/after tls.open()" — inside `embedded-tls`'s own read
  loop is not practical without patching the vendored crate, but the
  *transport* (`embedded_io_adapters::tokio_1::FromTokio<TcpStream>`) is
  ours to wrap: insert a thin logging shim around its `read()`/`write()`
  that calls `heap_probe()` on every call during the handshake window
  only (behind a cfg flag, removed after). If the collapse happens in
  discrete steps that line up with individual `read()` calls returning
  partial Certificate-record data (rather than one atomic drop), that is
  strong confirmation it is the TCP receive path, not something inside
  `embedded-tls`'s parsing/verification code.
- Independently: `idf.py menuconfig` (or grep the generated `sdkconfig`
  under `target/riscv32imc-esp-espidf/*/build/esp-idf-sys-*/out/sdkconfig`)
  to see the current `CONFIG_LWIP_PBUF_POOL_SIZE` /
  `CONFIG_LWIP_TCP_MSS` / any `CONFIG_LWIP_*_MALLOC` values. If pbufs are
  already coming from a fixed pool sized comfortably above what a 4.4 KB
  record needs, the hypothesis is wrong and the search should move
  elsewhere (e.g. mbedTLS scratch — not applicable here, `etls` is the
  pure-Rust backend — or `chacha20poly1305`/`sha2` transient state, which
  the earlier source read suggests is small and fixed, but hasn't been
  measured directly).

Do the sdkconfig read first — it is free (no build/flash) and might
settle the question in five minutes before spending an evening on the
finer probes.

**Already done (2026-09-26), no build needed**: grepped the generated
`sdkconfig` for the exact build this repo produces
(`target/riscv32imc-esp-espidf/debug/build/esp-idf-sys-*/out/sdkconfig`,
matched to the most recent build). Result: **there is no
`CONFIG_LWIP_PBUF_POOL_SIZE` or `CONFIG_LWIP_PBUF_POOL_BUFSIZE` option in
this ESP-IDF v5.5.2 sdkconfig at all** — those are the classic lwIP
`PBUF_POOL` knobs, and this ESP-IDF port doesn't expose them, which is
consistent with ESP-IDF's lwIP defaulting to `MEMP_MEM_MALLOC` (pbufs
allocated straight from the heap via `mem_malloc`, not carved from a
static slab). This **confirms the load-bearing half of the hypothesis**:
TCP RX pbufs on this build do come from the general heap, not a
dedicated pool, so there is no pre-existing "pool" to simply resize.
It does not yet confirm pbufs are *the specific* fragmenter (that still
needs the `heap_caps_get_info` block-count probe), but it rules out the
easy "just bump `PBUF_POOL_SIZE`" fix and reshapes option (a) below: the
available knobs on this config are `CONFIG_LWIP_TCP_MSS` (1440),
`CONFIG_LWIP_TCP_WND_DEFAULT`/`CONFIG_LWIP_TCP_SND_BUF_DEFAULT` (both
5760 — 4x MSS) and `CONFIG_LWIP_TCP_RECVMBOX_SIZE` (6), which govern how
many in-flight segments/how large a receive window the DERP TCP
connection is allowed, not a pool size. Full relevant excerpt for
reference:
```
CONFIG_LWIP_TCP_MSS=1440
CONFIG_LWIP_TCP_SND_BUF_DEFAULT=5760
CONFIG_LWIP_TCP_WND_DEFAULT=5760
CONFIG_LWIP_TCP_RECVMBOX_SIZE=6
CONFIG_LWIP_TCP_OVERSIZE_MSS=y
CONFIG_LWIP_TCP_QUEUE_OOSEQ=y
CONFIG_LWIP_TCP_OOSEQ_MAX_PBUFS=4
```
With a 5760 B window (4x the 1440 B MSS) and OOSEQ queueing enabled, a
~4.4 KB certificate record arriving as ~3-4 MSS-sized segments is exactly
within one window's worth of in-flight, heap-backed pbufs — plausible
as the source of the fragmentation burst.

### 3. Ranked options (cheapest / lowest-risk first)

**(a) lwIP TCP window/MSS tuning that's low-risk and reversible.**
Confirmed (see step 2): this ESP-IDF build has no `PBUF_POOL_SIZE` knob
to resize — TCP RX pbufs come straight from the heap. The available,
config-only lever is instead **shrinking `CONFIG_LWIP_TCP_WND_DEFAULT`**
(currently 5760 B = 4x the 1440 B MSS) so fewer segments (and therefore
fewer, smaller heap pbufs) can be in flight at once during the
certificate-record burst, at the cost of a slower TCP receive window
generally (more round-trips for large transfers, which matters more for
the control-plane's ~29-40 KB netmap `MapResponse` pulls than for DERP's
mostly-small relayed packets). This is a one-line sdkconfig change, no
Rust code touched, trivially reversible, and costs no extra RAM (it
*reduces* the peak, it doesn't reserve more). Risk: low but *shared* —
this window setting applies to every TCP connection on the device
(control-plane H2 stream, the HTTP server, DERP), so a value that's too
small could slow down or destabilize the control-plane's large netmap
pulls, which is exactly the kind of regression this repo can't easily
catch without a real hardware pass against the live control server. This
is the first thing to try if the finer `heap_caps_get_info` probe (step
2) confirms many small transient blocks (not one big one) around
`tls.open()`.

**(b) Shrink the Certificate-record burst itself.** The DERP server's
cert chain is a 4-cert RSA chain (`1286+1247+1528+359` bytes measured
live against `derp1.tailscale.com`) — that shape is set by the server, not
us, so we cannot make Tailscale send a smaller chain. The one lever on
our side is `MaxFragmentLength::Bits11` (2048), already the smallest
`embedded-tls` offers and already set — but the module doc itself notes
"Go's `crypto/tls` server ignores it today", i.e. the server sends
whatever size records it wants regardless of what we request. This option
is effectively **not available** without a DERP-server-side change, which
is out of scope. Listed for completeness / to close it off, not to
pursue.

**(c) The bigger structural change: move TCP RX off the general heap
entirely (`CONFIG_LWIP_TCP_MSS` tuning combined with switching lwIP's
pbuf allocation for this path away from heap-`malloc`, or wrapping the
`etls` TCP socket in our own buffering layer that reads in one
`RECORD_READ_BUF`-sized gulp instead of letting lwIP hand back
however-sized segments).** This is the `tm_buf`-style fix applied one
layer down the stack: reserve a dedicated, statically-sized region for
DERP's TCP receive path so its churn can never fragment the heap the HTTP
server also needs. Cost: more static RAM reserved permanently (size TBD —
needs measuring the actual segment-size distribution during a handshake
first; guessing risks either not fixing it or over-reserving on an
already-tight ~128 KB heap). Risk: **meaningfully higher than (a)** —
this is shared lwIP infrastructure underneath *all* networking (WiFi
control frames, the control-plane H2 connection, the HTTP status server,
DERP), so a mistake here can regress paths that are currently fine, and
lwIP's pbuf/memp configuration is not something this repo owns test
coverage for. Only pursue this if (a) turns out insufficient (i.e. the
fragmentation isn't just "pool too small" but structural to how lwIP
hands off TCP data on this build).

### 4. What to measure before prototyping, and the recommended next step

1. ~~Read the generated `sdkconfig`~~ — **done** (see step 2 above): no
   pbuf pool exists to resize; TCP RX is heap-backed, and the levers are
   `CONFIG_LWIP_TCP_WND_DEFAULT`/`CONFIG_LWIP_TCP_MSS`/
   `CONFIG_LWIP_TCP_RECVMBOX_SIZE`, not a pool size.
2. Add the `heap_caps_get_info` block-count probe (cheap, same pattern as
   the existing `heap_probe()`, no architecture change) bracketing
   `tls.open()` to distinguish "many small blocks churned" (supports
   option (a)) from "one big thing allocated and freed" (would point
   elsewhere, e.g. inside `chacha20poly1305`/`sha2`/embedded-tls's key
   schedule, which the source read suggests is small but hasn't been
   measured directly) before touching any lwIP config.
3. Only then prototype **(a)** (sdkconfig-only, `CONFIG_LWIP_TCP_WND_DEFAULT`
   lowered, revert-in-one-line) and re-run the same before/after
   `tls.open()` heap probe on real hardware to see how much of the 30 KB
   collapse it recovers, *and* re-run a normal control-plane netmap pull
   to confirm the smaller window doesn't visibly slow or break that path.
   If (a) closes most of the gap without regressing the control plane,
   stop there — no need for (c)'s bigger, riskier change.

**Recommended next concrete step**: implement step 2 (the
`heap_caps_get_info` block-count probe around `tls.open()`) on real
hardware — it's the cheapest thing that discriminates between "lwIP RX
churn" and "something inside the crypto/TLS state machine," and the
answer determines whether option (a) is even worth prototyping.

### Step 2 result (2026-09-26): confirmed — many blocks, not one

Added `heap_probe_blocks()` (`tm_derp/src/lib.rs`, using
`heap_caps_get_info`/`multi_heap_info_t` instead of just
`heap_caps_get_largest_free_block`) bracketing `tls.open()` in
`tm_derp/src/tls.rs`, alongside the existing `heap_probe()` calls.
Flashed to the real ESP32-C3 (`/dev/ttyACM0`) and captured two
independent boot/DERP-connect cycles (reset with `espflash reset`
between them, no reflash needed):

```
Run 1: before  total_free=52000 largest_free=40960 free_blocks=9  allocated_blocks=623 total_blocks=632
       after   total_free=42060 largest_free=23552 free_blocks=10 allocated_blocks=639 total_blocks=649
       delta:  total_free -9940   largest_free -17408  free_blocks +1   allocated_blocks +16

Run 2: before  total_free=54712 largest_free=45056 free_blocks=5  allocated_blocks=621 total_blocks=626
       after   total_free=38268 largest_free=15872 free_blocks=11 allocated_blocks=643 total_blocks=654
       delta:  total_free -16444  largest_free -29184  free_blocks +6   allocated_blocks +22
```

**Read: many blocks, not one.** In both runs, `allocated_blocks` jumps by
a double-digit count (+16, +22) across the single `tls.open()` call —
this rules out "one big thing allocated": a single large allocation would
show `allocated_blocks` moving by ~1, not 16-22. `free_blocks` also grows
(+1, +6) rather than staying flat or exploding into dozens/hundreds of
slivers, so it isn't extreme, chaotic fragmentation either — it's a
moderate handful of small allocations landing and (mostly, not entirely)
freeing back within the same call, consistent with a burst of similarly-
purposed operations (TCP segment receives, most of which get consumed and
released back to the allocator, leaving a residual few unreleased or
oddly-positioned).

The ratio of `largest_free` drop to `total_free` drop is remarkably
consistent across both runs — **~1.75x** (17408/9940 = 1.75; 29184/16444
= 1.77) — meaning the loss in usable contiguous space is reliably ~75%
more than the raw bytes actually consumed. That gap is exactly the
fragmentation signature: if the 16-22 new blocks were packed tightly at
one end of the original free region, the remaining contiguous tail would
only shrink by the bytes consumed (ratio ~1.0), not 1.75x. Landing at a
consistent ~1.75x across two independent runs with different exact byte
counts is stronger evidence of a structural (repeatable) fragmentation
pattern than noise would produce.

**Caveat, for honesty**: this device runs a cooperative single-threaded
executor where sibling actors (WiFi housekeeping, the control-plane H2
connection, WG timer ticks) get to run at every `.await` point inside
`tls.open()`'s ~700-900ms duration (see "Scheduling facts" above), so the
`multi_heap_info_t` counters are heap-wide, not scoped to only the DERP
TLS code path. The data cannot fully rule out some of the 16-22 blocks
being unrelated background churn coincident with the handshake window.
But it does not need to: the practical conclusion is the same either way
— *something* is producing a burst of several-to-two-dozen small
allocations precisely during the DERP TLS handshake window, not one
large one, so a pool/window-sizing style fix (option (a), or option (c)
if (a) proves insufficient) is the right shape of fix, not a search for
a single oversized `Box`/`Vec`. This also matches the "embedded-tls is
heapless throughout" source-read finding from the original investigation
— the remaining candidate producing heap traffic in this window is
exactly the TCP layer underneath it (lwIP pbufs) or, less likely,
background actors coincidentally sharing the window.

**Conclusion for the fix plan**: this confirms option (a)
(`CONFIG_LWIP_TCP_WND_DEFAULT` reduction) is worth prototyping next, as
originally ranked — the data supports "many blocks churned" over "one
big thing," which is what would make a window/pool-shaped fix effective.
It does not yet prove lwIP specifically (vs. background actor noise)
without further isolation (e.g. quiescing the control-plane/WG actors
during a synthetic DERP-only reconnect, which is more invasive to set up
than this probe), so option (a) should still be evaluated empirically
(prototype it, re-measure, see if the collapse shrinks) rather than
assumed to fully close the gap.

Instrumentation left in place (`heap_probe_blocks`, feature-gated behind
`etls`), same as `heap_probe` — strip both once the underlying fix lands.

### Step 3 result (2026-09-26): option (a) prototyped, confirmed effective

Lowered `CONFIG_LWIP_TCP_WND_DEFAULT` from 5760 (4x MSS) to 2880 (2x MSS)
in `tasmolike-rs/sdkconfig.defaults` (that repo's own change to commit,
not this one's — this file only records the result). Built, flashed, and
captured two independent boot/DERP-connect cycles with the same
`heap_probe`/`heap_probe_blocks` bracketing `tls.open()`:

```
Run 1: before  total_free=43780 largest_free=30720
       after   total_free=41804 largest_free=27648
       delta:  total_free -1976   largest_free -3072

Run 2: before  total_free=43780 largest_free=30720
       after   total_free=41660 largest_free=27648
       delta:  total_free -1660   largest_free -3072
       (largest_internal_block recovered back to 30720 within the same
       connect sequence, after HTTP Upgrade/ServerKey/ClientInfo/ServerInfo)
```

Compare to the pre-fix baseline (Step 2 result above): `largest_free`
drop across `tls.open()` went from **17408-29184 bytes, permanent, never
recovering** down to **3072 bytes, and it recovers back to the
pre-handshake value** by the time the DERP connection finishes setting
up. This closes almost all of the previously-unaccounted collapse.

Sanity checks with the change in place, all clean:
- Control-plane connect/register/netmap-pull (H2 over the same lwIP TCP
  stack) completed normally, no new errors or timeouts, 4096-byte DATA
  frames still arriving fine.
- 5 sequential `status 0` HTTP requests over DERP: all 200 OK.
- 30-request burst over DERP: device stayed up the whole time (uptime
  confirmed continuous via serial log, no `rst:0x`/`abort()` at any
  point). 25 of 30 requests failed at the transport level (`curl` exit
  000, couldn't connect) — traced to the already-documented
  `bospill`<->`esp32c3` stale-DERP-peer flakiness (see project memory:
  "DERP reachability diagnostics"), not a firmware crash: no crash
  signature anywhere in the capture, and the failure pattern (sudden full
  connection refusal, unrelated to request size or timing) doesn't match
  the 8192-byte-allocation crash signature at all.

**Conclusion**: option (a) works as predicted by the Step 2 data. This is
still a prototype — one MSS multiplier picked as a conservative first
step, not yet stress-tested to the same depth as the original crash
repro (that needs the `bospill` connectivity issue out of the way first
to get a clean high-volume burst). Recommended before shipping: rerun the
original 60-request stress test that reliably reproduced the 8192-byte
crash pre-fix, once `bospill`<->`esp32c3` connectivity is stable, to get
a real 0-vs-N crash comparison rather than relying on the heap-probe
numbers alone.

### Step 4 (2026-09-27): live crash resurfaced with disco PONG in the mix — analysis and instrumentation

**Trigger**: after Step 3 landed, a separate change added real DERP-reconnect-
with-backoff and a real sealed disco PONG (allowlist population via
`DiscoCmd::AllowPeer`, `SalsaBox` sealing with `OsRng`, DERP-relay
`src_ipport` addressing — `tm_disco`/`tm_runtime`, commits `989da2d`,
`57c9c81`, `6b9ab65`). On real hardware, with the Step 3 `TCP_WND=2880`
prototype still in place, the **exact 8192-byte-allocation crash signature**
(`connection accepted` -> `memory allocation of 8192 bytes failed` -> abort
-> reboot) reappeared on the very first HTTP connection after boot, despite
Step 3 previously getting a clean 30-request burst with zero crashes.

**Hypothesis to check**: the new disco/PONG code path consumes heap margin
that the TCP-window fix had freed up, on top of the still-present DERP-TLS
handshake collapse (Step 2/3).

**What I could confirm by reading the code (no hardware run yet — see
blocker below):**

`tm_disco/src/lib.rs`'s module doc says "No heap allocation. All state is in
fixed-size arrays on the struct." That's no longer true. `tm_disco/Cargo.toml`
pulls in `crypto_box` with the `"alloc"` feature enabled, and both crypto
calls in the PING/PONG path use the **allocating** side of the `aead::Aead`
trait, not the in-place, no-heap side:

- `DiscoActor::process()`: `bx.decrypt(&nonce, ciphertext.as_ref())` —
  `Aead::decrypt`'s default impl allocates a `Vec<u8>` (message length + tag),
  fills it, and calls `decrypt_in_place` on that heap buffer internally. This
  runs on **every** disco datagram that passes the allowlist check, not just
  PINGs.
- `build_sealed_pong()`: `bx.encrypt(&nonce, pong_plaintext.as_ref())` — same
  story in the encrypt direction, on **every** PONG sent (so, potentially,
  every PING received from an allowed peer, subject to the 100ms rate limit).

Each of these allocations is small on its own (the PONG plaintext is 32
bytes, so `encrypt` allocates ~48 bytes; the PING decrypt path is similarly
tiny), so this is very unlikely to be the direct cause of an *8192-byte*
allocation failing outright. But it is real, previously-undocumented heap
churn added squarely onto the hottest path in the new code (every allowed
peer's PING now does a heap alloc+free on top of whatever's happening in
`tm_derp`/`tm_control`/`tm_wg` in the same cooperative-scheduler window), and
per the Step 2 finding, this firmware's crash mode is about **fragmentation**
(largest contiguous block), not total free bytes — small, frequent,
differently-sized allocations churning the allocator are exactly the kind of
thing that can knock a borderline `largest_free_block` down below whatever a
subsequent 8192-byte request needs, even though each individual alloc is
small. `OsRng` itself (`esp_fill_random`-backed on this target, same as
`tm_derp`/`tm_wg` already use) is not expected to allocate and is not a
suspect here.

I added `heap_probe_blocks` calls (same `heap_caps_get_info`-based helper as
`tm_derp`'s, duplicated locally in `tm_disco` rather than adding a
`tm_disco -> tm_derp` dependency for a debug aid) bracketing:
- `DiscoCmd::AllowPeer` / `add_peer()` in `DiscoActor::run()`,
- `bx.decrypt(...)` in `process()`,
- the `OsRng` nonce fill + `build_sealed_pong()` call in `process()`.

This needed a small `tm_disco/Cargo.toml` addition (`tracing` +
`esp-idf-sys` under `[target.'cfg(target_os = "espidf")'.dependencies]`,
mirroring `tm_derp`'s existing pattern) since `tm_disco` previously had
neither. Verified with `cargo check -p tm_disco` on host — compiles clean
(only a pre-existing, unrelated `unused_mut` warning).

**Blocker — no live numbers yet**: I was not able to build/flash this round
(a build-permission restriction in my environment blocked running the
`cargo build` toolchain invocation entirely, independent of anything in this
repo). So the probe calls above are staged and committed, but I have **not**
captured actual before/after `largest_free`/`allocated_blocks` numbers for
the disco/PONG path, and I have **not** re-confirmed the live 8192-byte
crash myself. Saying so plainly rather than guessing at numbers.

**Ranked next steps** (cheapest/lowest-risk first, none implemented yet):

1. **(Recommended next concrete step.)** Get the instrumentation above onto
   hardware (build + flash, from whoever/wherever has build-toolchain
   access) and re-run one disco PING/PONG exchange with a real peer,
   capturing the bracketed `heap_probe_blocks` output the same way Step 2/3
   did for `tls.open()`. This settles, with data instead of code-reading,
   whether the disco path's churn is transient noise or is actually landing
   on top of the DERP-TLS collapse's already-thin margin at the moment the
   8192-byte allocation is attempted. Zero code risk — instrumentation only.
2. **If confirmed a contributor**: switch `tm_disco`'s two `Aead::encrypt`/
   `Aead::decrypt` calls to the `AeadInPlace::encrypt_in_place`/
   `decrypt_in_place` methods against a fixed-size `heapless::Vec` (the
   `ciphertext` buffer at line ~278 is already a `heapless::Vec<u8, 256>` —
   the decrypt side could operate on it in place instead of handing it to
   the allocating `Aead::decrypt`; the encrypt side would need a similar
   fixed `heapless`/`GenericArray` scratch buffer sized to
   `PONG_PLAINTEXT_LEN + TAG_LEN`, which is a compile-time constant). This
   removes the heap allocation from the disco hot path entirely — same shape
   as the `tm_buf::PktBuf` fix already applied elsewhere in this repo, and
   would also make the module's "No heap allocation" doc comment true again.
   Low risk (no behavior change, same crypto primitive, just a different
   buffer-ownership API on the same `crypto_box` crate), but needs a
   correctness re-check against `tools/wg_validator/disco.py` /
   `aead_crosscheck` the way every other crypto change in this file has been
   cross-checked, since the ciphertext layout must stay byte-identical.
3. **If the disco path is not the dominant contributor** (i.e. Step 4's
   numbers show it's small relative to the still-present ~3072-byte
   post-`tls.open()` floor from Step 3): the TCP window may need to go lower
   still (e.g. 1x MSS / 1440B) as a second, more aggressive step down from
   the Step 3 prototype — same lever, one more notch. This was explicitly
   out of scope to touch this round per instructions, so it's listed here
   only as the fallback if step 1 rules out the disco hypothesis.
4. **Not recommended yet**: option (c) from the original fix plan (a
   structural/pool-based rework of the TCP-RX path) — still the most
   invasive option and nothing found this round changes that ranking.

### Step 4 result (2026-09-27): disco crypto ruled out; TLS collapse got worse anyway

Built and flashed the `fd9cf76` instrumentation (this session has working
build/flash access to `tasmolike-rs`/`tailmicro-rs`, unlike the sandbox the
prior round's agent was blocked in). Captured boot + a real `tailscale
ping esp32c3` (3 disco PING/PONG round trips over DERP) on real hardware.

**Disco crypto's own allocations: ruled out.** `largest_free` does not
move at all across `bx.decrypt`/`build_sealed_pong` — flat at 20480 bytes
across all three ping/pong exchanges (only `total_free` and `free_blocks`
wobble by a few dozen bytes/blocks, consistent with the "tens of bytes,
mostly freed back" prediction from the Step 4 hypothesis). This
specific suspicion is closed: the disco PONG crypto is not what's eating
the TCP-window fix's headroom.

**But the underlying TLS-handshake collapse itself is measurably worse
than the Step 3 prototype run, on the same `CONFIG_LWIP_TCP_WND_DEFAULT
=2880`:**

```
Step 3 (TCP window fix alone):
  before tls.open: total_free=43780 largest_free=30720
  after  tls.open: total_free=41660 largest_free=27648   (-3072, recovers to 30720 later)

Step 4 (same window fix + DERP-reconnect + disco-PONG code now linked in):
  before DerpTls::connect:        total_free=64876 largest_internal=53248  (more headroom at boot than Step 3!)
  before tls.open:                total_free=57736 largest_internal=47104
  after  tls.open:                total_free=46644 largest_internal=29696  (-17408)
  after ServerInfo decrypt (handshake done): total_free=45388 largest_internal=20480  (further -9216, no recovery)
  floor for rest of connection's life: 20480
```

So even though this build has *more* free heap and a *larger* largest
block before the handshake even starts, it ends up at a **lower, worse
floor** (20480 vs 27648-30720) after the exact same handshake. The disco
PONG crypto calls happen well after this collapse (confirmed flat at
20480 through all three probes), so they aren't the cause — something
about linking the new `tm_disco` code (the `crypto_box`/`rand`/`tracing`/
`esp-idf-sys` additions to `tm_disco/Cargo.toml`, or just more actors
being constructed before `DerpActor` runs) has shifted the heap's layout
enough that the same TLS handshake now fragments a worse region. This
was reproduced as a live crash: the 8192-byte hyper-buffer allocation
failed on the first HTTP connection after boot with this exact build,
serial-confirmed (`connection accepted` -> `memory allocation of 8192
bytes failed` -> abort -> reboot), despite the TCP-window fix being in
place and working as designed in isolation.

**Conclusion**: the TCP-window fix (option a) is real and still worth
keeping, but it is not sufficient on its own once the rest of the
firmware's code/RAM footprint grows — the safety margin it bought was
consumed by something structurally unrelated to disco's own crypto
allocations. Per the ranked list above, the next lever to try is
tightening the window further (1x MSS = 1440B) and re-measuring against
this now-larger firmware, since the "3072-byte floor" assumption used to
rank that option was based on the smaller Step-3 firmware and no longer
holds.

### Step 5 (2026-09-27): Kconfig floor bug found, static `.bss` conversion implemented, 20480-vs-8192 mismatch narrowed but not yet pinned

**Context**: a follow-up live test (run by the requester, not from this
session) tightened `CONFIG_LWIP_TCP_WND_DEFAULT` to 1440 (1x MSS). Reported
result: the DERP-TLS handshake collapse itself improved a lot (recovers to
43008 after `DerpTls::connect`, vs the 20480 floor from Step 4's 2x-MSS
build), but the crash still reproduced — this time apparently caused by
three lazy "on first use" tm_wg heap allocations (`WgEndpoint`,
`RecvOut`/recv scratch, `DispatchOut`/dispatch scratch, ~6 KB each) firing
in sequence once real WG peer traffic starts, dropping `largest_free` from
43008 straight to 20480 and pinning it there. Then, with a reported 20480
bytes free, an 8192-byte allocation (hyper's h1 buffer) still failed —
the "20480-vs-8192 mismatch" this step set out to root-cause.

**Bug found before any of that: the 1440 test never ran at 1440.**
`components/lwip/Kconfig` in this ESP-IDF release (v5.5.2) defines:

```
config LWIP_TCP_WND_DEFAULT
    int "Default receive window size"
    default 5760 # 4 * default MSS
    range 2440 65535 if !LWIP_WND_SCALE
```

A value below 2440 is **silently clamped back to the Kconfig `default`
(5760)** during sdkconfig generation — not to 2440, not to the
out-of-range value requested. Confirmed by grepping the freshly-generated
`target/riscv32imc-esp-espidf/debug/build/esp-idf-sys-*/out/sdkconfig`
after a clean rebuild with `1440` in `sdkconfig.defaults`: it read back
`CONFIG_LWIP_TCP_WND_DEFAULT=5760`. This means the "1x MSS" test that
reported the 43008-after-TLS improvement was actually still running at
the original default (5760), not a tighter window — the causal story
built on that test (tighter window -> better TLS recovery) is not
supported by what was actually flashed. **Corrected to 2440**, the true
Kconfig-enforced floor, and re-verified via the same sdkconfig grep that
2440 actually took effect. `sdkconfig.defaults` is left at
`CONFIG_LWIP_TCP_WND_DEFAULT=2440` (uncommitted, per the usual
tasmolike-rs prototype-only rule).

**Capability mismatch: ruled out.** Added `heap_probe_at_accept()` in
`tasmolike-rs/src/server.rs`, checking `MALLOC_CAP_INTERNAL` and
`MALLOC_CAP_DEFAULT` side by side at three points around
`serve_connection` (after accept, immediately before serve_connection,
immediately after it returns). On this ESP32-C3 build (no PSRAM, single
RAM pool) the two capability buckets reported **identical
`largest_free_block` at every probe**, so hyper's allocator wanting a
different capability flag than what was being measured is not the
explanation.

**Heap-state-changes-between-probe-and-allocation: confirmed, and
the actual mechanism is cooperative-scheduler interleaving with a
different actor, not a bad probe placement.** Correlating precise serial
timestamps in `serial-lwip2440-http.log`: the "before serve_connection"
probe read `largest_free=20480` at t=42151ms; 86ms later, the only log
line in between is `WgEvent::InboundDecrypted 160 bytes`; the very next
probe (in `tm_runtime`'s router, logged for that event, *before*
`tailnet::inject_inbound` is even called) already reads
`largest_free=7680`; the crash's `memory allocation of 8192 bytes failed`
follows immediately after. Since this firmware runs a single-threaded
Tokio executor (`tm_runtime::Runtime::join`'s `tokio::join!`), nothing
runs "in between" two synchronous statements without an actual `.await`
yield — so the WG actor's inbound-packet handling and the HTTP server's
connection setup are provably interleaved on the same executor, and the
~12.8 KB (largest-block) / ~16.4 KB (total-free) collapse attributed to
that single WG event happened for real, in that window. The reported
20480 in the "before" probe was genuine; it just didn't survive to the
point where hyper's allocation was actually attempted, because the WG
event got a turn on the executor first.

**What was ruled out as the source of that ~12.8-16 KB collapse**, in
the WG event's own code path (`WgActor::on_inbound` ->
`WgEndpoint::recv_one_into` -> `drain_recv` -> `pkt_to_buf` ->
`events.send`):
- The three now-converted-to-static buffers (see below) — confirmed by
  their own log line ("binding static ... on first use") firing once,
  early, and never again.
- WG data-plane decrypt: `session.rs` already uses no-heap
  `AeadInPlace::decrypt_in_place` (`use aead::AeadInPlace;` at
  `tm_wg/src/vendor/session.rs:16`, called from
  `endpoint.rs:800`'s `decrypt_one`), not the allocating `Aead` trait.
  `chacha20poly1305`'s `"alloc"` feature is enabled in `tm_wg/Cargo.toml`
  but is only exercised by the unused `Vec`-returning convenience
  wrapper and tests, not this hot path.
- `tm_buf::PktBuf::acquire()` (used by `pkt_to_buf`): confirmed
  pool-only for this event, `pktbuf_pool: allocs=0 frees=0` in the log —
  no heap fallback fired.
- The `events: Sender<WgEvent>` channel's own first-block allocation:
  ruled out, since this specific channel had already carried an earlier
  `WgEvent::OutboundPacket` message earlier in the same boot session.
- The handshake-response path's `Vec::new()` at
  `tm_wg/src/vendor/handshake.rs:490` (`.decrypt(&packet.auth_tag, &mut
  Vec::new())`): an empty `Vec` doesn't heap-allocate until pushed to,
  and this path only fires once per handshake completion, not per
  established-session data packet (the incident packet was 160 bytes of
  ordinary data-plane traffic, not a handshake response) — ruled out.
- `tailnet::inject_inbound` itself: ruled out by construction — the
  probe that already reads the collapsed 7680 value sits *before* that
  call in `tm_runtime`, so whatever consumed the heap did so before
  `inject_inbound` ever ran.

**Not yet pinned down**: the exact allocation site. A tighter probe
(`heap_probe_blocks` immediately before/after `self.endpoint()
.recv_one_into(...)` in `WgActor::on_inbound`, `tm_wg/src/lib.rs`) has
been added this step to localize whether the collapse happens inside
`recv_one_into` itself (i.e., somewhere in the vendored WG session/
handshake state machine not yet examined) or after it (in `drain_recv`/
channel machinery, already mostly ruled out above, or in a genuinely
different, unlogged actor that happened to get a scheduler turn in the
same window). Hardware verification of this new probe is the next
concrete step once build/flash access is available again (see below).

**Implemented (not just proposed): static `.bss` conversion of the
three ~6 KB tm_wg "on first use" scratch buffers.** Checked first for
any reason this couldn't be static: all three (`WgEndpoint`, `RecvOut`,
`DispatchOut`) are fixed-size (`ArrayVec`-backed, no runtime-dependent
capacity), constructed exactly once per boot, and held for the process's
entire lifetime — the same "fixed-size, single instance, allocated once,
held forever" shape already established for `tm_buf::PktBuf`'s pool. The
only per-instance runtime state (`WgEndpoint`'s `my_key`) is written
in-place after zero-cost const-initializing the rest, same technique
`new_boxed` already used, just targeting a function-local `static` instead
of a heap `Box`:

- `WgEndpoint::new_static()` (`tm_wg/src/endpoint.rs`) — mirrors
  `new_boxed`'s field-by-field raw-pointer init, writing into a
  `static mut ENDPOINT_STORAGE: MaybeUninit<WgEndpoint>` guarded by a
  `static TAKEN: AtomicBool` that panics on a second call.
- `RecvOut::recv_out_static()` and `dispatch_out_static()`
  (`tm_wg/src/endpoint.rs`) — same `AtomicBool`-guarded pattern, both
  const-initializable directly (`ArrayVec::new_const()` for every
  field), so no `MaybeUninit`/raw-pointer writes needed.
- `WgActor`'s three `Option<Box<T>>` fields became `Option<&'static mut
  T>` (`tm_wg/src/lib.rs`); accessors (`endpoint()`,
  `take_scratch`/`return_scratch`, `take_dispatch_scratch`/
  `return_dispatch_scratch`) now bind from the `_static()` constructors
  instead of `Box::new`. Call sites (`on_inbound`, `on_send_data`,
  `on_tick`) needed **no changes** — `&mut &'static mut T` coerces to
  `&mut T` at the call site the same way `&mut Box<T>` did.
- Cost: ~18 KB of permanent `.bss`, in exchange for removing these three
  allocations' fragmentation impact entirely — the same accepted
  heap-cost-for-no-fragmentation tradeoff as `tm_buf::PKT_CAP`.
- Verified on host: `cargo check -p tm_wg` clean (only a pre-existing,
  unrelated `tm_control` warning); `cargo test -p tm_wg` — all 24 tests
  pass (none of them exercise the new `_static()` constructors directly,
  since the unit tests build `WgEndpoint` via `WgEndpoint::new()`, so no
  cross-test static-singleton collision risk).
- Verified on real hardware (Step 4/5 capture,
  `serial-lwip2440-http.log`): the "binding static WgEndpoint (~6 KB,
  .bss) on first use" log line (and the equivalent for the two scratch
  buffers) fires exactly once, early in the WG peer's first-traffic
  window, and never recurs — confirming the conversion works as
  designed and these three allocations no longer contribute heap churn
  after boot.

**Honest bottom line on this step**: the static-buffer conversion is a
real, verified win (removes a genuine ~18 KB one-time fragmentation
event), and the Kconfig floor bug is a real, useful correction to the
investigation's own methodology (a prior test's conclusion was invalid).
But **neither of these, individually or combined, has yet been confirmed
to get a real HTTP request through without crashing** — that combined
hardware pass (static buffers + `CONFIG_LWIP_TCP_WND_DEFAULT=2440` +
the new `recv_one_into` bracket probe) could not be completed this step:
build/flash access to real hardware became unavailable mid-step (the
sandbox running this session lost outbound network entirely — `curl`,
`ping`, and DNS all fail to every host, including `github.com` and
`dl.espressif.com` — which `esp-idf-sys`'s build script needs for its
managed ESP-IDF checkout/tooling validation, even when no ESP-IDF version
change is involved). This is an environment problem, not a code problem;
the changes above are believed correct (host-verified) but **not yet
hardware-verified end-to-end**. Next session/step with working
build/flash access should: rebuild with the current
`tm_wg`/`tasmolike-rs` state, capture a boot + real HTTP request, and
use the new `recv_one_into` bracket to finally localize the remaining
~12.8-16 KB collapse.

### Step 6 (2026-09-27): hardware-verified — collapse localized to `drain_recv`, not `recv_one_into`; still crashes

**Context**: build/flash access was restored (a different environment than
the one that lost it in Step 5). Rebuilt `tasmolike-rs` against
`tailmicro-rs@c2c8c81` (the static-buffer + Kconfig-2440 state from Step
5) and flashed real hardware to finally run the combined pass Step 5
couldn't complete.

**Static-buffer fix confirmed working on this fresh flash**: all three
"binding static ... on first use" log lines (`WgEndpoint`, dispatch
scratch, `RecvOut` scratch) each fire exactly once during boot/first
traffic and never recur — same result as Step 5's earlier capture, now
reproduced independently.

**The crash still reproduces.** A 30-request HTTP burst against the real
device over the tailnet (`curl` to its Tailscale IP) got 1-2 successes
then `memory allocation of 8192 bytes failed` / `abort()` at the same PC
(`0x420abeb3`) / `rst:0xc (RTC_SW_CPU_RST)`, reproduced 4 times across two
capture runs.

**New finding — the new `recv_one_into` bracket probe (added in Step 5,
hardware-verified for the first time this step) answers Step 5's open
question**: the collapse is NOT inside `recv_one_into`. Serial capture
shows `largest_free` reads identically before and after `recv_one_into`
across every observed inbound packet (e.g. `before recv_one_into:
largest_free=20480` -> `after recv_one_into, before drain_recv:
largest_free=20480`, unchanged). The very next probe, `after drain_recv`,
is where the collapse shows up (one representative capture: `total_free`
36240 -> 30024, `largest_free` 25600 -> 19456, `allocated_blocks` 659 ->
665, i.e. +6 blocks, all inside the single `drain_recv` call for one
inbound event). This matches Step 5's already-correlated crash-adjacent
window (`before serve_connection` probe: `largest_free=20480`,
`total_free=31004`; next `on_inbound: after drain_recv` probe:
`total_free=14304`, `largest_free=7680`, `allocated_blocks` 667 -> 673,
again +6 blocks) — same signature, same call.

**`tm_buf::PktBuf` pool fallback ruled out as the cause of this specific
collapse**, contrary to what the +6-blocks number might suggest at first
glance: correlating a different capture window where the same
`largest_free` collapse happens (22528 -> 7680, `total_free` 32956 ->
15368) shows `pktbuf_pool allocs=2 frees=1` **unchanged** on both sides of
the drop — no new fallback heap allocation fired in that window. So the
~6 new allocated blocks / ~15-17 KB consumed inside `drain_recv` are not
(all) `PktBuf` fallbacks; something else in `drain_recv`'s call chain
(`events.send` on the `WgCmd`/`WgEvent` channel, or something the send
wakes downstream in the *same* scheduler turn before the next `.await`
actually yields — e.g. the event router in `tm_runtime` or a lwIP-side
callback interleaved into the same window) is the real remaining
consumer. Not yet pinned to a single line.

**Two live hypotheses for the next step, not yet distinguished**:
1. The `events.send(...).await` calls in `drain_recv` don't just enqueue —
   on this single-threaded executor, a `.send` that wakes and resumes
   `tm_runtime`'s router *inline* (rather than yielding back to
   `on_inbound`'s caller first) would mean the "after drain_recv" probe
   is actually downstream of the router already having processed the
   event and called `tailnet::inject_inbound` — which Step 5 ruled out
   only for the *specific* probe ordering it had at the time (before
   `inject_inbound`), not for a scenario where the whole router turn
   completes inside the `.send().await` itself. Worth adding a probe
   immediately inside `tm_runtime`'s router, bracketing its own call to
   `inject_inbound`, to see if it fires between the two `drain_recv`
   probes.
2. `inject_inbound` feeds the decrypted packet into the tailnet virtual
   netif, which lwIP treats as ordinary inbound IP/TCP traffic for the
   HTTP server's *own* accepted connection — meaning the same class of
   TCP-RX-pbuf churn Step 2/3's `CONFIG_LWIP_TCP_WND_DEFAULT` fix
   targeted on the DERP TLS connection could equally apply here, on the
   virtual netif's TCP reassembly for the HTTP request itself. If so,
   `2440` (this Kconfig's hard floor per Step 5) is already the best that
   specific knob can do — this axis may be exhausted, and the real fix
   would need to reduce pbuf *count* (`CONFIG_LWIP_NUM_TCP_PCB`/
   `CONFIG_LWIP_PBUF_MEM_POOL_SIZE`, currently 16/256 in
   `tasmolike-rs/sdkconfig.defaults`) or the number of concurrent
   in-flight segments some other way, not the window size.

**Honest bottom line**: Step 5's fixes are real, hardware-confirmed, and
necessary but not sufficient. The remaining crash is now narrowed to one
specific `.await` window (`drain_recv`'s `events.send` calls) rather than
"somewhere in the WG receive path," but the exact allocation site inside
that window is still unidentified. `tasmolike-rs/sdkconfig.defaults` and
`src/server.rs` remain uncommitted there (per the standing rule); no
`tailmicro-rs` code was changed this step, only this log entry.

### Step 7 (2026-09-28): neither hypothesis — the crash is total heap budget (main-task stack + concurrent hyper connections), plus a router deadlock; mostly fixed (30/30 bursts), one residual 8 KiB failure under sustained load

**Context**: Step 6 left two hypotheses for the `drain_recv` collapse:
(1) `events.send(..).await` resumes the router *inline*, so the "after
drain_recv" probe already sees `inject_inbound`'s effects; (2) lwIP TCP-RX
pbuf churn on the tailnet netif, triggered by `inject_inbound`. This step
tested both on hardware with better tools than block-count probes, and
followed the data to the actual crash.

**New instrumentation** (`tm_wg/src/heapdiag.rs`, temporary, like
`heap_probe_blocks`):
- `trace_begin`/`trace_end`: an ESP-IDF standalone heap trace
  (`HEAP_TRACE_LEAKS`, 64 records, 6-deep frame-pointer backtraces) around
  `drain_recv` and around the router's `inject_inbound` call. Prints every
  allocation made inside the window, from *any* FreeRTOS task, that is still
  live at its end. A window opened while another is open logs `NESTED` (the
  proof that the outer one yielded). Behind the new `tm_wg` feature
  `heap-trace` + `CONFIG_HEAP_TRACING_STANDALONE=y`/`_STACK_DEPTH=6` in the
  app sdkconfig; off by default (the window then only diffs two snapshots).
- `send_diag` in `drain_recv`: logs `chan_len_before`, `full_before`, and
  how many times the send future returned `Pending`.
- `install_alloc_failed_dump()` (called at router start): on any failed
  allocation >= 4000 B, prints the whole internal heap as an address-ordered
  `U<size>`/`[F<size>@addr]` map, from inside the failure itself.
- `snap()` also prints the main task's stack high-water mark.

**Hypothesis 1: false as stated.** `async_channel::Sender::send` never runs
the receiver inline. Host test (tokio current-thread, `bounded(2)`, a
receiver parked in `recv().await`): a send with room returns `Ready` on the
first poll and the receiver has not run; only a send on a *full* channel
returns `Pending`, and then the whole executor (router, hyper task,
everything) runs before it completes. On hardware, 118 of 130 `drain_recv`
sends had `pendings=0`; the rest were `full_before=true` with 1-5 yields,
and in those yielded windows the router's `inject_inbound` window opened
`NESTED` inside `drain_recv`'s. So the "collapse inside `drain_recv`" was
just heap-wide work by other tasks during a yield (15 of 30 yielded windows
lost `largest_free`, vs 6 of 68 non-yielded ones — the latter being the
tcpip/WiFi threads, which preempt at any time regardless of `.await`).
The heap trace of the biggest window (-5120 `largest_free`): two 1536 B
`PktBuf::acquire` pool fallbacks, a 1532 B lwIP `pbuf_alloc` from
`tcp_write` (tcpip thread), 16 B lwIP `sys_timeout`s. Nothing structural.

**Hypothesis 2: small, not the cause.** `inject_inbound` itself costs one
`PBUF_POOL` pbuf per packet (1532 B, since ESP-IDF's `PBUF_POOL` is
heap-backed with a fixed buffer size — a 48 B TCP ACK costs 1.5 KB) plus
~160 B of netconn/mbox on a new connection. Real, but at most ~2 KB, never
the ~8-16 KB swings. (Follow-up: `PBUF_RAM` sized to the packet would shrink
this; not done here.)

**What actually fails, from the heap map at 11 crash points** (pre-fix
build): `total_free` 15-28 KB but no free block >= 8192 (largest 6520-8132,
plus an unusable 7748 B RTC-RAM block). The big used blocks are the same
every time, and two stand out:
- `U57344@0x3fca8bd0` = **the main task's stack** (address equals
  `pxTaskGetStackStart`; `CONFIG_ESP_MAIN_TASK_STACK_SIZE=55296` in
  `tasmolike-rs`, a heap allocation at boot). Its high-water mark never went
  below **19680 B free** across boot, DERP TLS, WG handshakes with both
  peers and HTTP traffic: ~35.6 KB used, ~19.6 KB of heap reserved for
  nothing. The 55296 was sized when `RecvOut` (12 KB) lived on that stack;
  Step 5 moved it (and `DispatchOut`/`WgEndpoint`) to `.bss`.
- one or two `U8192` = hyper's per-connection buffers. Every h1 connection
  allocates **two** 8 KiB blocks: `WriteBuf`'s headers
  `Vec::with_capacity(INIT_BUFFER_SIZE)` at `serve_connection`, then the read
  buffer's `reserve(8192)` on first read (`hyper-1.9.0/src/proto/h1/io.rs`
  lines 71/522; `max_buf_size` caps growth, not these). The crash is the
  second one.

**Fix, step by step, each hardware-verified**:
1. `CONFIG_ESP_MAIN_TASK_STACK_SIZE` 55296 -> 43008 (`tasmolike-rs`,
   uncommitted). +12 KB heap; measured stack minimum afterwards 6088-7784 B
   free. 30 requests at ~1/s: **30/30**, `largest_free` before
   `serve_connection` >= 26624 (was 9728-18432). But 60 **back-to-back**
   requests: 6/60, 6 aborts — heap maps now show *two* live `U8192` plus the
   failing third: the previous connection is still draining (FIN over the
   DERP tunnel) when the next is accepted, and each spawned connection wants
   16 KB.
2. One HTTP connection at a time (`tasmolike-rs/src/server.rs`, uncommitted):
   a 1-permit `Semaphore` acquired before `accept`, released when the
   connection task ends; `keep_alive(false)` so an idle client cannot hold
   the slot; 15 s `timeout` around `serve_connection`. Next connection waits
   in lwIP's backlog. (Tasmota's own web server is single-client too.)
3. Surfaced by 2: the **data plane deadlocked** (no crash, no reboot; DERP,
   WG and HTTP silent while the control plane kept polling). Cause: the
   router `await`ed `wg_tx2.send(WgCmd::InboundPacket/SendData)` on a full
   `CHAN_CAP = 2` channel while `WgActor` was blocked in `drain_recv` on a
   full `WgEvent` channel whose only consumer is the router. Fixed in
   `tm_runtime`: every packet-carrying router->actor send
   (`WgCmd::InboundPacket`/`SendData`, `DerpCmd::SendPacket`,
   `DiscoCmd::MaybeDisco`, both router copies) now goes through
   `forward_or_drop` (`try_send`; drop + counted warn on `Full`). Packets are
   droppable; the `PktBuf` returns to the pool. 10 drops in a 60-request
   back-to-back run, all recovered by TCP. (These edits were swept into
   commit `7073249` by a concurrent LAN-direct agent's commit; content as
   described here.)
4. Diagnostic bug found on the way: dumping the heap map on *every* failed
   allocation livelocked the device when WiFi dynamic RX buffers (1700 B,
   routine and recoverable) started failing — hundreds of 5 KB dumps at
   115200 baud from the wifi task. Now only failures >= 4000 B dump.

**Results** (real ESP32-C3, requests from bospill over DERP,
`curl /cm?cmnd=Status`), with 1+2+3:
```
back-to-back:     58/60   (2 client timeouts, no reset)
slow soak 6 min:  36/36   (1 req / 10 s)
final burst:      30/30   back-to-back
resets: 0   fatal alloc failures: 0   main stack min free: 6088 B
```
That run built against a side worktree (at `2f7b548` + these files) because
the main checkout was briefly unbuildable mid-LAN-direct work. On the final
build from this repo's main checkout (`7073249` + this commit, with 4, no
heap tracing): a 30-request burst was 30/30 with 0 resets, but the full soak
was **not** clean:
```
back-to-back:     54/60
slow soak 6 min:  36/36
final burst:      29/30
resets: 1  (t ~ 342 s: "memory allocation of 8192 bytes failed")
```
Heap map at that failure: `total_free` 21736, two `U8192` already live (one
connection's headers buffer + its read buffer), largest free block
**8100 B** — 92 B short. Router drops so far: 1; no connection timeouts.
So serializing connections removed the 3x8 KiB case, but a single
connection's 2x8 KiB still sometimes can't find a contiguous 8 KiB.

**Ruled out / confirmed**: hypothesis 1 (inline resume) ruled out by host
test and on-device pending counts; the real mechanism is yield-on-full plus
preemptive FreeRTOS threads. Hypothesis 2 real but ~1.5 KB/packet, not the
cause. Confirmed: the crash was a heap *budget* problem (12-20 KB of idle
main-task stack + 16 KB per concurrent hyper connection on a ~100 KB heap),
not an unidentified allocation in `drain_recv`.

**Honest bottom line**: much improved (from crashing within a few
back-to-back requests to 1 reset in ~130 requests over ~10 min), but **not
fixed**: the contiguous-8 KiB margin is still marginal under sustained load
(largest free 8100 vs 8192 needed at the one failure). Also thin: ~6 KB of stack headroom (a deeper path not
exercised here, e.g. a WG rekey coinciding with a DERP reconnect, could
overflow; ESP-IDF catches overflow and resets rather than corrupting) and
~20 KB heap before `serve_connection`. Two of the three fixes live in
`tasmolike-rs` (`sdkconfig.defaults`, `src/server.rs`, `Cargo.toml` tokio
`sync`/`time` features), uncommitted there per the standing rule. Next
levers, in order of expected yield: shrink hyper's two 8 KiB per-connection
buffers (or a smaller HTTP server for `/cm`), `PBUF_RAM` sized to the packet
in `inject_inbound`, trim the main stack further (needs a worst-case
stack measurement first); strip `heapdiag`/probes once this holds up.

### Step 8 (2026-09-28): hyper replaced, send-queue pileup found and fixed; clean soak with 15.8 KB minimum largest block

**Context**: Step 7's residual failure was hyper needing 8 KiB contiguous
blocks per connection (a `WriteBuf` headers `Vec::with_capacity(8192)` plus
a read `reserve(8192)`). hyper's server `max_buf_size` cannot go below
`MINIMUM_MAX_BUFFER_SIZE` (8192), so the buffers could not be shrunk.

**Fix 1 (tasmolike-rs `src/server.rs`, `Cargo.toml`): replace hyper with a
minimal HTTP/1.1 responder.** The responder does the following:

- Keeps the axum `Router` (all handlers unchanged) and calls it via
  `tower::ServiceExt::oneshot`.
- Parses the request with `httparse`: a 1 KiB buffer allocated once at
  startup, 24 headers max, and a Content-Length body only (chunked request
  bodies get 501).
- Writes the response through that same buffer, coalescing body frames:
  `content-length` when the body size is exact, and `connection: close`.
- Serves one connection at a time with a 10 s cap.
- Runs the server loop in a spawned task. Inlining it in `block_on` put its
  state on the main stack and dropped the stack high-water mark to 5016 B.

`hyper`/`hyper-util` are gone. After this, no allocation over about 3.2 KB
remains on the request path (the largest is a `U3168`).

Result: back-to-back requests were 60/60, and largest_free at every accept
and close stayed at 19456 or above. But 4-way **parallel** `Status 0`
requests (about 3 KB responses) then **aborted** on a 3168 B allocation
with only about 7 KB free in total.

**Root-cause refinement, from annotated heap maps.** `heapdiag` now marks
lwIP pbuf blocks as `P<size>:<type>/<len>/<ref>{srcport>dstport}`.

- At the failure, 15 to 18 `P1344:80` blocks (PBUF_RAM, 1280/532/132 byte
  segments, i.e. TCP MSS 1240 + 40 B headers) held about 24 KB.
- Their ports showed they were the tailnet HTTP server's (`80>...`) *sent,
  unACKed* segments from connections the app had **already closed**.
- lwIP keeps a closed socket's unACKed data and retransmits it for up to
  `TCP_MAXRTX`=12 backoffs. These were typically clients that had timed out
  on the slow relay path.
- There were no PBUF_POOL (`0x82`) inbound pbufs of note, so switching
  `inject_inbound` to PBUF_RAM (a Step 7 lever) would not help.
- The 10 `U1664` blocks are the WiFi driver's static RX buffers
  (`ESP_WIFI_STATIC_RX_BUFFER_NUM=10`), a fixed cost.

A subtle trap, found via the port annotation: setting `SO_LINGER=0` *after*
`shutdown()` did not free those segments. lwIP turns a `shutdown(SHUT_WR)`
into the full close when the receive side is already closed, and
`netconn_recv` issues `SHUT_RD` on reading the client's FIN, which turns a
socket already in FIN_WAIT into the full close. The full close then runs
with the default linger, detaches the pcb from the socket, and keeps its
queue, so a later `setsockopt` cannot reach it.

**Fix 2 (tasmolike-rs):**
- **Lingering then abortive close:**
  1. `set_zero_linger()` **before** `shutdown()`.
  2. Send our FIN.
  3. Wait up to 5 s for the client's FIN.
  4. Drop.

  A well-behaved client ACKs everything before its FIN, so the normal path
  closes gracefully. An abandoned connection gets RST and its send queue
  is freed at once.
- `CONFIG_LWIP_SO_LINGER=y`, which `set_zero_linger` needs.
- Listen backlog 2 (`TcpSocket::listen(2)`), so queued connections cannot
  take heap from the one being served.

**Fix 3 (this commit, plus the app-side log levels): console throughput.**
With `CONFIG_LOG_DEFAULT_LEVEL_VERBOSE` on a blocking 115200-baud UART, log
bytes are data-plane time. The following were saturating the UART (about
13 KB/s of output against about 11.5 KB/s of capacity) and throttling the
tailnet to a few packets/s:

- per-packet `info!` lines (`RecvPacket`, `OutboundPacket`,
  `InboundDecrypted`);
- one `warn!` per router drop;
- the Step 5 to 7 per-packet heap probes;
- per-request efuse/nvs debug lines.

That throttling caused channel drops, then retransmits, then more queued
segments.

Changes:
- `heapdiag::ENABLED` (off unless the `heap-trace` feature is on) now gates
  every per-packet probe.
- The per-packet lines are `trace!`.
- The drop warning is rate-limited to powers of two and every 256th drop.
- The app caps `tm_derp`/`tm_runtime`/`tm_wg`/`efuse`/`nvs`/`pthread`/
  `registry` at Info.

This commit also adds `heapdiag::dump_heap_map()` (on demand, allocation-free)
and `heapdiag::count_pbufs()`. The failed-allocation dump threshold is now
3000 B.

**Results** (real ESP32-C3 on `/dev/ttyACM0`, built from this repo's main
checkout at `6d5d23d` + this commit; requests from bospill over DERP `sao`,
RTT 400 to 700 ms, `curl /cm?cmnd=Status`):
```
full soak (one boot, about 21 min of load):
  back-to-back:           60/60
  parallel 4x20 Status 0: 80/80   (client timeout 40 s)
  slow soak (1 per 10 s): 36/36
  final burst:            30/30
  resets 0, alloc failures 0, server-side timeouts 0
  largest_free, sampled every 250 ms: min 15872  (Step 7: 8100)
  largest_free at accept/close (n=209): min 18432, p10 26624, median 32768
  min_ever_free 24248, main-task stack min free 7248 B (Step 7: 6088)
  pbuf bytes live at any accept/close: max 3072
```
Abusive case: 4-way parallel with a 10 s client timeout, so most clients
give up mid-response:

| run | fixes in place | largest_free min | outcome |
|---|---|---|---|
| before Fix 2 | none | down to 2304 | abort on the 3168 B alloc |
| with linger=0 after `shutdown` | partial | 4096 | no crash; up to 16 pbufs / 18 KB live after close |
| final | all | 12288 | 0 resets; at most 3 KB of pbufs live at any close |

The client success rate in the abusive case is low, 4/32. That is
throughput, not memory:
- one `Status 0` takes about 5 s end to end over this relay path (TCP slow
  start with `TCP_WND` 2440 and a 400 to 700 ms RTT);
- connections are served one at a time;
- so the 4th parallel client waits past 10 s.

**Bottom line**: the heap-margin issue is closed for this workload. The
smallest largest-free block seen under any load is 12288 B, and 15872 B in
the realistic soak. The largest request-path allocation is about 3.2 KB and
hyper's 8 KiB blocks are gone, so that is about 4x headroom, not 92 B.

Remaining, not heap:
- request latency over DERP (about 5 s for 3 KB), which a direct LAN path
  (LAN-direct plan) or a larger `TCP_WND`/initial cwnd would address;
- router drops still occur under parallel load (at least 256 in the soak,
  with `CHAN_CAP`=2);
- the `heap_watch`/`heap-probe` instrumentation in tasmolike-rs
  `server.rs` stays, per the decision below.

**Decision (2026-09-29): the instrumentation stays permanently.** The user
accepted Step 8 and chose to keep all of the following as a standing safety
net, not a temporary aid to remove "once accepted":
- tasmolike-rs `heap_watch` (a 250 ms largest-free sampler that dumps a
  heap map below 10000 B);
- `heap_probe_at_accept` (per-connection largest/total free, stack
  high-water mark, live pbuf count);
- this repo's `heapdiag` (the `ENABLED` gating, the failed-alloc map dump,
  `dump_heap_map`, `count_pbufs`).

It is cheap: one heap-info call every 250 ms, a heap walk per connection,
and the per-packet parts are compiled out unless the `heap-trace` feature is
on. It also catches regressions early. The heap floor is now a number in
every log instead of something rediscovered after a crash. Later cleanups
should not remove it without a new explicit decision.

### Step 9 (2026-09-30): LAN round-trip latency; the router's 50-tick yield and per-PING disco work were most of it

**Context**: with LAN-direct up, `tailscale ping esp32c3` from the phone
averaged about 561 ms (290 to 1166 ms) on a confirmed direct path. A LAN
round trip should be tens of ms. The phone also saw the same range over
other paths, which points at the device, not the network.

**Method**: a new `latency-trace` feature (tm_buf `lat` module, forwarded
by tm_runtime; off by default) stamps each hop in microseconds into static
atomics:
- ICMP-over-WG: UDP rx, WG dequeue, decrypt, router, lwIP echo out, inject
  return, router netif, WG send, encrypt, router outbound, UDP tx;
- disco: UDP rx, disco dequeue, PONG sealed, router, UDP tx.

It prints at most one line per 300 ms plus a 10 s router summary (loop
iterations and time blocked in `vTaskDelay`), so the trace cannot saturate
the UART (Step 8 Fix 3). All numbers below are from the real ESP32-C3.
Traffic came from bospill, direct via `192.168.15.74:41641`, 30 samples per
run, and the load case was a back-to-back `curl /cm?cmnd=Status` loop.
Device-side values are from the device stamps; end-to-end values are what
bospill measured.

**Findings (before)**:

1. **The event router blocked 50 ms per event.** `tokio_freertos_yield()`
   is `vTaskDelay(50)`, and `CONFIG_FREERTOS_HZ=1000` makes that 50 ms. It
   ran at the top of every router iteration and after forwards. On the
   single-threaded executor that stalls every actor. Its effect:
   - An ICMP echo crossed the router three times and paid about 55 to 65 ms
     each time. Device-side hops in ms: WG dequeue 7-9, decrypt 3-4, to
     router 2-8, lwIP echo 1, **netif to router 56-94, router to WG send
     52-57**, encrypt 2, **to router outbound 58-65**, UDP send 3. The total
     p50 was 191 ms, of which about 170 ms was vTaskDelay.
   - Under curl load, 58-73% of wall time was spent in vTaskDelay. The
     router topped out near 9 events/s, so every queued event added 50 to
     100 ms. It also dropped more packets: WG channel drops reached 128 in
     the soak below, and pool drops 277.
2. **Disco spent about 138 ms per PING in `process()`**, out of 146-176 ms
   from UDP rx to PONG sent. The cost came from two things:
   - three X25519 scalar multiplications: `SalsaBox::new` to open,
     `SalsaBox::new` again to seal, and `our_disco_key.public()`;
   - four unconditional info-level `heap_probe_blocks` lines, about 600 B
     of blocking UART per PING.

   With the cache in place, the only PING that still builds a box took
   38.7 ms in `process()`. So one box costs about 35 to 40 ms and the UART
   lines about 30 ms. That split is inferred; no probe-gating-only build
   was flashed.
3. **WiFi modem sleep** (ESP-IDF default `WIFI_PS_MIN_MODEM`; nothing calls
   `esp_wifi_set_ps`). Plain LAN ICMP to the WiFi IP, with no tailmicro
   code involved, measured min 2-4, p50 58-71, max 112-122 ms, which
   matches waiting for DTIM beacons. This is the device radio, not
   tailmicro.

**Ruled out** (measured, each at most a few ms): WG decrypt (3.4 ms) and
encrypt (2.5 ms), UDP syscalls (2-3 ms), lwIP's echo (1 ms), and actor
channel queueing at idle. The WG data path does not wait for the 400 ms
tick; it is event-driven. **Path independence**: all of the device-side
cost is paid before and after path selection. DERP-received packets pass
through the same router, WG, and disco actors, so the phone seeing the same
300-1200 ms on another path fits: the latency was mostly on-device
scheduling plus the radio, not the network.

**Fixes**:
- `tm_runtime`: the event router yields 1 tick (`ROUTER_YIELD_TICKS`), not
  50, per event. It still yields to FreeRTOS on every iteration, so idle
  and lower-priority tasks keep running and the TWDT stays fed. The boot
  path in `Runtime::build` keeps its 50-tick yields.
- `tm_disco`:
  - the per-peer `SalsaBox` is built once and kept in the peer's
    rate-limit entry;
  - our disco public key is computed once in `DiscoActor::new`;
  - `seal_pong` takes the cached box;
  - a test checks that cached-box PONGs open and that forgeries still fail.
- `tm_disco`: the `heap_probe_blocks` calls are compiled out unless the new
  `heap-trace` feature is on (the Step 8 Fix 3 rule: per-packet
  diagnostics are opt-in). The permanent safety net is untouched: tasmolike
  `heap_watch`/`heap_probe_at_accept` and `tm_wg::heapdiag`.

**Results** (min / p50 / avg / p90 / max, ms):

| measurement | before | after |
|---|---|---|
| disco `tailscale ping`, idle | 174-178 / 228-230 / 245-273 / 290-429 / 424-542 (3 runs) | 45 / 124 / 121 / 128 / 135 |
| kernel ICMP over WG, idle | 202 / 276 / 276 / 322 / 404 | 57 / 115 / 115 / 167 / 190 |
| disco, under curl load | 214 / 476 / 478 / 754 / 965 | 20 / 88 / 94 / 131 / 260 |
| ICMP over WG, under curl load | 248 / 480 / 529 / 859 / 894, 20% loss | 54 / 113 / 126 / 218 / 241, 3% loss |
| device-side disco, UDP rx to PONG sent | p50 150-154 | p50 15.5, p90 19.3 |
| device-side ICMP, UDP rx to reply sent | p50 191, max 496 | p50 40.6, max 63.9 (load: p90 65.6, max 144.5) |
| router time in vTaskDelay, under load | 58-73% | 1% |
| curl `Status` total, under load | p50 2273, max 4752 (43 in 110 s) | p50 1303, max 1441 (69 in 110 s) |

After the fixes, the device-side ICMP hops are: dequeue 4-10, decrypt 3.4,
to router 2-9, lwIP 1.2, netif to router 5-8, to WG send 3-8, encrypt 2.5,
to router outbound 6-13, send 2.4.

**Heap safety of the faster router.** The Step 8 soak harness was run
over the direct path on both builds, from the same boot state:

| | before | after |
|---|---|---|
| back-to-back 60 | 60/60 in 134 s | 60/60 in 81 s |
| parallel 4x20 Status 0 (10 s timeout) | 38/80 | 80/80 |
| slow soak / final burst | 35/36, 30/30 | 36/36, 30/30 |
| resets, alloc failures, timeouts | 0, 0, 0 | 0, 0, 0 |
| heap_watch min largest_free | 11776 | 13824 |
| largest_free at accept/close, min | 18432 | 17408 |
| min_ever_free | 18676 | 22832 |
| main-task stack min free | 7424 | 7424 |
| UDP pool drops / WG channel drops | 277 / 128+ | 144 / 64+ |

There is no heap regression. The router moves packets faster, so fewer
wait in flight.

**Remaining, not fixed here**:
- **WiFi modem sleep is about 100 ms of the remaining idle round trip.**
  An experiment build of the wrapper (not committed) called
  `esp_wifi_set_ps(WIFI_PS_NONE)` after `wifi.start()`. Results:
  - idle disco: 16 / 22 / 22 / 26 / 29 ms;
  - idle ICMP over WG: p50 46 ms;
  - plain LAN ICMP: p50 3 ms;
  - under load, disco p50 26 ms and ICMP p50 48 ms.

  Turning modem sleep off costs radio power, so it is the application's
  choice.
- **A back-to-back TCP connect costs about 1 s.** Each new connection
  opened right after the previous one closed took about 1.07 s to connect,
  which is Linux's initial SYN retransmit timeout. With 3 s gaps, 10/10
  connected in about 45 ms. In one sample, 5 slow connects matched exactly
  5 `pool_drop` increments. The SYN arrives while the previous
  connection's tail segments still hold `tm_buf` buffers, and
  `UDP_MIN_FREE_PKTBUFS` (2 of `POOL_N` = 4) drops it. This is most of the
  remaining curl time. Options:
  - wait briefly for a buffer in `rx_loop` instead of dropping, so lwIP's
    bounded UDP recvmbox provides the backpressure;
  - raise `POOL_N` to 6, about 3 KB more static DRAM.

  Both touch the Step 5/6 design and the heap budget, so they are left for
  a decision.
- **Observation, not investigated.** On two boots, the device's second full
  MapResponse, at about 75-115 s, arrived while bospill was briefly
  reconnecting to control. It listed only one peer. The device then logged
  `no peer for handshake initiator key` every 5 s and never re-added
  bospill until it rebooted. Disco PINGs were still answered. No later
  MapUpdate arrived to repair it.

### Step 10 (2026-09-30): `POOL_N = 6` for the back-to-back TCP stall; tried, not kept

**Hypothesis** (Step 9, "Remaining"): the new connection's SYN is dropped by
the UDP receive path's 2-free-buffer floor, so raising `POOL_N` from 4 to 6
removes the ~1 s connect.

**Cost, measured** from the ELFs: `tm_buf::BLOCKS` grows from 0x1820 to
0x2430 bytes (6176 to 9264), 1544 B per buffer (1532 data, the `Vec` length
word, the pool node). `.dram0.bss` grows by exactly 3088 B, and boot free
heap drops from 57208 to 54396.

**Result**: same method as Step 9, over the direct path, from a fresh boot
each time. `b2b` is 40 back-to-back `Status` requests; a connect over 500 ms
is a SYN retransmit.

| | `POOL_N = 4` | `POOL_N = 6` | `POOL_N = 6`, WG cmd channel 4 (experiment) |
|---|---|---|---|
| b2b connects > 500 ms | 40/40 | 39/40 | 5/40 |
| b2b connect p50 / total p50, ms | 1160 / 1306 | 1171 / 1311 | 171 / 338 |
| 10 requests, 3 s apart: connect p50 | 133 | 115 | |
| UDP `pool_drop` (whole run) | 167 | 6 | 14 (short run) |
| back-to-back 60, parallel 4x20, slow soak, final burst | 60/60, 80/80, 36/36, 30/30 | 60/60, 80/80, 36/36, 30/30 | parallel 4x10: 40/40 |
| resets, alloc failures, timeouts | 0, 0, 0 | 0, 0, 0 | 0, 0 |
| heap_watch min largest_free | 14336 | 11776 | 13824 (short run) |
| largest_free at accept/close, min | 16384 | 14336 | |
| min_ever_free | 23244 | 22376 | |

`POOL_N = 6` removes the pool drops, but the stall stays: the drops move one
hop later, to `forward_or_drop` into the `CHAN_CAP = 2` WG command channel
("WgCmd::InboundPacket (udp) channel full"). During the b2b phase that
counter reached 32 by 83 s of uptime at 6, versus 159 s at 4. The likely
shape: a client's final ACK/FIN and its next SYN arrive together, and a
2-slot queue cannot hold them while the WG actor decrypts. Only the combination, in an
uncommitted experiment, mostly fixes it. On its own, 6 costs 3 KB and about
2 KB of minimum largest free block for no gain, so it was reverted.

Options for a real fix, left for a decision:
- `POOL_N = 6` plus a WG command channel of 4 (measured above; the
  remaining 5 slow connects match the remaining pool/channel drops);
- have `udp_rx_task` wait for WG channel space instead of `try_send`.
  The UDP task is not the router, so awaiting does not risk the Step 7
  deadlock, and lwIP's bounded recvmbox then provides the backpressure.
  `rx_loop` takes a sync callback, so this needs a restructure.

### Step 11 (2026-09-30): `POOL_N = 6` plus a 4-slot `WgCmd` channel; kept

**Change**: the first option from Step 10.
- `tm_buf::POOL_N` goes from 4 to 6.
- A new `tm_runtime::WG_CMD_CHAN_CAP = 4` sizes the router-to-WG `WgCmd`
  channel.
- Every other inter-actor channel stays at `CHAN_CAP = 2`.

**Cost, measured** from the ELF:
- Pool: `.dram0.bss` grows by exactly 3088 B, as in Step 10 (`BLOCKS`
  0x1820 to 0x2430).
- Channel: static cost 0. `async_channel::bounded` allocates its slot array
  on the heap. From DWARF, `tm_wg::WgCmd` is 56 B and
  `concurrent_queue::bounded::Slot<WgCmd>` is 64 B, so going from 2 to 4
  slots adds 128 B in one heap allocation, allocated once at boot.
- Boot heap: `Heap after storing device` measured 54272, 54288 and
  54384 B, against 54396 B for `POOL_N = 6` alone and 57208 B at 4. The
  total is about 3.2 KB of DRAM against Step 9's build.
- The 2 extra slots hold `PktBuf` handles, not bytes. The packet data stays
  in the pool.

**Result**: same harness and direct path as Steps 9 and 10.
- The full soak ran twice, each from a fresh boot.
- On a third boot, 5 back-to-back 40-request passes ran 20 s apart,
  followed by a 4x20 parallel run. That parallel run passed but went
  unlogged: a harness bug had stopped the serial capture before it.
- Then 6 further fresh boots each served one request, to check the boot
  phase's heap.

| | Step 10, `POOL_N = 4` | Step 10, `POOL_N = 6` | soak 1 | soak 2 | 5 x b2b40, one boot |
|---|---|---|---|---|---|
| b2b connects > 500 ms | 40/40 | 39/40 | 5/40 | 6/40 | 4, 3, 3, 4, 7 of 40 |
| b2b connect p50 / total p50, ms | 1160 / 1306 | 1171 / 1311 | 172 / 344 | 170 / 342 | 167-179 / 328-353 |
| 10 requests, 3 s apart: slow, connect p50 | 0, 133 | 0, 115 | 0, 124 | 1, 122 | |
| back-to-back 60, parallel 4x20, slow soak, final burst | 60/60, 80/80, 36/36, 30/30 | same | 60/60, 80/80, 36/36, 30/30 | 60/60, 80/80, 36/36, 30/30 | parallel 80/80 |
| resets, alloc failures, timeouts | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 |
| heap_watch min largest_free | 14336 | 11776 | 13312 | **7936** (at boot, see below) | 15872 |
| largest_free at accept/close, min | 16384 | 14336 | 16384 | 16384 | 18432 |
| min_ever_free | 23244 | 22376 | 22092 | **2592** (at boot, see below) | 23620 |
| main-task stack min free | | 7408 | 7408 | 7392 | |
| UDP `pool_drop` (whole run) | 167 | 6 | 25 | 30 | 3 |
| WG command channel drops (whole run) | | 32 by 83 s | 8 to 15 | 8 to 15 | 0 |

Over all 280 back-to-back connects, 32 (11%) were slow, against 98-100%
before. Connect p50 is 169 ms and total p50 337 ms, against about 1.17 s
and 1.31 s. The rate stays between 3 and 7 per 40 across 7 passes on 3
boots, so Step 10's short sample of 5/40 was representative.

**The residual 11% is not these two queues.** On the 5-pass boot, the 21
slow connects coincided with 0 WG command channel drops and 3 UDP pool
drops for the whole boot. One slow connect also occurred with 3 s gaps
(soak 2). The remaining ~1.1 s connects are still SYN-retransmit shaped.
Where that SYN is lost was not investigated: WiFi (modem sleep, Step 9),
lwIP, or the tailnet netif are all open. The obvious suspect,
`LWIP_MAX_ACTIVE_TCP=16` against 40 closes in about 15 s with
`TCP_MSL=60000`, was not tested. lwIP reclaims TIME_WAIT PCBs when that
limit is hit, so it is not an obvious drop point.

**One boot-time heap dip, not reproduced.** On soak 2's boot, at 22 s of
uptime, the heap reached `min_ever_free=2592`, with a 7936 B largest free
block. That was before the harness's first request (at 50 s), during the
first WireGuard handshakes with all three peers, DERP connect, and disco.
Some packets were dropped on the DERP-path `WgCmd` channel at the same
moment. The heapdiag map from that instant has 10 x 1664 B and 11 x 1728 B
used blocks, about 35 KB. That size does not match a `tm_buf` heap
fallback, which is about 1.55 KB. They look like WiFi/lwIP receive
buffers, but this is inferred from the size; no allocation was traced to
its owner.

That boot was the first after a different firmware build (from a parallel
experiment) had run on the board. The dip did not recur in any other boot
of this build: soak 1, the 5-pass boot, and 6 more fresh boots (min_ever_free
20408-26556, heap_watch min largest_free 11776-19456). It appears in none
of the ~12 earlier captured boots in Steps 8-10, which were all at 18.6 KB
or more. It cannot be ruled out that this change makes such a burst more
likely: 2 more `WgCmd` slots let more received packets wait at once. It
is recorded here as open. No reset or allocation failure followed.

**Kept**: about 3.2 KB of DRAM relative to `POOL_N = 4` buys roughly
7x faster connects (p50 169 ms vs about 1.17 s) and 3.9x faster requests
(p50 337 ms vs 1.31 s) for back-to-back HTTP clients. Outside the one boot
dip, the minimum largest free block did not measurably drop:
- heap_watch minimum: 13312 and 15872, against 14336 at `POOL_N = 4`;
- accept-time minimum: 16384 and 18432, against 16384.

Run-to-run spread on the same build is about 2-3 KB. Step 10's second option,
`udp_rx_task` awaiting WG channel space, remains the no-extra-RAM
alternative. It would not address the residual 11% either, since that
occurs with neither queue dropping.

## Design principle going forward

Fixed-size, same-shape allocations that recur on a hot path should be
allocated **once** (lazily, on first use, or pre-warmed at a known-good
moment) and reused, not `Box::new`'d and dropped per call:

- Within one actor and one synchronous call: a persistent scratch field
  taken and returned around the call (`recv_scratch`/`dispatch_scratch`).
- Across actors (moved through an `async_channel`): `tm_buf::PktBuf`, whose
  `Drop` returns the buffer to a shared pool. New packet-carrying channels
  should use it rather than a fresh `Box<heapless::Vec<..>>`.

## Design record: cross-actor packet buffers

Why the pool looks the way it does, and what else was considered (written
2026-09-26 as a proposal, then implemented as "Step 0" (one buffer size,
router forwards instead of copying) plus the RAII free-list, later moved
onto a static `heapless` object pool; see "Fixed" for what landed).

### Before

| Path | Allocations per packet (size incl. `heapless` len word) |
|---|---|
| DERP -> WG transport (inbound data) | 1536 (`tm_derp`) -> 1504 (router re-box) -> 1504 (`pkt_to_box`, decrypted) |
| DERP -> disco | 1536 -> 260 (router re-box) |
| netif -> WG -> DERP (outbound data) | 1504 (tcpip thread) -> 1504 (`pkt_to_box`, encrypted) -> 1536 (router re-box) |
| `on_tick` handshake/keepalive -> DERP | 1504 (`emit_to_peer`) -> 1536 (router re-box) |

Three ~1.5 KB alloc/free pairs per data packet, alternating between two
size classes 32 B apart (plus 260 B for disco) — close to worst case for
ESP-IDF v5.5's TLSF `multi_heap`: a freed 1504 hole cannot satisfy the next
1536 request. After Step 0: two pairs, all 1536. After the pool: none while
at most `POOL_N` packets are in flight.

### Scheduling facts that set the safety bar

- The app runs a tokio `current_thread` runtime, and `Runtime::join`/
  `connect` poll all five actors inside one `tokio::join!`
  (`tm_runtime/src/lib.rs`, `Driver` construction): the actors are
  cooperative coroutines on one FreeRTOS task and only interleave at
  `.await` points.
- Exception: `tailnet_output_cb` (`tm_netstack/src/tailnet/device.rs`) runs
  on lwIP's tcpip FreeRTOS thread and produces packets from there.
- `Runtime::spawn` uses `tokio::spawn`, which imposes `Send` bounds.
- `inject_inbound` copies into an lwIP `PBUF_POOL` pbuf, so lwIP never
  retains our buffer.

Hence the pool must be `Sync` across FreeRTOS threads (not `RefCell`).
The first version used a `std::sync::Mutex` held for one push/pop; the
current one is heapless's lock-free stack, whose CAS goes through
`portable-atomic` + `critical-section/std` on this target. Neither is held
across an `.await`.

### Rules the implementation relies on

- **Never wait for a buffer.** `acquire` falls back to allocation on an
  empty pool. Waiting could deadlock: `tm_derp` blocked on a buffer while
  the free-able buffers sit in its own command channel, which only it
  drains.
- **Safety is ownership.** A `PktBuf` has one owner; returning it is
  dropping it, so use-after-return and double-return are impossible
  (the only `unsafe` in `tm_buf` is the one-time `&'static mut` to the
  static blocks). Undelivered messages
  (including those handed back in a `SendError`) are dropped and so
  recycled.
- **The failure mode is benign.** Holding buffers longer than expected, or
  a burst beyond `POOL_N`, just degrades to the old alloc/free behavior
  (same size) and shows up in `pktbuf_pool allocs=` (otherwise 0).
- **Sizing.** Worst-case in flight is ~6 packet channels x `CHAN_CAP = 2`
  + ~1 in hand per actor ~= 16; realistic steady state is 2-4, with
  bursts of ~5-6 during an HTTP connection. `POOL_N = 4` (~6 KB). Static
  storage does not make buffers free: `.bss` comes out of the same
  internal DRAM as the heap, so each extra buffer is ~1.5 KB less heap
  from boot (it just can't fragment it). A brief 8 was measured and
  reverted; see the A/B under "Fixed". Tune from `pktbuf_pool allocs=`.
- **One size.** `tm_wg`'s vendored `Packet` stays 1500 B internally; only
  the channel type is 1532. Oversize packets are dropped at the `tm_wg`
  boundary (see "Fixed").

### Alternatives considered and not taken

- **A. `bytes::Bytes`/`BytesMut`.** Viable: `bytes 1.12.1` is already in
  the build via tokio (and via hyper/axum in the app), supports
  `no_std + alloc`, and its atomic refcounts work on this target. But to
  avoid allocating it must be used as a per-producer ring of
  single-packet `BytesMut`s recycled with `try_reclaim` (one big arena is
  all-or-nothing: a single straggling slice pins it, and `reserve` then
  allocates a whole new arena). Each slot's first `split()` also `Box`es a
  hidden `Shared` header (`promote_to_shared`), `Bytes` is immutable, and
  a stray `.clone()` silently pins a slot. Net: the same pool as B with an
  implicit refcount-based "is it free?" check and more to audit. Still the
  right tool if packets ever need zero-copy sub-slicing.
- **C. Static `.bss` slab with owned 1-byte index handles** (atomic
  bitmask, `UnsafeCell` slots). Rejected as hand-rolled: ~30-50 lines of
  `unsafe`. Its goal (packet path entirely off the heap) was later
  reached with `heapless::pool` instead, with no call-site changes outside
  `tm_buf`. Cost: the ~6 KB (`POOL_N = 4`) is now reserved in `.bss` at boot even when
  the tailnet is never used.
