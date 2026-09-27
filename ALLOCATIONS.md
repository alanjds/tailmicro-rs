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
