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
  (the free-list design in the design record below; commits `d1607a8`,
  `b392722`.) The channel buffer
  is `tm_buf::PktBuf`: a pointer-sized owner of a boxed `PKT_CAP` buffer
  whose `Drop` puts the storage back into a process-wide free list
  (`static POOL: Mutex<heapless::Vec<Box<PktInner>, POOL_N = 4>>`) instead
  of freeing it. Producers — `tm_derp`'s `RecvPacket` handling,
  `tm_wg::pkt_to_buf` (was `pkt_to_box`, used by `drain_recv` and
  `emit_to_peer`), the lwIP netif output callback, the rung-6a ICMP echo —
  call `PktBuf::acquire()`/`from_slice()`, which pop from the pool and
  allocate only when it is empty (counted). `WgActor::apply_map` calls
  `tm_buf::prewarm()` right after the lazy `WgEndpoint` allocation, so the
  4 x 1536 B (~6 KB, held permanently) are carved before per-packet traffic
  starts. The router's "heap after inbound-decrypted" debug line now also
  prints `pktbuf_pool: free= allocs= frees=`: once warm, `allocs` should
  stay at 4; growth means more than `POOL_N` packets were in flight.
  **Verified: builds only** — host `cargo build`/`cargo test` for
  `tm_buf`/`tm_wg`/`tm_disco`/`tm_derp` (+`etls`)/`tm_netstack` pass
  (`tm_buf` has a pool-lifecycle unit test: reuse returns the same
  pointer, no allocation while warm, exhaustion falls back, overflow frees
  on return, `size_of::<PktBuf>() == size_of::<usize>()`), and
  `tm_runtime`, `tm_netstack`, `tm_derp --features etls` and the root
  `tailmicro` lib cross-compile for `riscv32imc-esp-espidf`. (A plain
  `cargo build --workspace` on host fails before and after this change:
  `tm_tls` needs a backend feature and `tm_runtime` pulls `esp-idf-sys`.)
  **Not yet verified on hardware**: the firmware is built from
  `tasmolike-rs`, which had someone else's uncommitted work in progress,
  so it was deliberately not built or flashed. To verify, flash and check
  that the `pktbuf_pool` counters stay flat under the `status 0` stress
  test and that no `memory allocation of 15xx bytes failed` appears.

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
router forwards instead of copying) plus the RAII free-list; see
"Fixed" for what landed).

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

Hence the pool is behind a `std::sync::Mutex` (not `RefCell`), held only
for one push/pop inside `acquire`/`Drop` — never across an `.await`, and no
allocation or free happens while holding it.

### Rules the implementation relies on

- **Never wait for a buffer.** `acquire` falls back to allocation on an
  empty pool. Waiting could deadlock: `tm_derp` blocked on a buffer while
  the free-able buffers sit in its own command channel, which only it
  drains.
- **Safety is ownership.** A `PktBuf` has one owner; returning it is
  dropping it, so use-after-return and double-return are impossible
  without `unsafe` (there is none in `tm_buf`). Undelivered messages
  (including those handed back in a `SendError`) are dropped and so
  recycled.
- **The failure mode is benign.** Holding buffers longer than expected, or
  a burst beyond `POOL_N`, just degrades to the old alloc/free behavior
  (same size) and shows up in `pktbuf_pool allocs=`.
- **Sizing.** Worst-case in flight is ~6 packet channels x `CHAN_CAP = 2`
  + ~1 in hand per actor ~= 16; realistic steady state is 2-4. `POOL_N = 4`
  (~6 KB permanent) was chosen over the proposal's 6 because the heap is
  already tight; raise it only if the counter shows sustained fallback.
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
  bitmask, `UnsafeCell` slots). Takes the packet path off the heap
  entirely, but needs ~30-50 lines of `unsafe` and permanently shrinks
  the heap at boot even when the tailnet is never used. Kept as the
  upgrade path: switching `tm_buf`'s internals to it would change no call
  site outside `tm_buf`, if the heap-based pool proves insufficient.
