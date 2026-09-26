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

## Hard to remove (cross-actor channel sends, not a single-call-frame reuse)

These all share one shape: a fixed-size buffer is boxed fresh and moved
through an `async_channel` to a different actor task, which consumes it on
its own schedule. Unlike `RecvOut`/`DispatchOut` (boxed, used, and freed
within one synchronous call), the sender here has no way to know when the
receiver is done with the buffer, so a single persistent scratch field
would be unsound — the receiver could still be holding buffer N when the
sender starts overwriting it for N+1. Fixing this needs a real mechanism
(a bounded pool with an explicit return path, or a shared buffer type the
whole pipeline forwards by reference instead of copying at each hop), which
is more design commitment than the scratch-reuse pattern used above.
Documented rather than fixed, per your instruction to flag rather than
force these:

- **`tm_derp` — inbound payload re-boxed on every DERP packet.**
  `tm_derp/src/lib.rs` (`DerpActor` main loop, `RecvPacket` handling) does
  `Box::new(payload)` per received packet, where `payload` is a fixed
  `heapless::Vec<u8, MAX_DERP_PAYLOAD>` (`MAX_DERP_PAYLOAD = 1500 + 32 =
  1532`, so ~1.5 KB per box), sent via `DerpEvent::PacketReceived`.

- **`tm_runtime::event_router_task` — DERP payload copied and re-boxed a
  second time**, right after the above, when demuxing disco-vs-WireGuard:
  a fresh `heapless::Vec::new()` + `extend_from_slice(&payload)` +
  `Box::new(...)` builds either `DiscoCmd::MaybeDisco { data: Box<..., 256> }`
  (via `disco_tx2`) or `WgCmd::InboundPacket { payload: Box<..., 1500> }`
  (via `wg_tx2`). This is a copy *and* a second box of data already boxed
  once by `tm_derp` — a unified buffer type across `tm_derp`/`tm_wg`/
  `tm_disco` (today: 1532 B / 1500 B / 256 B, all different) would let this
  hop forward the same box instead of copying, but that's a cross-crate
  type change, not a local one.

- **`tm_wg::WgActor` — `pkt_to_box` re-boxes each outbound/decrypted packet
  individually.** `drain_recv` (called from `on_inbound`/`on_send_data`)
  calls `pkt_to_box(pkt) -> Box<heapless::Vec<u8, 1500>>` once per packet in
  `out.to_peer` and `out.decrypted` (up to 4 times per call, `OUT_CAP=2`
  each), and `emit_to_peer` (called from `on_tick`'s dispatch loop, up to
  `DISPATCH_CAP=4` times per tick) calls it once more — each box sent
  through the `WgEvent` channel to `tm_runtime::event_router_task`. Same
  shape as the `tm_derp` case above: fixed size (1500 B), but consumed
  asynchronously by a different task, so `RecvOut`'s synchronous
  take/return pattern doesn't apply directly. Notably `RecvOut` and
  `DispatchOut` (now scratch-reused, see Fixed above) are exactly the
  *sources* of the packets `pkt_to_box` then re-copies into fresh boxes for
  the channel send — so this is the next hop in the same pipeline, and the
  most-frequently-hit instance of this whole category (up to 8 boxes per
  `on_tick`/`on_inbound` cycle vs. 1 for `tm_derp`).

- **`tasmolike-rs` (app, not this repo) — axum/Tasmota JSON status
  handling.** Confirmed by the 2026-09-26 hardware test above: the 16384 B
  axum connection buffer and the 3148 B `tasmota_compat::cm_status`
  allocation are the other half of the contention, not fixable from this
  repo.

## Design principle going forward

Fixed-size, same-shape allocations that recur on a hot path should be
allocated **once** (lazily, on first use) and reused via `&mut` for the life
of the actor, following the `WgEndpoint`/`RecvOut` scratch-buffer pattern —
not `Box::new`'d and dropped per call. Reserve `Box::new` for allocations
that genuinely need to be short-lived and cannot be reused (e.g. values
moved across an async channel to a different task, where a synchronous
take/return dance is not possible).
