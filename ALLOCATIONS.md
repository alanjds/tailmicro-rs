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

## Next up

- **`tm_derp` — inbound payload re-boxed on every DERP packet.**
  `tm_derp/src/lib.rs` (`DerpActor` main loop, `RecvPacket` handling) does
  `Box::new(payload)` per received packet, where `payload` is a fixed
  `heapless::Vec<u8, MAX_DERP_PAYLOAD>` (`MAX_DERP_PAYLOAD = 1500 + 32 =
  1532`, so ~1.5 KB per box). Same shape as the `RecvOut` fix: same fixed
  size every time, freed almost immediately after being forwarded over the
  `DerpEvent` channel. Candidate fix: a small fixed-size pool/free-list of
  boxed buffers reused across receives (a single persistent scratch box
  won't work here directly since the buffer is *sent* through the event
  channel and consumed asynchronously by the receiver, so it can't be
  reclaimed synchronously the way `RecvOut` is — needs either a bounded pool
  with a return path, or accepting the box back once the receiver is done
  with it).

- **`tm_wg::WgActor::on_tick` — `dispatch()` output re-boxed every tick
  (~400 ms).** `Box::new(self.endpoint().dispatch(now, now_unix()))` boxes
  an `ArrayVec<(PeerId, Packet), _>` (~12 KB per the existing comment) fresh
  every tick, dropped at the end of the same function. Same shape as the
  `RecvOut` fix (synchronous, fully consumed before the function returns) —
  could become a second persistent scratch field on `WgActor`, allocated
  lazily alongside `recv_scratch`.

- **`tm_control` — `serde_json::to_vec` / `from_slice` for `MapRequest` /
  `MapResponse` / `RegisterRequest`.** Variable-length allocations (register
  body, publish body, republish body, and the ~29 KB live-measured
  MapResponse body). These are control-plane-only (rare: register once,
  republish once after DERP-home selection, then periodic map polls), so
  lower priority than the per-packet data-plane churn above, but each one is
  a large, variable-sized transient allocation that competes for the same
  contiguous space the data plane's fixed-size boxes need. Not yet measured
  against the failure log; revisit if register/republish ever coincides with
  a crash.

- **`tasmolike-rs` (app, not this repo) — axum/Tasmota JSON status
  handling.** The variable-sized `String`/`format!`/`serde_json` traffic
  from handling each HTTP request is the other half of the fragmentation
  picture (it's what's interleaving with the data-plane's fixed-size boxes
  in the failure log). Out of scope for this repo, but worth flagging
  upstream: pre-sized/heapless response buffers there would reduce the
  variable-size allocation traffic competing with the data plane.

## Design principle going forward

Fixed-size, same-shape allocations that recur on a hot path should be
allocated **once** (lazily, on first use) and reused via `&mut` for the life
of the actor, following the `WgEndpoint`/`RecvOut` scratch-buffer pattern —
not `Box::new`'d and dropped per call. Reserve `Box::new` for allocations
that genuinely need to be short-lived and cannot be reused (e.g. values
moved across an async channel to a different task, where a synchronous
take/return dance is not possible).
