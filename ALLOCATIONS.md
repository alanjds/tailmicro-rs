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

## Proposal: removing the cross-actor per-packet boxes (design, not implemented)

Written 2026-09-26 against branch `wg-dispatch-scratch`. Nothing below is
implemented yet; this is a comparison of three mechanisms for the "Hard to
remove" items above, plus a recommendation.

### What actually happens per packet today

| Path | Allocations (size incl. `heapless` len word) | Sites |
|---|---|---|
| DERP -> WG transport (inbound data) | 1536 (`tm_derp`) -> 1504 (router re-box) -> 1504 (`pkt_to_box` for `decrypted`) | `tm_derp/src/lib.rs:312-319`, `tm_runtime/src/lib.rs:491-496`, `tm_wg/src/lib.rs:376-382,406-410` |
| DERP -> disco | 1536 -> 260 (router re-box) | `tm_derp/src/lib.rs:312-319`, `tm_runtime/src/lib.rs:481-487` |
| netif -> WG -> DERP (outbound data) | 1504 (tcpip thread) -> 1504 (`pkt_to_box` for `to_peer`) -> 1536 (router re-box) | `tm_netstack/src/tailnet/device.rs:210-211`, `tm_wg/src/lib.rs:368-374`, `tm_runtime/src/lib.rs:530-535` |
| `on_tick` handshake/keepalive -> DERP | 1504 (`emit_to_peer`) -> 1536 (router re-box) | `tm_wg/src/lib.rs:389-398`, `tm_runtime/src/lib.rs:530-535` |

So every data packet costs **three** ~1.5 KB alloc/free pairs, and they
alternate between **two size classes that differ by 32 bytes** (1504 vs
1536) plus a 260 B one for disco. That is close to the worst case for a
first-fit/TLSF heap (ESP-IDF v5.5's `multi_heap` is TLSF): a freed 1504 hole
cannot satisfy the next 1536 request, so each hop tends to carve a fresh
block instead of reusing the one just freed. (The same copy-and-re-box also
exists in the `Runtime::spawn` router duplicate at
`tm_runtime/src/lib.rs:1014-1031`.)

### How the actors are actually scheduled (this sets the safety bar)

- The app builds a tokio **`current_thread`** runtime
  (`tasmolike-rs/src/main.rs:58`, `block_on`), and `Runtime::join`/`connect`
  run all five actor futures (control, derp, disco, wg, event_router) inside
  **one** `tokio::join!` (`tm_runtime/src/lib.rs:873-879`). So the dataplane
  actors are **cooperative coroutines on one FreeRTOS task**: they interleave
  only at `.await` points and never run truly concurrently with each other.
- **One real exception:** `tailnet_output_cb`
  (`tm_netstack/src/tailnet/device.rs:192-240`) runs on lwIP's **tcpip
  FreeRTOS thread** and `try_send`s a freshly boxed packet into
  `netif_out_tx`. Anything that participates in the netif outbound path
  must therefore be `Send`/`Sync`-correct across OS threads, not just
  across tasks.
- `Runtime::spawn` uses `tokio::spawn` (still current_thread), which imposes
  `Send` bounds on the actor futures even though they run on one thread.
- `inject_inbound` (`device.rs:79-104`) copies into an lwIP `PBUF_POOL`
  pbuf, so lwIP never retains our buffer after the call returns.

Consequence: a `RefCell`/`Rc` pool would be *logically* sound for the four
tokio-side actors, but the `Send` bounds and the tcpip-thread producer mean
any shared pool must be `Sync` (a `std::sync::Mutex` held only for a
push/pop — never across an `.await` — or atomics). Contention is
effectively nil, so the cost is one uncontended FreeRTOS mutex per
acquire/release.

### Step 0 (common to all three): one buffer type, forward instead of copy

All three alternatives assume the pipeline first converges on **one**
buffer size class for packets, e.g. `PKT_CAP = 1532` (the current superset,
`MAX_DERP_PAYLOAD`), so the router can *move* the buffer it received on to
the next actor instead of copying it:

- `DerpEvent::PacketReceived.payload` -> `WgCmd::InboundPacket.payload` or
  `DiscoCmd::MaybeDisco.data`: same object, moved (router checks
  `len <= 256` for disco explicitly instead of relying on the 256-cap
  truncation).
- `WgEvent::OutboundPacket.payload` -> `DerpCmd::SendPacket.payload`: same
  object, moved.

Where the type lives: the crate graph is `tm_derp -> tm_keys`,
`tm_wg -> tm_control, tm_keys`, `tm_disco -> tm_keys`, `tm_netstack ->`
(no `tm_*`). The only crate every packet producer already shares is
`tm_keys`, which is a poor home for a buffer type; a new ~100-line leaf
crate (`tm_buf`) depended on by `tm_derp`, `tm_wg`, `tm_disco`,
`tm_runtime` and optionally `tm_netstack` is cleaner.

Risk of unifying sizes: low. Disco just gets a larger-capacity buffer
(no extra allocation once pooled). WG today silently gets an *empty*
payload for 1501..1532-byte DERP frames (`heapless::extend_from_slice`
fails atomically and the `let _ =` hides it); with 1532 it gets the real
bytes and `recv_one_into` rejects them by parsing — strictly better.
Outbound 1500 -> 1532 always fits. `tm_wg`'s vendored `Packet`
(`CAPACITY = 1500`, `tm_wg/src/vendor/packet.rs:16`) is **not** touched:
it stays the in-crate crypto buffer inside `RecvOut`/`DispatchOut`; only
the channel-facing type changes.

Step 0 alone (still `Box::new` per packet, no pool) already drops each data
packet from 3 allocations to 2 and makes them all the **same size**, so a
just-freed hole exactly fits the next request. It is worth doing first
regardless of which alternative follows.

### Alternative A — `bytes::Bytes` / `BytesMut` (refcounted slices)

**Viability.** `bytes` is already in the build: `tokio` pulls it in this
workspace (`Cargo.lock`: `bytes 1.12.1`), and hyper/axum in `tasmolike-rs`
use it for every HTTP body. It supports `no_std + alloc`
(`default = ["std"]`), and the ESP-IDF target is `std` anyway; it relies on
atomic CAS for refcounts, which already works on this target (`Arc`,
tokio). So flash/viability is a non-issue. `Bytes` is 16 B on riscv32, so
channel messages no longer need a `Box` at all (removing the async_channel
31-slot stack-balloon concern that forced the boxing in the first place).

**Mechanism.** Each producer (DerpActor RX, WgActor output, netif callback)
owns a small **ring of N `BytesMut`**, each `with_capacity(PKT_CAP)`. Per
packet: pick a slot for which `slot.try_reclaim(PKT_CAP)` returns `true`
(bytes >= 1.8; it succeeds only when no `Bytes` split from that slot is
still alive, and then rewinds the slot to the start of its allocation
without allocating); `extend_from_slice(frame)`; `slot.split().freeze()`
-> `Bytes`, sent through the channel and moved hop-to-hop by the router.
When the final consumer drops the `Bytes`, the refcount falls back to 1
(the producer's slot) and the slot becomes reclaimable. Note:
`try_reclaim` is all-or-nothing **per allocation** — that is why the ring
must be N single-packet `BytesMut`s, not one big arena `BytesMut` sliced N
ways (one straggling slice would pin the whole arena, and `reserve` would
then allocate a *new* arena-sized block — worse than today).

**Changes.** `tm_derp`: `DerpEvent::PacketReceived`/`DerpCmd::SendPacket`
payload -> `Bytes`; RX ring in `run_connection` around `lib.rs:312`.
`tm_runtime`: router forwards `Bytes` (lines 471-499, 521-536, 1014-1031).
`tm_wg`: `WgCmd`/`WgEvent` payloads -> `Bytes`; `pkt_to_box` becomes
"copy `pkt.as_slice()` into a ring slot" (still one memcpy — the decrypted
data lives in `RecvOut`'s `Packet`). `tm_disco`: `MaybeDisco.data -> Bytes`.
`tm_netstack`: optional (tcpip-thread ring behind a `Mutex`).

**Allocation behavior.** Steady state: zero heap traffic for the payload.
But each slot's *first* `split()` promotes it `KIND_VEC -> KIND_ARC`,
which `Box`es a small `Shared` header (`promote_to_shared`,
`bytes-1.12.1/src/bytes_mut.rs:1106-1125`); it is retained while the slot
lives, so it is one-off per slot, not per packet — but it is exactly the
kind of hidden allocation this log exists to track. Ring exhausted -> must
drop the packet or fall back to `Bytes::copy_from_slice` (a fresh alloc).

**Safety.** Fully safe Rust from our side; `bytes` owns the unsafe and is
heavily audited. Use-after-return is impossible (immutable shared views,
refcounted). The failure mode is *silent pinning*: any `.clone()` of a
`Bytes` that gets stashed (a log line, a future WG queue, a retry list)
keeps its slot unreclaimable forever with no compile-time signal; the only
symptom is the ring quietly degrading to the fallback path.

**Complexity/risk.** Medium. The reclaim rules are subtle and implicit
(`split` vs `split_to`, when `try_reclaim` can rewind, KIND_VEC vs
KIND_ARC), and `Bytes` is immutable, so nothing downstream can reuse the
buffer in place. In effect this is a per-producer buffer pool (Alternative
B) whose "is it free?" check is an atomic refcount inside a third-party
type instead of an explicit ownership move — same result, more machinery,
less auditable.

### Alternative B — recycling free-list of uniform `Box`es (RAII return)

**Mechanism.** One process-wide pool of the Step-0 buffer:
`static POOL: Mutex<heapless::Vec<Box<PktInner>, POOL_N>>` where
`PktInner = heapless::Vec<u8, PKT_CAP>` (1536 B). The channel-facing type
is a newtype `PktBuf(Option<Box<PktInner>>)` (still a single pointer in
the channel message, so the existing stack-frame reasoning is unchanged):

- `PktBuf::acquire() -> PktBuf`: pop from `POOL`, else `Box::new` (fallback,
  counted). Never `.await`s.
- `impl Drop for PktBuf`: `clear()` the Vec, push the `Box` back into
  `POOL`; if the pool is full, let it deallocate (bounds the pool).
- `Deref/DerefMut` to `heapless::Vec<u8, PKT_CAP>` so call sites barely
  change (`extend_from_slice`, `&payload[..6]`, `payload.as_slice()`).
- Pre-warm `POOL_N` buffers once, early (e.g. alongside the first
  `ApplyMap`, same "allocate after the netmap buffer is freed" logic as
  `WgActor::endpoint`), so they are carved from a still-unfragmented heap
  and then never freed.

**Changes.** New leaf crate `tm_buf` (~80 lines, zero `unsafe`).
`tm_derp` `lib.rs:312-319`: `PktBuf::acquire()` + `extend_from_slice`
instead of stack Vec + `Box::new`; `DerpCmd`/`DerpEvent` payload types.
`tm_runtime` router: move the buffer on (lines 481-496, 530-535 and the
`spawn` duplicate), no copy. `tm_wg`: `WgCmd`/`WgEvent` payload types;
`pkt_to_box` becomes `pkt_to_buf` using `acquire()`. `tm_disco`:
`MaybeDisco.data: PktBuf`. `tm_netstack` `device.rs:210`: `acquire()`
instead of `Box::write(Box::new_uninit(), ..)` (the Mutex makes this safe
from the tcpip thread; the `Box` is already heap-resident so the tcpip
stack concern documented there is preserved).

**Allocation behavior.** After pre-warm: **zero** heap traffic per packet
while in-flight packets <= `POOL_N`; beyond that it falls back to exactly
today's behavior (one alloc/free of the *same* 1536 size) and increments a
counter worth logging next to the existing heap probes. Sizing: the hard
upper bound on buffers in flight is roughly 6 packet-carrying channels
(`derp_ev`, `wg`, `disco`, `wg_ev`, `derp`, `netif_out`) x `CHAN_CAP = 2`
+ ~1 in hand per actor ~= 16, but realistic steady state is 2-4.
`POOL_N = 6` (~9 KB permanently held) is a reasonable start; tune from the
fallback counter. The permanent cost is real (heap that today is only
transiently used), but it is held as N fixed blocks carved early, which is
exactly the "reserve a dedicated pool per subsystem" fix called for in
"Verified on real hardware, but not the whole story" above.

**Safety.** Comes entirely from Rust move semantics: a `PktBuf` has exactly
one owner at any time; returning it to the pool *is* dropping it, which
the borrow checker guarantees happens once and only after the last use. No
`unsafe`, no refcounts, no generation counters. Error paths are covered
automatically: a failed `send` returns the message inside `SendError`,
which is dropped -> recycled. The Mutex is held only inside
`acquire`/`drop` (never across `.await`), so no deadlock with the
cooperative scheduler, and it is correct for the tcpip-thread producer.
**Never make `acquire` wait** for a free buffer: that creates a cycle
(DerpActor awaiting a buffer while buffers sit in the `derp` cmd channel
that only DerpActor drains). Fallback-alloc (or drop, for datagrams) on
exhaustion keeps the system deadlock-free by construction.

**Complexity/risk.** Low. Mechanical type changes along one pipeline, same
lazy-once/reuse discipline as `recv_scratch`/`dispatch_scratch`, and the
worst case is "behaves like today". Main thing to get right is not letting
a `PktBuf` be held long-term by accident (same pinning risk as A, but
visible: it is an owned value with a named type, and the fallback counter
shows it).

### Alternative C — static slab with owned index handles (no heap at all)

**Mechanism.** Move packet storage out of the heap entirely:
`static SLAB: Slab<POOL_N>` in `.bss` with
`slots: [UnsafeCell<PktInner>; POOL_N]` and a `busy: AtomicU32` bitmask
(`POOL_N <= 32`). The channel carries a 1-byte, non-`Copy`, non-`Clone`
handle `SlabBuf { idx: u8 }`:

- `SlabBuf::acquire() -> Option<SlabBuf>`: CAS-claim a clear bit in `busy`.
  `None` on exhaustion -> drop the packet (or fall back to a heap `Box`,
  which requires an enum handle and gives back most of B's shape).
- `Deref/DerefMut` via `unsafe { &*SLAB.slots[idx].get() }`: sound because
  the handle is the unique owner of that bit.
- `Drop`: clear the bit with `Release` ordering.
- Optional generation counter per slot (`SlabBuf { idx, gen }`, checked in
  `deref` under `debug_assertions`) if handles are ever made `Copy` or
  serialized; with a non-`Copy` owned handle it is redundant.

**Changes.** Same call sites and type changes as B (`tm_buf` crate, router
forwarding, `pkt_to_buf`, `MaybeDisco`, netif callback); only the
`tm_buf` internals and the exhaustion policy differ.

**Allocation behavior.** **No heap involvement at all** on the packet path,
ever — not even a pre-warm. Memory cost is fixed at link time (visible in
`size`/the map file) and is taken out of DRAM before the heap is sized, so
it shrinks the heap by `POOL_N * 1536` at boot whether or not the tailnet
ever comes up (B only pays once the dataplane starts).

**Safety.** Requires ~30-50 lines of `unsafe` (`UnsafeCell` access,
`unsafe impl Sync for Slab`) whose soundness rests on the bitmask
invariant plus correct atomic orderings, and on the handle never being
duplicated (e.g. no `mem::forget`-then-rebuild, no `Clone` derive). This
is small and auditable but is the only alternative that needs it. CAS on
ESP32-C3 (riscv32imc, no `A` extension) is emulated by ESP-IDF; it already
works (`Arc`, tokio), but every acquire/release pays that cost — similar
to B's uncontended mutex.

**Complexity/risk.** Medium. Strongest fragmentation guarantee (the packet
path simply cannot fragment the heap), but it adds `unsafe`, a hard
exhaustion edge (drop vs. fallback needs a policy decision per path), and
permanently reserves RAM even on devices/configs that never use the
dataplane.

### Recommendation

**Do Step 0, then Alternative B.**

1. Step 0 (unify on a 1532-capacity channel buffer and forward instead of
   copy in the router) is low-risk and on its own removes one of three
   allocations per packet and eliminates the 1504/1536/260 size mix. Land
   and hardware-test it by itself first.
2. Then B: the `PktBuf` RAII free-list. It reaches zero per-packet heap
   traffic in the common case, its safety argument is "ownership moves"
   — no `unsafe`, no refcount subtleties, no generations — and its failure
   mode is a graceful fallback to today's behavior with a counter that
   tells us whether `POOL_N` is right. It follows the same "allocate once,
   early, reuse forever" principle as `recv_scratch`/`dispatch_scratch`,
   and generalizes it across actors via `Drop` instead of a synchronous
   take/return.
3. Keep C as the upgrade path: if B's pool, even pre-warmed early, still
   gets squeezed by the axum/`cm_status` side (see the 16384/3148 B
   failures above), switching `tm_buf`'s internals from a heap free-list
   to a `.bss` slab changes no call site outside `tm_buf`.

A (`bytes`) is viable on this target and costs no extra flash, but I
would not pick it here: to avoid allocations it has to be used as a
per-slot ring, at which point it is Alternative B with an implicit,
refcount-based "is it free?" test, a hidden `Shared` allocation per slot,
and immutable buffers — more to reason about for the same outcome. It
remains the right tool if we ever need to *slice* a packet into
sub-views (e.g. headers vs body) without copying, which the current
pipeline does not.
