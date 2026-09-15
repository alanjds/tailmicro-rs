# WireGuard data-plane (`tm_wg`) implementation plan

## Status

`tm_wg` is currently an unconditional stub (`tm_wg/build.rs` always emits
`cargo:rustc-cfg=wireguard_stub`). The ts2021 Noise/HTTP2 control plane
(`tm_control`) is fully working end-to-end against the real Tailscale control
server: registration, MapRequest, and streaming MapUpdate all succeed live
(see `docs/noise-handshake-wire-format.md`). This plan covers the next layer:
actually moving packets, i.e. the WireGuard (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`)
data plane.

This document was produced by: three parallel deep-dive evaluations (one per
candidate reference implementation), a fourth synthesis pass comparing them,
and four follow-up spikes that closed every open unknown the synthesis
flagged. All of that work is summarized below, then followed by the concrete
plan.

---

## Part 1 — Reference implementation comparison

Three existing implementations were evaluated as reuse candidates for the
`tm_wg` data plane: the official Go client (`tailscale/tailscale` +
`tailscale/wireguard-go`), the official Rust client's `ts_tunnel` crate
(`tailscale-rs` upstream, **not** any fork), and a working ESP32 client
called MicroLink (`CamM2325/microlink`, wrapping a forked `wireguard_lwip` C
component). A Go-runtime-alongside-Rust idea (to reuse `wireguard-go`
directly) was also considered and rejected early: `wireguard-go` uses
`reflect.ValueOf(fn).Pointer()`, a `//go:linkname` against an internal Go
runtime symbol, and `gvisor.dev/gvisor` netstack — none TinyGo-compatible —
and no precedent exists for two coexisting runtimes in one flashed ESP-IDF
image.

### Side-by-side

| | **Go — wireguard-go / tailscale fork** | **Rust — `ts_tunnel` (vendor-and-adapt)** | **C — MicroLink `wireguard_lwip` (FFI)** |
|---|---|---|---|
| **Direct reuse viable?** | **No.** Zero cgo exports; TinyGo cannot compile the real source (`reflect`+`runtime.FuncForPC`, `go:linkname runtime.fastrandn`, `x/sys/unix`, gvisor). Reference value only. | **Not as a dependency; yes as vendored source.** Blocked as a `path`/`git` dep on `x25519-dalek 3.0.0-pre.6` vs workspace `2`, `rand 0.10` vs `0.8`, edition 2024, `crypto_box` dead weight via `ts_packet`. None of that blocks copying the crypto-core files in. | **Yes, mechanically** — self-contained, chip-agnostic ESP-IDF component, no mbedTLS, no Xtensa asm, no HW-crypto deps. But `tm_wg`'s existing FFI declarations are entirely fabricated; not one declared symbol exists in the real `wireguardif.h`. |
| **Effort to integrate** | N/A as code; ~1,500 LOC worth reading as spec (`noise-protocol`, `noise-helpers`, `cookie`, `constants`, `timers`, `keypair`, `replay`, `tai64n`). | ~1,500 LOC vendored with mechanical edits (inject clock + RNG, `PacketMut`→`heapless::Vec<u8,1500>` with front-headroom) + ~600 LOC `endpoint.rs` rewritten against `ArrayVec`. Plus two must-add features (replay window, message-count rekey). | Vendor the component; add `esp-idf-sys`+`embuild` to `tm_wg` (has neither today); wire `ESP_IDF_EXTRA_COMPONENT_DIRS`; regenerate bindings with `bindgen` against lwIP types; base64-encode keys; wire `derp_output`/`udp_output` callbacks, `disable_socket_bind`, `inject_packet`, 400ms `periodic()`. Then most of `WgActor` becomes redundant — the C owns session/rekey/keepalive state. |
| **Runtime footprint** | Fatal: Go GC + goroutine stacks, 128-entry batch pools, 6 goroutines + 4 timers/peer. | Upstream allocates per packet (`BytesMut`, `HashMap<PeerId,Vec<PacketMut>>` returns, 32-deep `VecDeque` = 48KB/peer) — **the rewrite is precisely what removes this**; post-rewrite: static `ArrayVec`, no heap, no FFI, no lwIP entanglement. | Smallest, most predictable: ~20KB C, fixed tables, no heap. Pure-software X25519 on a 160MHz RISC-V core with no accelerator costs real CPU per handshake — anticipated via `wireguardif_periodic()`. |
| **Rekey** | ✅ full spec (message-count + time, initiator-only on time, 5s rate limit, triple-buffer keys) | ⚠️ time-only, hardcoded magic numbers, checked only on `send()` | ✅ full |
| **Cookie/MAC1+MAC2** | ✅ both directions incl. rate limiter | ⚠️ half — sends/verifies MAC1, but never generates cookie replies and never enforces MAC2 | ✅ both directions; only `is_under_load()` stubbed false (harmless for a client) |
| **Endpoint roaming** | ✅ authenticated-only, 4 update points + src-clearing on retry | ❌ explicitly out of scope by design (caller's job) | ✅ implemented, correctly suppressed for DERP-sourced packets |
| **Keepalive** | ✅ full | ✅ full | ✅ full |
| **Data-plane replay protection** | ✅ RFC 6479, 8128-counter window | ❌ **missing** — `session.rs:154 // TODO: nonce sliding window` | ✅ sliding window |
| **License** | wireguard-go **MIT** (not BSD — carry WireGuard LLC notice on derived files); tailscale/tailscale BSD-3 | **BSD-3-Clause — identical to `tailmicro-rs`** | `wireguard_lwip` BSD-3 (Floorsense); bundled `x25519.c` MIT; MicroLink glue MIT |
| **Real-world validation** | Reference-grade — it's the actual global deployment | Weak: v0.2.0 pre-1.0, README says "assume a critical security hole", 8 tests/2431 LOC, one happy-path loopback test | Mixed: no CI/tests, squashed history, but credible field-debugging scars (named cellular/DERP fixes); zero ESP32-C3-specific validation |
| **Biggest single risk** | Reading Go structs literally yields a 144-byte initiation nothing accepts (real value: 148 — see Part 2) | Adopting unaudited, under-tested code, then modifying it further, invalidating what little test coverage exists | Architectural inversion: `ml_wg_mgr.c` (1656 LOC) duplicates `tm_disco`/`tm_derp`/`tm_wg`'s own peer-LRU logic; adopting the FFI path means C permanently owns session state, hollowing out the Rust actor design |

### Recommendation (adopted)

**Vendor-and-adapt `ts_tunnel` as the base for `tm_wg`. Use wireguard-go as
the normative spec for what `ts_tunnel` gets wrong or omits (replay
protection, message-count rekey, exact constants). Use MicroLink as a working
bench peer and design reference — not as a dependency.**

Why: `ts_tunnel` is the only candidate where "reuse" and "clean" are the
same decision — same language, byte-identical BSD-3 license, and an
architecture (`Endpoint::send/recv` + `next_event()`/`dispatch_events(now)`)
that already matches `tailmicro-rs`'s actor pattern. It explicitly puts DERP
and cryptokey routing out of scope, which is exactly the seam `tm_derp`/
`tm_disco` were designed against — not a gap to paper over. Its
dependency-version blockers all dissolve once vendored instead of `git`/
`path`-dependency-ed, since the copied files get retargeted to the
workspace's existing `x25519-dalek 2`/`rand 0.8` (see Part 2, point 3)
instead of dragging the whole workspace onto a pre-release dalek that would
also destabilize the already-working `snow`-based control plane.

The FFI path (MicroLink) was rejected as the primary path because it
doesn't save work, it relocates it: in exchange for `esp-idf-sys`+`bindgen`+
callback-wiring effort, the C component takes over ownership of session,
rekey, keepalive, and netif plumbing — meaning any later "we'll rewrite it in
Rust properly" pass is a second from-scratch implementation against a
load-bearing seam, not a refactor. It also cuts against the pattern that
already worked on `tm_control`'s Noise IK implementation: small, documented,
`no_std`-friendly Rust over FFI to C. MicroLink's real, non-duplicable value
is that it's a working device you can put on a bench as an interop oracle —
that doesn't require vendoring a line of it.

---

## Part 2 — Four follow-up unknowns, resolved

Four specific unknowns were flagged as needing verification before writing a
plan. All four were checked independently (dispatched as four parallel
investigations); all four resolved favorably, with one change to the RAM
budget assumption.

### 1. Toolchain: let-chains / edition 2024 support — **no blocker**

`tailmicro-rs` has no `rust-toolchain.toml` of its own; it inherits
`tasmolike-rs`'s pinned `channel = "nightly"` (currently rustc 1.97.0-nightly).
There is no separate Espressif Rust fork in play — `riscv32imc-esp-espidf` is
an upstream tier-3 target built via `build-std` on the same nightly as the
host. Both gates clear trivially (let-chains need 1.88, edition 2024 needs
1.85), confirmed by an actual compile test targeting
`riscv32imc-esp-espidf` with a let-chain under `--edition 2024`.

**Action**: vendored `ts_tunnel` files can keep their let-chains verbatim.
Set `edition = "2024"` on `tm_wg/Cargo.toml` alone (edition is per-crate in
Cargo; the rest of the workspace stays `edition = "2021"` — mixed editions in
one workspace are fine). Do not bump the whole workspace.

*Minor unrelated hygiene note surfaced in passing*: the toolchain pin is an
unversioned floating `nightly`, so the build is only as reproducible as
whatever nightly was last fetched. Worth pinning a dated nightly at some
point — not a blocker for this work.

### 2. The 148-vs-144-byte Handshake Initiation layout — **148 confirmed, root cause found**

Verified against four independent authoritative sources (WireGuard
whitepaper, Linux kernel `messages.h`, wireguard-go's own marshal code,
Cloudflare's `boringtun`) — all agree byte-for-byte. The apparent 144-byte
discrepancy in an earlier read of the Go source was a single field-size slip:
assuming the TAI64N timestamp is 8 bytes (plain seconds) instead of its
actual **12 bytes** (8-byte seconds + 4-byte nanoseconds), which understates
the encrypted-timestamp field by exactly 4 bytes (12+16=28, not 8+16=24).

Full offset table (all four message types), for direct use in `tm_wg`:

**Handshake Initiation (type 1) — 148 bytes**

| Offset | Len | Field |
|---|---|---|
| 0 | 4 | `msg_type` (le32 = 1; byte-wise: `01 00 00 00`) |
| 4 | 4 | `sender_index` (le32) |
| 8 | 32 | `unencrypted_ephemeral` |
| 40 | 48 | `encrypted_static` (32 pubkey + 16 tag) |
| 88 | 28 | `encrypted_timestamp` (12 TAI64N + 16 tag) |
| 116 | 16 | `mac1` |
| 132 | 16 | `mac2` |

**Handshake Response (type 2) — 92 bytes**

| Offset | Len | Field |
|---|---|---|
| 0 | 4 | `msg_type` = 2 |
| 4 | 4 | `sender_index` |
| 8 | 4 | `receiver_index` |
| 12 | 32 | `unencrypted_ephemeral` |
| 44 | 16 | `encrypted_nothing` (**16 bytes** — bare Poly1305 tag over empty plaintext; assuming 0 here gives the wrong total of 76) |
| 60 | 16 | `mac1` |
| 76 | 16 | `mac2` |

**Cookie Reply (type 3) — 64 bytes**

| Offset | Len | Field |
|---|---|---|
| 0 | 4 | `msg_type` = 3 |
| 4 | 4 | `receiver_index` |
| 8 | 24 | `nonce` (XChaCha20 nonce) |
| 32 | 32 | `encrypted_cookie` (16 cookie + 16 tag) |

**Transport Data (type 4) — 16-byte fixed header, ≥32 bytes total**

| Offset | Len | Field |
|---|---|---|
| 0 | 4 | `msg_type` = 4 |
| 4 | 4 | `receiver_index` |
| 8 | 8 | `counter` (**le64**) |
| 16 | var | ciphertext + 16-byte tag (min 16 bytes → 32-byte keepalive) |

Endianness note: index/counter fields are little-endian; the TAI64N
timestamp itself is big-endian (required so it compares lexicographically
for the replay check).

Rust struct shape for the initiation message (no interior padding — every
field is a byte array, alignment 1):

```rust
#[repr(C)]
pub struct HandshakeInitiation {
    pub msg_type:              [u8; 4],   // offset   0
    pub sender_index:          [u8; 4],   // offset   4
    pub unencrypted_ephemeral: [u8; 32],  // offset   8
    pub encrypted_static:      [u8; 48],  // offset  40
    pub encrypted_timestamp:   [u8; 28],  // offset  88  (12 TAI64N + 16 tag)
    pub mac1:                  [u8; 16],  // offset 116
    pub mac2:                  [u8; 16],  // offset 132
}                                          // total  148
```

MAC domains: `mac1` covers `msg[0..116]` (`len-32`), `mac2` covers
`msg[0..132]` (`len-16`) — matches boringtun's `mac1_off = len - 32`,
`mac2_off = len - 16` convention.

### 3. Dalek unification — **not required, but do it anyway per explicit preference**

`snow` (the control plane's Noise library) does **not** depend on
`x25519-dalek` at all — it uses `curve25519-dalek` directly. Today the
workspace already has exactly one `curve25519-dalek` (4.1.3), shared by
`snow`, `tm_keys`, and `tm_disco`. Two incompatible dalek majors *could*
coexist safely if needed (Cargo handles it, `getrandom` auto-selects the
correct ESP-IDF backend per major with no conflict, and the firmware already
carries a precedent — `tm_disco`'s pre-release `chacha20poly1305
0.11.0-rc.3`/`aead 0.6.0-rc.10` stack duplicates a chunk of RustCrypto
already). But the user's explicit preference is to carry only one dalek even
if it means porting — and the retargeting cost turns out to be small:
`x25519-dalek 2.0.1`'s API is a verbatim match for what `ts_tunnel` calls
(`ReusableSecret::random()`, `StaticSecret::from()`, etc.), and the
`rand 0.10`→`0.8` delta is ~6 lines confined to `ts_tunnel/src/config.rs`
(`RngExt`/`distr::StandardUniform`/`rng.random()` → `rand::distributions`/
`Standard`/`rng.gen()`; the bare `rand::random()` calls elsewhere are
unchanged between the two `rand` versions).

**Action**: when vendoring, retarget to `x25519-dalek 2` / `rand 0.8`. Add
`reusable_secrets` to the workspace's `x25519-dalek` feature list (currently
`static_secrets, serde`). Do not introduce a second dalek major.

*Aside, not part of this plan*: if flash pressure ever becomes a real
concern, `tm_disco`'s pre-release AEAD stack is a bigger duplicated-code
target than dalek ever was — worth a separate look someday.

### 4. RAM headroom — **measured live; budget corrected from 400KB to ~130KB free**

A live Wokwi run of the current firmware (WiFi → DHCP → TCP → Noise IK →
HTTP/2 registration → MapUpdate) gave real, not estimated, numbers:

- **Usable heap at boot: 263 KiB**, not 400KB — roughly half the ESP32-C3's
  400KB SRAM is already claimed by IRAM/static allocations before `main`.
- **~143KB free heap** after WiFi + tokio are up, before the control
  connection opens.
- **114,688 bytes (112 KiB) largest contiguous block** — measured constant
  through the entire control-plane run (Noise handshake, H2 framing,
  MapUpdate parse); the control plane's own peak allocations (~17KB, mostly
  two 4KB `NoiseChannel` buffers) don't touch it.
- **~130–135KB free, steady-state, with the control plane connected.**
- mbedTLS is confirmed **not** in the runtime path (the TLS-removal/
  control-key-pinning work already landed) — no need to budget its usual
  ~20KB session buffers.

**Budget for `tm_wg`**: target **40–60KB steady-state**; treat **~90KB as a
hard ceiling** (above that you start competing with the one large contiguous
block and WiFi's dynamic RX buffers under load); leave 20–30KB margin since
the measurement was taken at idle, not under WiFi TX/RX burst pressure. This
directly constrains `MAX_PEERS`, the replay-window size per keypair, and
packet-queue depth (see Step 5 below).

*Infra notes surfaced along the way, not blocking this plan*: heap
instrumentation exists (`tm_runtime/src/lib.rs`) but only logs largest-
contiguous-block, not total-free — a one-line addition
(`esp_get_free_heap_size()`) would make future measurement trivial instead
of needing a live-run investigation each time. Also, `.env.wokwi` and
`.env.aj2004` had a stale/expired `TAILSCALE_AUTH_KEY` during this
investigation (now fixed, synced from `.env`).

---

## Part 3 — Concrete implementation plan

### Step 0: Branch

New branch off `control-key-pinning` (or `main` if that's merged by the time
this starts) in `/home/alanjds/src/tailmicro-rs`, e.g. `wg-dataplane`.

### Step 1: Vendor `ts_tunnel`'s crypto core

Source: `~/src/tailscale-rs_upstream/ts_tunnel/src/{handshake,messages,macs,session,time}.rs`
(record the exact commit hash vendored, since upstream is pre-1.0 and
actively developed — no automatic re-sync).

Land as `tm_wg/src/vendor/{handshake,messages,macs,session,tai64n}.rs`, with
a `tm_wg/src/vendor/mod.rs` doc comment crediting `tailscale-rs` (BSD-3-
Clause, Copyright Tailscale Inc & contributors) and carrying its `PATENTS`
file forward into `tailmicro-rs`'s repo root (or a note pointing at it) if
that file exists in the vendored commit.

Mechanical edits during the port (per Part 2 findings — this is a port, not
a rewrite, for these five files):
- `x25519_dalek::ReusableSecret::random()` → same call, just now resolving
  against the workspace's `x25519-dalek = "2"` with `reusable_secrets` added
  to its feature list.
- `rand::{RngExt, distr::StandardUniform}` in `config.rs`-equivalent code →
  `rand::distributions::{Distribution, Standard}`, `rng.random()` →
  `rng.gen()`.
- `std::time::Instant`/`SystemTime` calls → thread an explicit `now:
  Instant`/`now_unix: u64` parameter instead of reaching for ambient time
  (matches the actor-driven `dispatch_events(now)` pattern already in
  `ts_tunnel`'s public API, just extended to the internals too — needed
  since `tm_wg` has no `std::time` ambient clock guarantee to lean on the
  same way `tailmicro`'s existing `now_unix()` helper in `src/config.rs`
  does, per the control-key-pinning work).
- `messages.rs`'s structs: retain as-is if already `zerocopy`-derived
  fixed-layout (per the upstream evaluation, `messages.rs` is described as
  "pure `zerocopy` structs, already `core`-only") — cross-check field
  offsets against Part 2's confirmed 148/92/64/32-byte tables while porting,
  since this is exactly the kind of off-by-N-bytes bug that silently breaks
  interop. Do not trust the vendored offsets blindly; verify against the
  table above.
- `PacketMut` (wraps `bytes::BytesMut`) → replace with a small
  `heapless::Vec<u8, 1500>`-backed type that preserves the one property
  `PacketMut` is used for (cheap 16-byte header prepending) via a headroom-
  offset wrapper, rather than pulling in `bytes`.

`tm_wg/Cargo.toml`: set `edition = "2024"` (Part 2 finding #1), add
`zerocopy` (with `derive`), keep `blake2`/`chacha20poly1305`/`hkdf` on the
workspace's existing pinned versions, add `aead = { version = "0.5",
default-features = false }` if the vendored code needs the trait. Do NOT add
`ts_packet`, `ts_time`, `itertools`, `crypto_box`, or `bytes` — none are
needed once `PacketMut` and the `Scheduler` are replaced (Steps 1 and 2).

### Step 2: Rewrite `endpoint.rs` against `ArrayVec` (not vendored)

New `tm_wg/src/endpoint.rs`, modeled on `ts_tunnel/src/endpoint.rs`'s shape
but restructured for no-heap, bounded-memory operation, sized against the
Step 4 RAM budget:

- `HashMap<PeerId, Peer>` → `ArrayVec<Peer, MAX_PEERS>` linear scan
  (`MAX_PEERS` stays at `tm_wg`'s existing 8, or is resized after Step 5's
  sizing pass).
- `HashMap<SessionId, PeerId>` → small `ArrayVec<(SessionId, PeerId), 3 *
  MAX_PEERS>` (3 keypairs/peer: current/previous/next).
- `SendResult`/`RecvResult`/`EventResult` (currently `HashMap<_, Vec<_>>`) →
  single-packet-at-a-time return, or a caller-provided `&mut ArrayVec` sink —
  matches `tm_wg`'s existing `WgCmd`/`WgEvent` actor-mailbox shape, which
  already boxes single 1500-byte packets deliberately (see the existing
  `WgCmd::InboundPacket { payload: Box<heapless::Vec<u8,1500>> }` doc
  comment on stack-overflow rationale — keep that pattern).
- Per-peer `Queue(VecDeque<PacketMut>)` (32 deep = 48KB/peer, unaffordable) →
  2–4-deep `ArrayVec`.
- `ts_time::Scheduler<Event>` (`Arc`+`LazyLock`) → since there are only two
  event kinds (`HandshakeTimeout`, `MaybeSendKeepalive`), a 2-slot-per-peer
  `Option<(Instant, Event)>` is sufficient; no `Arc` needed on a
  single-threaded `tokio` runtime.

### Step 3: Fill the two gaps `ts_tunnel` leaves open (per Part 1's comparison)

Both are well-specified, bounded units — implement against wireguard-go's
exact constants (already extracted in the Go evaluation, reproduced here for
convenience):

1. **Data-plane replay protection** (`ts_tunnel`'s `session.rs:154` TODO).
   RFC 6479 sliding-window bitmap, per keypair, reset on session derive.
   **Shrink the window** from wireguard-go's default 8128 counters (1032
   bytes × 3 keypairs × N peers — too much at this RAM budget) to something
   in the 64–128-counter range; this is protocol-legal (any window size ≤
   8128 is a valid implementation choice) and directly sized against Step
   4's 40–60KB target.
2. **Message-count rekey trigger**, added alongside `ts_tunnel`'s existing
   time-only rekey: `RekeyAfterMessages = 1<<60`, `RejectAfterMessages =
   2^64 - 2^13 - 1` (hard TX/RX stops). Also: thread an explicit
   `isInitiator` flag through the key-split step (`BeginSymmetricSession`
   equivalent) — required for the 165s "last-minute" rekey
   (`RejectAfterTime(180) - KeepaliveTimeout(10) - RekeyTimeout(5)`) to ever
   fire; since an ESP32 client is always the initiator this path is
   load-bearing, not optional.

Also apply while porting (small, but easy to silently drop — call out
explicitly in code review):
- Keep the PSK mix (KDF3) even though Tailscale's PSK is 32 zero bytes — the
  chain key must still advance through it.
- Preserve the asymmetric mixKey/mixHash ordering between the initiation
  path and the response-consumption path (classic interop bug if swapped;
  `ts_tunnel`'s existing handshake code should already get this right since
  it interops today per its own tests — verify, don't re-derive).
- Reject an all-zero X25519 DH output (low-order point) in constant time.
- Retain the last-sent MAC1 for cookie-reply decryption (it's the AAD).
- Add handshake-retry jitter (0–334ms) — not cosmetic, prevents synchronized
  handshake storms across a fleet of identical devices.

### Step 4: TAI64N wall-clock time

Neither reference source has a fully correct answer for this target
(`ts_tunnel` uses ambient `SystemTime::now()`, unverified for pre-SNTP
correctness; MicroLink's ESP32 port derives it from uptime, which is
confirmed wrong). Feed `tm_wg`'s TAI64N generation from the same clock
discipline already established in the control-key-pinning work
(`now_unix()` in `src/config.rs`, which distinguishes a real synced clock
from ESP-IDF's pre-SNTP boot clock via a `now > 1_700_000_000` sanity
check). Persisting the last-sent timestamp across reboots is a nice-to-have,
not required for correctness against a live peer.

### Step 5: Actor wiring in `tm_wg/src/lib.rs`

- Keep the existing `WgActor`/`WgCmd`/`WgEvent` shape; drop the
  `wireguard-lwip` FFI block entirely (the stub, and its fabricated
  extern declarations).
- `apply_map(&MapState)` → `endpoint.add_peer`/`remove_peer`.
- Add a `tokio::select!` arm driving `endpoint.next_event()` →
  `dispatch_events(now)`, matching the existing single-current-thread-
  runtime actor pattern used by `tm_control`/`tm_derp`/`tm_disco`.
- Model the transport endpoint as `enum Endpoint { Udp(SocketAddr),
  Derp(region_id, node_key) }` — explicitly **do not** replicate Tailscale's
  `127.3.3.40`-fake-IP-plus-port-as-region-ID hack; that exists only because
  Go's `conn.Endpoint` is address-shaped, and a Rust enum is strictly
  better here.
- Disco messages **must** be demuxed before reaching the WireGuard message
  parser — sniff the WireGuard type byte (values 1-4) on every inbound
  packet from `tm_derp`/`tm_netstack` and route non-WireGuard-shaped
  payloads to `tm_disco` first. This applies regardless of which reference
  base was chosen; it is not something `ts_tunnel` does for you.
- Endpoint roaming: adopt a peer's new source address **only** from
  authenticated packets (post-decrypt), and explicitly skip roaming updates
  for DERP-sourced packets (MicroLink gets this right; `ts_tunnel` has no
  roaming at all, so this is new code, not a port).
- Keep crypto off any latency-sensitive path: drive handshake/rekey
  processing from the actor's own tick rather than inline on every socket
  read, mirroring MicroLink's ~400ms `wireguardif_periodic()` discipline —
  relevant given real X25519 CPU cost on a 160MHz RISC-V core with no
  accelerator.

### Step 6: Sizing pass against the measured RAM budget

Once Steps 1–5 compile, measure actual `tm_wg` steady-state heap cost (the
existing `heap_caps_get_largest_free_block` instrumentation in
`tm_runtime/src/lib.rs` already logs around actor creation; add
`esp_get_free_heap_size()` alongside it per Part 2 finding #4's note) with 1,
then `MAX_PEERS` (currently 8) peers active. Confirm it lands in the
40–60KB target band; if the replay-window size or per-peer queue depth from
Steps 2–3 pushes past ~90KB, shrink the replay window further (down to 64
counters) before reducing `MAX_PEERS`.

### Step 7: Tests

- `cargo test -p tm_wg` (host-native, no ESP target needed) for: the
  handshake transcript against a known-good test vector (generate one via
  the same live-server test harness pattern used for `tm_control`, or via
  `ts_tunnel`'s own vendored test if it carries fixed test vectors); replay
  window accept/reject boundary cases; message-count and time-based rekey
  triggers; MAC1/MAC2 generation and verification; the 148/92/64/32-byte
  message layouts round-tripping through the `zerocopy` structs bit-exact
  against Part 2's offset tables.
- A live bench test: bring up `tm_wg` against MicroLink running on a real
  ESP32 board on the same tailnet, as an interop oracle (this is the
  "working peer" value MicroLink offers per Part 1, without vendoring any of
  its code).

### Verification checklist

1. `cargo test -p tm_wg` passes on host.
2. `cargo tree -d` from `tailmicro-rs` shows no new duplicate `dalek`/
   `curve25519` versions (Part 2 finding #3).
3. Wokwi/live run: WireGuard handshake completes against a real peer
   (MicroLink bench device, or a real Tailscale peer node), transport data
   flows, `esp_get_free_heap_size()` stays within the 40–60KB `tm_wg` budget
   with the control plane also connected.
4. Grep for any remaining reference to the fabricated FFI symbols
   (`wireguard_setup`, `wireguard_add_peer`, etc.) or the `wireguard_stub`
   cfg flag — should be zero.
5. Each fix/feature gets the same docs-commit-then-code-commit pairing used
   throughout the control-plane work, documented in a new
   `docs/wg-dataplane-notes.md` (sibling to
   `docs/noise-handshake-wire-format.md`) as bugs are found.
6. Any new protocol-behavior bug (not pure bookkeeping) gets a Python
   prototype against a live peer before the Rust fix, per the established
   methodology.
