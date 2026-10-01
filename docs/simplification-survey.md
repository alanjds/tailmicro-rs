# tailmicro-rs simplification survey

Branch `simplification-survey` (from `wg-dataplane-scratch`), surveyed 2026-10-01. Read-only: no source changes were made.
The dependency facts below come from `cargo tree --target riscv32imc-esp-espidf --locked --offline` run against the real firmware consumer, `tasmolike-rs`. Cargo.lock was unchanged before and after (md5 `0c35d885…`).

There is one rule for every recommendation: **no regression in correctness, CPU, RAM or flash**.
- Items that touch an ALLOCATIONS.md decision (pool sizes, channel capacities, stack sizes, yields, backpressure) are marked **[ALLOC]**.
- Items that need a number before they land are listed under *Needs measurement*.

---

## 1. Executive summary (ranked by benefit × confidence / effort)

| # | ID | Recommendation | Verdict |
|---|----|----------------|---------|
| 1 | R-01 | Delete dead code and crates: `tm_tls` (no workspace user, unused by tasmolike), `Runtime::spawn` (host-only stale router), `Runtime::join` + deprecated `Device::new`, `todo!()` socket APIs and the 3 examples that call them, `WgEndpoint::new_boxed`, `map_serde::parse`, tm_derp `IoStream`/`send_packet_frame`/`recv_frame`, `tm_wg/build.rs`, `build_icmp_echo_reply`. About 1.3k LOC. | **Do** (S) |
| 2 | R-02 | Drop unused deps: `thiserror` (0 uses in the workspace; removes thiserror 1 from the firmware tree), root-crate `serde`, `serde_json`, `log`, `esp-idf-svc`, `esp-idf-hal`, `embedded-svc`, `async-channel`, `thiserror`; tm_derp `arrayvec`. | **Do** (S) |
| 3 | R-03 | Replace `rand` 0.8 with `rand_core::OsRng` (`rand_core` 0.6, feature `getrandom`). It is used only for `OsRng` at 10 sites, and this drops `rand`, `rand_chacha` and `ppv-lite86` from the firmware tree. | **Do** (S) |
| 4 | P-01 | In `event_router_task`, receive through the `Stream` impl of `async_channel::Receiver` instead of `recv()`. The `Recv` future heap-allocates a boxed `EventListener` on every pending poll; the `Stream` impl keeps it while blocked. This removes up to 4 malloc/free pairs per router iteration with no API change. | **Do, measure** (S) |
| 5 | C-01 | Replace `snow` with a ~150-line `Noise_IK_25519_ChaChaPoly_BLAKE2s` initiator built on the primitives tm_wg's vendored IKpsk2 already uses (same hash, cipher and DH). snow's `default-resolver` links AES-GCM, SHA-512 and BLAKE2b through runtime dyn dispatch, plus about 6 `Box`es per handshake. | **Do after measuring flash** (M) |
| 6 | H-01 | Remove TEMPORARY / "Remove once Step N is resolved" instrumentation that ALLOCATIONS.md marks resolved, and route what stays through `tm_wg::heapdiag`. There are 6 heap-probe copies across 4 crates. | **Do** (S) |
| 7 | P-02 | **[ALLOC]** Router yield is `vTaskDelay(1)` per loop iteration and after each forward. That is ≥1 ms of forced whole-task sleep per event, ×3 per ping echo. Replace with a busy-time budget (yield when ≥N ms have passed since the last park). | **Measure first** (S) |
| 8 | P-03 | tm_disco: `bx.decrypt`/`bx.encrypt` allocate a `Vec` per PING/PONG. Use `AeadInPlace::{decrypt,encrypt}_in_place_detached` on the stack buffers that already exist, then drop `crypto_box`'s `alloc` feature (tm_derp ClientInfo also needs to switch). | **Do** (S) |
| 9 | R-04 | Merge `tm_h2` (355 LOC, zero deps, one consumer) into `tm_control` as a module. Deduplicate tm_control's two H/2 frame loops (`stream_map_response` and `read_one_h2_body`). | **Do** (M) |
| 10 | A-01 | Actors: keep the hand-rolled actor + router pattern. **Do not adopt crossbus.** Optionally move to static `embassy_sync::channel::Channel` later (A-02, M); it is already in the firmware tree via esp-idf-hal. | **Verdict: no framework** |
| 11 | D-01 | Comment hygiene: delete stale or narrating comments ("Bug 2 fix", "Step N", "Rung-N", "round 6", card IDs, dates) and fix factually wrong docs: README, tm_runtime "crossbeam" doc, tm_derp "mpsc / fingerprint" doc, tm_tls "build script", noise.rs httparse claim, several "~28 KB" leftovers. | **Do** (S–M) |

Crypto verdict:
- Keep RustCrypto + dalek.
- **embassy-crypto** is real, active work in `embassy-rs/embassy` git (unreleased 0.1.0; crates.io only has a 0.0.0 placeholder). It is a link-time-pluggable API, and its software driver *is* RustCrypto + dalek. It has no BLAKE2s, no XSalsa20/crypto_box and no ESP driver, so it cannot replace our stack and adds nothing on the C3. Revisit when it ships an ESP32 HW driver (see §4).
- **krypteia** is `github.com/cslashm/krypteia`, a single-author zero-dependency workspace. It covers every primitive we use, but it is pre-1.0 and self-declared "do not deploy … in a context that requires an audited cryptographic library". Reject for now.
- `ed25519-compact` 2.6.0 is actively maintained (commits through 2026-09-29) but would *add* a second curve25519 implementation next to curve25519-dalek 4.1.3. Reject.
- The ESP32-C3 accelerates only AES, SHA-1/224/256, RSA/MPI and HMAC. None of the data-path primitives (ChaCha20-Poly1305, BLAKE2s, X25519, XSalsa20) are accelerated, so mbedtls/PSA buys nothing on the hot path. Reject.
- Real win: C-01, which removes the only true duplication (snow's resolver).

---

## 2. Inventory

LOC are Rust lines including tests.

| Crate | Role | LOC | std / no_std | Key deps (firmware) |
|---|---|---|---|---|
| `tailmicro` (root) | `Device`/`Config` facade, key loading | 392 | std | tm_runtime, tm_control, tm_keys, tm_netstack, tokio, tracing, heapless (+8 unused, R-02) |
| tm_runtime | Boots channels and actors, event router, LAN UDP glue | 1780 | std; esp-idf-svc/sys **unconditional** (breaks host tests) | all tm_*, async-channel, tokio, esp-idf-sys |
| tm_control | ts2021 control: Noise over TCP/80, H/2, register/map, streaming map parse | 2783 | std | snow 0.9.6, tm_h2, actson 2.1.0, serde/serde_json 1.0.151, httparse 1.10, arrayvec, heapless |
| tm_h2 | Minimal H/2 frame codec | 355 | core-only (no `#![no_std]` attr) | none |
| tm_derp | DERP actor and embedded-tls TLS 1.3 leg | 1028 | std (tokio) | embedded-tls 0.19.0 (P-256 ECDHE), embedded-io(-async/-adapters) 0.7, crypto_box 0.9, chacha20poly1305, sha2 |
| tm_wg | WireGuard actor, bounded endpoint, vendored ts_tunnel core, heapdiag | 4811 | std (`Instant`, `SystemTime`, atomics) | x25519-dalek 2, blake2 0.10.6, hkdf, chacha20poly1305, aead, zerocopy 0.8, **tm_control** (for `MapState`) |
| tm_disco | Disco PING→PONG actor | 1182 | std (`Instant`) | crypto_box 0.9 (alloc, salsa20), rand |
| tm_keys | Key newtypes, chip-seeded derivation, control-pin verify | 600 | std (doc claims "no_std-friendly") | x25519-dalek, ed25519-dalek 2.2 (std feature), hkdf/sha2, rand |
| tm_netstack | lwIP tailnet netif, LAN UDP rx loop | 1300 | std (`std::net`, mpsc, OnceLock) | tokio, async-channel, esp-idf-sys, tm_buf |
| tm_buf | Static 4×1532 B `PktBuf` pool, latency trace | 573 | std via `critical-section/std` | heapless 0.9 object_pool |
| tm_tls | mbedTLS/rustls wrapper | 788 | std | **unused** |

The workspace totals about 15.9k LOC, plus about 5k lines of design docs.

---

## 3. Actors and message passing

### Map

| Actor (future in one `tokio::join!`) | Inbox | Outbox | Notes |
|---|---|---|---|
| ControlActor | `ControlCmd` cap 2 | `ControlEvent` cap 2 (`MapUpdate(Box<MapState>)`) | |
| DerpActor | `DerpCmd` cap 2 | `DerpEvent` cap 2 | `select!{biased; cmd, tls.read_frame_buffered()}` |
| DiscoActor | `DiscoCmd` cap 2 | `DiscoEvent` cap 2 | |
| WgActor | `WgCmd` cap 2 (`WG_CMD_CHAN_CAP`) | `WgEvent` cap 2 | own 400 ms ticker |
| udp_rx (lan-direct) | socket | → `wg_tx` / `disco_tx` via `forward_backpressured` (2 ms pool poll, 100 ms budget) | |
| lwIP `tailnet_output_cb` (**tcpip thread**) | — | `try_send` → netif_out cap 8 | cross-thread producer |
| event_router_task | `select!` over 5 receivers | `forward_or_drop` (`try_send`) to actors | never awaits a full channel (Step 7) |

Two facts constrain any replacement:
- One producer, the lwIP output callback, runs on another FreeRTOS thread.
- The router relies on `try_send` and on channel close (`Err(_)` on recv) as a shutdown signal.

### Findings

| ID | File:line | Proposal | Benefit | Risk | Verify | Effort |
|---|---|---|---|---|---|---|
| A-01 | — | **Do not adopt crossbus.** | Avoids an unmaintained dep and a per-message heap allocation | — | — | — |

Why not crossbus (checked at github.com/hominee/crossbus on 2026-10-01):
- **Maintenance.** The last commit on `master` is 2024-03-01 ("change static mutable reactor to AtomicPtr"). The commit before it is the 0.0.6-a release of 2023-04-05. That 2024 commit is the only unreleased work. There are no tags or releases. Only 3 issues exist; #3, opened 2023-04-24, is still open.
- **Tokio integration.** `src/rt/runtime_tokio.rs` builds **its own** `runtime::Builder::new_current_thread()` plus a `LocalSet`, held in a global `AtomicPtr`. The file's own note says it "does not support features `time` `io` of tokio". Adding it would mean either two runtimes on one FreeRTOS task, or the `set_runtime` hand-off. Neither path has been exercised on esp-idf. Not tested here, because nothing was built.
- **Allocation.** Its mailbox (`src/queue.rs`) is a linked list that does `Box::new(Node)` for **every message**. That is worse than async-channel's bounded ring and contradicts ALLOCATIONS.md.
- **No real gain.** It does nothing about the actual costs here: the per-recv listener Box, `vTaskDelay` yields and per-packet copies. The existing pattern is already "actor = `run(rx, tx)` + central router".

| ID | File:line | Proposal | Benefit | Risk | Verify | Effort |
|---|---|---|---|---|---|---|
| A-02 | tm_runtime/src/lib.rs:1398-1533, all actor `run()` signatures | Optional later step: replace `async_channel::bounded` with `static embassy_sync::channel::Channel<CriticalSectionRawMutex, T, N>`. embassy-sync 0.7.2 is already in the firmware tree via esp-idf-hal. | Ring storage moves to .bss: no channel heap, no event-listener Box, one fewer crate family (async-channel 2.5.0, event-listener 5.4.2, concurrent-queue 2.5.0, event-listener-strategy) | **[ALLOC]** See the risk notes below. | Heap watermark before/after `Runtime::build`; `ROUTER_DROPS`; lat trace | M |
| A-03 | tm_runtime/src/lib.rs:829-1236 | `router_yield()` is cfg'd at about 13 call sites. Make `router_yield` a no-op on host so the `#[cfg(target_os="espidf")]` lines go away. | -26 lines, readability | none | `cargo test` host + device build | S |
| A-04 | tm_runtime/src/lib.rs:1505-1530 | Write the `tokio::join!` once. Make the udp_rx future a `pending()` / no-op future when `lan-direct` is off. | Removes the duplicated join | stack frame shape **[ALLOC]** (spawn_* helpers must stay `#[inline(never)]` + `Box::pin`) | `uxTaskGetStackHighWaterMark` on main task (currently about 7.3 KB free) | S |
| A-05 | tm_runtime/src/lib.rs:1585-1705, 1546; src/lib.rs:167-205 | Delete `Runtime::spawn` and `Runtime::join`, and deprecate-then-delete `Device::new`. `Runtime::spawn` is a stale duplicate router: wrong disco check `payload[0]==0x6d`, a TODO, and it drops disco/wg events. | -180 LOC, one source of truth | API break for `Device::new` (tasmolike uses `connect` only) | build tasmolike | S |
| A-06 | tm_runtime/src/lib.rs (receivers), tm_wg/src/lib.rs:244, tm_derp/src/lib.rs:426 | Same as **P-01**: poll receivers via `Stream::poll_next` (`futures-core`, already a dep of async-channel) to keep the listener alive across `select!` iterations. | Heap churn ↓, CPU ↓ | none (same channel) | count `malloc` calls per router iteration with heapdiag trace | S |

Risks and requirements for A-02:
- `Channel` has no close. Shutdown must rely on the existing `Shutdown` variants and an explicit netif-closed flag.
- It has a single sender-waker slot. With several blocked senders, embassy re-wakes the displaced waker, which is correct but means extra wakeups.
- Statics mean `Runtime::build` can run once per boot. That is already true for `WgEndpoint::new_static`.
- The cross-thread `try_send` from tcpip is fine with `CriticalSectionRawMutex`. The impl in the firmware is `critical-section/std`, which tm_buf already depends on.

---

## 4. Crypto

### What the firmware links

All crates below have **no duplicate versions** in the tree.

| Primitive | Crate (version) | Users |
|---|---|---|
| X25519 | x25519-dalek 2.0.1 → curve25519-dalek 4.1.3 | tm_keys, tm_wg, snow, crypto_box (shared backend) |
| Ed25519 verify | ed25519-dalek 2.2.0 (SHA-512) | tm_keys pin check, once per boot |
| ChaCha20-Poly1305 | chacha20poly1305 0.10 | tm_wg (data path), snow, tm_control NoiseChannel, tm_derp TLS suite |
| XSalsa20-Poly1305 | crypto_box 0.9.1 | tm_disco, tm_derp ClientInfo |
| BLAKE2s | blake2 0.10.6 | tm_wg, snow |
| BLAKE2b, SHA-512, AES-256-GCM | via snow `default-resolver` | **linked only because snow resolves at runtime** (`resolvers/default.rs:43-58` matches on the parsed pattern) |
| SHA-256, HKDF | sha2 0.10, hkdf 0.12 | tm_keys derivation, embedded-tls transcript |
| P-256 ECDH | p256 via embedded-tls 0.19.0 | DERP TLS key share. embedded-tls only offers `Secp256r1` (`config.rs:319`), so this is required. |

### ESP32-C3 hardware (Espressif TRM v1.4)

- The chip has AES-128/256, SHA-1/224/256, RSA/big-int up to 3072 bits, HMAC, Digital Signature and a TRNG.
- There is **no ECC accelerator** (that arrives on C6/H2), no ChaCha, no BLAKE2 and no Curve25519 support.
- So per-packet crypto (ChaCha20-Poly1305), the WG handshake (X25519 + BLAKE2s) and disco (X25519 + XSalsa20) cannot be accelerated.
- Only the DERP TLS SHA-256 transcript could use it, and that cost is negligible.

### Findings

| ID | File:line | Proposal | Benefit | Risk | Verify | Effort |
|---|---|---|---|---|---|---|
| C-01 | tm_control/src/noise.rs:97-105, 398-560; Cargo.toml `snow` | Replace snow with an in-tree IK initiator (see below). | Removes snow, AES-GCM, SHA-512-for-Noise, BLAKE2b code and snow's ~6 Boxes per handshake | Handshake correctness | Byte-exact test vs a snow transcript with a fixed ephemeral (keep snow as a dev-dep for this test); live handshake; `cargo bloat`/`size -A` before and after | M |
| C-02 | tm_wg ↔ tm_control | Can tm_wg's IKpsk2 and the control-plane IK share code? **Yes, partially.** | One audited Noise core | Must keep the vendored WG files diffable against upstream | as C-01 | M (with C-01) |
| C-03 | tm_disco/src/lib.rs:480-491, 664-678; tm_derp/src/tls.rs:182-190 | Use in-place/detached AEAD and drop crypto_box `alloc` (see below). | 2 heap allocs fewer per PING; fewer features | none | existing pynacl cross-check tests (`pong_wire_matches_pynacl_reference`) | S |
| C-04 | root Cargo.toml `ed25519-dalek = { features=["std"] }` | Drop the `std` feature. `verify` needs no std. | Smaller feature set | none | build + pin tests | S |
| C-05 | — | **Reject** `ed25519-compact` 2.6.0 (detail below). | — | — | — | — |
| C-06 | — | **Reject for now** embassy-crypto and krypteia (detail below), and a mbedtls/PSA swap (no HW for these primitives; FFI and heap). | — | — | Revisit triggers below | — |
| C-07 | tm_keys/src/lib.rs:20 (HKDF-SHA256 derivation) | **Do not** switch to HKDF-BLAKE2s to save sha2. It would change every device's derived keys, and sha2 is still needed by ed25519-dalek and embedded-tls. | — | — | — | — |

C-01 detail:
- ts2021 is `Noise_IK_25519_ChaChaPoly_BLAKE2s` (noise.rs:105). That is exactly tm_wg's primitive set (`vendor/handshake.rs`: `Blake2s256`, `SimpleHkdf<Blake2s256>`, `ChaCha20Poly1305`, `x25519_dalek`).
- The initiator is two messages: `-> e, es, s, ss` and `<- e, ee, se`. Split gives the raw keys that are already used with BE nonces.
- The replacement also gets rid of `risky-raw-split` / `dangerously_get_raw_split` and the prologue `format!` (noise.rs:414).

C-02 detail:
- Factor `mix_hash`, `mix_key` (HKDF2/3 over BLAKE2s) and `encrypt_and_hash` / `decrypt_and_hash` into one small `noise_core` module. Candidates are tm_wg `vendor/handshake.rs:104-150` (`must_hkdf2`, `must_hkdf3`, `HandshakeState`).
- The message layouts differ, and WG adds psk, MAC1/MAC2 and TAI64N, so only the symmetric-state core is shared.
- Keep it in tm_wg, or move it to tm_keys so tm_control does not depend on tm_wg.

C-03 detail:
- `crypto_box::SalsaBox` implements `AeadInPlace` (aead 0.5). Decrypt the `heapless::Vec<u8,256>` copy that already exists in place: `decrypt_in_place_detached(nonce, b"", &mut ct[..n-16], tag)`.
- Seal the 32-byte PONG with `encrypt_in_place_detached` into the `wire` array.
- Then drop `features=["alloc"]` from crypto_box in tm_disco and tm_derp. tm_derp ClientInfo is the same pattern.

### Rejected crypto crates, checked on GitHub (2026-10-01)

All claims below come from GitHub API fetches on 2026-10-01. Nothing was built or benchmarked.

**embassy-crypto** (C-06)
- **Source.** github.com/embassy-rs/embassy, directories `embassy-crypto/`, `embassy-crypto-rustcrypto/`, `embassy-crypto-rand/` and `embassy-crypto-test/`, on the default branch.
- **Status.** Version `0.1.0` in Cargo.toml, but **no `embassy-crypto-v*` tag exists**; crates.io still serves only the 0.0.0 name reservation. 52 commits touch `embassy-crypto/`, between 2026-08-28 and 2026-09-25. Recent merged PRs include #6868 (p256), #6955 (p384), #6972 (split software drivers into `embassy-crypto-rustcrypto`), #6995 ("add chacha", nrf crypto) and #7059/#7087 (stm32-wpan uses it). PR #7018 (stm32 rng) is open. The README says "TODO: write readme".
- **What it is.** A `#![no_std]`, no-alloc API facade. Each operation (hash, HMAC, HKDF, AES modes, ChaCha, P-256/P-384, X25519, Ed25519, RNG) is a global driver resolved at link time through `embassy-rs/unitrait`, which is pinned by git rev.
- **Drivers.** Hardware drivers exist for stm32, nrf, rp and nxp (code search hits). There are **none for ESP**: zero hits in esp-rs/esp-hal.
- **Software driver.** `embassy-crypto-rustcrypto` wraps the RustCrypto crates and dalek directly: chacha20poly1305 0.11, sha2 0.11, hmac 0.13, aead 0.6, p256 0.14, x25519-dalek 2, ed25519-dalek 2. So on the C3 it would *be* our current stack, one major version newer, plus an indirection layer.
- **Gaps for us.** `hkdf.rs` offers only `HkdfSha256`/`HkdfSha384`. There is **no BLAKE2s** (WG and Noise need it), no **XSalsa20-Poly1305 / crypto_box** (disco and DERP need it) and no streaming `AeadInPlace` equivalent confirmed.
- **Audit.** No audit is claimed. It inherits whatever RustCrypto has (NCC Group 2020 review of chacha20poly1305 and aes-gcm).
- **Verdict unchanged.** Its version skew (aead 0.6 vs our 0.5) would *add* duplicate RustCrypto majors until the rest of the tree migrates.
- **Revisit when** both of these hold: an `embassy-crypto` release ships with an ESP32 (C3) HW driver, and tailmicro moves to embassy (§5). Measure then: flash with `size -A`, and per-packet cycles via `esp_cpu_get_cycle_count`. The only HW-accelerable piece on the C3 would still be SHA-256/AES, which is not on our data path.

**krypteia** (C-06)
- **Source.** github.com/cslashm/krypteia, Apache-2.0. The crates are published as `krypteia-arcana`, `-tessera`, `-silentops`, `-memory` and `-quantica`. The bare `krypteia` name is not a crate.
- **Maintenance.** Single maintainer (`cslashm`, 135 of 135 commits). The repo was created 2026-07-26 and last pushed 2026-07-29, when v0.2.0 was released. About 135 MB including test-vector corpora. 1 star.
- **Primitives we need.**
  - `arcana/src/ecc/`: `x25519.rs` and `eddsa.rs` (Ed25519).
  - `arcana/src/cipher/`: `chacha20poly1305.rs`, `xsalsa20.rs`, `salsa20.rs`, `poly1305.rs`, `xchacha20poly1305.rs`.
  - `tessera`: BLAKE2s, HKDF, HMAC, SHA-2.
  - So it covers all of X25519, ChaCha20-Poly1305, BLAKE2s, HKDF, XSalsa20-Poly1305 and Ed25519 verify. However, there is no ready crypto_box (HSalsa20 key derivation plus framing), so that would have to be composed in-tree.
- **Claims.** Zero external dependencies. Side-channel hardened, with arch-specific constant-time asm. ctgrind and dudect run in CI. NIST ACVP and Wycheproof vectors. CI covers `riscv32imc` ESP32-C3 under qemu-system. Its RustCrypto trait bridge covers only `digest`, `cipher` and `signature` (no `aead`).
- **Self-declared caveats.** Pre-1.0 API. "No third-party evaluation yet … Do not deploy v0.1 in a context that requires an audited cryptographic library." Hardening tiers vary per primitive.
- **Versus RustCrypto + dalek.** Those are years old, used across the ecosystem and partly audited: NCC Group reviewed chacha20poly1305 and aes-gcm in 2020 (per RustCrypto/AEADs `chacha20poly1305/README.md`). The dalek READMEs fetched here state no audit. They are also what WireGuard/Tailscale interop is tested against here. Switching would replace 6 crate families with 2, but trades maturity for unproven code on the authenticated data path.
- **Verdict unchanged:** reject.
- **Revisit after** a third-party audit and a 1.0 release. Measure then: flash (`size -A`), ChaCha20-Poly1305 cycles per 1400 B packet and X25519 cycles on the C3 versus the current stack, plus the existing WG and disco interop tests (pynacl vector, live tailnet ping).

**ed25519-compact** (C-05)
- **Source.** github.com/jedisct1/rust-ed25519-compact. Version 2.6.0, active, with commits through 2026-09-29 (e.g. 2026-09-25 "Strict ed25519 verification and add X25519 DER/PEM").
- **Possible use.** It has an `x25519` feature, so in principle it could replace both x25519-dalek and ed25519-dalek.
- **Why it doesn't help.** `crypto_box` 0.9 still pulls curve25519-dalek. Removing curve25519-dalek would also require replacing crypto_box, which means an XSalsa20 box built by hand.
- **Verdict unchanged.** The net effect is a second curve implementation, or an L-sized rewrite with no measured gain.

---

## 5. no_std readiness

### Gap list (current → no_std equivalent)

| Gap | Where | Replacement | Effort |
|---|---|---|---|
| tokio runtime, `select!`, `time`, net | all actors, tm_netstack | embassy-executor + embassy-time + embassy-net (smoltcp) | **L**. Also loses lwIP, so the tasmolike HTTP-over-tailnet design (tailnet lwIP netif) would need a rewrite. |
| esp-idf-sys (heap probes, eFuse MAC, vTaskDelay, lwIP netif FFI) | tm_runtime, tm_netstack, tm_wg::heapdiag, tm_keys, tm_derp, tm_disco | esp-hal equivalents; probes behind a trait | M |
| lwIP vs smoltcp | tm_netstack/tailnet/* | smoltcp `Device` impl that feeds `PktBuf` | L (whole netstack) |
| tm_tls (mbedtls) | unused | delete (R-01). embedded-tls is already no_std. | S |
| tracing (+`log` bridge) / mixed `log::` | 7 crates use `tracing::`; tm_netstack, tm_runtime and tm_control also use `log::` | pick `log` (smaller) or `defmt`; one facade | S–M |
| thiserror 1 | declared, **unused** | delete (R-02) | S |
| serde_json (`std` for `to_writer`) | tm_control | keep with `alloc`; the `io::Write` shim → `serde_json::to_writer` needs std. Alternative `serde-json-core` adds a crate: reject unless going no_std. | M |
| `std::collections::BTreeMap`, `Vec` | tm_control/map_serde.rs:82-87 | delete `map_serde::parse` (R-01); production uses actson | S |
| `std::time::Instant` / `SystemTime` | tm_wg, tm_disco, tm_netstack, tm_runtime | `embassy_time::Instant` or an injected clock trait | M |
| `std::net::SocketAddrV4` | many | `core::net` (stable since Rust 1.77): mechanical | S |
| `std::sync::{OnceLock, Mutex, mpsc}`, `Rc/RefCell` | tm_netstack, tm_runtime, tm_buf lat | `critical_section::Mutex`, `static` + atomics | M |
| `std::io` | tm_control/noise.rs io shim, tm_control/io.rs | `embedded-io-async` 0.6/0.7 (both already in the tree; tm_derp uses 0.7) | M |
| `OsRng` (getrandom) | 10 sites | `rand_core::RngCore` injected; esp-hal `Rng` | S |

### Per-crate status and order

| Order | Crate | Cost to `#![no_std]` (+alloc) | Blocker |
|---|---|---|---|
| 1 | tm_h2 | **S**: add the attribute, it has no deps | — (or merge into tm_control, R-04) |
| 2 | tm_keys | **S**: `rand` → `rand_core`; esp-idf-sys eFuse stays a target cfg; ed25519 without `std` | getrandom is target-provided |
| 3 | tm_buf | **S–M**: `critical-section` without `std` (the impl is chosen by the binary); `lat` module under std feature | the binary must provide the critical-section impl |
| 4 | tm_disco | **M**: `Instant` → clock trait; async-channel works `no_std` with `default-features=false` (event-listener `portable-atomic` path) | channel choice (A-02) |
| 5 | tm_wg | **M**: `Instant`/`SystemTime` → clock; std atomics → core; drop the dependency on tm_control (move `MapState`/`PeerInfo`/`TailnetIp` to a leaf types module, e.g. in tm_keys) | the tm_control dep (R-07) |
| 6 | tm_derp | **M**: embedded-tls already no_std; tokio TCP → embedded-io-async socket | tokio net |
| 7 | tm_control | **L**: serde_json io, tokio TCP | serde_json std, tokio |
| 8 | tm_netstack / tm_runtime | **L**: lwIP/tokio-bound by design | runtime choice |

Recommendation:
- Do steps 1–3, plus the `core::net` mechanical change, opportunistically.
- **Do not** start the tokio→embassy / lwIP→smoltcp migration. It contradicts the current product design (tasmolike serves HTTP via lwIP on the tailnet netif) and has no measured CPU/RAM payoff.

---

## 6. Other redundancy

| ID | File:line | Proposal | Benefit | Risk | Verify | Effort |
|---|---|---|---|---|---|---|
| R-01 | tm_tls/* | Delete the crate. No workspace crate depends on it; tasmolike declares it with `mbedtls` but never uses it (remove it there too). Its Cargo comment "The build script enforces this" is false: no build.rs exists. | -788 LOC, faster builds | none | both repos build | S |
| R-01b | src/lib.rs:225-240; examples/{peer_ping,tcp_echo,udp_echo} | `udp_bind`/`tcp_listen`/`tcp_connect` are `todo!()`, and all 3 examples call them, so they panic at runtime. Delete the APIs and examples, or feature-gate them until implemented. | Honest API | none | build | S |
| R-01c | tm_wg/src/endpoint.rs:440-488 (`new_boxed`), 133-142 (`queue_push`), 254-261 (`needs_rotation`), 588-595 (`peer_endpoint`, `peer_direct`: tests only?), 47 (`QUEUE_DEPTH=0`), `Queue` type | Delete `new_boxed` (unused). `QUEUE_DEPTH = 0` makes `SessionState::None(Queue)` a zero-sized placeholder, so either delete the queue concept or keep a single comment. | -80 LOC | none | tm_wg tests | S |
| R-01d | tm_wg/src/lib.rs:166-171, 512-515; tm_runtime 176/1316 | `priority_peer` is plumbed through 4 layers and never used ("Retained for API compatibility"). Delete it. | Simpler config | public API (tasmolike does not set it) | build | S |
| R-01e | tm_derp/src/lib.rs:511-559 | `send_packet_frame`, `recv_frame` and the `IoStream` trait are unused (etls uses `tls::read_frame`/`write_frame`). `DerpTls::read_frame` (tls.rs:226) is unused too. | -50 LOC, one fewer duplicate trait | none | build | S |
| R-01f | tm_control/src/map_serde.rs:1-178 | `parse()` and the serde `Deserialize` structs are unused in production (`MapStreamParser` replaced them). Keep `hex_key`/`parse_ipv4`/`parse_derp_region`/`region_id_or` in a `scalars` module and port the 2 tests to map_stream (equivalents already exist). | -180 LOC, no `BTreeMap` | none | tm_control tests | S |
| R-01g | tm_runtime/src/lib.rs:630-662 | Delete `build_icmp_echo_reply` (`#[allow(dead_code)]`). | | none | build | S |
| R-01h | tm_wg/build.rs | It is a no-op ("intentionally does nothing"). Delete it. | Faster build | none | build | S |
| R-02 | Cargo.toml:103-118; tm_control, tm_derp, tm_tls Cargo.toml | Remove the unused deps listed below. | Smaller tree, honest manifests | none | `cargo build` both repos; `cargo udeps` | S |
| R-03 | tm_wg/src/vendor/{config,handshake,keys,messages}.rs, tm_wg/src/endpoint.rs:1020, tm_derp/src/lib.rs:410, tm_keys/src/lib.rs:252, tm_disco/src/lib.rs:34,554 | `rand::rngs::OsRng` → `rand_core::OsRng` (rand_core 0.6 feature `getrandom`; same type, re-exported by rand 0.8). | Drops rand 0.8.6, rand_chacha 0.3.1, ppv-lite86 (tm_wg enables rand's default `std_rng`) | none (same RNG) | build + tests | S |
| R-04 | tm_h2/*; tm_control/src/lib.rs:697-917 vs 964-1038 | Merge tm_h2 into `tm_control::h2`. Factor one `read_frame_loop` (DATA / WINDOW_UPDATE / SETTINGS-ack / PING-ack) used by both `stream_map_response` and `read_one_h2_body`, which also duplicate the `FB_CAP` comment. | -1 crate, -~80 LOC | stack: `frame_buf` 4096 B lives in these futures **[ALLOC]**; keep one buffer, not two | live register + map stream; main-stack watermark | M |
| R-05 | tm_control/src/io.rs:5-7 | Keep the one `IoStream` (control). The derp copy dies in R-01e. | | | | S |
| R-06 | tm_control/src/map_serde.rs:185-205; tm_keys/src/pin.rs:102-131; tm_keys/src/lib.rs:78,116,166 | There are 5 hand-rolled hex encode/decode helpers. `base16ct` 0.2.0 is already in the firmware tree (via p256/elliptic-curve), offering `base16ct::lower::encode_str` and `mixed::decode`, but only while `etls` is on. **Preferred: one tiny `tm_keys::hex` module** rather than leaning on a transitive dep. | One implementation | none | existing tests | S |
| R-07 | tm_wg/Cargo.toml (`tm_control` dep) | tm_wg depends on tm_control only for `MapState`/`PeerInfo`/`TailnetIp`. Move those types to a leaf crate/module (tm_keys or a new `types` module in tm_buf), or have tm_runtime translate them. | Decouples the data plane from serde/actson; enables no_std for tm_wg | type moves | build | M |
| R-08 | tm_runtime/Cargo.toml (default `lan-direct`); root `lan-direct` pass-through; tm_runtime/src/lib.rs:219 `DISCO_PING_SETS_SEND_PATH=false`; tm_control/src/lib.rs:279 `PUBLISH_LAN_ENDPOINT=true` | Constants that are always on or always off. Fold or delete them; keep the `lan-direct` cargo feature only if a DERP-only build is a supported product (Open Q3). | Fewer cfg branches | behavior must stay identical | device run | S |
| R-09 | tm_runtime/src/lib.rs:571-615, 1122-1148 | The rung-6a ICMP echo "elicitor" sends a ping to every peer on `PeerHandshook`. It is a bring-up diagnostic: put it behind a feature or delete it. | Less traffic and code | it may be keeping NAT/session warm (Open Q4) | device | S |
| R-10 | tasmolike Cargo.toml:54-62 | tasmolike lists 9 tm_* crates directly but uses only `tailmicro`, `tm_runtime::Driver`, `tm_keys::NodeState`, `tm_wg::heapdiag`. Re-export those from `tailmicro`, add a `tailmicro/etls` feature forwarding to `tm_derp/etls`, and drop the rest. | One integration point | none | tasmolike build | S |
| R-11 | tm_runtime/Cargo.toml (esp-idf-svc/sys unconditional), tm_runtime/src/lib.rs:1708-1721 | Move to `[target.'cfg(target_os="espidf")'.dependencies]` so the tm_runtime tests run on host. | Router tests on CI | none | `cargo test -p tm_runtime` | S |
| R-12 | tm_control/src/lib.rs:167-178 | `ControlError::{Tls, Http, PeerTableFull, Pin}` and `JsonError::{InvalidUtf8, MissingField}` are never constructed. Delete them. | | none | build | S |
| R-13 | src/config.rs | `Config::new(_auth_key)` ignores its argument; `default_with_key_file`/`key_file` are unused. Delete or fix. | | API | build | S |
| R-14 | noise.rs:585-601 (`base64_encode`) | Keep. It is 17 lines, used once, and no base64 crate is in the tree. | | | | — |

R-02: unused deps to remove
- Root `tailmicro`: `thiserror`, `log`, `serde`, `serde_json`, `esp-idf-svc`, `esp-idf-hal`, `embedded-svc`, `async-channel`. Grep of `src/` shows only tm_*, tokio, tracing and heapless.
- `thiserror` in tm_control and tm_derp: 0 `#[error]`/derive uses anywhere. This drops thiserror 1.0.69 and thiserror-impl 1.0.69 from the firmware tree (thiserror 2 stays, via actson/postcard).
- `arrayvec` in tm_derp: 0 uses.
- `httparse` in the workspace deps: keep it, it is used by noise.rs:657. Its comment at noise.rs:624 ("already in our dependency tree via tm_h2 chain") is false; it actually comes via tasmolike's hyper.
- Root Cargo.toml: `repository = "your-org"` placeholder, and the comment "patch.crates-io below" refers to a section that is above it.

### Duplicate heap probes (H-01)

These must be consolidated into `tm_wg::heapdiag`, which the 2026-09-29 decision keeps permanently.

| Copy | File:line | Gated? | Action |
|---|---|---|---|
| `log_heap` (3 capability classes, identical on C3 per Step 5) | tm_runtime/src/lib.rs:96-109, ~25 call sites in `build` | no | one `heapdiag::snap` line at start and end of `build` |
| `log_heap_blocks` | tm_runtime/src/lib.rs:243-256 | no | → heapdiag |
| `heap_probe` + `heap_probe_blocks` ("TEMPORARY … strip once settled") | tm_derp/src/lib.rs:22-74; ~10 calls in tls.rs:136-200 ("not for commit as-is") | **no**, 10 blocking UART lines per DERP connect | gate on `heapdiag::ENABLED` or delete |
| `heap_probe_blocks` ("Remove once Step 4 is resolved") | tm_disco/src/lib.rs:39-70 | `heap-trace` | → heapdiag |
| `heap_probe_blocks` ("Remove once Step 5 is resolved") | tm_wg/src/lib.rs:37-58 | `ENABLED` | → `heapdiag::snap` |
| `send_diag` ("TEMPORARY (ALLOCATIONS.md Step 7)") | tm_wg/src/lib.rs:518-543 | `ENABLED` | keep under heapdiag or delete |

---

## 7. Performance (hot path)

| ID | File:line | Finding | Proposal | Risk | Measurement | Effort |
|---|---|---|---|---|---|---|
| P-01 | tm_runtime/src/lib.rs:833 (`select!` over 5 `recv()`) | event-listener 5.4.2 `listen()` does `Box::pin(InnerListener{..})` (lib.rs:306-310). async-channel 2.5.0 `RecvInner` creates one on each pending poll, and `select!` drops it each iteration. So up to 4 small malloc/free pairs per routed event, while the router is the hottest loop. | Poll `Receiver` as a `Stream` (async-channel lib.rs:921-960 keeps `listener` inside the `Receiver` while blocked). Same in WgActor (`run` select) and DerpActor. | none | heapdiag trace window over 1000 pings: count allocs; lat `RouterIter` hop | S |
| P-02 | tm_runtime/src/lib.rs:65, 70-80, 830 + ~12 sites | **[ALLOC]** `vTaskDelay(1)` (1 ms at HZ=1000) before every router iteration and after most forwards. The whole runtime sleeps ≥1 ms per event; a ping echo crosses the router 3× (≥3–6 ms). Step 9 cut this from 50 to 1 tick. The stated purpose (idle task / WDT) is met whenever the runtime parks in its reactor. | Yield to FreeRTOS only when the router has been continuously busy for ≥ X ms (e.g. 10 ms, tracked with `esp_timer_get_time`); keep `yield_now` per event. | WDT under sustained flood; lwIP/WiFi are higher priority anyway | `tm_buf::lat` RTT histogram (latency-trace feature) and iperf-like UDP flood with TWDT enabled for 10 min | S |
| P-03 | tm_disco/src/lib.rs:487, 665 | `Aead::decrypt`/`encrypt` heap-allocate a `Vec` per PING and PONG. | C-03 in-place detached | none | heapdiag alloc count per PING | S |
| P-04 | tm_wg/src/endpoint.rs:889-898, tm_wg/src/lib.rs:477-493, 549-553 | Inbound transport copies a 1.5 KB packet 3–4 times (see below). Outbound is symmetric. | Decrypt/encrypt in place in the `PktBuf` (PKT_CAP 1532 ≥ 1500 + header): give `vendor::packet::Packet` a borrowed-buffer variant, or make `RecvOut` hold `PktBuf`s. | Diverges further from vendored upstream; `RecvOut` holds pool buffers longer **[ALLOC]** (POOL_N = 4) | Cycle count around `on_inbound` (`esp_cpu_get_cycle_count`); ChaCha of 1.4 KB is ~150–250 µs on C3, each 1.5 KB memcpy ~5–10 µs, so expect ≤10% | M |
| P-05 | tm_wg/src/endpoint.rs:906 | `vec![Packet::from_wire(raw)]` allocates 1.5 KB on the heap at every responder-session confirmation (once per handshake, every ~2 min per peer). This contradicts the no-heap endpoint discipline. | Change the vendored `confirm` to take one `Packet` (`core::iter::once`). | vendored diff | heapdiag | S |
| P-06 | tm_wg/src/lib.rs:293-304, 331-348 | `apply_map` rebuilds `endpoint_peer_ids()` (scanning ids 1..=32) **inside** a `for i in 0..MAX_PEERS` loop: 8×32 lookups, each a linear scan, per MapUpdate. | Iterate the endpoint's peer table once (`ep.peers().filter(..)`). | none | unit test | S |
| P-07 | tm_wg/src/lib.rs:449-453 | `on_tick` does `pkt.clone()` and then `pkt_to_buf` copies again, so 2 copies per timer packet. | Pass `&Packet` to `emit_to_peer`. | none | — | S |
| P-08 | tm_derp/src/tls.rs:246-290 + lib.rs:462 | DERP rx: TLS decrypts in place in `read_buf`, copies into `frame_buf` (Box, 1532 B), then copies into `PktBuf`. One extra memcpy. | Accept as is (`frame_buf` makes reads cancel-safe; reading into a pool buffer would pin it while idle **[ALLOC]**). | — | — | — |
| P-09 | tm_derp/src/tls.rs:170 | `let mut buf = [0u8; MAX_DERP_PAYLOAD]` puts 1.5 KB on the stack during `connect`, while `frame_buf` (1.5 KB) is boxed separately afterwards. | Allocate `frame_buf` first and use it for the handshake frames. | stack **[ALLOC]** (improves) | stack HWM | S |
| P-10 | tm_derp/src/lib.rs:399-400, tm_derp/src/tls.rs:216; tm_control/src/noise.rs (`NoiseChannel` 2×4114 B) | Reconnect re-allocates 5 KB + 2 KB + 1.5 KB (DERP) and 8.2 KB (Noise) on every reconnect. This is ALLOCATIONS "future improvement #3". | **[ALLOC]** Make them `static` once-only buffers (same pattern as `recv_out_static`): about 17 KB of .bss for zero reconnect fragmentation. | .bss +17 KB, heap −17 KB (net zero; less fragmentation) | largest-free-block after 20 forced reconnects | M |
| P-11 | tm_control/src/lib.rs:944-962 | `build_h2_post` boxes a 4.3 KB ArrayVec per request and pushes byte by byte. | `extend_from_slice`; write into the NoiseChannel write buffer directly. | none | — | S |
| P-12 | tm_control/src/noise.rs:628-670 | `read_101_response` reads 1 byte per `read` (a syscall into lwIP each), about 200 per control connect. | Read into a 512 B buffer and hand the leftover to `NoiseChannel` (it already handles EarlyNoise). | framing correctness | host_handshake example | S |
| P-13 | tm_runtime/src/lib.rs:1405-1446 | **[ALLOC]** `Runtime::build` runs 9 × `tokio_freertos_yield` (50 ms) = **450 ms of boot sleep**, plus about 25 heap log lines. These came from the fragmentation investigation. | Keep one yield before the first allocation, if any is still needed, and remove the rest. | ALLOCATIONS decision; was diagnostic | boot-to-`OurIpAssigned` time; heap map at end of build unchanged | S |
| P-14 | tm_netstack/src/tailnet/device.rs:79-104 | Inbound to lwIP copies `PktBuf` → `PBUF_POOL` (`pbuf_take`). | `pbuf_alloced_custom(PBUF_RAW, PBUF_REF)` with a free callback returning the `PktBuf` would make it zero-copy. **Not recommended**: lwIP TCP can hold rx pbufs in ooseq/recvmbox and starve the 4-buffer pool **[ALLOC]**. | high | — | — |

P-04: the inbound copy chain
1. `PktBuf` → `Packet::from_wire` (stack, 1.5 KB)
2. → moved into static `RecvOut`
3. → `pkt_to_buf` → new `PktBuf`
4. → `pbuf_take` into lwIP

---

## 8. Comment hygiene

The policy: keep *why* and the invariants. Delete narration (bug histories, "Step N", "Rung N", "round N", card IDs like `t_e34afeed`, dates), which already lives in ALLOCATIONS.md and docs/*.md and git history.

| File:lines | Problem | Action |
|---|---|---|
| README.md (whole) | Claims FFI `wireguard-lwip`, `mpsc::channel(4)`, a "Channels 4×4×1.5 KB" budget, a stub status table and a `Device::new` + `udp_bind` example | **Rewrite** (short: architecture, `Device::connect`, link ALLOCATIONS.md) |
| tm_runtime/src/lib.rs:14-26 | Says `Runtime::spawn` is the default and that channels are `crossbeam::channel` | fix (async_channel; join only) |
| tm_runtime/src/lib.rs:111-139 | Long stack-frame narration | shorten to 3 lines + link |
| tm_runtime/src/lib.rs:816-821, 838, 850 | "Belt-and-suspenders 2026-09", "Rung-3/4 evidence" | delete the tags |
| tm_runtime/src/lib.rs:839-849 | `info!("Runtime::join() - …")`: wrong function name in logs | rename the log prefix |
| tm_control/src/lib.rs:1-13 | Stale memory notes ("320 KB", "~6 KB") | delete; link ALLOCATIONS.md |
| tm_control/src/lib.rs (`ControlEvent::MapUpdate` doc) | "concurrent-queue has 31 slots per block": true for *unbounded* only; all channels are bounded | fix |
| tm_control/src/lib.rs:534-690 | "Step N" narration in `bring_up` | shorten |
| tm_control/src/map_serde.rs:1-15 | Says this is the decoder; it was superseded by map_stream | delete with R-01f |
| tm_control/src/noise.rs:398-421 | Inconsistent indentation | rustfmt |
| tm_control/src/noise.rs:624 | False provenance claim for httparse | fix |
| tm_wg/src/lib.rs:65-68, 87-90 | "Boxed: async_channel's unbounded ring … 31 slots"; `SendData` says "Boxed" but is not | fix |
| tm_wg/src/lib.rs:128-165 | 38 lines of field narration (Step 5 history); 279-281 and 409-410, 436-438 still say "~28 KB" while 195 says "~6 KB" | shorten to one invariant line each; fix sizes |
| tm_wg/src/endpoint.rs:50-69 | `OUT_CAP`/`DISPATCH_CAP` docs still describe the per-call/per-tick `Box` that no longer exists | update (statics now) |
| tm_wg/src/endpoint.rs:701-709 | Duplicated doc first line; "~12 KB" (actually ~6 KB) | fix |
| tm_wg/build.rs | Narrates removed FFI | delete file |
| tm_derp/src/lib.rs:5-17 | "TLS fingerprint — same as tm_control", "mpsc::channel mailbox": both false (no-verify TLS, async_channel) | fix |
| tm_derp/src/lib.rs:262-278, 305-307 | Bug-history narration | move to docs; keep 2 lines |
| tm_derp/src/lib.rs:173-181 | `cert_fingerprint` doc ("From MicroLink: avoids CA bundle"), but it is always `None` and ignored | delete the field (tm_runtime:887, 1027) |
| tm_derp/src/tls.rs:46-49 | "dwarfed by tm_wg's ~28 KB WgEndpoint" (now ~6 KB static) | fix |
| tm_derp/src/tls.rs:136-141 | "TEMPORARY … not for commit as-is" | delete with H-01 |
| tm_disco/src/lib.rs:174-186, 525-533, 684-690, 853-858 | "Bug 2 fix", "Step 1 bug fix", Kanban `t_c414048d` | shorten to the invariant ("per-path PONG rate limit") |
| tm_tls/Cargo.toml | "The build script enforces this" (none exists) | moot after R-01 |
| Cargo.toml (root) | "patch.crates-io below" (it is above); `your-org` | fix |
| Stray files | `gmon.out` (root, tools/wg_validator), `tools/**/__pycache__`, two copies of `tm_signing_key.bin` (root + tools/) | gitignore/remove. **Check that the signing key should be in the repo at all** (Open Q1). |

---

## 9. Rejected / not worth it

| Idea | Why rejected |
|---|---|
| crossbus actor framework | github.com/hominee/crossbus (checked 2026-10-01): last commit 2024-03-01, last release 0.0.6-a (2023-04-05). Its tokio backend spins up its own current_thread runtime with no time/io, and its mailbox boxes every message. It adds a layer without removing the real costs (A-01). |
| Hand-rolled generic `Actor` trait | Each actor's `run` is already ~30 lines; a trait would force `Box<dyn>` or generics through the `#[inline(never)]` spawn helpers that keep futures off the 32 KB stack. |
| tokio → embassy, lwIP → smoltcp | L effort and it breaks the tailnet-netif HTTP design; no measured payoff. |
| embassy-crypto | Active but unreleased in embassy-rs/embassy (checked 2026-10-01). Its software driver is RustCrypto + dalek (newer majors). It has no BLAKE2s, no XSalsa20/crypto_box and no ESP HW driver. Revisit on release + ESP driver + embassy migration (§4). |
| krypteia | github.com/cslashm/krypteia (checked 2026-10-01): one maintainer, v0.2.0 (2026-07-29). It covers all our primitives except a ready crypto_box, but it is pre-1.0 and self-declared unaudited "do not deploy". Revisit after an audit and 1.0 (§4). |
| ed25519-compact 2.6.0 | Active (jedisct1/rust-ed25519-compact, commits through 2026-09-29), but crypto_box keeps curve25519-dalek, so it would be a second curve implementation (§4). |
| mbedtls / PSA for crypto | The C3 has no HW for ChaCha/BLAKE2/X25519; it adds FFI and heap. |
| HKDF-BLAKE2s for key derivation | It would change derived device identities. |
| `serde-json-core` instead of serde_json | It adds a crate; the serialization path is cold and bounded. |
| Zero-copy lwIP `PBUF_REF` injection (P-14) | Pool starvation risk. |
| DERP rx straight into `PktBuf` (P-08) | It would pin a pool buffer while idle. |
| base64 crate | 17-line encoder used once. |
| Unify embedded-io 0.6/0.7 | 0.7 is required by embedded-tls 0.19, and 0.6 by esp-idf-hal/embassy-sync 0.7; not ours to fix. |

---

## 10. Needs measurement

| ID | What | How |
|---|---|---|
| C-01 | Flash saved by dropping snow (AES-GCM, SHA-512, BLAKE2b, dyn resolver) | `cargo bloat --release --crates` or `riscv32-esp-elf-size -A` / `nm --size-sort` on the tasmolike ELF, before and after |
| P-01 / A-06 | Allocations per routed packet | `heapdiag::trace_begin/end` around 100 router iterations under ping load; compare counts |
| P-02 | Latency and WDT safety of a budgeted router yield | `latency-trace` RTT histogram (`tm_buf::lat`) at 1, 10, 50 pings/s; TWDT on, 10 min UDP flood |
| P-04 | Copy cost vs crypto cost per packet | `esp_cpu_get_cycle_count()` around `recv_one_into` and around `pkt_to_buf` |
| P-10 | Fragmentation after reconnects with static buffers | Largest free block after 20 forced DERP and control reconnects |
| P-13 | Boot time without the 9×50 ms yields | Timestamp from `Runtime::build` start to `OurIpAssigned`; heap map at the end of build must match |
| A-02 | RAM: async-channel heap rings vs static embassy channels | `heap_caps_get_info` after build vs `.bss` delta from `size -A` |
| R-04 | Stack after merging the H/2 loops | `uxTaskGetStackHighWaterMark` on the main task (currently about 7.3 KB free of 43008) |

---

## 11. Open questions for the maintainer

1. Should `tm_signing_key.bin` (root and tools/) be in the tree? If it is the pin *signing* key, it is a secret.
2. Is `Device::new` / `Runtime::join` / `Runtime::spawn` kept for any consumer other than tasmolike? If not, delete them (A-05).
3. Is a DERP-only (`lan-direct` off) build a supported product? If not, remove the feature and the duplicated `join!` (R-08, A-04).
4. Is the rung-6a ICMP echo on `PeerHandshook` still needed, for example to warm the peer's path? If not, gate or delete it (R-09).
5. Will the outbound app-data queue (`QUEUE_DEPTH`) ever come back? If not, delete the queue plumbing (R-01c).
6. Is the 400 ms WG tick still the right cadence now that timers are per-peer `Option<Instant>`? A `sleep_until(next_event())` would cut idle wakeups. This needs a power measurement.
7. Is it acceptable for the vendored ts_tunnel files to diverge further (P-04, P-05, C-02)? `vendor/mod.rs` says there is no automatic re-sync.

---

### Not verified in this survey

- No firmware build was run, so flash and RAM figures are estimates (see §10).
- `cargo udeps` was not run; unused deps were found by grep of `crate::` paths and `use` lines.
- The GitHub re-check (2026-10-01, via the `gh api` REST/search endpoints) read repo metadata, commit lists, Cargo.toml files, READMEs and directory listings. It did **not** read the primitive implementations, run any test vectors or benchmarks, or compile any of these crates for `riscv32imc-esp-espidf`.
- The crossbus-on-tokio-current_thread + esp-idf conclusion comes from reading `src/rt/runtime_tokio.rs` and `src/queue.rs`, not from running it.
- krypteia's constant-time, ctgrind/dudect and ESP32-C3 qemu CI claims are quoted from its README. The CI runs themselves were not inspected.
- GitHub code search covers only default branches, so embassy-crypto work on other branches or forks may have been missed. PR search did cover closed and open PRs.
- curve25519-dalek audit status could not be confirmed from the READMEs fetched.
- The ESP32-C3 crypto peripheral list is from Espressif's TRM v1.4 summary and datasheet search results, not the full PDF.
