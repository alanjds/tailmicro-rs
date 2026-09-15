# WireGuard data-plane (`tm_wg`) implementation notes

Sibling to `docs/noise-handshake-wire-format.md`. This file records the
concrete findings, provenance, and deliberate deviations made while
implementing the `tm_wg` WireGuard data plane per
`docs/wg-dataplane-implementation-plan.md`. As with the control-plane work,
docs are committed *before* the code they describe.

## Provenance of the vendored crypto core

The crypto core is vendored (copied, not depended-upon) from the official
`tailscale-rs` `ts_tunnel` crate:

- Upstream repo: `tailscale-rs` (BSD-3-Clause, Copyright Tailscale Inc &
  contributors).
- **Exact commit vendored: `0b8d819b99c6463e4f0b6ae64d244909b866bfe0`**
  (`ts_bitset: implement bit shift traits`), from
  `~/src/tailscale-rs_upstream/ts_tunnel/src/`.
- License and PATENTS grant carried forward verbatim as
  `tm_wg/src/vendor/VENDOR-LICENSE` and `tm_wg/src/vendor/VENDOR-PATENTS`
  (the repo root has no top-level LICENSE/PATENTS to merge into, so they
  live next to the vendored source they cover).

`tailmicro-rs` is itself BSD-3-Clause, identical to the upstream, so this is
a clean same-license vendoring. Upstream is pre-1.0 and actively developed;
there is no automatic re-sync — the commit hash above is the anchor.

Files vendored (with edits, see below):
`messages.rs`, `macs.rs`, `time.rs` (→ `tai64n.rs`), `session.rs`,
`handshake.rs`, and `config.rs` (its `Psk`/`PeerId`/`PeerConfig` types).
`endpoint.rs` is **rewritten**, not vendored (see plan Step 2).

## Mechanical / structural edits made during the port

These deviate from a pure copy. Each is a deliberate adaptation to
`tailmicro-rs`'s constraints, called out here for review.

### 1. Key-type bridge is a self-contained shim, not an extension of `tm_keys`

The vendored files `use ts_keys::{NodeKeyPair, NodePrivateKey,
NodePublicKey}`. `tm_keys` has no `NodeKeyPair`, and its `NodePrivateKey`
wraps an `x25519_dalek::StaticSecret` (which is **not `Copy`**), whereas the
vendored handshake code copies `NodePrivateKey`/`NodePublicKey` by value
repeatedly (e.g. `initiate_handshake` takes them by value and calls
`.into()` several times; `SentHandshake` stores an owned `my_static`).

Rather than make `tm_keys::NodePrivateKey` `Copy` (impossible while it wraps
`StaticSecret`) or fork its API and destabilize the *already-working*
control plane that depends on it, the bridge is a small self-contained shim
in `tm_wg/src/vendor/keys.rs`: `Copy` newtypes over `[u8; 32]` with exactly
the constructors and `From` impls the vendored code needs
(`NodeKeyPair::new`, `From<[u8;32]> for NodePublicKey`, `to_bytes()`,
`From<NodePublicKey> for x25519_dalek::PublicKey`, `From<NodePrivateKey> for
x25519_dalek::StaticSecret`, `From<NodePrivateKey> for NodePublicKey`). The
actor boundary converts to/from the `[u8; 32]` node keys carried in
`tm_control::PeerInfo`, so nothing outside `tm_wg` is touched. This is the
"shim" option explicitly permitted by the plan's correction #1.

### 2. RNG resolved via `random_from_rng(OsRng)`, no new `getrandom` surface

The vendored code calls `x25519_dalek::ReusableSecret::random()` and
`rand::random()`. To match `tm_keys`'s existing
`StaticSecret::random_from_rng(OsRng)` discipline (and avoid adding a new
`getrandom` feature surface to `x25519-dalek`), these are rewritten to
`ReusableSecret::random_from_rng(rand::rngs::OsRng)` and, for `SessionId` /
`Psk`, `OsRng.fill_bytes(...)`. This requires the `reusable_secrets`
feature on `x25519-dalek` (added to the workspace feature list) but no new
`getrandom` route.

### 3. `PacketMut` (over `bytes::BytesMut`) → `vendor::packet::Packet`

Upstream `PacketMut` wraps `bytes::BytesMut` and is used for one load-bearing
property: cheap 16-byte header prepending (`grow_front`). It is replaced by
`Packet`, a `heapless::Vec<u8, 1500>` plus a front offset, implementing
`aead::Buffer`. Per the plan's inner-MTU correction (#6): 16 bytes of front
headroom are reserved for the transport-data header, so the inner plaintext
is capped at `1500 - 16 (header) - 16 (AEAD tag) = 1468` bytes. Outbound
plaintext is constructed at `front = 16`; inbound wire packets at
`front = 0`. No `bytes` dependency is pulled in.

### 4. `handshake.rs` structurally edited (not a pure port)

Upstream `Handshake::Initiated(SentHandshake, ts_time::Handle<Event>, Mac)`
embeds a scheduler handle and a back-reference to `crate::endpoint::Event`.
Since the `ts_time::Scheduler` is replaced by a per-peer
`Option<Instant>` timer in the rewritten `endpoint.rs` (plan Step 2), the
`Handle<Event>` field and the `timeout.cancel()` call are dropped, and the
`crate::endpoint::Event` import is removed. `Handshake::Initiated` becomes
`(SentHandshake, Mac)`; timeouts are owned by the endpoint's peer table.

### 5. Explicit clock threading; TAI64N fed from synced-clock discipline

`time.rs`/`session.rs` reach for ambient `SystemTime::now()`/`Instant::now()`.
`Instant`-based session lifetime timing is kept (esp-idf `std` provides
`Instant`), but TAI64N handshake timestamps gain a `TAI64N::from_unix(secs,
nanos)` constructor fed from the same `now > 1_700_000_000` synced-clock
sanity check used in the control-key-pinning work (`src/config.rs`), so a
pre-SNTP boot clock never produces a bogus handshake timestamp.

## Gaps filled that upstream `ts_tunnel` leaves open

Per the plan's Part 1 comparison, `ts_tunnel` is missing two data-plane
pieces that wireguard-go specifies. Both are pure client-side bookkeeping
(no new protocol *behavior* to discover against a live peer), so per the
established methodology they do **not** require a Python-first live-peer
prototype — they are implemented directly against wireguard-go's constants
and unit-tested on host:

### Replay protection (RFC 6479 sliding window)

`session.rs:154` had `// TODO: nonce sliding window`. Implemented as an
RFC-6479-style sliding-window bitmap per receive session, reset on session
derive. Window shrunk from wireguard-go's 8128 counters to **128** (a
protocol-legal choice — any window ≤ 8128 is valid) to fit the measured
~40–60 KB RAM budget. Per correction #5, the replay window is a rounding
error against RAM (≈16 bytes/keypair); the dominant term is per-peer packet
queues, so queue depth and `MAX_PEERS` are the real levers if the budget is
exceeded.

### Message-count rekey trigger

Added alongside `ts_tunnel`'s existing time-only rekey, using wireguard-go's
constants: `REKEY_AFTER_MESSAGES = 1<<60`, `REJECT_AFTER_MESSAGES = 2^64 -
2^13 - 1`. An `is_initiator` flag is threaded through session creation
(required for the 165 s last-minute rekey path, which is load-bearing since
an ESP32 client is always the initiator).

## Independent Python reference validator (`tools/wg_validator/`)

The Rust data plane initially had only *self*-round-trip tests (its own
encoder against its own decoder). That cannot catch a wire-format/crypto bug
that is uniformly wrong on both the encode and decode side. To close that gap,
an **independent from-spec oracle** was written in Python
(`cryptography` for X25519/ChaCha20Poly1305, `hashlib.blake2s`; HKDF, HChaCha20,
and the whole Noise IKpsk2 state machine hand-rolled) that shares no code with
`tm_wg` and is written against the WireGuard whitepaper and the plan's Part 2
offset tables; never by mirroring the Rust. It reuses the Python-first
methodology already established for the control plane
(`docs/noise-handshake-wire-format.md`).

To let the oracle compare against the *real* Rust code path (not a
re-implementation), `handshake.rs` gained a small, documented testability seam:
a private `EphemeralSecret` trait so `build_initiation` / `build_response` are
the single source of truth for the mix-chain, plus two `#[doc(hidden)]`
deterministic-ephemeral emitters (`initiate_handshake_with_ephemeral`,
`ReceivedHandshake::respond_vector`). Production keeps `ReusableSecret` (whose
scalar bytes deliberately can't leak); the emitters use `StaticSecret` (which
*can* be built from a fixed scalar) so byte-exact vectors are reproducible.
`tm_wg/examples/wg_emit_vectors.rs` and `wg_cookie_probe.rs` expose the bytes.

### Results

**Rung 1, offline byte-level oracle: PASS, byte-for-byte, no discrepancy
found.** `validate_offline.py` runs the real `tm_wg` core for fixed inputs and
independently reconstructs every field. All of the following matched exactly:

- Handshake Initiation (148 B) byte-for-byte; MAC1 (offset 116, over
  `msg[0..116]`) and MAC2 (offset 132, all-zero) domains.
- Handshake Response (92 B) byte-for-byte; MAC1 (offset 60), MAC2 (offset 76).
- Cookie Reply (type 3): XChaCha20Poly1305 decrypt with AAD = last mac1, and
  the mac2 keyed-MAC domain (`msg[0..len-16]`), driven through the real
  `MACSender::receive_cookie` + `write_macs`.
- Transport Data (type 4): 16-byte header, **little-endian** 64-bit counter
  nonce (correctly distinct from the ts2021 *control* plane's big-endian
  transport nonce; a real cross-layer trap), byte-for-byte + decrypt.
- TAI64N 12-byte big-endian timestamp encoding.
- The full **bidirectional key schedule**: initiator-side and responder-side
  derivations both agree with each other and with Rust for both directions.

This proves the Rust encode/decode is not uniformly wrong *relative to the
spec as the oracle understands it*.

**Interop against a third independent implementation: PASS.**
`validate_live_boringtun.py` drives the from-spec Python initiator through a
full live handshake + bidirectional transport exchange against **boringtun**
(Cloudflare's independent production Rust WireGuard, driven in-memory over
loopback UDP, no tun/root). boringtun accepts our initiation, returns a valid
type-2 response, decrypts our transport data to the exact plaintext, and its
reverse-direction transport data decrypts on our side. This closes the residual
risk that the oracle and `tm_wg` share the *same* from-spec misreading: a truly
independent third party interoperates with the oracle, and `tm_wg`'s output is
byte-identical to the oracle (above), so `tm_wg` would interop too.

boringtun 0.6 pins `curve25519-dalek 4.0.0-rc.3`, which needs
`--cfg curve25519_dalek_backend="serial"` to build on current nightly; the
peer crate is a detached workspace so it never touches the firmware graph.

### Honest limits (what this does NOT prove)

- **Not run against the live Tailscale tailnet.** Rung 2 as specified (a real
  WireGuard handshake to a real Tailscale peer node) requires either direct
  UDP (blocked by NAT; needs disco/`tm_disco`) or a **DERP relay client**, on
  top of an independent Python ts2021 control-plane client to fetch peers. The
  control endpoint is reachable and live (a `GET /key?v=72` returned the
  current server Noise key), so the blocker is implementation scope, not
  access; the prior throwaway control-plane Python harness is not recoverable
  from git history, and a from-scratch control-plane + DERP client was out of
  scope for this pass. boringtun is real WireGuard but not a Tailscale peer.
- The oracle validates the crypto/wire format and key schedule. It does not
  exercise the actor, endpoint table, replay window under adversarial load,
  rekey timers, or the ESP32 target (those remain covered by host `cargo test`
  / future Wokwi runs).

## Out of scope for this run (needs hardware)

- Wokwi/ESP live run and the MicroLink interop bench (plan checklist #3):
  require a physical ESP32-C3 board and a bench peer. Host-native
  `cargo test -p tm_wg` and `cargo build -p tm_wg` are the verification for
  this run.
