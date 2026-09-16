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

## Live Tailscale tailnet interop — the missing rung, now CLOSED

The prior pass explicitly could not reach a real Tailscale peer (see "Honest
limits" above: it needed a from-spec ts2021 control client + a DERP relay
client, which were out of scope then). This pass built exactly those, all
independent and from-spec, and drove `wg_spec.py`'s initiator through DERP to a
**real Tailscale peer on the live tailnet**.

New from-spec Python under `tools/wg_validator/` (independent oracles, not Rust
transliterations; cross-checked against `tm_control`, `tm_derp`, `tm_disco`,
and the upstream `tailscale-rs` reference):

- `ts_control.py` — ts2021 control client: fetches the server Noise key from
  `GET /key?v=72`, does the Noise_IK handshake (distinct construction string /
  no-PSK / IK pre-message vs. the WireGuard `Noise_IKpsk2` in `wg_spec.py`),
  the big-endian-nonce + 3-byte-Record transport codec, skips the challenge
  packet, then drives HTTP/2 (the `h2` library) over the Noise transport to
  register and to MapRequest/MapResponse.
- `derp_client.py` — DERP relay client: TLS + `GET /derp` upgrade, ServerKey /
  ClientInfo / ServerInfo handshake (NaCl `crypto_box`/SalsaBox), and
  SendPacket/RecvPacket framing.
- `disco.py` — from-spec disco ping/pong (SalsaBox, magic `TS💬`), needed to
  wake a real peer's lazy wireguard config (see finding 3 below).
- `validate_live_tailnet.py` — the glue that runs all five rungs.

### Result: LIVE PEER INTEROP CONFIRMED — no `tm_wg` discrepancy

Against peer `lenovopill` (a real Tailscale node) home DERP region 11, relayed
through `derp11e.tailscale.com`, every rung passed with real captured output:

1. ts2021 Noise IK control handshake + transport established (server key
   `mkey:7d2792f9…`).
2. Node registered on the live tailnet: `MachineAuthorized=true`.
3. MapResponse parsed: our tailnet IP assigned, 32 peers, 3 online; DERPMap
   region→hostname table extracted.
4. DERP handshake completed (`proto=2`).
5. **The real peer returned a genuine WireGuard Handshake Response (type 2,
   92 B) over DERP** — e.g.
   `02000000d0f5751dd86eb4ee764dd44e062efa7ef83c4d99592e42f8c618779e36f9d6c6…`
   — which **decrypts with a valid empty-payload AEAD tag** using the key
   schedule derived from our initiation. The peer performed real X25519 DHs
   against our ephemeral + static keys and its own; a wrong wire byte or a
   wrong mix-chain step anywhere would fail the tag. It did not.
6. **Transport data round-tripped**: an ICMP echo request built by
   `wg_spec.build_transport` and sent through DERP was decrypted by the peer,
   its OS replied, and the reverse-direction transport packet decrypted on our
   side (`counter=0`, inner IPv4, `ip_proto=1` ICMP, `icmp_type=0` Echo Reply).

Since `validate_offline.py` already proved `tm_wg`'s bytes are identical to
`wg_spec.py`'s, and `wg_spec.py` now interoperates with real Tailscale, this is
**an explicit "no discrepancy — real Tailscale peer interop confirmed"** for
the `tm_wg` wire format and key schedule. WireGuard PSK is all-zero (Tailscale
convention), matching the offline/boringtun passes.

### Findings while building the control/DERP/disco clients (NOT `tm_wg` bugs)

These are in the *reference/control-plane* code, surfaced by the from-spec
Python; none affect the `tm_wg` data plane, but they are recorded for accuracy:

1. **A streaming MapRequest is read-only.** With `Stream=true` and cap
   version ≥ 68 the control server ignores `Hostinfo`, `DiscoKey`,
   `Endpoints` and every other write field (confirmed live: our disco key
   propagated to peers as all-zeros from a streaming request). The disco key /
   preferred DERP / endpoints must be published via a **non-streaming**
   MapRequest first. `tm_control`'s only MapRequest is `Stream=true` and never
   sends a `DiscoKey` at all — so as written it cannot establish a disco path
   to a peer. This is the single change that unblocked the live handshake.
2. **`Hostinfo` is required in a MapRequest** (a `400 "Hostinfo required in
   MapRequest"` otherwise). `tm_control`'s `MapRequest` omits it.
3. **Real peers gate the data plane behind disco.** A raw WireGuard
   initiation to an idle peer is silently dropped: Tailscale trims inactive
   peers out of its wireguard-go config and only re-adds one on disco
   activity. A from-spec disco PING (which the peer answered with a PONG) is
   what makes the peer configure our node and answer the WG handshake.
4. **`tm_disco` uses the wrong AEAD.** `tm_disco/src/lib.rs` decrypts disco
   payloads with XChaCha20-Poly1305 (24-byte nonce). Real disco uses NaCl
   `crypto_box`/SalsaBox (Curve25519-XSalsa20-Poly1305), confirmed against both
   the Go source and the upstream `ts_disco_protocol` (`crypto_box::SalsaBox`).
   With XChaCha20-Poly1305 `tm_disco` cannot open a real peer's disco messages.
5. **`tm_derp` frame-type constants are wrong for Ping/Pong/Health/Restarting.**
   `tm_derp/src/lib.rs` uses `0x40/0x41/0x42/0x43`; the authoritative values
   (Go source + `ts_transport_derp`) are `0x12/0x13/0x14/0x15`.

Findings 1–2 are the reason the earlier note's claim that `tm_control` reached
a working map poll should be read narrowly (it got a MapResponse, but never
published a disco identity). Fixing them in Rust is a control-plane task,
tracked separately from this WireGuard-data-plane validation; they are
documented here because the from-spec oracle is what surfaced them.

### Hygiene

No secret key material or the Tailscale auth key is ever printed or committed;
the auth key is read from the `.env` files at run time only. Node/machine/disco
**public** keys and peer public keys are printed (safe). Each run registers a
node named `wg-validator-probe`; with the current (non-ephemeral) auth key
these persist and should be removed from
`https://login.tailscale.com/admin/machines`.

## Fixes applied (disco/control-plane bring-up, Kanban t_c414048d)

Tracking fixes for three findings above (#5, #4, #1+#2) that block `tm_wg`
from completing a live handshake with a real peer, in safest-first order.
Each fix is verified against its already-working from-spec Python reference
in `tools/wg_validator/` (which interoperated with a real Tailscale peer), or
against authoritative upstream Tailscale source where noted.

### Bug 1 — `tm_derp` frame-type constants (finding #5 above)

`tm_derp/src/lib.rs:42-45` had `Ping=0x40, Pong=0x41, Health=0x42,
Restarting=0x43`. The enum otherwise runs `WatchConns=0x10, ClosePeer=0x11`
and then wrongly jumped to `0x40`. Fixed to the authoritative
`tailscale/derp/derp.go` frame constants `Ping=0x12, Pong=0x13, Health=0x14,
Restarting=0x15`, matching `tools/wg_validator/derp_client.py`'s
`FRAME_PING=0x12` / `FRAME_PONG=0x13` / `FRAME_HEALTH=0x14` /
`FRAME_RESTARTING=0x15` (that client interoperated with a real DERP server).

Also fixed `TryFrom<u8>` (`tm_derp/src/lib.rs:61-66`), which mapped the old
0x40/0x41 values and had no arms at all for Health/Restarting or, pre-existing
independent of this bug, for `WatchConns` (0x10) / `ClosePeer` (0x11) despite
both being declared in the enum — any of those frame types arriving on the
wire would have hit the `_ => Err(())` catch-all. All eight declared variants
now round-trip through `TryFrom`.

Verified with `cargo build -p tm_derp` on host and by diffing the constants
1:1 against `derp_client.py`'s `FRAME_*` block; see the following commit for
the build output.

### Bug 2 — `tm_disco` wrong AEAD (finding #4 above)

`tm_disco/src/lib.rs` sealed/opened disco payloads with XChaCha20-Poly1305:
it fed the raw X25519 Diffie-Hellman shared secret straight into
`chacha20poly1305::XChaCha20Poly1305` as the AEAD key. Real Tailscale disco
uses NaCl `crypto_box` = X25519 + XSalsa20-Poly1305 with a 24-byte nonce,
where `crypto_box` additionally runs the DH output through an HSalsa20
subkey-derivation step before it becomes the cipher key — a different cipher
core (Salsa20 vs ChaCha20) *and* a different key derivation, so the previous
code could not open a real peer's disco messages at all.
`tools/wg_validator/disco.py` uses `nacl.public.Box` (pynacl's crypto_box)
and interoperated with a real peer; the authoritative upstream reference
`~/src/tailscale-rs/ts_disco_protocol/src/packet.rs` builds
`crypto_box::SalsaBox::new(&receiver.into(), &secret.into())` for exactly
this purpose, pinned to `crypto_box = { version = "0.9" }`.

Replaced the AEAD in `DiscoActor::process` (`tm_disco/src/lib.rs`) with the
RustCrypto `crypto_box` crate's `SalsaBox` (same `0.9` line as the upstream
reference): `crypto_box::SalsaBox::new(&sender_pub, &our_secret)` (this call
does both the X25519 DH *and* the HSalsa20 derivation), then
`.decrypt(&nonce, ciphertext)` via the crate's re-exported `aead::Aead`
trait — this mirrors `ts_disco_protocol::packet::Packet::decrypt_in_place`'s
construction exactly, modulo that reference's zerocopy in-place framing.
`tm_disco/Cargo.toml` drops the unused `chacha20poly1305`/`x25519-dalek`
direct dependencies (the DH is now internal to `SalsaBox::new`) in favor of
`crypto_box = "0.9"`.

Verified: (1) `cargo build -p tm_disco` on host — clean, no errors; (2) a
new `#[cfg(test)]` in `tm_disco/src/lib.rs`
(`aead_crosscheck::salsa_box_decrypts_pynacl_sealed_payload`) decrypts a
payload sealed by `pynacl.public.Box` with fixed keys/nonce and asserts the
plaintext matches byte-for-byte; `cargo test -p tm_disco` passes. The pynacl
vector (fixed `sender_priv=01..20`, `receiver_priv=21..40` hex, fixed
24-byte nonce `01..18` hex) was generated with a one-off script using the
`nacl.public.Box` API `disco.py` itself uses (the workstream's environment
had no `pynacl` preinstalled; installed into a throwaway venv against
Python 3.12 only for generating this test vector — no live network peer was
contacted).

Note (not fixed, out of scope for this AEAD-only bug): `tm_disco::process`
also assumes the wire payload starts directly with the sender's disco public
key, with no leading 6-byte `"TS💬"` magic (`disco.py`'s `MAGIC`,
`DISCO_MAGIC` in `tm_disco` is declared but never checked), and its PING
branch reads the 12-byte transaction ID starting at `plaintext[1]` (the
version byte's position per `disco.py`) instead of `plaintext[2]`. Both look
like real framing bugs but are a separate finding from the AEAD swap;
flagging here for a follow-up card rather than folding into this fix.

### Bug 3 — `tm_control` MapRequest never publishes the disco key (findings #1+#2 above)

`tm_control/src/lib.rs` sent only a `Stream=true` MapRequest (Step 8), and
its `MapRequest` struct carried no `Hostinfo`/`DiscoKey`/`Endpoints` fields
at all. Per finding #1, the control server treats a streaming request (cap
>= 68) as read-only and silently ignores those fields — so even if they had
been added to a `Stream=true` request, they would never reach peers (a real
device's disco key would propagate as all-zeros). Per finding #2, `Hostinfo`
is unconditionally required (`400 "Hostinfo required in MapRequest"`
otherwise) — the previous request also omitted it, though this had not yet
surfaced as a visible failure in this codebase's own runs (see the
narrowing note about that below).

Fix, matching `tools/wg_validator/ts_control.py`'s `write_map()` /
`start_keepalive_poll()` split exactly: send a **non-streaming** MapRequest
first — `Stream: false`, carrying `Hostinfo` (`{"OS":"embedded",
"Hostname":"esp32c3"}`, the same value already used for `/machine/register`),
`DiscoKey` (`self.node_state.disco_key.public().to_hex()` — `NodeState`
already carried the disco key, it just was never threaded into the map
request), and `Endpoints` (empty — no active-path discovery is implemented
yet, matching `ts_control.py`'s `endpoints or []` default) — before opening
the existing streaming poll unchanged.

Strictly additive, per the task's own risk framing (this is the only bug of
the three that touches the currently-working registration/MapUpdate path):

- `MapRequest` gained two fields, `disco_key: Option<&str>` and
  `hostinfo: Option<HostInfo>`, both `#[serde(skip_serializing_if =
  "Option::is_none")]`. The existing streaming call now explicitly passes
  `disco_key: None, hostinfo: None`, which serializes byte-identically to
  the pre-fix JSON body (the fields are omitted, not sent as `null`) — the
  streaming request's wire bytes are unchanged.
- A new step (labeled "Step 7.5" in the log/comments, between registration
  and the streaming poll) builds and sends the publish MapRequest, then
  drains its response via the existing `read_one_h2_body` helper (same
  pattern already used for the register response) without altering
  `stream_map_response` or `MapParser` at all.
- HTTP/2 stream-id discipline (`docs/noise-handshake-wire-format.md`):
  register stays on stream 1; the new publish request takes stream 3
  (previously the streaming poll's ID); the streaming poll moves to stream
  5. Each is still its own incrementing odd client-initiated stream ID per
  RFC 7540 §5.1.1 — `tm_h2::H2State` has no cross-stream dynamic-table state
  that ordering could break (confirmed by inspection: it only tracks
  connection/stream flow-control byte counters).

Verified: `cargo build -p tm_control` and `cargo check -p tm_control` on
host — both clean (0 errors; only pre-existing, unrelated warnings —
confirmed via `git stash`/`cargo test` before and after this change, both
show the same 3-passed/2-failed `map_parser` test result, so nothing here
regressed or fixed those). The new `MapRequest` JSON shape was diffed
field-for-field against `ts_control.py::write_map`'s body (`Version`,
`Compress`, `KeepAlive`, `NodeKey`, `DiscoKey`, `Endpoints`, `Stream`,
`Hostinfo`) — same field set, same semantics. Not exercised against the
live control server in this pass (per the task's rules, preferring not to
register a live node); the wire shape is the verification. No live network
command was run and no node was registered for this bug's fix.

## Out of scope for this run (needs hardware)

- Wokwi/ESP live run and the MicroLink interop bench (plan checklist #3):
  require a physical ESP32-C3 board and a bench peer. Host-native
  `cargo test -p tm_wg` and `cargo build -p tm_wg` are the verification for
  this run.

## On-device acceptance-test pass (Wokwi, `tm_wg` data-plane bring-up)

This pass is the on-device acceptance test: build the real firmware for
`riscv32imc-esp-espidf`, run it in Wokwi against the live tailnet, and observe
how far `tm_wg` itself gets, with real serial evidence at each rung.

### Bug 4 — `tm_disco::process` disco framing (magic + PING `tx_id` offset)

Flagged in Bug 2's follow-up note above and by this pass's task brief:
`tm_disco::process` had two framing bugs versus the peer-validated from-spec
reference `tools/wg_validator/disco.py` (which interoperated with a real
Tailscale peer):

1. **The 6-byte disco magic was never checked or skipped.** `process` treated
   the datagram as starting directly with the sender's 32-byte disco public
   key. The real wire format (see `disco.py` `open_disco` and the module
   docstring, cross-checked against the authoritative `ts_disco_protocol`) is
   `magic(6)="TS💬" + sender_disco_pub(32) + nonce(24) + SalsaBox_ct`, so every
   field was read 6 bytes early and decryption of a real peer's packet could
   never succeed. `DISCO_MAGIC` was additionally declared as the placeholder
   `\xc0\xde\x00\x00\x00\x00` (with a `// simplified` comment) instead of the
   real `b"TS\xf0\x9f\x92\xac"` (`disco.py`'s `MAGIC`), and was never used.

2. **The PING transaction ID was read off-by-one.** The disco plaintext is
   `type(1) + version(1) + tx_id(12) + body`. `process` read the 12-byte
   `tx_id` at `plaintext[1..13]` (the version byte's position), so it echoed
   `version || tx_id[0..11]` in the PONG instead of the true `tx_id[0..12]` at
   `plaintext[2..14]` — a PONG a peer would reject as not matching its PING.

Fix (`tm_disco/src/lib.rs`): `DISCO_MAGIC` set to the real `TS💬` bytes; the
length guard widened to `MAGIC_LEN + PUBKEY_LEN + NONCE_LEN + TAG_LEN + 1`;
`process` now verifies `data[..6] == DISCO_MAGIC`, reads `sender_pub` at
`data[6..38]`, `nonce` at `data[38..62]`, ciphertext at `data[62..]`, and the
PING `tx_id` at `plaintext[2..14]` (guarded by `plaintext.len() >= 2 +
PING_LEN`). This matches `disco.py` field-for-field.

Verified Python-first: the fix targets exactly the framing that
`tools/wg_validator/disco.py` implements and that already interoperated with a
real peer (documented in "Live Tailscale tailnet interop" above), so the
Python-first prototype for this protocol behavior predates the Rust change. A
new host test `framing::process_extracts_ping_tx_id_after_magic`
(`tm_disco/src/lib.rs`) wraps the existing pynacl-sealed vector
(`aead_crosscheck`, sealed by `nacl.public.Box`, the primitive `disco.py`
uses) into a full `magic || sender_pub || nonce || ct` datagram, runs it
through `DiscoActor::process`, and asserts the emitted PONG echoes the true
`tx_id` `01..0c` (the old off-by-one code would have echoed `00 01..0b`).
`tm_keys::DiscoPrivateKey` gained a `from_bytes([u8;32])` constructor
(additive, mirrors `DiscoPublicKey::from_bytes`) so the receiver disco key in
that vector can be reconstructed deterministically.

Not fixed here (still out of scope, unchanged risk): the PONG is still emitted
as a bare 12-byte `tx_id` via `DiscoEvent::SendPong` with a UDP-shaped
`dst_ip/dst_port`; a wire-correct PONG must be `magic || our_disco_pub ||
nonce || SalsaBox_seal(type=0x02, ver=0, tx_id, src_endpoint)` addressed to the
peer's node key over DERP. That, and outbound disco PING (needed to *wake* an
idle peer per finding #3), are gated behind the DERP transport, which is a stub
on-device (see the blocker below), so sealing the PONG would have nowhere to go
this pass.

### Data-path wiring in `tm_runtime` + total-free-heap instrumentation

Per the task's "wire `tm_wg`'s data path" item and the plan's Part 2 heap-note:

- `Runtime::join` (the `espidf` path) now consumes the previously-dropped
  `WgEvent` and `DiscoEvent` receivers (they were bound as `_wg_ev_rx` /
  `_disco_ev_rx` and never read, so `WgEvent::InboundDecrypted`,
  `WgEvent::OutboundPacket`, `WgEvent::PeerHandshook` and `DiscoEvent` went
  nowhere). The event router now: routes `WgEvent::OutboundPacket` to
  `DerpCmd::SendPacket` (the outbound WireGuard path — handshake initiations
  and transport data leave `tm_wg` here), logs `PeerHandshook` and
  `InboundDecrypted` (the decrypted-inbound seam; the on-device `tm_netstack`
  is a stub with no lwIP injection, so there is no local socket to deliver to
  yet), and forwards `DiscoEvent::SendPong` toward DERP.
- The DERP inbound demux (`payload[0] == 0x6d`) was replaced with the real
  disco/WireGuard discriminator: a datagram whose first 6 bytes are the disco
  magic `TS💬` goes to `tm_disco`; a first byte in `1..=4` (a WireGuard message
  type) goes to `tm_wg`. `0x6d` matched neither the disco magic (`0x54`) nor a
  WireGuard type byte.
- Added `esp_get_free_heap_size()` logging alongside the existing
  largest-contiguous-block logging in `tm_runtime` (plan Part 2 finding #4
  asked for this), so steady-state total-free heap is reportable against the
  40–60 KB target / 90 KB ceiling without a fresh live-run investigation.

### BLOCKER: the on-device DERP relay client is a stub (rungs 4–6)

Root cause, with code evidence: rungs 4 (disco ping/pong), 5 (WireGuard
handshake) and 6 (transport round-trip) all require moving bytes to a real
peer, and the only path to a peer is DERP (direct UDP is NAT-blocked — this is
exactly why the Python validator relayed through `derp11e.tailscale.com`).
On-device, DERP is not implemented:

- `tm_derp::run_connection` (`tm_derp/src/lib.rs`) is a stub: no TLS dial, no
  `DERP` magic write, no ServerKey/ClientInfo/ServerInfo NaCl handshake, and
  both the send (`// self.send_packet(...)`) and receive
  (`// recv = self.recv_frame(...)`) arms of its select loop are commented
  out. `send_packet_frame`/`recv_frame` helpers exist but are never called.
- Nothing ever sends `DerpCmd::Connect`: `tm_runtime` never issues a Connect
  and never threads the `DERPMap` region→hostname table (which the control
  plane *does* now receive) into the DERP actor. So the actor sits idle in its
  outer `cmds.recv()` loop, silently dropping any `SendPacket`.

Consequently `tm_wg` can build and *attempt* a handshake on-device (its
`apply_map` calls `endpoint.initiate` and emits `WgEvent::OutboundPacket` — now
observable in the log via the new wiring), but the initiation cannot leave the
chip. Bringing rungs 4–6 up on-device requires implementing the DERP relay
client in Rust over `tm_tls` (mirroring the from-spec, peer-validated
`tools/wg_validator/derp_client.py`: TLS + `GET /derp` upgrade, the
ServerKey/ClientInfo/ServerInfo `crypto_box`/SalsaBox handshake, and
SendPacket/RecvPacket framing) and wiring `DerpCmd::Connect` from the
MapResponse DERPMap. That is a substantial net-new device implementation and is
the honest remaining work; it is documented here rather than hidden behind an
inferred rung.

---

## UPDATE (2026-09-16): no-TLS direction — DERP requires TLS; direct-UDP blocked by NAT/path-selection

The device path deliberately avoids TLS (control plane is plain TCP + Noise_IK,
pinned by the control key). The section above recommending a `tm_tls`-based DERP
client is therefore **superseded**: the direction is to eliminate TLS, not
replicate it. Two Python-first spikes (repo methodology) were run against the
REAL live tailnet to decide the transport. Both are reproducible under
`tools/wg_validator/`.

### Spike 1 — no-TLS DERP: REJECTED by real Tailscale DERP
`tools/wg_validator/derp_notls_spike.py`, against `derp{1,2,10}.tailscale.com`:

| attempt | result |
|---|---|
| plain TCP `:80` `GET /derp` | `HTTP/1.1 302 Found`, `Location: https://<host>/derp` (refuses plaintext upgrade) |
| plaintext `:443` `GET /derp` | `HTTP/1.0 400 Bad Request` (TLS listener) |
| TLS `:443` `GET /derp` | `HTTP/1.1 101 Switching Protocols` + DERP ServerKey frame (`01 00000028 44455250f09f9491…`) |

Conclusion: hosted Tailscale DERP has **no non-TLS `/derp` path**. Per the
"do not implement TLS" directive, a DERP relay client is not pursued.

### Spike 2 — direct UDP (skip DERP): disco works, WireGuard handshake does not complete
`tools/wg_validator/udp_recon.py` + `validate_live_udp.py`. Recon of the live
MapResponse: several online peers advertise PUBLIC IPv4 UDP endpoints
(`lenovopill 177.162.84.64:1024`, `alanjds-s25 189.98.243.233:63935`,
`bospill 177.162.84.64:41641`), all in DERP region 11 with disco keys. But every
one is a **NAT-mapped** address (home/mobile), not a server with an open port.

Sending WG Handshake Initiations (and disco PINGs) straight to those public
endpoints from an external initiator got **no response of any kind** — the
peers' NATs drop unsolicited datagrams (symmetric/port-restricted; the inbound
mapping is normally opened by disco call-me-maybe, which rides DERP).

To isolate NAT from the protocol, the same drive was run on the peers' LAN
(the runner shares `192.168.15.0/24` with `lenovopill`, `INCLUDE_PRIVATE=1`):
- **disco PING/PONG round-tripped directly over UDP** with `lenovopill`
  (`192.168.15.139:41641`) — we received both disco `type=2` (PONG) and `type=1`
  (PING) from it. So the disco `crypto_box`/SalsaBox layer works over plain UDP
  against a real peer (effectively the rung-4 crypto, no DERP, no TLS).
- **still no WireGuard type-2 response**, even on the LAN. Tailscale's responder
  sends the WG handshake response over its currently *preferred* path, which
  stays DERP until the disco direct-path upgrade completes in both directions
  over several seconds; without a DERP leg we are not reachable on that path, so
  the response is never delivered to us.

### Conclusion / open architecture decision (for the user)
Against arbitrary REAL Tailscale peers, completing a WireGuard handshake needs
DERP as the NAT-traversal + path-selection bootstrap, and hosted DERP needs TLS.
So "no TLS anywhere in the device path" and "acceptance test against an
arbitrary live Tailscale peer" are in tension. Options, none implemented here:
1. Allow TLS **only** for the DERP leg (isolated to `tm_derp`; all relayed
   payloads are already E2E-encrypted by WireGuard + disco). Smallest change.
2. Provision a peer with a genuinely internet-reachable UDP endpoint (public
   host / port-forward / full-cone NAT) so the device can handshake it directly,
   no DERP. Then implement the on-device path over UDP (`tm_netstack`), no TLS.
3. Run a self-hosted `derper` in plaintext/HTTP mode on a reachable host and
   point the DERPMap at it (no public-Tailscale TLS involved).

Per the "stop rather than reach for TLS" instruction, work paused here for the
decision. The disco-over-UDP result (spike 2) shows the crypto path is sound;
what is missing is a reachable peer + a path the responder will actually use.

### Orthogonal, TLS-independent boot fix landed in the working tree
While investigating, a real on-device boot blocker was root-caused (independent
of the transport decision): `WgActor::run`'s async future was ~90 KB because
`WgEndpoint` (~28 KB) was embedded by value (and duplicated across suspend
states) and `RecvOut` (~12 KB) was doubled through `drain_recv`. Boxing
`WgEndpoint` in `WgActor`, taking `Box<RecvOut>` in `drain_recv` (iterating by
reference), boxing the `dispatch` output in `on_tick`, and `Box::pin`-ing the
per-command handlers in `run()` drops the future to **336 bytes**
(`-Zprint-type-sizes`), fixing the original "memory allocation of ~230 KB
failed" abort (a single alloc larger than the ESP32-C3's ~138 KB largest block).
A residual debug-build stack-frame issue in `Runtime::join` remains (see the
`log_heap`/`spawn_*` `#[inline(never)]` helpers added there); it is unrelated to
the transport decision and is the next on-device step once the architecture is
chosen.

## `Runtime::join` stack-overflow fix (transport-independent, boot to rung 3)

Follow-up to the previous section: the residual `Runtime::join` stack-frame
issue is now root-caused and fixed. This section documents it independently of
the (paused) TLS/DERP transport decision above — nothing here touches
`tm_derp`, `tm_tls`, or implements any transport.

### Symptom
A live Wokwi run crashed with a Guru Meditation "Stack protection fault" in
`Runtime::join`'s `{closure#0}` (the state machine backing `tokio::join!` of
the four actors), on the ESP32-C3 main task's 32000-byte stack, before any
actor started running.

### Root cause (compound, three layers)
1. **`Runtime::join` itself**: `-Zprint-type-sizes` showed the generator's own
   captured-across-await state was only 928 bytes, but the live/objdump frame
   was **56432 bytes** (`addi sp,sp,-256` + `sub sp,sp,0xdb70`). At this
   crate's `dev` profile (`opt-level = "z"`, `lto = true`,
   `tasmolike-rs/Cargo.toml`), the compiler does not reuse stack slots across
   the function's ~15 inline heap-probe blocks, ~33 tracing-macro format
   temporaries, and the inline `event_router` `async move` block — all of that
   transient (non-persisted) local state gets its own slot, additively.
2. **LTO re-inlining across the fix**: extracting the event-router into a
   top-level `async fn` and moving the per-actor heap-probe/error-log code
   into `#[inline(never)]` helpers shrank `join`'s state, but `join` then
   *disappeared* as a standalone symbol — LTO+opt-z folded it wholesale into
   its caller, `tailmicro::Device::new`, whose combined `Timeout<...>::poll`
   frame was still ~55.7 KB. `#[inline(never)]` on `join` itself does not
   stop the *caller* from inlining it in; only a `#[inline(never)]` boundary
   at the *call site* does.
3. **`WgActor::new`/`WgEndpoint::new`**: once `join`'s own frame was forced
   into isolation (see fix below), the ~28 KB cost relocated rather than
   disappeared — first into `spawn_wg` (56032 bytes: `WgActor::new`, a small
   plain function, was inlined into `spawn_wg` despite `spawn_wg` itself being
   `#[inline(never)]`, since that attribute only stops *its caller* from
   inlining it, not what it calls), then into `WgEndpoint::new_boxed` after
   isolating that (55952 bytes: `Box::new(Self::new(..))` still built the
   ~28 KB `WgEndpoint` — dominated by `ArrayVec<Peer, 8>` at 27656 bytes — on
   the stack before moving it into the `Box`, a genuine double-copy).

### Fix
- `tm_runtime/src/lib.rs`: extracted the inline `event_router` closure into a
  top-level `async fn event_router_task(...)`; added an `#[inline(never)] fn
  log_heap(tag: &str)` helper replacing all ~15 inline heap-probe blocks, plus
  `log_control_error`/`log_derp_error` helpers for the remaining `debug!`/
  `info!` format temporaries; added `#[inline(never)] fn spawn_control/
  spawn_derp/spawn_disco/spawn_wg/spawn_event_router(...) -> Pin<Box<dyn
  Future<Output = ()>>>` helpers that construct the actor **and** `Box::pin`
  its `run()` future inside the *same* non-inlinable function (constructing
  the actor in `join` and passing it into a spawn helper was not enough — see
  layer 3 above). `Runtime::join`'s body now only allocates channels
  (`log_heap`'d between each), calls the five `spawn_*` helpers, sends
  `ControlCmd::Start`, and awaits `tokio::join!` on the five boxed futures.
- `src/lib.rs` (tailmicro crate): added `#[inline(never)] fn
  spawn_runtime_join(rt_config) -> Pin<Box<dyn Future<Output = Runtime>>>`
  wrapping `Box::pin(Runtime::join(rt_config))`, and call it from
  `Device::new` instead of awaiting `Runtime::join` directly — this is the
  call-site boundary needed to stop LTO from re-merging `join` into
  `Device::new` (layer 2 above).
- `tm_wg/src/endpoint.rs`: added `WgEndpoint::new_boxed(my_key) -> Box<Self>`,
  `#[inline(never)]`, using `Box::<Self>::new_uninit()` +
  `core::ptr::addr_of_mut!` field writes. The `peers: ArrayVec<Peer, 8>` and
  `state.sessions: ArrayVec<_, SESSION_MAP_CAP>` fields are written via
  `core::ptr::copy_from_nonoverlapping` from `static EMPTY_PEERS`/
  `static EMPTY_SESSIONS` (built with `arrayvec`'s `ArrayVec::new_const()`,
  the crate's own documented pattern for large const-initialized
  `ArrayVec`s) rather than `.clone()`/`.write(value)` — a raw memcpy from a
  fixed `static` address needs no stack-resident source value, whereas
  `ArrayVec::new()` is not `const fn` and still materialized a fresh ~27.6 KB
  value on the stack when used as a `.write()` argument. `nm` confirmed
  `EMPTY_PEERS` lands in `.bss` at a fixed address, not on the stack.
- `tm_wg/src/lib.rs`: `WgActor::new` now calls `WgEndpoint::new_boxed(kp)`
  instead of `Box::new(WgEndpoint::new(kp))`.

### Evidence (objdump prologue sizes, `riscv32-esp-elf-objdump -d`, RISC-V
`addi sp,sp,-N` / `sub sp,sp,-M` prologue arithmetic; toolchain at
`~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20251107/...`)

| Function | Before | After |
|---|---|---|
| `Runtime::join::{closure#0}` | 56432 B (baseline) / 56720 B (mid-fix, still merged into `Device::new`) | **672 B** |
| `Device::new`'s `Timeout<...>::poll` (LTO-merged frame) | ~55.7 KB (merged with `join`) | 800 B (standalone once `spawn_runtime_join` added) |
| `spawn_wg` | n/a (didn't exist) | 96 B (after actor-construction moved fully inside it) |
| `WgEndpoint::new_boxed` | 55952 B (iter. 1: `Box::new(Self::new())`) → 27696 B (iter. 2: `new_uninit` + `.write(value)`) | **64 B** (iter. 3: `new_uninit` + static + `copy_nonoverlapping`) |
| `spawn_control` / `spawn_derp` / `spawn_disco` / `spawn_event_router` | n/a | 160 B / 32 B / 32 B / 64 B |

`-Zprint-type-sizes` (`/tmp/typesizes.log`, not committed) cross-checks:
`{async fn body of Runtime::join()}` = 928 B (confirms the 56432 B live frame
was transient/non-reused locals, not captured state);
`tm_wg::endpoint::WgEndpoint` = 27968 B, dominated by
`ArrayVec<Peer, 8>` = 27656 B.

### Live Wokwi verification
With the fix landed, a live Wokwi run no longer crashes at any of the three
former fault points (`Runtime::join`, the `Device::new`-merged frame, or
`WgEndpoint` construction). The boot now reaches: all four actors + event
router constructed and spawned, `ControlCmd::Start` sent, `tokio::join!`
entered, TCP connect to `login.tailscale.com:80`, Noise IK handshake against
the **verified, non-expired control-key pin** (Noise handshake failure is the
documented symptom of an expired pin — this did not occur), node
registration (`machine_authorized=true`), and the Step 7.5 non-streaming
MapRequest (Hostinfo + DiscoKey + Endpoints) being sent. See
`tools/wokwi_run_20260916_141831.log` and `tools/wokwi_run_20260916_142008.log`.

**Honest gap**: neither run observed the Step 7.5 response, the streaming
MapRequest/response, or a `DERPMap`/peers-seen log before the run ended (a
60-real-second Wokwi wall-clock timeout in the first case; the app's own
60-device-second `Device::new` timeout — `src/tailscale_rust.rs` — in the
second, longer run). This stall is **downstream of, and unrelated to, the
stack-overflow bug fixed above** (heap stayed flat and healthy throughout —
~120 KB free — ruling out a heap/stack fault; the fixed code is not on this
path at all past the initial `join`/`spawn_*` calls). Diagnosing it
(real network latency in Wokwi's simulated internet vs. a genuine protocol
stall in `stream_map_response`/`read_one_h2_body`) is out of scope for this
transport-independent boot fix and was not pursued further, per the
instruction to stop at rung 3 and not touch the control/transport protocol
logic. Rung 3 (control-plane connect confirmed; disco key sent; DERPMap/peers
not yet observed) is therefore reached up to registration + map-publish, but
not fully confirmed by a `MapUpdate`/`DERPMap` log line.
