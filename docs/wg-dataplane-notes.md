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

## DERP TLS leg: embedded-tls (locked decision, 2026-09-16)

Transport is unpaused with a locked decision: the on-device DERP client's TLS
leg is `embedded-tls` (pure-Rust, no_std, TLS 1.3-only), optimized for the
SMALLEST possible RAM. NOT mbedTLS/esp-tls, NOT rustls. Isolated inside
`tm_derp` (feature `etls`); the rest of the firmware stays mbedTLS-free on this
path.

### Config (smallest-RAM, non-negotiable)
- TLS 1.3 only (embedded-tls is 1.3-only by construction).
- Certificate verification DISABLED: `UnsecureProvider` wires `NoVerify` +
  `NoSign` (no CA, no webpki, no hostname check). Safe by design: every byte
  DERP relays is already E2E-encrypted (WireGuard transport + disco
  `crypto_box`), so a MITM on the TLS hop sees only ciphertext; it can DoS but
  cannot read or forge tunnel contents. We DO advertise RSA signature schemes
  (`TlsConfig::enable_rsa_signatures`) so the RSA-certificated DERP server can
  choose a `CertificateVerify` scheme; we simply never check the signature (no
  rsa crate pulled in).
- Single cipher suite `TLS_CHACHA20_POLY1305_SHA256` (0x1303). embedded-tls
  0.19 ships only AES suites, so the suite is a custom `TlsCipherSuite` impl
  (`tm_derp::tls::Chacha20Poly1305Sha256`) reusing the RustCrypto
  `chacha20poly1305` + `sha2` crates already compiled for Noise/WireGuard: zero
  extra AEAD/hash flash, and ChaCha is the fast path on the ESP32-C3 (no AES
  accel wired here).
- RFC 6066 `max_fragment_length = 2048` advertised (`MaxFragmentLength::Bits11`).
  Go's `crypto/tls` server ignores it today so it does not shrink inbound
  handshake records, but it is free and future-proof.

### Python parity (proven against live derp1.tailscale.com)
`tools/wg_validator/derp_client.py` gained `connect(minimal_tls=True)` (TLS 1.3
only, `CERT_NONE`, no hostname check). It completes the full DERP handshake
through ServerInfo (crypto_box round-trip returns `{'version': 2}`) and pulls
the real ServerKey `69dcb903...4b817171`. Python's stdlib ssl cannot restrict
the TLS 1.3 ciphersuite set, so the single-ChaCha half was proven with
`openssl s_client -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256`: with ONLY
ChaCha offered and verification off, the server returns
`HTTP/1.1 101 Switching Protocols` + `Derp-Version: 2` followed by the ServerKey
frame `01 00000028 44455250f09f9491 <serverkey>`.

### Wire measurement that sets the read-buffer floor
Live TLS 1.3 handshake trace (`openssl s_client -trace`) to derp1.tailscale.com:
the server `Certificate` handshake message is 4444 bytes (a 4-cert RSA chain,
1286 + 1247 + 1528 + 359), sent in a single ~4.47 KB TLS record. embedded-tls
decrypts records in place, so the read buffer must hold the largest inbound
record whole. `max_fragment_length` does not help (Go server ignores it). This
sets `RECORD_READ_BUF = 5120` (confirmed: a live handshake with exactly 5120 B
succeeds).

### RAM HEADLINE
embedded-tls takes caller-provided record buffers; those buffers plus the small
connection state ARE the whole steady-state cost. Measured with the exact
suite/verifier/buffer config in a real Rust handshake to derp1.tailscale.com
(host spike, embedded-tls 0.19):

| Term | Bytes |
|---|---|
| `TlsConnection` fixed state (key schedule, traffic secrets, running SHA-256 transcript, cipher keys/IVs, record reader/writer), excl. buffers | 1384 |
| `RECORD_READ_BUF` (floor from measured 4444 B cert record) | 5120 |
| `RECORD_WRITE_BUF` (covers ~1500 B WG packet + framing + 128 B TLS overhead) | 2048 |
| **Total steady-state TLS session heap** | **8552 (~8.5 KB)** |

Handshake peak equals steady-state: embedded-tls runs the handshake inside these
same fixed buffers with no heap spike, and NoVerify skips the one large
transient (signature verification). Against the budget: ~8.5 KB is ~6.5% of the
~130 KB free heap and is dwarfed by tm_wg's ~28 KB `WgEndpoint`. An
mbedTLS/esp-tls session would instead cost 40-70 KB. This is exactly why
embedded-tls was chosen.

HONEST CAVEAT: the 8.5 KB is measured from (a) the real embedded-tls 0.19 API
(`core::mem::size_of` of the connection state), (b) the caller-controlled buffer
sizes, and (c) a live-wire cert measurement, all cross-checked by a real Rust
handshake that completes against derp1.tailscale.com. It is NOT yet an
on-device `esp_get_free_heap_size()` before/after delta: a full firmware build
(embedded-tls + deps on the riscv32imc-esp-espidf target) + Wokwi run to a TLS
handshake was not completed in this session. The buffer terms (7168 B) are
architecture-independent; the 1384 B fixed state is host-measured (x86-64,
8-byte pointers) and is marginally SMALLER on the 32-bit target, so the
on-device figure should land within a few hundred bytes of 8.5 KB.

### embedded-tls integration (files/functions)
- `tm_derp/Cargo.toml`: new `etls` feature (default OFF) gating optional deps
  embedded-tls 0.19, embedded-io-async/adapters, chacha20poly1305, crypto_box,
  sha2, digest, typenum, rand_core. Default build (feature off) is unchanged, so
  the firmware's esp build is not disturbed until `etls` is enabled and run.
- `tm_derp/src/tls.rs` (feature `etls`): `Chacha20Poly1305Sha256` custom suite;
  `RECORD_READ_BUF`/`RECORD_WRITE_BUF` constants; `DerpTls::connect(...)` doing
  the TLS 1.3 open (no-verify) + `GET /derp` upgrade + ServerKey/ClientInfo/
  ServerInfo handshake; `send_packet`, `read_frame`, `pong`. DERP framing and
  the SalsaBox handshake are reused field-for-field from the paused stash's
  DERP client (`stash@{0}`), which itself mirrors derp_client.py; only the TLS
  backend changed (rustls/tm_tls -> embedded-tls). Generic over
  `S: embedded_io_async::Read + Write` (on device:
  `embedded_io_adapters::tokio_1::FromTokio<tokio::net::TcpStream>`, since the
  control plane already dials plain TCP via tokio there).
- `tm_derp/src/lib.rs`: `DERP_MAGIC` corrected to the 8-byte `DERP` + U+1F511
  literal and made `pub`; `pub mod tls` added under the `etls` feature.

### Remaining
- Turn on `etls` in the firmware, add the `esp_get_free_heap_size()` +
  largest-contiguous probe immediately before/after `DerpTls::connect`, build
  twice, `elf2image`, `wokwi-cli`, and record the live heap delta to close the
  loop on the headline number.
- Wire `DerpCmd::Connect` in `tm_runtime` to `DerpTls`, thread the MapResponse
  DERPMap (region -> hostname), and land the disco PONG sealing (available in
  the stash's `tm_disco`) for the disco ping/pong over DERP (rung 4).

## Step 7.5 stall ROOT CAUSE (2026-09-16, live-observed): HTTP/2 flow control in `read_one_h2_body`

The "Honest gap" above (firmware sends the Step 7.5 non-streaming MapRequest
then never observes its response, the streaming poll, or `DERPMap`/peers) is
now root-caused against the LIVE control server, Python-first, no inference.

### Direct observation (`tools/wg_validator/`, ephemeral registration)
A probe that reuses `ts_control.py` to register + `write_map()` and instruments
the `h2` driver to record every DATA-frame size on the map stream measured, on
the live `login.tailscale.com`:

- non-streaming `/machine/map` response body = **29404 bytes across 9 DATA
  frames**, arriving in **4096-byte chunks** (first six frames: 4096 each).

The server caps its DATA frames to our advertised
`SETTINGS_INITIAL_WINDOW_SIZE` and, after it has sent one stream-window's
worth (`tm_h2::INITIAL_WINDOW = 4096`) and one connection-window's worth
(`CONN_WINDOW = 32 KB`), it **stops and waits for a `WINDOW_UPDATE`** before
sending more. The Python client keeps the stream flowing purely because its
`h2` driver calls `acknowledge_received_data()` after each frame, which emits
`WINDOW_UPDATE`s (`_pump()` in `ts_control.py`).

### The bug
`tm_control::read_one_h2_body` (used to drain BOTH the register response and
the Step 7.5 publish response) never emits any `WINDOW_UPDATE`: its Data arm
only appends payload and handles SETTINGS/PING acks. It does NOT call
`H2State::consumed()` nor `write_window_update()` the way `stream_map_response`
does. So:

- the register response (< 4096 bytes) drained fine — under one window, no
  update ever needed. This is why registration always succeeded.
- the Step 7.5 publish response (29 KB) delivers its first 4096 bytes, then the
  server blocks on flow control forever; `read_one_h2_body` sits in
  `noise.read_exact` waiting for a DATA frame the server will never send until
  granted window. **Permanent hang.** Exactly the observed symptom.

This is a genuine protocol stall (not Wokwi network latency), and it is
independent of, and downstream of, the earlier stack-overflow fix.

### Fix
Give `read_one_h2_body` the same flow-control accounting `stream_map_response`
already has: after each `FrameAction::Data`, call `h2.consumed(payload.len())`
and write the connection-level (stream 0) and stream-level (`expected_stream`)
`WINDOW_UPDATE` frames it returns. Purely additive; the register path is
unaffected (it never crosses a window boundary). Unblocks the Step 7.5
response, the streaming poll, and the `DERPMap`/peers parse (rung 3).

## Step 7.5 continued: three more live bugs behind the netmap parse (2026-09-16)

With the `WINDOW_UPDATE` fix above the 29 KB publish response finally arrived
on-device, which surfaced three further bugs, each root-caused on hardware with
direct serial evidence (no inference). All are fixed; rung 3 is now reached.

### Bug A — `arrayvec::push` panics on window overflow
`read_one_h2_body` accumulated the body into a fixed `ArrayVec<u8, 4096>` with
`.push()`. Once the response exceeded 4096 bytes (it is 29 KB) the first byte
past the cap hit `CapacityError` and `push` **panics/aborts**. Fixed by draining
into a growable buffer and using `try_push`/`extend` so an over-cap body can
never abort the task.

### Bug B — the MapResponse body is 4-byte-LE length-prefixed, not raw JSON
Both the non-streaming publish response and the streaming poll frame each
MapResponse as `u32-LE length + JSON` (confirmed against
`ts_control.py::read_full_body`/`read_stream_message`, whose `write_map` unpacks
`struct.unpack("<I", resp[:4])`). The firmware had been feeding the whole body —
prefix bytes included — straight to the JSON parser, so it never parsed. Fixed
by buffering DATA payloads and de-framing every complete `4 + len` message before
parsing (`stream_map_response`, shared by the publish and the streaming poll).

### Bug C — the hand-rolled `map_parser` mis-parses the real response
The streaming `MapParser` extracted 0 peers / 0 regions / no IP from the live
34 KB response. Its own unit tests fail on the committed code: the root `{`
skipped the whole document, its skip logic was not string-aware, and array-
element strings were misclassified as object keys. Because device RAM is ample
for this small tailnet (tens of KB body vs ~120 KB free heap), it was replaced
with `map_serde.rs`: buffer the de-prefixed JSON and parse with `serde_json`
(already a dependency), borrowing `&str` for the escape-free fields we read.
`map_parser.rs` was removed (see git history); `map_serde`'s unit test parses a
real-shaped response including the `{}[],`-bearing skipped subtrees that broke
the old parser.

### Two heap hazards found while wiring `map_serde` in
- **`Vec` doubling OOM.** Accumulating a 34 KB message by `Vec` doubling steps
  through a 64 KB reservation; on the fragmented ESP heap (largest contiguous
  ~69 KB, and the old buffer is still held across `realloc`) that step aborts
  ("memory allocation of 65536 bytes failed"). Fixed by `reserve_exact` for the
  exact `4 + len` once the length prefix is known — one ~34 KB allocation fits.
- **Garbage length prefix on the streaming keepalive → 1.95 GB reserve abort.**
  After rung 3 succeeded via the publish response, the follow-on `Stream=true`
  keepalive poll read a desynced/garbage 4-byte prefix (seen live as
  `1953722188`) and `reserve_exact` OOM-aborted. Guarded with `MAX_MAP_MSG`
  (512 KB): any prefix beyond a plausible netmap means the stream is desynced,
  so `stream_map_response` logs and returns `Ok(())` gracefully rather than
  aborting. The authoritative netmap already came from the publish response, so
  the keepalive bailing does not lose peers/DERPMap. (The keepalive framing
  itself is left for a later pass; it is not needed for rungs 3–6 bring-up,
  during which the freshly delivered map keeps us online.)

### Rung 3 REACHED — live serial evidence
A clean Wokwi run (live `login.tailscale.com`, ephemeral registration) shows:

- `Tailscale OurIpAssigned event sent: 100.90.118.17`
- `Tailscale MapUpdate event sent (8 peers, 4 DERP regions)`
- `Runtime::join() - MapUpdate: 8 peers, 4 DERP regions, our_ip=100.90.118.17`
- DERP regions with real hostnames: region 1 (nyc) `derp1g.tailscale.com`,
  10 (sea), 11 (sao) `derp11e.tailscale.com`, 12 (ord)
- 8 peers enumerated (e.g. `raspill derp_region=11 ip=100.123.201.53`)

i.e. control connect + Noise/H2 + register + **disco key published** +
**MapResponse/DERPMap/peers parsed and delivered to the runtime** — the rung-3
bar. Next: wire `DerpCmd::Connect` over `etls` to the target peer's home region
(rung 4).

## Step 7.5 RESOLUTION: the real OOM root cause was heap budget vs map size (2026-09-17)

The `MAX_MAP_MSG` cap and the prefix/body reassembly above stopped OUR code from
aborting, but the device still crash-looped with a constant `memory allocation
of 12100 bytes failed` — an abort from a DIFFERENT component, not our map
buffer. Root-caused on hardware with the runtime's per-step heap probes:

- The live netmap had grown to ~40 KB (`mlen` seen live: 40178, 40948, 41679,
  climbing per boot as ephemeral test-nodes from repeated registrations
  accumulate; a fresh `ts_control.py` probe measured 29404 B — the body is
  dominated by the full public DERPMap, not by our peers).
- By the time `connect_and_poll` runs, `Runtime::join` has already constructed
  all actors up front, and the **WgActor's eager `WgEndpoint` (~28 KB) alone**
  drops the largest contiguous block from ~110 KB to ~69 KB (serial:
  `heap [after WgActor spawn]: total_free 114120 -> 85916, largest 102400 ->
  73728`).
- Buffering the ~40 KB map whole then cannot coexist with the rest of the
  connection's working set in that ~69 KB fragmented budget. It is a genuine
  catch-22: allocate the map buffer LATE (during the read) and a concurrent
  ~12 KB alloc fails once our buffer takes the last big block; allocate it
  EARLY (before the handshake) and the Noise handshake's own ~12 KB alloc
  starves instead. Neither ordering fits.
- When the map was small (~12 KB, an earlier boot) everything fit and rung 3
  was reached — confirming size, not logic, was the gate.

### Fix — allocate the WgEndpoint lazily (frees the ~28 KB when the map needs it)
`WgActor::endpoint` became `Option<Box<WgEndpoint>>`, built on first use
(`apply_map` / inbound packet) instead of at construction. `apply_map` runs only
AFTER the control plane has parsed the netmap and freed its buffer, so the
~28 KB is allocated exactly when it is free to take — and stays out of the heap
during the control read, giving the map buffer room. `on_tick` returns early
while the endpoint is `None` so a timer tick never forces the allocation.

Purely a lifetime change; all 21 `tm_wg` unit tests still pass.

### Clean run — live serial evidence (single boot, no crash-loop)
- `Tailscale OurIpAssigned event sent: 100.96.169.109`
- `Tailscale MapUpdate event sent (8 peers, 4 DERP regions)`
- `Runtime::join() - MapUpdate: 8 peers, 4 DERP regions, our_ip=100.96.169.109`
  with DERP regions 1 (nyc) `derp1g.tailscale.com`, 10 (sea) `derp10b`,
  11 (sao) `derp11e`, 12 (ord) `derp12d`, and 8 peers enumerated.
- `tm_wg: WgActor: allocating WgEndpoint (~28 KB) on first use` — the deferred
  allocation, happening after the map is delivered.
- The `Stream=true` keepalive's garbage length is caught: `stream_map_response:
  implausible message length 1953722184 on stream 5, ending` (graceful, no OOM).
- The device then runs stably for ~40 s emitting `WgEvent::OutboundPacket 148
  bytes -> DERP peer ...` — real WireGuard **handshake-init** messages (148 B)
  for each peer. The outbound WG leg works; the packets are queued to the DERP
  transport, which is not wired yet (Task 2), so they do not yet reach peers.

Rung 3 is reached cleanly, and `tm_wg` is already producing WireGuard handshake
initiations (the outbound half of rung 5). The remaining gap to rungs 4-6 is the
DERP `etls` leg (connect to the peer's home region, relay disco ping/pong and
the WG handshake). NB: whole-buffering a ~40 KB map is inherently tight on this
heap; if the netmap grows further the durable fix is a streaming parse that
extracts only the fields we keep (our IP, peers, DERP regions) without holding
the whole body — `map_serde` is the buffered stopgap that fits today's map.

## Rungs 4 → 5: DERP `etls` leg wired, live relay round-trip, WG-finish blocker

The DERP transport (Task 2) is now wired end-to-end and validated live on
ESP32-C3 in Wokwi against real Tailscale DERP and a real peer.

### What was wired

- **`tm_derp` `etls` enabled in the firmware** (`Cargo.toml`:
  `tm_derp = { ..., features = ["etls"] }`). `DerpTls::connect` (embedded-tls
  TLS 1.3, ChaCha-only, no-verify + the ServerKey/ClientInfo/ServerInfo NaCl
  `crypto_box` handshake) was already implemented; this change makes the actor
  actually use it.
- **`DerpActor` now carries the node Curve25519 private key** (`node_priv`),
  paired with `our_key` (node public) for the DERP `crypto_box` handshake.
  `DerpActor::new(our_key, node_priv)`; the runtime passes `wg_priv` (the node
  key) for both.
- **`DerpActor::run_connection` (feature `etls`) is a real send/receive loop.**
  It dials TCP via tokio, wraps it in `embedded_io_adapters::tokio_1::FromTokio`,
  runs `DerpTls::connect`, then services a `tokio::select!` that only *decides*
  what happened (a command arrived, or a frame was read) and performs every
  `&mut tls` action *after* the `select!` — so the send path and the receive
  path never borrow `tls` simultaneously. `TlsConnection::split()` was not an
  option: it requires `Socket: Clone`, and `FromTokio<tokio::net::TcpStream>`
  is not `Clone`.
- **Cancellation-safe resumable frame reader** (`DerpTls::read_frame_buffered`
  + `DerpTls::frame`). embedded-tls's record layer already retains a partial
  *record* (`RecordReader::pending` lives in the connection), and this method
  keeps the partial *frame* (header/body byte counters + an owned boxed body
  buffer) in `DerpTls` itself. Dropping the read future when the command branch
  of the `select!` wins therefore never loses bytes or desyncs framing; the
  next call resumes at the exact byte.
- **Runtime issues `DerpCmd::Connect` on `MapUpdate`**: it picks a target peer
  (first online, else first) and connects to the DERP region that peer is homed
  on, so the server can relay to it. A repeat Connect from a later map snapshot
  is ignored while a connection is up.

### Task 5: measured on-device DERP TLS RAM cost

Heap probes (`esp_get_free_heap_size` + `heap_caps_get_largest_free_block`,
`MALLOC_CAP_INTERNAL`) straddling `DerpTls::connect`, with the probe placed
*before* the record buffers are allocated so the delta captures the full
session (both record buffers + embedded-tls fixed state + the boxed frame
buffer). Live serial, consistent across boots:

```
DerpActor heap [before DerpTls::connect]: total_free=52536, largest_internal_block=40960
DerpActor heap [after  DerpTls::connect]: total_free=40708, largest_internal_block=26624
```

=> **measured ≈ 11.8 KB total-free delta** (≈ 16 KB largest-block delta from
allocation placement/fragmentation). This is larger than the ~8.5 KB
host-side estimate: the estimate counted the 5120+2048 record buffers and
~1.3 KB fixed state; the on-device figure also includes the 1532-byte boxed
frame buffer and allocator rounding/fragmentation. It remains a small fraction
of the ~125 KB heap and an order of magnitude below an mbedTLS/esp-tls session.

### Live evidence (rung 4 reached; rung 5 pipeline proven to the AEAD step)

Single stable boot, no crash, ~130 s:

```
Runtime::join() - DERP connect -> region 11 (sao) host=derp11e.tailscale.com port=443 for peer lenovopill
tm_derp: DerpActor: dialing derp11e.tailscale.com:443
tm_derp: DerpActor: DERP handshake complete with derp11e.tailscale.com
tm_derp: DerpActor: RecvPacket 92 bytes from 0e63..     (x7)
tm_wg::vendor::handshake: decryption failed error=aead::Error
tm_wg::endpoint: handshake failed to complete
```

So: DERP TLS + DERP protocol handshake **succeed** on-device; we send 148-byte
WireGuard handshake *initiations* to peers over the relay; the target peer
**responds** with 92-byte WireGuard handshake *responses* which the server
relays back to us (`RecvPacket 92 bytes`); those are demuxed, routed to
`tm_wg`, parsed as `HandshakeResponse`, and fed to `handshake.finish`. The
**bidirectional DERP relay round-trip works** — this is rung 4, and stronger
than the disco-ping/pong proxy originally planned for it (real WG packets both
directions).

The remaining gap to rung 5 (`PeerHandshook`) is a WireGuard **crypto interop**
failure: `handshake.finish` fails the AEAD tag check on the response's encrypted
empty payload (`aead::Error`), consistently (not a stale-ephemeral race — the
re-init is gated at `HANDSHAKE_TIMEOUT` ≈ 5 s and responses arrive within a DERP
RTT). The node keypair itself is proven valid: the DERP `crypto_box` handshake,
which uses the *same* node Curve25519 key, succeeds. The failure is inside the
WireGuard-specific Noise `finish` derivation. Per the project rule this is
"new protocol behaviour" and must be pinned down **Python-first** against the
live peer (compare our IK/response transcript and key schedule to a reference
`wg_validator` run) before patching `tm_wg`'s handshake. That is the precise,
narrow remaining blocker for rungs 5-6.

### Stack-overflow root cause + fix (surfaced by the now-working inbound path)

Wiring the relay made `tm_wg` receive real inbound packets for the first time —
which immediately hit a `Guru Meditation ... Stack protection fault` in
`WgEndpoint::recv_one` on task `main`. Root cause (byte-exact from the crash SP
vs the reported stack bounds): `RecvOut` embeds two `ArrayVec<Packet, OUT_CAP>`
(OUT_CAP=4, `Packet`≈1512 B `heapless` inline) ≈ **12 KB**, and `recv_one`
returned it **by value**, which `on_inbound` then `Box::new`'d — materialising
~12 KB on the stack on top of the tokio/actor poll chain and the deep
Blake2s/HKDF handshake-finish crypto. The outbound-only rungs never exercised
this (DERP delivered no inbound before).

Two fixes, in order of preference (heap-neutral first):

1. **`WgEndpoint::recv_one_into(&mut RecvOut)`** — fill a caller-provided,
   heap-allocated `RecvOut` instead of returning 12 KB by value. `on_inbound`
   now does `let mut out = Box::new(RecvOut::default()); recv_one_into(.., &mut
   out)`. Removed exactly ~12 KB from the stack (crash SP moved from 22.8 KB to
   10.7 KB past the bound). The 12 KB now lives on the heap, where the
   post-connect largest block (~16 KB at the final stack size) has room.
2. **`CONFIG_ESP_MAIN_TASK_STACK_SIZE` 40960 → 55296.** The residual ~10.7 KB
   is genuine call-depth in the vendored WireGuard `handshake.finish`
   (HKDF/HMAC-Blake2s) key schedule — not a boxable single frame. The bump is
   sized against the heap: it keeps the post-connect largest free block
   (~14-16 KB) above the 12 KB the boxed `RecvOut` needs, so the two-sided
   squeeze (bigger stack vs. the heap the relay + boxed `RecvOut` need) stays
   satisfied. With both fixes the device runs the full window with **no fault**.

## Rung 5 root cause: WG-finish `aead::Error` was an INDEX-MATCHING bug, not crypto

The `handshake.finish` `aead::Error` (blocking rung 5) was root-caused
Python-first and pinned to the initiator's response↔initiation matching, NOT to
the Noise key schedule. Evidence, in order:

### The crypto core is byte-correct (ruled out first)
`tools/wg_validator/validate_offline.py` still passes 16/16 against the real
Rust core (`cargo run -p tm_wg --example wg_emit_vectors`): initiation bytes,
responder bytes, both transport keys, transport-data, cookie/mac2 domains all
byte-for-byte vs. the independent from-spec oracle. The response MAC1 also
verifies live on-device (`finish` reaches the `decrypt` step, past
`cookies.verify_macs`), which proves the 92 response bytes arrive intact and are
keyed with our correct static pubkey. So neither the schedule nor the wire
framing (no DERP-header leak) is at fault.

Gap this exposed: the offline oracle drives the responder path
(`respond_vector`) for its keys and only exercises the initiator-consume schedule
in *Python* (step 7). Rust's own `finish()` was covered only by the symmetric
in-crate `test_handshake` (both sides the same code), so an operational fault in
how `finish()` is *fed* was invisible to the oracle.

### The bug: `dispatch` never freed a timed-out initiation's session id
`WgEndpoint::dispatch` retries a handshake every `HANDSHAKE_TIMEOUT` (5 s), each
retry with a fresh ephemeral and a new sender session id. The retry was meant to
free the timed-out initiation's session id from the `sessions` map, but the two
loops ran in the wrong order:

```
// first loop
peer.handshake = Handshake::None;      // cleared the handshake ...
// second loop
... self.peers[idx].handshake.session_id()  // ... so this now returned None
    -> free_session never called
```

So the stale session id was **never freed**; the map accumulated one dead entry
per retry. A type-2 response names, in its `receiver_id`, exactly which
outstanding initiation it answers. Because DERP relay + the peer's lazy-wireguard
wake make responses lag the 5 s retry cadence, a response answering an *earlier*
initiation still matched `peer_for_session(receiver_id)` (its id was leaked into
the map), routed to the live peer, and was fed to `finish()` -- which ran it
against the CURRENT (rotated) ephemeral. `finish()` never checked
`receiver_id == sent_handshake.id`, so the `ee`/`se` Diffie-Hellman inputs no
longer matched what the responder used: wrong derived key, failed empty-payload
AEAD tag = the live `aead::Error`, consistently.

`tools/wg_validator/validate_index_matching.py` reproduces this from spec,
independently of Rust: a response for session S1 (ephemeral E1) verifies when
finished against E1, and fails with `InvalidTag` when finished against a
different initiation's ephemeral E2 -- the exact on-device symptom.

### The fix (two parts, `tm_wg`)
1. `endpoint.rs::dispatch` -- capture the timed-out handshake's `session_id()`
   BEFORE clearing the handshake, and free it in the retry loop. The session map
   no longer leaks a dead entry per retry, so a late response to a rotated-out
   initiation is cleanly dropped as "unknown session" instead of being routed to
   a live peer.
2. `vendor/handshake.rs::finish` -- guard `packet.receiver_id ==
   sent_handshake.id` before any crypto. Defense-in-depth: even a duplicate or
   reordered response can no longer be run against the wrong ephemeral; a
   mismatch is rejected cleanly instead of failing the AEAD tag.

### New regression tests
- `tm_wg` unit test `retry_frees_stale_session_and_ignores_late_response`:
  drives two endpoints, forces a retry, and asserts (a) the session map does not
  leak the stale id (`session_count()` stays 1; was 2 before the fix -- verified
  RED), (b) a withheld response to the stale initiation does not complete a
  handshake, and (c) the response to the current initiation still completes.
- `tools/wg_validator/validate_index_matching.py`: the from-spec oracle above.

With the guard, a response arriving within a DERP RTT of the current initiation
(the common case once the peer's wireguard config is awake) matches and completes
`finish()` -> `PeerHandshook`; lagging responses to rotated-out initiations are
dropped instead of poisoning the schedule.

## Rung 5 REACHED live on-device (2026-09-17) + the completion-tail stack fix

With the index-matching fix above, a first Wokwi run got PAST the crypto but hit
a NEW fault: a `Guru Meditation ... Stack protection fault` in task `main`,
symbolized (riscv32-esp-elf-addr2line) to `SessionState::activate` called from
`WgEndpoint::recv_one_into`. This is decisive evidence the crypto fix worked: the
crash was NOT `aead::Error` but the handshake-COMPLETION tail. The AEAD-failing
path returned before `activate`, so only a SUCCESSFUL `finish()` reached it -- the
handshake now completes.

Root cause of the new fault: `SessionState::activate` returned an
`ArrayVec<Packet, OUT_CAP>` (~6 KB of inline `heapless` packet buffers) BY VALUE,
materialised on the caller's stack deep inside the tokio poll chain ->
boxed `on_inbound` future -> `recv_response` -> `finish` (Blake2s/HKDF). Same
class as the earlier `RecvOut`-by-value overflow; the outbound-only and
AEAD-failing rungs never exercised it. Fix: `activate` now writes its packets
into the caller's already heap-allocated `RecvOut::to_peer` (passed `&mut`) and
returns only the tiny freed-session-id list; the two callers (`recv_response`,
`recv_transport`) were updated and their stack `pkts`/`ka` temporaries removed.
Heap-neutral, no task-stack bump.

### Live serial evidence (single clean boot, no crash, ~56 s window)
```
tm_runtime: Runtime::join() - DERP connect -> region 11 (sao) host=derp11e.tailscale.com port=443 for peer lenovopill
tm_derp: DerpActor: DERP handshake complete with derp11e.tailscale.com   (24581 ms)
tm_runtime: WgEvent::OutboundPacket 148 bytes -> DERP peer 0e63..        (148-byte WG inits)
tm_derp: DerpActor: RecvPacket 92 bytes from 0e63..                      (29022 ms, peer's WG response)
tm_runtime: Runtime::join() - WgEvent::PeerHandshook with peer 0e63..    (31692 ms)  <-- RUNG 5
```
No `aead::Error`, no `Guru Meditation`, no reboot (1 boot in the whole log); the
device kept running and emitting outbound WG packets through ~53 s until the
Wokwi session was closed by the harness timeout. The ~2.7 s between the first
92-byte response and `PeerHandshook` is exactly the guard at work: responses to
rotated-out initiations are dropped until one answers the current initiation,
which completes. `0e63..` is the online peer `lenovopill` (region 11).

Rung 6 (inbound transport round-trip) was NOT reached in this window: no
`WgEvent::InboundDecrypted` was observed. Landing rung 5 cleanly is the honest
outcome here; rung 6 additionally needs the peer to send transport data toward
us and `tm_netstack`'s lwIP inbound injection (still a stub) to deliver it.

## Rung 6a: outbound transport elicitor implemented (live verification blocked on Wokwi quota)

Rung 6 (inbound transport round-trip) splits into two coupled halves:
- **6a** — drive an outbound transport payload so the peer replies, and observe
  the reply arrive as `WgEvent::InboundDecrypted`. This is a tm_wg/tm_runtime
  task: nothing in the firmware previously emitted transport data, so the peer
  never had anything to answer.
- **6b** — deliver the decrypted inbound IP packet into the on-device lwIP
  stack so a local socket receives it (`tm_netstack` is still a stub). Larger
  half; not started here.

### What 6a adds
- `WgEndpoint::send_data(dst_key, payload, now, out)` (`tm_wg/src/endpoint.rs`):
  encrypts a plaintext IP packet under the peer's active send session into
  `out.to_peer` (16-byte transport-data header prepended by `session::encrypt`),
  or queues it if no session is active yet (flushed on activation). Same
  heap-boxed `RecvOut` discipline as the rung-5 fixes — no by-value packet
  buffers on the ESP32-C3 main-task stack.
- `WgCmd::SendData { dst_key, payload }` + `WgActor::on_send_data`
  (`tm_wg/src/lib.rs`): routes an app-data payload through `send_data` and drains
  the ciphertext out as `WgEvent::OutboundPacket` for DERP relay.
- `tm_runtime` (`event_router_task`): captures `our_ip` and each peer's
  `tailnet_ip` from `MapUpdate`, and on `WgEvent::PeerHandshook` synthesizes an
  ICMP echo request (`build_icmp_echo_request`, RFC 1071 checksums) from our
  tailnet IP to the peer's and sends it via `WgCmd::SendData`. tailscaled's host
  kernel answers pings to its own tailnet address with no listening app, so the
  echo reply returns as an inbound transport packet -> `InboundDecrypted`.

### Offline verification (green)
- `tm_wg` unit test `send_data_encrypts_over_active_session_and_queues_without_one`:
  A encrypts an app-data payload over its active session, B decrypts it back to
  the *exact* plaintext; before a session exists the payload is queued and
  nothing hits the wire; an unknown peer key is a no-op. 23/23 tm_wg tests pass.
- `tools/wg_validator/validate_icmp_echo.py`: from-spec oracle; the synthesized
  28-byte packet has valid IPv4 + ICMP checksums and scapy parses it as a
  well-formed echo request (a real peer kernel will answer it).
- Firmware builds clean twice for `riscv32imc-esp-espidf` (flash bin produced).

### Live verification: BLOCKED (needs a human decision)
The Wokwi run to capture on-device serial could not execute:
```
API Error: You have used up your Free plan monthly CI minute quota.
```
This is a hard monthly Wokwi CI-minute cap, not a transient rate limit. Landing
6a *on-device* (the `WgEvent::InboundDecrypted N bytes from peer 0e63..` line)
needs one of: a Wokwi plan/quota with CI minutes available, a different Wokwi
token, waiting for the monthly reset, or a real ESP32-C3. The code + offline
oracles are in place; only the live serial confirmation is outstanding.

## Rung 6a on real ESP32-C3 hardware: heap-OOM reboot root-caused + fixed

Moving from Wokwi to a real ESP32-C3 (/dev/ttyACM0, .env.aj2004 tailnet)
surfaced a hard-fault the emulator never hit. The board reboot-cycled every
~22 s: WiFi -> control register -> MapUpdate -> DERP TLS connect (~19 s) ->
sent 148-byte WG inits -> **crash before any PeerHandshook**:

```
memory allocation of 12100 bytes failed
abort() was called at PC 0x420abd7f
... rst:0xc (RTC_SW_CPU_RST)
```

### Root cause: transient ~12 KB allocations vs a fragmented ~8 KB heap block
On real hardware the DERP TLS session + the live 8-peer netmap fragment the heap
so that, post-connect, `largest_internal_block` is only ~8-9 KB (measured:
`total_free=18888, largest_internal_block=9728` after `DerpTls::connect`), even
though total free is ~19 KB. Two per-call allocations exceeded that single
contiguous block:
1. `on_inbound` / `on_send_data`: `Box::new(RecvOut::default())`. `RecvOut` =
   `2 * OUT_CAP * ~1516 B`; with `OUT_CAP = 4` that is **~12100 B** — the exact
   failing size. Hit first, when the first inbound WG packet arrived.
2. `on_tick`: `Box::new(dispatch(..))`. `dispatch` returned
   `ArrayVec<(PeerId,Packet), MAX_PEERS=8>` ≈ **12160 B**, and `Box::new`
   allocates the full array every 100 ms tick regardless of how many entries are
   used. Would have failed on the first post-connect tick too.
Wokwi never hit this because its TLS/netmap left a larger contiguous block.

### Fix (tm_wg only; heap-shrinking, no stack change, no tasmolike-rs change)
- `OUT_CAP` 4 -> 2: `RecvOut` ~12.1 KB -> ~6 KB (fits the ~8 KB block). Our
  flows emit at most 1-2 packets per recv; a rare queue-flush+keepalive overflow
  is dropped by `try_push`.
- `dispatch` now returns `ArrayVec<_, DISPATCH_CAP=4>` (~6 KB) and stops
  collecting when full, leaving still-due peers' timers untouched so they are
  serviced on the next 100 ms tick. Nothing is lost.
- 23/23 tm_wg tests still pass.

### Verified live on hardware
After the fix: **single clean boot, zero reboots, zero OOM/abort**, board stable
through the full ~68 s capture (was crashing at ~22 s). The heap OOM is gone.

### Remaining blocker: no online peer on the .env.aj2004 tailnet
The netmap snapshot shows **all 8 peers `online=false`** (`raspill` derp_region=11
offline; the rest derp_region=0). We send WG inits over DERP every ~5 s but no
peer is connected to answer, so we never reach `PeerHandshook` (the rung-5
prerequisite) — hence no rung-6a echo either. This is a live-tailnet
availability issue, not a firmware fault. Observing rung 6a end-to-end needs an
**online** Tailscale peer on this tailnet at the time the board registers (the
control path uses a non-streaming MapRequest, so the peer should be up before
boot to appear online in the snapshot).

## Card t_e34afeed v1: online-only netmap + streaming-poll drain-and-discard (2026-09-17)

### Symptom (live, real HW)
With lenovopill (100.69.230.65) and bospill (100.85.218.10) confirmed online
on the tailnet, the board's netmap still didn't contain them: `tailscale
status` showed both up, but the board's parsed snapshot listed stale offline
peers instead. Root causes (both confirmed against `tools/wg_validator/`):

1. `map_serde::parse::<8, 4>` (map_serde.rs:108-134) stored the first 8 peers
   as they appeared in the server's `Peers` array, regardless of `Online`.
   The live tailnet has 12+ peers; the online ones didn't happen to be in the
   first 8, so they were dropped.
2. The streaming keepalive poll (`Stream:true`, MAP_STREAM_ID) desyncs its
   4-byte-LE length-prefix framing (`implausible message length 1953722184`,
   which is ASCII `"Host"` read as a little-endian u32) and the old code
   bailed with `return Ok(())`, orphaning the stream. Per
   `tools/wg_validator/ts_control.py`'s `start_keepalive_poll` docstring, the
   control server keeps a node marked online only while it keeps draining
   this stream; bailing likely made the board look offline to peers, so they
   wouldn't answer its WireGuard handshake even against an online peer.

### Python-first confirmation
`tools/wg_validator/validate_live_tailnet.py` (which already filters
`p.online` off the non-streaming write_map response) ran live against
`.env.aj2004`'s tailnet and printed:

```
[PASS] MapResponse parsed: our_ip=100.119.119.118, 12 peers, 3 online (non-self)
        online: lenovopill(derp11), alanjds-s25(derp11), bospill(derp11)
```

confirming (a) the non-streaming publish response carries per-peer
`Online=true` for the live online peers, and (b) the board's existing
`PeerR.online` field (serde `rename = "Online"`) is the right thing to filter
on — the field is already parsed correctly, just not used to filter.

### Fix 1 — online-only netmap (`tm_control/src/map_serde.rs`)
`parse()`'s peer loop now skips any peer with `Online != true` before the
existing `key`/`address` extraction, so the fixed-size `ArrayVec<_, MAX_PEERS>`
only ever holds reachable peers. An offline peer can't answer a WG handshake,
so it was dead weight that pushed out live peers under the MAX_PEERS=8 cap.
When a peer comes online later the streaming poll (or a future re-publish)
re-delivers its full record. An empty peer set when nobody is online is
correct behavior, not a bug. This also reduces steady-state peer storage
(~140 B/peer) since most tailnets have far fewer online peers than MAX_PEERS.
New unit test `map_serde::tests::only_online_peers_are_kept` pins this against
a 3-peer fixture (offline, online, and `Online` field absent).

### Fix 2 — streaming poll drain-and-discard (`tm_control/src/lib.rs`)
`stream_map_response` now takes note of which caller it's serving
(`let streaming = expected_stream == MAP_STREAM_ID;`) so it can tell the
one-shot non-streaming publish (MAP_PUBLISH_STREAM_ID, must still parse the
snapshot and return at `end_stream`) apart from the long-lived streaming
keepalive poll. On the length-prefix desync (`mlen > MAX_MAP_MSG`):

- non-streaming (publish): unchanged, still bails with `Ok(())` (this path
  isn't the one that desyncs in practice, and the snapshot must be trusted).
- streaming (poll): instead of returning, sets a `discarding` flag and keeps
  looping forever, reading H2 DATA frames, sending the proactive
  WINDOW_UPDATEs (already unconditional), and throwing away every payload
  byte without attempting to re-interpret it as a length prefix or body (once
  desynced, no later byte can be trusted as a frame boundary either). This
  keeps the HTTP/2 stream alive and drained from the server's point of view,
  which per ts_control.py is what keeps the node marked online, without
  reintroducing the ~2 GB `with_capacity` OOM the original cap guarded
  against. `end_stream` is still honored (returns `Ok(())`) whether or not
  discarding, since a real stream close from the server needs no more
  draining. v2 (actually parsing the streaming deltas so a peer that comes
  online after registration is picked up without a reflash) is out of scope
  for v1; see the card (t_e34afeed) comment for the staged plan.

### Tests
`cargo test -p tm_control` (25 -> passes incl. new test) and
`cargo test -p tm_wg` (23, unchanged) both green; no regression to the
publish-response path or heap budget (online-only filtering can only shrink
peer storage, never grow it).

## Bring-up timeout (Shape A — cooperative, no dedicated thread)

Card t_0d32f11d ("Board never stays online on tailnet") root-caused the
board never appearing on the dashboard: the app-side outer wrapper
(`tasmolike-rs::tailscale_rust`) wrapped its ENTIRE `Device::new(..)` call in
`tokio::time::timeout(60s, ..)`. On ESP32-C3, `Device::new` (via
`Runtime::join`) never returns while the actors run — `Runtime::join`'s
`tokio::join!` only resolves once every actor task ends, and the streaming
MapResponse poll (this doc's "Fix 2" above) is deliberately unbounded so the
control server keeps the ephemeral node marked online. So the wrapper's
timeout *always* eventually fires, even on a fully successful connection,
dropping the whole `Runtime::join` future — every actor with it — which
closes the control connection and gets the ephemeral node garbage-collected
off the tailnet. That is why rung-6a (handshake + round-trip) succeeded in
testing yet the board never showed up: the timeout fired sometime after
success, not before it.

The owner's chosen fix (Shape A, rejecting a dedicated ~32 KB
`std::thread::spawn` "Shape B") is that **the connect deadline moves inside
`tm_control`, and only bounds bring-up** — never the streaming poll:

- `tm_control::Config` gains `connect_timeout: Option<Duration>`.
  `tm_runtime::RuntimeConfig` gains the same field and copies it into
  `config.control.connect_timeout` right before actor construction in both
  `Runtime::join` and `Runtime::spawn`. `tailmicro::Config` gains a
  `.with_connect_timeout(Duration)` builder mirroring
  `.with_control_pin_hex(..)`, plumbed through `Device::new`.
- `ControlActor::connect_and_poll` is split into `bring_up` (TCP + Noise +
  register + the non-streaming publish MapRequest + its parse — i.e.
  everything through `OurIpAssigned`) and the streaming poll that follows.
  `connect_and_poll` wraps ONLY the `bring_up` call in
  `tokio::time::timeout(dur, ..)` when `connect_timeout` is `Some`; with
  `None` it calls `bring_up` directly, no deadline. The streaming
  `stream_map_response(.., MAP_STREAM_ID)` call after it is never wrapped in
  anything.
- On a bring-up timeout, `connect_and_poll` returns
  `Err(ControlError::Timeout)` (new variant), which `ControlActor::run`'s
  existing error path turns into `events.send(ControlEvent::Error(..))` and
  a clean return from `run` — no streamer was ever constructed at that
  point, so there is nothing to tear down beyond dropping the half-open
  connection.
- `tm_control`'s main `tokio` dependency gained the `"time"` feature (it was
  previously `sync`/`io-util`/`net` only — `time` was dev-deps-only, used by
  host examples, not by the shipped crate). `tokio::time::timeout` needs the
  runtime's time driver; `Builder::enable_all()` (already the documented
  guidance in `src/lib.rs`'s module doc and `examples/udp_echo/main.rs`) or
  an explicit `.enable_time()` covers this. **The actual esp-idf
  `tokio::runtime::Builder` is constructed in the sibling app
  (`tasmolike-rs`), not in this repo** — that app's real `main`/`app_main`
  runtime construction must confirm `.enable_time()` (or `.enable_all()`) is
  set, or `tokio::time::timeout` will panic ("there is no timer running")
  instead of firing.
- The readiness signal the wrapper should await instead of an external
  timeout already existed and is unchanged: `RuntimeConfig.our_ip_tx`, fired
  by the event router on `ControlEvent::OurIpAssigned` (emitted from the
  non-streaming publish parse, before the streaming poll starts). Verified
  intact end-to-end for this change.
- No retry logic on bring-up timeout — that's an explicitly deferred v2
  follow-up (card t_0d32f11d comment "CHOSEN DESIGN").

### New tests (`tm_control/src/lib.rs`, `mod tests`)
Both host-only, against a local `TcpListener` stand-in for the control
server (no real Noise/H2 handshake needs to complete — bring-up just needs
to hang long enough for the deadline to matter):
- `bring_up_timeout_emits_error_and_returns`: a listener that accepts but
  never answers, `connect_timeout: Some(50ms)` — asserts
  `ControlEvent::Error(ControlError::Timeout)` and that `run()` returns
  within an outer 5s bound (i.e. it doesn't hang past the deadline).
- `none_connect_timeout_disables_deadline`: `connect_timeout: None` against
  a closed port (fails fast, connection refused) — asserts the resulting
  `ControlEvent::Error` is never `ControlError::Timeout`.

### Wrapper-side change needed (sibling app, not in this repo)
`tasmolike-rs::tailscale_rust` must delete its external
`tokio::time::timeout(60s, Device::new(..))` wrapper — it is what was
killing the node — and instead pass `connect_timeout` into
`tailmicro::Config` and await the `our_ip` readiness signal out-of-band, so
the long-running device future is never raced against a dropping timeout.
See the implementation report on card t_0d32f11d for the concrete patch
text (not applied here; out of this repo's scope per the card).
