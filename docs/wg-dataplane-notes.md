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
