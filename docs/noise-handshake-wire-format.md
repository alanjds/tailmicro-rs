# ts2021 Noise handshake: real wire format vs. what we had implemented

## Summary

`tm_control::noise::do_noise_handshake` implemented the HTTP-level framing
correctly (POST `/ts2021`, `X-Tailscale-Handshake` header, no body) but was
missing two things the real Tailscale control protocol requires *inside*
that header's base64 payload and in the Noise handshake state itself. Both
were needed together before any real handshake would succeed:

1. **Missing Noise prologue.** The real protocol mixes
   `"Tailscale Control Protocol v" + <cap_version>` (ASCII, decimal) into the
   Noise hash state via `MixHash` immediately after `Initialize()`, before
   the IK pre-message (`MixHash(responder_static_key)`). Our `snow::Builder`
   never called `.prologue(...)`, so it used an empty prologue. This makes
   the initiator's and responder's hash states diverge from the very first
   step, so every later `EncryptAndHash`/`DecryptAndHash` call (which uses
   the hash state as AEAD associated data) authenticates against a different
   value than the server computes — the server's decryption of our encrypted
   static key fails silently and it drops the connection. No error is ever
   sent back; there's nothing to catch on our side except a naked EOF.

2. **Missing 5-byte/3-byte message framing.** The base64 payload in
   `X-Tailscale-Handshake` is not the bare 96-byte Noise message. It's a
   101-byte `initiationMessage` (Tailscale's `control/controlbase/messages.go`):
   - 2 bytes: protocol/cap version, big-endian
   - 1 byte: message type (`0x01` = initiation)
   - 2 bytes: payload length, big-endian (= 96)
   - 96 bytes: the actual Noise IK message (32-byte ephemeral pubkey + 48-byte
     encrypted static key + 16-byte payload tag)

   The server's reply is similarly wrapped: a 3-byte header (1-byte type,
   `0x02` = response; 2-byte big-endian length = 48) followed by the 48-byte
   Noise response message. Our code read the bare 48 bytes directly (modulo
   an EarlyNoise-magic-byte check that never fires against this server), so
   it was trying to Noise-decrypt a buffer that started 3 bytes into the
   real message.

Neither bug alone explains the symptom fully; both needed fixing together.
Cap version: `72` (the value `tm_control::CAPABILITY_VERSION` already used,
chosen elsewhere in this codebase to avoid dealing with `PeerChangesDelta`)
works fine for the handshake — the real current `tailcfg.CurrentCapabilityVersion`
upstream is `147` as of this writing, but the server accepts lower supported
versions too, and this codebase intentionally targets an older, simpler
capability contract, so `CAPABILITY_VERSION` was left at `72` rather than
bumped.

## Symptom (what made this hard to find)

Every test setup — the ESP32-C3 under Wokwi, a direct host-native TCP
connection, `do_noise_handshake` called in complete isolation, and a local
Python MITM proxy relaying byte-for-byte to the real server — hit the exact
same failure: the server replies `HTTP/1.1 101 Switching Protocols`, then
closes the connection immediately (`UnexpectedEof: "early eof"`) while we're
trying to read the Noise response. This looked at first like a Rust-specific
networking bug (buffering, TCP flags, async I/O quirk) because:

- A garbage handshake payload of the same length produced the identical
  101-then-close behavior, which seemed to prove content didn't matter — but
  a Noise responder that fails decryption for *any* reason (garbage or a
  subtly-wrong-but-plausible message) just silently drops the connection.
  That test only proved the 101 response is dispatched on header presence
  alone, not that the failure was content-independent.
- Both TLS/443 and plaintext/80 failed identically, which seemed to rule out
  a plaintext-specific issue — true, but for the wrong reason (both lacked
  the same two fixes, so of course they behaved the same).
- The control server's pinned Noise static key (verified via
  `tm_control::pin`) exactly matched the live key returned by
  `GET /key?v=<cap>` at the time of testing, ruling out a stale pin.

## How it was actually root-caused

A minimal, from-spec Noise_IK_25519_ChaChaPoly_BLAKE2s implementation was
written in Python (`cryptography` + `hashlib.blake2s`, no Noise library
available/installable in the sandbox) as an independent reference, and used
to send a genuinely valid handshake message against the live server,
decrypting its real response to prove success end-to-end — rather than just
checking for a `101` status, which earlier ad hoc `curl`/socket tests had
mistaken for "success" without ever completing the round trip. Once that
Python reference completed a full handshake (decrypted the server's message
2 with a valid AEAD tag) on both port 80 and port 443, the exact byte-level
differences from our Rust implementation were directly comparable, which is
what surfaced the prologue and framing gaps above. Cross-checked against the
real `tailscale/tailscale` Go source (`control/controlbase/handshake.go`,
`control/controlbase/messages.go`) to confirm both findings against ground
truth rather than trial and error.

## Follow-up: transport-phase framing and nonce endianness

Fixing the handshake above got past the Noise IK exchange, but registration
then failed with a raw `Connection reset by peer` while reading the
response. Cross-checked against the *official Rust reference implementation*
(`github.com/tailscale/tailscale-rs`, specifically its `ts_control_noise`
crate - locally available at `~/src/tailscale-rs`, our own fork with
`~/src/tailscale-rs_upstream` kept alongside as the pristine tracking
checkout), which independently confirmed two more real bugs, both again in
`tm_control/src/noise.rs`'s `NoiseChannel`:

1. **Wrong post-handshake wire framing.** `NoiseChannel` used a bare 2-byte
   big-endian length prefix for transport-mode (`Record`) messages. The real
   protocol wraps every post-handshake message the same way as the handshake
   response: a 3-byte header (1-byte type - `0x04` for `Record`, `0x03` for
   an unauthenticated `Error` message - + 2-byte big-endian length). Sending
   without the type byte meant the server read our length's high byte as an
   invalid message type and reset the connection outright - this explains
   the raw TCP reset rather than a decrypt failure.
2. **Wrong nonce endianness in the transport cipher.** `snow::TransportState`
   uses the Noise spec's default little-endian nonce encoding. The real
   ts2021 transport cipher uses **big-endian** nonces (confirmed in
   `ts_control_noise::cipher::ChaCha20Poly1305BigEndian`, whose entire reason
   for existing - per its own doc comment - is this exact deviation).
   `snow::TransportState` has no way to override this, so `tm_control` now
   takes the raw split keys via `dangerously_get_raw_split()` (an explicit,
   `risky-raw-split`-feature-gated snow API for exactly this situation) and
   drives `chacha20poly1305::ChaCha20Poly1305` directly with a big-endian
   nonce, matching the reference.

There's also a third, related piece: an optional **post-handshake challenge
packet** - magic `\xFF\xFF\xFF 'T' 'S'` + 4-byte big-endian length + JSON
(`{"nodeKeyChallenge": "chalpub:..."}`), sent as the server's first
already-encrypted `Record` message, before any real HTTP/2 traffic. This is
a different layer than the pre-handshake "EarlyNoise" concept `noise.rs`
already handled (that one is cleartext, before the Noise response message).
Both the official Go and Rust clients skip it unconditionally; `tm_control`
now does the same (`NoiseChannel::skip_challenge_packet`).

All three were verified with the same from-spec Python approach: extended
the Python Noise IK reference with a matching transport codec (big-endian
nonce, 3-byte Record framing), sent a minimal HTTP/2 client preface as the
first Record after a real handshake, and confirmed the server replied with
a real challenge packet (successfully decrypted, readable JSON) instead of
resetting the connection - before porting any of this into Rust.

Ported into `tm_control`, this gets the handshake and transport layer fully
working end-to-end against the live server: `host_handshake.rs` now reaches
real HTTP/2-level traffic (a `GoAway` from the h2 crate on the registration
request) instead of failing anywhere in the Noise/transport plumbing. The
`GoAway` is a distinct, later-stage bug (something about how the register
request itself is built), tracked separately.

## Follow-up: two H/2-layer bugs behind the same `GoAway`

The `GoAway { error_code: 1 }` (PROTOCOL_ERROR) turned out to have two
independent causes in `tm_h2`/`tm_control`, found one at a time using the
same Python-first approach (a real `h2` library client driven over the
already-validated Noise transport, `h2_register_test.py` and its variants).

1. **Hardcoded `:path`.** `tm_h2::write_map_request_headers` always wrote
   `/ts2021` (the *upgrade* path) as the HEADERS frame's `:path`, ignoring
   the actual endpoint (`/machine/register`, `/machine/map`) the caller
   wanted. Sending a correctly-pathed request via the `h2` library over the
   validated transport got a normal response (`:status 500`) instead of a
   `GoAway`, confirming this. Fixed by adding a `path: &[u8]` parameter and
   threading it through from `build_h2_post`. **This fix alone was not
   sufficient** — re-testing against the live server after porting it to
   Rust still produced the identical `GoAway`, which is what led to bug 2.
2. **`SETTINGS_MAX_FRAME_SIZE` below the RFC 7540 minimum.**
   `tm_h2::write_settings` advertised `SETTINGS_MAX_FRAME_SIZE = 4096`.
   RFC 7540 SS6.5.2 fixes the legal range for this setting at
   `2^14..=2^24-1` (16384..=16777215) and mandates that a peer treat any
   value outside that range as a connection-level PROTOCOL_ERROR — which is
   exactly the `GoAway { error_code: 1 }` seen, sent immediately after our
   SETTINGS frame, before the server ever looked at the HEADERS/DATA that
   followed. This was not caught by the `path`-fix Python test because that
   test used the `h2` library's own `initiate_connection()`, which sends
   spec-compliant default settings — it never replicated `tm_h2`'s actual
   (invalid) SETTINGS bytes. Root-caused by building a Python test that
   sends a byte-for-byte reproduction of `tm_h2::write_settings`'s frame as
   its own Record ahead of the HEADERS/DATA: with `MAX_FRAME_SIZE=4096` the
   live server sent `ConnectionTerminated error_code:1` right after the
   SETTINGS record (matching the Rust symptom exactly); with
   `MAX_FRAME_SIZE=16384` the same script got a real `:status 500` response.
   Fixed by raising `tm_h2::MAX_FRAME_SIZE` to `16384`. Frame buffers in
   `tm_control` are heap `Vec<u8>`s sized per received frame, not fixed-size
   stack arrays, so this costs nothing unless the server actually sends a
   frame that large.

**Lesson for future Python-first bisection**: a reference script must
replicate the actual bytes the Rust code sends for *every* frame in the
sequence under test, not just the one frame believed to be buggy — reusing
a well-behaved library's defaults for "the rest" of the exchange can hide a
second bug (as it did here for one iteration).

## Follow-up: RegisterRequest's always-empty `OldNodeKey` field

With both H/2 bugs above fixed, `host_handshake.rs` reached
`Json(ParseError)` on the registration response — even with a real
`TAILSCALE_AUTH_KEY` from `.env`, not just the earlier placeholder one. The
server was still replying `500 Internal Server Error` (plain text, not
JSON), so parsing it as `RegisterResponse` correctly failed; the real bug
was upstream of that, in what we sent.

`tm_control`'s `RegisterRequest.old_node_key` was a bare `&str`, always
serialized as `"OldNodeKey":""` (no key rotation ever in progress in this
codebase). Root-caused in Python: extended the real-auth-key `h2` test to
print the exact JSON body sent and vary it field-by-field against the live
server. Two things needed fixing together to get an actual `200`:

1. **`"OldNodeKey":""` must be omitted, not sent empty.** The control
   server's Go-side type for this field is `key.NodePublic`, whose
   `UnmarshalText` requires either the field be entirely absent/null or a
   real `"nodekey:<64 hex chars>"` value — an empty string fails to parse
   and (apparently, based on observed behavior) surfaces as a generic `500`
   rather than a `400`. This matches the official Rust client's own
   `Option<NodePublicKey>` type with a serde skip-if-default annotation for
   this exact field (`ts_control_serde::register::RegisterRequest`) — our
   plain-`&str` port had dropped the "optional" part.
2. **`NodeKey` must be a real, non-all-zero key.** An earlier isolated
   Python test that used `"nodekey:" + "00"*32` (an all-zero placeholder)
   still got `500` even after fixing bug 1 above; switching to a real random
   32-byte key got a real `200` with a genuine JSON `RegisterResponse` body.
   This particular sub-case doesn't need a Rust-side fix: `tm_control`
   already uses `NodeState::generate()`'s real key, never an all-zero
   placeholder, in the actual (non-test) code path — it only mattered for
   correctly interpreting the Python isolation test.

Fixed by changing `RegisterRequest::old_node_key` to `Option<&str>` with
`#[serde(skip_serializing_if = "Option::is_none")]`, and passing `None` from
`connect_and_poll` (`tm_control` has no node-key-rotation logic yet, so this
is always `None` for now — revisit when rotation is implemented).

**Caution for future live verification against the real auth key**: each
successful registration attempt with a fresh random node key creates a real
device entry in the account's tailnet (or consumes a reusable key's use
count). Prefer a single confirming run per fix rather than repeated retries,
and check `https://login.tailscale.com/admin/machines` afterwards to clean
up any throwaway `esp32c3` test devices this creates.

## Follow-up: truncated NodeKey hex and wrong Hostinfo.OS field name

Fixing `OldNodeKey` above still wasn't enough: `host_handshake.rs` kept
getting `500 Internal Server Error` even with a real `TAILSCALE_AUTH_KEY`.
Added temporary `tracing::debug!` logging of the exact JSON request/response
bytes (rather than writing another Python isolation test - the bug was
visible directly in the Rust-side request body once logged) and found two
more bugs in the same request:

1. **`NodeKey` was silently truncated to 30 bytes (60 hex digits) instead
   of 32 (64 hex digits).** `tm_keys`'s `{Node,Machine,Disco}PublicKey::to_hex()`
   built the hex string into a `heapless::String<68>`, but `"nodekey:"` (8
   bytes) + 64 hex digits = 72 bytes - already over capacity before the
   `discokey:` (9-byte prefix, 73 bytes total) and `mkey:` (5-byte prefix,
   69 bytes total) variants are even considered. `heapless::String::push_str`
   and the `core::fmt::write` calls used per-byte both return `Result` and
   were called with `let _ =` / `.ok()`, silently discarding the overflow
   error instead of failing loudly - so the string just stopped 4 hex digits
   short of a full key with no visible error anywhere except a subtly wrong
   value on the wire. This is exactly the kind of bug the project's own
   "no `unwrap_or`/`.ok()`/`let _ =` swallowing a real error" review habit
   exists to catch; it slipped through because `heapless::String::push_str`'s
   failure mode is silent truncation, not a panic. Fixed by raising the
   capacity to 80 (comfortably over the worst case, `discokey:` + 64 hex =
   73) for all three `to_hex()` methods.
2. **`Hostinfo.OS` was serialized as `"Os"`, not `"OS"`.** The real Go
   struct field is `tailcfg.Hostinfo.OS` (all-caps, no explicit JSON tag
   needed on the Go side since the field name itself is `OS`). Rust's
   `#[serde(rename_all = "PascalCase")]` on a lowercase `os` field produces
   `"Os"` (only the first letter is capitalized), not `"OS"` - PascalCase
   doesn't know this particular abbreviation should stay fully capitalized.
   Fixed with an explicit `#[serde(rename = "OS")]` on that one field.

Both were live-verified fixed via the debug logging (not yet a full
end-to-end registration success at the time of writing - see the Rust
change's commit message for the actual outcome of the next live run).

With all of the above fixed and a fresh, valid reusable auth key, a live run
achieved a **full successful registration**: the server returned
`MachineAuthorized: true` for a real node in the account's tailnet. This is
the first point in the project where a real Tailscale device registration
has been completed end-to-end from this codebase.

## Follow-up: hardcoded stream ID 1 broke the second (map) request

Registration succeeding immediately surfaced the next bug: proceeding to
`/machine/map` failed with `H2(UnexpectedStream(3))`.

`tm_h2::parse_frame` hardcoded `if hdr.stream_id != 1`, and
`tm_control::stream_map_response`'s proactive stream-level `WINDOW_UPDATE`
hardcoded stream `1` too. Both were fine as long as the map poll was the
*only* request ever made on a connection (the module's original one-stream
design assumption) - but `connect_and_poll` actually sends **two** requests
over the same connection: `/machine/register` on stream 1, then
`/machine/map` on stream 3. Per RFC 7540 SS5.1.1, each new client-initiated
HTTP/2 request must use its own, incrementing odd stream ID - stream IDs
are not reusable - so the map response's DATA frames correctly arrived on
stream 3, and our hardcoded `1` check rejected every one of them.

Not re-verified in Python first: this is a pure client-side bookkeeping bug
(which stream ID our own code expects), not a question of server behavior -
the "new request needs a new stream ID" rule is exactly what the Python `h2`
library already did automatically (via `get_next_available_stream_id()`) in
every earlier reference script, so there was nothing left to discover
end-to-end against the real server that wasn't already established.

Fixed by adding an `expected_stream: u32` parameter to
`tm_h2::parse_frame`, and named `REGISTER_STREAM_ID = 1` /
`MAP_STREAM_ID = 3` constants in `tm_control`, threaded through
`read_one_h2_body`, `build_h2_post`'s two call sites, and the map-response
loop's `WINDOW_UPDATE`.

## Process note

Going forward, when a new protocol-level roadblock turns up, prototype the
fix in a throwaway Python script against the real server first, confirm it
actually works end-to-end (not just "got further than before"), and only
then port the confirmed-correct behavior into `tm_control`. This is faster
than iterating in Rust (host-native `cargo run --example` still needs a
recompile per attempt) and, more importantly, decouples "is the protocol
understanding correct" from "did the Rust port introduce a mistake" —
this bug took multiple Wokwi-quota-burning cycles to even get investigated
correctly, whereas the actual root cause took a handful of Python attempts
once approached this way.
