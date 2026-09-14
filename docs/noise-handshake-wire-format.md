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
