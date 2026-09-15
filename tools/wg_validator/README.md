# `tm_wg` WireGuard reference validator

An **independent, from-spec** Python oracle for the `tm_wg` WireGuard data
plane. It is written against the WireGuard whitepaper
(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) and the byte-offset tables in
`docs/wg-dataplane-implementation-plan.md` Part 2, deliberately **not** by
mirroring the Rust code, so it can catch a wire-format/crypto bug that would
be uniformly wrong on both the Rust encode and decode side (which a Rust
self-round-trip test cannot).

Primitives: `cryptography` (X25519, ChaCha20Poly1305) and `hashlib.blake2s`.
HKDF, HChaCha20, the MAC1/MAC2 machinery, and the whole Noise IKpsk2 state
machine are hand-rolled in `wg_spec.py`. No Noise/WireGuard library is used.

## Files

- `wg_spec.py`: the independent from-spec implementation (importable).
- `validate_offline.py`: **rung 1**: runs the real `tm_wg` core via
  `cargo run --example wg_emit_vectors` (+ `wg_cookie_probe`) and asserts
  byte-for-byte equality for Initiation / Response / Cookie / Transport, the
  MAC1/MAC2 domains, the TAI64N encoding, and the full bidirectional key
  schedule. No network.
- `validate_live_boringtun.py`: interop: drives the from-spec Python
  initiator through a full handshake + bidirectional transport exchange against
  **boringtun** (Cloudflare's independent Rust WireGuard), in memory over
  loopback UDP. Validates the oracle against a genuinely independent third
  implementation.
- `boringtun_peer/`: a tiny detached-workspace Rust crate that runs boringtun
  as a responder for the interop test.

The Rust side of the oracle lives in `tm_wg/examples/wg_emit_vectors.rs` and
`tm_wg/examples/wg_cookie_probe.rs`, reached via the documented deterministic
ephemeral seam in `tm_wg/src/vendor/handshake.rs`.

## Running

`cryptography` is pulled ephemerally via `uv`:

```sh
# Rung 1: offline byte-level oracle (no network):
uv run --with cryptography python3 tools/wg_validator/validate_offline.py

# Interop vs. boringtun (loopback UDP, no root/tun, no network):
#   boringtun 0.6 pins curve25519-dalek 4.0.0-rc.3, which needs the serial
#   backend on current nightly; keep the build target out of the repo.
CARGO_TARGET_DIR="$(mktemp -d)" \
  uv run --with cryptography python3 tools/wg_validator/validate_live_boringtun.py
```

Both scripts print a PASS/FAIL table and exit non-zero on any failure.

## Status / limits

- **Rung 1 (offline byte-level): PASS, byte-for-byte, no discrepancy found.**
- **boringtun interop: PASS** (handshake + transport, both directions).
- **NOT run against the live Tailscale tailnet.** A real handshake to a real
  Tailscale peer needs a DERP relay client (peers are NAT'd) plus an
  independent ts2021 control-plane client to fetch peers; that was out of
  scope for this pass. The control endpoint is live and reachable (blocker is
  implementation scope, not access). See `docs/wg-dataplane-notes.md`.

The scalars in the emitters/scripts are fixed **test constants**, not secrets.
No secret key material or Tailscale auth key is printed or committed.
