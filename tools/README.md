# tools/gen_fingerprint.py

Generates a signed "control-key pin" blob for the control-key-pinning PoC.

## What it does

1. Fetches the real Tailscale control server's Noise public key with
   `GET https://<host>/key?v=<cap>` over normal, fully X.509-validated
   HTTPS. This is the one remaining place in the whole system that does
   certificate-chain validation, and it happens here: off-device, once, by
   a human running this script.
2. Loads (or creates) a local Ed25519 signing key.
3. Signs `(magic, version, pubkey, not_after)` into a 109-byte blob,
   self-verifies it, and prints it hex-encoded.

## How to run it

```
pip install cryptography
python3 gen_fingerprint.py
```

Useful flags: `--host`, `--cap`, `--key-file`, `--expiry-days`, `--insecure`
(self-hosted/Headscale testing only), `--dump-raw` (debug), `--pubkey-hex`
(skip the network fetch and use a supplied 32-byte hex pubkey, for offline
test fixtures). Run `python3 gen_fingerprint.py --help` for the full list.

## Where the two printed outputs go

- `pub const PIN_VERIFY_KEY: [u8; 32] = [...];` -> paste into
  `tm_control/src/pin.rs` (not created yet -- that happens in a later step
  of the control-key-pinning plan).
- `export TAILMICRO_CONTROL_PIN=<hex>` -> paste into tasmolike-rs's
  `.env.wokwi` / build env (also a later step there; it gets picked up by
  `build.rs` and baked into the firmware via `env!()`).

## The signing seed is secret

The signing-seed file (`tm_signing_key.bin` by default, overridable via
`--key-file`) is the private key that lets you mint pins your devices will
trust. It is saved with restrictive permissions on creation, and it is
listed in this repo's `.gitignore`. Never commit it, even for a PoC --
anyone who obtains it can sign a pin pointing devices at an attacker's
control key.
