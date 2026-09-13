#!/usr/bin/env python3
"""Generate a signed control-key pin blob for the control-key-pinning PoC.

This script performs the one-time, off-device, X.509-validated fetch of the
real Tailscale control server's Noise public key (GET /key over normal
validated HTTPS, using Python's urllib/ssl with default certificate
verification). This one fetch is the entire remaining reason X.509
certificate validation exists anywhere in this system: it happens here,
off-device, once, by a human running this script. Everything downstream of
it (the ESP32 firmware, the control connection itself) never validates a
certificate chain again.

The script then signs (magic, version, pubkey, not_after) with a local
Ed25519 signing key, producing a 109-byte blob, self-verifies that blob
before printing anything, and prints:

  - a human-readable comment block (control host, fetched key, expiry),
  - a Rust `pub const PIN_VERIFY_KEY: [u8; 32] = [...]` line, for pasting
    into tm_control/src/pin.rs in a later step (that file does not exist
    yet; this script does not create it), and
  - an `export TAILMICRO_CONTROL_PIN=<hex>` line, for pasting into a
    tasmolike-rs .env file (a later step there wires it into build.rs).

The device only ever performs one Ed25519 signature verification against the
embedded PIN_VERIFY_KEY at startup; it never validates a certificate chain
and never talks TLS to the control server. This script is a stand-in for a
future server that will serve the same signed blob at `GET /fingerprint`
over plain HTTP -- this PoC does that fetch+sign step by hand, offline.

Blob layout (109 bytes total):
    magic       4 bytes   b"TMPN"
    version     1 byte    0x01
    pubkey      32 bytes  the control server's Noise static public key
    not_after   8 bytes   little-endian u64 unix seconds
    signature   64 bytes  Ed25519 signature over the preceding 45 bytes

Dependencies: only the `cryptography` package (pip install cryptography)
plus the Python standard library.

Usage:
    python3 gen_fingerprint.py
    python3 gen_fingerprint.py --host controlplane.tailscale.com --cap 110
    python3 gen_fingerprint.py --pubkey-hex <64 hex chars>   # offline, no fetch
    python3 gen_fingerprint.py --insecure                    # self-hosted/Headscale testing only
"""

import argparse
import json
import os
import ssl
import stat
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAGIC = b"TMPN"
VERSION = 1
BODY_LEN = len(MAGIC) + 1 + 32 + 8  # 45
BLOB_LEN = BODY_LEN + 64  # 109
DEFAULT_HOST = "controlplane.tailscale.com"
DEFAULT_CAP = 110
DEFAULT_KEY_FILE = "tm_signing_key.bin"
DEFAULT_EXPIRY_DAYS = 35


def fetch_control_pubkey(host: str, cap: int, insecure: bool, dump_raw: bool) -> bytes:
    """Fetch the control server's Noise public key over validated HTTPS.

    This is the one X.509-validated network call in the whole system. It is
    made off-device, once, by whoever runs this script -- never by firmware.
    """
    url = f"https://{host}/key?v={cap}"
    if insecure:
        ctx = ssl._create_unverified_context()
        sys.stderr.write(
            "WARNING: --insecure disables certificate verification. "
            "Only use this against a self-hosted/Headscale control server "
            "you already trust by other means.\n"
        )
    else:
        ctx = ssl.create_default_context()  # default cert verification, as documented above

    with urllib.request.urlopen(url, context=ctx, timeout=15) as resp:
        raw = resp.read()

    if dump_raw:
        sys.stderr.write(f"--- raw /key response from {url} ---\n")
        sys.stderr.write(raw.decode("utf-8", errors="replace"))
        sys.stderr.write("\n--- end raw response ---\n")

    data = json.loads(raw)
    pubkey_field = data["publicKey"]
    prefix = "mkey:"
    if not pubkey_field.startswith(prefix):
        raise ValueError(f"unexpected publicKey format: {pubkey_field!r}")
    hex_part = pubkey_field[len(prefix):]
    pubkey = bytes.fromhex(hex_part)
    if len(pubkey) != 32:
        raise ValueError(f"expected 32-byte control pubkey, got {len(pubkey)} bytes")
    return pubkey


def load_or_create_signing_key(key_file: str) -> Ed25519PrivateKey:
    """Load a cached 32-byte Ed25519 seed, or create and cache a new one."""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            seed = f.read()
        if len(seed) != 32:
            raise ValueError(
                f"{key_file} does not contain a 32-byte Ed25519 seed "
                f"(got {len(seed)} bytes) -- delete it to regenerate, "
                "or point --key-file elsewhere"
            )
        return Ed25519PrivateKey.from_private_bytes(seed)

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    with open(key_file, "wb") as f:
        f.write(seed)
    try:
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)  # 0600, best-effort
    except OSError:
        pass
    sys.stderr.write(
        f"Generated new signing key seed at {key_file!r}. "
        "This file is SECRET: it must never be committed to git, even for "
        "a PoC. Anyone holding it can mint pins your devices will trust.\n"
    )
    return key


def build_blob(pubkey: bytes, not_after: int, signing_key: Ed25519PrivateKey) -> bytes:
    body = MAGIC + bytes([VERSION]) + pubkey + not_after.to_bytes(8, "little")
    assert len(body) == BODY_LEN
    signature = signing_key.sign(body)
    assert len(signature) == 64
    blob = body + signature
    assert len(blob) == BLOB_LEN
    return blob


def self_verify(blob: bytes, verify_key: Ed25519PublicKey) -> None:
    """Verify the blob we just built before ever printing it.

    Never emit a blob that doesn't self-verify: that would be a bug in this
    script, not a legitimate PoC output.
    """
    if len(blob) != BLOB_LEN:
        raise AssertionError(f"internal error: blob has wrong length {len(blob)}")
    body, signature = blob[:BODY_LEN], blob[BODY_LEN:]
    try:
        verify_key.verify(signature, body)
    except InvalidSignature as e:
        raise AssertionError(
            "internal error: freshly built blob failed self-verification -- "
            "this is a bug in gen_fingerprint.py, not a legitimate output"
        ) from e


def rust_const(verify_pubkey_bytes: bytes) -> str:
    values = ", ".join(f"0x{b:02x}" for b in verify_pubkey_bytes)
    return f"pub const PIN_VERIFY_KEY: [u8; 32] = [{values}];"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch/sign a control-key pin blob for the control-key-pinning PoC.",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"control server host (default: {DEFAULT_HOST})")
    parser.add_argument("--cap", type=int, default=DEFAULT_CAP, help=f"Tailscale-Cap-Version to request (default: {DEFAULT_CAP})")
    parser.add_argument("--key-file", default=DEFAULT_KEY_FILE, help=f"path to cached Ed25519 signing seed (default: {DEFAULT_KEY_FILE})")
    parser.add_argument("--expiry-days", type=int, default=DEFAULT_EXPIRY_DAYS, help=f"days until not_after (default: {DEFAULT_EXPIRY_DAYS})")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (self-hosted/Headscale testing only)")
    parser.add_argument("--dump-raw", action="store_true", help="print the raw /key HTTP response body to stderr")
    parser.add_argument("--pubkey-hex", default=None, help="skip the network fetch; use this 32-byte hex control pubkey instead (for offline test fixtures)")
    args = parser.parse_args()

    if args.pubkey_hex is not None:
        pubkey = bytes.fromhex(args.pubkey_hex)
        if len(pubkey) != 32:
            parser.error(f"--pubkey-hex must decode to exactly 32 bytes, got {len(pubkey)}")
        source_desc = "offline (--pubkey-hex)"
    else:
        pubkey = fetch_control_pubkey(args.host, args.cap, args.insecure, args.dump_raw)
        source_desc = f"https://{args.host}/key?v={args.cap}"

    signing_key = load_or_create_signing_key(args.key_file)
    verify_key = signing_key.public_key()
    verify_key_bytes = verify_key.public_bytes_raw()

    not_after = int(datetime.now(timezone.utc).timestamp()) + args.expiry_days * 86400
    blob = build_blob(pubkey, not_after, signing_key)
    self_verify(blob, verify_key)  # hard fail (raises) if this ever doesn't hold

    not_after_iso = datetime.fromtimestamp(not_after, tz=timezone.utc).isoformat()
    blob_hex = blob.hex()

    print(f"# control host / source: {source_desc}")
    print(f"# control pubkey: mkey:{pubkey.hex()}")
    print(f"# not_after: {not_after} unix seconds ({not_after_iso})")
    print(f"# blob length: {len(blob)} bytes ({len(blob_hex)} hex chars)")
    print("#")
    print("# Paste into tailmicro-rs/tm_control/src/pin.rs (PIN_VERIFY_KEY):")
    print(rust_const(verify_key_bytes))
    print("#")
    print("# Paste into tasmolike-rs .env / .env.wokwi:")
    print(f"export TAILMICRO_CONTROL_PIN={blob_hex}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
