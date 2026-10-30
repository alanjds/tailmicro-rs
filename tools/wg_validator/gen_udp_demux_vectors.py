"""Step 2 validation assets for docs/lan-direct-path-plan.md.

Writes two hex files that tm_netstack's `lan_udp` tests `include_str!`:

- udp_demux_ping.hex: a real disco PING (pynacl crypto_box, fixed nonce), as
  a LAN peer would send it to our :41641.
- udp_demux_wg_init.hex: a real 148-byte WireGuard handshake initiation built
  by the from-spec wg_spec.py with fixed keys.

The demux only looks at framing (magic, type byte, reserved bytes, length),
so these vectors prove it recognizes genuine wire output of both protocols,
not a hand-typed approximation of it.

Run:
  uv run --with pynacl --with cryptography python3 tools/wg_validator/gen_udp_demux_vectors.py
"""

from __future__ import annotations

import os

from nacl.public import Box, PrivateKey, PublicKey

import disco
import wg_spec

HERE = os.path.dirname(os.path.abspath(__file__))

# Arbitrary fixed keys; only determinism matters.
PEER_DISCO_PRIV = bytes((0x41 + i) & 0xFF for i in range(32))
OUR_DISCO_PRIV = bytes((0x21 + i) & 0xFF for i in range(32))
PEER_NODE_PUB = bytes((0x61 + i) & 0xFF for i in range(32))
TX_ID = bytes(range(1, 13))
NONCE = bytes(range(1, 25))

INIT_STATIC = bytes((0x11 + i) & 0xFF for i in range(32))
INIT_EPHEMERAL = bytes((0x31 + i) & 0xFF for i in range(32))
RESP_STATIC = bytes((0x51 + i) & 0xFF for i in range(32))


def build_ping() -> bytes:
    peer_pub = bytes(PrivateKey(PEER_DISCO_PRIV).public_key)
    our_pub = bytes(PrivateKey(OUR_DISCO_PRIV).public_key)
    plaintext = bytes([disco.MSG_PING, disco.VERSION]) + TX_ID + PEER_NODE_PUB
    ct = Box(PrivateKey(PEER_DISCO_PRIV), PublicKey(our_pub)).encrypt(plaintext, NONCE).ciphertext
    return disco.MAGIC + peer_pub + NONCE + ct


def build_wg_init() -> bytes:
    wire, _st, _eph = wg_spec.build_initiation(
        INIT_STATIC,
        wg_spec.x25519_pub(RESP_STATIC),
        INIT_EPHEMERAL,
        0x01020304,
        wg_spec.tai64n_from_unix(1_700_000_123, 0),
    )
    return wire


def main() -> None:
    ping = build_ping()
    init = build_wg_init()
    assert disco.is_disco(ping) and len(init) == 148
    for name, data in (("udp_demux_ping.hex", ping), ("udp_demux_wg_init.hex", init)):
        with open(os.path.join(HERE, name), "w") as f:
            f.write(data.hex() + "\n")
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
