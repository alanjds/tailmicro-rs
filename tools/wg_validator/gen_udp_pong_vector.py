"""Step 1 validation asset for docs/lan-direct-path-plan.md.

Generates a fixed-nonce pynacl reference vector for a disco PONG whose
`src_ipport` carries a REAL literal UDP endpoint (`disco.pack_endpoint`),
instead of the `127.3.3.40:<region>` DERP-relay convention the existing
`tm_disco::pong_seal_crosscheck::pong_wire_matches_pynacl_reference` test
covers. This is the "same construction, addressed/sent differently" vector
the plan's Step 1 asks for (docs/lan-direct-path-plan.md, Step 1 "Validation
(Python first)"), so whoever implements `tm_disco`'s UDP PONG path (Step 1,
Rust, not done in this round) has an immediately-usable ground-truth vector,
the same way `pong_seal_crosscheck` already does for the DERP-relayed PONG.

This script does NOT touch tm_disco/src/lib.rs. It only prints (and, run via
`__main__`, writes to udp_pong_vector.txt next to it) the inputs and the
resulting wire bytes as a ready-to-paste Rust `[u8; N]` literal.

Fixture reuse: `receiver_priv` (0x21..0x40) and `sender_pub` are the exact
same fixed keys already hardcoded in tm_disco/src/lib.rs's `aead_crosscheck`,
`framing`, and `pong_seal_crosscheck` tests, so a Step 1 test can share the
same `DiscoPrivateKey::from_bytes(receiver_priv)` fixture and just add a new
`#[test]` next to the existing one instead of inventing new keys.

Run:
  uv run --with pynacl python3 tools/wg_validator/gen_udp_pong_vector.py
"""

from __future__ import annotations

from nacl.public import Box, PrivateKey, PublicKey

import disco

# Same fixed vector as tm_disco/src/lib.rs's aead_crosscheck / framing /
# pong_seal_crosscheck tests.
RECEIVER_PRIV = bytes((0x21 + i) & 0xFF for i in range(32))
SENDER_PUB = bytes([
    0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8, 0xb7, 0x55, 0xdc, 0x1b,
    0x10, 0xe8, 0x6c, 0xb4, 0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed,
    0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
])
TX_ID = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
NONCE = bytes(range(1, 25))  # 0x01..0x18, same pattern as the existing tests

# The plan's own Step 1 example endpoint (docs/lan-direct-path-plan.md,
# "generate a fixed-nonce vector with pynacl ... src_endpoint =
# ::ffff:192.168.15.139 port 41641").
PEER_LAN_IP = "192.168.15.139"
PEER_LAN_PORT = 41641


def receiver_pub() -> bytes:
    return bytes(PrivateKey(RECEIVER_PRIV).public_key)


def build() -> bytes:
    src_endpoint = disco.pack_endpoint(PEER_LAN_IP, PEER_LAN_PORT)
    assert len(src_endpoint) == 18
    # disco.build_pong seals with Box(my_priv=receiver, peer_pub=sender), the
    # same direction tm_disco's build_sealed_pong runs (our_disco_key,
    # sender_pub). Reach into the private _seal helper's construction
    # directly so we control the nonce (build_pong draws a random one).
    plaintext = bytes([disco.MSG_PONG, disco.VERSION]) + TX_ID + src_endpoint
    box = Box(PrivateKey(RECEIVER_PRIV), PublicKey(SENDER_PUB))
    ciphertext = box.encrypt(plaintext, NONCE).ciphertext
    wire = disco.MAGIC + receiver_pub() + NONCE + ciphertext
    return wire


def rust_array_literal(name: str, data: bytes) -> str:
    lines = [f"const {name}: [u8; {len(data)}] = ["]
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append("    " + " ".join(f"0x{b:02x}," for b in chunk))
    lines.append("];")
    return "\n".join(lines)


def main() -> None:
    wire = build()
    print("# Step 1 reference vector: UDP disco PONG with a real src_ipport")
    print(f"receiver_priv (our_disco_key) = {RECEIVER_PRIV.hex()}")
    print(f"receiver_pub                  = {receiver_pub().hex()}")
    print(f"sender_pub (peer disco key)    = {SENDER_PUB.hex()}")
    print(f"tx_id                          = {TX_ID.hex()}")
    print(f"nonce                          = {NONCE.hex()}")
    print(f"src_endpoint (peer LAN addr)   = {PEER_LAN_IP}:{PEER_LAN_PORT}"
          f"  -> 18B {disco.pack_endpoint(PEER_LAN_IP, PEER_LAN_PORT).hex()}")
    print(f"sealed wire ({len(wire)} bytes) = {wire.hex()}")
    print()
    print(rust_array_literal("EXPECTED_UDP_PONG_WIRE", wire))
    print()
    print("# Self-consistency check only (tautological, like tm_disco's own")
    print("# `framing` test notes): decrypts with the SAME Box that sealed it,")
    print("# since we only fix sender_pub here, not a matching sender_priv (a")
    print("# real peer would decrypt with Box(their_priv, our_pub) instead --")
    print("# that pairing is exactly what pong_seal_crosscheck's byte-for-byte")
    print("# comparison against the Rust output is for; see tm_disco/src/lib.rs).")
    magic, sender_field, nonce_field, ct = wire[:6], wire[6:38], wire[38:62], wire[62:]
    assert magic == disco.MAGIC
    assert sender_field == receiver_pub()  # PONG embeds the SENDER's (our) pub
    assert nonce_field == NONCE
    box = Box(PrivateKey(RECEIVER_PRIV), PublicKey(SENDER_PUB))
    plaintext_out = box.decrypt(ct, nonce_field)
    assert plaintext_out[0] == disco.MSG_PONG and plaintext_out[1] == disco.VERSION
    assert plaintext_out[2:14] == TX_ID
    assert plaintext_out[14:32] == disco.pack_endpoint(PEER_LAN_IP, PEER_LAN_PORT)
    print("OK: wire format is internally consistent")


if __name__ == "__main__":
    main()
