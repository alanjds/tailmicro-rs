"""Independent, from-spec Tailscale 'disco' message codec (ping/pong).

Disco is the side-channel Tailscale nodes use over DERP (and UDP) to discover
paths. It matters here for one reason: a real Tailscale peer keeps its
wireguard-go peer set *trimmed* (lazy config) and will silently drop a
WireGuard handshake from a node it has no active path to. Receiving a disco
PING from us marks our endpoint active on the peer, which makes magicsock add
us back to its wireguard-go config so it will actually answer our WG handshake.

Wire format (cross-checked against the authoritative `ts_disco_protocol` and
`tm_disco` in this workspace):
  magic(6)="TS💬" + sender_disco_pub(32) + nonce(24) + SalsaBox_ciphertext
  plaintext = type(1) + version(1, =0) + body

NOTE: the box is NaCl `crypto_box`/SalsaBox (Curve25519-XSalsa20-Poly1305),
the SAME primitive DERP uses -- NOT XChaCha20-Poly1305. `tm_disco`'s current
code decrypts with XChaCha20-Poly1305, which disagrees with both the upstream
Rust reference and the Go source (flagged in the validator report).
"""

from __future__ import annotations

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random

MAGIC = b"TS\xf0\x9f\x92\xac"  # "TS💬"
VERSION = 0
MSG_PING = 0x01
MSG_PONG = 0x02
MSG_CALL_ME_MAYBE = 0x03


def _seal(my_disco_priv: bytes, my_disco_pub: bytes, peer_disco_pub: bytes,
          plaintext: bytes) -> bytes:
    box = Box(PrivateKey(my_disco_priv), PublicKey(peer_disco_pub))
    nonce = nacl_random(24)
    ct = box.encrypt(plaintext, nonce).ciphertext
    return MAGIC + my_disco_pub + nonce + ct


def build_ping(my_disco_priv: bytes, my_disco_pub: bytes, peer_disco_pub: bytes,
               tx_id: bytes, my_node_pub: bytes) -> bytes:
    assert len(tx_id) == 12
    plaintext = bytes([MSG_PING, VERSION]) + tx_id + my_node_pub
    return _seal(my_disco_priv, my_disco_pub, peer_disco_pub, plaintext)


def build_pong(my_disco_priv: bytes, my_disco_pub: bytes, peer_disco_pub: bytes,
               tx_id: bytes, src_endpoint: bytes = b"\x00" * 18) -> bytes:
    assert len(tx_id) == 12
    plaintext = bytes([MSG_PONG, VERSION]) + tx_id + src_endpoint
    return _seal(my_disco_priv, my_disco_pub, peer_disco_pub, plaintext)


def is_disco(packet: bytes) -> bool:
    return packet[:6] == MAGIC


def open_disco(packet: bytes, my_disco_priv: bytes):
    """Return (sender_disco_pub, msg_type, version, body) or None if not disco /
    not decryptable by us."""
    if not is_disco(packet):
        return None
    sender_pub = packet[6:38]
    nonce = packet[38:62]
    ct = packet[62:]
    try:
        pt = Box(PrivateKey(my_disco_priv), PublicKey(sender_pub)).decrypt(ct, nonce)
    except Exception:  # noqa: BLE001
        return None
    if len(pt) < 2:
        return None
    return sender_pub, pt[0], pt[1], pt[2:]
