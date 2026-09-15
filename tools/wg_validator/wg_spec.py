"""Independent, from-spec WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
reference implementation.

This is written directly against the WireGuard whitepaper / protocol spec and
the byte-offset tables in `docs/wg-dataplane-implementation-plan.md` Part 2.
It deliberately does NOT import or mirror the Rust `tm_wg` code: the whole
point is an *independent* oracle that can catch a wire-format/crypto bug that
is uniformly wrong on both the Rust encode and decode sides.

Crypto primitives used from the stdlib / `cryptography`:
  * BLAKE2s     -> hashlib.blake2s
  * X25519      -> cryptography X25519 (RFC 7748; clamps the scalar internally,
                   matching x25519-dalek's StaticSecret)
  * ChaCha20Poly1305 -> cryptography AEAD

Nothing else. HKDF and the Noise state machine are implemented here by hand.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ── WireGuard protocol constants (from spec, cross-checked in the plan) ───────
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

# TAI64 seconds base for the Unix epoch (deliberately bug-for-bug per WireGuard;
# see https://blog.dave.tf/post/tai64-is-not-tai/).
TAI_BASE = 0x400000000000000A
# Nanosecond whitening: keep only the high bits (mask off low 24 bits).
WHITEN_MASK = (~0xFFFFFF) & 0xFFFFFFFF

MSG_INITIATION = 1
MSG_RESPONSE = 2
MSG_COOKIE = 3
MSG_TRANSPORT = 4


# ── BLAKE2s helpers ───────────────────────────────────────────────────────────
def blake2s(data: bytes, digest_size: int = 32) -> bytes:
    return hashlib.blake2s(data, digest_size=digest_size).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    """HMAC using BLAKE2s as the hash (block size 64, output 32)."""
    block = 64
    if len(key) > block:
        key = blake2s(key)
    key = key + b"\x00" * (block - len(key))
    o_pad = bytes(b ^ 0x5C for b in key)
    i_pad = bytes(b ^ 0x36 for b in key)
    return blake2s(o_pad + blake2s(i_pad + data))


def hkdf(chaining_key: bytes, key_material: bytes, num: int) -> list[bytes]:
    """WireGuard's HKDF: RFC 5869 with BLAKE2s, `num` 32-byte outputs (1..3)."""
    prk = hmac_blake2s(chaining_key, key_material)  # extract
    outputs = []
    t = b""
    for i in range(1, num + 1):
        t = hmac_blake2s(prk, t + bytes([i]))  # expand
        outputs.append(t)
    return outputs


# ── X25519 ────────────────────────────────────────────────────────────────────
def x25519_pub(scalar: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes_raw()
    )


def x25519_dh(scalar: bytes, peer_pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(peer_pub)
    )


# ── TAI64N ──────────────────────────────────────────────────────────────────--
def tai64n_from_unix(secs: int, nanos: int) -> bytes:
    """12-byte big-endian TAI64N (8-byte secs + 4-byte nanos)."""
    return struct.pack(">Q", TAI_BASE + secs) + struct.pack(">I", nanos & WHITEN_MASK)


# ── Noise handshake state ─────────────────────────────────────────────────────
class Noise:
    """Minimal Noise_IKpsk2 mixer, exactly as WireGuard uses it."""

    def __init__(self, responder_static_pub: bytes):
        h = blake2s(CONSTRUCTION)
        self.chaining_key = h
        # MixHash(identifier) then MixHash(responder static pub).
        self.hash = blake2s(h + IDENTIFIER)
        self.hash = blake2s(self.hash + responder_static_pub)
        self.key: bytes | None = None

    def mix_hash(self, data: bytes) -> None:
        self.hash = blake2s(self.hash + data)

    def mix_key(self, key_material: bytes) -> None:
        ck, k = hkdf(self.chaining_key, key_material, 2)
        self.chaining_key = ck
        self.key = k

    def mix_psk(self, psk: bytes) -> None:
        ck, temp_h, k = hkdf(self.chaining_key, psk, 3)
        self.chaining_key = ck
        self.mix_hash(temp_h)
        self.key = k

    def encrypt(self, plaintext: bytes) -> bytes:
        """EncryptAndHash: AEAD with a zero 12-byte nonce, AAD = current hash."""
        aead = ChaCha20Poly1305(self.key)
        ct = aead.encrypt(b"\x00" * 12, plaintext, self.hash)
        self.mix_hash(ct)
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        aead = ChaCha20Poly1305(self.key)
        pt = aead.decrypt(b"\x00" * 12, ciphertext, self.hash)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[bytes, bytes]:
        """Final Split(): the two transport keys."""
        k1, k2 = hkdf(self.chaining_key, b"", 2)
        return k1, k2


# ── MAC1 (independent of the Noise state) ─────────────────────────────────────
def mac1(peer_static_pub: bytes, msg_up_to_mac1: bytes) -> bytes:
    """mac1 = BLAKE2s-128 keyed with BLAKE2s(LABEL_MAC1 || peer_pub) over the
    message bytes preceding the mac1 field (i.e. msg[0..len-32])."""
    key = blake2s(LABEL_MAC1 + peer_static_pub)
    return hashlib.blake2s(msg_up_to_mac1, digest_size=16, key=key).digest()


# ── Message builders ──────────────────────────────────────────────────────────
def build_initiation(
    init_static_scalar: bytes,
    resp_static_pub: bytes,
    init_ephemeral_scalar: bytes,
    session_id: int,
    tai64n: bytes,
) -> tuple[bytes, Noise, bytes]:
    """Build the 148-byte Handshake Initiation (mac2 = zeros; no cookie).

    Returns (wire_bytes, noise_state_after_initiation, ephemeral_pub).
    """
    init_static_pub = x25519_pub(init_static_scalar)
    ephemeral_pub = x25519_pub(init_ephemeral_scalar)

    st = Noise(resp_static_pub)
    st.mix_hash(ephemeral_pub)  # e
    st.mix_key(ephemeral_pub)  # e (psk variant extra mix)
    st.mix_key(x25519_dh(init_ephemeral_scalar, resp_static_pub))  # es
    enc_static = st.encrypt(init_static_pub)  # s (32 + 16)
    st.mix_key(x25519_dh(init_static_scalar, resp_static_pub))  # ss
    enc_ts = st.encrypt(tai64n)  # timestamp (12 + 16)

    # Assemble per the offset table: type(4) + sender(4) + eph(32) +
    # enc_static(48) + enc_ts(28) + mac1(16) + mac2(16) = 148.
    body = (
        struct.pack("<I", MSG_INITIATION)
        + struct.pack("<I", session_id)
        + ephemeral_pub
        + enc_static
        + enc_ts
    )
    assert len(body) == 116, len(body)
    m1 = mac1(resp_static_pub, body)
    wire = body + m1 + (b"\x00" * 16)
    assert len(wire) == 148, len(wire)
    return wire, st, ephemeral_pub


def consume_initiation(
    wire: bytes,
    resp_static_scalar: bytes,
) -> tuple[Noise, bytes, bytes]:
    """Responder side: decrypt an initiation, returning
    (noise_state, recovered_initiator_static_pub, recovered_tai64n)."""
    resp_static_pub = x25519_pub(resp_static_scalar)
    ephemeral_pub = wire[8:40]
    enc_static = wire[40:88]
    enc_ts = wire[88:116]

    st = Noise(resp_static_pub)
    st.mix_hash(ephemeral_pub)  # e
    st.mix_key(ephemeral_pub)  # e
    st.mix_key(x25519_dh(resp_static_scalar, ephemeral_pub))  # es (responder view)
    init_static_pub = st.decrypt(enc_static)  # s
    st.mix_key(x25519_dh(resp_static_scalar, init_static_pub))  # ss
    tai64n = st.decrypt(enc_ts)  # timestamp
    return st, init_static_pub, tai64n


def build_response(
    st: Noise,
    peer_ephemeral_pub: bytes,
    peer_static_pub: bytes,
    resp_ephemeral_scalar: bytes,
    resp_session_id: int,
    init_session_id: int,
    psk: bytes,
    initiator_static_pub_for_mac: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Responder builds the 92-byte Handshake Response, continuing from the
    post-initiation Noise state `st`.

    Returns (wire_bytes, initiator_to_responder_key, responder_to_initiator_key).
    """
    resp_ephemeral_pub = x25519_pub(resp_ephemeral_scalar)

    st.mix_hash(resp_ephemeral_pub)  # e
    st.mix_key(resp_ephemeral_pub)  # e
    st.mix_key(x25519_dh(resp_ephemeral_scalar, peer_ephemeral_pub))  # ee
    st.mix_key(x25519_dh(resp_ephemeral_scalar, peer_static_pub))  # se (responder)
    st.mix_psk(psk)  # psk
    enc_nothing = st.encrypt(b"")  # empty payload -> bare 16-byte tag
    k_i2r, k_r2i = st.split()

    body = (
        struct.pack("<I", MSG_RESPONSE)
        + struct.pack("<I", resp_session_id)
        + struct.pack("<I", init_session_id)
        + resp_ephemeral_pub
        + enc_nothing
    )
    assert len(body) == 60, len(body)
    m1 = mac1(initiator_static_pub_for_mac, body)
    wire = body + m1 + (b"\x00" * 16)
    assert len(wire) == 92, len(wire)
    return wire, k_i2r, k_r2i


# ── Transport data ────────────────────────────────────────────────────────────
def transport_nonce(counter: int) -> bytes:
    """96-bit ChaCha20Poly1305 nonce = 4 zero bytes + 64-bit LITTLE-endian
    counter (WireGuard data-plane convention; the ts2021 CONTROL plane instead
    uses big-endian, a distinct layer -- see docs/noise-handshake-wire-format.md)."""
    return b"\x00\x00\x00\x00" + struct.pack("<Q", counter)


def build_transport(key: bytes, receiver_id: int, counter: int, plaintext: bytes) -> bytes:
    """type(4) + receiver_id(4) + counter le64(8) + ciphertext||tag."""
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(transport_nonce(counter), plaintext, None)
    header = struct.pack("<I", MSG_TRANSPORT) + struct.pack("<I", receiver_id) + struct.pack("<Q", counter)
    assert len(header) == 16
    return header + ct


def _rotl32(v: int, c: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _qr(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (RFC draft): 32-byte key + 16-byte nonce -> 32-byte subkey.
    Implemented from spec so the oracle stays independent of any XChaCha lib."""
    const = b"expand 32-byte k"
    state = list(struct.unpack("<4I", const))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(state, 0, 4, 8, 12)
        _qr(state, 1, 5, 9, 13)
        _qr(state, 2, 6, 10, 14)
        _qr(state, 3, 7, 11, 15)
        _qr(state, 0, 5, 10, 15)
        _qr(state, 1, 6, 11, 12)
        _qr(state, 2, 7, 8, 13)
        _qr(state, 3, 4, 9, 14)
    out = state[0:4] + state[12:16]
    return struct.pack("<8I", *out)


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, pt: bytes, aad: bytes) -> bytes:
    """XChaCha20Poly1305 = HChaCha20 subkey derivation + ChaCha20Poly1305 with a
    96-bit nonce of 4 zero bytes + the last 8 bytes of the 24-byte nonce."""
    subkey = hchacha20(key, nonce24[:16])
    chacha_nonce = b"\x00\x00\x00\x00" + nonce24[16:24]
    return ChaCha20Poly1305(subkey).encrypt(chacha_nonce, pt, aad)


def mac2_key(peer_static_pub: bytes) -> bytes:
    return blake2s(LABEL_COOKIE + peer_static_pub)


def build_cookie_reply(
    resp_static_pub: bytes,
    receiver_id: int,
    nonce24: bytes,
    cookie16: bytes,
    last_mac1: bytes,
) -> bytes:
    """64-byte Cookie Reply: type(4) + receiver_id(4) + nonce(24) +
    XChaCha20Poly1305(cookie)(16+16). Encrypted under BLAKE2s("cookie--"||
    resp_pub) with the initiation's mac1 as AAD."""
    assert len(nonce24) == 24 and len(cookie16) == 16
    enc = xchacha20poly1305_encrypt(
        mac2_key(resp_static_pub), nonce24, cookie16, last_mac1
    )  # 32 bytes (16 + tag)
    wire = struct.pack("<I", MSG_COOKIE) + struct.pack("<I", receiver_id) + nonce24 + enc
    assert len(wire) == 64, len(wire)
    return wire


def mac2(cookie16: bytes, msg_up_to_mac2: bytes) -> bytes:
    """mac2 = BLAKE2s-128 keyed with the decrypted cookie over msg[0..len-16]."""
    return hashlib.blake2s(msg_up_to_mac2, digest_size=16, key=cookie16).digest()


def decrypt_transport(key: bytes, wire: bytes) -> tuple[int, int, bytes]:
    """Returns (receiver_id, counter, plaintext)."""
    (msg_type,) = struct.unpack("<I", wire[0:4])
    assert msg_type == MSG_TRANSPORT, msg_type
    (receiver_id,) = struct.unpack("<I", wire[4:8])
    (counter,) = struct.unpack("<Q", wire[8:16])
    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(transport_nonce(counter), wire[16:], None)
    return receiver_id, counter, pt
