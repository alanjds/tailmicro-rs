#!/usr/bin/env python3
"""Rung 1: offline byte-level oracle.

Runs the real `tm_wg` crypto core (via `cargo run --example wg_emit_vectors`),
then independently reconstructs every emitted message from spec (`wg_spec.py`)
and asserts byte-for-byte equality. No network. This catches a port-introduced
offset / endianness / MAC-domain / DH-ordering / KDF bug even with no live peer,
because the Python side shares no code with Rust.

Run:  uv run --with cryptography python3 tools/wg_validator/validate_offline.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import wg_spec as wg

REPO = Path(__file__).resolve().parents[2]


def h(s: str) -> bytes:
    return bytes.fromhex(s)


def run_rust_emitter() -> dict:
    out = subprocess.run(
        ["cargo", "run", "-q", "-p", "tm_wg", "--example", "wg_emit_vectors"],
        cwd=REPO,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "RUSTFLAGS": "-A warnings"},
    )
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        raise SystemExit(f"rust emitter failed: {out.returncode}")
    # Isolate the JSON object (cargo may print nothing else with -q).
    text = out.stdout
    start = text.index("{")
    return json.loads(text[start:])


def run_cookie_probe(resp_pub_hex: str, cookie_hex: str, mac1_hex: str, pkt_hex: str) -> bytes:
    out = subprocess.run(
        ["cargo", "run", "-q", "-p", "tm_wg", "--example", "wg_cookie_probe",
         "--", resp_pub_hex, cookie_hex, mac1_hex, pkt_hex],
        cwd=REPO,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "RUSTFLAGS": "-A warnings"},
    )
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        raise SystemExit(f"cookie probe failed: {out.returncode}")
    return bytes.fromhex(out.stdout.strip().splitlines()[-1])


PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


def main() -> int:
    v = run_rust_emitter()
    inp = v["inputs"]
    outp = v["outputs"]

    init_static_scalar = h(inp["init_static_scalar"])
    resp_static_scalar = h(inp["resp_static_scalar"])
    init_ephemeral_scalar = h(inp["init_ephemeral_scalar"])
    resp_ephemeral_scalar = h(inp["resp_ephemeral_scalar"])
    init_session_id = inp["init_session_id"]
    resp_session_id = inp["resp_session_id"]
    ts_secs = inp["ts_secs"]
    ts_nanos = inp["ts_nanos"]
    psk = h(inp["psk"])
    transport_plaintext = h(inp["transport_plaintext"])
    transport_counter = inp["transport_counter"]

    rust_init = h(outp["initiation"])
    rust_resp = h(outp["response"])
    rust_k_i2r = h(outp["initiator_to_responder_key"])
    rust_k_r2i = h(outp["responder_to_initiator_key"])
    rust_transport = h(outp["transport_data"])

    results: list[tuple[str, bool, str]] = []

    # ── 0. Independently derive the public keys ───────────────────────────────
    py_init_pub = wg.x25519_pub(init_static_scalar)
    py_resp_pub = wg.x25519_pub(resp_static_scalar)
    results.append((
        "static pubkeys derived from scalars match Rust",
        py_init_pub == h(inp["init_static_pub"]) and py_resp_pub == h(inp["resp_static_pub"]),
        f"init={py_init_pub.hex()[:16]}.. resp={py_resp_pub.hex()[:16]}..",
    ))

    # ── 1. TAI64N timestamp encoding ──────────────────────────────────────────
    py_ts = wg.tai64n_from_unix(ts_secs, ts_nanos)
    results.append((
        "TAI64N(secs,nanos) 12-byte big-endian encoding",
        py_ts == h(outp["timestamp_tai64n"]),
        f"py={py_ts.hex()} rust={outp['timestamp_tai64n']}",
    ))

    # ── 2. Handshake Initiation: byte-for-byte ────────────────────────────────
    py_init, noise_after_init, eph_pub = wg.build_initiation(
        init_static_scalar, py_resp_pub, init_ephemeral_scalar, init_session_id, py_ts
    )
    results.append((
        "Handshake Initiation (148 B) byte-for-byte == Rust",
        py_init == rust_init,
        _diff(py_init, rust_init),
    ))

    # ── 3. MAC1 domain / offset ───────────────────────────────────────────────
    py_mac1 = wg.mac1(py_resp_pub, rust_init[0:116])
    results.append((
        "Initiation MAC1 (offset 116..132, over msg[0..116]) == Rust",
        py_mac1 == rust_init[116:132] == h(outp["initiation_mac1"]),
        f"py={py_mac1.hex()}",
    ))
    results.append((
        "Initiation MAC2 (offset 132..148) is all-zero (no cookie)",
        rust_init[132:148] == b"\x00" * 16,
        rust_init[132:148].hex(),
    ))

    # ── 4. Responder consumes the (Rust) initiation, recovers static + ts ─────
    noise_resp, recovered_static, recovered_ts = wg.consume_initiation(
        rust_init, resp_static_scalar
    )
    results.append((
        "Python decrypts Rust's initiation -> recovers initiator static pub",
        recovered_static == py_init_pub,
        f"recovered={recovered_static.hex()[:16]}..",
    ))
    results.append((
        "Python decrypts Rust's initiation -> recovers exact timestamp",
        recovered_ts == py_ts,
        f"recovered={recovered_ts.hex()}",
    ))

    # ── 5. Handshake Response: byte-for-byte (independent responder path) ─────
    py_resp, py_k_i2r, py_k_r2i = wg.build_response(
        noise_resp,
        eph_pub,
        py_init_pub,
        resp_ephemeral_scalar,
        resp_session_id,
        init_session_id,
        psk,
        py_init_pub,
    )
    results.append((
        "Handshake Response (92 B) byte-for-byte == Rust",
        py_resp == rust_resp,
        _diff(py_resp, rust_resp),
    ))
    results.append((
        "Response MAC1 (offset 60..76) == Rust",
        py_resp[60:76] == rust_resp[60:76] == h(outp["response_mac1"]),
        py_resp[60:76].hex(),
    ))
    results.append((
        "Response MAC2 (offset 76..92) all-zero",
        rust_resp[76:92] == b"\x00" * 16,
        rust_resp[76:92].hex(),
    ))

    # ── 6. Derived transport keys match (both directions) ─────────────────────
    results.append((
        "Derived initiator->responder key == Rust",
        py_k_i2r == rust_k_i2r,
        f"py={py_k_i2r.hex()[:16]}..",
    ))
    results.append((
        "Derived responder->initiator key == Rust",
        py_k_r2i == rust_k_r2i,
        f"py={py_k_r2i.hex()[:16]}..",
    ))

    # ── 7. Initiator independently completes the handshake -> same keys ───────
    # (Proves the initiator's response-consumption key schedule, not just the
    # responder's, matches -- both parties must derive identical keys.)
    ni = noise_after_init  # initiator's state right after sending initiation
    resp_eph_pub = rust_resp[12:44]
    ni.mix_hash(resp_eph_pub)  # e
    ni.mix_key(resp_eph_pub)  # e
    ni.mix_key(wg.x25519_dh(init_ephemeral_scalar, resp_eph_pub))  # ee
    ni.mix_key(wg.x25519_dh(init_static_scalar, resp_eph_pub))  # se (initiator)
    ni.mix_psk(psk)  # psk
    ni.decrypt(rust_resp[44:60])  # verifies the empty-payload auth tag
    ik_i2r, ik_r2i = ni.split()
    results.append((
        "Initiator-side key schedule agrees with responder + Rust",
        ik_i2r == rust_k_i2r and ik_r2i == rust_k_r2i,
        "both directions match" if (ik_i2r == rust_k_i2r) else "MISMATCH",
    ))

    # ── 8. Transport data: byte-for-byte + decrypt ────────────────────────────
    py_transport = wg.build_transport(
        rust_k_i2r, resp_session_id, transport_counter, transport_plaintext
    )
    results.append((
        "TransportData (le64 nonce, 16 B header) byte-for-byte == Rust",
        py_transport == rust_transport,
        _diff(py_transport, rust_transport),
    ))
    rid, ctr, pt = wg.decrypt_transport(rust_k_i2r, rust_transport)
    results.append((
        "Python decrypts Rust's TransportData -> exact plaintext",
        pt == transport_plaintext and rid == resp_session_id and ctr == transport_counter,
        f"plaintext={pt!r} receiver_id={rid} counter={ctr}",
    ))

    # ── 9. Cookie Reply (type 3) + mac2 domain, via a Rust probe ──────────────
    # Python builds a valid cookie reply that only the correct
    # BLAKE2s("cookie--"||resp_pub) key + mac1 AAD can decrypt; Rust decrypts it
    # and stamps mac2; Python independently recomputes mac2 and compares.
    cookie16 = bytes(range(0x30, 0x40))  # 16 fixed bytes
    nonce24 = bytes(range(0x10, 0x28))  # 24 fixed bytes
    last_mac1 = rust_init[116:132]
    cookie_reply = wg.build_cookie_reply(
        py_resp_pub, init_session_id, nonce24, cookie16, last_mac1
    )
    # A fresh 148-byte packet to stamp: reuse the initiation body, mac fields zeroed.
    probe_pkt = bytearray(rust_init)
    probe_pkt[116:148] = b"\x00" * 32
    rust_mac2 = run_cookie_probe(
        py_resp_pub.hex(), cookie_reply.hex(), last_mac1.hex(), bytes(probe_pkt).hex()
    )
    # write_macs first recomputes mac1 over msg[0..116], then mac2 over msg[0..132].
    py_mac1_probe = wg.mac1(py_resp_pub, bytes(probe_pkt)[0:116])
    probe_after_mac1 = bytes(probe_pkt)[0:116] + py_mac1_probe + b"\x00" * 16
    py_mac2 = wg.mac2(cookie16, probe_after_mac1[0:132])
    results.append((
        "Cookie decrypt (XChaCha20, AAD=mac1) + mac2 domain (msg[0..len-16]) == Rust",
        py_mac2 == rust_mac2,
        f"py_mac2={py_mac2.hex()} rust_mac2={rust_mac2.hex()}",
    ))

    # ── Report ────────────────────────────────────────────────────────────────
    print("=" * 78)
    print("tm_wg OFFLINE byte-level oracle (Python from-spec vs. real Rust core)")
    print("=" * 78)
    ok = True
    for name, passed, detail in results:
        ok = ok and passed
        print(f"[{PASS if passed else FAIL}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 78)
    print(("ALL CHECKS PASSED" if ok else "FAILURES PRESENT"))
    return 0 if ok else 1


def _diff(a: bytes, b: bytes) -> str:
    if a == b:
        return f"{len(a)} bytes identical"
    if len(a) != len(b):
        return f"LENGTH DIFFERS py={len(a)} rust={len(b)}"
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"first diff at byte {i}: py={x:02x} rust={y:02x}"
    return "?"


if __name__ == "__main__":
    raise SystemExit(main())
