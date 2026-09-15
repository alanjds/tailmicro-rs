#!/usr/bin/env python3
"""Interop oracle: the from-spec Python WireGuard initiator vs. boringtun.

boringtun is Cloudflare's independent, production Rust WireGuard implementation
(one of the four authoritative references cited in the plan). Driving a real
handshake + bidirectional transport exchange against it -- with the Python
`wg_spec` initiator -- proves the oracle interoperates with a THIRD, fully
independent implementation. Because `tm_wg`'s output is byte-for-byte identical
to `wg_spec` (see validate_offline.py), this transitively shows `tm_wg` would
interop too, and closes the residual risk that oracle and `tm_wg` share the
same from-spec misreading.

This runs over a loopback UDP socket, in memory, with no tun device / root and
no network -- it is NOT the live tailnet, but it IS a real, independent WG peer.

Run:
  CARGO_TARGET_DIR=<scratch> \
  uv run --with cryptography python3 tools/wg_validator/validate_live_boringtun.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import wg_spec as wg

HERE = Path(__file__).resolve().parent
PEER_DIR = HERE / "boringtun_peer"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

# Fixed initiator (Python) static + ephemeral scalars (test constants).
INIT_STATIC = bytes(range(0x01, 0x21))
INIT_EPHEMERAL = bytes(range(0x41, 0x61))
INIT_SESSION_ID = 0x0A0B0C0D


def main() -> int:
    init_static_pub = wg.x25519_pub(INIT_STATIC)

    target_dir = os.environ.get(
        "CARGO_TARGET_DIR",
        str(HERE.parent.parent / "target" / "btpeer"),
    )
    # Build (serial dalek backend, so the rc.3 dalek compiles on nightly).
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": target_dir,
        "RUSTFLAGS": '--cfg curve25519_dalek_backend="serial"',
    }
    build = subprocess.run(
        ["cargo", "build", "-q"], cwd=PEER_DIR, env=env, capture_output=True, text=True
    )
    if build.returncode != 0:
        sys.stderr.write(build.stderr)
        raise SystemExit("boringtun_peer build failed")

    binary = Path(target_dir) / "debug" / "boringtun_peer"
    peer = subprocess.Popen(
        [str(binary), init_static_pub.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Read PORT and PUBKEY lines.
    port = None
    resp_pub = None
    for _ in range(2):
        line = peer.stdout.readline().strip()
        if line.startswith("PORT "):
            port = int(line.split()[1])
        elif line.startswith("PUBKEY "):
            resp_pub = bytes.fromhex(line.split()[1])
    assert port and resp_pub, f"peer did not announce port/pubkey (port={port})"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    addr = ("127.0.0.1", port)

    results: list[tuple[str, bool, str]] = []

    # ── 1. Send a from-spec initiation to boringtun ───────────────────────────
    ts = wg.tai64n_from_unix(int(time.time()), 0)
    init_wire, noise_after_init, eph_pub = wg.build_initiation(
        INIT_STATIC, resp_pub, INIT_EPHEMERAL, INIT_SESSION_ID, ts
    )
    sock.sendto(init_wire, addr)

    # ── 2. Receive boringtun's Handshake Response (type 2) ────────────────────
    try:
        resp_wire, _ = sock.recvfrom(2048)
    except socket.timeout:
        results.append(("boringtun replied to our initiation", False, "TIMEOUT (no response)"))
        return report(results, peer)

    got_type2 = len(resp_wire) == 92 and resp_wire[0] == 2
    results.append((
        "boringtun accepted our initiation and returned a Handshake Response (type 2, 92 B)",
        got_type2,
        f"len={len(resp_wire)} type={resp_wire[0]}",
    ))
    if not got_type2:
        return report(results, peer)

    # ── 3. Complete the handshake (initiator side) and derive keys ────────────
    resp_eph_pub = resp_wire[12:44]
    bt_index = int.from_bytes(resp_wire[4:8], "little")  # boringtun's sender index
    ni = noise_after_init
    ni.mix_hash(resp_eph_pub)  # e
    ni.mix_key(resp_eph_pub)  # e
    ni.mix_key(wg.x25519_dh(INIT_EPHEMERAL, resp_eph_pub))  # ee
    ni.mix_key(wg.x25519_dh(INIT_STATIC, resp_eph_pub))  # se
    ni.mix_psk(b"\x00" * 32)  # psk (Tailscale-style zeros; matches boringtun)
    try:
        ni.decrypt(resp_wire[44:60])  # verify the empty-payload auth tag
        auth_ok = True
    except Exception as e:  # noqa: BLE001
        auth_ok = False
        detail = repr(e)
    if auth_ok:
        detail = "empty-payload AEAD tag verified"
    results.append((
        "Response decrypts with a valid AEAD tag (handshake cryptographically complete)",
        auth_ok,
        detail,
    ))
    if not auth_ok:
        return report(results, peer)
    k_i2r, k_r2i = ni.split()

    # ── 4. Send transport data; boringtun must decrypt it ─────────────────────
    # boringtun routes the decrypted inner payload by IP version nibble, so use
    # a minimal well-formed IPv4 packet (version=4) as the plaintext.
    payload = bytes([0x45, 0, 0, 20]) + bytes(16)
    data_wire = wg.build_transport(k_i2r, bt_index, 0, payload)
    sock.sendto(data_wire, addr)

    # boringtun prints "GOT <hex>" of the decrypted payload, then replies.
    peer.stdout.flush()
    got_line = None
    deadline = time.time() + 5
    while time.time() < deadline:
        line = peer.stdout.readline().strip()
        if line.startswith("GOT "):
            got_line = line
            break
        if not line:
            break
    decrypted_ok = got_line is not None and bytes.fromhex(got_line.split()[1]) == payload
    results.append((
        "boringtun decrypted our TransportData to the exact plaintext",
        decrypted_ok,
        f"boringtun saw: {got_line}",
    ))

    # ── 5. Receive boringtun's encrypted reply; decrypt it ────────────────────
    try:
        reply_wire, _ = sock.recvfrom(2048)
        rid, ctr, pt = wg.decrypt_transport(k_r2i, reply_wire)
        reply_ok = pt == b"boringtun-reply"
        rdetail = f"decrypted reverse-direction payload: {pt!r} (counter={ctr})"
    except Exception as e:  # noqa: BLE001
        reply_ok = False
        rdetail = f"no/invalid reply: {e!r}"
    results.append((
        "Python decrypted boringtun's reverse-direction TransportData",
        reply_ok,
        rdetail,
    ))

    return report(results, peer)


def report(results, peer) -> int:
    try:
        peer.terminate()
    except Exception:  # noqa: BLE001
        pass
    print("=" * 78)
    print("tm_wg LIVE interop oracle: from-spec Python initiator vs. boringtun responder")
    print("(independent third-party WireGuard implementation, loopback UDP)")
    print("=" * 78)
    ok = True
    for name, passed, detail in results:
        ok = ok and passed
        print(f"[{PASS if passed else FAIL}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 78)
    print("ALL INTEROP CHECKS PASSED" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
