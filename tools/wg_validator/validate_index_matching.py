#!/usr/bin/env python3
"""Root-cause regression for the rung-5 blocker: the WG handshake `aead::Error`
was an INDEX-MATCHING bug, not a crypto bug.

The device, as initiator, retries its handshake every ~5 s, each retry with a
fresh ephemeral (a new sender session id). A type-2 response carries a
`receiver_id` naming exactly which outstanding initiation it answers. When a
DERP-relayed response answering an EARLIER initiation is fed to `finish()`
against the CURRENT (rotated) ephemeral, the `ee`/`se` Diffie-Hellman inputs no
longer match what the responder used, so the derived key is wrong and the
empty-payload AEAD tag fails -- exactly the live `aead::Error`.

This oracle proves that mechanism from spec, independently of the Rust code:

  * A responder answers initiation #1 (ephemeral E1, session S1).
  * Consuming that response against E1's post-init state SUCCEEDS.
  * Consuming the SAME response against a different initiation's ephemeral E2
    FAILS with an AEAD error -- the live symptom.

So the fix is to only ever run `finish()` against the initiation the response's
`receiver_id` names (and to free a timed-out initiation's session id so a late
response can no longer be mis-routed to a live peer). See
docs/wg-dataplane-notes.md and tm_wg/src/endpoint.rs::dispatch.

Run:  uv run --with cryptography python3 tools/wg_validator/validate_index_matching.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wg_spec as wg

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
ZERO_PSK = b"\x00" * 32


def consume_response(noise_after_init, init_static_scalar, init_ephemeral_scalar, resp_wire):
    """Initiator-side response consumption (Noise_IKpsk2), from spec. Mirrors
    tm_wg's `Handshake::finish` and validate_live_tailnet.py. Raises on a bad
    AEAD tag."""
    resp_eph = resp_wire[12:44]
    ni = noise_after_init
    ni.mix_hash(resp_eph)  # e
    ni.mix_key(resp_eph)  # e (psk variant extra mix)
    ni.mix_key(wg.x25519_dh(init_ephemeral_scalar, resp_eph))  # ee
    ni.mix_key(wg.x25519_dh(init_static_scalar, resp_eph))  # se (initiator)
    ni.mix_psk(ZERO_PSK)  # psk
    ni.decrypt(resp_wire[44:60])  # empty payload -> verifies the auth tag
    return ni.split()


def build_one_initiation(init_static_scalar, resp_static_pub, session_id):
    eph = wg.X25519PrivateKey.generate().private_bytes_raw()
    ts = wg.tai64n_from_unix(int(time.time()), 0)
    wire, noise_after, _ = wg.build_initiation(
        init_static_scalar, resp_static_pub, eph, session_id, ts
    )
    return wire, noise_after, eph


def main() -> int:
    results: list[tuple[str, bool, str]] = []

    init_static = wg.X25519PrivateKey.generate().private_bytes_raw()
    resp_static = wg.X25519PrivateKey.generate().private_bytes_raw()
    resp_static_pub = wg.x25519_pub(resp_static)
    init_static_pub = wg.x25519_pub(init_static)

    # Two initiations to the same responder, each with its own ephemeral and
    # sender session id -- exactly what a retry produces on the device.
    s1, s2 = 0x1111_1111, 0x2222_2222
    init1_wire, noise1, eph1 = build_one_initiation(init_static, resp_static_pub, s1)
    init2_wire, noise2, eph2 = build_one_initiation(init_static, resp_static_pub, s2)

    # The responder receives initiation #1 and builds a response answering S1.
    noise_r, recovered_static, _ = wg.consume_initiation(init1_wire, resp_static)
    assert recovered_static == init_static_pub
    resp_eph_scalar = wg.X25519PrivateKey.generate().private_bytes_raw()
    resp1_wire, _, _ = wg.build_response(
        noise_r,
        eph1_pub := init1_wire[8:40],
        init_static_pub,
        resp_eph_scalar,
        resp_session_id=0x5566_7788,
        init_session_id=s1,  # this response's receiver_id == S1
        psk=ZERO_PSK,
        initiator_static_pub_for_mac=init_static_pub,
    )
    assert resp1_wire[8:12] == s1.to_bytes(4, "little"), "response must name S1"

    # (a) Consuming resp1 against the MATCHING initiation (#1 / E1) succeeds.
    #     `noise1` is init #1's post-init state -- exactly what the responder
    #     continued from -- and has not been mutated since it was built.
    try:
        consume_response(noise1, init_static, eph1, resp1_wire)
        ok_match, detail_match = True, "AEAD tag verified (correct ephemeral E1)"
    except Exception as e:  # noqa: BLE001
        ok_match, detail_match = False, f"unexpected failure: {e!r}"
    results.append((
        "Response for S1 verifies when finished against its own initiation (E1)",
        ok_match, detail_match,
    ))

    # (b) Consuming the SAME resp1 against initiation #2's ephemeral E2 (the
    #     rotated-in handshake) fails the AEAD tag -- the live `aead::Error`.
    try:
        consume_response(noise2, init_static, eph2, resp1_wire)
        reproduced, detail_mismatch = False, "no error (bug NOT reproduced)"
    except Exception as e:  # noqa: BLE001
        reproduced = "tag" in (type(e).__name__ + repr(e)).lower()
        detail_mismatch = f"AEAD failed as on device: {type(e).__name__}"
    results.append((
        "Response for S1 FAILS the AEAD tag when finished against E2 "
        "(reproduces the live aead::Error = index-matching bug)",
        reproduced, detail_mismatch,
    ))

    print("=" * 78)
    print("tm_wg index-matching root-cause oracle (from-spec; independent of Rust)")
    print("=" * 78)
    ok = True
    for name, passed, detail in results:
        ok = ok and passed
        print(f"[{PASS if passed else FAIL}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 78)
    print("ROOT CAUSE CONFIRMED: wrong-ephemeral finish, not a crypto bug"
          if ok else "oracle inconclusive")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
