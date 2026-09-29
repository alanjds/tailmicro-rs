"""Step 3 validation asset for docs/lan-direct-path-plan.md.

Captures the exact JSON body that ts_control.py's write_map() sends for
publish #2 with a LAN endpoint, so tm_control's test can check its own
publish #2 body against the Python client that is known to publish
successfully against the live control server. write_map() itself builds
the body; only the transport is replaced by a stub that captures it.

Fixed inputs (mirrored by the Rust test):
  node key  = 32 bytes 0x01..0x20
  disco key = 32 bytes 0x21..0x40
  region    = 11
  endpoints = ["192.168.15.20:41641", "127.3.3.40:11"]
  hostname  = "esp32c3"

Run:
  uv run --with pynacl --with cryptography --with h2 python3 tools/wg_validator/gen_publish2_lan_vector.py
"""

from __future__ import annotations

import os

import ts_control

HERE = os.path.dirname(os.path.abspath(__file__))


class _Captured(Exception):
    pass


class _CaptureH2:
    body: bytes = b""

    def post(self, sid: int, path: str, body: bytes) -> None:
        assert path == "/machine/map"
        self.body = body

    def read_full_body(self, sid: int):
        raise _Captured()


def main() -> None:
    c = ts_control.TsControlClient.__new__(ts_control.TsControlClient)
    c.cap = 72
    c.node_pub = bytes(range(0x01, 0x21))
    c.disco_pub = bytes(range(0x21, 0x41))
    c.h2 = _CaptureH2()
    c._next_stream = 3
    try:
        c.write_map(hostname="esp32c3", preferred_derp=11,
                    endpoints=["192.168.15.20:41641", "127.3.3.40:11"])
    except _Captured:
        pass
    out = os.path.join(HERE, "publish2_lan_body.json")
    with open(out, "wb") as f:
        f.write(c.h2.body + b"\n")
    print(f"publish2_lan_body.json: {len(c.h2.body)} bytes")


if __name__ == "__main__":
    main()
