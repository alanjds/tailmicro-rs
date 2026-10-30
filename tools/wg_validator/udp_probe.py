"""LAN-side probe for the device's direct-path UDP socket
(docs/lan-direct-path-plan.md, Step 2 on-device validation).

Sends datagrams from this host's LAN to <device-lan-ip>:41641 so the
device's `udp rx: disco=N wg=M junk=K ...` serial counter can be checked
against what was sent. No tailnet identity or auth key is needed: at Step 2
the device only classifies by framing (disco magic, WireGuard type/length),
it does not decrypt or answer, so structurally real datagrams are enough.
The disco PING and WireGuard initiation bytes are the same real wire
vectors the host tests use (gen_udp_demux_vectors.py).

Usage:
  python3 udp_probe.py <device-ip> probe            # 1 disco, 1 WG init, 1 junk
  python3 udp_probe.py <device-ip> burst N [SIZE] [PPS]
      N datagrams of SIZE bytes (default 1400, shaped as WireGuard transport
      data so the device counts them as wg) at PPS per second (default 0 =
      as fast as possible). This is the heap-transient test: it fills lwIP's
      per-socket receive mailbox and the WiFi RX buffers behind it.
"""

from __future__ import annotations

import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "41641"))


def vec(name: str) -> bytes:
    with open(os.path.join(HERE, name)) as f:
        return bytes.fromhex(f.read().strip())


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    dst = (sys.argv[1], PORT)
    mode = sys.argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if mode == "probe":
        ping = vec("udp_demux_ping.hex")
        init = vec("udp_demux_wg_init.hex")
        for label, data in (("disco PING", ping), ("WG init", init), ("junk", b"not a packet")):
            s.sendto(data, dst)
            print(f"sent {label} ({len(data)} B) -> {dst[0]}:{dst[1]}")
            time.sleep(0.2)
        return 0
    if mode == "burst":
        n = int(sys.argv[3])
        size = int(sys.argv[4]) if len(sys.argv) > 4 else 1400
        pps = float(sys.argv[5]) if len(sys.argv) > 5 else 0.0
        # WireGuard transport-data shape: type 4, 3 reserved zero bytes.
        payload = bytes([4, 0, 0, 0]) + os.urandom(max(size, 32) - 4)
        t0 = time.monotonic()
        for i in range(n):
            s.sendto(payload, dst)
            if pps > 0:
                target = t0 + (i + 1) / pps
                delay = target - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
        dt = time.monotonic() - t0
        print(f"sent {n} x {len(payload)} B -> {dst[0]}:{dst[1]} in {dt:.3f}s ({n / dt if dt else 0:.0f} pps)")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
