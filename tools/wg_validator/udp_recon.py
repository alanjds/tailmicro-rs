"""Direct-UDP feasibility recon (no TLS, no DERP).

Pivot spike: the hosted Tailscale DERP requires TLS (see derp_notls_spike.py),
which this project's device path must avoid. Fallback plan is to drive tm_wg's
WireGuard handshake + a transport packet over DIRECT UDP to a peer that
advertises a publicly reachable UDP endpoint, skipping DERP entirely.

This recon registers the ephemeral wg-validator-probe node, fetches the live
MapResponse, and prints every online non-self peer's advertised UDP `Endpoints`
(and Addresses), classifying each endpoint as PUBLIC (globally routable) vs
private/CGNAT/link-local. A peer with a PUBLIC endpoint is a candidate for the
direct-UDP acceptance test.

Never prints the auth key. Run:
  uv run --with cryptography --with h2 --with pynacl \
      python3 tools/wg_validator/udp_recon.py
"""

from __future__ import annotations

import ipaddress
import os
import time

import ts_control as tc

HOSTNAME = "wg-validator-probe"


def load_auth_key() -> str:
    envs = [os.environ["TS_ENV"]] if os.environ.get("TS_ENV") else [
        "/home/alanjds/src/tasmolike-rs/.env",
        "/home/alanjds/src/tasmolike-rs/.env.aj2004",
        "/home/alanjds/src/tasmolike-rs/.env.wokwi",
    ]
    for p in envs:
        if not os.path.exists(p):
            continue
        for line in open(p):
            line = line.strip()
            if line.startswith("TAILSCALE_AUTH_KEY="):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v:
                    return v
    raise SystemExit("no TAILSCALE_AUTH_KEY found in env files")


def classify(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "not-an-ip"
    if ip.version == 4 and ipaddress.ip_address("100.64.0.0") <= ip <= ipaddress.ip_address("100.127.255.255"):
        return "CGNAT(100.64/10 = tailnet addr, not routable)"
    if ip.is_private:
        return "PRIVATE(RFC1918/local)"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_global:
        return "PUBLIC"
    return "other"


def main() -> int:
    auth_key = load_auth_key()
    c = tc.TsControlClient()
    print(f"[..] our node key:  nodekey:{c.node_pub.hex()}")
    c.connect()
    reg = c.register(auth_key, hostname=HOSTNAME)
    print(f"[..] registered: MachineAuthorized={reg.get('MachineAuthorized')}")

    mr = c.write_map(hostname=HOSTNAME)
    # A short second poll: endpoints often arrive on a follow-up netmap.
    time.sleep(3)
    try:
        mr = c.map(hostname=HOSTNAME)
    except Exception as exc:  # noqa: BLE001
        print(f"[..] follow-up map poll failed (using first map): {exc}")

    online = [p for p in mr.peers
              if p.online and p.node_key and p.node_key != c.node_pub
              and p.hostname != HOSTNAME]
    print(f"\n=== {len(mr.peers)} peers, {len(online)} online (non-self) ===")
    candidates = 0
    for p in mr.peers:
        tag = "ONLINE" if p.online else "offline"
        self_or_probe = (p.node_key == c.node_pub or p.hostname == HOSTNAME)
        print(f"\n peer {p.hostname!r} [{tag}]"
              f"{' (self/probe)' if self_or_probe else ''}"
              f" derp_region={p.derp_region} disco={'yes' if p.disco_key else 'no'}")
        print(f"   addresses={p.addresses}")
        if not p.endpoints:
            print("   endpoints=[]  (none advertised — needs NAT traversal/DERP)")
        for ep in p.endpoints:
            hostpart = ep.rsplit(":", 1)[0].strip("[]")
            cls = classify(hostpart)
            marker = "  <== DIRECT-UDP CANDIDATE" if (cls == "PUBLIC" and p.online and not self_or_probe) else ""
            if marker:
                candidates += 1
            print(f"   endpoint {ep}  -> {cls}{marker}")

    print(f"\n=== direct-UDP candidates (online, public endpoint): {candidates} ===")
    try:
        c.stop_keepalive_poll()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
