"""Step 0 of docs/lan-direct-path-plan.md: corrected LAN-direct-UDP spike.

Redoes the old "Spike 2" (docs/wg-dataplane-notes.md, 2026-09-16 update)
properly. Spike 2 showed disco PING/PONG round-tripped over plain UDP against
a real peer, but never proved the WireGuard handshake because its harness had
two bugs, not because the mechanism is unsound (see
docs/lan-direct-path-plan.md, "Spike 2, re-read: what actually failed"):

  1. It published `endpoints=[f"0.0.0.0:{my_port}"]` -- not a usable address.
  2. It received the peer's disco PING and only printed it. It never answered
     with a PONG, so the peer's magicsock never trusted our path.

This script fixes both:
  1. Learns our real, reachable LAN IPv4 address the same way
     `tm_control::bring_up` (D1 in the plan) will: the source address the
     control-plane TCP socket picked to reach the control server
     (`sock.getsockname()`), filtered to reject IPv6, unspecified, loopback,
     and the tailnet's own 100.64.0.0/10 CGNAT range. Publishes
     `endpoints=[f"{lan_ip}:{UDP_PORT}", f"127.3.3.40:{region}"]`.
  2. Answers every UDP disco PING from an allowlisted peer's disco key with a
     real, sealed `disco.build_pong(..., src_endpoint=<peer's observed UDP
     source address>)`, sent back over the SAME UDP socket the PING arrived
     on -- not the DERP-relay `127.3.3.40:<region>` convention.
  3. Also brings up the DERP leg (`derp_client.py`) so a WireGuard handshake
     response has a path either way, exactly like a real Tailscale node.

Pass criteria (from the plan): from a LAN peer sharing our subnet,
`tailscale ping <this-node>` reports `via <lan_ip>:<UDP_PORT>`, `tailscale
status` shows `direct`, and a WireGuard handshake the peer initiates arrives
on our UDP socket. Absent a live `tailscale` CLI to assert that from the peer
side, this script's own pass bar is: we receive, on the UDP socket, either
(a) a disco PING for our node's disco key (then we answer with a PONG and
keep listening for a WireGuard Handshake Initiation), or (b) a WireGuard
Handshake Initiation directly. Either one, arriving over UDP (not DERP), is
the same evidence the plan's Step 5/6 hardware acceptance test looks for.

**Known environment constraint (recorded here, not papered over):** this
script's D1 IPv4 filter can legitimately find NO usable LAN address to
publish -- e.g. an IPv6-only host with no local IPv4 route at all. When that
happens the script reports BLOCKED rather than faking an address (the same
"a bad endpoint cannot make the device unreachable, but an unreachable
endpoint proves nothing either" principle as D2). See the "Step 0 status"
section appended to docs/lan-direct-path-plan.md for what was actually
observed when this was run.

Run:
  TS_ENV=/home/alanjds/src/tasmolike-rs/.env.wokwi \
  PEER_HOSTNAME=lenovopill \
  uv run --with cryptography --with h2 --with pynacl \
      python3 tools/wg_validator/validate_lan_direct.py
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time

import derp_client as derp
import disco
import ts_control as tc

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
BLOCKED = "\033[33mBLOCKED\033[0m"
HOSTNAME = "wg-lan-direct-probe"
UDP_PORT = 41641
TAILNET_CGNAT = ipaddress.ip_network("100.64.0.0/10")


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


def d1_lan_ip(sockname_ip: str) -> str | None:
    """D1 filter (docs/lan-direct-path-plan.md): IPv4, not unspecified, not
    loopback, not 100.64.0.0/10 (never advertise a tailnet address as an
    underlay endpoint). RFC1918 is fine; so is a public LAN IP."""
    try:
        ip = ipaddress.ip_address(sockname_ip)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    if ip.is_unspecified or ip.is_loopback:
        return None
    if ip in TAILNET_CGNAT:
        return None
    return str(ip)


def report(results: list[tuple[str, object, str]]) -> int:
    print("=" * 80)
    ok = True
    blocked = False
    for name, status, detail in results:
        label = {True: PASS, False: FAIL, None: BLOCKED}[status]
        ok = ok and (status is True)
        blocked = blocked or (status is None)
        print(f"[{label}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 80)
    if blocked:
        print("STEP 0 BLOCKED — see BLOCKED rung(s) above; not a protocol failure")
        return 2
    print("STEP 0 CONFIRMED" if ok else "STEP 0 FAILED — see plan's stopping rule")
    return 0 if ok else 1


def main() -> int:
    results: list[tuple[str, object, str]] = []
    auth_key = load_auth_key()

    c = tc.TsControlClient()
    print(f"[..] our node key:  nodekey:{c.node_pub.hex()}")
    print(f"[..] our disco key: discokey:{c.disco_pub.hex()}")
    c.connect()
    reg = c.register(auth_key, hostname=HOSTNAME)
    if not reg.get("MachineAuthorized"):
        results.append(("Control-plane registration authorized", False,
                         f"MachineAuthorized=False: {reg}"))
        return report(results)
    results.append(("Control-plane registration authorized", True, ""))

    # First map (no endpoints yet) just to learn peers + DERP hostnames.
    mr = c.write_map(hostname=HOSTNAME)
    online = [p for p in mr.peers if p.online and p.node_key != c.node_pub]
    print(f"[..] {len(online)} other online peers in this tailnet")
    for p in online:
        print(f"      - {p.hostname} region={p.derp_region} "
              f"disco={'yes' if p.disco_key else 'no'}")

    target_hostname = os.environ.get("PEER_HOSTNAME")
    target = None
    if target_hostname:
        target = next((p for p in online if p.hostname == target_hostname), None)
        if target is None:
            print(f"[!!] PEER_HOSTNAME={target_hostname!r} not found among "
                  f"online peers; proceeding without a specific allowlist target")
    if target is None and online:
        target = online[0]
    if target is None:
        results.append(("A real online tailnet peer is available to test against",
                         False, "no online peers in this tailnet right now"))
        return report(results)
    print(f"[..] target peer: {target.hostname} "
          f"(nodekey:{target.node_key.hex()[:16]}…, region {target.derp_region})")

    # D1: derive our LAN IPv4 from the control TCP socket's local_addr.
    control_sock = c.h2.t.sock
    sockname = control_sock.getsockname()
    lan_ip = d1_lan_ip(sockname[0])
    print(f"[..] control-plane TCP local_addr={sockname} -> D1 lan_ip={lan_ip}")
    if lan_ip is None:
        results.append((
            "D1: a usable IPv4 LAN address is derivable from this host's "
            "control-plane socket",
            None,
            f"local_addr={sockname} was rejected (not IPv4 / loopback / "
            f"unspecified / tailnet CGNAT). This host has no IPv4 route at "
            f"all in this environment (see the status note in "
            f"docs/lan-direct-path-plan.md) -- a genuine environment "
            f"scoping constraint, not a disco/WireGuard protocol failure. "
            f"Re-run this script from a host with a real IPv4 LAN interface "
            f"(e.g. one sharing a subnet with {target.hostname}) to exercise "
            f"the rest of Step 0."))
        return report(results)
    results.append(("D1: usable IPv4 LAN address derived from control socket",
                     True, f"{lan_ip}"))

    region = target.derp_region or next(iter(mr.derp_hostnames), 0)
    derp_host = mr.derp_hostnames.get(region)

    # Bind the real UDP socket before publishing it (Step 0 mirrors D4's
    # ordering: never publish an endpoint that isn't already listening).
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.bind(("0.0.0.0", UDP_PORT))
        bound_port = UDP_PORT
    except OSError as e:
        print(f"[!!] bind :{UDP_PORT} failed ({e}); falling back to an ephemeral port")
        udp.bind(("0.0.0.0", 0))
        bound_port = udp.getsockname()[1]
    udp.settimeout(1.0)
    print(f"[..] UDP socket bound to 0.0.0.0:{bound_port}")

    endpoints = [f"{lan_ip}:{bound_port}", f"127.3.3.40:{region}"]
    c.write_map(hostname=HOSTNAME, preferred_derp=region, endpoints=endpoints)
    c.start_keepalive_poll(hostname=HOSTNAME)
    print(f"[..] published endpoints={endpoints}, preferred_derp={region}")

    # Bring up the DERP leg too (D4 spirit: a real node always keeps DERP as
    # fallback; Step 0 does the same so a WG response has a path either way).
    derp_ok = False
    dc = None
    if derp_host:
        try:
            dc = derp.DerpClient(derp_host, c.node_priv)
            dc.connect(minimal_tls=True)
            derp_ok = True
        except Exception as e:  # noqa: BLE001
            print(f"[!!] DERP leg to {derp_host} failed: {e!r}")
    results.append(("DERP fallback leg connects (region "
                     f"{region}, {derp_host})", derp_ok,
                     "" if derp_ok else "see log above"))

    print(f"[..] waiting up to 60s for {target.hostname}'s disco PING / WG "
          f"init to arrive over UDP on :{bound_port} "
          f"(the peer only sends one after netmap propagation, which can "
          f"take several seconds to tens of seconds)")

    got_udp_ping = False
    got_udp_wg_init = False
    last_peer_addr = None
    deadline = time.time() + 60
    while time.time() < deadline and not (got_udp_ping and got_udp_wg_init):
        try:
            data, src = udp.recvfrom(2048)
        except socket.timeout:
            continue
        if not data:
            continue
        if disco.is_disco(data):
            opened = disco.open_disco(data, c.disco_priv)
            if not opened:
                print(f"  <- undecryptable disco datagram from {src} (not from an allowlisted key)")
                continue
            sender_pub, mtype, _ver, body = opened
            if sender_pub != target.disco_key:
                print(f"  <- disco msg type={mtype} from {src} but NOT the allowlisted peer's disco key; ignoring")
                continue
            if mtype == disco.MSG_PING and len(body) >= 12:
                tx_id = body[:12]
                got_udp_ping = True
                last_peer_addr = src
                print(f"  <- disco PING (tx_id={tx_id.hex()}) from {target.hostname} at {src} over UDP")
                pong = disco.build_pong(
                    c.disco_priv, c.disco_pub, target.disco_key, tx_id,
                    src_endpoint=disco.pack_endpoint(src[0], src[1]),
                )
                udp.sendto(pong, src)
                print(f"  -> disco PONG to {src} over UDP "
                      f"(src_endpoint={src[0]}:{src[1]}, the peer's OWN observed address)")
            elif mtype == disco.MSG_PONG:
                print(f"  <- disco PONG from {target.hostname} at {src} over UDP")
            else:
                print(f"  <- disco msg type={mtype} from {target.hostname} at {src}")
            continue
        if data[0] in (1, 2, 3, 4):
            print(f"  <- WG type={data[0]} len={len(data)} from {src} over UDP")
            if data[0] == 1:  # Handshake Initiation
                got_udp_wg_init = True
                last_peer_addr = src

    results.append((
        f"Received a disco PING from {target.hostname} over real UDP (not DERP) "
        "and answered it with a valid sealed PONG",
        got_udp_ping,
        f"peer addr={last_peer_addr}" if got_udp_ping else
        "no disco PING arrived on the UDP socket within 60s"))
    results.append((
        f"Received a WireGuard Handshake Initiation from {target.hostname} over "
        "UDP (the actual Step 0 stopping-condition evidence: a real peer moved "
        "its data path off DERP)",
        got_udp_wg_init,
        f"peer addr={last_peer_addr}" if got_udp_wg_init else
        "no WG type=1 packet arrived on the UDP socket within 60s -- if a PING "
        "did arrive and got a PONG, re-run with a longer wait; magicsock can "
        "take 10s+ after a trusted PONG before it moves WireGuard traffic"))

    try:
        c.stop_keepalive_poll()
    except Exception:  # noqa: BLE001
        pass
    if dc:
        dc.close()
    udp.close()
    return report(results)


if __name__ == "__main__":
    raise SystemExit(main())
