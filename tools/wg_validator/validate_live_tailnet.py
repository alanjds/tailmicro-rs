#!/usr/bin/env python3
"""LIVE end-to-end validation: from-spec Python WireGuard initiator vs. a REAL
Tailscale peer on the live tailnet, relayed through DERP.

This is the missing rung the prior passes could not reach: `wg_spec.py` was
proven byte-for-byte and against boringtun over loopback, but never against
Tailscale itself. This driver:

  1. ts2021 control plane (`ts_control.py`): Noise IK handshake, register a node
     with the auth key, MapRequest -> peer list (node key, DERP home, disco key,
     addresses, online) + DERPMap.
  2. Picks an ONLINE peer.
  3. DERP relay (`derp_client.py`): connect to the peer's home DERP region.
  4. Wakes the peer's lazy wireguard config with a from-spec disco PING
     (`disco.py`), then drives `wg_spec.py`'s initiator THROUGH DERP: sends a
     real Handshake Initiation, receives + verifies the real type-2 Handshake
     Response, completes the key schedule.
  5. Attempts a transport-data exchange (an ICMP echo to the peer's tailnet IP).

Run:
  uv run --with cryptography --with h2 --with pynacl \
    python3 tools/wg_validator/validate_live_tailnet.py

No secrets are printed. Registers a node named "wg-validator-probe" on the
tailnet -- remove it afterwards from https://login.tailscale.com/admin/machines
if the auth key is not ephemeral.
"""

from __future__ import annotations

import os
import socket as _socket
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wg_spec as wg
import ts_control as tc
import disco
from derp_client import DerpClient

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

HOSTNAME = "wg-validator-probe"
ZERO_PSK = b"\x00" * 32


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


# ── minimal IPv4/ICMP builders (for the transport-data exchange) ───────────────
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def icmp_echo_request(src_ip: str, dst_ip: str, ident: int, seq: int, payload: bytes) -> bytes:
    icmp = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = icmp[:2] + struct.pack(">H", _checksum(icmp)) + icmp[4:]
    total = 20 + len(icmp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 1, 0,
                     _socket.inet_aton(src_ip), _socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]
    return ip + icmp


def ip_of(addrs: list[str]) -> str | None:
    for a in addrs:
        host = a.split("/")[0]
        if ":" not in host:
            return host
    return None


def main() -> int:
    auth_key = load_auth_key()
    results: list[tuple[str, bool, str]] = []

    # ── Rung 1: control handshake + registration ──────────────────────────────
    c = tc.TsControlClient()
    my_node_priv, my_node_pub = c.node_priv, c.node_pub
    my_disco_priv, my_disco_pub = c.disco_priv, c.disco_pub
    print(f"[..] our node key:  nodekey:{my_node_pub.hex()}")
    print(f"[..] our disco key: discokey:{my_disco_pub.hex()}")
    c.connect()
    results.append(("ts2021 Noise IK control handshake + transport established", True,
                    f"server key mkey:{tc.fetch_server_key(c.host).hex()[:16]}..."))
    reg = c.register(auth_key, hostname=HOSTNAME)
    ok = bool(reg.get("MachineAuthorized"))
    results.append(("Node registered on the live tailnet (MachineAuthorized)", ok,
                    f"MachineAuthorized={reg.get('MachineAuthorized')}"))
    if not ok:
        return report(results)

    # ── Rung 2: MapResponse peer list ─────────────────────────────────────────
    # A non-streaming ("write") MapRequest: publishes our disco key and returns
    # the peer list. A streaming request would be read-only (disco key ignored).
    mr = c.write_map(hostname=HOSTNAME)
    our_ip = ip_of(mr.our_addresses)
    online = [p for p in mr.peers
              if p.online and p.node_key and p.node_key != my_node_pub
              and p.hostname != HOSTNAME]
    results.append((f"MapResponse parsed: our_ip={our_ip}, {len(mr.peers)} peers, "
                    f"{len(online)} online (non-self)", len(online) > 0,
                    "online: " + ", ".join(f"{p.hostname}(derp{p.derp_region})" for p in online)))
    if not online:
        print("No online non-self peers to handshake against.")
        return report(results)

    # Prefer an online peer with a resolvable DERP home and a disco key.
    def score(p):
        return (p.derp_region not in mr.derp_hostnames, p.disco_key == b"", not p.endpoints)
    peer = sorted(online, key=score)[0]
    derp_host = mr.derp_hostnames.get(peer.derp_region)
    print(f"[..] target peer: host={peer.hostname!r}")
    print(f"     nodekey={peer.node_key.hex()}")
    print(f"     discokey={peer.disco_key.hex()} derp_region={peer.derp_region} ({derp_host})")

    # Republish our disco key with PreferredDERP = the peer's home region, so
    # control tells peers to reach us over that DERP region, and keep an online
    # keepalive poll running so the peer keeps seeing us as online.
    c.write_map(hostname=HOSTNAME, preferred_derp=peer.derp_region,
                endpoints=[f"127.3.3.40:{peer.derp_region}"])
    c.start_keepalive_poll(hostname=HOSTNAME)
    print(f"[..] published disco key + PreferredDERP={peer.derp_region}; "
          f"waiting 12s for netmap propagation to peers")
    time.sleep(12)

    # ── Rung 3: DERP connect ──────────────────────────────────────────────────
    derp = DerpClient(derp_host, my_node_priv)
    derp.connect()
    results.append((f"DERP handshake with {derp_host} (peer home region {peer.derp_region})",
                    True, f"server_key={derp.server_key.hex()[:16]}... "
                    f"proto={derp.server_info.get('version')}"))

    # ── Rung 4: disco wake + relayed WireGuard handshake ──────────────────────
    resp_wire, matched = drive_handshake(derp, peer, my_node_priv, my_node_pub,
                                         my_disco_priv, my_disco_pub)
    results.append(("REAL Tailscale peer returned a WireGuard Handshake Response "
                    "(type 2, 92 B) over DERP", resp_wire is not None,
                    f"response bytes: {resp_wire.hex()}" if resp_wire else
                    "no type-2 response received (see stdout trace)"))
    if resp_wire is None:
        return report(results, [c, derp])

    noise_after, eph_priv, session_id = matched
    resp_eph = resp_wire[12:44]
    peer_index = int.from_bytes(resp_wire[4:8], "little")
    ni = noise_after
    ni.mix_hash(resp_eph)
    ni.mix_key(resp_eph)
    ni.mix_key(wg.x25519_dh(eph_priv, resp_eph))       # ee
    ni.mix_key(wg.x25519_dh(my_node_priv, resp_eph))   # se
    ni.mix_psk(ZERO_PSK)
    auth_ok, detail = True, "empty-payload AEAD tag verified — key schedule complete"
    try:
        ni.decrypt(resp_wire[44:60])
    except Exception as e:  # noqa: BLE001
        auth_ok, detail = False, f"AEAD tag verify FAILED: {e!r}"
    results.append(("Handshake Response decrypts with a valid AEAD tag "
                    "(cryptographic interop confirmed)", auth_ok, detail))
    if not auth_ok:
        return report(results, [c, derp])
    k_i2r, k_r2i = ni.split()

    # ── Rung 5: transport data (ICMP echo to the peer's tailnet IP) ────────────
    peer_ip = ip_of(peer.addresses)
    transport_ok = False
    tdetail = "no transport reply (peer may not answer ICMP; handshake already proven)"
    if our_ip and peer_ip:
        echo = icmp_echo_request(our_ip, peer_ip, 0x4242, 1, b"tm_wg-live-validator")
        derp.send_packet(peer.node_key, wg.build_transport(k_i2r, peer_index, 0, echo))
        print(f"[..] sent {len(echo)}-byte ICMP echo to {peer_ip} in a WG transport packet")
        derp.sock.settimeout(3)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                ft, body = derp.read_frame()
            except Exception:  # noqa: BLE001
                continue
            if ft != 0x05 or body[:32] != peer.node_key:
                if ft == 0x12:
                    derp.write_frame(0x13, body[:8])
                continue
            pkt = body[32:]
            if not pkt or pkt[0] != wg.MSG_TRANSPORT:
                continue
            try:
                rid, ctr, pt = wg.decrypt_transport(k_r2i, pkt)
            except Exception:  # noqa: BLE001
                continue
            proto = pt[9] if len(pt) >= 20 else None
            icmp_type = pt[20] if len(pt) >= 21 else None
            transport_ok = True
            tdetail = (f"decrypted reverse-direction transport packet (counter={ctr}, "
                       f"{len(pt)} B inner IP, ip_proto={proto}, icmp_type={icmp_type})")
            break
    results.append(("Transport data round-trip with the real peer (bonus)", transport_ok, tdetail))

    return report(results, [c, derp])


def drive_handshake(derp, peer, my_node_priv, my_node_pub, my_disco_priv, my_disco_pub):
    """Send a disco ping to wake the peer's WG config, then WG inits; return
    (response_wire, (noise_after, eph_priv, session_id)) or (None, None)."""
    pending: dict[int, tuple] = {}  # session_id -> (noise_after, eph_priv)
    derp.sock.settimeout(2)

    def send_ping():
        tx = os.urandom(12)
        derp.send_packet(peer.node_key, disco.build_ping(
            my_disco_priv, my_disco_pub, peer.disco_key, tx, my_node_pub))
        print("  -> disco PING")

    def send_init():
        sid = int.from_bytes(os.urandom(4), "little")
        eph = wg.X25519PrivateKey.generate().private_bytes_raw()
        ts = wg.tai64n_from_unix(int(time.time()), 0)
        wire, noise_after, _ = wg.build_initiation(my_node_priv, peer.node_key, eph, sid, ts)
        pending[sid] = (noise_after, eph)
        derp.send_packet(peer.node_key, wire)
        print(f"  -> WG Handshake Initiation (session {sid:#010x})")

    if peer.disco_key:
        send_ping()
        time.sleep(1.0)
    send_init()

    end = time.time() + 40
    next_action = time.time() + 5
    while time.time() < end:
        if time.time() >= next_action:
            if peer.disco_key:
                send_ping()
            send_init()
            next_action = time.time() + 6
        try:
            ft, body = derp.read_frame()
        except Exception:  # noqa: BLE001
            continue
        if ft == 0x12:  # DERP Ping -> Pong
            derp.write_frame(0x13, body[:8])
            continue
        if ft != 0x05:  # not RecvPacket
            continue
        src, pkt = body[:32], body[32:]
        if not pkt:
            continue
        if disco.is_disco(pkt):
            opened = disco.open_disco(pkt, my_disco_priv)
            if opened:
                _, mtype, _, dbody = opened
                if mtype == disco.MSG_PING:
                    tx = dbody[:12]
                    derp.send_packet(src, disco.build_pong(
                        my_disco_priv, my_disco_pub, peer.disco_key, tx))
                    print("  <- disco PING; -> disco PONG")
                elif mtype == disco.MSG_PONG:
                    print("  <- disco PONG (path confirmed by peer)")
                elif mtype == disco.MSG_CALL_ME_MAYBE:
                    print("  <- disco CallMeMaybe")
            continue
        if pkt[0] == wg.MSG_RESPONSE and len(pkt) == 92:
            sid = int.from_bytes(pkt[8:12], "little")
            if sid in pending:
                print(f"  <- WG Handshake Response (type 2) for session {sid:#010x}")
                na, eph = pending[sid]
                return pkt, (na, eph, sid)
            print(f"  <- WG type-2 for unknown session {sid:#010x}")
        elif pkt[0] in (1, 2, 3, 4):
            print(f"  <- relayed WG packet type={pkt[0]} len={len(pkt)}")
    return None, None


def report(results, closers=()) -> int:
    for obj in closers:
        try:
            if hasattr(obj, "close"):
                obj.close()
        except Exception:  # noqa: BLE001
            pass
    print("=" * 80)
    print("LIVE tailnet interop: from-spec Python WireGuard initiator vs. a REAL Tailscale peer")
    print("(relayed through DERP; control plane + DERP + disco all from-spec, independent)")
    print("=" * 80)
    ok = True
    for name, passed, detail in results:
        ok = ok and passed
        print(f"[{PASS if passed else FAIL}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 80)
    print("LIVE PEER INTEROP CONFIRMED" if ok else "PIPELINE STOPPED — see the last rung above")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
