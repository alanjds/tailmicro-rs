"""Direct-UDP live interop: from-spec WireGuard initiator vs a REAL Tailscale
peer, over DIRECT UDP — no DERP, no TLS.

Pivot spike (see derp_notls_spike.py: hosted DERP requires TLS, which the device
path avoids). Instead of relaying through DERP, we send the WireGuard handshake
initiation straight to a peer's advertised PUBLIC UDP endpoint. WireGuard is
roaming: the responder replies to the source address of the initiation, so only
the peer's NAT (not ours) has to admit our packet. If a peer with a full-cone /
port-forwarded public endpoint is reachable, this proves the whole data plane
without DERP.

Steps:
  1. ts2021 control: register + publish our disco key & endpoints + keepalive
     (so the peer's netmap contains our node key and it will answer our init).
  2. Pick online peers that advertise a PUBLIC IPv4 UDP endpoint.
  3. Open one UDP socket; send a disco PING then a WG Handshake Initiation to
     each candidate endpoint; retry.
  4. On a type-2 WG Handshake Response: complete the Noise key schedule, then
     send an ICMP echo inside a WG transport packet and await the reply.

Run:
  TS_ENV=/home/alanjds/src/tasmolike-rs/.env.wokwi \
  uv run --with cryptography --with h2 --with pynacl \
      python3 tools/wg_validator/validate_live_udp.py
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time

import wg_spec as wg
import ts_control as tc
import disco

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


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def icmp_echo_request(src_ip, dst_ip, ident, seq, payload):
    icmp = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = icmp[:2] + struct.pack(">H", _checksum(icmp)) + icmp[4:]
    total = 20 + len(icmp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 1, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]
    return ip + icmp


def ip_of(addrs):
    for a in addrs:
        host = a.split("/")[0]
        if ":" not in host:
            return host
    return None


# INCLUDE_PRIVATE=1 additionally offers RFC1918 IPv4 endpoints as targets — used
# only to prove the WireGuard-over-UDP bytes when the runner shares a LAN with a
# peer (isolating NAT traversal from the protocol); not representative of Wokwi.
INCLUDE_PRIVATE = os.environ.get("INCLUDE_PRIVATE") == "1"


def public_ipv4_endpoints(peer):
    out = []
    for ep in peer.endpoints:
        if ep.startswith("["):
            continue  # IPv6
        host, _, port = ep.rpartition(":")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if ip.version == 4 and (ip.is_global or (INCLUDE_PRIVATE and ip.is_private)):
            out.append((host, int(port)))
    return out


def main() -> int:
    auth_key = load_auth_key()
    results = []

    c = tc.TsControlClient()
    my_node_priv, my_node_pub = c.node_priv, c.node_pub
    my_disco_priv, my_disco_pub = c.disco_priv, c.disco_pub
    print(f"[..] our node key:  nodekey:{my_node_pub.hex()}")
    print(f"[..] our disco key: discokey:{my_disco_pub.hex()}")
    c.connect()
    reg = c.register(auth_key, hostname=HOSTNAME)
    if not reg.get("MachineAuthorized"):
        print("registration not authorized"); return 1

    mr = c.write_map(hostname=HOSTNAME)
    our_ip = ip_of(mr.our_addresses)
    online = [p for p in mr.peers
              if p.online and p.node_key and p.node_key != my_node_pub
              and p.hostname != HOSTNAME and public_ipv4_endpoints(p)]
    print(f"[..] our_ip={our_ip}; {len(online)} online peers with a public IPv4 endpoint")
    for p in online:
        print(f"      - {p.hostname}: {public_ipv4_endpoints(p)}")
    if not online:
        print("no direct-UDP candidate peers"); return 1

    # Publish our disco key + a plausible endpoint, keep online.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    my_port = sock.getsockname()[1]
    c.write_map(hostname=HOSTNAME, preferred_derp=online[0].derp_region,
                endpoints=[f"0.0.0.0:{my_port}"])
    c.start_keepalive_poll(hostname=HOSTNAME)
    print(f"[..] published; UDP socket bound to :{my_port}; waiting 8s for netmap propagation")
    time.sleep(8)

    # Build one (peer, endpoint) candidate list.
    cands = []
    for p in online:
        for host, port in public_ipv4_endpoints(p):
            cands.append((p, host, port))

    pending = {}  # sid -> (peer, noise_after, eph)

    def send_init(peer, host, port):
        sid = int.from_bytes(os.urandom(4), "little")
        eph = wg.X25519PrivateKey.generate().private_bytes_raw()
        ts = wg.tai64n_from_unix(int(time.time()), 0)
        wire, noise_after, _ = wg.build_initiation(my_node_priv, peer.node_key, eph, sid, ts)
        pending[sid] = (peer, noise_after, eph)
        sock.sendto(wire, (host, port))
        print(f"  -> WG init sid={sid:#010x} to {host}:{port} ({peer.hostname})")

    def send_disco(peer, host, port):
        tx = os.urandom(12)
        wire = disco.build_ping(my_disco_priv, my_disco_pub, peer.disco_key, tx, my_node_pub)
        sock.sendto(wire, (host, port))

    sock.settimeout(2.0)
    got_response = None
    end = time.time() + 45
    next_send = 0.0
    while time.time() < end and not got_response:
        if time.time() >= next_send:
            for p, host, port in cands:
                if p.disco_key:
                    send_disco(p, host, port)
                send_init(p, host, port)
            next_send = time.time() + 6
        try:
            data, src = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if not data:
            continue
        if disco.is_disco(data):
            opened = disco.open_disco(data, my_disco_priv)
            if opened:
                _, mtype, _, _ = opened
                print(f"  <- disco msg type={mtype} from {src}")
            continue
        if data[0] == wg.MSG_RESPONSE and len(data) == 92:
            sid = int.from_bytes(data[8:12], "little")
            if sid in pending:
                peer, na, eph = pending[sid]
                print(f"  <- WG Handshake Response (type 2) sid={sid:#010x} from {src} "
                      f"peer={peer.hostname}")
                got_response = (peer, data, na, eph, src)
                break
            print(f"  <- WG type-2 unknown sid={sid:#010x} from {src}")
        elif data[0] in (1, 2, 3, 4):
            print(f"  <- WG type={data[0]} len={len(data)} from {src}")

    results.append(("Direct-UDP WireGuard Handshake Response (type 2) from a real peer",
                    got_response is not None,
                    f"peer={got_response[0].hostname} src={got_response[4]}"
                    if got_response else "no type-2 response over direct UDP (see trace)"))
    if not got_response:
        return report(results, c, sock)

    peer, resp_wire, noise_after, eph_priv, src = got_response
    resp_eph = resp_wire[12:44]
    peer_index = int.from_bytes(resp_wire[4:8], "little")
    ni = noise_after
    ni.mix_hash(resp_eph); ni.mix_key(resp_eph)
    ni.mix_key(wg.x25519_dh(eph_priv, resp_eph))
    ni.mix_key(wg.x25519_dh(my_node_priv, resp_eph))
    ni.mix_psk(ZERO_PSK)
    auth_ok, detail = True, "empty-payload AEAD tag verified — key schedule complete"
    try:
        ni.decrypt(resp_wire[44:60])
    except Exception as e:  # noqa: BLE001
        auth_ok, detail = False, f"AEAD verify FAILED: {e!r}"
    results.append(("Response decrypts with a valid AEAD tag (crypto interop)", auth_ok, detail))
    if not auth_ok:
        return report(results, c, sock)
    k_i2r, k_r2i = ni.split()

    peer_ip = ip_of(peer.addresses)
    transport_ok = False
    tdetail = "no transport reply (peer may not answer ICMP; handshake already proven)"
    if our_ip and peer_ip:
        echo = icmp_echo_request(our_ip, peer_ip, 0x4242, 1, b"tm_wg-udp-validator")
        sock.sendto(wg.build_transport(k_i2r, peer_index, 0, echo), src)
        print(f"[..] sent ICMP echo to {peer_ip} in a WG transport packet over UDP -> {src}")
        deadline = time.time() + 10
        sock.settimeout(3)
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if not data or data[0] != wg.MSG_TRANSPORT:
                continue
            try:
                rid, ctr, pt = wg.decrypt_transport(k_r2i, data)
            except Exception:  # noqa: BLE001
                continue
            proto = pt[9] if len(pt) >= 20 else None
            itype = pt[20] if len(pt) >= 21 else None
            transport_ok = True
            tdetail = (f"decrypted reverse transport (counter={ctr}, {len(pt)} B inner IP, "
                       f"ip_proto={proto}, icmp_type={itype})")
            break
    results.append(("Transport data round-trip over direct UDP (bonus)", transport_ok, tdetail))
    return report(results, c, sock)


def report(results, c=None, sock=None) -> int:
    for obj in (c, sock):
        try:
            if obj is c and c is not None:
                c.stop_keepalive_poll()
            elif obj is not None:
                obj.close()
        except Exception:  # noqa: BLE001
            pass
    print("=" * 80)
    ok = True
    for name, passed, detail in results:
        ok = ok and passed
        print(f"[{PASS if passed else FAIL}] {name}")
        if detail:
            print(f"        {detail}")
    print("=" * 80)
    print("DIRECT-UDP INTEROP CONFIRMED" if ok else "STOPPED — see last rung")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
