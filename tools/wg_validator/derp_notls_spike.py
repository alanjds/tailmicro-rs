"""Spike: does the hosted Tailscale DERP accept a NON-TLS `GET /derp` upgrade?

Motivation: this project deliberately avoids TLS on the device (the control
plane runs over plain TCP + Noise_IK, pinned by the control key). DERP is the
last thing still on TLS. All traffic DERP relays is already end-to-end
encrypted (WireGuard + disco crypto_box), and DERP has its own
ServerKey/ClientInfo/ServerInfo NaCl-box handshake, so the *outer* TLS might be
removable. This spike tests that hypothesis against the REAL Tailscale DERP
servers, before committing any Rust.

It does NOT need PyNaCl: the HTTP/1.1 Upgrade handshake happens before any DERP
crypto, so the 101-vs-redirect/400 answer alone decides the architecture.

Run: python3 derp_notls_spike.py [host ...]
Default hosts are a sample of hosted Tailscale DERP servers; pass the target
peer's home DERP hostname (from the DERPMap, ts_control.MapResult.derp_hostnames)
to test the exact server a given peer uses.

RESULT (2026-09-16, against derp1/derp2/derp10.tailscale.com):
  * plain TCP  :80   GET /derp -> HTTP/1.1 302 Found, Location: https://<h>/derp
                                  (server refuses plaintext upgrade; redirects)
  * plaintext  :443  GET /derp -> HTTP/1.0 400 Bad Request  (TLS listener)
  * TLS        :443  GET /derp -> HTTP/1.1 101 Switching Protocols, then the
                                  DERP ServerKey frame (01 00000028 "DERP<f0..>")
  => Hosted Tailscale DERP REQUIRES TLS. There is no non-TLS /derp path.
"""

from __future__ import annotations

import socket
import ssl
import sys

DERP_MAGIC_HEX = "44455250f09f9491"  # "DERP" + U+1F511 (🔑) in UTF-8


def probe(host: str, port: int, use_tls: bool, label: str) -> None:
    try:
        raw = socket.create_connection((host, port), timeout=10)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.settimeout(10)
        req = (
            f"GET /derp HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: DERP\r\n"
            f"User-Agent: wg-validator-spike/1.0\r\n\r\n"
        ).encode()
        sock.sendall(req)

        resp = b""
        try:
            while b"\r\n\r\n" not in resp and len(resp) < 4096:
                chunk = sock.recv(256)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass

        status = resp.split(b"\r\n", 1)[0]
        print(f"[{label}] {host}:{port} tls={use_tls} -> {status.decode(errors='replace')}")

        if b"101" in status:
            try:
                sock.settimeout(5)
                extra = sock.recv(64)
            except Exception:
                extra = b""
            if extra:
                is_derp = extra[5:5 + 8].hex() == DERP_MAGIC_HEX
                print(f"        post-upgrade bytes[:16]={extra[:16].hex()} "
                      f"(DERP ServerKey frame={is_derp})")
        for hl in resp.split(b"\r\n")[1:8]:
            if hl.lower().startswith((b"location:", b"content-type:")):
                print(f"        {hl.decode(errors='replace')}")
        sock.close()
    except Exception as exc:  # noqa: BLE001 - spike: report every failure mode
        print(f"[{label}] {host}:{port} tls={use_tls} -> ERROR "
              f"{type(exc).__name__}: {exc}")


def main() -> None:
    hosts = sys.argv[1:] or [
        "derp1.tailscale.com",
        "derp2.tailscale.com",
        "derp10.tailscale.com",
    ]
    for host in hosts:
        probe(host, 80, False, "plain80")
        probe(host, 443, False, "plaintext443")
        probe(host, 443, True, "tls443")
        print("-" * 60)


if __name__ == "__main__":
    main()
