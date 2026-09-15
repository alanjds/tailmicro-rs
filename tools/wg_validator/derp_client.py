"""Independent, from-spec DERP relay client.

Connects to a Tailscale DERP server over TLS, performs the DERP client
handshake, and sends/receives relayed frames addressed to peers by their node
public key. Written from spec against the DERP wire format; cross-checked
against the Rust `tm_derp` crate in this workspace and the upstream
`tailscale-rs` `ts_transport_derp` reference (NOTE: `tm_derp`'s own Ping/Pong/
Health/Restarting frame-type constants are 0x40-0x43, which disagree with the
authoritative 0x12-0x15 -- see the validator report; not on this client's
critical path).

Handshake:
  1. TLS connect, then `GET /derp` HTTP/1.1 Upgrade: DERP -> 101.
  2. Read ServerKey frame (type 0x01): 8-byte magic "DERP🔑" + 32-byte server
     public key.
  3. Send ClientInfo frame (type 0x02): our node public key (32) + nonce (24) +
     NaCl crypto_box(SalsaBox)-sealed JSON `{"version":2,...}`.
  4. Read ServerInfo frame (type 0x03): nonce (24) + sealed JSON (decrypted to
     confirm the box round-trips).

Data:
  * SendPacket (0x04): dst node pubkey (32) + raw WireGuard packet bytes.
  * RecvPacket (0x05): src node pubkey (32) + raw WireGuard packet bytes.

Frames are `type(1) + length(4, big-endian) + body`.
"""

from __future__ import annotations

import json
import socket
import ssl
import struct

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random

DERP_MAGIC = bytes([0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91])  # "DERP🔑"
PROTOCOL_VERSION = 2

FRAME_SERVER_KEY = 0x01
FRAME_CLIENT_INFO = 0x02
FRAME_SERVER_INFO = 0x03
FRAME_SEND_PACKET = 0x04
FRAME_RECV_PACKET = 0x05
FRAME_KEEP_ALIVE = 0x06
FRAME_NOTE_PREFERRED = 0x07
FRAME_PEER_GONE = 0x08
FRAME_PEER_PRESENT = 0x09
FRAME_PING = 0x12
FRAME_PONG = 0x13
FRAME_HEALTH = 0x14
FRAME_RESTARTING = 0x15


class DerpClient:
    def __init__(self, host: str, node_priv: bytes, port: int = 443,
                 timeout: float = 20.0):
        self.host = host
        self.port = port
        self.node_priv = PrivateKey(node_priv)
        self.node_pub = bytes(self.node_priv.public_key)
        self.timeout = timeout
        self.sock: ssl.SSLSocket | None = None
        self.server_key: bytes | None = None
        self._buf = b""

    # ── low-level frame IO ────────────────────────────────────────────────────
    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65535)
            if not chunk:
                raise ConnectionError("EOF from DERP server")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def read_frame(self) -> tuple[int, bytes]:
        hdr = self._read_exact(5)
        ftype = hdr[0]
        length = struct.unpack(">I", hdr[1:5])[0]
        body = self._read_exact(length) if length else b""
        return ftype, body

    def write_frame(self, ftype: int, body: bytes) -> None:
        self.sock.sendall(bytes([ftype]) + struct.pack(">I", len(body)) + body)

    # ── handshake ──────────────────────────────────────────────────────────────
    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock.settimeout(self.timeout)

        req = (
            f"GET /derp HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: DERP\r\n"
            f"User-Agent: wg-validator/1.0\r\n\r\n"
        ).encode()
        self.sock.sendall(req)

        # Read HTTP/1.1 headers up to \r\n\r\n (byte-at-a-time to keep frame
        # bytes intact in self._buf).
        resp = b""
        while not resp.endswith(b"\r\n\r\n"):
            b = self.sock.recv(1)
            if not b:
                raise ConnectionError("EOF reading DERP upgrade response")
            resp += b
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"DERP upgrade rejected: {resp[:120]!r}")

        # ServerKey frame.
        ftype, body = self.read_frame()
        if ftype != FRAME_SERVER_KEY:
            raise ConnectionError(f"expected ServerKey, got frame type {ftype:#x}")
        if body[:8] != DERP_MAGIC:
            raise ConnectionError(f"bad DERP magic: {body[:8]!r}")
        self.server_key = body[8:40]

        # ClientInfo frame.
        box = Box(self.node_priv, PublicKey(self.server_key))
        nonce = nacl_random(24)
        payload = json.dumps({
            "version": PROTOCOL_VERSION,
            "canAckPings": True,
            "isProber": False,
        }).encode()
        sealed = box.encrypt(payload, nonce).ciphertext  # ciphertext only (nonce is separate field)
        self.write_frame(FRAME_CLIENT_INFO, self.node_pub + nonce + sealed)

        # ServerInfo frame.
        ftype, body = self.read_frame()
        if ftype != FRAME_SERVER_INFO:
            raise ConnectionError(f"expected ServerInfo, got frame type {ftype:#x}")
        si_nonce, si_ct = body[:24], body[24:]
        info_json = box.decrypt(si_ct, si_nonce)
        self.server_info = json.loads(info_json)

    # ── data plane ──────────────────────────────────────────────────────────────
    def send_packet(self, dst_key: bytes, packet: bytes) -> None:
        assert len(dst_key) == 32
        self.write_frame(FRAME_SEND_PACKET, dst_key + packet)

    def recv_packet(self, want_src: bytes | None = None, deadline_frames: int = 200):
        """Read frames until a RecvPacket arrives (optionally from want_src).

        Returns (src_key, packet). Auto-answers PING with PONG. Raises on
        timeout / connection loss. `deadline_frames` bounds keepalive churn.
        """
        for _ in range(deadline_frames):
            ftype, body = self.read_frame()
            if ftype == FRAME_RECV_PACKET:
                src, packet = body[:32], body[32:]
                if want_src is None or src == want_src:
                    return src, packet
            elif ftype == FRAME_PING:
                self.write_frame(FRAME_PONG, body[:8])
            elif ftype in (FRAME_KEEP_ALIVE, FRAME_HEALTH, FRAME_PEER_PRESENT,
                           FRAME_PEER_GONE, FRAME_NOTE_PREFERRED, FRAME_RESTARTING):
                continue
            # ignore anything else
        raise TimeoutError("no RecvPacket within frame budget")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
