"""Independent, from-spec ts2021 control-plane client.

Implements the Tailscale control protocol client end-to-end, from scratch,
against the WireGuard/Tailscale wire format and the byte-level findings in
`docs/noise-handshake-wire-format.md`. It deliberately shares no code with the
Rust `tm_control` crate: the whole point is an *independent* oracle that could
catch a wire-format/crypto bug uniformly wrong on both the Rust encode and
decode sides.

Layers implemented here from spec:
  * Noise_IK_25519_ChaChaPoly_BLAKE2s handshake (initiator) -- distinct from
    the WireGuard Noise_IKpsk2 in `wg_spec.py`: different construction string,
    no PSK, IK pre-message = responder static only. The X25519 / ChaCha20Poly1305
    / blake2s / HKDF primitives are the from-spec helpers reused from wg_spec.
  * The ts2021 transport codec: 3-byte Record framing (type 0x04 + 2-byte BE
    length) and a 12-byte ChaCha20Poly1305 nonce of 4 zero bytes + an 8-byte
    BIG-endian counter (the control plane's deviation from Noise's little-endian
    default; the WireGuard data plane uses little-endian -- a real cross-layer
    trap, see wg_spec.transport_nonce).
  * The HTTP/1.1 `POST /ts2021` upgrade with the wire-framed init message in
    the base64 `X-Tailscale-Handshake` header.
  * HTTP/2 over the Noise transport (via the sans-IO `h2` library): register
    on stream 1, MapRequest (streaming) on stream 3.
  * MapResponse parsing: peers (node key, disco key, DERP home, addresses,
    online), and the DERPMap regions -> hostnames.

The control server's Noise static public key is fetched from `GET /key?v=<cap>`
(the `publicKey` mkey), matching what `tm_control::pin` verifies out of band.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import urllib.request
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import wg_spec as wg  # reuse the from-spec X25519 / blake2s / HKDF primitives

# ── ts2021 constants ──────────────────────────────────────────────────────────
NOISE_IK_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
CAP_VERSION = 72  # matches tm_control::CAPABILITY_VERSION

MSG_TYPE_INITIATION = 0x01
MSG_TYPE_RESPONSE = 0x02
MSG_TYPE_ERROR = 0x03
MSG_TYPE_RECORD = 0x04

# The optional post-handshake challenge packet's magic (a Record payload).
CHALLENGE_MAGIC = b"\xff\xff\xff" b"TS"


def be_nonce(counter: int) -> bytes:
    """ts2021 transport nonce: 4 zero bytes + 8-byte BIG-endian counter."""
    return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)


# ── Noise IK initiator (from spec) ──────────────────────────────────────────────
class NoiseIK:
    """Minimal Noise_IK initiator, exactly as the ts2021 control base uses it."""

    def __init__(self, prologue: bytes, responder_static_pub: bytes):
        h = wg.blake2s(NOISE_IK_NAME)  # name is 33 bytes > 32 -> HASH(name)
        self.ck = h
        self.h = wg.blake2s(h + prologue)          # MixHash(prologue)
        self.h = wg.blake2s(self.h + responder_static_pub)  # pre-message: rs
        self.k: bytes | None = None

    def _mix_hash(self, data: bytes) -> None:
        self.h = wg.blake2s(self.h + data)

    def _mix_key(self, key_material: bytes) -> None:
        self.ck, self.k = wg.hkdf(self.ck, key_material, 2)

    def _encrypt(self, plaintext: bytes) -> bytes:
        ct = ChaCha20Poly1305(self.k).encrypt(b"\x00" * 12, plaintext, self.h)
        self._mix_hash(ct)
        return ct

    def _decrypt(self, ciphertext: bytes) -> bytes:
        pt = ChaCha20Poly1305(self.k).decrypt(b"\x00" * 12, ciphertext, self.h)
        self._mix_hash(ciphertext)
        return pt

    def write_message1(self, static_priv: bytes, static_pub: bytes,
                       ephemeral_priv: bytes, responder_static_pub: bytes) -> bytes:
        e_pub = wg.x25519_pub(ephemeral_priv)
        self._mix_hash(e_pub)                                   # token e
        self._mix_key(wg.x25519_dh(ephemeral_priv, responder_static_pub))  # es
        enc_s = self._encrypt(static_pub)                       # token s
        self._mix_key(wg.x25519_dh(static_priv, responder_static_pub))     # ss
        enc_p = self._encrypt(b"")                              # empty payload
        msg = e_pub + enc_s + enc_p
        assert len(msg) == 96, len(msg)
        self._e_priv = ephemeral_priv
        self._s_priv = static_priv
        return msg

    def read_message2(self, msg: bytes) -> tuple[bytes, bytes]:
        assert len(msg) == 48, len(msg)
        re_pub = msg[0:32]
        enc_empty = msg[32:48]
        self._mix_hash(re_pub)                                  # token e
        self._mix_key(wg.x25519_dh(self._e_priv, re_pub))       # ee
        self._mix_key(wg.x25519_dh(self._s_priv, re_pub))       # se
        self._decrypt(enc_empty)                                # empty payload
        c1, c2 = wg.hkdf(self.ck, b"", 2)                       # Split()
        return c1, c2  # tx (initiator->responder), rx (responder->initiator)


# ── Noise transport (record framing + BE nonce) ───────────────────────────────
class NoiseTransport:
    """Byte-stream view over the ts2021 Noise transport.

    Post-handshake data is a stream of Record frames, each `type(1) + len(2 BE)
    + ciphertext`, decrypted with a big-endian counter nonce. The decrypted
    plaintext is a continuous byte stream that carries whatever the upper layer
    (the challenge packet, then HTTP/2) put on it -- upper-layer message
    boundaries do NOT line up with Record boundaries (the control server
    fragments even the tiny challenge packet across three Records), so this
    class exposes a byte stream, not per-record reads.
    """

    def __init__(self, sock: socket.socket, tx_key: bytes, rx_key: bytes):
        self.sock = sock
        self.tx = ChaCha20Poly1305(tx_key)
        self.rx = ChaCha20Poly1305(rx_key)
        self.tx_n = 0
        self.rx_n = 0
        self._recv_buf = b""       # undecrypted wire bytes
        self._plain = bytearray()  # decrypted plaintext stream

    def _read_wire(self, n: int) -> bytes:
        while len(self._recv_buf) < n:
            chunk = self.sock.recv(65535)
            if not chunk:
                raise ConnectionError("EOF from control server")
            self._recv_buf += chunk
        out, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return out

    def _fill_one_record(self) -> None:
        hdr = self._read_wire(3)
        mtype = hdr[0]
        clen = struct.unpack(">H", hdr[1:3])[0]
        ct = self._read_wire(clen)
        if mtype == MSG_TYPE_ERROR:
            raise ConnectionError("ts2021 error record: " + ct.decode("utf-8", "replace"))
        if mtype != MSG_TYPE_RECORD:
            raise ConnectionError(f"unexpected record type {mtype}")
        self._plain += self.rx.decrypt(be_nonce(self.rx_n), ct, None)
        self.rx_n += 1

    def write_record(self, data: bytes) -> None:
        # Fragment into <=4096-byte plaintext Records (matches tm_control).
        off = 0
        while off < len(data):
            chunk = data[off:off + 4096]
            ct = self.tx.encrypt(be_nonce(self.tx_n), chunk, None)
            self.tx_n += 1
            hdr = bytes([MSG_TYPE_RECORD]) + struct.pack(">H", len(ct))
            self.sock.sendall(hdr + ct)
            off += len(chunk)

    def read_exact(self, n: int) -> bytes:
        while len(self._plain) < n:
            self._fill_one_record()
        out, self._plain = bytes(self._plain[:n]), self._plain[n:]
        return out

    def recv_plain(self) -> bytes:
        """Return whatever decrypted plaintext is buffered, filling one Record
        if the buffer is empty. Used to feed the sans-IO HTTP/2 engine."""
        if not self._plain:
            self._fill_one_record()
        out, self._plain = bytes(self._plain), bytearray()
        return out

    def skip_challenge_packet(self) -> None:
        """Consume the optional post-handshake challenge packet if present:
        magic(5) + length(4 BE) + JSON. Confirmed sent by
        controlplane.tailscale.com. If the first bytes aren't the magic they
        are left buffered for HTTP/2."""
        head = self.read_exact(5)
        if head != CHALLENGE_MAGIC:
            self._plain[:0] = head  # push back for the h2 layer
            return
        json_len = struct.unpack(">I", self.read_exact(4))[0]
        self.read_exact(json_len)


# ── Handshake over HTTP/1.1 upgrade ────────────────────────────────────────────
def fetch_server_key(host: str, cap: int = CAP_VERSION) -> bytes:
    url = f"https://{host}/key?v={cap}"
    body = urllib.request.urlopen(url, timeout=15).read()
    pub = json.loads(body)["publicKey"]
    assert pub.startswith("mkey:"), pub
    return bytes.fromhex(pub[len("mkey:"):])


def do_handshake(host: str, port: int, machine_priv: bytes, server_pub: bytes,
                 cap: int = CAP_VERSION) -> NoiseTransport:
    machine_pub = wg.x25519_pub(machine_priv)
    ephemeral_priv = wg.X25519PrivateKey.generate().private_bytes_raw()

    prologue = f"Tailscale Control Protocol v{cap}".encode()
    ik = NoiseIK(prologue, server_pub)
    msg1 = ik.write_message1(machine_priv, machine_pub, ephemeral_priv, server_pub)

    # Wire-frame: 2-byte cap (BE) + 1-byte type + 2-byte len (BE) + payload.
    frame = struct.pack(">H", cap) + bytes([MSG_TYPE_INITIATION]) + struct.pack(">H", len(msg1)) + msg1
    b64 = base64.b64encode(frame).decode()

    sock = socket.create_connection((host, port), timeout=20)
    sock.settimeout(20)
    req = (
        f"POST /ts2021 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: tailscale-control-protocol\r\n"
        f"Connection: upgrade\r\n"
        f"Tailscale-Cap-Version: {cap}\r\n"
        f"X-Tailscale-Handshake: {b64}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    sock.sendall(req)

    # Read HTTP response headers up to \r\n\r\n, one byte at a time so we don't
    # swallow the Noise bytes that immediately follow the header boundary.
    buf = b""
    while not buf.endswith(b"\r\n\r\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF reading 101 response")
        buf += b
    status = buf.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise ConnectionError(f"upgrade rejected: {status!r}")

    # Read the response frame. Optional EarlyNoise (first byte 0xFF) is skipped.
    def read_exact(n: int) -> bytes:
        out = b""
        while len(out) < n:
            c = sock.recv(n - len(out))
            if not c:
                raise ConnectionError("EOF reading response frame")
            out += c
        return out

    first = read_exact(1)
    if first[0] == 0xFF:
        json_len = struct.unpack(">I", read_exact(4))[0]
        read_exact(json_len)
        mtype = read_exact(1)[0]
    else:
        mtype = first[0]
    rlen = struct.unpack(">H", read_exact(2))[0]
    if mtype == MSG_TYPE_ERROR:
        raise ConnectionError("handshake error: " + read_exact(rlen).decode("utf-8", "replace"))
    if mtype != MSG_TYPE_RESPONSE:
        raise ConnectionError(f"unexpected response frame type {mtype}")
    if rlen != 48:
        raise ConnectionError(f"unexpected response length {rlen}")
    resp = read_exact(48)

    tx_key, rx_key = ik.read_message2(resp)
    return NoiseTransport(sock, tx_key, rx_key)


# ── HTTP/2 over the Noise transport ────────────────────────────────────────────
import h2.config  # noqa: E402
import h2.connection  # noqa: E402
import h2.events  # noqa: E402


class H2Driver:
    def __init__(self, transport: NoiseTransport, host: str):
        self.t = transport
        self.host = host
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.initiate_connection()
        self._flush()
        self._stream_data: dict[int, bytearray] = {}
        self._stream_status: dict[int, int] = {}
        self._stream_ended: set[int] = set()

    def _flush(self) -> None:
        data = self.conn.data_to_send()
        if data:
            self.t.write_record(data)

    def _pump(self) -> None:
        pt = self.t.recv_plain()
        events = self.conn.receive_data(pt)
        for ev in events:
            if isinstance(ev, h2.events.ResponseReceived):
                for name, val in ev.headers:
                    if name == ":status":
                        self._stream_status[ev.stream_id] = int(val)
            elif isinstance(ev, h2.events.DataReceived):
                self._stream_data.setdefault(ev.stream_id, bytearray()).extend(ev.data)
                if ev.flow_controlled_length:
                    self.conn.acknowledge_received_data(
                        ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, (h2.events.StreamEnded,)):
                self._stream_ended.add(ev.stream_id)
            elif isinstance(ev, h2.events.StreamReset):
                self._stream_ended.add(ev.stream_id)
                raise ConnectionError(f"stream {ev.stream_id} reset: {ev.error_code}")
            elif isinstance(ev, h2.events.ConnectionTerminated):
                raise ConnectionError(
                    f"GOAWAY error={ev.error_code} last_stream={ev.last_stream_id}")
        self._flush()

    def post(self, stream_id: int, path: str, body: bytes) -> None:
        headers = [
            (":method", "POST"),
            (":authority", self.host),
            (":scheme", "http"),
            (":path", path),
            ("content-type", "application/json"),
            ("content-length", str(len(body))),
        ]
        self.conn.send_headers(stream_id, headers)
        self.conn.send_data(stream_id, body, end_stream=True)
        self._flush()

    def read_full_body(self, stream_id: int) -> tuple[int, bytes]:
        while stream_id not in self._stream_ended:
            self._pump()
        return self._stream_status.get(stream_id, 0), bytes(self._stream_data.get(stream_id, b""))

    def read_stream_message(self, stream_id: int) -> tuple[int, bytes]:
        """Read one 4-byte-LE-length-prefixed message off a streaming response."""
        buf = self._stream_data.setdefault(stream_id, bytearray())
        while len(buf) < 4:
            if stream_id in self._stream_ended:
                return self._stream_status.get(stream_id, 0), b""
            self._pump()
        msg_len = struct.unpack("<I", bytes(buf[:4]))[0]
        while len(buf) < 4 + msg_len:
            if stream_id in self._stream_ended:
                break
            self._pump()
        msg = bytes(buf[4:4 + msg_len])
        del buf[:4 + msg_len]
        return self._stream_status.get(stream_id, 0), msg


# ── High-level client ───────────────────────────────────────────────────────────
@dataclass
class Peer:
    node_key: bytes
    disco_key: bytes
    hostname: str
    derp_region: int
    addresses: list[str]
    online: bool
    endpoints: list[str] = field(default_factory=list)


@dataclass
class MapResult:
    our_addresses: list[str]
    peers: list[Peer]
    derp_hostnames: dict[int, str]  # region_id -> home DERP hostname


class TsControlClient:
    def __init__(self, host: str = "login.tailscale.com", port: int = 80,
                 cap: int = CAP_VERSION):
        self.host = host
        self.port = port
        self.cap = cap
        self.node_priv = wg.X25519PrivateKey.generate().private_bytes_raw()
        self.node_pub = wg.x25519_pub(self.node_priv)
        self.machine_priv = wg.X25519PrivateKey.generate().private_bytes_raw()
        self.disco_priv = wg.X25519PrivateKey.generate().private_bytes_raw()
        self.disco_pub = wg.x25519_pub(self.disco_priv)
        self.h2: H2Driver | None = None
        self._poll_stop = False
        self._poll_thread = None

    def node_key_hex(self) -> str:
        return "nodekey:" + self.node_pub.hex()

    def connect(self) -> None:
        server_pub = fetch_server_key(self.host, self.cap)
        transport = do_handshake(self.host, self.port, self.machine_priv,
                                 server_pub, self.cap)
        transport.skip_challenge_packet()
        self.h2 = H2Driver(transport, self.host)

    def register(self, auth_key: str, hostname: str = "wg-validator-probe") -> dict:
        body = json.dumps({
            "Version": self.cap,
            "NodeKey": self.node_key_hex(),
            "Auth": {"AuthKey": auth_key},
            "Hostinfo": {"OS": "linux", "Hostname": hostname},
        }).encode()
        self.h2.post(1, "/machine/register", body)
        status, resp = self.h2.read_full_body(1)
        if status != 200:
            raise ConnectionError(f"register HTTP {status}: {resp[:300]!r}")
        return json.loads(resp)

    _next_stream = 3

    def _stream_id(self) -> int:
        sid = self._next_stream
        self._next_stream += 2
        return sid

    def write_map(self, hostname: str = "wg-validator-probe",
                  preferred_derp: int = 0, endpoints: list[str] | None = None) -> MapResult:
        """A NON-streaming ("write") MapRequest.

        Critical: a streaming MapRequest (Stream=true) with cap version >= 68
        is treated by the control server as READ-ONLY -- it ignores Hostinfo,
        DiscoKey, Endpoints and every other write field (confirmed live: the
        disco key propagates to peers as all-zeros from a streaming request).
        So the disco key / preferred DERP / endpoints MUST be published via a
        non-streaming request first, or peers can never bind our disco key and
        will drop our disco pings (and thus our WireGuard handshake). Its
        response is itself a full MapResponse, so we also return the peers.

        Hostinfo is required regardless (a 400 "Hostinfo required in
        MapRequest" otherwise); tm_control's MapRequest omits both Hostinfo and
        DiscoKey.
        """
        hostinfo: dict = {"OS": "linux", "Hostname": hostname}
        if preferred_derp:
            hostinfo["NetInfo"] = {"PreferredDERP": preferred_derp}
        body = json.dumps({
            "Version": self.cap,
            "Compress": "",
            "KeepAlive": False,
            "NodeKey": self.node_key_hex(),
            "DiscoKey": "discokey:" + self.disco_pub.hex(),
            "Endpoints": endpoints or [],
            "Stream": False,
            "Hostinfo": hostinfo,
        }).encode()
        sid = self._stream_id()
        self.h2.post(sid, "/machine/map", body)
        status, resp = self.h2.read_full_body(sid)
        if status != 200:
            raise ConnectionError(f"write-map HTTP {status}: {resp[:200]!r}")
        # The body is 4-byte little-endian length-prefixed, same as a streamed
        # message.
        msg_len = struct.unpack("<I", resp[:4])[0]
        return parse_map_response(json.loads(resp[4:4 + msg_len]))

    def start_keepalive_poll(self, hostname: str = "wg-validator-probe") -> None:
        """Open a streaming map poll and drain it on a background thread so the
        control server keeps this node marked online while we do DERP work."""
        import threading
        body = json.dumps({
            "Version": self.cap, "Compress": "", "KeepAlive": True,
            "NodeKey": self.node_key_hex(), "Stream": True,
            "Hostinfo": {"OS": "linux", "Hostname": hostname},
        }).encode()
        sid = self._stream_id()
        self.h2.post(sid, "/machine/map", body)
        self.h2.read_stream_message(sid)  # consume the first snapshot

        def _drain():
            while not self._poll_stop:
                try:
                    self.h2.t.sock.settimeout(2)
                    self.h2._pump()
                except Exception:  # noqa: BLE001
                    pass

        self._poll_stop = False
        self._poll_thread = threading.Thread(target=_drain, daemon=True)
        self._poll_thread.start()

    def stop_keepalive_poll(self) -> None:
        self._poll_stop = True

    # Backwards-compatible alias: a streaming read-only map (peers only).
    def map(self, hostname: str = "wg-validator-probe") -> MapResult:
        body = json.dumps({
            "Version": self.cap, "Compress": "", "KeepAlive": True,
            "NodeKey": self.node_key_hex(), "Endpoints": [], "Stream": True,
            "Hostinfo": {"OS": "linux", "Hostname": hostname},
        }).encode()
        sid = self._stream_id()
        self.h2.post(sid, "/machine/map", body)
        status, msg = self.h2.read_stream_message(sid)
        if status != 200:
            raise ConnectionError(f"map HTTP {status}")
        return parse_map_response(json.loads(msg))


def _hexkey(v: str) -> bytes:
    for p in ("nodekey:", "discokey:", "mkey:"):
        if v.startswith(p):
            v = v[len(p):]
            break
    return bytes.fromhex(v) if len(v) == 64 else b""


def parse_map_response(m: dict) -> MapResult:
    node = m.get("Node") or {}
    our_addrs = node.get("Addresses") or []

    derp_hostnames: dict[int, str] = {}
    regions = ((m.get("DERPMap") or {}).get("Regions") or {})
    for rid, region in regions.items():
        nodes = region.get("Nodes") or []
        if nodes:
            derp_hostnames[int(rid)] = nodes[0].get("HostName", "")

    peers: list[Peer] = []
    # The first streamed MapResponse delivers the peer list in "PeersChanged"
    # (a full snapshot for a fresh node), not "Peers"; accept both.
    for p in ((m.get("Peers") or []) + (m.get("PeersChanged") or [])):
        derp = p.get("DERP", "")
        region = 0
        if ":" in derp:
            try:
                region = int(derp.rsplit(":", 1)[1])
            except ValueError:
                region = 0
        peers.append(Peer(
            node_key=_hexkey(p.get("Key", "")),
            disco_key=_hexkey(p.get("DiscoKey", "")),
            hostname=(p.get("Hostinfo") or {}).get("Hostname", "")
            or (p.get("Name") or ""),
            derp_region=region,
            addresses=p.get("Addresses") or [],
            online=bool(p.get("Online", False)),
            endpoints=p.get("Endpoints") or [],
        ))
    return MapResult(our_addrs, peers, derp_hostnames)
