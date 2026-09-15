//! Independent WireGuard responder for the interop oracle.
//!
//! Uses boringtun (Cloudflare's real, independent Rust WireGuard implementation)
//! as an in-memory responder on a loopback UDP socket. The from-spec Python
//! oracle acts as the initiator and drives a full handshake + transport
//! exchange against it. This validates the Python oracle (and, transitively,
//! the byte-identical `tm_wg` Rust core) against a THIRD independent
//! implementation, closing the residual risk that oracle and `tm_wg` share the
//! same from-spec misreading. No tun device / root needed.
//!
//! argv[1] = initiator (Python) static public key, 64 hex chars.
//! stdout  = "PORT <p>", "PUBKEY <hex>", then "GOT <hex>" on decrypt.

use std::net::UdpSocket;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let peer_pub_bytes: [u8; 32] = from_hex(&args[1]).try_into().unwrap();
    let peer_pub = PublicKey::from(peer_pub_bytes);

    // Fixed responder static key (deterministic; a test constant).
    let resp_priv_bytes: [u8; 32] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
        0xde, 0xdf,
    ];
    let resp_priv = StaticSecret::from(resp_priv_bytes);
    let resp_pub = PublicKey::from(&resp_priv);

    // Tailscale uses an all-zero PSK; keep it consistent with the oracle.
    let mut tun = Tunn::new(resp_priv, peer_pub, Some([0u8; 32]), None, 1, None)
        .expect("Tunn::new");

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let port = sock.local_addr().unwrap().port();

    println!("PORT {port}");
    println!("PUBKEY {}", to_hex(resp_pub.as_bytes()));
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut buf = [0u8; 2048];
    let mut out = [0u8; 2048];
    let mut replied = false;

    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("timeout / no more packets");
                return;
            }
        };
        match tun.decapsulate(None, &buf[..n], &mut out) {
            TunnResult::WriteToNetwork(pkt) => {
                // Handshake response (or cookie). Send back to the initiator.
                sock.send_to(pkt, src).unwrap();
                // Flush any additional queued network packets.
                loop {
                    match tun.decapsulate(None, &[], &mut out) {
                        TunnResult::WriteToNetwork(p) => {
                            sock.send_to(p, src).unwrap();
                        }
                        _ => break,
                    }
                }
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                println!("GOT {}", to_hex(data));
                std::io::stdout().flush().ok();
                if !replied {
                    replied = true;
                    // Send an encrypted reply back to prove the reverse direction.
                    let mut reply = [0u8; 2048];
                    match tun.encapsulate(b"boringtun-reply", &mut reply) {
                        TunnResult::WriteToNetwork(p) => {
                            sock.send_to(p, src).unwrap();
                        }
                        other => eprintln!("unexpected encapsulate result: {:?}", disc(&other)),
                    }
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                eprintln!("decapsulate error: {e:?}");
            }
        }
    }
}

fn disc(r: &TunnResult) -> &'static str {
    match r {
        TunnResult::Done => "Done",
        TunnResult::Err(_) => "Err",
        TunnResult::WriteToNetwork(_) => "WriteToNetwork",
        TunnResult::WriteToTunnelV4(..) => "WriteToTunnelV4",
        TunnResult::WriteToTunnelV6(..) => "WriteToTunnelV6",
    }
}
