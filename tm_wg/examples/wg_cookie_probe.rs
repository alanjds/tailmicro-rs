//! Cookie-reply probe for the offline oracle.
//!
//! Reads (from argv, all hex):
//!   1. responder static pubkey (32 B): the peer the initiation was sent to
//!   2. a CookieReply message (64 B), built independently by the Python oracle
//!   3. the last-sent handshake mac1 (16 B): the AEAD AAD for the cookie
//!   4. a packet (>= 32 B) to stamp mac2 onto
//!
//! Feeds the CookieReply through the REAL `MACSender::receive_cookie` and then
//! `write_macs`, and prints the resulting mac2 (final 16 bytes). The Python
//! oracle independently computes the same mac2 to confirm the cookie decryption
//! (XChaCha20Poly1305, key = BLAKE2s("cookie--"||resp_pub), AAD = mac1) and the
//! mac2 keyed-MAC domain (BLAKE2s-128 over msg[0..len-16]) match the spec.

use tm_wg::vendor::keys::NodePublicKey;
use tm_wg::vendor::macs::MACSender;
use tm_wg::vendor::messages::CookieReply;

use zerocopy::TryFromBytes;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let resp_pub_bytes: [u8; 32] = h(&args[1]).try_into().unwrap();
    let cookie_bytes = h(&args[2]);
    let mac1: [u8; 16] = h(&args[3]).try_into().unwrap();
    let mut pkt = h(&args[4]);

    let resp_pub = NodePublicKey::from(resp_pub_bytes);
    let mut sender = MACSender::new(&resp_pub);

    let cookie = CookieReply::try_ref_from_bytes(&cookie_bytes).expect("valid cookie reply");
    sender.receive_cookie(cookie, &mac1);

    // With a stored cookie, write_macs now stamps a non-zero mac2.
    let _mac1_out = sender.write_macs(&mut pkt);
    let n = pkt.len();
    let mac2 = &pkt[n - 16..];
    let mut s = String::new();
    for b in mac2 {
        s.push_str(&format!("{b:02x}"));
    }
    println!("{s}");
}
