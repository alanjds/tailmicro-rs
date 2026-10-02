//! Emit deterministic WireGuard data-plane reference vectors as JSON on stdout.
//!
//! This drives the REAL `tm_wg` crypto core (via the `build_initiation` /
//! `build_response` cores, reached through the doc-hidden deterministic
//! ephemeral seams) for a set of FIXED inputs, and prints every input and
//! output as hex. An independent from-spec Python oracle
//! (`tools/wg_validator/`) reproduces the same bytes and asserts byte-for-byte
//! equality; catching any wire-format/crypto bug that a Rust self-round-trip
//! test cannot (one that is uniformly wrong on both the encode and decode side).
//!
//! The private scalars here are fixed TEST CONSTANTS, not real key material.
//!
//! Run: `cargo run -p tm_wg --example wg_emit_vectors`

use tm_time::Instant;

use tm_wg::vendor::config::Psk;
use tm_wg::vendor::handshake::{ReceivedHandshake, initiate_handshake_with_ephemeral};
use tm_wg::vendor::keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use tm_wg::vendor::macs::{MACReceiver, MACSender};
use tm_wg::vendor::messages::{HandshakeInitiation, SessionId, TransportDataHeader};
use tm_wg::vendor::packet::Packet;
use tm_wg::vendor::session::TransmitSession;
use tm_wg::vendor::tai64n::TAI64N;

use zerocopy::{IntoBytes, TryFromBytes};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() {
    // ── Fixed test inputs (NOT secrets; deterministic vector constants) ──────
    let init_static_scalar: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let resp_static_scalar: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    let init_ephemeral_scalar: [u8; 32] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f, 0x60,
    ];
    let resp_ephemeral_scalar: [u8; 32] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
        0x9f, 0xa0,
    ];
    let init_session_id: u32 = 0x1122_3344;
    let resp_session_id: u32 = 0x5566_7788;
    let ts_secs: u64 = 1_726_000_000; // synced-clock era
    let ts_nanos: u32 = 0; // already a whitening multiple
    let transport_plaintext: &[u8] = b"tailmicro wg oracle";
    let transport_counter: u64 = 0;

    // ── Derived public keys ───────────────────────────────────────────────────
    let init_priv = NodePrivateKey(init_static_scalar);
    let resp_priv = NodePrivateKey(resp_static_scalar);
    let init_kp = NodeKeyPair::from_private(init_priv);
    let resp_kp = NodeKeyPair::from_private(resp_priv);
    let init_pub: NodePublicKey = init_kp.public;
    let resp_pub: NodePublicKey = resp_kp.public;

    let timestamp = TAI64N::from_unix(ts_secs, ts_nanos);

    // ── (1) Handshake Initiation, deterministic ephemeral ─────────────────────
    let init_msg: HandshakeInitiation = initiate_handshake_with_ephemeral(
        init_priv,
        resp_pub,
        SessionId::from(init_session_id),
        timestamp,
        init_ephemeral_scalar,
    );
    // Wrap and apply MACs (initiator -> responder key).
    let mut init_pkt = Packet::from_wire(init_msg.as_bytes());
    let init_mac_sender = MACSender::new(&resp_pub);
    let init_mac1 = init_mac_sender.write_macs(init_pkt.as_mut());
    let init_wire = init_pkt.as_slice().to_vec();

    // ── (2) Responder consumes the initiation (real decrypt path) ─────────────
    let resp_mac_recv = MACReceiver::new(&resp_pub);
    let init_ref = HandshakeInitiation::try_ref_from_bytes(&init_wire)
        .expect("emitted initiation must parse");
    let received = ReceivedHandshake::new(init_ref, &resp_kp, &resp_mac_recv)
        .expect("responder must accept the emitted initiation");
    assert_eq!(
        received.peer_static(),
        init_pub,
        "responder must recover the initiator's static pubkey"
    );

    // ── (3) Responder builds a response, deterministic ephemeral ──────────────
    let psk = Psk::zero(); // Tailscale PSK is 32 zero bytes
    let (initiator_to_responder, responder_to_initiator, resp_msg) =
        received.respond_vector(SessionId::from(resp_session_id), &psk, resp_ephemeral_scalar);
    let mut resp_pkt = Packet::from_wire(resp_msg.as_bytes());
    // Response MACs are computed toward the initiator's key.
    let resp_mac_sender = MACSender::new(&init_pub);
    let resp_mac1 = resp_mac_sender.write_macs(resp_pkt.as_mut());
    let resp_wire = resp_pkt.as_slice().to_vec();

    // ── (4) Transport data packet, initiator -> responder, counter 0 ──────────
    // Initiator's send key is initiator_to_responder; receiver_id = responder's
    // session id.
    let tx = TransmitSession::new(
        initiator_to_responder,
        SessionId::from(resp_session_id),
        Instant::now(),
        true,
    );
    let mut data_pkt = [Packet::from_plaintext(transport_plaintext)];
    assert_eq!(transport_counter, 0, "vector uses the first nonce");
    tx.encrypt(&mut data_pkt);
    let transport_wire = data_pkt[0].as_slice().to_vec();

    // Sanity: header framing/size the oracle will cross-check.
    let hdr_len = size_of::<TransportDataHeader>();
    assert_eq!(hdr_len, 16);

    // ── Emit JSON ─────────────────────────────────────────────────────────────
    // Hand-rolled to avoid a serde dependency in this example.
    println!("{{");
    println!("  \"note\": \"deterministic tm_wg reference vectors; scalars are test constants, not secrets\",");
    println!("  \"inputs\": {{");
    println!("    \"init_static_scalar\": \"{}\",", hex(&init_static_scalar));
    println!("    \"resp_static_scalar\": \"{}\",", hex(&resp_static_scalar));
    println!("    \"init_ephemeral_scalar\": \"{}\",", hex(&init_ephemeral_scalar));
    println!("    \"resp_ephemeral_scalar\": \"{}\",", hex(&resp_ephemeral_scalar));
    println!("    \"init_static_pub\": \"{}\",", hex(init_pub.as_bytes()));
    println!("    \"resp_static_pub\": \"{}\",", hex(resp_pub.as_bytes()));
    println!("    \"init_session_id\": {init_session_id},");
    println!("    \"resp_session_id\": {resp_session_id},");
    println!("    \"ts_secs\": {ts_secs},");
    println!("    \"ts_nanos\": {ts_nanos},");
    println!("    \"psk\": \"{}\",", hex(&[0u8; 32]));
    println!("    \"transport_plaintext\": \"{}\",", hex(transport_plaintext));
    println!("    \"transport_counter\": {transport_counter}");
    println!("  }},");
    println!("  \"outputs\": {{");
    println!("    \"initiation\": \"{}\",", hex(&init_wire));
    println!("    \"initiation_mac1\": \"{}\",", hex(&init_mac1));
    println!("    \"timestamp_tai64n\": \"{}\",", hex(timestamp.as_bytes()));
    println!("    \"response\": \"{}\",", hex(&resp_wire));
    println!("    \"response_mac1\": \"{}\",", hex(&resp_mac1));
    println!("    \"initiator_to_responder_key\": \"{}\",", hex(initiator_to_responder.as_slice()));
    println!("    \"responder_to_initiator_key\": \"{}\",", hex(responder_to_initiator.as_slice()));
    println!("    \"transport_data\": \"{}\"", hex(&transport_wire));
    println!("  }}");
    println!("}}");
}
