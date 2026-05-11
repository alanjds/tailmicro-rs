//! UDP client — sends "hello" to a tailnet peer once per second.
//!
//! Source-compatible with the `peer_ping` example from tailscale-rs.
//! The only difference is `flavor = "current_thread"` in the runtime,
//! which is required on ESP32-C3 but harmless on the host.

use std::{net::Ipv4Addr, time::Duration, error::Error};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let auth_key = std::env::var("TS_AUTHKEY")
        .expect("set TS_AUTHKEY env var");
    let peer_ip: Ipv4Addr = std::env::var("TS_PEER_IP")
        .expect("set TS_PEER_IP env var")
        .parse()?;

    // ── Identical to tailscale-rs example ────────────────────────────────────
    let dev = tailmicro::Device::new(
        &tailmicro::Config::default_with_key_file("tailmicro_keys.json").await?,
        Some(auth_key),
    ).await?;

    let sock = dev.udp_bind((dev.ipv4_addr().await?, 1234).into()).await?;

    tracing::info!("Connected. Sending to {}:5678 every second.", peer_ip);

    loop {
        sock.send_to((peer_ip, 5678u16).into(), b"hello").await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
