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

    let control_pin_hex = std::env::var("TAILMICRO_CONTROL_PIN")
        .expect("set TAILMICRO_CONTROL_PIN env var (hex pin blob from tools/gen_fingerprint.py)");

    // ── Identical to tailscale-rs example ────────────────────────────────────
    let config = tailmicro::Config::default_with_key_file("tailmicro_keys.json")
        .await?
        .with_control_pin_hex(&control_pin_hex)?
        .with_connect_timeout(Duration::from_secs(60));
    // `driver` must be folded into this fn's own tokio::join! below -- never
    // awaited alone, never raced under an external timeout/select! (see
    // docs/wg-dataplane-notes.md "Readiness-decoupled connect handle").
    let (dev, driver) = tailmicro::Device::connect(&config, Some(auth_key)).await?;

    let sock = dev.udp_bind((dev.ipv4_addr(), 1234).into()).await?;

    tracing::info!("Connected. Sending to {}:5678 every second.", peer_ip);

    let ping_loop = async {
        loop {
            sock.send_to((peer_ip, 5678u16).into(), b"hello").await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn Error>>(())
    };

    let (ping_result, ()) = tokio::join!(ping_loop, driver);
    ping_result
}
