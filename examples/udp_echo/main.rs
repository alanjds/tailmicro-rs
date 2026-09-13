//! UDP echo server — ESP32-C3 entry point pattern.
//!
//! Shows how to use tailmicro inside an ESP-IDF application with a
//! `current_thread` Tokio runtime explicitly constructed.
//!
//! On the host this compiles and runs normally.
//! On ESP32-C3 replace the `#[tokio::main]` with the explicit runtime
//! construction shown in the comment below.

use std::{error::Error, net::Ipv4Addr};

// ── Host entry point (for development / CI) ───────────────────────────────────
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    run().await
}

// ── ESP32-C3 entry point (uncomment, remove tokio::main above) ───────────────
//
// #[no_mangle]
// extern "C" fn app_main() {
//     let rt = tokio::runtime::Builder::new_current_thread()
//         .enable_all()
//         .build()
//         .unwrap();
//     rt.block_on(run()).unwrap();
// }

async fn run() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let auth_key = std::env::var("TS_AUTHKEY").expect("set TS_AUTHKEY");
    let control_pin_hex = std::env::var("TAILMICRO_CONTROL_PIN")
        .expect("set TAILMICRO_CONTROL_PIN env var (hex pin blob from tools/gen_fingerprint.py)");

    let config = tailmicro::Config::new(&auth_key)
        .with_control_pin_hex(&control_pin_hex)?;
    let dev = tailmicro::Device::new(&config, Some(auth_key)).await?;

    let our_ip = dev.ipv4_addr().await?;
    tracing::info!("Tailnet IP: {}", our_ip);

    let sock = dev.udp_bind((our_ip, 9000u16).into()).await?;
    tracing::info!("UDP echo listening on {}:9000", our_ip);

    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        tracing::debug!("Echo {} bytes to {}", n, from);
        sock.send_to(from, &buf[..n]).await?;
    }
}
