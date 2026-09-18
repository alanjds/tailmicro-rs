//! TCP echo server — listens on the tailnet and echoes bytes back.
//!
//! Source-compatible with the `tcp_echo` example from tailscale-rs.

use std::{error::Error, net::Ipv4Addr};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let auth_key = std::env::var("TS_AUTHKEY").expect("set TS_AUTHKEY");
    let control_pin_hex = std::env::var("TAILMICRO_CONTROL_PIN")
        .expect("set TAILMICRO_CONTROL_PIN env var (hex pin blob from tools/gen_fingerprint.py)");

    let config = tailmicro::Config::default_with_key_file("tailmicro_keys.json")
        .await?
        .with_control_pin_hex(&control_pin_hex)?
        .with_connect_timeout(std::time::Duration::from_secs(60));
    // `driver` must be folded into this fn's own tokio::join! below -- never
    // awaited alone, never raced under an external timeout/select! (see
    // docs/wg-dataplane-notes.md "Readiness-decoupled connect handle").
    let (dev, driver) = tailmicro::Device::connect(&config, Some(auth_key)).await?;

    let addr = (dev.ipv4_addr(), 7u16).into(); // port 7 = echo
    let listener = dev.tcp_listen(addr).await?;
    tracing::info!("Listening on {:?}", addr);

    let accept_loop = async {
        loop {
            let (mut stream, peer) = listener.accept().await?;
            tracing::info!("Connection from {:?}", peer);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = stream.write_all(&buf[..n]).await; }
                        Err(_) => break,
                    }
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn Error>>(())
    };

    let (accept_result, ()) = tokio::join!(accept_loop, driver);
    accept_result
}
