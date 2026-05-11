//! TCP echo server — listens on the tailnet and echoes bytes back.
//!
//! Source-compatible with the `tcp_echo` example from tailscale-rs.

use std::{error::Error, net::Ipv4Addr};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let auth_key = std::env::var("TS_AUTHKEY").expect("set TS_AUTHKEY");

    let dev = tailmicro::Device::new(
        &tailmicro::Config::default_with_key_file("tailmicro_keys.json").await?,
        Some(auth_key),
    ).await?;

    let addr = (dev.ipv4_addr().await?, 7u16).into(); // port 7 = echo
    let listener = dev.tcp_listen(addr).await?;
    tracing::info!("Listening on {:?}", addr);

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
}
