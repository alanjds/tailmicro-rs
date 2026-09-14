//! Bisection tool: connects to a local MITM proxy (see mitm_proxy.py in the
//! session scratchpad) instead of the real control server directly, while
//! keeping the real hostname for the Host header / Noise handshake logic.
//! The proxy relays to the real server via a plain Python socket (already
//! confirmed to work), logging every byte. If this succeeds, the bug is in
//! how Rust talks to the real network path (not in the request content);
//! if it still fails the same way even through the proxy, the bug is
//! entirely on the Rust side, independent of the network path.

use tm_keys::MachinePrivateKey;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
    let pin_hex = std::env::var("TAILMICRO_CONTROL_PIN").expect("set TAILMICRO_CONTROL_PIN");
    let control_pin = tm_control::pin::verify_pin_hex(&pin_hex, &tm_control::pin::PIN_VERIFY_KEY, None).unwrap();
    let real_host = "controlplane.tailscale.com"; // used only for the Host header / handshake host arg
    let proxy_addr = "127.0.0.1:8899"; // actual TCP destination

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    println!("connected to proxy at {proxy_addr}, Host header will say {real_host}");
    let machine_key = MachinePrivateKey::generate();
    match tm_control::noise::do_noise_handshake(&mut stream, &machine_key, &control_pin, real_host, 72).await {
        Ok(_) => println!("SUCCESS"),
        Err(e) => println!("FAILED: {:?}", e),
    }
}
