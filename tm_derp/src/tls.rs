//! On-device DERP TLS leg. Uses `embedded-tls` (pure Rust, no_std, TLS 1.3 only),
//! optimized for the SMALLEST possible RAM.
//!
//! ## Why this config (locked decision)
//!
//! Every byte DERP relays is already end-to-end encrypted (WireGuard transport
//! + disco `crypto_box`), so the outer TLS hop only needs confidentiality
//! against a passive observer of *ciphertext*; a MITM there can DoS but can
//! neither read nor forge tunnel contents. That makes it safe to run the
//! smallest TLS 1.3 profile that a real Tailscale DERP server accepts:
//!
//! * **TLS 1.3 only** (`embedded-tls` is 1.3-only by construction).
//! * **Certificate verification DISABLED**. `UnsecureProvider` wires
//!   `NoVerify` + `NoSign`, so no CA bundle, no webpki, no hostname check, and
//!   no RSA/ECDSA *verification* code is pulled in (we still *advertise* RSA
//!   signature schemes via [`embedded_tls::TlsConfig::enable_rsa_signatures`]
//!   so the RSA-certificated DERP server can pick a `CertificateVerify`
//!   scheme; we just never check the signature).
//! * **One cipher suite: `TLS_CHACHA20_POLY1305_SHA256`** ([`Chacha20Poly1305Sha256`]).
//!   embedded-tls 0.19 ships only AES suites, so the suite is defined here
//!   reusing the RustCrypto `chacha20poly1305` + `sha2` crates ALREADY compiled
//!   for Noise/WireGuard, so zero extra AEAD/hash flash. The ESP32-C3 has no AES
//!   acceleration wired on this path, so ChaCha is also the fast choice.
//! * **RFC 6066 max_fragment_length = 2048** advertised. (Go's `crypto/tls`
//!   server ignores it today, so it does not shrink the inbound handshake
//!   records; we still advertise it since it is free and future-proof.)
//!
//! ## RAM (the headline)
//!
//! embedded-tls takes caller-provided record buffers; those two buffers plus
//! the small connection state ARE the whole steady-state RAM cost:
//!
//! * `RECORD_READ_BUF`  = 5120 B. Floor set by the **measured** 4444-byte
//!   server `Certificate` record on the live handshake to `derp1.tailscale.com`
//!   (a 4-cert RSA chain: 1286+1247+1528+359). embedded-tls decrypts records
//!   in place, so the read buffer must hold the largest inbound record whole.
//!   A live handshake with exactly 5120 B succeeds; steady-state DERP relayed
//!   records (~1500 B WG packets) are far smaller.
//! * `RECORD_WRITE_BUF` = 2048 B. Covers a ~1500-byte relayed WG packet plus
//!   DERP SendPacket framing (37 B) and `TLS_RECORD_OVERHEAD` (128 B).
//! * `TlsConnection` fixed state (key schedule, traffic secrets, running
//!   SHA-256 transcript, cipher keys/IVs, record reader/writer) ≈ 1.2-1.4 KB.
//!
//! => **~8.5 KB per DERP TLS session, steady-state AND handshake peak**
//! (embedded-tls performs the handshake inside these same fixed buffers with
//! no heap spike; NoVerify skips the one large transient, the signature check).
//! That is ~6.5% of the ~130 KB free heap and dwarfed by tm_wg's ~28 KB
//! `WgEndpoint`; an mbedTLS/esp-tls session would cost 40-70 KB instead.
//!
//! These numbers were validated host-side against the real
//! `derp1.tailscale.com` with this exact suite/verifier/buffer config (see
//! `docs/wg-dataplane-notes.md`); they are architecture-independent for the
//! buffers, and the fixed state is marginally smaller on 32-bit.
//!
//! ## DERP protocol logic
//!
//! Reused field-for-field from the peer-validated
//! `tools/wg_validator/derp_client.py`: the `GET /derp` HTTP/1.1 upgrade, the
//! ServerKey / ClientInfo / ServerInfo NaCl `crypto_box` (SalsaBox) handshake,
//! and `type(1) + length(4 BE) + body` framing. Only the TLS backend changed
//! (was rustls/`tm_tls`; now embedded-tls).

use chacha20poly1305::ChaCha20Poly1305;
use crypto_box::{aead::Aead, Nonce, PublicKey as BoxPublic, SalsaBox, SecretKey as BoxSecret};
use digest::OutputSizeUser;
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};
use embedded_tls::{
    MaxFragmentLength, TlsCipherSuite, TlsConfig, TlsConnection, TlsContext, UnsecureProvider,
};
use rand_core::RngCore;
use sha2::Sha256;
use typenum::{Sum, U10, U12, U32};

use crate::{DerpError, DerpFrameType, DERP_MAGIC, MAX_DERP_PAYLOAD};

/// Smallest-RAM record buffers (see the module RAM note).
pub const RECORD_READ_BUF: usize = 5 * 1024;
pub const RECORD_WRITE_BUF: usize = 2 * 1024;

/// Single cipher suite: `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
///
/// embedded-tls 0.19 has no built-in ChaCha suite, so we implement the trait
/// here over the RustCrypto AEAD/hash already used by Noise/WireGuard. The
/// `LabelBufferSize` reconstructs embedded-tls's private `LabelBuffer` alias:
/// `hash_out(32) + longest_label(12) + overhead(10)`.
pub struct Chacha20Poly1305Sha256;
impl TlsCipherSuite for Chacha20Poly1305Sha256 {
    const CODE_POINT: u16 = 0x1303;
    type Cipher = ChaCha20Poly1305;
    type KeyLen = U32;
    type IvLen = U12;
    type Hash = Sha256;
    type LabelBufferSize = Sum<<Sha256 as OutputSizeUser>::OutputSize, Sum<U12, U10>>;
}

/// A DERP connection over embedded-tls. `S` is the raw byte transport
/// (`embedded_io_adapters::tokio_1::FromTokio<tokio::net::TcpStream>` on
/// ESP32-C3, since the control plane already dials plain TCP via tokio there).
pub struct DerpTls<'a, S: AsyncRead + AsyncWrite> {
    tls: TlsConnection<'a, S, Chacha20Poly1305Sha256>,
    /// 32-byte DERP server public key from the ServerKey frame.
    pub server_key: [u8; 32],
}

impl<'a, S: AsyncRead + AsyncWrite> DerpTls<'a, S> {
    /// Perform the TLS 1.3 handshake (no-verify, ChaCha-only) and the full DERP
    /// ServerKey/ClientInfo/ServerInfo handshake. `read_buf`/`write_buf` should
    /// be [`RECORD_READ_BUF`]/[`RECORD_WRITE_BUF`] sized.
    ///
    /// `our_pub`/`our_priv` are the node's Curve25519 key pair; the ClientInfo
    /// box is `Box(our_priv, server_pub)`, matching derp_client.py.
    pub async fn connect<R: RngCore + rand_core::CryptoRng>(
        socket: S,
        read_buf: &'a mut [u8],
        write_buf: &'a mut [u8],
        host: &str,
        our_pub: &[u8; 32],
        our_priv: &[u8; 32],
        mut rng: R,
    ) -> Result<DerpTls<'a, S>, DerpError> {
        let mut tls = TlsConnection::new(socket, read_buf, write_buf);
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures()
            .with_max_fragment_length(MaxFragmentLength::Bits11);
        // UnsecureProvider = NoVerify + NoSign: certificate verification off.
        let provider = UnsecureProvider::new::<Chacha20Poly1305Sha256>(&mut rng);
        tls.open(TlsContext::new(&config, provider))
            .await
            .map_err(|_| DerpError::Tls)?;

        // GET /derp HTTP/1.1 Upgrade (assembled without format! to avoid an fmt
        // chain on device).
        let mut req: heapless::String<256> = heapless::String::new();
        let _ = req.push_str("GET /derp HTTP/1.1\r\nHost: ");
        let _ = req.push_str(host);
        let _ = req.push_str(
            "\r\nConnection: Upgrade\r\nUpgrade: DERP\r\nUser-Agent: tm_derp/1.0\r\n\r\n",
        );
        write_all(&mut tls, req.as_bytes()).await?;
        tls.flush().await.map_err(|_| DerpError::Io)?;
        read_http_upgrade(&mut tls).await?;

        let mut buf: [u8; MAX_DERP_PAYLOAD] = [0u8; MAX_DERP_PAYLOAD];

        // ServerKey (0x01): magic(8) + server_pub(32).
        let (ft, n) = read_frame(&mut tls, &mut buf).await?;
        if ft != DerpFrameType::ServerKey as u8 || n < 40 || &buf[..8] != DERP_MAGIC {
            return Err(DerpError::HandshakeFailed);
        }
        let mut server_key = [0u8; 32];
        server_key.copy_from_slice(&buf[8..40]);

        // ClientInfo (0x02): node_pub(32) + nonce(24) + sealed JSON.
        let bx = SalsaBox::new(&BoxPublic::from(server_key), &BoxSecret::from(*our_priv));
        let mut nonce_bytes = [0u8; 24];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let info = br#"{"version":2,"canAckPings":true,"isProber":false}"#;
        let ct = bx
            .encrypt(&nonce, &info[..])
            .map_err(|_| DerpError::HandshakeFailed)?;
        write_frame(
            &mut tls,
            DerpFrameType::ClientInfo as u8,
            &[our_pub, &nonce_bytes, &ct],
        )
        .await?;

        // ServerInfo (0x03): nonce(24) + sealed JSON : decrypt to confirm box.
        let (ft, n) = read_frame(&mut tls, &mut buf).await?;
        if ft != DerpFrameType::ServerInfo as u8 || n < 24 {
            return Err(DerpError::HandshakeFailed);
        }
        let mut si_nonce = [0u8; 24];
        si_nonce.copy_from_slice(&buf[..24]);
        bx.decrypt(&Nonce::from(si_nonce), &buf[24..n])
            .map_err(|_| DerpError::HandshakeFailed)?;

        Ok(DerpTls { tls, server_key })
    }

    /// Send a WireGuard packet to `dst_key` as a DERP SendPacket (0x04) frame.
    pub async fn send_packet(&mut self, dst_key: &[u8; 32], packet: &[u8]) -> Result<(), DerpError> {
        write_frame(&mut self.tls, DerpFrameType::SendPacket as u8, &[dst_key, packet]).await
    }

    /// Read one DERP frame into `buf`; returns `(frame_type_byte, body_len)`.
    pub async fn read_frame(
        &mut self,
        buf: &mut [u8; MAX_DERP_PAYLOAD],
    ) -> Result<(u8, usize), DerpError> {
        read_frame(&mut self.tls, buf).await
    }

    /// Answer a server PING (0x12) with a PONG (0x13) echoing its payload.
    pub async fn pong(&mut self, ping_body: &[u8]) -> Result<(), DerpError> {
        write_frame(&mut self.tls, DerpFrameType::Pong as u8, &[ping_body]).await
    }
}

// ── Frame IO over embedded-tls (partial-read safe) ────────────────────────────

async fn read_exact<S: AsyncRead + AsyncWrite>(
    tls: &mut TlsConnection<'_, S, Chacha20Poly1305Sha256>,
    out: &mut [u8],
) -> Result<(), DerpError> {
    let mut got = 0;
    while got < out.len() {
        let n = tls.read(&mut out[got..]).await.map_err(|_| DerpError::Io)?;
        if n == 0 {
            return Err(DerpError::Io);
        }
        got += n;
    }
    Ok(())
}

async fn write_all<S: AsyncRead + AsyncWrite>(
    tls: &mut TlsConnection<'_, S, Chacha20Poly1305Sha256>,
    mut data: &[u8],
) -> Result<(), DerpError> {
    while !data.is_empty() {
        let n = tls.write(data).await.map_err(|_| DerpError::Io)?;
        if n == 0 {
            return Err(DerpError::Io);
        }
        data = &data[n..];
    }
    Ok(())
}

/// Read the HTTP/1.1 upgrade response up to CRLFCRLF; require a 101 status.
async fn read_http_upgrade<S: AsyncRead + AsyncWrite>(
    tls: &mut TlsConnection<'_, S, Chacha20Poly1305Sha256>,
) -> Result<(), DerpError> {
    let mut acc: heapless::Vec<u8, 512> = heapless::Vec::new();
    let mut one = [0u8; 1];
    let mut count = 0usize;
    loop {
        read_exact(tls, &mut one).await?;
        let _ = acc.push(one[0]);
        count += 1;
        let l = acc.len();
        if l >= 4 && &acc[l - 4..] == b"\r\n\r\n" {
            break;
        }
        if count > 4096 || acc.len() == acc.capacity() {
            return Err(DerpError::HandshakeFailed);
        }
    }
    let line_end = acc.iter().position(|&b| b == b'\r').unwrap_or(acc.len());
    if !acc[..line_end].windows(3).any(|w| w == b"101") {
        return Err(DerpError::HandshakeFailed);
    }
    Ok(())
}

async fn read_frame<S: AsyncRead + AsyncWrite>(
    tls: &mut TlsConnection<'_, S, Chacha20Poly1305Sha256>,
    buf: &mut [u8; MAX_DERP_PAYLOAD],
) -> Result<(u8, usize), DerpError> {
    let mut hdr = [0u8; 5];
    read_exact(tls, &mut hdr).await?;
    let ftype = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > buf.len() {
        return Err(DerpError::FrameTooLarge(len as u32));
    }
    if len > 0 {
        read_exact(tls, &mut buf[..len]).await?;
    }
    Ok((ftype, len))
}

async fn write_frame<S: AsyncRead + AsyncWrite>(
    tls: &mut TlsConnection<'_, S, Chacha20Poly1305Sha256>,
    ftype: u8,
    parts: &[&[u8]],
) -> Result<(), DerpError> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut hdr = [0u8; 5];
    hdr[0] = ftype;
    hdr[1..5].copy_from_slice(&(total as u32).to_be_bytes());
    write_all(tls, &hdr).await?;
    for p in parts {
        write_all(tls, p).await?;
    }
    tls.flush().await.map_err(|_| DerpError::Io)?;
    Ok(())
}
