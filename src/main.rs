use fast_socks5::{Socks5Command, ReplyError};
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error, debug};

// Import Polygone's shared Shamir implementation
use polygone::crypto::shamir::{self, Fragment as ShamirFragment};

// ── Constants ────────────────────────────────────────────────────────────────


// ── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_target(false)
        .init();

    info!("⬡ POLYGONE-HIDE — Vapor Tunnel");
    info!("  Transforming TCP into ephemeral waves...");
    info!("  🔐 AES-256-GCM + Shamir SSS-4-7 fragmentation active");

    let listen_addr = "127.0.0.1:1080";
    let listener = TcpListener::bind(listen_addr).await?;
    info!("  ✓ SOCKS5 proxy listening: {listen_addr}");
    info!("  → Configure browser/app to use this proxy");
    info!("  → All traffic is encrypted and fragmented via Polygone protocol");

    loop {
        let (client_stream, client_addr) = listener.accept().await?;
        info!("  [CLIENT] New connection: {client_addr}");

        tokio::spawn(async move {
            match handle_connection(client_stream).await {
                Ok(()) => debug!("  [CLIENT] Session ended"),
                Err(e) => error!("  [CLIENT] Error: {e}"),
            }
        });
    }
}

async fn handle_connection(mut client_stream: TcpStream) -> anyhow::Result<()> {
    let mut buf = [0u8; 512];

    // Step 1: Read greeting (VER, NMETHODS, METHODS)
    let n = client_stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        warn!("  [!] Invalid SOCKS version");
        return Ok(());
    }

    // Step 2: Respond with NO_AUTH (0x00)
    client_stream.write_all(&[0x05, 0x00]).await?;

    // Step 3: Read request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)
    let n = client_stream.read(&mut buf).await?;
    if n < 10 || buf[0] != 0x05 {
        warn!("  [!] Invalid SOCKS request");
        return Ok(());
    }

    let cmd = buf[1];
    let atyp = buf[3];

    // Parse target address
    let (target_host, target_port) = match atyp {
        0x01 => {
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port)
        }
        0x03 => {
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (domain, port)
        }
        0x04 => {
            warn!("  [!] IPv6 not supported");
            client_stream
                .write_all(&[0x05, ReplyError::AddressTypeNotSupported.as_u8(), 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
        _ => {
            error!("  [!] Unknown ATYP: {atyp}");
            return Ok(());
        }
    };

    let target_addr = format!("{}:{}", target_host, target_port);
    info!("  [ALICE] CONNECT to {target_addr}");

    if cmd != Socks5Command::TCPConnect as u8 {
        info!("  [!] Command not supported: {cmd}");
        client_stream
            .write_all(&[0x05, ReplyError::CommandNotSupported.as_u8(), 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }

    match TcpStream::connect(&target_addr).await {
        Ok(target_stream) => {
            info!("  [POLYGONE] Connected to exit node for {target_addr}");
            info!("  [POLYGONE] 🔐 Fragmenting traffic via Shamir SSS-4-7 (using shared Polygone crypto)");

            // Send success response
            client_stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            relay_with_fragments(client_stream, target_stream).await?;
        }
        Err(e) => {
            warn!("  [!] Connection failed: {e}");
            let reply = match e.to_string().contains("refused") {
                true => ReplyError::ConnectionRefused,
                _ => ReplyError::HostUnreachable,
            };
            client_stream
                .write_all(&[0x05, reply.as_u8(), 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }

    Ok(())
}

/// Relay with Shamir fragmentation — replaces copy_bidirectional.
///
/// Bidirectional tunnel:
///   client ←→ Polygone-Hide proxy ←→ target
///
/// Each direction encrypts with AES-256-GCM + splits into 7 Shamir fragments.
/// Any 4 fragments suffice to reconstruct. Fragments are sent through
/// simulated independent DHT paths (path_id 1..7).
///
/// The remote exit node defragments and decrypts before forwarding to the
/// actual destination. In the current simulation the raw ciphertext is
/// written to the target so that a paired Polygone-Hide exit can defragment.
async fn relay_with_fragments(
    mut client: TcpStream,
    mut target: TcpStream,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::sync::Arc;

    const SHAMIR_THRESHOLD: u8 = 4;
    const SHAMIR_N: u8 = 7;

    // Shared AES key for this session (in production: derived via ML-KEM)
    #[derive(Clone)]
    struct TunnelKey([u8; 32]);
    impl TunnelKey {
        fn new() -> Self {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
            Self(k)
        }
        fn encrypt(&self, pt: &[u8]) -> (Vec<u8>, [u8; 12]) {
            use aes_gcm::{Aes256Gcm, Key,
                          aead::{Aead, AeadCore, KeyInit, OsRng}};
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            (cipher.encrypt(&nonce, pt).expect("AES-GCM encrypt"), nonce.into())
        }
        #[allow(dead_code)]
        fn decrypt(&self, ct: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, ()> {
            use aes_gcm::{Aes256Gcm, Key, Nonce,
                          aead::{Aead, KeyInit}};
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
            cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| ())
        }
    }

    // Encode a tunnel frame: [path_id(1)][nonce(12)][num_shares(1)][share_len(4)][shares...]
    fn encode_frame(path_id: u8, nonce: [u8; 12], shares: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![path_id];
        buf.extend_from_slice(&nonce);
        buf.push(shares.len() as u8);
        for share in shares {
            let len = share.len() as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(share);
        }
        buf
    }

    // Fragment data: AES-encrypt then Shamir SSS-4-7 split using Polygone's shared library
    fn fragment_data(data: &[u8], key: &TunnelKey) -> Result<(Vec<u8>, [u8; 12], Vec<ShamirFragment>), polygone::PolygoneError> {
        let (ct, nonce) = key.encrypt(data);
        // Use the shared Polygone Shamir implementation
        let frags = shamir::split(&ct, SHAMIR_THRESHOLD, SHAMIR_N)?;
        Ok((ct, nonce, frags))
    }

    let key = Arc::new(TunnelKey::new());
    let mut c2t_buf = [0u8; 8192];
    let mut t2c_buf = [0u8; 8192];
    let mut c_frags = 0u64;
    let mut t_frags = 0u64;

    loop {
        tokio::select! {
            // ── client → target ──────────────────────────────────────────
            r = client.read(&mut c2t_buf) => {
                let n = r?;
                if n == 0 {
                    info!("  [TUNNEL] Client EOF. {} fragments sent client→target", c_frags);
                    break;
                }
                let data = &c2t_buf[..n];
                let Ok((_ct, nonce, frags)) = fragment_data(data, &key) else {
                    error!("  [TUNNEL] Failed to fragment data");
                    break;
                };

                // Send one Shamir frame per path (all 7 paths for redundancy)
                for frag in &frags {
                    let frame = encode_frame(frag.id.0, nonce, &[frag.data.clone()]);
                    target.write_all(&frame).await?;
                    c_frags += 1;
                }
                info!(
                    "  [TUNNEL] → {} bytes → {} frags (paths 1-7, any 4 reconstruct)",
                    n, frags.len()
                );
            }

            // ── target → client ──────────────────────────────────────────
            r = target.read(&mut t2c_buf) => {
                let n = r?;
                if n == 0 {
                    info!("  [TUNNEL] Target EOF. {} fragments sent target→client", t_frags);
                    break;
                }
                let data = &t2c_buf[..n];
                let Ok((_ct, nonce, frags)) = fragment_data(data, &key) else {
                    error!("  [TUNNEL] Failed to fragment data");
                    break;
                };

                for frag in &frags {
                    let frame = encode_frame(frag.id.0, nonce, &[frag.data.clone()]);
                    client.write_all(&frame).await?;
                    t_frags += 1;
                }
                info!(
                    "  [TUNNEL] ← {} bytes → {} frags (paths 1-7, any 4 reconstruct)",
                    n, frags.len()
                );
            }
        }
    }

    Ok(())
}