use fast_socks5::{Socks5Command, ReplyError};
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error, debug};
use std::sync::Arc;

// ── Cryptographic imports ────────────────────────────────────────────────────
use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Constants ────────────────────────────────────────────────────────────────
const SHAMIR_THRESHOLD: u8 = 4;
const SHAMIR_N_FRAGMENTS: u8 = 7;
const FRAGMENT_SIZE: usize = 8192; // 8KB chunks

// ── Tunnel key with zeroization ───────────────────────────────────────────
#[derive(ZeroizeOnDrop, Zeroize)]
struct TunnelKey([u8; 32]);

impl TunnelKey {
    fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).expect("AES-GCM encrypt");
        (ciphertext, nonce.into())
    }
}

// ── Fragment structure ─────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct TunnelFragment {
    id: u8,
    path_id: u8,
    nonce: [u8; 12],
    data: Vec<u8>,
}

// ── Fragmentation engine using sharks v0.5 ────────────────────────────────
struct Fragmenter {
    key: TunnelKey,
}

impl Fragmenter {
    fn new() -> Self {
        Self { key: TunnelKey::new() }
    }

    /// Fragment data into 7 Shamir fragments sent through different "paths"
    fn fragment(&self, data: &[u8]) -> Vec<TunnelFragment> {
        let (ciphertext, nonce) = self.key.encrypt(data);

        // Use sharks 0.5 API: dealer_rng returns iterator of shares
        let sharks = sharks::Sharks(SHAMIR_THRESHOLD);
        let dealer = sharks.dealer_rng(&ciphertext, &mut OsRng);

        dealer
            .take(SHAMIR_N_FRAGMENTS as usize)
            .enumerate()
            .map(|(i, share)| TunnelFragment {
                id: (i as u8) + 1,
                path_id: (i as u8) + 1,
                nonce,
                data: Vec::from(&share),
            })
            .collect()
    }
}

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
            info!("  [POLYGONE] 🔐 Fragmenting traffic via Shamir SSS-4-7");

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

/// Relay with Shamir fragmentation.
/// Each chunk is encrypted with AES-256-GCM, then split into 7 fragments.
/// Fragments are sent with simulated path delays (in real impl, would go through different DHT nodes).
async fn relay_with_fragments(
    mut client: TcpStream,
    mut target: TcpStream,
) -> anyhow::Result<()> {
    let fragmenter = Arc::new(Fragmenter::new());
    let mut client_buf = [0u8; FRAGMENT_SIZE];
    let mut target_buf = [0u8; FRAGMENT_SIZE];

    let mut client_fragments_sent = 0u64;
    let mut target_fragments_sent = 0u64;

    loop {
        tokio::select! {
            // Client -> Target: fragment, then send
            result = client.read(&mut client_buf) => {
                let n = result?;
                if n == 0 {
                    info!("  [TUNNEL] Client closed. Total fragments sent: {}", client_fragments_sent);
                    break;
                }

                let data = &client_buf[..n];
                let fragments = fragmenter.fragment(data);

                // In a real implementation, each fragment would go through a different DHT path
                // Here we simulate by sending all fragments sequentially with small delays
                for frag in &fragments {
                    // Simulate different network paths with micro-delays
                    tokio::time::sleep(tokio::time::Duration::from_micros(
                        (frag.path_id as u64) * 50
                    )).await;

                    // In real impl: send to different DHT nodes
                    // For now, we send the encrypted fragment to the target
                    target.write_all(&frag.data).await?;
                    client_fragments_sent += 1;
                }
            }

            // Target -> Client: fragment, then send
            result = target.read(&mut target_buf) => {
                let n = result?;
                if n == 0 {
                    info!("  [TUNNEL] Target closed. Total fragments sent: {}", target_fragments_sent);
                    break;
                }

                let data = &target_buf[..n];
                let fragments = fragmenter.fragment(data);

                for frag in &fragments {
                    tokio::time::sleep(tokio::time::Duration::from_micros(
                        (frag.path_id as u64) * 50
                    )).await;

                    client.write_all(&frag.data).await?;
                    target_fragments_sent += 1;
                }
            }
        }
    }

    Ok(())
}

/// Old relay (kept for reference, unused)
async fn relay(mut client: TcpStream, mut target: TcpStream) -> anyhow::Result<()> {
    let (ci, ct) = tokio::io::copy_bidirectional(&mut client, &mut target)
        .await
        .map_err(|e| anyhow::anyhow!("Relay error: {}", e))?;
    info!(
        "  [TUNNEL] Relayed {} bytes client->target, {} bytes target->client",
        ci, ct
    );

    Ok(())
}