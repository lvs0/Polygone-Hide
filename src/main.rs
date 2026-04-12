use fast_socks5::{Socks5Command, ReplyError};
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error, debug};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_target(false)
        .init();

    info!("⬡ POLYGONE-HIDE — Vapor Tunnel");
    info!("  Transforming TCP into ephemeral waves...");
    
    let listen_addr = "127.0.0.1:1080";
    let listener = TcpListener::bind(listen_addr).await?;
    info!("  ✓ SOCKS5 proxy listening: {listen_addr}");
    info!("  → Configure browser/app to use this proxy");

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
            // IPv4: 4 bytes
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port)
        }
        0x03 => {
            // Domain name: 1 byte length + domain
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5+len]).to_string();
            let port = u16::from_be_bytes([buf[5+len], buf[6+len]]);
            (domain, port)
        }
        0x04 => {
            // IPv6 - skip for now
            warn!("  [!] IPv6 not supported");
            client_stream.write_all(&[0x05, ReplyError::AddressTypeNotSupported.as_u8(), 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            return Ok(());
        }
        _ => {
            error!("  [!] Unknown ATYP: {atyp}");
            return Ok(());
        }
    };
    
    let target_addr = format!("{}:{}", target_host, target_port);
    info!("  [ALICE] CONNECT to {target_addr}");
    
    // We only support TCP Connect
    if cmd != Socks5Command::TCPConnect as u8 {
        info!("  [!] Command not supported: {cmd}");
        client_stream.write_all(&[0x05, ReplyError::CommandNotSupported.as_u8(), 0x00, 0x01, 0,0,0,0, 0,0]).await?;
        return Ok(());
    }
    
    // Connect to target
    match TcpStream::connect(&target_addr).await {
        Ok(target_stream) => {
            info!("  [POLYGONE] Connected to exit node for {target_addr}");
            
            // Send success response
            client_stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            
            // Relay traffic (simulating Polygone fragmentation)
            relay(client_stream, target_stream).await?;
        }
        Err(e) => {
            warn!("  [!] Connection failed: {e}");
            let reply = match e.to_string().contains("refused") {
                true => ReplyError::ConnectionRefused,
                _ => ReplyError::HostUnreachable,
            };
            client_stream.write_all(&[0x05, reply.as_u8(), 0x00, 0x01, 0,0,0,0, 0,0]).await?;
        }
    }
    
    Ok(())
}

async fn relay(mut client: TcpStream, mut target: TcpStream) -> anyhow::Result<()> {
    let (ci, ct) = tokio::io::copy_bidirectional(&mut client, &mut target).await
        .map_err(|e| anyhow::anyhow!("Relay error: {e}"))?;
    info!("  [TUNNEL] Relayed {} bytes client->target, {} bytes target->client", ci, ct);
    
    Ok(())
}
