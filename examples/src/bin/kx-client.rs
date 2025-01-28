use obfswire::{Config, ObfuscatedStream, SharedKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    const ADDRESS: &str = "127.0.0.1:9092";
    let socket = TcpStream::connect(ADDRESS).await?;
    let mut stream = ObfuscatedStream::with_config_in(
        Config::builder_with_shared_key(SharedKey::from([0u8; 32]))
            .with_default_cipher_and_tcp_padding(),
        socket,
    );
    println!("connected to server: {:?}", ADDRESS);

    let client_secret = EphemeralSecret::random();
    let client_public = PublicKey::from(&client_secret);

    stream.write_all(client_public.as_bytes()).await?;

    let mut server_public = [0u8; 32];
    stream.read_exact(&mut server_public).await?;

    let key_material = client_secret
        .diffie_hellman(&PublicKey::from(server_public))
        .to_bytes();
    stream.update_key(key_material)?;
    println!("cv25519 key exchange successfully");

    for i in 1..=4 {
        match stream.write(format!("message {}", i).as_bytes()).await {
            Ok(n) if n > 0 => {
                println!("sent successfully");
            }
            Ok(_) => {
                println!("server closed connection");
            }
            Err(e) => {
                println!("sending failed: {:?}", e);
                return Err(e);
            }
        }

        let mut buf = vec![0; 1024];
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => {
                println!(
                    "echo message received: {}",
                    String::from_utf8_lossy(&buf[..n])
                );
            }
            Ok(_) => {
                println!("server closed connection");
                break;
            }
            Err(err) => {
                println!("read failed: {:?}", err);
                return Err(err);
            }
        }
    }
    stream.inner_stream_mut().shutdown().await?;
    Ok(())
}
