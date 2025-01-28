use obfswire::{Config, ObfuscatedStream, SharedKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    const ADDRESS: &str = "127.0.0.1:9091";
    let socket = TcpStream::connect(ADDRESS).await?;
    let mut stream = ObfuscatedStream::with_config_in(
        Config::builder_with_shared_key(SharedKey::from([0u8; 32]))
            .with_default_cipher_and_tcp_padding(),
        socket,
    );
    println!("connected to server: {:?}", ADDRESS);

    for i in 1..=2 {
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
            }
            Err(e) => {
                println!("read failed: {:?}", e);
                return Err(e);
            }
        }
    }
    stream.inner_stream_mut().shutdown().await?;
    Ok(())
}
