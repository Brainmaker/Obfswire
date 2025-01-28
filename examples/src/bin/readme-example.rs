use obfswire::{Config, ObfuscatedStream, SharedKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let message = b"Hello, world!";

    // Setup TCP listener
    let listener = TcpListener::bind("127.0.0.1:8888").await?;

    // Setup client/server common configuration
    let config = Config::builder_with_shared_key(SharedKey::from_entropy())
        .with_default_cipher_and_tcp_padding();

    let client_config = config.clone();
    let client_task = tokio::spawn(async move {
        // Get a TCP connection
        let stream = TcpStream::connect("127.0.0.1:8888").await?;

        // Setup client stream of obfswire
        let mut client_stream = ObfuscatedStream::with_config_in(client_config, stream);

        // Do some I/O
        client_stream.write_all(message).await?;
        let mut buf = [0; 128];
        client_stream.read_exact(&mut buf[..message.len()]).await?;
        println!(
            "Client received: {}",
            String::from_utf8_lossy(&buf[..message.len()])
        );
        Ok::<(), std::io::Error>(())
    });

    // Accept a TCP connection
    while let Ok((stream, _)) = listener.accept().await {
        let server_config = config.clone();

        // handle client connection
        tokio::spawn(async move {
            // Setup server stream of obfswire
            let mut server_stream = ObfuscatedStream::with_config_in(server_config, stream);

            // Do some I/O
            let mut buf = [0; 128];
            server_stream.read_exact(&mut buf[..message.len()]).await?;
            println!(
                "Server received: {}",
                String::from_utf8_lossy(&buf[..message.len()])
            );
            server_stream.write_all(&buf[..message.len()]).await?;
            Ok::<(), std::io::Error>(())
        });
    }

    client_task.await??;
    Ok(())
}
