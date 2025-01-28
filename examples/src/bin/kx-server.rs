use obfswire::{Config, ObfuscatedStream, SharedKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    const ADDRESS: &str = "127.0.0.1:9092";
    let listener = TcpListener::bind(ADDRESS).await?;
    println!("Listening on address: {:?}", ADDRESS);

    loop {
        let (socket, addr) = listener.accept().await?;
        let mut stream = ObfuscatedStream::with_config_in(
            Config::builder_with_shared_key(SharedKey::from([0u8; 32]))
                .with_default_cipher_and_tcp_padding(),
            socket,
        );
        println!("receiving obfs stream from a new client: {:?}", addr);
        tokio::spawn(async move {
            let server_secret = EphemeralSecret::random();
            let server_public = PublicKey::from(&server_secret);

            let mut client_public = [0u8; 32];
            stream.read_exact(&mut client_public).await?;
            stream.write_all(server_public.as_bytes()).await?;

            let key_material = server_secret
                .diffie_hellman(&PublicKey::from(client_public))
                .to_bytes();
            stream.update_key(key_material)?;
            println!("cv25519 key exchange successfully");

            loop {
                let mut buf = vec![0; 1024];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        println!("received message: {}", String::from_utf8_lossy(&buf[..n]));
                        stream.write_all(&buf[..n]).await?;
                        println!("echoed message");
                    }
                    Ok(_) => {
                        stream.inner_stream_mut().shutdown().await?;
                        println!("client closed connection: {:?}", addr);
                        return Ok::<(), std::io::Error>(());
                    }
                    Err(e) => {
                        stream.inner_stream_mut().shutdown().await?;
                        println!("failed to read from socket; error = {:?}", e);
                        return Err(e);
                    }
                }
            }
        });
    }
}
