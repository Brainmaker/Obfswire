# Obfswire

[![Build Status](https://github.com/Brainmaker/Obfswire/actions/workflows/ci.yml/badge.svg)](https://github.com/Brainmaker/Obfswire/actions/workflows/ci.yml)
![docs.rs](https://img.shields.io/docsrs/obfswire)
[![codecov](https://codecov.io/github/Brainmaker/Obfswire/graph/badge.svg?token=WVLFE0TA33)](https://codecov.io/github/Brainmaker/Obfswire)
![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%20or%20Apache%202.0-blue)

Obfswire is a network obfuscation protocol designed to counter Deep Packet 
Inspection (DPI) and active probing, offering privacy and anti-analysis 
capabilities for reliable and ordered stream transmission.

[API Documentation](https://docs.rs/obfswire/latest/obfswire/)

## Features

- Provides endpoint authentication, data integrity, and confidentiality to 
  ensure secure data transmission.
- Offers complete protection against replay attacks, safeguarding 
  against man-in-the-middle (MITM) replay attempts.
- Resists active probing that targets endpoint state machine behavior,
  enhancing robustness against active probing.
- Supports optional randomized packet length to mitigate passive traffic
  analysis, balancing obfuscation with performance.
- Enables 0-RTT data transmission for low-latency communication.
- Easily integrates with various key exchange schemes to provide forward secrecy, 
  minimizing performance overhead caused by nested encryption.
- Implements a fully state-driven sans-I/O protocol, without handling network 
  I/O directly or spawning internal threads.
- Optionally supports asynchronous streams based on [`tokio`][tokio-link], 
  providing an interface similar to [`TcpStream`][tcp-stream-link] for async 
  application development.

## Design Goals

#### Obfswire Adopts the Obfs4 Threat Model

Obfswire establishes an obfuscated tunnel between two endpoints, aiming to make 
transmitted content indistinguishable from random byte streams. It also protects 
against active probing and non-content protocol fingerprinting, 
adhering to the threat model of [obfs4][obfs4-link].

#### Obfswire Focuses on Modular Obfuscation

Obfswire is designed with a modular architecture that separates obfuscation from 
other transport-layer functionalities. This ensures that obfswire focuses 
exclusively on obfuscation without directly implementing features like key exchange, 
client authentication, multiplexing, DNS resolution, or proxying. These capabilities 
can be integrated by upper-layer protocols, allowing for greater flexibility to 
meet diverse application needs.

While obfswire typically operates over reliable and ordered streams, such as TCP 
connections, it is not strictly tied to TCP. Any underlying transport implementing 
Rust’s [`Read`][read-trait-link] and [`Write`][write-trait-link] traits can be 
used as the foundation for obfswire's obfuscation pipeline.

#### Obfswire Integrates with Application-Layer Forward Secrecy

Obfswire is designed as a 0-RTT protocol to enable low-latency communication. 
It ensures data confidentiality, integrity, and endpoint authentication through 
pre-shared keys. While key exchange mechanisms can provide forward secrecy, they 
introduce additional handshake latency, which may not be suitable for 
latency-sensitive scenarios. Furthermore, the use of certain key exchange algorithms, 
such as post-quantum cryptographic methods, can significantly increase 
computational overhead.

To strike a balance between 0-RTT efficiency and forward secrecy, Obfswire 
delegates key exchange responsibilities to the application layer.
Although Obfswire does not include a built-in key exchange mechanism, it offers 
seamless integration points for implementing such protocols within its 
obfuscation pipeline. This approach allows applications to negotiate shared keys 
while reusing Obfswire's encryption pipeline, eliminating the performance overhead
of nested encryption.

## Usage

Here’s a minimal, client-server echo code snippet to help you get started:

```rust
use obfswire::{Config, ObfuscatedStream, SharedKey};
use tokio::{
    net::{TcpListener, TcpStream},
    io::{AsyncReadExt, AsyncWriteExt}
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let message = b"Hello, world!";

    // Setup a TCP listener
    let listener = TcpListener::bind("127.0.0.1:8888").await?;

    // Setup a client/server common configuration
    let config = Config::builder_with_shared_key(SharedKey::from_entropy())
        .with_default_cipher_and_tcp_padding();

    let client_config = config.clone();
    let client_task = tokio::spawn(async move {
        // Get a TCP connection
        let stream = TcpStream::connect("127.0.0.1:8888").await?;

        // Setup a client stream of obfswire
        let mut client_stream = ObfuscatedStream::with_config_in(client_config, stream);

        // Do some I/O
        client_stream.write_all(message).await?;
        let mut buf = [0; 128];
        client_stream.read_exact(&mut buf[..message.len()]).await?;
        println!("Client received: {}", String::from_utf8_lossy(&buf[..message.len()]));
        Ok::<(), std::io::Error>(())
    });

    // Accept a TCP connection
    while let Ok((stream, _)) = listener.accept().await {
        let server_config = config.clone();

        // Handle client connection
        tokio::spawn(async move {
            // Setup server stream of obfswire
            let mut server_stream = ObfuscatedStream::with_config_in(server_config, stream);

            // Do some I/O
            let mut buf = [0; 128];
            server_stream.read_exact(&mut buf[..message.len()]).await?;
            println!("Server received: {}", String::from_utf8_lossy(&buf[..message.len()]));
            server_stream.write_all(&buf[..message.len()]).await?;
            Ok::<(), std::io::Error>(())
        });
    }

    client_task.await??;
    Ok(())
}
```

For more practical examples, refer to the [examples](examples/src/bin) directory:

 - [`simple-client`](examples/src/bin/simple-client.rs) and 
   [`simple-server`](examples/src/bin/simple-server.rs):
   Demonstrate a minimal Obfswire client and server setup.
 - [`kx-client`](examples/src/bin/kx-client.rs) and 
   [`kx-server`](examples/src/bin/kx-server.rs):
   Show how to integrate Obfswire with an application-layer key exchange protocol.
 - [`tokio_stream_impl`](src/tokio_stream_impl.rs):
   Part of the library code that demonstrates how to integrate the Obfswire state 
   machine with asynchronous streams using tokio. This can serve as a reference for 
   implementing similar functionality in your own projects.

## License

This project is licensed under either of
- MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0)) at your option.

[obfs4-link]: https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt#L35
[tokio-link]: https://tokio.rs/
[tcp-stream-link]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html
[read-trait-link]: https://doc.rust-lang.org/std/io/trait.Read.html
[write-trait-link]: https://doc.rust-lang.org/std/io/trait.Write.html
