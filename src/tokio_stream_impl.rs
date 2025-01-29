use core::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use pin_project_lite::pin_project;
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng, TryRngCore,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    spawn,
    time::{sleep, Duration},
};

use crate::{
    config::Config,
    error::{BadDataReceived, Error},
    state_machine::Obfuscator,
};

pin_project! {
    /// Asynchronous obfuscated stream based on `Tokio` runtime.
    ///
    /// [`ObfuscatedStream`] implements the [`AsyncRead`] and [`AsyncWrite`] traits,
    /// allowing it to be used similarly to a [`TcpStream`].
    ///
    /// [`TcpStream`]: tokio::net::TcpStream
    #[derive(Debug)]
    pub struct ObfuscatedStream<IO> {
        stream: IO,
        obfuscator: Obfuscator,
        read_state: ReadState,
        write_state: WriteState,
        detected_error: Option<BadDataReceived>,
        is_shutdown_by_err: Arc<AtomicBool>,
        rng: StdRng,
        max_delay_before_shutdown_in_millis: u64,
    }
}

/// State Transition Diagram
/// ```text
///
///          |
///          V
///   +---- Read <------+
///   |      |          |
///   |      V          |
///   |     WaitData ---+
///   |  
///   +--> DecoyMode
///
/// ```
#[derive(Copy, Clone, Debug)]
enum ReadState {
    Read,
    WaitData,
    DecoyMode,
}

/// State Transition Diagram
/// ```text
///
///    |
///    V
///  WaitData <---+
///    |          |
///    V          |
///   Write ------+
/// ```
#[derive(Copy, Clone, Debug)]
enum WriteState {
    WaitData,
    Write { written: usize },
}

impl<IO> ObfuscatedStream<IO> {
    /// Creates a new [`ObfuscatedStream`] instance from the underlying `stream`
    /// and the given `config`.
    ///
    /// For details on constructing and configuring `config`, refer to
    /// the [`config`] module.
    ///
    /// [`config`]: crate::config
    pub fn with_config_in(config: Config, stream: IO) -> Self {
        let mut random = [0u8; 144];
        OsRng
            .try_fill_bytes(&mut random)
            .expect("system random source failure");
        Self::with_config_and_random_in(config, random, stream)
    }

    /// Creates a new [`ObfuscatedStream`] instance from the underlying `stream`,
    /// the given `config` and a 144-byte cryptographically secure random number
    /// `random`.
    ///
    /// **Warning**: The `random` parameter must be sourced from a
    /// high-quality, cryptographically secure entropy source.
    /// Failure to do so may compromise the security provided by the `ObfuscatedStream`.
    /// For general use cases, the `with_config_in` method is recommended.
    ///
    /// For details on constructing and configuring `config`, refer to
    /// the [`config`] module.
    ///
    /// [`config`]: crate::config
    pub fn with_config_and_random_in(config: Config, random: [u8; 144], stream: IO) -> Self {
        Self {
            stream,
            read_state: ReadState::Read,
            write_state: WriteState::WaitData,
            obfuscator: Obfuscator::with_config_and_random(
                config,
                random[..136].try_into().unwrap(),
            ),
            detected_error: None,
            max_delay_before_shutdown_in_millis: 5000,
            is_shutdown_by_err: Arc::new(AtomicBool::new(false)),
            rng: {
                let seed = u64::from_le_bytes(random[136..].try_into().unwrap());
                StdRng::seed_from_u64(seed)
            },
        }
    }

    /// Sets the maximum delay before closing the connection after an error
    /// is detected, in milliseconds. The default is 5000 milliseconds.
    ///
    /// The delay before shutdown is sampled from a uniform distribution within
    /// the range `[0, delay_in_millis]`.
    pub fn set_max_delay_before_shutdown(&mut self, delay_in_millis: u64) {
        self.max_delay_before_shutdown_in_millis = delay_in_millis;
    }

    /// Returns a reference to the internal stream.
    pub fn inner_stream(&self) -> &IO {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn inner_stream_mut(&mut self) -> &mut IO {
        &mut self.stream
    }

    /// Immediately updates the session keys using the provided key material.
    ///
    /// This function performs the same operation as [`Obfuscator::update_key`].
    /// For more details, refer to the documentation of that function.
    pub fn update_key(&mut self, key_material: [u8; 32]) -> std::io::Result<()> {
        self.obfuscator.update_key(key_material)
    }

    /// Sends a key update notification to the peer and updates the session key
    /// after the notification is sent.
    ///
    /// This function performs the same operation as
    /// [`Obfuscator::update_key_with_notif`].
    /// For more details, refer to the documentation of that function.
    pub fn update_key_with_notif(&mut self, key_material: [u8; 32]) -> std::io::Result<()> {
        self.obfuscator.update_key_with_notif(key_material)
    }
}

impl<IO> AsyncRead for ObfuscatedStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut me = self.project();
        loop {
            if me.is_shutdown_by_err.load(Ordering::Acquire) {
                return if let Some(reason) = &me.detected_error {
                    Poll::Ready(Err(Error::BadDataReceived(reason.clone()).into()))
                } else {
                    // This branch is never reached.
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                };
            }
            match *me.read_state {
                ReadState::Read => {
                    let mut reader = SyncReadAdapter {
                        io: &mut me.stream,
                        cx,
                    };
                    match me.obfuscator.read_wire(&mut reader) {
                        // Read successfully, deliver the buffered data to the caller.
                        Ok(n) if n > 0 => *me.read_state = ReadState::WaitData,

                        // Reached EOF.
                        Ok(_) => return Poll::Ready(Ok(())),

                        // Wait for more data, pending.
                        Err(e) if e.kind() == ErrorKind::WouldBlock => return Poll::Pending,

                        // Data corruption, close connection after random delay.
                        Err(e) if e.kind() == ErrorKind::Other => {
                            match e.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
                                Some(Error::BadDataReceived(reason)) => {
                                    // After the obfuscator returns `BadDataReceived`,
                                    // it will not return the same value again.
                                    // But for the sake of robustness, we still
                                    // check whether the error has been detected here.
                                    if me.detected_error.is_some() {
                                        return Poll::Ready(Err(e));
                                    }

                                    *me.detected_error = Some(reason.clone());

                                    let max_delay = *me.max_delay_before_shutdown_in_millis;
                                    let delay_before_shutdown = me.rng.random_range(0..=max_delay);
                                    let is_shutdown_by_err = me.is_shutdown_by_err.clone();

                                    // start a timer.
                                    spawn(async move {
                                        sleep(Duration::from_millis(delay_before_shutdown)).await;
                                        is_shutdown_by_err.store(true, Ordering::Release);
                                    });

                                    // Into decoy mode, continue "fake reading".
                                    *me.read_state = ReadState::DecoyMode;
                                }
                                _ => return Poll::Ready(Err(e)),
                            }
                        }

                        // general I/O error.
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                }
                ReadState::WaitData => {
                    return match me.obfuscator.reader().read(buf.initialize_unfilled()) {
                        Ok(n) => {
                            buf.advance(n);
                            *me.read_state = ReadState::Read;
                            Poll::Ready(Ok(()))
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            *me.read_state = ReadState::Read; // try to read again.
                            continue;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                }
                ReadState::DecoyMode => {
                    let mut reader = SyncReadAdapter {
                        io: &mut me.stream,
                        cx,
                    };
                    match me.obfuscator.read_wire(&mut reader) {
                        // Read successfully, decoy mode completes, connection closed
                        Ok(n) if n > 0 => me.is_shutdown_by_err.store(true, Ordering::Release),

                        // reached EOF.
                        Ok(_) => return Poll::Ready(Ok(())),

                        // pending, wait for more data.
                        Err(e) if e.kind() == ErrorKind::WouldBlock => return Poll::Pending,

                        // general I/O error.
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            }
        }
    }
}

impl<IO> AsyncWrite for ObfuscatedStream<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut me = self.project();
        loop {
            // If an error occurs on the read side,
            // stop the upper-layer application from continuing to write data
            if me.is_shutdown_by_err.load(Ordering::Acquire) {
                return if let Some(reason) = &me.detected_error {
                    Poll::Ready(Err(Error::BadDataReceived(reason.clone()).into()))
                } else {
                    // This branch is never reached.
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                };
            }
            match me.write_state {
                WriteState::WaitData => match me.obfuscator.writer().write(buf) {
                    Ok(written) => {
                        *me.write_state = WriteState::Write { written };
                    }
                    Err(e) => {
                        return Poll::Ready(Err(e));
                    }
                },
                WriteState::Write { written } => {
                    let mut writer = SyncWriteAdapter {
                        io: &mut me.stream,
                        cx,
                    };
                    return match me.obfuscator.write_wire(&mut writer) {
                        // normal write, continue to write data.
                        Ok(_n) => {
                            let written = *written;
                            *me.write_state = WriteState::WaitData;
                            Poll::Ready(Ok(written))
                        }

                        // pending, wait for I/O.
                        Err(e) if e.kind() == ErrorKind::WouldBlock => Poll::Pending,

                        // I/O error from the writer.
                        Err(e) => Poll::Ready(Err(e)),
                    };
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let mut me = self.project();
        // If an error occurs on the read side,
        // stop the upper-layer application from continuing to write data
        if me.is_shutdown_by_err.load(Ordering::Acquire) {
            return if let Some(reason) = &me.detected_error {
                Poll::Ready(Err(Error::BadDataReceived(reason.clone()).into()))
            } else {
                // This branch is never reached.
                Poll::Ready(Err(ErrorKind::InvalidData.into()))
            };
        }
        match me.write_state {
            WriteState::WaitData => Poll::Ready(Ok(())),
            WriteState::Write { .. } => {
                let mut writer = SyncWriteAdapter {
                    io: &mut me.stream,
                    cx,
                };
                match me.obfuscator.write_wire(&mut writer) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                };
                *me.write_state = WriteState::WaitData;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// An adapter that implements a [`Read`] interface for [`AsyncRead`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
///
/// The credit goes to the [futures-rustls](https://github.com/rustls/futures-rustls)
/// project for this adapter.
struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

/// An adapter that implements a [`Write`] interface for [`AsyncWrite`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
///
/// The credit goes to the [futures-rustls](https://github.com/rustls/futures-rustls)
/// project for this adapter.
struct SyncWriteAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::SharedKey;

    #[tokio::test]
    async fn test_async_read_write_echo() {
        const DATA_LEN: usize = 65536 * 10;
        let data = Arc::new(vec![0u8; DATA_LEN]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = spawn(async move {
            let (server_inner, _) = listener.accept().await.unwrap();
            let mut server_stream = ObfuscatedStream::with_config_in(
                Config::builder_with_shared_key(SharedKey::from([0u8; 32]))
                    .with_default_cipher_and_tcp_padding(),
                server_inner,
            );

            let mut buf = vec![0u8; DATA_LEN + 1024];
            server_stream
                .read_exact(&mut buf[..DATA_LEN])
                .await
                .unwrap();
            server_stream.write_all(&buf[..DATA_LEN]).await.unwrap();
        });

        let client_task = spawn(async move {
            let client_inner = TcpStream::connect(addr).await.unwrap();
            let mut client_stream = ObfuscatedStream::with_config_in(
                Config::builder_with_shared_key(SharedKey::from([0u8; 32]))
                    .with_default_cipher_and_tcp_padding(),
                client_inner,
            );
            let mut buf = vec![0u8; DATA_LEN + 1024];

            client_stream.write_all(&data).await.unwrap();
            client_stream
                .read_exact(&mut buf[..DATA_LEN])
                .await
                .unwrap();
            assert_eq!(&buf[..DATA_LEN], &data[..]);
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }
}
