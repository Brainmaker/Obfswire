use std::io::{self, BufRead, ErrorKind, Read, Write};

use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng, TryRngCore,
};

use crate::{
    codec::{
        Command, FrameBufMut, FrameDecoder, FrameEncoder, InitFrameBufMut, InitFrameDecoder,
        InitFrameEncoder,
    },
    config::{Config, EndpointType},
    crypto::SessionKey,
    error::{Error, Retryable},
    specification::{
        BODY_MAX_LEN, BODY_MIN_LEN, FRAME_MAX_LEN, HDR_LEN, INIT_BODY_MAX_LEN, INIT_BODY_MIN_LEN,
        INIT_FRAME_MAX_LEN, INIT_FRAME_MIN_LEN, INIT_HDR_LEN
    },
};

/// A network traffic obfuscator that provides a secure communication channel.
///
/// The `Obfuscator` acts as an obfuscation/deobfuscation state machine.
/// You provide plaintext on one side and receive encrypted traffic on the other,
/// and vice versa:
///
/// ```text
///         Plaintext                           Obfuscated Data
///         =========                           ===============
///     writer()        +-------------------+      write_wire()
///                     |                   |
///           +--------->                   +--------->
///                     |    Obfuscator     |
///           <---------+                   <---------+
///                     |                   |
///     reader()        +-------------------+       read_wire()
/// ```
///
/// * Use [`read_wire`] to receive and decode an obfuscated frame from a peer.
///   Then, use [`reader`] to create a [`Reader`] for reading the plaintext.
///
/// * Use [`writer`] to create a [`Writer`] to write data into the internal buffer,
///   and then use [`write_wire`] to send the obfuscated frame to the peer.
///
/// [`read_wire`]: Obfuscator::read_wire
/// [`write_wire`]: Obfuscator::write_wire
/// [`reader`]: Obfuscator::reader
/// [`writer`]: Obfuscator::writer
/// [`update_key_by_material`]: Obfuscator::update_key_with_notif
/// [`Retryable::KeySyncRequired`]: Retryable::KeyMaterialRequired
#[derive(Debug)]
pub struct Obfuscator {
    read_state: ReadState,
    write_state: WriteState,
    init_state: InitState,
    init_receiver: InitReceiver,
    init_sender: InitSender,
    receiver: Receiver,
    sender: Sender,
    stream_id: u64,
}

impl Obfuscator {
    /// Creates a new `Obfuscator` with the specified `config`.
    ///
    /// For details on constructing and configuring `config`, refer to
    /// the [`config`] module.
    ///
    /// [`config`]: crate::config
    pub fn with_config(config: Config) -> Self {
        let mut random = [0u8; 136];
        OsRng
            .try_fill_bytes(&mut random)
            .expect("system random source failure");
        Self::with_config_and_random(config, random)
    }

    /// Creates a new `Obfuscator` with the specified `config`
    /// and a 136-byte cryptographically secure random number.
    ///
    /// This method can be used when you need to deterministically construct
    /// an `Obfuscator`.
    ///
    /// **Warning**: The `random` parameter must be sourced from a
    /// high-quality, cryptographically secure entropy source.
    /// Failure to do so may compromise the security provided by the `Obfuscator`.
    /// For general use cases, the `with_config` method is recommended.
    ///
    /// For details on constructing and configuring `config`, refer to
    /// the [`config`] module.
    ///
    /// [`config`]: crate::config
    pub fn with_config_and_random(config: Config, random: [u8; 136]) -> Self {
        Self {
            read_state: ReadState::WaitInit,
            write_state: WriteState::WaitInitialData,
            init_state: InitState::Uninitialized,
            init_sender: InitSender::with_config_and_rng(
                &config,
                StdRng::from_seed(random[..32].try_into().unwrap()),
            ),
            init_receiver: InitReceiver::with_config_and_rng(
                &config,
                StdRng::from_seed(random[32..64].try_into().unwrap()),
            ),
            sender: Sender::with_config_and_rng(
                &config,
                StdRng::from_seed(random[64..96].try_into().unwrap()),
            ),
            receiver: Receiver::with_config_and_rng(
                &config,
                StdRng::from_seed(random[96..128].try_into().unwrap()),
            ),
            stream_id: u64::from_le_bytes(random[128..].try_into().unwrap()),
        }
    }

    /// Read obfuscated data from the `wire` into the internal buffer,
    /// returning how many bytes were read.
    ///
    /// The `wire` implements the `Read` trait, so it can provide a data
    /// stream like a socket or pipe, and the obfuscator will automatically
    /// frame the data.
    ///
    /// Once this function succeeds, you can call [`reader`] to get a reader
    /// pointing to the internal buffer to access the plaintext payload.
    ///
    /// If this function returns `Ok(n)` where `n > 0`, it indicates the number
    /// of bytes read from the `wire`. Calling this function again will read new
    /// data from the `wire` and overwrite the previously read data in the
    /// internal buffer.
    ///
    /// If this function returns `Ok(0)`, it indicates that this obfuscator has
    /// reached the EOF of `wire`, and the underlying connection shoud be closed.
    ///
    /// # Errors
    ///
    /// 1. If an I/O error occurs on the underlying connection, i.e.,
    ///    the `wire`, this function will return the [`io::Error`] from
    ///    the `wire`;  this is a recoverable error, and you can call this
    ///    function again to resume the obfuscator from the point of interruption
    ///    if the underlying connection becomes readable again.
    ///
    ///    For example, the `wire` might return I/O error with
    ///    `ErrorKind::WouldBlock`, indicating that the current read needs to
    ///    block to complete, and you can call this function again later to
    ///    complete the read operation.
    ///
    /// 2. If the state machine returns I/O error with `ErrorKind::Other`,
    ///    you can downcast this error to [`Error`], which can be one of the
    ///    following three cases:
    ///
    ///    * [`BadDataReceived`], which is unrecoverable and
    ///      indicates that the data may have been tampered with. When this
    ///      occurs, you should drop the underlying connection after a random
    ///      delay, and continue calling `read_wire` to read data from
    ///      the underlying connection before dropping the connection.
    ///
    ///      After returning `BadDataReceived`, continuing to
    ///      call `read_wire` will cause the obfuscator to attempt to read
    ///      a random number of bytes from the underlying connection and return
    ///      `Ok(0)` after reaching the EOF.
    ///
    ///      This makes it difficult for any tampering with the stream data to
    ///      deterministically change the behavior of the obfuscator's state
    ///      machine and the underlying connection, increasing the difficulty
    ///      for an attacker to reveal obfuscator through behavioral
    ///      characteristics.
    ///
    ///    * [`Retryable::KeySyncRequired`], indicating
    ///      that the peer is requesting to provide key material. In this case,
    ///      you should call [`update_key_with_notif`] to provide
    ///      the key material, and then call `read_wire` again to
    ///      resume reading.
    ///
    ///    * Any other case, indicating an unrecoverable error, usually caused
    ///      by the peer deviated from the protocol. In such cases, you should
    ///      always close the connection. Generally, users should not change
    ///      their behavior in response to such errors, and there is nothing
    ///      that can be done to improve the situation.
    ///
    /// [`reader`]: Obfuscator::reader
    /// [`update_key_with_notif`]: Obfuscator::update_key_with_notif
    /// [`BadDataReceived`]: Error::BadDataReceived
    /// [`Retryable::KeySyncRequired`]: Retryable::KeyMaterialRequired
    pub fn read_wire(&mut self, wire: &mut dyn Read) -> io::Result<usize> {
        loop {
            match self.read_state {
                ReadState::WaitInit => {
                    if self.init_state == InitState::Uninitialized {
                        self.init_receiver.init_endpoint_type(EndpointType::Server);
                        self.init_sender.init_endpoint_type(EndpointType::Server);
                        self.receiver.init_endpoint_type(EndpointType::Server);
                        self.sender.init_endpoint_type(EndpointType::Server);
                        self.init_state = InitState::Initialized;
                    }
                    self.read_state = ReadState::InitialReceive;
                }
                ReadState::InitialReceive => {
                    let read_n = self.init_receiver.read_wire(wire)?;
                    if read_n == 0 {
                        self.read_state = ReadState::Eof;
                        return Ok(0);
                    }
                    let Some(output) = self.init_receiver.take_output() else {
                        // If the output frame meta-info is None, it means entering DecoyMode.
                        // At this time we continue to read until EOF or
                        // the connection is interrupted externally.
                        return Ok(read_n);
                    };
                    self.receiver.init_session_key(output.session_key);
                    self.stream_id = output.stream_id;
                    self.read_state = ReadState::InitialPayloadReady;
                    return Ok(read_n);
                }
                ReadState::InitialPayloadReady => {
                    self.read_state = ReadState::Receive;
                }
                ReadState::Receive => {
                    let read_n = self.receiver.read_wire(wire)?;
                    if read_n == 0 {
                        self.read_state = ReadState::Eof;
                        return Ok(0);
                    }
                    self.read_state = ReadState::PayloadReady;
                    return Ok(read_n);
                }
                ReadState::PayloadReady => {
                    self.read_state = ReadState::Receive;
                }
                ReadState::Eof => {
                    return Ok(0);
                }
            }
        }
    }

    /// Write data in the internal buffer to the `writer`,
    /// returning how many bytes were written.
    ///
    /// Once successful, returns `Ok(n)` where `n > 0`, indicating that `n`
    /// bytes have been written to the `wire`. A return value of `Ok(0)`
    /// indicates that the EOF of the `wire` has been reached.
    ///
    /// Before calling this function, you should call [`writer`] to create a
    /// [`Writer`] to write data to the internal buffer. Then, call
    /// `write_wire` to send the data to the peer.
    ///
    /// If `write_wire` is called without writing any data, the obfuscator will
    /// send an empty packet. When padding is enabled, this packet will always be
    /// padded, and its length will be obfuscated. When padding is not enabled,
    /// the packet will not be padded, and its length will be fixed. In some
    /// cases, this may lead to noticeable patterns.
    ///
    /// # Errors
    ///
    /// The writing state machine never fails, so this function only returns
    /// [`io::Error`] if an I/O error occurs from the `wire`.
    ///
    /// [`writer`]: Obfuscator::writer
    pub fn write_wire(&mut self, wire: &mut dyn Write) -> io::Result<usize> {
        loop {
            match self.write_state {
                WriteState::WaitInitialData if self.init_state == InitState::Uninitialized => {
                    self.init_receiver.init_endpoint_type(EndpointType::Client);
                    self.init_sender.init_endpoint_type(EndpointType::Client);
                    self.receiver.init_endpoint_type(EndpointType::Client);
                    self.sender.init_endpoint_type(EndpointType::Client);
                    self.init_state = InitState::Initialized;
                }
                WriteState::WaitInitialData => {
                    self.init_sender.init_stream_id(self.stream_id);
                    self.init_receiver.init_stream_id(self.stream_id);
                    self.write_state = WriteState::InitialSend;
                }
                WriteState::InitialSend => {
                    let write_n = self.init_sender.write_wire(wire)?;
                    if write_n == 0 {
                        self.write_state = WriteState::Eof;
                        return Ok(0);
                    }
                    self.sender
                        .init_session_key(self.init_sender.take_session_key());
                    self.write_state = WriteState::WaitData;
                    return Ok(write_n);
                }
                WriteState::WaitData => {
                    self.write_state = WriteState::Send;
                }
                WriteState::Send => {
                    let write_n = self.sender.write_wire(wire)?;
                    if write_n == 0 {
                        self.write_state = WriteState::Eof;
                        return Ok(0);
                    }
                    self.write_state = WriteState::WaitData;
                    return Ok(write_n);
                }
                WriteState::Eof => {
                    return Ok(0);
                }
            }
        }
    }

    /// Immediately updates the session keys using the provided key material.
    ///
    /// The old key will not be involved in the update, and once updated,
    /// the old key will be cleared.
    ///
    /// This method must be called after successful read and write operations,
    /// i.e., after `read_wire()` and `write_wire()` both return non-negative values.
    /// Calling this method after successful read and write operations will
    /// immediately change the key for subsequent data I/O.
    ///
    /// The application layer protocol is responsible for ensuring that both
    /// parties call this method synchronously. If one party calls this method
    /// and the other does not, communication will be interrupted due to key mismatch.
    ///
    /// The operation flow of this function is as follows:
    /// ```text
    ///    update_key will fail     update_key          
    ///               |                    |
    ///               V                    V
    ///    +-------+-------+-------+-------+-------+-------+----
    ///    |  R/W  |  R/W  |  R/W  |  R/W  |  R/W  |  R/W  | ...
    ///    +-------+-------+-------+-------+-------+-------+----
    ///    | <- old key ->                 | <- new key -> |
    ///
    /// R/W: Represents a successful read_wire/write_wire operation
    /// ```
    ///
    /// # Errors
    ///
    /// If this method is called before successfully reading or writing data
    /// (e.g., the underlying I/O is blocking), this method will return
    /// an I/O error with `ErrorKind::WouldBlock`.
    ///
    /// If the key update process initiated by `update_key_with_notif` has not
    /// completed, this method will return an I/O error with
    /// `ErrorKind::WouldBlock`.
    pub fn update_key(&mut self, key_material: [u8; 32]) -> io::Result<()> {
        if self.receiver.is_updating_key() && self.sender.is_updating_key() {
            return Err(ErrorKind::WouldBlock.into());
        }
        let not_receving = !matches!(
            self.read_state,
            ReadState::Receive | ReadState::InitialReceive
        );
        let not_sending = !matches!(self.write_state, WriteState::Send | WriteState::InitialSend);

        if not_receving && not_sending {
            self.receiver.update_key(key_material);
            self.sender.update_key(key_material);
            Ok(())
        } else {
            Err(ErrorKind::WouldBlock.into())
        }
    }

    /// Sends a key update notification to the peer and updates the session key
    /// after sending the notification.
    ///
    /// The old key will not be involved in the update, and once updated,
    /// the old key will be cleared.
    ///
    /// This function can be called at any time. After calling this function,
    /// the key will not be immediately changed. Instead, a key change
    /// notification will be sent to the peer in the next read/write cycle, and
    /// the new key will be used in the cycle following the notification.
    ///
    /// If one party calls this method and the other does not, the party that
    /// did not call it will return [`Retryable::KeyMaterialRequired`] when
    /// calling `read_wire`, causing the read operation to be interrupted.
    /// In this case, you should call `update_key_with_notif` to provide the key m
    /// aterial and then call `read_wire` again to resume reading.
    ///
    /// The operation flow of this function is as follows:
    /// ```text
    ///     update_key_with_notif
    ///               |              
    ///               |      NOTIF           
    ///               V    |       |         
    ///    +-------+-------+-------+-------+-------+-------+----
    ///    |  R/W  |  R/W  |  R/W  |  R/W  |  R/W  |  R/W  | ...
    ///    +-------+-------+-------+-------+-------+-------+----
    ///    |     <- old key ->     |     <- new key ->     |
    ///
    /// R/W: Represents a successful read_wire/write_wire operation
    /// ```
    ///
    /// # Error
    ///
    /// If the key update process initiated by `update_key_with_notif` has not
    /// completed, this method will return an I/O error with
    /// `ErrorKind::WouldBlock`.
    pub fn update_key_with_notif(&mut self, key_material: [u8; 32]) -> io::Result<()> {
        if self.receiver.is_updating_key() && self.sender.is_updating_key() {
            return Err(ErrorKind::WouldBlock.into());
        }
        self.receiver.ready_for_update_key_notif(key_material);
        self.sender.update_key_with_notif(key_material);
        Ok(())
    }

    /// Returns a [`Reader`] that allows reading plaintext
    /// from the obfuscator's internal receive buffer.
    pub fn reader(&mut self) -> Reader<'_> {
        Reader(self)
    }

    /// Returns a [`Writer`] that allows writing plaintext
    /// to the obfuscator's internal send buffer.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer(self)
    }
}

/// A structure that implements [`Read`] and [`BufRead`] for reading plaintext data.
///
/// `Reader` points to the internal receive buffer of the [`Obfuscator`].
/// To create a `Reader`, use the [`reader`] method.
///
/// [`reader`]: Obfuscator::reader
#[derive(Debug)]
pub struct Reader<'a>(&'a mut Obfuscator);

impl Reader<'_> {
    /// Returns the number of unread bytes that can be read from the internal
    /// receive buffer.
    ///
    /// If the underlying connection is already closed or the obfuscator is
    /// currently receiving data from the wire, this function returns `0`.
    pub fn remaining(&self) -> usize {
        match self.0.read_state {
            ReadState::InitialPayloadReady => match self.0.init_receiver.state {
                InitFrameReadState::PayloadReady { payload_len, n } => payload_len - n,
                _ => 0,
            },
            ReadState::PayloadReady => match self.0.receiver.state {
                FrameReadState::PayloadReady { payload_len, n } => payload_len - n,
                _ => 0,
            },
            _ => 0,
        }
    }

    /// Returns true if there is unread data in the reader.
    ///
    /// This is equivalent to `self.remaining() != 0`.
    pub fn has_remaining(&self) -> bool {
        self.remaining() != 0
    }
}

impl Read for Reader<'_> {
    /// Reads plaintext from the internal receive buffer of the [`Obfuscator`].
    ///
    /// If this function returns `Ok(n)` where `n > 0`, it indicates that `n`
    /// bytes have been read from the internal buffer and consumed.
    ///
    /// If the underlying connection is closed, this function always
    /// returns `Ok(0)`.
    ///
    /// If the obfuscator is currently receiving data or there is no data
    /// available to read, this function returns I/O error with
    /// `ErrorKind::WouldBlock`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let buffer = self.fill_buf()?;
        let k = std::cmp::min(buf.len(), buffer.len());
        buf[..k].copy_from_slice(&buffer[..k]);
        self.consume(k);
        Ok(k)
    }
}

impl BufRead for Reader<'_> {
    /// Returns a reference to the payload in the internal receive buffer
    /// of the [`Obfuscator`].
    ///
    /// If the underlying connection is closed, this function always
    /// returns empty buffer.
    ///
    /// If the obfuscator is currently receiving data or there is no data
    /// available to read, this function returns I/O error with
    /// `ErrorKind::WouldBlock`.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self.0.read_state {
            ReadState::InitialPayloadReady => match self.0.init_receiver.state {
                InitFrameReadState::PayloadReady { payload_len, .. } => {
                    Ok(&self.0.init_receiver.buf[..payload_len])
                }
                _ => Err(ErrorKind::WouldBlock.into()),
            },
            ReadState::PayloadReady => match self.0.receiver.state {
                FrameReadState::PayloadReady { payload_len, .. } => {
                    Ok(&self.0.receiver.buf[..payload_len])
                }
                _ => Err(ErrorKind::WouldBlock.into()),
            },
            ReadState::Eof => Ok(&[]),
            _ => Err(ErrorKind::WouldBlock.into()),
        }
    }

    /// Consumes `amt` bytes from the buffer, indicating that these bytes
    /// should no longer be returned in subsequent calls to `fill_buf`. This
    /// function can be called to consume `amt` bytes regardless of whether
    /// `fill_buf` has been called or not.
    ///
    /// `Amt` should be less than or equal to the number of bytes in the buffer.
    /// If `amt` is greater than the number of bytes in the buffer,
    /// all bytes will be consumed.
    ///
    /// If the obfuscator is currently reading data or underlying connection
    /// has closed, `amt` will be ignored.
    fn consume(&mut self, amt: usize) {
        match self.0.read_state {
            ReadState::InitialPayloadReady => {
                if let InitFrameReadState::PayloadReady {
                    ref mut n,
                    payload_len,
                } = self.0.init_receiver.state
                {
                    if *n + amt >= payload_len {
                        *n = payload_len;
                    } else {
                        *n += amt;
                    }
                }
            }
            ReadState::PayloadReady => {
                if let FrameReadState::PayloadReady {
                    ref mut n,
                    payload_len,
                } = self.0.receiver.state
                {
                    if *n + amt >= payload_len {
                        *n = payload_len;
                    } else {
                        *n += amt;
                    }
                }
            }
            _ => {}
        }
    }
}

/// A structure that implements [`Write`] for writing plaintext data.
///
/// `Writer` points to the internal send buffer of the [`Obfuscator`].
/// To create a `Writer`, use the [`writer`] method.
///
/// [`writer`]: Obfuscator::writer
#[derive(Debug)]
pub struct Writer<'a>(&'a mut Obfuscator);

impl Writer<'_> {
    /// Returns the number of bytes that can be written to the internal send buffer.
    ///
    /// If the underlying connection is already closed or the obfuscator is
    /// currently sending data to the wire, this function returns `0`
    pub fn remaining_mut(&self) -> usize {
        match self.0.write_state {
            WriteState::InitialSend => match self.0.init_sender.state {
                InitFrameWriteState::Wait { .. } => self.0.init_sender.buf.remaining(),
                _ => 0,
            },
            WriteState::Send => self.0.sender.buf.remaining(),
            _ => 0,
        }
    }

    /// Returns true if there is space in writer for more bytes.
    ///
    /// This is equivalent to `self.remaining_mut() != 0`.
    pub fn has_remaining_mut(&self) -> bool {
        self.remaining_mut() != 0
    }
}

impl Write for Writer<'_> {
    /// Writes plaintext to the internal send buffer of the [`Obfuscator`].
    ///
    /// If the underlying connection is already closed or the provided buffer
    /// is empty, this function always returns `Ok(0)`.
    ///
    /// If the internal buffer is full or the obfuscator is currently sending data
    /// to the wire and cannot respond to the writing request, this function
    /// returns I/O error with `ErrorKind::WouldBlock`.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.write_state {
            WriteState::WaitInitialData => match self.0.init_sender.state {
                InitFrameWriteState::Wait { .. } => {
                    let remaining = self.0.init_sender.buf.remaining();
                    if remaining == 0 {
                        return Err(ErrorKind::WouldBlock.into());
                    }
                    let k = std::cmp::min(buf.len(), remaining);
                    self.0.init_sender.buf.push_payload(&buf[..k]);
                    Ok(k)
                }
                _ => Err(ErrorKind::WouldBlock.into()),
            },
            WriteState::WaitData => {
                let remaining = self.0.sender.buf.remaining();
                if remaining == 0 {
                    return Err(ErrorKind::WouldBlock.into());
                }
                let k = std::cmp::min(buf.len(), remaining);
                self.0.sender.buf.push_payload(&buf[..k]);
                Ok(k)
            }
            WriteState::Eof => Ok(0),
            _ => Err(ErrorKind::WouldBlock.into()),
        }
    }

    /// This function does not perform any actual operation
    /// and always returns `Ok(())`. You need to call [`write_wire`] to
    /// send the data to the peer.
    ///
    /// [`write_wire`]: Obfuscator::write_wire
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ReadState {
    WaitInit,
    InitialReceive,
    InitialPayloadReady,
    Receive,
    PayloadReady,
    Eof,
}

#[derive(Debug, Eq, PartialEq)]
enum WriteState {
    WaitInitialData,
    InitialSend,
    WaitData,
    Send,
    Eof,
}

#[derive(Debug, Eq, PartialEq)]
enum InitState {
    Uninitialized,
    Initialized,
}

/// Decompose `io::Result<usize>`.
///
/// Keep the number of non-negative bytes successfully read or write,
/// return error and EOF (i.e. Ok(0)).
macro_rules! handle_io_result {
    ($io_result:expr) => {
        match $io_result {
            Ok(n) if n > 0 => n,
            Ok(_) => return Ok(0),
            Err(e) => return Err(e),
        }
    };
}

/// State Transition Diagram:
///
/// ```text
///
///           |
///           V
///       ReadHeader -->----+
///           |             |
///           V             |
///        ReadBody --->----+
///                         |
///                         |
///       DecoyMode <-------+
///
/// ```
#[derive(Debug)]
struct InitReceiver {
    state: InitFrameReadState,
    buf: Vec<u8>,
    decoder: InitFrameDecoder,
    output: Option<InitReceiverOutput>,
    rng: StdRng,
}

impl InitReceiver {
    fn with_config_and_rng(config: &Config, rng: StdRng) -> Self {
        Self {
            state: InitFrameReadState::ReadHeader {
                n: 0,
                total: INIT_HDR_LEN,
            },
            buf: vec![0x00; INIT_FRAME_MAX_LEN],
            decoder: InitFrameDecoder::with_config(config),
            output: None,
            rng,
        }
    }

    /// Set a new stream ID.
    ///
    /// This function must be called before starting to receive initial frame
    /// (i.e. before calling `read_wire()`).
    fn init_stream_id(&mut self, stream_id: u64) {
        self.decoder.init_stream_id(stream_id);
    }

    fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.decoder.init_endpoint_type(endpoint_type);
    }

    /// Get the metadata read from the frame.
    fn take_output(&mut self) -> Option<InitReceiverOutput> {
        self.output.take()
    }

    fn read_wire(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        loop {
            match self.state {
                InitFrameReadState::ReadHeader { n, total } if n < total => {
                    self.state = InitFrameReadState::ReadHeader {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                    };
                }
                InitFrameReadState::ReadHeader { total, .. } => {
                    match self.decoder.open_header(&mut self.buf[..total]) {
                        Ok(header) => {
                            self.output = Some(InitReceiverOutput {
                                stream_id: header.stream_id,
                                session_key: header.session_key,
                            });
                            self.state = InitFrameReadState::ReadBody {
                                n: 0,
                                total: header.body_len,
                                payload_len: header.payload_len,
                            };
                        }
                        Err(Error::BadDataReceived(e)) => {
                            self.state = InitFrameReadState::DecoyMode {
                                n: 0,
                                total: self.rng.random_range(INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN),
                            };
                            return Err(Error::BadDataReceived(e).into());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                InitFrameReadState::ReadBody {
                    n,
                    total,
                    payload_len,
                } if n < total => {
                    self.state = InitFrameReadState::ReadBody {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                        payload_len,
                    }
                }
                InitFrameReadState::ReadBody {
                    total, payload_len, ..
                } => {
                    return match self.decoder.open_body(&mut self.buf[..total]) {
                        Ok(()) => {
                            self.state = InitFrameReadState::PayloadReady { n: 0, payload_len };
                            Ok(INIT_HDR_LEN + total)
                        }
                        Err(Error::BadDataReceived(e)) => {
                            self.state = InitFrameReadState::DecoyMode {
                                n: 0,
                                total: self
                                    .rng
                                    .random_range(INIT_FRAME_MIN_LEN..=INIT_FRAME_MAX_LEN),
                            };
                            Err(Error::BadDataReceived(e).into())
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                InitFrameReadState::PayloadReady { .. } => {
                    unreachable!("programming error: PayloadReady state should not be reached")
                }
                InitFrameReadState::DecoyMode { n, total } if n < total => {
                    self.state = InitFrameReadState::DecoyMode {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                    }
                }
                InitFrameReadState::DecoyMode { total, .. } => {
                    // Return the number of bytes read in DecoyMode to encourage
                    // normal connection closure
                    return Ok(total);
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum InitFrameReadState {
    ReadHeader {
        n: usize,
        total: usize,
    },
    ReadBody {
        n: usize,
        total: usize,
        payload_len: usize,
    },
    PayloadReady {
        n: usize,
        payload_len: usize,
    },
    DecoyMode {
        n: usize,
        total: usize,
    },
}

#[derive(Debug)]
struct InitReceiverOutput {
    stream_id: u64,
    session_key: SessionKey,
}

/// State Transition Diagram
/// ```text
///
///             |
///             V
///  +----> ReadHeader -->----+
///  |          |             |
///  |          V             |
///  +---<-- ReadBody --->----+
///                           |
///                           |
///          DecoyMode <------+
///
/// ```
#[derive(Debug)]
struct Receiver {
    state: FrameReadState,
    key_state: ReceiverKeyState,
    buf: Vec<u8>,
    decoder: FrameDecoder,
    key_material: Option<[u8; 32]>,
    rng: StdRng,
}

impl Receiver {
    fn with_config_and_rng(config: &Config, rng: StdRng) -> Self {
        Self {
            state: FrameReadState::ReadHeader {
                n: 0,
                total: HDR_LEN,
            },
            key_state: ReceiverKeyState::None,
            buf: vec![0u8; FRAME_MAX_LEN],
            decoder: FrameDecoder::with_config(config),
            key_material: None,
            rng,
        }
    }

    fn init_session_key(&mut self, session_key: SessionKey) {
        self.decoder.init_session_key(session_key);
    }

    fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.decoder.init_endpoint_type(endpoint_type);
    }

    fn ready_for_update_key_notif(&mut self, key_material: [u8; 32]) {
        self.key_material = Some(key_material);
    }

    fn update_key(&mut self, key_material: [u8; 32]) {
        self.decoder.update_key_by_material(key_material);
    }

    fn is_updating_key(&self) -> bool {
        !matches!(self.key_state, ReceiverKeyState::None) || self.key_material.is_some()
    }

    fn read_wire(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        loop {
            match self.state {
                FrameReadState::ReadHeader { n, total } if n < total => {
                    self.state = FrameReadState::ReadHeader {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                    }
                }
                FrameReadState::ReadHeader { total, .. } => {
                    match self.decoder.open_header(&mut self.buf[..total]) {
                        Ok(header) => {
                            if header.command == Command::PeerTxKeyWillChange {
                                self.key_state = ReceiverKeyState::WaitChangeKey;
                            }
                            self.state = FrameReadState::ReadBody {
                                n: 0,
                                total: header.body_len,
                                payload_len: header.payload_len,
                            };
                        }
                        Err(Error::BadDataReceived(e)) => {
                            self.state = FrameReadState::DecoyMode {
                                n: 0,
                                total: self.rng.random_range(BODY_MIN_LEN..=BODY_MAX_LEN),
                            };
                            return Err(Error::BadDataReceived(e).into());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                FrameReadState::ReadBody {
                    n,
                    total,
                    payload_len,
                } if n < total => {
                    self.state = FrameReadState::ReadBody {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                        payload_len,
                    }
                }
                FrameReadState::ReadBody {
                    total, payload_len, ..
                } => {
                    return match self.decoder.open_body(&mut self.buf[..total]) {
                        Ok(()) => {
                            self.state = FrameReadState::PayloadReady { n: 0, payload_len };
                            Ok(HDR_LEN + total)
                        }
                        Err(Error::BadDataReceived(e)) => {
                            self.state = FrameReadState::DecoyMode {
                                n: 0,
                                total: self
                                    .rng
                                    .random_range(INIT_FRAME_MIN_LEN..=INIT_FRAME_MAX_LEN),
                            };
                            Err(Error::BadDataReceived(e).into())
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                FrameReadState::PayloadReady { .. } => match self.key_state {
                    ReceiverKeyState::None => {
                        self.state = FrameReadState::ReadHeader {
                            n: 0,
                            total: HDR_LEN,
                        };
                    }
                    ReceiverKeyState::WaitChangeKey => match self.key_material.take() {
                        Some(key_material) => {
                            self.decoder.update_key_by_material(key_material);
                            self.key_state = ReceiverKeyState::None;
                            self.state = FrameReadState::ReadHeader {
                                n: 0,
                                total: HDR_LEN,
                            };
                        }
                        None => {
                            return Err(Retryable::KeyMaterialRequired.into());
                        }
                    },
                },
                FrameReadState::DecoyMode { n, total } if n < total => {
                    self.state = FrameReadState::DecoyMode {
                        n: n + handle_io_result!(reader.read(&mut self.buf[n..total])),
                        total,
                    }
                }
                FrameReadState::DecoyMode { total, .. } => {
                    return Ok(total);
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum FrameReadState {
    ReadHeader {
        n: usize,
        total: usize,
    },
    ReadBody {
        n: usize,
        total: usize,
        payload_len: usize,
    },
    PayloadReady {
        n: usize,
        payload_len: usize,
    },
    DecoyMode {
        n: usize,
        total: usize,
    },
}

#[derive(Debug, Eq, PartialEq)]
enum ReceiverKeyState {
    None,
    WaitChangeKey,
}

/// State Transition Diagram
/// ```text
///
///        |
///        V
///       Seal
///        |
///        V
///      Write
///
/// ```
#[derive(Debug)]
struct InitSender {
    state: InitFrameWriteState,
    buf: InitFrameBufMut,
    encoder: InitFrameEncoder,
    session_key: Option<SessionKey>,
}

impl InitSender {
    fn with_config_and_rng(config: &Config, mut rng: StdRng) -> Self {
        Self {
            state: InitFrameWriteState::Wait { stream_id: 0 },
            buf: InitFrameBufMut::with_random(rng.random()),
            encoder: InitFrameEncoder::with_config_and_rng(config, rng),
            session_key: None,
        }
    }

    fn init_stream_id(&mut self, stream_id: u64) {
        if let InitFrameWriteState::Wait { .. } = self.state {
            self.state = InitFrameWriteState::Wait { stream_id };
        }
    }

    fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.encoder.init_endpoint_type(endpoint_type);
    }

    fn take_session_key(&mut self) -> SessionKey {
        self.session_key
            .take()
            .expect("Programming Error: Session key is None")
    }

    fn write_wire(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        loop {
            match self.state {
                InitFrameWriteState::Wait { stream_id } => {
                    self.encoder.init_stream_id(stream_id);
                    self.session_key = Some(self.encoder.seal(&mut self.buf));
                    self.state = InitFrameWriteState::Write {
                        n: 0,
                        total: self.buf.inner().len(),
                    };
                }
                InitFrameWriteState::Write { n, total } if n < total => {
                    self.state = InitFrameWriteState::Write {
                        n: n + handle_io_result!(writer.write(&self.buf.inner()[n..total])),
                        total,
                    }
                }
                InitFrameWriteState::Write { total, .. } => {
                    self.buf.release_memory();
                    return Ok(total);
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum InitFrameWriteState {
    Wait { stream_id: u64 },
    Write { n: usize, total: usize },
}

/// State Transition Diagram
/// ```text
///
///          |
///          V
///   +---> Seal
///   |      |
///   |      V
///   +--- Write
///
/// ```
#[derive(Debug)]
struct Sender {
    state: FrameWriteState,
    key_state: SenderKeyState,
    buf: FrameBufMut,
    encoder: FrameEncoder,
}

impl Sender {
    fn with_config_and_rng(config: &Config, rng: StdRng) -> Self {
        Self {
            state: FrameWriteState::Wait,
            key_state: SenderKeyState::None,
            buf: FrameBufMut::with_pad_option_and_rng(config.pad_option.clone(), rng),
            encoder: FrameEncoder::with_config(config),
        }
    }

    fn init_session_key(&mut self, session_key: SessionKey) {
        self.encoder.init_session_key(session_key);
    }

    fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.encoder.init_endpoint_type(endpoint_type);
    }

    fn update_key_with_notif(&mut self, key_material: [u8; 32]) {
        if self.key_state == SenderKeyState::None {
            self.key_state = SenderKeyState::WaitChangeKey(key_material);
        }
    }

    fn update_key(&mut self, key_material: [u8; 32]) {
        self.encoder.update_key_by_material(key_material);
    }

    fn is_updating_key(&self) -> bool {
        !matches!(self.key_state, SenderKeyState::None)
    }

    fn write_wire(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        loop {
            match self.state {
                FrameWriteState::Wait => {
                    let command = match self.key_state {
                        SenderKeyState::WaitChangeKey(key_material) => {
                            self.key_state = SenderKeyState::KeyWillChange(key_material);
                            Command::PeerTxKeyWillChange
                        }
                        _ => Command::Payload,
                    };
                    self.encoder.seal(command, &mut self.buf);
                    self.state = FrameWriteState::Write {
                        n: 0,
                        total: self.buf.inner().len(),
                    }
                }
                FrameWriteState::Write { n, total } if n < total => {
                    self.state = FrameWriteState::Write {
                        n: n + handle_io_result!(writer.write(&self.buf.inner()[n..total])),
                        total,
                    }
                }
                FrameWriteState::Write { total, .. } => {
                    self.buf.reset();
                    if let SenderKeyState::KeyWillChange(key_material) = self.key_state {
                        self.encoder.update_key_by_material(key_material);
                        self.key_state = SenderKeyState::None;
                    }
                    self.state = FrameWriteState::Wait;
                    return Ok(total);
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum FrameWriteState {
    Wait,
    Write { n: usize, total: usize },
}

#[derive(Debug, Eq, PartialEq)]
enum SenderKeyState {
    None,
    WaitChangeKey([u8; 32]),
    KeyWillChange([u8; 32]),
}

#[cfg(test)]
mod test {
    use std::collections::VecDeque;

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::{
        config::{Config, PadOption},
        crypto::SharedKey,
        error::BadDataReceived,
        specification::{INIT_SALT_LEN, PAYLOAD_MIN_LEN},
        test::MockStream,
    };

    fn cfg_no_pad() -> Config {
        Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::None,
        }
    }

    fn cfg_with_mpu(link_mpu: u16) -> Config {
        Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::UniformTail { link_mpu },
        }
    }

    fn cfg_tcp_pad() -> Config {
        Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::default_tcp_padding(),
        }
    }

    #[test]
    fn test_echo_no_padding() {
        let mut mock_stream = MockStream::default();
        let mut rng = StdRng::from_seed([0u8; 32]);
        let dummy_data = vec![0xaau8; 70000];

        let mut client = Obfuscator::with_config_and_random(cfg_no_pad(), [1; 136]);
        let mut server = Obfuscator::with_config_and_random(cfg_no_pad(), [2; 136]);

        const N_TESTS: usize = 1000;
        const MAX_SEND_N_TIMES: usize = 10;
        let mut remember_written_how_many_bytes = VecDeque::with_capacity(MAX_SEND_N_TIMES);

        for _ in 0..N_TESTS {
            let client_send_n_frame = rng.random_range(1..=MAX_SEND_N_TIMES);
            // Client random send n frame;
            for _ in 0..client_send_n_frame {
                let payload_len = rng.random_range(PAYLOAD_MIN_LEN..=70000);
                let n = client.writer().write(&dummy_data[..payload_len]).unwrap();
                client.write_wire(&mut mock_stream).unwrap();

                remember_written_how_many_bytes.push_back(n);
            }
            // Server receive n frame
            for _ in 0..client_send_n_frame {
                let n = remember_written_how_many_bytes.pop_front().unwrap();
                server.read_wire(&mut mock_stream).unwrap();
                let received_data = server.reader().fill_buf().unwrap().to_vec();

                assert_eq!(dummy_data[..n], received_data);
            }

            let server_send_n_frame = rng.random_range(1..=MAX_SEND_N_TIMES);
            // Server random send n frame
            for _ in 0..server_send_n_frame {
                let payload_len = rng.random_range(PAYLOAD_MIN_LEN..=70000);
                let n = server.writer().write(&dummy_data[..payload_len]).unwrap();
                server.write_wire(&mut mock_stream).unwrap();

                remember_written_how_many_bytes.push_back(n);
            }
            // Client receive n frame
            for _ in 0..server_send_n_frame {
                let n = remember_written_how_many_bytes.pop_front().unwrap();
                client.read_wire(&mut mock_stream).unwrap();
                let received_data = client.reader().fill_buf().unwrap().to_vec();

                assert_eq!(dummy_data[..n], received_data);
            }
        }
    }

    #[test]
    fn test_echo_with_padding() {
        let mut mock_stream = MockStream::default();
        let mut rng = StdRng::from_seed([0u8; 32]);
        let dummy_data = vec![0xaau8; 70000];

        for link_mpu in [128u16, 1448, 16384] {
            let random = {
                let mut r = [3u8; 136];
                r[..2].copy_from_slice(&link_mpu.to_le_bytes());
                r
            };
            let mut client = Obfuscator::with_config_and_random(cfg_with_mpu(link_mpu), random);
            let mut server = Obfuscator::with_config_and_random(cfg_with_mpu(link_mpu), random);

            const N_TESTS: usize = 1000;
            const MAX_SEND_N_TIMES: usize = 10;
            let mut remember_written_how_many_bytes = VecDeque::with_capacity(MAX_SEND_N_TIMES);

            for _ in 0..N_TESTS {
                let client_send_n_frame = rng.random_range(1..=MAX_SEND_N_TIMES);
                // Client random send n frame;
                for _ in 0..client_send_n_frame {
                    let payload_len = rng.random_range(PAYLOAD_MIN_LEN..=70000);
                    let n = client.writer().write(&dummy_data[..payload_len]).unwrap();
                    client.write_wire(&mut mock_stream).unwrap();

                    remember_written_how_many_bytes.push_back(n);
                }
                // Server receive n frame
                for _ in 0..client_send_n_frame {
                    let n = remember_written_how_many_bytes.pop_front().unwrap();
                    server.read_wire(&mut mock_stream).unwrap();
                    let received_data = server.reader().fill_buf().unwrap().to_vec();

                    assert_eq!(dummy_data[..n], received_data);
                }

                let server_send_n_frame = rng.random_range(1..=MAX_SEND_N_TIMES);
                // Server random send n frame
                for _ in 0..server_send_n_frame {
                    let payload_len = rng.random_range(PAYLOAD_MIN_LEN..=70000);
                    let n = server.writer().write(&dummy_data[..payload_len]).unwrap();
                    server.write_wire(&mut mock_stream).unwrap();

                    remember_written_how_many_bytes.push_back(n);
                }
                // Client receive n frame
                for _ in 0..server_send_n_frame {
                    let n = remember_written_how_many_bytes.pop_front().unwrap();
                    client.read_wire(&mut mock_stream).unwrap();
                    let received_data = client.reader().fill_buf().unwrap().to_vec();

                    assert_eq!(dummy_data[..n], received_data);
                }
            }
        }
    }

    #[test]
    fn test_reader() {
        let mut mock_stream = MockStream::default();
        let mut client = Obfuscator::with_config_and_random(cfg_no_pad(), [4; 136]);
        let mut server = Obfuscator::with_config_and_random(cfg_no_pad(), [5; 136]);

        let w1 = client.writer().write(&[0xaau8; 100]).unwrap();
        client.write_wire(&mut mock_stream).unwrap();
        let w2 = client.writer().write(&[0xaau8; 100]).unwrap();
        client.write_wire(&mut mock_stream).unwrap();

        server.read_wire(&mut mock_stream).unwrap();
        let mut reader = server.reader();
        let mut buf = vec![0u8; 200];
        let r1 = reader.read(&mut buf).unwrap();
        assert_eq!(w1, r1);
        assert!(!reader.has_remaining());

        server.read_wire(&mut mock_stream).unwrap();
        let mut reader = server.reader();
        let r2 = reader.fill_buf().unwrap().len();
        assert_eq!(w2, r2);
        reader.consume(r2);
        assert!(!reader.has_remaining());
        reader.consume(65536); // no effect.

        mock_stream.set_eof();
        assert_eq!(server.read_wire(&mut mock_stream).unwrap(), 0);
        let mut reader = server.reader();
        assert_eq!(reader.fill_buf().unwrap(), &[]);
    }

    #[test]
    fn test_writer() {
        let dummy_data = vec![0u8; 70000];
        let mut mock_stream = MockStream::default();
        let mut client = Obfuscator::with_config_and_random(cfg_no_pad(), [6; 136]);
        let mut server = Obfuscator::with_config_and_random(cfg_no_pad(), [7; 136]);

        let w1 = {
            let mut writer = client.writer();
            writer.write(&[0xaau8; 100]).unwrap()
        };
        client.write_wire(&mut mock_stream).unwrap();
        let w2 = {
            let mut writer = client.writer();
            let n = writer.write(&dummy_data).unwrap();
            assert!(matches!(
                writer.write(&dummy_data), 
                Err(e) if e.kind() == ErrorKind::WouldBlock));
            n
        };
        client.write_wire(&mut mock_stream).unwrap();

        server.read_wire(&mut mock_stream).unwrap();
        let r1 = server.reader().fill_buf().unwrap().len();
        assert_eq!(w1, r1);

        server.read_wire(&mut mock_stream).unwrap();
        let r2 = server.reader().fill_buf().unwrap().len();
        assert_eq!(w2, r2);

        mock_stream.set_eof();
        assert_eq!(server.write_wire(&mut mock_stream).unwrap(), 0);
        assert_eq!(server.writer().write(b"cannot send").unwrap(), 0);
    }

    #[test]
    fn test_update_key() {
        let mut mock_stream = MockStream::default();
        let mut client = Obfuscator::with_config_and_random(cfg_no_pad(), [8; 136]);
        let mut server = Obfuscator::with_config_and_random(cfg_no_pad(), [9; 136]);

        client.write_wire(&mut mock_stream).unwrap();
        server.read_wire(&mut mock_stream).unwrap();
        server.update_key([1u8; 32]).unwrap();
        client.update_key([1u8; 32]).unwrap();

        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        server.update_key([2u8; 32]).unwrap();
        client.update_key([2u8; 32]).unwrap();

        server.write_wire(&mut mock_stream).unwrap();
        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        server.update_key([3u8; 32]).unwrap();
        client.update_key([3u8; 32]).unwrap();

        server.write_wire(&mut mock_stream).unwrap();
        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
    }

    #[test]
    fn test_update_key_with_notif() {
        let mut mock_stream = MockStream::default();
        let mut client = Obfuscator::with_config_and_random(cfg_no_pad(), [10; 136]);
        let mut server = Obfuscator::with_config_and_random(cfg_no_pad(), [10; 136]);

        client.write_wire(&mut mock_stream).unwrap();
        server.read_wire(&mut mock_stream).unwrap();

        assert!(server.update_key_with_notif([1u8; 32]).is_ok());
        assert!(client.update_key_with_notif([1u8; 32]).is_ok());

        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();

        assert!(server.update_key_with_notif([2u8; 32]).is_err());
        assert!(client.update_key_with_notif([2u8; 32]).is_err());

        server.write_wire(&mut mock_stream).unwrap();
        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();

        assert!(server.update_key_with_notif([3u8; 32]).is_ok());
        assert!(client.update_key_with_notif([3u8; 32]).is_ok());

        server.write_wire(&mut mock_stream).unwrap();
        server.write_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
        client.read_wire(&mut mock_stream).unwrap();
    }

    #[test]
    fn test_pipe_tempered_init_header() {
        let dummy_data = vec![0xaau8; 80000];
        let mut mock_stream = MockStream::default();

        const N_TESTS: u64 = 1024;
        for i in 0..N_TESTS {
            let random = {
                let mut r = [21u8; 136];
                r[..8].copy_from_slice(&i.to_le_bytes());
                r
            };
            let mut client = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);
            let mut server = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);

            client.write_wire(&mut mock_stream).unwrap();

            // Tempering the initial frame header
            mock_stream.buf[INIT_SALT_LEN + 1] = mock_stream.buf[INIT_SALT_LEN + 1].wrapping_add(1);

            let err = server.read_wire(&mut mock_stream).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Other);
            let err = err.downcast::<Error>().unwrap();
            assert!(matches!(
                err,
                Error::BadDataReceived(BadDataReceived::InitFrameHeaderFailed)
            ));

            // Assert the server pipe into decoy mode.
            assert_eq!(server.read_state, ReadState::InitialReceive);
            assert!(matches!(
                server.init_receiver.state,
                InitFrameReadState::DecoyMode { .. }
            ));

            // Inject enough data into mock stream.
            // If the data is insufficient, it will cause read_wire
            // to return WouldBlock error (raised by MockStream).
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // decoy mode read.
            let decoy_read_n = server.read_wire(&mut mock_stream).unwrap();
            assert!((INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN).contains(&decoy_read_n));
            mock_stream.clear();
        }
    }

    #[test]
    fn test_pipe_tempered_init_body() {
        let dummy_data = vec![0xaau8; 80000];
        let mut mock_stream = MockStream::default();

        const N_TESTS: u64 = 1024;
        for i in 0..N_TESTS {
            let random = {
                let mut r = [22u8; 136];
                r[..8].copy_from_slice(&i.to_le_bytes());
                r
            };
            let mut client = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);
            let mut server = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);

            client.write_wire(&mut mock_stream).unwrap();

            // Tempering the initial frame body
            mock_stream.buf[INIT_HDR_LEN + 1] = mock_stream.buf[INIT_HDR_LEN + 1].wrapping_add(1);

            let err = server.read_wire(&mut mock_stream).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Other);
            let err = err.downcast::<Error>().unwrap();
            assert!(
                matches!(
                    err,
                    Error::BadDataReceived(BadDataReceived::InitFrameBodyFailed)
                ),
                "{}",
                err
            );

            // Assert the server pipe into decoy mode.
            assert_eq!(server.read_state, ReadState::InitialReceive);
            assert!(matches!(
                server.init_receiver.state,
                InitFrameReadState::DecoyMode { .. }
            ));

            // Inject enough data into mock stream.
            // If the data is insufficient, it will cause read_wire
            // to return WouldBlock error (raised by MockStream).
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // decoy mode read.
            let decoy_read_n = server.read_wire(&mut mock_stream).unwrap();
            assert!((INIT_FRAME_MIN_LEN..=INIT_FRAME_MAX_LEN).contains(&decoy_read_n));
            mock_stream.clear();
        }
    }

    #[test]
    fn test_pipe_tempered_header() {
        let mut mock_stream = MockStream::default();
        let dummy_data = vec![0xaau8; 80000];

        const N_TESTS: u64 = 1024;
        for i in 0..N_TESTS {
            let random = {
                let mut r = [23u8; 136];
                r[..8].copy_from_slice(&i.to_le_bytes());
                r
            };
            let mut client = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);
            let mut server = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);

            // transmit init frame.
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = server.read_wire(&mut mock_stream).unwrap();

            // send normal frame
            let _ = client.writer().write(&dummy_data).unwrap();
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // Tempering the normal frame header
            mock_stream.buf[0] = mock_stream.buf[0].wrapping_add(1);

            // Read tempered data
            let err = server.read_wire(&mut mock_stream).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Other);
            let err = err.downcast::<Error>().unwrap();
            assert!(matches!(
                err,
                Error::BadDataReceived(BadDataReceived::FrameHeaderFailed)
            ));

            // Assert the server pipe into decoy mode.
            assert_eq!(server.read_state, ReadState::Receive);
            assert!(matches!(
                server.receiver.state,
                FrameReadState::DecoyMode { .. }
            ));

            // Inject enough data into mock stream.
            // If the data is insufficient, it will cause read_wire
            // to return WouldBlock error (raised by MockStream).
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // Read in decoy mode.
            let decoy_read_n = server.read_wire(&mut mock_stream).unwrap();
            assert!((BODY_MIN_LEN..=BODY_MAX_LEN).contains(&decoy_read_n));
            mock_stream.clear();
        }
    }

    #[test]
    fn test_pipe_tempered_body() {
        let mut mock_stream = MockStream::default();
        let dummy_data = vec![0xaau8; 80000];

        const N_TESTS: u64 = 1024;
        for i in 0..N_TESTS {
            let random = {
                let mut r = [24u8; 136];
                r[..8].copy_from_slice(&i.to_le_bytes());
                r
            };
            let mut client = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);
            let mut server = Obfuscator::with_config_and_random(cfg_tcp_pad(), random);

            // transmit init frame.
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = server.read_wire(&mut mock_stream).unwrap();

            // send normal frame
            let _ = client.writer().write(&dummy_data).unwrap();
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // Tempering the normal frame body
            mock_stream.buf[HDR_LEN + 1] = mock_stream.buf[HDR_LEN + 1].wrapping_add(1);

            // Read tempered data
            let err = server.read_wire(&mut mock_stream).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Other);
            let err = err.downcast::<Error>().unwrap();
            assert!(matches!(
                err,
                Error::BadDataReceived(BadDataReceived::FrameBodyFailed)
            ));

            // Assert the server pipe into decoy mode.
            assert_eq!(server.read_state, ReadState::Receive);
            assert!(matches!(
                server.receiver.state,
                FrameReadState::DecoyMode { .. }
            ));

            // Inject enough data into mock stream.
            // If the data is insufficient, it will cause read_wire
            // to return WouldBlock error (raised by MockStream).
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();
            let _ = client.writer().write(&dummy_data);
            let _ = client.write_wire(&mut mock_stream).unwrap();

            // Read in decoy mode.
            let decoy_read_n = server.read_wire(&mut mock_stream).unwrap();
            assert!((INIT_FRAME_MIN_LEN..=INIT_FRAME_MAX_LEN).contains(&decoy_read_n));
            mock_stream.clear();
        }
    }

    #[test]
    fn test_client_self_replay() {
        let mut mock_stream = MockStream::default();
        let mut client = Obfuscator::with_config(cfg_tcp_pad());

        client.write_wire(&mut mock_stream).unwrap();

        // Replay on self.
        let err = client.read_wire(&mut mock_stream).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.downcast::<Error>().unwrap();
        assert!(matches!(
            err,
            Error::BadDataReceived(BadDataReceived::UnmatchedDirection)
        ));
    }

    #[test]
    fn test_client_each_other_replay() {
        let mut mock_stream1 = MockStream::default();
        let mut client1 = Obfuscator::with_config(cfg_tcp_pad());

        let mut mock_stream2 = MockStream::default();
        let mut client2 = Obfuscator::with_config(cfg_tcp_pad());

        client1.write_wire(&mut mock_stream1).unwrap();
        client2.write_wire(&mut mock_stream2).unwrap();

        // Replay on self.
        let err = client1.read_wire(&mut mock_stream2).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.downcast::<Error>().unwrap();
        assert!(matches!(
            err,
            Error::BadDataReceived(BadDataReceived::UnmatchedDirection)
        ));
    }

    #[test]
    fn test_client_replay_to_server() {
        let mut mock_stream1 = MockStream::default();
        let mut client = Obfuscator::with_config(cfg_tcp_pad());

        let mut server1 = Obfuscator::with_config(cfg_tcp_pad());
        let mut server2 = Obfuscator::with_config(cfg_tcp_pad());

        client.write_wire(&mut mock_stream1).unwrap();

        // Copy client request.
        let mut mock_stream2 = mock_stream1.clone();

        // Ok
        server1.read_wire(&mut mock_stream1).unwrap();

        // Server 2 detected replay,
        // because server 2 shares the same replay cache with server 1.
        let err = server2.read_wire(&mut mock_stream2).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.downcast::<Error>().unwrap();
        dbg!(&err);
        assert!(matches!(
            err,
            Error::BadDataReceived(BadDataReceived::ReusedSalt)
        ));
    }

    #[test]
    fn test_server_replay_to_server() {
        let mut mock_stream1 = MockStream::default();
        let mut client = Obfuscator::with_config(cfg_tcp_pad());
        let mut server1 = Obfuscator::with_config(cfg_tcp_pad());
        let mut server2 = Obfuscator::with_config(cfg_tcp_pad());

        client.write_wire(&mut mock_stream1).unwrap();
        server1.read_wire(&mut mock_stream1).unwrap();
        server1.write_wire(&mut mock_stream1).unwrap();
        let err = server2.read_wire(&mut mock_stream1).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.downcast::<Error>().unwrap();
        dbg!(&err);
        assert!(matches!(
            err,
            Error::BadDataReceived(BadDataReceived::UnmatchedDirection)
        ));
    }

    #[test]
    fn test_client_cross_replay_to_client() {
        let mut mock_stream1 = MockStream::default();
        let mut mock_stream2 = MockStream::default();
        let mut client1 = Obfuscator::with_config(cfg_tcp_pad());
        let mut client2 = Obfuscator::with_config(cfg_tcp_pad());
        let mut server1 = Obfuscator::with_config(cfg_tcp_pad());
        let mut server2 = Obfuscator::with_config(cfg_tcp_pad());

        client1.write_wire(&mut mock_stream1).unwrap();
        server1.read_wire(&mut mock_stream1).unwrap();
        server1.write_wire(&mut mock_stream1).unwrap();

        client2.write_wire(&mut mock_stream2).unwrap();
        server2.read_wire(&mut mock_stream2).unwrap();
        server2.write_wire(&mut mock_stream2).unwrap();

        // Cross replay
        let err = client1.read_wire(&mut mock_stream2).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let err = err.downcast::<Error>().unwrap();
        dbg!(&err);
        assert!(matches!(
            err,
            Error::BadDataReceived(BadDataReceived::UnmatchedClientStreamId { .. })
        ));
    }
}
