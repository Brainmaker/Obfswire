use rand::{
    Rng, SeedableRng,
    rngs::StdRng,
};
use crate::{
    REPLAY_CACHE,
    config::{Config, EndpointType, PadOption},
    crypto::{InitCipher, InitKey, SessionCipher, SessionKey, SharedKey},
    error::{BadDataReceived, Error, PeerMisbehaved},
    replay_cache::{current_timestamp_with_granularity, TIME_TORLERANCE},
    specification::{
        BODY_MAX_LEN, BODY_MIN_LEN, FRAME_MAX_LEN, FRAME_MIN_LEN, HDR_LEN,
        INIT_BODY_MAX_LEN, INIT_BODY_MIN_LEN, INIT_HDR_LEN, PAYLOAD_MIN_LEN,
        INIT_PAYLOAD_MAX_LEN, INIT_PAYLOAD_MIN_LEN, INIT_SALT_LEN, INIT_TAG_LEN,
        TAG_LEN,
    },
};

#[derive(Debug)]
pub(crate) struct InitFrameDecoder {
    shared_key: SharedKey,
    cipher: InitCipher,
    stream_id: u64,
    endpoint_type: EndpointType,
}

impl InitFrameDecoder {
    pub(crate) fn with_config(config: &Config) -> Self {
        Self {
            shared_key: config.shared_key.clone(),
            cipher: InitCipher::dumb(),
            stream_id: 0,
            endpoint_type: EndpointType::Undetermined,
        }
    }

    pub(crate) fn init_stream_id(&mut self, stream_id: u64) {
        self.stream_id = stream_id;
    }

    pub(crate) fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.endpoint_type = endpoint_type;
    }

    pub(crate) fn open_header(&mut self, buf: &mut [u8]) -> Result<InitHeader, Error> {
        debug_assert!(buf.len() == INIT_HDR_LEN);

        // Derive the initialization key using the received salt and `shared_key`.
        let salt: [u8; 32] = buf[0..32].try_into().unwrap();
        self.cipher.set_init_key(InitKey::derive(&self.shared_key, &salt));

        // Open initialization frame header
        if self.cipher.open(&mut buf[INIT_SALT_LEN..]).is_err() {
            return Err(BadDataReceived::InitFrameHeaderFailed.into());
        }

        // buf[32..48] is the authentication tag.

        // Check whether the command field is reserved (0x00).
        if buf[48] != 0 {
            return Err(PeerMisbehaved::InvalidCommand { received: buf[48] }.into());
        }

        // Check whether the flow direction field is valid.
        let direction = Direction::try_from(buf[49])?;
        match direction {
            Direction::ClientToServer => {
                // Received a client-to-server stream, but the endpoint is not a server.
                if self.endpoint_type != EndpointType::Server {
                    return Err(BadDataReceived::UnmatchedDirection.into());
                }
            }
            Direction::ServerToClient => {
                // Received a server-to-client stream, but the endpoint is not a client.
                if self.endpoint_type != EndpointType::Client {
                    return Err(BadDataReceived::UnmatchedDirection.into());
                }
            }
        }

        // Take out the stream_id.
        let stream_id = u64::from_be_bytes(buf[50..58].try_into().unwrap());

        // Check if the timestamp is within the accepted range.
        // Both the client and the server will perform this check.
        let timestamp = u64::from_be_bytes(buf[58..66].try_into().unwrap());
        let now = current_timestamp_with_granularity();
        if now.abs_diff(timestamp) > TIME_TORLERANCE {
            return Err(BadDataReceived::ExpiredTimestamp {
                received_timestamp: timestamp
            }.into());
        }

        match self.endpoint_type {
            EndpointType::Client => {
                // If I am a client, check whether the ID of the incoming stream
                // matches the ID of the outcoming stream.
                if stream_id != self.stream_id {
                    return Err(BadDataReceived::UnmatchedClientStreamId {
                        received: stream_id,
                    }.into());
                }
            }
            EndpointType::Server => {
                // If I am a server, check whether salt is reused.
                REPLAY_CACHE.check_or_insert(salt, timestamp, now)?;
            }
            EndpointType::Undetermined => {
                unreachable!("programming error: EndpointType is not initialized")
            }
        }

        // Check the length of the initial frame body.
        let body_len = u16::from_be_bytes(buf[66..68].try_into().unwrap()) as usize;
        if !(INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN).contains(&body_len) {
            return Err(PeerMisbehaved::InitFrameBodyLenInvalid {
                received: body_len as u16
            }.into());
        }

        // Check the length of the initial frame payload (if any).
        let payload_len = u16::from_be_bytes(buf[68..70].try_into().unwrap()) as usize;
        if !(INIT_PAYLOAD_MIN_LEN..=(body_len-INIT_TAG_LEN)).contains(&payload_len) {
            return Err(PeerMisbehaved::InitPayloadLenInvalid {
                received: payload_len as u16
            }.into());
        }

        Ok(InitHeader {
            session_key: SessionKey::derive_from_shared_key(&self.shared_key, &salt),
            stream_id,
            body_len,
            payload_len,
        })
    }

    pub(crate) fn open_body(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        debug_assert!((INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN).contains(&buf.len()));
        if self.cipher.open(buf).is_err() {
            return Err(BadDataReceived::InitFrameBodyFailed.into())
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct InitFrameEncoder {
    shared_key: SharedKey,
    cipher: InitCipher,
    stream_id: u64,
    endpoint_type: EndpointType,
    rng: StdRng,
}

impl InitFrameEncoder {
    pub(crate) fn with_config_and_rng(config: &Config, rng: StdRng) -> Self {
        Self {
            shared_key: config.shared_key.clone(),
            cipher: InitCipher::dumb(),
            stream_id: 0,
            endpoint_type: EndpointType::Undetermined,
            rng,
        }
    }

    pub(crate) fn init_stream_id(&mut self, stream_id: u64) {
        self.stream_id = stream_id;
    }

    pub(crate) fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.endpoint_type = endpoint_type;
    }

    pub(crate) fn seal(&mut self, buf: &mut InitFrameBufMut) -> SessionKey {
        let salt: [u8; 32] = self.rng.random();
        self.cipher.set_init_key(InitKey::derive(&self.shared_key, &salt));

        let direction = match self.endpoint_type {
            EndpointType::Client => Direction::ClientToServer,
            EndpointType::Server => Direction::ServerToClient,
            EndpointType::Undetermined => {
                unreachable!("programming error: EndpointType is not initialized")
            }
        };
        buf.pad();
        let body_len = buf.body_len();
        let payload_len = buf.payload_len();
        buf.header_mut()[0..32].copy_from_slice(&salt);
        buf.header_mut()[32..48].copy_from_slice(&[0u8; INIT_TAG_LEN]);
        buf.header_mut()[48] = 0x00;
        buf.header_mut()[49] = direction.into();
        buf.header_mut()[50..58].copy_from_slice(&self.stream_id.to_be_bytes());
        buf.header_mut()[58..66].copy_from_slice(&current_timestamp_with_granularity().to_be_bytes());
        buf.header_mut()[66..68].copy_from_slice(&(body_len as u16).to_be_bytes());
        buf.header_mut()[68..70].copy_from_slice(&(payload_len as u16).to_be_bytes());
        self.cipher.seal(&mut buf.header_mut()[INIT_SALT_LEN..]);
        self.cipher.seal(buf.body_mut());
        SessionKey::derive_from_shared_key(&self.shared_key, &salt)
    }
}

#[derive(Debug)]
pub(crate) struct FrameDecoder {
    cipher: SessionCipher,
    endpoint_type: EndpointType,
}

impl FrameDecoder {
    pub(crate) fn with_config(config: &Config) -> Self {
        Self {
            cipher: SessionCipher::with_cipher(config.cipher_kind),
            endpoint_type: EndpointType::Undetermined,
        }
    }

    pub(crate) fn init_session_key(&mut self, session_key: SessionKey) {
        self.cipher.init_session_key(session_key);
    }

    pub(crate) fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.endpoint_type = endpoint_type;
    }

    pub(crate) fn update_key_by_material(&mut self, key_material: [u8; 32]) {
        match self.endpoint_type {
            EndpointType::Client => {
                self.cipher.update_session_key(key_material, b"server_to_client");
            }
            EndpointType::Server => {
                self.cipher.update_session_key(key_material, b"client_to_server");
            }
            EndpointType::Undetermined => {
                unreachable!("programming error: EndpointType is not initialized")
            }
        }
    }

    pub(crate) fn open_header(&mut self, buf: &mut [u8]) -> Result<Header, Error> {
        debug_assert_eq!(buf.len(), HDR_LEN);
        if self.cipher.open(buf).is_err() {
            return Err(BadDataReceived::FrameHeaderFailed.into());
        }

        // buf[0..16] is the authentication tag.

        // Check whether the command field is valid.
        let Ok(command) = Command::try_from(buf[16]) else {
            return Err(PeerMisbehaved::InvalidCommand {
                received: buf[0]
            }.into());
        };

        // Check the length of the frame body.
        let body_len = u16::from_be_bytes(buf[17..19].try_into().unwrap()) as usize;
        if !(BODY_MIN_LEN..=BODY_MAX_LEN).contains(&body_len) {
            return Err(PeerMisbehaved::FrameBodyLenInvalid {
                received: body_len as u16
            }.into());
        }

        // Check the length of the frame payload (if any).
        let payload_len = u16::from_be_bytes(buf[19..21].try_into().unwrap()) as usize;
        if !(PAYLOAD_MIN_LEN..=body_len-TAG_LEN).contains(&payload_len) {
            return Err(PeerMisbehaved::PayloadLenInvalid {
                received: payload_len as u16
            }.into());
        }

        Ok(Header { command, body_len, payload_len })
    }

    pub(crate) fn open_body(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        debug_assert!((BODY_MIN_LEN..=BODY_MAX_LEN).contains(&buf.len()));
        if self.cipher.open(buf).is_err() {
            return Err(BadDataReceived::FrameBodyFailed.into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct FrameEncoder {
    cipher: SessionCipher,
    endpoint_type: EndpointType,
}

impl FrameEncoder {
    pub(crate) fn with_config(config: &Config) -> Self {
        Self {
            cipher: SessionCipher::with_cipher(config.cipher_kind),
            endpoint_type: EndpointType::Undetermined,
        }
    }

    pub(crate) fn init_session_key(&mut self, session_key: SessionKey) {
        self.cipher.init_session_key(session_key);
    }

    pub(crate) fn init_endpoint_type(&mut self, endpoint_type: EndpointType) {
        self.endpoint_type = endpoint_type;
    }

    pub(crate) fn update_key_by_material(&mut self, key_material: [u8; 32]) {
        match self.endpoint_type {
            EndpointType::Client => {
                self.cipher.update_session_key(key_material, b"client_to_server");
            }
            EndpointType::Server => {
                self.cipher.update_session_key(key_material, b"server_to_client");
            }
            EndpointType::Undetermined => {
                unreachable!("programming error: EndpointType is not initialized")
            }
        }
    }

    pub(crate) fn seal(&mut self, command: Command, buf: &mut FrameBufMut) {
        buf.pad();
        let body_len = buf.body_len();
        let payload_len = buf.payload_len();
        buf.header_mut()[16] = command.into();
        buf.header_mut()[17..19].copy_from_slice(&(body_len as u16).to_be_bytes());
        buf.header_mut()[19..21].copy_from_slice(&(payload_len as u16).to_be_bytes());
        self.cipher.seal(buf.header_mut());
        self.cipher.seal(buf.body_mut());
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Command {
    Payload,
    PeerTxKeyWillChange,
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> u8 {
        match cmd {
            Command::Payload => 0,
            Command::PeerTxKeyWillChange => 20,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Command::Payload),
            20 => Ok(Command::PeerTxKeyWillChange),
            _ => Err(PeerMisbehaved::InvalidCommand { received: value }.into()),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Direction {
    ClientToServer,
    ServerToClient,
}

impl From<Direction> for u8 {
    fn from(direction: Direction) -> u8 {
        match direction {
            Direction::ClientToServer => 1,
            Direction::ServerToClient => 2,
        }
    }
}

impl TryFrom<u8> for Direction {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Direction::ClientToServer),
            2 => Ok(Direction::ServerToClient),
            _ => Err(PeerMisbehaved::InvalidDirection { received: value }.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InitHeader {
    pub(crate) session_key: SessionKey,
    pub(crate) stream_id: u64,
    pub(crate) body_len: usize,
    pub(crate) payload_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub(crate) command: Command,
    pub(crate) body_len: usize,
    pub(crate) payload_len: usize,
}

#[derive(Debug)]
pub(crate) struct InitFrameBufMut {
    buf: Vec<u8>,
    payload_pos: usize,
    capacity: usize,
}

impl InitFrameBufMut {
    pub(crate) fn with_random(random: [u8; 32]) -> Self {
        let random_len = StdRng::from_seed(random)
            .random_range(INIT_PAYLOAD_MIN_LEN..=INIT_PAYLOAD_MAX_LEN);
        Self {
            buf: vec![0u8; INIT_HDR_LEN + INIT_TAG_LEN],
            payload_pos: INIT_HDR_LEN + INIT_TAG_LEN,

            // A predetermined random frame length,
            capacity: INIT_HDR_LEN + INIT_TAG_LEN + random_len,
        }
    }

    pub(crate) fn release_memory(&mut self) {
        self.buf = Vec::new();
    }

    pub(crate) fn header_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..INIT_HDR_LEN]
    }

    pub(crate) fn body_mut(&mut self) -> &mut [u8] {
        &mut self.buf[INIT_HDR_LEN..]
    }

    pub(crate) fn body_len(&self) -> usize {
        self.buf[INIT_HDR_LEN..].len()
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_pos - INIT_HDR_LEN - INIT_TAG_LEN
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity - self.payload_pos
    }

    pub(crate) fn push_payload(&mut self, payload: &[u8]) {
        debug_assert!(payload.len() <= self.remaining());
        self.buf.extend_from_slice(payload);
        self.payload_pos += payload.len();
    }

    pub(crate) fn pad(&mut self) {
        // The initial frame will be padded to a predetermined random length,
        // regardless of whether it contains a payload.
        self.buf.resize(self.capacity, 0);
    }

    pub(crate) fn inner(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

#[derive(Debug)]
pub(crate) struct FrameBufMut {
    buf: Vec<u8>,
    payload_pos: usize,
    capacity: usize,

    rng: StdRng,
    pad_option: PadOption,
}

impl FrameBufMut {
    pub(crate) fn with_pad_option_and_rng(pad_option: PadOption, rng: StdRng) -> Self {
        Self {
            buf: vec![0u8; HDR_LEN + TAG_LEN],
            payload_pos: HDR_LEN + TAG_LEN,
            capacity: match pad_option {
                PadOption::None => FRAME_MAX_LEN,

                // Based on the provided MPU, we divide the buffer into N blocks,
                // each with a length of one MPU.
                //
                // We use only N-1 blocks. If the padding length exceeds the
                // length of the N-1 block, we pad the last block to ensure the
                // final packet length appears uniformly distributed.
                PadOption::UniformTail { link_mpu } => {
                    (FRAME_MAX_LEN / link_mpu as usize - 1) * link_mpu as usize
                },
            },
            rng,
            pad_option,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.buf.clear();
        self.buf.resize(HDR_LEN + TAG_LEN, 0);
        self.payload_pos = HDR_LEN + TAG_LEN;
    }

    pub(crate) fn header_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..HDR_LEN]
    }

    pub(crate) fn body_mut(&mut self) -> &mut [u8] {
        &mut self.buf[HDR_LEN..]
    }

    pub(crate) fn body_len(&self) -> usize {
        self.buf[HDR_LEN..].len()
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_pos - HDR_LEN - TAG_LEN
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity - self.payload_pos
    }

    pub(crate) fn push_payload(&mut self, payload: &[u8]) {
        debug_assert!(payload.len() <= self.remaining());
        self.buf.extend_from_slice(payload);
        self.payload_pos += payload.len();
    }

    pub(crate) fn pad(&mut self) {
        match self.pad_option {
            PadOption::None => (),  // do nothing.
            PadOption::UniformTail { link_mpu } => {
                debug_assert!(self.buf.len() <= self.capacity);

                let frame_len = self.buf.len();
                let last_packet_len = frame_len % link_mpu as usize;

                // If the length of the last packet is 0, it means all previous
                // packets have been full to the MPU, and no additional padding
                // is needed.
                if last_packet_len == 0 {
                    return;
                }

                let sample_len = self.rng.random_range(FRAME_MIN_LEN..link_mpu as usize);
                let pad_len = if sample_len >= last_packet_len {
                    let p = sample_len - last_packet_len;
                    debug_assert!((0..=(link_mpu as usize - 2)).contains(&p));
                    p
                } else {
                    // If the desired length is less than the current payload
                    // length, advance by one MPU length.
                    let p = sample_len + link_mpu as usize - last_packet_len;
                    debug_assert!((FRAME_MIN_LEN+1..=(link_mpu as usize - 1)).contains(&p));
                    p
                };

                let len = self.buf.len();
                self.buf.resize(len + pad_len, 0x00);
            }
        }
    }

    pub(crate) fn inner(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        config::{PadOption, EndpointType},
        specification::{
            INIT_FRAME_MIN_LEN, INIT_FRAME_MAX_LEN, INIT_PAYLOAD_MIN_LEN,
            PAYLOAD_MIN_LEN, PAYLOAD_MAX_LEN,
        },
    };
    use super::*;

    #[test]
    fn test_initial_frame_client_encode_server_decode() {
        const N_TESTS: usize = 8192 * 10;
        let dummy_payload = vec![0u8; INIT_FRAME_MAX_LEN];
        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut encoder = InitFrameEncoder::with_config_and_rng(
            &Config {
                shared_key: SharedKey::from([0u8; 32]),
                cipher_kind: Default::default(),
                pad_option: PadOption::None,
            },
            StdRng::from_seed([0u8; 32])
        );
        encoder.init_endpoint_type(EndpointType::Client);
        let mut decoder = InitFrameDecoder::with_config(&Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::None,
        });
        decoder.init_endpoint_type(EndpointType::Server);
        for _ in 0..N_TESTS {
            let mut buf = InitFrameBufMut::with_random(rng.random());
            let remaining = buf.remaining();
            buf.push_payload(&dummy_payload[..remaining]);

            let encoder_session_key = encoder.seal(&mut buf);

            let (hdr, body) = buf.buf.split_at_mut(INIT_HDR_LEN);

            let InitHeader {
                session_key: decoder_session_key,
                stream_id,
                body_len,
                payload_len,
            } = decoder.open_header(hdr).unwrap();
            decoder.open_body(body).unwrap();

            assert_eq!(encoder_session_key, decoder_session_key);
            assert_eq!(stream_id, encoder.stream_id);
            assert!((INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN).contains(&body_len));
            assert_eq!(payload_len, remaining);
            assert_eq!(
                &dummy_payload[..remaining],
                &body[INIT_TAG_LEN..INIT_TAG_LEN+payload_len]
            );
        }
    }

    #[test]
    fn test_initial_frame_server_encode_client_decode() {
        const N_TESTS: usize = 8192 * 10;
        let dummy_payload = vec![0u8; INIT_FRAME_MAX_LEN];
        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut encoder = InitFrameEncoder::with_config_and_rng(
            &Config {
                shared_key: SharedKey::from([0u8; 32]),
                cipher_kind: Default::default(),
                pad_option: PadOption::None,
            },
            StdRng::from_seed([0u8; 32])
        );
        encoder.init_endpoint_type(EndpointType::Server);
        let mut decoder = InitFrameDecoder::with_config(&Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::None,
        });
        decoder.init_endpoint_type(EndpointType::Client);
        for _ in 0..N_TESTS {
            let mut buf = InitFrameBufMut::with_random(rng.random());
            let remaining = buf.remaining();
            buf.push_payload(&dummy_payload[..remaining]);

            let encoder_session_key = encoder.seal(&mut buf);

            let (hdr, body) = buf.buf.split_at_mut(INIT_HDR_LEN);

            let InitHeader {
                session_key: decoder_session_key,
                stream_id,
                body_len,
                payload_len,
            } = decoder.open_header(hdr).unwrap();
            decoder.open_body(body).unwrap();

            assert_eq!(encoder_session_key, decoder_session_key);
            assert_eq!(stream_id, encoder.stream_id);
            assert!((INIT_BODY_MIN_LEN..=INIT_BODY_MAX_LEN).contains(&body_len));
            assert_eq!(payload_len, remaining);
            assert_eq!(
                &dummy_payload[..remaining],
                &body[INIT_TAG_LEN..INIT_TAG_LEN+payload_len]
            );
        }
    }

    #[test]
    fn test_frame_encode_decode_no_padding() {
        const N_TESTS: usize = 65536;
        let dummy_payload = vec![0u8; FRAME_MAX_LEN];
        let config = Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::None,
        };
        let mut encoder = FrameEncoder::with_config(&config);
        let mut decoder = FrameDecoder::with_config(&config);
        encoder.init_session_key(SessionKey::from([0u8; 32]));
        decoder.init_session_key(SessionKey::from([0u8; 32]));
        encoder.init_endpoint_type(EndpointType::Client);
        decoder.init_endpoint_type(EndpointType::Server);

        let mut buf = FrameBufMut::with_pad_option_and_rng(
            PadOption::None,
            StdRng::from_seed([0u8; 32])
        );
        for _ in 0..N_TESTS {
            buf.reset();
            let remaining = buf.remaining();
            buf.push_payload(&dummy_payload[..remaining]);

            encoder.seal(Command::Payload, &mut buf);

            let (hdr, body) = buf.buf.split_at_mut(HDR_LEN);

            let Header {
                command,
                body_len,
                payload_len
            } = decoder.open_header(hdr).unwrap();
            decoder.open_body(body).unwrap();

            assert_eq!(Command::Payload, command);
            assert_eq!(payload_len, remaining);
            assert!((BODY_MIN_LEN..=BODY_MAX_LEN).contains(&body_len));
            assert_eq!(
                &dummy_payload[..remaining],
                &body[TAG_LEN..TAG_LEN+payload_len]
            );
        }
    }

    #[test]
    fn test_frame_encode_decode_with_padding() {
        const N_TESTS: usize = 65536;
        let dummy_payload = vec![0u8; FRAME_MAX_LEN];
        let config = Config {
            shared_key: SharedKey::from([0u8; 32]),
            cipher_kind: Default::default(),
            pad_option: PadOption::None,
        };
        let mut encoder = FrameEncoder::with_config(&config);
        let mut decoder = FrameDecoder::with_config(&config);
        encoder.init_session_key(SessionKey::from([0u8; 32]));
        decoder.init_session_key(SessionKey::from([0u8; 32]));
        encoder.init_endpoint_type(EndpointType::Client);
        decoder.init_endpoint_type(EndpointType::Server);

        for link_mpu in [128u16, 1448, 16384] {
            let mut buf = FrameBufMut::with_pad_option_and_rng(
                PadOption::UniformTail { link_mpu },
                StdRng::from_seed([0u8; 32]),
            );
            for _ in 0..N_TESTS {
                buf.reset();
                let remaining = buf.remaining();
                buf.push_payload(&dummy_payload[..remaining]);

                encoder.seal(Command::Payload, &mut buf);

                let (hdr, body) = buf.buf.split_at_mut(HDR_LEN);

                let Header {
                    command,
                    body_len,
                    payload_len
                } = decoder.open_header(hdr).unwrap();
                decoder.open_body(body).unwrap();

                assert_eq!(Command::Payload, command);
                assert_eq!(payload_len, remaining);
                assert!((BODY_MIN_LEN..=BODY_MAX_LEN).contains(&body_len));
                assert_eq!(
                    &dummy_payload[..remaining],
                    &body[TAG_LEN..TAG_LEN+payload_len]
                );
            }
        }

    }

    #[test]
    fn test_init_frame_buf_mut() {
        const N_TESTS: usize = 8192 * 10;
        let dummy_payload = vec![0u8; INIT_FRAME_MAX_LEN];
        let mut rng = StdRng::from_seed([0u8; 32]);
        for _ in 0..N_TESTS {
            let mut buf = InitFrameBufMut::with_random(rng.random());
            let remaining = buf.remaining();
            assert!((INIT_PAYLOAD_MIN_LEN..=INIT_PAYLOAD_MAX_LEN).contains(&remaining));

            buf.push_payload(&dummy_payload[..remaining]);
            buf.pad();
            let frame_len = buf.inner().len();
            assert!((INIT_FRAME_MIN_LEN..=INIT_FRAME_MAX_LEN).contains(&frame_len));
        }
    }

    #[test]
    fn test_frame_buf_mut_no_padding() {
        const N_TESTS: usize = 63336 * 10;
        let dummy_payload = vec![0u8; FRAME_MAX_LEN];

        let mut buf = FrameBufMut::with_pad_option_and_rng(
            PadOption::None,
            StdRng::from_seed([0u8; 32]),
        );
        for _ in 0..N_TESTS {
            buf.reset();
            let remaining = buf.remaining();
            assert!((PAYLOAD_MIN_LEN..=PAYLOAD_MAX_LEN).contains(&remaining));

            buf.push_payload(&dummy_payload[..remaining]);
            buf.pad();
            let frame_len = buf.inner().len();
            assert!((FRAME_MIN_LEN..=FRAME_MAX_LEN).contains(&frame_len));
        }
    }

    #[test]
    fn test_frame_buf_mut_uniform_tail() {
        const N_TESTS: usize = 65536 * 10;
        let dummy_payload = vec![0u8; FRAME_MAX_LEN];

        for link_mpu in [128u16, 1448, 16384] {
            let mut buf = FrameBufMut::with_pad_option_and_rng(
                PadOption::UniformTail { link_mpu },
                StdRng::from_seed([0u8; 32]),
            );
            for _ in 0..N_TESTS {
                buf.reset();
                let remaining = buf.remaining();
                assert!((PAYLOAD_MIN_LEN..=PAYLOAD_MAX_LEN).contains(&remaining));

                buf.push_payload(&dummy_payload[..remaining]);
                buf.pad();
                let frame_len = buf.inner().len();
                assert!((FRAME_MIN_LEN..=FRAME_MAX_LEN).contains(&frame_len));
            }
        }
    }
}
