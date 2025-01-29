//! All possible non-I/O protocol errors.
//!
use core::{
    error,
    fmt::{Display, Formatter},
};
use std::io::{self, ErrorKind};

/// Enumeration of all possible non-I/O protocol errors.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The data was corrupted during reading from the underlying transport.
    ///
    /// This could be due to the peer using an incorrect key,
    /// random errors in network, or active probing attacks.
    ///
    /// Upon detecting this condition, the implementation should take
    /// appropriate strategies to avoid exposing obfuscator behavior characteristics.
    ///
    /// # Suggested error handling strategy
    ///
    /// This error is fatal, meaning the connection cannot continue.
    /// Upon detection, the implementer should introduce a random delay before
    /// closing the connection. During this delay, the implementer should
    /// continue to call [`read_wire`] to receive data,
    /// in order to avoid revealing obfuscator behavior patterns.
    ///
    /// [`read_wire`]: crate::Obfuscator::read_wire
    BadDataReceived(BadDataReceived),

    /// The peer deviated from the protocol. It is typically caused by a peer
    /// that knows the endpoint's identity sending malformed data.
    ///
    /// The parameter provides a hint about where the deviation occurred.
    ///
    /// # Suggested error handling strategy
    ///
    /// This error is fatal. Upon detecting this error,
    /// the implementer can immediately close the connection without exposing
    /// endpoint behavior characteristics.
    PeerMisbehaved(PeerMisbehaved),

    /// The peer requested an operation. The parameter provides a hint.
    ///
    /// # Suggested error handling strategy
    ///
    /// This error is recoverable. Upon detecting this error,
    /// the implementer should take appropriate actions based on the error
    /// hint and retry the transmission.
    Retryable(Retryable),
}

/// All errors that require disguise measures.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BadDataReceived {
    /// The timestamp of the connection request is within the allowed range,
    /// but the salt was reused.
    ReusedSalt,

    /// The timestamp of the connection request is outside the allowed
    /// range of the protocol.
    ExpiredTimestamp {
        /// The expired timestamp we received.
        received_timestamp: u64,
    },

    /// The direction of the incoming stream is not as expected.
    UnmatchedDirection,

    /// The stream ID received by the client does not match expectations.
    UnmatchedClientStreamId {
        /// The unmatched stream ID received by the client.
        received: u64,
    },

    /// Failed to decrypt or authenticate the initial frame header.
    InitFrameHeaderFailed,

    /// Failed to decrypt or authenticate the initial frame body.
    InitFrameBodyFailed,

    /// Failed to decrypt or authenticate the frame header.
    FrameHeaderFailed,

    /// Failed to decrypt or authenticate the frame body.
    FrameBodyFailed,
}

/// The connection cannot continue due to improper behavior by the peer.
///
/// Generally, implementers should not alter their behavior in response
/// to these errors, and there is nothing it can do to improve matters.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum PeerMisbehaved {
    /// The `body_len` field of the initial frame is incorrect.
    InitBodyLenInvalid {
        /// The expected `body_len` field of the initial frame.
        expect: u16,
        /// The received `body_len` field of the initial frame.
        received: u16,
    },

    /// The `command` field of the initial frame is incorrect.
    InvalidInitCommand {
        /// The received `command` field of the initial frame.
        received: u8,
    },

    /// The `command` field of the frame is incorrect.
    InvalidCommand {
        /// The received `command` field of the frame.
        received: u8,
    },

    /// The `command` field of the frame conflicts with the `key_state` of the obfuscator.
    CommandStateConflict {
        /// The command field of the frame.
        command: u8,
        /// The `key_state` of the obfuscator.    
        state: u8,
    },

    /// The `direction` field of the frame does not match.
    InvalidDirection {
        /// The received `direction` field of the frame.
        received: u8,
    },

    /// The `body_len` field of the initial frame is too large or too small.
    InitFrameBodyLenInvalid {
        /// The received `body_len` field of the frame.
        received: u16,
    },

    /// The `payload_len` field of the initial frame is too large or too small.
    InitPayloadLenInvalid {
        /// The received `payload_len` field of the frame.
        received: u16,
    },

    /// The `body_len` field of the frame is too large or too small.
    FrameBodyLenInvalid {
        /// The received `body_len` field of the frame.
        received: u16,
    },

    /// The `payload_len` field of the frame is too large or too small.
    PayloadLenInvalid {
        /// The received `payload_len` field of the frame.
        received: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
/// The peer requested an operation. The parameter provides a hint.
pub enum Retryable {
    /// The peer requested the endpoint provide key material to continue
    /// transmission.
    ///
    /// The [`update_key_with_notif`] method
    /// must be called to provide key material to continue.
    ///
    /// [`update_key_with_notif`]: crate::Obfuscator::update_key_with_notif
    KeyMaterialRequired,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadDataReceived(err) => write!(f, "BadDataReceived: {}", err),
            Error::PeerMisbehaved(err) => write!(f, "PeerMisbehaved: {}", err),
            Error::Retryable(err) => write!(f, "Retryable: {}", err),
        }
    }
}

impl Display for BadDataReceived {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            BadDataReceived::ReusedSalt => write!(f, "ReusedSalt"),
            BadDataReceived::UnmatchedDirection => write!(f, "UnmatchedDirection"),
            BadDataReceived::UnmatchedClientStreamId { received } => {
                write!(f, "InvalidStreamId: received {:?}", received)
            }
            BadDataReceived::ExpiredTimestamp { received_timestamp } => write!(
                f,
                "ExpiredTimestamp: received timestamp {}",
                received_timestamp
            ),
            BadDataReceived::InitFrameHeaderFailed => write!(f, "InitFrameHeaderFailed"),
            BadDataReceived::InitFrameBodyFailed => write!(f, "InitFrameBodyFailed"),
            BadDataReceived::FrameHeaderFailed => write!(f, "FrameHeaderFailed"),
            BadDataReceived::FrameBodyFailed => write!(f, "FrameBodyFailed"),
        }
    }
}
impl Display for PeerMisbehaved {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PeerMisbehaved::InitBodyLenInvalid { expect, received } => write!(
                f,
                "InitBodyLenInvalid: expected {}, received {}",
                expect, received
            ),
            PeerMisbehaved::InvalidCommand { received } => {
                write!(f, "InvalidCommand: received {}", received)
            }
            PeerMisbehaved::InvalidInitCommand { .. } => write!(f, "InvalidInitCommand"),
            PeerMisbehaved::CommandStateConflict { command, state } => write!(
                f,
                "CommandStateConflict: command {}, state {}",
                command, state
            ),
            PeerMisbehaved::InvalidDirection { received } => {
                write!(f, "InvalidDirection: received {}", received)
            }
            PeerMisbehaved::InitFrameBodyLenInvalid { received } => {
                write!(f, "InitFrameBodyLenInvalid: received {}", received)
            }
            PeerMisbehaved::InitPayloadLenInvalid { received } => {
                write!(f, "InitPayloadLenInvalid: received {}", received)
            }
            PeerMisbehaved::FrameBodyLenInvalid { received } => {
                write!(f, "FrameBodyTooLarge: received {}", received)
            }
            PeerMisbehaved::PayloadLenInvalid { received } => {
                write!(f, "PayloadTooLarge: received {}", received)
            }
        }
    }
}

impl Display for Retryable {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Retryable::KeyMaterialRequired => write!(f, "KeyMaterialRequired"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::BadDataReceived(err) => Some(err),
            Error::PeerMisbehaved(err) => Some(err),
            Error::Retryable(err) => Some(err),
        }
    }
}

impl error::Error for BadDataReceived {}

impl error::Error for PeerMisbehaved {}

impl error::Error for Retryable {}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(ErrorKind::Other, e)
    }
}

impl From<BadDataReceived> for io::Error {
    fn from(e: BadDataReceived) -> Self {
        io::Error::new(ErrorKind::Other, Error::BadDataReceived(e))
    }
}

impl From<PeerMisbehaved> for io::Error {
    fn from(e: PeerMisbehaved) -> Self {
        io::Error::new(ErrorKind::Other, Error::PeerMisbehaved(e))
    }
}

impl From<Retryable> for io::Error {
    fn from(e: Retryable) -> Self {
        io::Error::new(ErrorKind::Other, Error::Retryable(e))
    }
}

impl From<BadDataReceived> for Error {
    fn from(e: BadDataReceived) -> Self {
        Error::BadDataReceived(e)
    }
}

impl From<PeerMisbehaved> for Error {
    fn from(e: PeerMisbehaved) -> Self {
        Error::PeerMisbehaved(e)
    }
}

impl From<Retryable> for Error {
    fn from(e: Retryable) -> Self {
        Error::Retryable(e)
    }
}
