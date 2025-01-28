//! Obfswire is an obfuscation transport protocol that operates over reliable,
//! ordered streams, designed to counter deep packet inspection (DPI) and
//! active probing attack of endpoints.
//!
//! ## Quick Start
//!
//! Obfswire provides two interfaces: [`Obfuscator`] and [`ObfuscatedStream`].
//!
//! * [`Obfuscator`]
//!
//!   The `Obfuscator` is a deterministic state machine implementation of the
//!   Obfswire protocol logic, following the sans-I/O principle. It does not
//!   include any network I/O code or spawn internal threads, focusing solely
//!   on data obfuscation and deobfuscation.
//!
//!   When using `Obfuscator`, it needs to be bound to a reliable, ordered stream
//!   that implements the [`Read`] and [`Write`] traits (e.g., [`TcpStream`]).
//!   `Obfuscator` does not restrict the type of underlying transport, but it is
//!   typically used with TCP transports.
//!
//! * [`ObfuscatedStream`]
//!
//!   For convenient use in asynchronous scenarios, Obfswire provides a
//!   ready-to-use asynchronous stream implementation based on tokio. It offers
//!   a future-based API. `ObfuscatedStream` requires the underlying transports
//!   to implement the  [`AsyncRead`] and [`AsyncWrite`] traits and the
//!   `tokio-stream-impl` feature to be enabled.
//!
//! `ObfuscatedStream` is an asynchronous wrapper around `Obfuscator`,
//! with almost identical logic. The only difference is that `ObfuscatedStream`
//! will delay disconnection by a random time when it detects interference,
//! adding randomness to its behavior. `Obfuscator` does not provide this
//! feature. It is strongly recommended that users of `Obfuscator` implement a
//! similar random disconnection mechanism to avoid exposing endpoint behavior
//! patterns.
//!
//! ## Configuration
//!
//! Obfswire provides the [`Config`] struct to configure the behavior of
//! [`Obfuscator`] and [`ObfuscatedStream`]. Configuration options include
//! the following:
//!
//! 1. Shared Key
//!
//!    The shared key is passed through the [`SharedKey`] struct.
//!    `SharedKey` is a 32-byte random number that must be securely distributed
//!    to communication endpoints out-of-band. The shared key is central to the
//!    Obfswire protocol's obfuscation and security. Ensure its security.
//!
//! 2. AEAD Algorithm
//!
//!    Configurable through the [`CipherKind`] enum. Currently supported algorithms
//!    are AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
//!
//! 3. Padding Strategy
//!
//!    The following padding options are available:
//!
//!    * **No Padding**: The length of the data remains the same as the original length.
//!    * **Tail Packet Uniform Padding**: If the data exactly fills a packet,
//!      no padding is added; if it does not, padding is added to make the length
//!      conform to a uniform distribution.
//!
//! Both endpoints must use the same shared key and cryptographic algorithm, but
//! padding strategies can be configured independently, and the protocol will
//! adapt automatically.
//!
//! For detailed configuration options, refer to the documentation of the
//! [`config`] module.
//!
//! Note: Obfswire relies on system time. Ensure that the UTC time difference
//! between both communication endpoints does not exceed 90 seconds
//! (regardless of time zone).
//!
//! ## Session Key Update
//!
//! Although Obfswire does not directly support Perfect Forward Secrecy (PFS)
//! and automatic key rotation, it provides interfaces for users to replace
//! session keys:
//!
//! * [`Obfuscator::update_key`]
//! * [`Obfuscator::update_key_with_notif`]
//!
//! Users can implement a key exchange protocol (e.g., Diffie-Hellman) at the
//! application layer and then update the session key through the above
//! interfaces. This approach allows continued use of the Obfswire encrypted
//! channel, avoiding the performance overhead of nested encryption.
//!
//! [`Read`]: std::io::Read
//! [`Write`]: std::.io::Write
//! [`TcpStream`]: std::.net::TcpStream
//! [`AsyncRead`]: tokio::io::AsyncRead
//! [`AsyncWrite`]: tokio::io::AsyncWrite
//! [`Obfuscator`]: Obfuscator
//! [`ObfuscatedStream`]: ObfuscatedStream
#![warn(missing_debug_implementations, missing_docs, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod config;
pub mod error;

mod codec;
mod crypto;
mod replay_cache;
mod specification;
mod state_machine;

#[cfg(feature = "tokio-stream-impl")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-stream-impl")))]
mod tokio_stream_impl;

pub use config::Config;
pub use crypto::{CipherKind, SharedKey};
pub use error::Error;

pub use state_machine::{Obfuscator, Reader, Writer};
#[cfg(feature = "tokio-stream-impl")]
pub use tokio_stream_impl::ObfuscatedStream;

use std::sync::LazyLock;

use replay_cache::ReplayCache;

/// A global (application-level) replay cache to prevent replay attacks.
///
/// This ensures that the salt is unique within the application.
///
/// The replay cache is only invoked when receiving new stream's initialization.
/// Each salt is cached for just over a minute.
static REPLAY_CACHE: LazyLock<ReplayCache> = LazyLock::new(|| ReplayCache::with_capacity(1024));

#[cfg(test)]
mod test {
    use std::io::{self, ErrorKind, Read, Write};

    #[derive(Debug)]
    pub(crate) struct MockStream {
        pub(crate) buf: Vec<u8>,
        pub(crate) eof: bool,
    }

    impl MockStream {
        #[allow(unused)]
        pub(crate) fn set_eof(&mut self) {
            self.buf.clear();
            self.eof = true;
        }

        #[allow(unused)]
        pub(crate) fn clear(&mut self) {
            self.buf.clear();
            self.eof = false;
        }
    }

    impl Default for MockStream {
        fn default() -> Self {
            Self {
                buf: Vec::with_capacity(65536),
                eof: false,
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.eof {
                return Ok(0);
            }
            if self.buf.is_empty() {
                return Err(io::Error::new(ErrorKind::WouldBlock, "empty buffer"));
            }
            let n = core::cmp::min(buf.len(), self.buf.len());
            buf[..n].copy_from_slice(&self.buf[..n]);
            self.buf = self.buf.split_off(n);
            Ok(n)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.eof {
                return Ok(0);
            }
            self.buf.extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
