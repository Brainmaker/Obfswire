//! Configuration structures for setting up an [`Obfuscator`] or [`ObfuscatedStream`].
//!
//! To build a config, you should make three decisions in order:
//!
//! 1. Generate a shared key [`SharedKey`] and distribute it through an
//!    out-of-band mechanism.
//! 2. Choose an AEAD cipher [`CipherKind`]. Note that both the client and
//!    server must use the same cipher; otherwise, they will not be able to
//!    communicate.
//! 3. Decide whether padding is needed. Padding can help obscure the length of
//!    the data packets but will increase their size. If padding is used,
//!    determine the maximum payload unit (MPU) supported by the underlying transport.
//!
//! # Example
//!
//! Create a basic client and server configuration:
//! ```
//! use obfswire::{Config, SharedKey};
//!
//! let shared_key = SharedKey::from_entropy();
//!
//! let client_config = Config::builder_with_shared_key(shared_key.clone())
//!     .with_default_cipher_and_tcp_padding();
//!
//! let server_config = Config::builder_with_shared_key(shared_key)
//!     .with_default_cipher_and_tcp_padding();
//! ```
//!
//! Create a client and server configuration using the AES-256-GCM cipher
//! and padding, with a maximum payload unit (MPU) of 2000 bytes:
//! ```
//! use obfswire::{CipherKind, Config, SharedKey};
//!
//! let shared_key = SharedKey::from_entropy();
//!
//! let client_config = Config::builder_with_shared_key(shared_key.clone())
//!     .with_cipher_kind(CipherKind::Aes256Gcm)
//!     .with_padding_in_link_mpu(2000);
//!
//! let server_config = Config::builder_with_shared_key(shared_key)
//!     .with_cipher_kind(CipherKind::Aes256Gcm)
//!     .with_padding_in_link_mpu(2000);
//! ```
//!
//! [`Obfuscator`]: crate::Obfuscator
//! [`ObfuscatedStream`]: crate::tokio_stream_impl::ObfuscatedStream
use crate::crypto::{CipherKind, SharedKey};

/// Configuration structure for setting up an [`Obfuscator`]  or [`ObfuscatedStream`].
///
/// For details on constructing and configuring `config`, refer to
/// the [`config`] module.
///
/// [`config`]: crate::config
/// [`Obfuscator`]: crate::Obfuscator
/// [`ObfuscatedStream`]: crate::tokio_stream_impl::ObfuscatedStream
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Config {
    pub(crate) shared_key: SharedKey,
    pub(crate) cipher_kind: CipherKind,
    pub(crate) pad_option: PadOption,
}

/// A builder for creating a [`Config`] instance.
///
/// To get a [`ConfigBuilder`], use [`Config::builder_with_shared_key`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConfigBuilder<State> {
    state: State,
}

impl Config {
    /// Sets up a shared key.
    pub fn builder_with_shared_key(shared_key: SharedKey) -> ConfigBuilder<WantsCipher> {
        ConfigBuilder {
            state: WantsCipher { shared_key },
        }
    }
}

impl ConfigBuilder<WantsCipher> {
    /// Sets up a AEAD cipher.
    ///
    /// The client and server must use the same cipher.
    pub fn with_cipher_kind(self, cipher: CipherKind) -> ConfigBuilder<WantsPadConfig> {
        ConfigBuilder {
            state: WantsPadConfig {
                shared_key: self.state.shared_key,
                cipher,
            },
        }
    }

    /// Use the default AEAD cipher (AES-128-GCM).
    pub fn with_default_cipher(self) -> ConfigBuilder<WantsPadConfig> {
        ConfigBuilder {
            state: WantsPadConfig {
                shared_key: self.state.shared_key,
                cipher: CipherKind::default(),
            },
        }
    }

    /// Use the default AEAD cipher (AES-128-GCM) and default TCP padding
    /// settings.
    pub fn with_default_cipher_and_tcp_padding(self) -> Config {
        Config {
            shared_key: self.state.shared_key,
            cipher_kind: CipherKind::default(),
            pad_option: PadOption::default_tcp_padding(),
        }
    }
}

impl ConfigBuilder<WantsPadConfig> {
    /// No padding for the stream.
    pub fn no_padding(self) -> Config {
        Config {
            shared_key: self.state.shared_key,
            cipher_kind: self.state.cipher,
            pad_option: PadOption::None,
        }
    }

    /// If the packet can fill the maximum payload unit (MPU) that the
    /// underlying connection can transmit, no padding is added. If the packet
    /// length does not fill the MPU, the packet length is adjusted to follow
    /// a uniform distribution.
    ///
    /// ## Panic
    /// Panics if `link_mpu` is less than 128 or greater than 16384.
    pub fn with_padding_in_link_mpu(self, link_mpu: u16) -> Config {
        assert!((128..=16384).contains(&link_mpu));
        Config {
            shared_key: self.state.shared_key,
            cipher_kind: self.state.cipher,
            pad_option: PadOption::UniformTail { link_mpu },
        }
    }

    /// When the underlying link is TCP, use the TCP MSS as the maximum payload
    /// unit (MPU) for the padding algorithm.
    pub fn with_default_tcp_padding(self) -> Config {
        Config {
            shared_key: self.state.shared_key,
            cipher_kind: self.state.cipher,
            pad_option: PadOption::default_tcp_padding(),
        }
    }
}

/// Config builder state where the caller must supply a AEAD cipher.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct WantsCipher {
    shared_key: SharedKey,
}

/// Config builder state where the caller must supply a padding option.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct WantsPadConfig {
    shared_key: SharedKey,
    cipher: CipherKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub(crate) enum PadOption {
    None,
    UniformTail { link_mpu: u16 },
}

impl PadOption {
    pub(crate) fn default_tcp_padding() -> Self {
        Self::UniformTail { link_mpu: 1448 }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum EndpointType {
    Client,
    Server,
    Undetermined,
}
