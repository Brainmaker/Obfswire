//! Crypto interface.
//!
//! This module provides an interface for AEAD
//! (Authenticated Encryption with Associated Data) ciphers.

use core::fmt::{Debug, Formatter};

use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use blake3::Hasher;
use rand::{rngs::OsRng, TryRngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Authenticated Encryption with Associated Data (AEAD) cipher used by the
/// [`Obfuscator`] or [`ObfuscatedStream`].
///
/// [`Obfuscator`]: crate::Obfuscator
/// [`ObfuscatedStream`]: crate::tokio_stream_impl::ObfuscatedStream
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CipherKind {
    /// ChaCha20-Poly1305-IETF with 128-bit tags and 96 bit nonces.
    ChaCha20Poly1305,

    /// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
    ///
    /// This is the default AEAD cipher.
    #[default]
    Aes128Gcm,

    /// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
    Aes256Gcm,
}

/// A 256-bit key shared between two parties communicating using the obfuscator.
///
/// The `SharedKey` is typically distributed through an out-of-band mechanism.
///
/// Avoid using low-entropy passwords provided by users to populate this structure,
/// as attackers could intercept communications and use dictionary attacks to
/// brute-force the correct password.
///
/// It is strongly recommended to use a secure entropy source to generate the
/// shared key, such as [`SharedKey::from_entropy`].
#[derive(Clone, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Generate a new [`SharedKey`] from system entropy.
    pub fn from_entropy() -> Self {
        let mut key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .expect("system random source failure");
        Self(key)
    }

    /// Extract this key’s bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Get a reference to the key’s bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for SharedKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Debug for SharedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedKey").field(&"*****").finish()
    }
}

/// A 256-bit key used for a single session.
#[derive(Clone, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SessionKey([u8; 32]);

impl SessionKey {
    /// Generates an invalid key, typically used as a placeholder.
    /// To prevent accidental use of this dumb key,
    /// it is filled with random data from system entropy.
    pub(crate) fn dumb() -> Self {
        let mut key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .expect("system random source failure");
        Self(key)
    }

    pub(crate) fn derive_from_shared_key(shared_key: &SharedKey, salt: &[u8; 32]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(shared_key.as_ref());
        hasher.update(salt);
        hasher.update(b"obfswire session key from shared key and salt");
        Self(*hasher.finalize().as_bytes())
    }

    pub(crate) fn derive_from_material(ikm: [u8; 32], context: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&ikm);
        hasher.update(context);
        Self(*hasher.finalize().as_bytes())
    }
}

impl From<[u8; 32]> for SessionKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Debug for SessionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionKey").field(&"*****").finish()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub(crate) struct InitKey([u8; 32]);

impl InitKey {
    /// Generates an invalid key, typically used as a placeholder.
    /// To prevent accidental use of this dumb key,
    /// it is filled with random data from system entropy.
    pub(crate) fn dumb() -> Self {
        let mut key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .expect("system random source failure");
        Self(key)
    }

    pub(crate) fn derive(shared_key: &SharedKey, salt: &[u8; 32]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(shared_key.as_ref());
        hasher.update(salt);
        hasher.update(b"obfswire first frame ephemeral key");
        Self(*hasher.finalize().as_bytes())
    }
}

impl Debug for InitKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InitKey").field(&"*****").finish()
    }
}

#[derive(Debug)]
pub(crate) struct SessionCipher {
    stateless_cipher: StatelessCipher,
    session_key: SessionKey,
    nonce: CounterNonce,
}

impl SessionCipher {
    pub(crate) fn with_cipher(cipher: CipherKind) -> Self {
        let dumb_key = SessionKey::dumb();
        Self {
            stateless_cipher: StatelessCipher::with_cipher_and_session_key(
                cipher,
                dumb_key.clone(),
            ),
            session_key: dumb_key,
            nonce: CounterNonce::default(),
        }
    }

    pub(crate) fn init_session_key(&mut self, session_key: SessionKey) {
        self.session_key = session_key;
        self.stateless_cipher = StatelessCipher::with_cipher_and_session_key(
            self.stateless_cipher.cipher,
            self.session_key.clone(),
        );
    }

    pub(crate) fn update_session_key(&mut self, ikm: [u8; 32], context: &[u8]) {
        self.session_key = SessionKey::derive_from_material(ikm, context);
        self.stateless_cipher = StatelessCipher::with_cipher_and_session_key(
            self.stateless_cipher.cipher,
            self.session_key.clone(),
        );
    }

    pub(crate) fn open(&mut self, in_out: &mut [u8]) -> Result<(), ()> {
        self.stateless_cipher.open(in_out, self.nonce.next())
    }

    pub(crate) fn seal(&mut self, in_out: &mut [u8]) {
        self.stateless_cipher.seal(in_out, self.nonce.next())
    }
}

#[derive(Debug)]
pub(crate) struct InitCipher {
    stateless_cipher: StatelessCipher,
    nonce: CounterNonce,
}

impl InitCipher {
    pub(crate) fn dumb() -> Self {
        Self {
            stateless_cipher: StatelessCipher::with_init_key(InitKey::dumb()),
            nonce: CounterNonce::default(),
        }
    }

    pub(crate) fn set_init_key(&mut self, init_key: InitKey) {
        self.stateless_cipher = StatelessCipher::with_init_key(init_key);
    }

    pub(crate) fn open(&mut self, in_out: &mut [u8]) -> Result<(), ()> {
        self.stateless_cipher.open(in_out, self.nonce.next())
    }

    pub(crate) fn seal(&mut self, in_out: &mut [u8]) {
        self.stateless_cipher.seal(in_out, self.nonce.next())
    }
}

#[derive(Debug)]
struct StatelessCipher {
    key: LessSafeKey,
    cipher: CipherKind,
}

impl StatelessCipher {
    const TAG_BYTES: usize = 16;

    pub(crate) fn with_cipher_and_session_key(ty: CipherKind, session_key: SessionKey) -> Self {
        Self {
            key: LessSafeKey::new(match ty {
                CipherKind::ChaCha20Poly1305 => {
                    UnboundKey::new(&CHACHA20_POLY1305, &session_key.0).unwrap()
                }
                CipherKind::Aes128Gcm => {
                    UnboundKey::new(&AES_128_GCM, &session_key.0[..16]).unwrap()
                }
                CipherKind::Aes256Gcm => UnboundKey::new(&AES_256_GCM, &session_key.0).unwrap(),
            }),
            cipher: ty,
        }
    }

    pub(crate) fn with_init_key(init_key: InitKey) -> Self {
        Self {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &init_key.0).unwrap()),
            cipher: CipherKind::ChaCha20Poly1305,
        }
    }

    pub(crate) fn open(&self, in_out: &mut [u8], nonce: [u8; 12]) -> Result<(), ()> {
        self.key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), in_out)
            .map_err(|_| ())?;
        Ok(())
    }

    pub(crate) fn seal(&self, in_out: &mut [u8], nonce: [u8; 12]) {
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - Self::TAG_BYTES);
        let t = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), in_out)
            .expect("encrypt failed, this should never happen");
        tag.copy_from_slice(t.as_ref());
    }
}

#[derive(Debug, Default)]
pub(crate) struct CounterNonce(u64);

impl CounterNonce {
    pub(crate) fn next(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.0.to_le_bytes());
        self.0 += 1;
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seal_open(cipher: CipherKind) {
        let cipher =
            StatelessCipher::with_cipher_and_session_key(cipher, SessionKey::from([0u8; 32]));
        let plaintext = b"Hello, world!";
        let mut buf = plaintext.to_vec();
        buf.extend_from_slice(&[0u8; StatelessCipher::TAG_BYTES]);

        // seal
        cipher.seal(&mut buf, [0u8; 12]);

        // open
        assert_eq!(cipher.open(&mut buf, [0u8; 12]), Ok(()));
        assert_eq!(&buf[..buf.len() - StatelessCipher::TAG_BYTES], plaintext);
    }

    fn test_empty_data(cipher: CipherKind) {
        let cipher =
            StatelessCipher::with_cipher_and_session_key(cipher, SessionKey::from([0u8; 32]));
        let mut buf = vec![0u8; StatelessCipher::TAG_BYTES];

        // seal with empty data
        cipher.seal(&mut buf, [0u8; 12]);
        let only_tag = buf.clone();

        // open the empty data
        assert_eq!(cipher.open(&mut buf, [0u8; 12]), Ok(()));

        // tag should be untouched
        assert_eq!(&buf, &only_tag);
    }

    fn test_decryption_error(cipher: CipherKind) {
        let cipher =
            StatelessCipher::with_cipher_and_session_key(cipher, SessionKey::from([0u8; 32]));
        let plaintext = b"Hello, world!";
        let mut buf = vec![0u8; StatelessCipher::TAG_BYTES];
        buf.extend_from_slice(plaintext);

        // seal
        cipher.seal(&mut buf, [0u8; 12]);

        // Tampering with the data
        buf[0] = buf[0].wrapping_add(1); // Modify the first byte

        // open
        assert_eq!(cipher.open(&mut buf, [0u8; 12]), Err(()));
    }

    #[test]
    fn test_cipher_chacha20_poly1305() {
        test_seal_open(CipherKind::ChaCha20Poly1305);
        test_empty_data(CipherKind::ChaCha20Poly1305);
        test_decryption_error(CipherKind::ChaCha20Poly1305);
    }

    #[test]
    fn test_cipher_aes_128_gcm() {
        test_seal_open(CipherKind::Aes128Gcm);
        test_empty_data(CipherKind::Aes128Gcm);
        test_decryption_error(CipherKind::Aes128Gcm);
    }

    #[test]
    fn test_cipher_aes_256_gcm() {
        test_seal_open(CipherKind::Aes256Gcm);
        test_empty_data(CipherKind::Aes256Gcm);
        test_decryption_error(CipherKind::Aes256Gcm);
    }
}
