#![feature(let_chains)]
#![feature(buf_read_has_data_left)]
//! A library for encrypting and decrypting data using the STREAM-LE-31 construction
//! with the AES-256-GCM-SIV cipher.
//! 
//! # Examples
//! 
//! ## Synchronous, `encrypt` and `decrypt` functions
//! 
//! ```rust
//! use std::io::{Read, Write};
//!
//! use gaia::{encrypt, decrypt, generate_handle, error::GaiaError};
//!
//! fn main() -> Result<(), GaiaError> {
//!    let input = "Hello, world!";
//!    let mut encrypted = Vec::new();
//!    let handle = encrypt(input.as_bytes(), &mut encrypted)?;
//! 
//!    let mut decrypted = Vec::new();
//!    decrypt(&encrypted, &mut decrypted, &handle)?;
//!    assert_eq!(input.as_bytes(), decrypted.as_slice());
//!    Ok(())
//! }
//! ```
//! 
//! ## Asynchronous, `encrypt_async` and `decrypt_async` functions
//! 
//! ```rust
//! use tokio::io::{AsyncRead, AsyncWrite};
//! 
//! use gaia::{encrypt_async, decrypt_async, generate_handle, error::GaiaError};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), GaiaError> {
//!     let input = "Hello, world!";
//!     let mut encrypted = Vec::new();
//!     let handle = encrypt_async(input.as_bytes(), &mut encrypted).await?;
//!     
//!     let mut decrypted = Vec::new();
//!     decrypt_async(&encrypted, &handle, &mut decrypted).await?;
//!     assert_eq!(input.as_bytes(), decrypted.as_slice());
//!     Ok(())
//! }
//! ```
//! 
//! ## Synchronous, `EncryptingReader` and `DecryptingReader` structs
//! 
//! ```rust
//! use std::io::{Read, Write};
//! use rand_core::OsRng;
//!
//! use gaia::{EncryptingReader, DecryptingReader, generate_handle, error::GaiaError};
//!
//! fn main() -> Result<(), GaiaError> {
//!     let input = "Hello, world!";
//!     let (mut reader, handle) = EncryptingReader::new_with_os_rng(input.as_bytes());
//!     let mut encrypted = Vec::new();
//!     reader.read_to_end(&mut encrypted)?;
//!     
//!     let mut reader = DecryptingReader::new(&encrypted, &handle);
//!     let mut decrypted = Vec::new();
//!     reader.read_to_end(&mut decrypted)?;
//! 
//!     assert_eq!(input.as_bytes(), decrypted.as_slice());
//!     Ok(())
//! }
//! ```
//! 
//! ## Asynchronous, `AsyncEncryptingReader` and `AsyncDecryptingReader` structs
//! ```rust
//! use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
//!
//! use gaia::{AsyncEncryptingReader, AsyncDecryptingReader, generate_handle, error::GaiaError};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), GaiaError> {
//!     let input = "Hello, world!";
//!     let (mut reader, handle) = AsyncEncryptingReader::new_with_os_rng(input.as_bytes());
//!     let mut encrypted = Vec::new();
//!     reader.read_to_end(&mut encrypted).await?;
//!     
//!     let mut reader = AsyncDecryptingReader::new(&encrypted, &handle);
//!     let mut decrypted = Vec::new();
//!     reader.read_to_end(&mut decrypted).await?;
//! 
//!     assert_eq!(input.as_bytes(), decrypted.as_slice());
//!     Ok(())
//! }
//! ```

use std::ops::Sub;

use aead::{AeadCore, stream::{
    Decryptor, Encryptor,
    StreamLE31, StreamPrimitive
}, stream};
use aead::generic_array::GenericArray;
use aead::rand_core::{CryptoRng, RngCore};

use crypto_common::Key;

/// The buffer size to which to split the input data.
/// This must stay consistent between encryption and decryption, but in general
/// this is an implementation detail and should not be exposed to the user.
const BUF_SIZE: usize = 16384;

/// The type of cipher used for encryption and decryption, AES-256-GCM-SIV.
pub type Cipher = aes_gcm_siv::Aes256GcmSiv;

/// The AEAD construction used for encryption and decryption, STREAM-LE-31.
pub type Stream = StreamLE31<Cipher>;

/// A pair of a key and nonce, required for encryption and decryption.
pub type Handle = (Key<Cipher>, stream::Nonce<Cipher, Stream>);

// I would document these types, but I forget how STREAM works.
type StreamNonceOverhead = <Stream as StreamPrimitive<Cipher>>::NonceOverhead;
type StreamNonceLength = <<Cipher as AeadCore>::NonceSize as Sub<StreamNonceOverhead>>::Output;
type StreamTagLength = <Cipher as AeadCore>::TagSize;

pub mod error;

#[cfg(feature = "base64")]
pub mod keystore;

#[cfg(feature = "tokio")]
mod tokio_crypt;
#[cfg(feature = "tokio")]
pub use tokio_crypt::{encrypt_async, decrypt_async, AsyncEncryptingReader, AsyncDecryptingReader};
mod std_crypt;

pub use std_crypt::{encrypt, decrypt, EncryptingReader, DecryptingReader};

/// Generates a Handle using the provided cryptographically secure random number generator.
/// Both the key and nonce are filled with random bytes.
pub fn generate_handle(rng: &mut (impl CryptoRng + RngCore)) -> Handle {
    let mut key = Key::<Cipher>::default();
    rng.fill_bytes(&mut key);

    let mut stream_nonce = GenericArray::<u8, StreamNonceLength>::default();
    rng.fill_bytes(&mut stream_nonce);
    (key, stream_nonce)
}
