#![feature(let_chains)]
#![feature(buf_read_has_data_left)]

use std::ops::Sub;

use aead::{AeadCore, stream::{
    Decryptor, Encryptor,
    StreamLE31, StreamPrimitive
}, stream};
use aead::generic_array::GenericArray;
use aead::rand_core::{CryptoRng, RngCore};

use crypto_common::Key;

const BUF_SIZE: usize = 16384;
pub type Cipher = aes_gcm_siv::Aes256GcmSiv;
pub type Stream = StreamLE31<Cipher>;
type StreamNonceOverhead = <Stream as StreamPrimitive<Cipher>>::NonceOverhead;
type StreamNonceLength = <<Cipher as AeadCore>::NonceSize as Sub<StreamNonceOverhead>>::Output;

type StreamTagLength = <Cipher as AeadCore>::TagSize;
pub type Handle = (Key<Cipher>, stream::Nonce<Cipher, Stream>);

pub mod error;

#[cfg(feature = "base64")]
pub mod keystore;

#[cfg(feature = "tokio")]
mod tokio_crypt;
#[cfg(feature = "tokio")]
pub use tokio_crypt::{encrypt_async, decrypt_async, AsyncEncryptingReader, AsyncDecryptingReader};
mod std_crypt;

pub use std_crypt::{encrypt, decrypt, EncryptingReader, DecryptingReader};

pub fn generate_handle(rng: &mut (impl CryptoRng + RngCore)) -> Handle {
    let mut key = Key::<Cipher>::default();
    rng.fill_bytes(&mut key);

    let mut stream_nonce = GenericArray::<u8, StreamNonceLength>::default();
    rng.fill_bytes(&mut stream_nonce);
    (key, stream_nonce)
}
