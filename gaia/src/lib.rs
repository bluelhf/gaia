#![feature(let_chains)]
#![feature(buf_read_has_data_left)]

use std::ops::Sub;

use aead::{
    AeadCore, 
    stream::{
        Decryptor, Encryptor,
        StreamLE31, StreamPrimitive
    }
};

use crypto_common::Key;

const BUF_SIZE: usize = 16384;
type Cipher = aes_gcm_siv::Aes256GcmSiv;
type Stream = StreamLE31<Cipher>;
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
