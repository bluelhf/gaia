#![feature(let_chains)]
#![feature(buf_read_has_data_left)]

use std::io::{BufRead, BufReader, Read, Write};
use std::ops::Sub;
use aead::{AeadCore, OsRng, stream};
use aead::consts::U4;
use aead::generic_array::{ArrayLength, GenericArray};
use aead::generic_array::typenum::Unsigned;
use aead::rand_core::RngCore;
use aead::stream::{Decryptor, Encryptor, StreamLE31, StreamPrimitive};
use crypto_common::{Key, KeyInit};

use crate::error::GaiaError;
pub mod error;

type Cipher = aes_gcm_siv::Aes256GcmSiv;
type Stream = StreamLE31<Cipher>;
type StreamNonceOverhead = <Stream as StreamPrimitive<Cipher>>::NonceOverhead;
type StreamNonceLength = <<Cipher as AeadCore>::NonceSize as Sub<StreamNonceOverhead>>::Output;
type StreamTagLength = <Cipher as AeadCore>::TagSize;

#[cfg(feature = "base64")]
pub mod keystore;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncReadExt};

const BUF_SIZE: usize = 16384;

pub fn encrypt(input: impl Read, mut output: impl Write) -> Result<(Key<Cipher>, stream::Nonce<Cipher, Stream>), GaiaError> {
    let key = Cipher::generate_key(&mut OsRng);

    let mut stream_nonce = GenericArray::<u8, StreamNonceLength>::default();
    (&mut OsRng).fill_bytes(&mut stream_nonce);

    let mut encryptor = Encryptor::<Cipher, Stream>::new(&key, &stream_nonce.into());

    let reader = &mut BufReader::new(input);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        reader.take(BUF_SIZE as u64).read_to_end(&mut buffer).map_err(|e| GaiaError::ReadingInput(e))?;

        if let Ok(more_data) = reader.has_data_left() && more_data {
            encryptor.encrypt_next_in_place(&[], &mut buffer).map_err(|e| GaiaError::Encrypting(e))?;
            output.write_all(&buffer).map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            encryptor.encrypt_last_in_place(&[], &mut buffer).map_err(|e| GaiaError::Encrypting(e))?;
            output.write_all(&buffer).map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok((key, stream_nonce))
}

pub fn decrypt(input: impl Read, kh: &(Key<Cipher>, stream::Nonce<Cipher, Stream>), mut output: impl Write) -> Result<(), GaiaError>
where
    <Cipher as AeadCore>::NonceSize: Sub<U4>,
    <<Cipher as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>
{
    let stream_nonce = kh.1;

    let mut decryptor = Decryptor::<Cipher, Stream>::new(&kh.0, &stream_nonce.into());
    let reader = &mut BufReader::new(input);

    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        reader.take(BUF_SIZE as u64 + StreamTagLength::to_u64()).read_to_end(&mut buffer).map_err(|e| GaiaError::ReadingInput(e))?;

        if let Ok(more_data) = reader.has_data_left() && more_data {
            decryptor.decrypt_next_in_place(&[], &mut buffer).map_err(|e| GaiaError::Decrypting(e))?;
            output.write_all(&buffer[0..BUF_SIZE.min(buffer.len())]).map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            decryptor.decrypt_last_in_place(&[], &mut buffer).map_err(|e| GaiaError::Decrypting(e))?;
            output.write_all(&buffer[0..BUF_SIZE.min(buffer.len())]).map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok(())
}

#[cfg(feature = "tokio")]
pub async fn encrypt_async(input: impl tokio::io::AsyncRead + Unpin, mut output: impl tokio::io::AsyncWrite + Unpin) -> Result<(Key<Cipher>, stream::Nonce<Cipher, Stream>), GaiaError> {
    let key = Cipher::generate_key(&mut OsRng);

    let mut stream_nonce = GenericArray::<u8, StreamNonceLength>::default();
    (&mut OsRng).fill_bytes(&mut stream_nonce);

    let mut encryptor = Encryptor::<Cipher, Stream>::new(&key, &stream_nonce.into());

    let reader = &mut tokio::io::BufReader::new(input);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        reader.take(BUF_SIZE as u64).read_to_end(&mut buffer).await.map_err(|e| GaiaError::ReadingInput(e))?;

        if let Ok(more_data) = reader.fill_buf().await && more_data != [] {
            encryptor.encrypt_next_in_place(&[], &mut buffer).map_err(|e| GaiaError::Encrypting(e))?;
            output.write_all(&buffer).await.map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            encryptor.encrypt_last_in_place(&[], &mut buffer).map_err(|e| GaiaError::Encrypting(e))?;
            output.write_all(&buffer).await.map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok((key, stream_nonce))
}

#[cfg(feature = "tokio")]
pub async fn decrypt_async(input: impl tokio::io::AsyncRead + Unpin, kh: &(Key<Cipher>, stream::Nonce<Cipher, Stream>), mut output: impl tokio::io::AsyncWrite + Unpin) -> Result<(), GaiaError>
where
    <Cipher as AeadCore>::NonceSize: Sub<U4>,
    <<Cipher as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>
{
    let stream_nonce = kh.1;

    let mut decryptor = Decryptor::<Cipher, Stream>::new(&kh.0, &stream_nonce.into());
    let reader = &mut tokio::io::BufReader::new(input);

    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        reader.take(BUF_SIZE as u64 + StreamTagLength::to_u64()).read_to_end(&mut buffer).await.map_err(|e| GaiaError::ReadingInput(e))?;

        if let Ok(more_data) = reader.fill_buf().await && more_data != [] {
            decryptor.decrypt_next_in_place(&[], &mut buffer).map_err(|e| GaiaError::Decrypting(e))?;
            output.write_all(&buffer).await.map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            decryptor.decrypt_last_in_place(&[], &mut buffer).map_err(|e| GaiaError::Decrypting(e))?;
            output.write_all(&buffer).await.map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok(())
}