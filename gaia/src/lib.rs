#![feature(let_chains)]
#![feature(buf_read_has_data_left)]

use std::io::{BufRead, BufReader, Read, Write};
use aead::{AeadCore, OsRng};
use aead::stream::{NewStream, StreamLE31, StreamPrimitive};
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit};

use crate::error::GaiaError;
pub mod error;

#[cfg(feature = "base64")]
pub mod keystore;

pub fn encrypt(input: impl Read, mut output: impl Write) -> Result<(Key<Aes256GcmSiv>, aes_gcm_siv::Nonce), GaiaError> {
    let key = Aes256GcmSiv::generate_key(&mut OsRng);
    let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
    let cipher = Aes256GcmSiv::new(&key);

    let stream_nonce = vec![0u8; nonce.len() - 4].splice(0..nonce.len() - 4, nonce).collect::<Vec<_>>();

    let stream: StreamLE31<Aes256GcmSiv> = StreamLE31::from_aead(cipher, aead::stream::Nonce::<Aes256GcmSiv, StreamLE31<Aes256GcmSiv>>::from_slice(&stream_nonce[..]));

    let mut encryptor = stream.encryptor();
    let mut reader = BufReader::new(input);

    loop {
        let buffer = reader.fill_buf().map_err(|e| GaiaError::ReadingInput(e))?.to_vec();
        reader.consume(buffer.len());
        if let Ok(more_data) = reader.has_data_left() && more_data {
            output.write_all(&*encryptor.encrypt_next(&buffer[..]).map_err(|e| GaiaError::Encrypting(e))?).map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            output.write_all(&*encryptor.encrypt_last(&buffer[..]).map_err(|e| GaiaError::Encrypting(e))?).map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok((key, nonce))
}

pub fn decrypt<'a>(input: impl Read, kh: &(Key<Aes256GcmSiv>, aes_gcm_siv::Nonce), mut output: impl Write) -> Result<(), GaiaError> {
    let cipher = Aes256GcmSiv::new(&kh.0);
    let stream_nonce = vec![0u8; kh.1.len() - 4].splice(0..kh.1.len() - 4, kh.1).collect::<Vec<_>>();

    let stream: StreamLE31<Aes256GcmSiv> = StreamLE31::from_aead(cipher, aead::stream::Nonce::<Aes256GcmSiv, StreamLE31<Aes256GcmSiv>>::from_slice(&stream_nonce[..]));
    let mut decryptor = stream.decryptor();
    let mut reader = BufReader::new(input);

    loop {
        let buffer = reader.fill_buf().map_err(|e| GaiaError::ReadingInput(e))?.to_vec();
        reader.consume(buffer.len());
        if let Ok(more_data) = reader.has_data_left() && more_data {
            output.write_all(&*decryptor.decrypt_next(&buffer[..]).map_err(|e| GaiaError::Decrypting(e))?).map_err(|e| GaiaError::WritingOutput(e))?;
        } else {
            output.write_all(&*decryptor.decrypt_last(&buffer[..]).map_err(|e| GaiaError::Decrypting(e))?).map_err(|e| GaiaError::WritingOutput(e))?;
            break;
        }
    }

    Ok(())
}
