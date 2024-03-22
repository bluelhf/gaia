use std::io::{self, Read, Write, BufRead, BufReader, ErrorKind};
use std::ops::Sub;
use aead::{AeadCore, OsRng, stream, consts::U4, generic_array::{ArrayLength, GenericArray}, rand_core::RngCore};
use crypto_common::{KeyInit, typenum::Unsigned};

use crate::{
    error::GaiaError, BUF_SIZE,
    Stream, Key, Cipher, Encryptor, Decryptor,
    StreamTagLength, StreamNonceLength
};

macro_rules! sync_crypt_reader_impl {
    ($name: ident, $transform: ident, $next_in_place: ident, $last_in_place: ident, $buf_size_calc: expr) => {
        pub struct $name<R> where R: Read {
            reader: Box<BufReader<R>>,
            transform: Option<$transform<Cipher, Stream>>,
            input_buffer: Vec<u8>,
            transform_buffer: Vec<u8>,
        }

        impl<R> $name<R> where R: Read {
            pub fn new(reader: R, key: &Key<Cipher>, nonce: &stream::Nonce<Cipher, Stream>) -> Self {
                let reader = BufReader::new(reader);
                let transform = $transform::<Cipher, Stream>::new(key, nonce);
                let buffer = Vec::new();

                Self { reader: Box::new(reader), transform: Some(transform), input_buffer: buffer, transform_buffer: vec![] }
            }
        }

        impl<R> Read for $name<R> where R: Read {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                self.input_buffer.clear();
                self.reader.as_mut().take($buf_size_calc as u64).read_to_end(&mut self.input_buffer)?;

                if let Ok(more_data) = self.reader.has_data_left() && more_data {
                    if let Some(ref mut transform) = self.transform.as_mut() {
                        transform.$next_in_place(&[], &mut self.input_buffer)
                            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                        self.transform_buffer.extend_from_slice(&self.input_buffer);
                    }
                } else {
                    if let Some(transform) = self.transform.take() {
                        transform.$last_in_place(&[], &mut self.input_buffer)
                            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                        self.transform_buffer.extend_from_slice(&self.input_buffer);
                    }
                }

                let effective_length = output.len().min(self.transform_buffer.len());
                output.split_at_mut(effective_length).0.copy_from_slice(&self.transform_buffer[0..effective_length]);
                self.transform_buffer.drain(0..effective_length);
                Ok(effective_length)
            }
        }
    };
}

sync_crypt_reader_impl!(EncryptingReader, Encryptor, encrypt_next_in_place, encrypt_last_in_place, BUF_SIZE);
sync_crypt_reader_impl!(DecryptingReader, Decryptor, decrypt_next_in_place, decrypt_last_in_place, BUF_SIZE + StreamTagLength::to_usize());

pub fn encrypt(input: impl Read, mut output: impl Write) -> Result<(Key<Cipher>, stream::Nonce<Cipher, Stream>), GaiaError> {
    let key = Cipher::generate_key(&mut OsRng);

    let mut stream_nonce = GenericArray::<u8, StreamNonceLength>::default();
    (&mut OsRng).fill_bytes(&mut stream_nonce);

    let mut reader = EncryptingReader::new(Box::new(input), &key, &stream_nonce.into());
    io::copy(&mut reader, &mut output).map_err(|e| GaiaError::WritingOutput(e))?;
    Ok((key, stream_nonce))
}

pub fn decrypt(input: impl Read, kh: &(Key<Cipher>, stream::Nonce<Cipher, Stream>), mut output: impl Write) -> Result<(), GaiaError>
    where
        <Cipher as AeadCore>::NonceSize: Sub<U4>,
        <<Cipher as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>
{
    let stream_nonce = kh.1;

    let mut reader = DecryptingReader::new(Box::new(input), &kh.0, &stream_nonce.into());
    io::copy(&mut reader, &mut output).map_err(|e| GaiaError::WritingOutput(e))?;

    Ok(())
}