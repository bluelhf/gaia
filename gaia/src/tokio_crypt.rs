use std::io::{self, ErrorKind};
use std::ops::Sub;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use aead::{AeadCore, consts::U4, generic_array::ArrayLength, OsRng};
use crypto_common::typenum::Unsigned;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{BUF_SIZE, Cipher, Decryptor, Encryptor, error::GaiaError, generate_handle, Handle, Stream, StreamTagLength};

pub async fn encrypt_async(input: impl AsyncRead + Unpin, mut output: impl tokio::io::AsyncWrite + Unpin) -> Result<Handle, GaiaError> {
    let handle = generate_handle(&mut OsRng);
    let mut reader = AsyncEncryptingReader::new(Box::new(input), &handle);
    tokio::io::copy(&mut reader, &mut output).await.map_err(|e| GaiaError::WritingOutput(e))?;
    Ok(handle)
}

pub async fn decrypt_async(input: impl AsyncRead + Unpin, handle: &Handle, mut output: impl tokio::io::AsyncWrite + Unpin) -> Result<(), GaiaError>
    where
        <Cipher as AeadCore>::NonceSize: Sub<U4>,
        <<Cipher as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>
{
    let mut reader = AsyncDecryptingReader::new(Box::new(input), handle);
    tokio::io::copy(&mut reader, &mut output).await.map_err(|e| GaiaError::WritingOutput(e))?;
    Ok(())
}

/// Async reader that always fills the requested buffer completely, unless EOF is reached.
///
/// Also included is the ability to check whether the previously read chunk was the last one.
/// Note that `was_last_chunk()` may return `false` when there are no chunks to read, i.e. the
/// original reader was empty to begin with.
pub struct AsyncChunkingReader<R> where R: AsyncRead + Unpin {
    reader: Box<R>,
    cursor: usize, // Tracks the real length of the buffer
    buffer: Vec<u8>, // Allocated region
    was_last_chunk: bool,
}

impl<R> AsyncChunkingReader<R> where R: AsyncRead + Unpin {
    pub fn new(reader: R) -> Self {
        Self {
            reader: Box::new(reader),
            buffer: vec![],
            was_last_chunk: false,
            cursor: 0,
        }
    }

    pub fn was_last_chunk(&self) -> bool {
        self.was_last_chunk
    }
}

impl<R> AsyncRead for AsyncChunkingReader<R> where R: AsyncRead + Unpin {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.cursor > output.remaining() {
            let effective_length = output.remaining();
            output.put_slice(this.buffer.drain(0..effective_length).as_slice());
            this.cursor -= effective_length;

            this.was_last_chunk = false;

            return Poll::Ready(Ok(()));
        }

        let mut pinned_reader = std::pin::pin!(this.reader.as_mut());

        let needed = output.remaining() + 1 - this.cursor;
        this.buffer.resize(needed, 0);

        let mut read_buf = ReadBuf::new(&mut this.buffer);
        read_buf.advance(this.cursor);

        loop {
            let previous_position = read_buf.filled().len();
            ready!(pinned_reader.as_mut().poll_read(cx, &mut read_buf)
                .map_ok(|_| this.cursor = read_buf.filled().len()))?;

            if read_buf.remaining() == 0 {
                break;
            }

            if read_buf.filled().len() == previous_position {
                this.was_last_chunk = true;
                break;
            }
        }

        let effective_length = output.remaining().min(this.cursor);
        output.put_slice(this.buffer.drain(0..effective_length).as_slice());
        this.cursor -= effective_length;
        Poll::Ready(Ok(()))
    }
}

macro_rules! async_crypt_reader_impl {
    ($name: ident, $transform: ident, $next_in_place: ident, $last_in_place: ident, $buf_size_calc: expr) => {
        pub struct $name<R> where R: AsyncRead + Unpin {
            chunk_reader: Box<AsyncChunkingReader<R>>,
            transform: Option<$transform<Cipher, Stream>>,
            input_buffer: Vec<u8>,
            completed_buffer: Vec<u8>,
        }

        impl<R> $name<R> where R: AsyncRead + Unpin {
            pub fn new(reader: R, (key, nonce): &Handle) -> Self {
                let transform = $transform::<Cipher, Stream>::new(key, nonce);

                Self { chunk_reader: Box::new(AsyncChunkingReader::new(reader)), transform: Some(transform),
                    input_buffer: vec![0; $buf_size_calc], completed_buffer: vec![],
                }
            }
        }

        impl<R> AsyncRead for $name<R> where R: AsyncRead + Unpin {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();

                let to_read = output.remaining().min(this.completed_buffer.len());

                if to_read != 0 {
                    output.put_slice(this.completed_buffer.drain(0..to_read).as_ref());
                    return Poll::Ready(Ok(()));
                }

                let mut chunk_reader = std::pin::pin!(this.chunk_reader.as_mut());

                let filled_len = {
                    let mut read_buf = ReadBuf::new(&mut this.input_buffer);
                    ready!(chunk_reader.as_mut().poll_read(cx, &mut read_buf))?;
                    read_buf.filled().len()
                };

                if filled_len == 0 { // end-of-file
                    return Poll::Ready(Ok(()));
                }

                this.input_buffer.truncate(filled_len);

                if !chunk_reader.was_last_chunk() {
                    if let Some(ref mut transform) = this.transform.as_mut() {
                        transform.$next_in_place(&[], &mut this.input_buffer)
                            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                        this.completed_buffer.extend_from_slice(&this.input_buffer);
                    }
                } else {
                    if let Some(transform) = this.transform.take() {
                        transform.$last_in_place(&[], &mut this.input_buffer)
                            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                        this.completed_buffer.extend_from_slice(&this.input_buffer);
                    }
                }

                this.input_buffer = vec![0u8; $buf_size_calc];

                let effective_length = output.remaining().min(this.completed_buffer.len());
                output.put_slice(&this.completed_buffer[0..effective_length]);
                this.completed_buffer.drain(0..effective_length);


                Poll::Ready(Ok(()))
            }
        }
    };
}

async_crypt_reader_impl!(AsyncEncryptingReader, Encryptor, encrypt_next_in_place, encrypt_last_in_place, BUF_SIZE);
async_crypt_reader_impl!(AsyncDecryptingReader, Decryptor, decrypt_next_in_place, decrypt_last_in_place, BUF_SIZE + StreamTagLength::to_usize());

impl<R> AsyncEncryptingReader<R> where R: AsyncRead + Unpin {
    pub fn new_with_os_rng(reader: R) -> (Self, Handle) {
        let handle = generate_handle(&mut OsRng);
        (Self::new(reader, &handle), handle)
    }
}