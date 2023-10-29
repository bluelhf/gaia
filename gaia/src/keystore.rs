use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use aead::Key;
use aead::generic_array::GenericArray;
use aead::generic_array::sequence::Concat;
use aes_gcm_siv::Aes256GcmSiv;
use base64::{DecodeError, Engine};
use base64::prelude::BASE64_URL_SAFE;

pub enum ConversionError {
    Base64EncodingError(DecodeError),
    KeyEncodingError(aead::Error)
}

impl Debug for ConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64EncodingError(cause) => write!(f, "failed to decode base64 because {cause:?}"),
            Self::KeyEncodingError(cause) => write!(f, "key encoding failed because {cause:?}")
        }
    }
}

impl Display for ConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64EncodingError(cause) => write!(f, "the key is in an invalid format: {cause}"),
            Self::KeyEncodingError(cause) => write!(f, "the key itself is invalid: {cause}")
        }
    }
}

impl Error for ConversionError {
    fn cause(&self) -> Option<&dyn Error> {
        match self {
            Self::Base64EncodingError(cause) => Some(cause),
            Self::KeyEncodingError(cause) => Some(cause)
        }
    }
}

pub fn to_secret(kh: &(Key<Aes256GcmSiv>, aes_gcm_siv::Nonce)) -> Result<String, ConversionError> {
    dbg!(kh.0, kh.1);
    Ok(BASE64_URL_SAFE.encode(kh.0.concat(kh.1)))
}


pub fn from_secret(secret: &str) -> Result<(Key<Aes256GcmSiv>, aes_gcm_siv::Nonce), ConversionError> {
    let data = BASE64_URL_SAFE.decode(secret).map_err(|e| ConversionError::Base64EncodingError(e))?;
    let (key, nonce) = data.split_at(32);
    Ok((*GenericArray::from_slice(key), *GenericArray::from_slice(nonce)))
}