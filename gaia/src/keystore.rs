use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use aead::KeySizeUser;
use aead::generic_array::GenericArray;
use aead::generic_array::sequence::Concat;
use aead::generic_array::typenum::Unsigned;
use base64::{DecodeError, Engine};
use base64::prelude::BASE64_URL_SAFE;
use crate::{Cipher, Handle};

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

pub fn to_secret(kh: &Handle) -> Result<String, ConversionError> {
    Ok(BASE64_URL_SAFE.encode(kh.0.concat(kh.1)))
}


pub fn from_secret(secret: &str) -> Result<Handle, ConversionError> {
    let data = BASE64_URL_SAFE.decode(secret).map_err(|e| ConversionError::Base64EncodingError(e))?;
    let (key, nonce) = data.split_at(<Cipher as KeySizeUser>::KeySize::to_usize());
    Ok((*GenericArray::from_slice(key), *GenericArray::from_slice(nonce)))
}