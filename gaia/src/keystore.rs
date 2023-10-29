use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use base64::{DecodeError, Engine};
use base64::prelude::BASE64_URL_SAFE;
use tink_core::keyset::{BinaryReader, BinaryWriter, Handle, insecure};
use tink_core::TinkError;

pub enum ConversionError {
    Base64EncodingError(DecodeError),
    KeyEncodingError(TinkError)
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
    let mut data: Vec<u8> = Vec::new();
    insecure::write(kh, &mut BinaryWriter::new(&mut data)).map_err(|e| ConversionError::KeyEncodingError(e))?;
    Ok(BASE64_URL_SAFE.encode(data))
}


pub fn from_secret(secret: &str) -> Result<Handle, ConversionError> {
    let data = BASE64_URL_SAFE.decode(secret).map_err(|e| ConversionError::Base64EncodingError(e))?;
    insecure::read(&mut BinaryReader::new(&data[..])).map_err(|e| ConversionError::KeyEncodingError(e))
}