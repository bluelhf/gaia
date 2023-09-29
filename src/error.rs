use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use tink_core::TinkError;

use crate::keystore;

pub enum GaiaError {
    OpeningInput(String, std::io::Error),
    OpeningOutput(String, std::io::Error),
    OpeningSecret(String, std::io::Error),
    WritingOutput(std::io::Error),
    GeneratingKey(TinkError),
    BuildingEncryption(TinkError),
    InvalidSecret(keystore::ConversionError)
}

impl<'a> Debug for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpeningInput(path, _) => write!(f, "failed to open the {path} for the input"),
            Self::OpeningOutput(path, _) => write!(f, "failed to open the {path} for the output"),
            Self::OpeningSecret(path, _) => write!(f, "failed to open the {path} for the secret"),
            Self::GeneratingKey(_) => write!(f, "failed to generate key"),
            Self::BuildingEncryption(_) => write!(f, "failed to build encryption primitive"),
            Self::WritingOutput(_) => write!(f, "failed to write output"),
            Self::InvalidSecret(_) => write!(f, "failed to decrypt the invalid key"),
        }
    }
}

impl<'a> Display for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpeningInput(path, _) => write!(f, "could not read from the {path}"),
            Self::OpeningOutput(path, _) => write!(f, "could not write to the {path}"),
            Self::OpeningSecret(path, _) => write!(f, "could not write the secret to the {path}"),
            Self::GeneratingKey(_) => write!(f, "could not encrypt the file"),
            Self::BuildingEncryption(_) => write!(f, "could not encrypt the file"),
            Self::WritingOutput(_) => write!(f, "could not make the encrypted output file"),
            Self::InvalidSecret(_) => write!(f, "the provided secret is invalid")
        }
    }
}

impl Error for GaiaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpeningInput(.., cause)
            | Self::OpeningOutput(.., cause)
            | Self::OpeningSecret(.., cause)
            | Self::WritingOutput(.., cause) => Some(cause),

            Self::InvalidSecret(cause) => Some(cause),

            Self::BuildingEncryption(cause)
            | Self::GeneratingKey(cause) => Some(cause)
        }
    }
}