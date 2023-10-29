use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

use gaia::keystore;

pub enum CliError {
    OpeningInput(String, std::io::Error),
    OpeningOutput(String, std::io::Error),
    WritingSecret(String, std::io::Error),
    InvalidSecret(keystore::ConversionError)
}

impl<'a> Debug for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpeningInput(path, _) => write!(f, "failed to open the {path} for the input"),
            Self::OpeningOutput(path, _) => write!(f, "failed to open the {path} for the output"),
            Self::WritingSecret(path, _) => write!(f, "failed to open the {path} for the secret"),
            Self::InvalidSecret(_) => write!(f, "failed to decrypt the invalid key"),
        }
    }
}

impl<'a> Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpeningInput(path, _) => write!(f, "could not read from the {path}"),
            Self::OpeningOutput(path, _) => write!(f, "could not write to the {path}"),
            Self::WritingSecret(path, _) => write!(f, "could not write the secret to the {path}"),
            Self::InvalidSecret(_) => write!(f, "the provided secret is invalid")
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpeningInput(.., cause)
            | Self::OpeningOutput(.., cause)
            | Self::WritingSecret(.., cause) => Some(cause),

            Self::InvalidSecret(cause) => Some(cause),
        }
    }
}