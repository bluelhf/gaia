use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use tink_core::TinkError;

pub enum GaiaError {
    GeneratingKey(TinkError),
    BuildingEncryption(TinkError),
    WritingOutput(std::io::Error),
}

impl<'a> Debug for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GeneratingKey(_) => write!(f, "failed to generate key"),
            Self::BuildingEncryption(_) => write!(f, "failed to build encryption primitive"),
            Self::WritingOutput(_) => write!(f, "failed to write output"),
        }
    }
}

impl<'a> Display for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GeneratingKey(_) => write!(f, "could not encrypt the file"),
            Self::BuildingEncryption(_) => write!(f, "could not encrypt the file"),
            Self::WritingOutput(_) => write!(f, "could not make the encrypted output file"),
        }
    }
}

impl Error for GaiaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BuildingEncryption(cause) | Self::GeneratingKey(cause) => Some(cause),
            Self::WritingOutput(.., cause) => Some(cause),
        }
    }
}