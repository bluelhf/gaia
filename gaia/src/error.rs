use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

pub enum GaiaError {
    ReadingInput(std::io::Error),
    WritingOutput(std::io::Error),
    Encrypting(aead::Error),
    Decrypting(aead::Error),
}

impl<'a> Debug for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadingInput(_) => write!(f, "failed to read input"),
            Self::WritingOutput(_) => write!(f, "failed to write output"),
            Self::Encrypting(_) => write!(f, "failed to encrypt block"),
            Self::Decrypting(_) => write!(f, "failed to decrypt block"),
        }
    }
}

impl<'a> Display for GaiaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadingInput(_) => write!(f, "could not read the input file"),
            Self::Encrypting(_) => write!(f, "could not encrypt the file"),
            Self::Decrypting(_) => write!(f, "could not decrypt the file"),
            Self::WritingOutput(_) => write!(f, "could not make the output file"),
        }
    }
}

impl Error for GaiaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encrypting(cause) | Self::Decrypting(cause) => Some(cause),
            Self::WritingOutput(.., cause) | Self::ReadingInput(.., cause) => Some(cause),
        }
    }
}