//! Error handling module

pub use crate::{aes::SymmError, scrypt::ScryptError};
use std::fmt;

/// Generic Error type for the crate
#[derive(Debug)]
pub enum Error {
    /// AES encryption error
    Aes(SymmError),
    /// Scrypt encryption error
    Scrypt(ScryptError),
}

impl From<SymmError> for Error {
    fn from(err: SymmError) -> Error {
        Error::Aes(err)
    }
}

impl From<ScryptError> for Error {
    fn from(err: ScryptError) -> Error {
        Error::Scrypt(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Aes(err) => err.fmt(f),
            Error::Scrypt(err) => err.fmt(f),
        }
    }
}
