//! The error type

use crate::ec;

pub use crate::{
    crypto::{error::ScryptError, Error as EthsignCryptoError},
    ec::Error as Secp256k1Error,
};

/// Key error
#[derive(Debug)]
pub enum Error {
    /// Invalid password for the keyfile
    InvalidPassword,
    /// Crypto error
    Crypto(EthsignCryptoError),
    /// Scrypt error
    ScryptError(ScryptError),
    /// Secp256k1 error
    Secp256k1(Secp256k1Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::InvalidPassword => write!(fmt, "Invalid Password"),
            Error::Crypto(ref e) => write!(fmt, "Crypto: {}", e),
            Error::ScryptError(ref e) => write!(fmt, "ScryptError: {}", e),
            Error::Secp256k1(ref e) => write!(fmt, "Secp256k1: {:?}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<ec::Error> for Error {
    fn from(e: ec::Error) -> Error {
        Error::Secp256k1(e)
    }
}
