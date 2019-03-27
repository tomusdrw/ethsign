use std::fmt;
pub use crate::aes::SymmError;
pub use crate::scrypt::ScryptError;

#[derive(Debug)]
pub enum Error {
    Aes(SymmError),
    Scrypt(ScryptError)
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
