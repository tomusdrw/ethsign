//! A simple library to read JSON keyfiles and sign Ethereum stuff.

#![warn(missing_docs)]

mod ec;
mod key;
mod protected;

pub mod keyfile;

pub use self::ec::Error;
pub use self::key::{PublicKey, SecretKey, Signature};
pub use self::protected::Protected;

