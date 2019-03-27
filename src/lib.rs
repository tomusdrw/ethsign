//! A simple library to read JSON keyfiles and sign Ethereum stuff.

#![warn(missing_docs)]

mod ec;
mod error;
mod key;
mod protected;

// Use `parity-crypto` by default
#[cfg(not(feature = "pure-rust"))]
use parity_crypto as crypto;

// Switch to pure Rust drop-in replacement `ethsign-crypto`
#[cfg(feature = "pure-rust")]
use ethsign_crypto as crypto;

pub mod keyfile;

pub use self::error::Error;
pub use self::key::{PublicKey, SecretKey, Signature};
pub use self::protected::Protected;
