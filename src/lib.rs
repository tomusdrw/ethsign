//! A simple library to read JSON keyfiles and sign Ethereum stuff.
//!
//! How to use it?
//! ```rust
//! use ethsign::{Protected, KeyFile};
//!
//! fn main() {
//!     let file = std::fs::File::open("./res/wallet.json").unwrap();
//!     let key: KeyFile = serde_json::from_reader(file).unwrap();
//!     let password: Protected = "".into();
//!     let secret = key.to_secret_key(&password).unwrap();
//!     let message = [1_u8; 32];
//!
//!     // Sign the message
//!     let signature = secret.sign(&message).unwrap();
//!     println!("{:?}", signature);
//!
//!     // Recover the signer
//!     let public = signature.recover(&message).unwrap();
//!     println!("{:?}", public);
//!
//!     // Verify the signature
//!     let res = public.verify(&signature, &message).unwrap();
//!     println!("{}", if res { "signature correct" } else { "invalid signature" });
//! }
//! ```

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
pub use self::keyfile::KeyFile;
pub use self::protected::Protected;
