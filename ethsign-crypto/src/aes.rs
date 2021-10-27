//! AES symmetric encryption

use aes::{
    cipher::{generic_array::GenericArray, FromBlockCipher, NewBlockCipher, StreamCipher},
    Aes128, Aes128Ctr,
};
use std::fmt;

/// Error type for the AES symmetric encryption
#[derive(Debug)]
pub enum SymmError {
    InvalidKey,
    InvalidNonce,
    SourceDestinationMismatch,
}

impl fmt::Display for SymmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SymmError::InvalidKey => f.write_str("Key must be 16 bytes long"),
            SymmError::InvalidNonce => f.write_str("Nonce must be 16 bytes long"),
            SymmError::SourceDestinationMismatch => f.write_str("Source and destination must have equal length"),
        }
    }
}

/// Encrypt a message (CTR mode).
///
/// Key (`k`) length and initialisation vector (`iv`) length have to be 16 bytes each.
/// An error is returned if the input lengths are invalid.
pub fn encrypt_128_ctr(k: &[u8], iv: &[u8], plain: &[u8], dest: &mut [u8]) -> Result<(), SymmError> {
    if k.len() != 16 {
        return Err(SymmError::InvalidKey);
    }
    if iv.len() != 16 {
        return Err(SymmError::InvalidNonce);
    }
    if plain.len() != dest.len() {
        return Err(SymmError::SourceDestinationMismatch);
    }

    let key = GenericArray::from_slice(k);
    let nonce = GenericArray::from_slice(iv);

    dest.copy_from_slice(plain);

    let cipher = Aes128::new(&key);
    let mut cipher_ctr = Aes128Ctr::from_block_cipher(cipher, &nonce);
    cipher_ctr.apply_keystream(dest);

    Ok(())
}

/// Decrypt a message (CTR mode).
///
/// Key (`k`) length and initialisation vector (`iv`) length have to be 16 bytes each.
/// An error is returned if the input lengths are invalid.
pub fn decrypt_128_ctr(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) -> Result<(), SymmError> {
    // This is symmetrical encryption, so those are equivalent operations
    encrypt_128_ctr(k, iv, encrypted, dest)
}
