//! Scrypt key derivation wrapper around the `scrypt` crate.

pub use scrypt::errors::InvalidParams as ScryptError;

use super::{KEY_LENGTH, KEY_LENGTH_AES};

pub fn derive_key(pass: &[u8], salt: &[u8], n: u32, p: u32, r: u32) -> Result<(Vec<u8>, Vec<u8>), ScryptError> {
    let log_n = (32 - n.leading_zeros() - 1) as u8;
    let mut derived_key = vec![0u8; KEY_LENGTH];
    let scrypt_params = scrypt::Params::new(log_n, r, p)?;
    scrypt::scrypt(pass, salt, &scrypt_params, &mut derived_key).expect("derived_key is long enough; qed");
    let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
    let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
    Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
}
