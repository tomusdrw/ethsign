use std::fmt;
use scrypt::{ScryptParams, errors::{InvalidParams, InvalidOutputLen}};

use super::{KEY_LENGTH_AES, KEY_LENGTH};

#[derive(Debug)]
pub enum ScryptError {
    InvalidOutputLen(InvalidOutputLen),
    InvalidParams(InvalidParams),
}

impl fmt::Display for ScryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScryptError::InvalidOutputLen(err) => err.fmt(f),
            ScryptError::InvalidParams(err) => err.fmt(f),
        }
    }
}

impl From<InvalidOutputLen> for ScryptError {
    fn from(err: InvalidOutputLen) -> ScryptError {
        ScryptError::InvalidOutputLen(err)
    }
}

impl From<InvalidParams> for ScryptError {
    fn from(err: InvalidParams) -> ScryptError {
        ScryptError::InvalidParams(err)
    }
}

pub fn derive_key(pass: &[u8], salt: &[u8], n: u32, p: u32, r: u32) -> Result<(Vec<u8>, Vec<u8>), ScryptError> {
    let log_n = (32 - n.leading_zeros() - 1) as u8;
    let mut derived_key = vec![0u8; KEY_LENGTH];
    let scrypt_params = ScryptParams::new(log_n, r, p)?;
    scrypt::scrypt(pass, salt, &scrypt_params, &mut derived_key)?;
    let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
    let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
    Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
}
