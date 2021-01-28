//! Pure Rust drop-in replacement for the `parity-crypto` crate.

pub mod aes;
pub mod error;
pub mod scrypt;

pub use error::Error;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use tiny_keccak::{Hasher, Keccak};

pub const KEY_LENGTH: usize = 32;
pub const KEY_LENGTH_AES: usize = KEY_LENGTH / 2;

/// Helper trait for conveniently hashing byte slices
pub trait Keccak256<T: Sized> {
    /// Hash self to a hash type `T`.
    fn keccak256(&self) -> T;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::v256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}

impl<T: AsRef<[u8]>> Keccak256<[u8; 32]> for T {
    fn keccak256(&self) -> [u8; 32] {
        self.as_ref().keccak256()
    }
}

pub fn derive_key_iterations(password: &[u8], salt: &[u8], c: u32) -> (Vec<u8>, Vec<u8>) {
    let mut derived_key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(password, salt, c, &mut derived_key);
    let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
    let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
    (derived_right_bits.to_vec(), derived_left_bits.to_vec())
}

pub fn derive_mac(derived_left_bits: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let mut mac = vec![0u8; KEY_LENGTH_AES + cipher_text.len()];
    mac[0..KEY_LENGTH_AES].copy_from_slice(derived_left_bits);
    mac[KEY_LENGTH_AES..cipher_text.len() + KEY_LENGTH_AES].copy_from_slice(cipher_text);
    mac
}

/// Check if two slices are equal, this is equivalent to `a == b` and is only exposed here
/// as a replacement for `parity-crypto` version which uses constant time compare from `ring`.
pub fn is_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}

#[cfg(test)]
mod test {
    #[test]
    fn derive_behaves_like_parity_crypto() {
        let password = b"amazing password";
        let salt = b"salty sailor";
        let c = 2048;

        let rust_derive = super::derive_key_iterations(password, salt, c);
        let ring_derive = parity_crypto::derive_key_iterations(password, salt, c);

        assert_eq!(rust_derive, ring_derive);
    }

    #[test]
    fn aes_behaves_like_parity_crypto() {
        let key = b"very secret key.";
        let nonce = b"and secret nonce";

        let data = b"some bytes over here!";
        let encrypted = b"\x74\x98\x10\x1d\x91\xf6\x5b\x89\xe4\xb9\x71\x96\x45\x4f\x02\xc3\xb4\x2f\xa3\xe4\x9b";

        let mut dest_rust = [0u8; 21];
        let mut dest_ring = [0u8; 21];

        super::aes::encrypt_128_ctr(key, nonce, data, &mut dest_rust).unwrap();
        parity_crypto::aes::encrypt_128_ctr(key, nonce, data, &mut dest_ring).unwrap();

        assert_eq!(&dest_rust, encrypted);
        assert_eq!(&dest_ring, encrypted);

        super::aes::decrypt_128_ctr(key, nonce, encrypted, &mut dest_rust).unwrap();
        parity_crypto::aes::decrypt_128_ctr(key, nonce, encrypted, &mut dest_ring).unwrap();

        assert_eq!(&dest_rust, data);
        assert_eq!(&dest_ring, data);
    }
}
