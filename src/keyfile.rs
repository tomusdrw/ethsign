//! JSON keyfile representation.

use crate::error::Error;
use crate::Protected;
use parity_crypto::Keccak256;
use std::num::NonZeroU32;

use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

/// A set of bytes.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes(#[serde(with = "bytes")] pub Vec<u8>);

/// Key file
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    /// Keyfile UUID
    pub id: String,
    /// Keyfile version
    pub version: u64,
    /// Keyfile crypto
    pub crypto: Crypto,
    /// Optional address
    pub address: Option<Bytes>,
}

/// Encrypted secret
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crypto {
    /// Cipher definition
    pub cipher: Cipher,
    /// Cipher parameters
    pub cipherparams: Aes128Ctr,
    /// Cipher bytes
    pub ciphertext: Bytes,
    /// KDF
    #[serde(flatten)]
    pub kdf: Kdf,
    /// MAC
    pub mac: Bytes,
}

/// Cipher kind
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cipher {
    /// AES 128 CTR
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
}

/// AES 128 CTR params
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aes128Ctr {
    /// Initialisation vector
    pub iv: Bytes,
}

/// Key-Derivation function
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kdf", content = "kdfparams")]
pub enum Kdf {
    /// Password-based KDF 2
    Pbkdf2(Pbkdf2),
    /// Scrypt
    Scrypt(Scrypt),
}

/// PBKDF2 params
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pbkdf2 {
    /// C
    pub c: NonZeroU32,
    /// DKLen
    pub dklen: u32,
    /// Prf
    pub prf: Prf,
    /// Salt
    pub salt: Bytes,
}

/// Scrypt params
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scrypt {
    /// DKLen
    pub dklen: u32,
    /// P
    pub p: u32,
    /// N
    pub n: u32,
    /// R
    pub r: u32,
    /// Salt
    pub salt: Bytes,
}

/// PRF
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prf {
    /// HMAC SHA256
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl Crypto {
    /// Encrypt plain data with password
    pub fn encrypt(
        plain: &[u8],
        password: &Protected,
        iterations: NonZeroU32,
    ) -> Result<Self, Error> {
        let mut rng = thread_rng();

        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];

        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);

        // two parts of derived key
        // DK = [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]
        let (derived_left_bits, derived_right_bits) =
            parity_crypto::derive_key_iterations(password.as_ref(), &salt, iterations);

        // preallocated buffer to hold cipher
        // length = length(plain) as we are using CTR-approach
        let plain_len = plain.len();
        let mut ciphertext = Bytes(vec![0u8; plain_len]);

        // aes-128-ctr with initial vector of iv
        parity_crypto::aes::encrypt_128_ctr(&derived_left_bits, &iv, plain, &mut *ciphertext.0)
            .map_err(parity_crypto::Error::from)
            .map_err(Error::Crypto)?;

        // KECCAK(DK[16..31] ++ <ciphertext>), where DK[16..31] - derived_right_bits
        let mac = parity_crypto::derive_mac(&derived_right_bits, &*ciphertext.0).keccak256();

        Ok(Crypto {
            cipher: Cipher::Aes128Ctr,
            cipherparams: Aes128Ctr {
                iv: Bytes(iv.to_vec()),
            },
            ciphertext,
            kdf: Kdf::Pbkdf2(Pbkdf2 {
                c: iterations,
                dklen: parity_crypto::KEY_LENGTH as u32,
                prf: Prf::HmacSha256,
                salt: Bytes(salt.to_vec()),
            }),
            mac: Bytes(mac.to_vec()),
        })
    }

    /// Decrypt into plain data
    pub fn decrypt(&self, password: &Protected) -> Result<Vec<u8>, Error> {
        let (left_bits, right_bits) = match self.kdf {
            Kdf::Pbkdf2(ref params) => {
                parity_crypto::derive_key_iterations(password.as_ref(), &params.salt.0, params.c)
            }
            Kdf::Scrypt(ref params) => parity_crypto::scrypt::derive_key(
                password.as_ref(),
                &params.salt.0,
                params.n,
                params.p,
                params.r,
            )
            .map_err(Error::ScryptError)?,
        };

        let mac = parity_crypto::derive_mac(&right_bits, &self.ciphertext.0).keccak256();

        if !parity_crypto::is_equal(&mac, &self.mac.0) {
            return Err(Error::InvalidPassword);
        }

        let mut plain = Vec::new();
        plain.resize(self.ciphertext.0.len(), 0);
        parity_crypto::aes::decrypt_128_ctr(
            &left_bits,
            &self.cipherparams.iv.0,
            &self.ciphertext.0,
            &mut plain,
        )
        .map_err(parity_crypto::Error::from)
        .map_err(Error::Crypto)?;

        Ok(plain)
    }
}

mod bytes {
    use std::fmt;

    use serde::{de, Deserializer, Serializer};

    /// Serializes a slice of bytes.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let it: String = rustc_hex::ToHex::to_hex(bytes);
        serializer.serialize_str(&it)
    }

    /// Deserialize into vector of bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'a> de::Visitor<'a> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a hex string of even length")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() % 2 != 0 {
                    return Err(E::invalid_length(v.len(), &self));
                }

                ::rustc_hex::FromHex::from_hex(&v).map_err(|e| E::custom(e.to_string()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_deserialize() {
        let _keyfile: KeyFile = serde_json::from_str(include_str!("../res/wallet.json")).unwrap();
    }

    #[test]
    fn decrypt_encrypt() {
        let data = &b"It was the year they finally immanentized the Eschaton."[..];
        let password = Protected::new(b"discord".to_vec());

        let crypto = Crypto::encrypt(data, &password, NonZeroU32::new(10240).unwrap()).unwrap();
        let decrypted = crypto.decrypt(&password).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }
}
