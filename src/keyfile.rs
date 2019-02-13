//! JSON keyfile representation.

use std::num::NonZeroU32;

use serde::{Serialize, Deserialize};

/// A set of bytes.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Bytes(#[serde(with="bytes")] pub Vec<u8>);

/// Key file
#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Crypto {
    /// Cipher definition
	pub cipher: Cipher,
    /// Cipher parameters
    pub cipherparams: Aes128Ctr,
    /// Cipher bytes
	pub ciphertext: Bytes,
    /// Key-derivation function
	pub kdf: Kdf,
    /// KDF params
    pub kdfparams: Pbkdf2,
    /// MAC
	pub mac: Bytes,
}

/// Cipher kind
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Cipher {
    /// AES 128 CTR
    #[serde(rename = "aes-128-ctr")]
	Aes128Ctr,
}

/// AES 128 CTR params
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Aes128Ctr {
    /// Initialisation vector
    pub iv: Bytes,
}

/// Key-Derivation function
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kdf {
    /// Password-based KDF 2
	Pbkdf2,
}

/// PBKDF2 params
#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

/// PRF
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Prf {
    /// HMAC SHA256
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

mod bytes {
    use std::fmt;

    use serde::{de, Serializer, Deserializer};

    /// Serializes a slice of bytes.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> where
        S: Serializer,
    {
        let it: String = rustc_hex::ToHex::to_hex(bytes);
        serializer.serialize_str(&it)
    }

    /// Deserialize into vector of bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error> where
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
                    return Err(E::invalid_length(v.len(), &self))
                }

                ::rustc_hex::FromHex::from_hex(&v)
                    .map_err(|e| E::custom(e.to_string()))
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
}
