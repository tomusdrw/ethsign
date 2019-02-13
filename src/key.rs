use crate::keyfile::KeyFile;
use crate::protected::Protected;
use parity_crypto::Keccak256;

/// Message signature
#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    /// V value
    pub v: u8,
    /// R value
    pub r: [u8; 32],
    /// S value
    pub s: [u8; 32],
}

impl Signature {
    /// Recover the signer of the message.
    pub fn recover(&self, message: &[u8]) -> Result<PublicKey, secp256k1::Error> {
        use secp256k1::{RecoverableSignature, Message, RecoveryId, Secp256k1};
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(&self.r);
        data[32..64].copy_from_slice(&self.s);

        let context = Secp256k1::new();
        let sig = RecoverableSignature::from_compact(&data, RecoveryId::from_i32(self.v as i32)?)?;
        let pubkey = context.recover(&Message::from_slice(message)?, &sig)?;
        let public = pubkey.serialize_uncompressed();

        Ok(PublicKey::from_slice(&public).expect("The length is correct; qed"))
    }
}

/// Represents public part of the Ethereum key.
#[derive(Debug)]
pub struct PublicKey {
    public: [u8; 64],
    address: [u8; 20],
}

impl PublicKey {
    /// Create a public key from given slice of 65 bytes.
    ///
    /// Returns an error if the length does not match.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ()> {
        if slice.len() != 64 {
            return Err(());
        }

        let mut public = [0u8; 64];
        public.copy_from_slice(slice);

        let mut address = [0u8; 20];
        address.copy_from_slice(&parity_crypto::Keccak256::keccak256(&&public[..])[12..]);

        Ok(Self { public, address })
    }

    /// Returns public key bytes.
    pub fn bytes(&self) -> &[u8; 64] {
        &self.public
    }

    /// Returns the ethereum address associated with this public key.
    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }
}

/// Represents the private part of the Ethereum key
#[derive(Debug)]
pub struct SecretKey {
    /// Valid secret (make sure to validate through secp256k1)
    secret: Protected,
}

/// Key error
#[derive(Debug)]
pub enum Error {
    /// Invalid password for the keyfile
    InvalidPassword,
    /// Crypto error
    Crypto(parity_crypto::Error),
    /// Secp256k1 error
    Secp256k1(secp256k1::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::InvalidPassword => write!(fmt, "Invalid Password"),
            Error::Crypto(ref e) => write!(fmt, "Crypto: {}", e),
            Error::Secp256k1(ref e) => write!(fmt, "Secp256k1: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl SecretKey {
    /// Convert a raw bytes secret into Key
    pub fn from_raw(slice: &[u8]) -> Result<Self, secp256k1::Error> {
        // verify correctness
        secp256k1::SecretKey::from_slice(slice)?;

        Ok(Self {
            secret: Protected(slice.to_vec()),
        })
    }

    /// Convert a keyfile into Ethereum Key
    pub fn from_keyfile(keyfile: KeyFile, password: &Protected) -> Result<Self, Error> {
        let crypto = keyfile.crypto;
        let (left_bits, right_bits) = parity_crypto::derive_key_iterations(
            &password.0,
            &crypto.kdfparams.salt.0,
            crypto.kdfparams.c,
        );

		let mac = parity_crypto::derive_mac(&right_bits, &crypto.ciphertext.0).keccak256();

		if !parity_crypto::is_equal(&mac, &crypto.mac.0) {
			return Err(Error::InvalidPassword);
		}

        let mut plain = Vec::new();
        plain.resize(crypto.ciphertext.0.len(), 0);
        parity_crypto::aes::decrypt_128_ctr(
            &left_bits,
            &crypto.cipherparams.iv.0,
            &crypto.ciphertext.0,
            &mut plain,
        ).map_err(parity_crypto::Error::from).map_err(Error::Crypto)?;

        Self::from_raw(&plain).map_err(Error::Secp256k1)
    }

    /// Public key
    pub fn public(&self) -> PublicKey {
        use secp256k1::{SecretKey, Secp256k1};
        let sec = SecretKey::from_slice(&self.secret.0)
            .expect("The key is validated in the constructor; qed");

        let context = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&context, &sec);
        
        PublicKey::from_slice(&pubkey.serialize_uncompressed()[1..])
            .expect("The length of the key is correct; qed")
    }

    /// Sign given 32-byte message with the key.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, secp256k1::Error> {
        use secp256k1::{SecretKey, Secp256k1, Message};
        let context = Secp256k1::new();
        let sec = SecretKey::from_slice(&self.secret.0)?;
        let sig = context.sign_recoverable(&Message::from_slice(message)?, &sec);
        let (rec_id, data) = sig.serialize_compact();
        let v = rec_id.to_i32() as u8;
        let mut r = [0u8; 32];
        r.copy_from_slice(&data[0..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&data[32..64]);

        Ok(Signature { v, r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::{FromHex, ToHex};

    #[test]
    fn should_read_keyfile() {
        let keyfile: KeyFile = serde_json::from_str(include_str!("../res/wallet.json")).unwrap();
        let password = b"";
        let key = SecretKey::from_keyfile(keyfile, &Protected(password.to_vec())).unwrap();
        let pub_key = key.public();

        assert_eq!(pub_key.address().to_hex::<String>(), "005b3bcf82085eededd551f50de7892471ffb272");
        assert_eq!(&pub_key.bytes().to_hex::<String>(), "782cc7dd72426893ae0d71477e41c41b03249a2b72e78eefcfe0baa9df604a8f979ab94cd23d872dac7bfa8d07d8b76b26efcbede7079f1c5cacd88fe9858f6e");
    }

    #[test]
    fn should_derive_public_and_address_correctly() {
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7".from_hex().unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();

        let pub_key = key.public();

        assert_eq!(&pub_key.bytes().to_hex::<String>(), "3fa8c08c65a83f6b4ea3e04e1cc70cbe3cd391499e3e05ab7dedf28aff9afc538200ff93e3f2b2cb5029f03c7ebee820d63a4c5a9541c83acebe293f54cacf0e");
        assert_eq!(pub_key.address().to_hex::<String>(), "00a329c0648769a73afac7f9381e08fb43dbea72");
    }
}
