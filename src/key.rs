use std::fmt;

use crate::{crypto::Keccak256, ec, error::Error, keyfile::Crypto, protected::Protected};
use rustc_hex::ToHex;

/// Message signature
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// V value
    pub v: u8,
    /// R value
    pub r: [u8; 32],
    /// S value
    pub s: [u8; 32],
}

impl fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Signature")
            .field("v", &self.v)
            .field("r", &ToHex::to_hex::<String>(&self.r[..]))
            .field("s", &ToHex::to_hex::<String>(&self.s[..]))
            .finish()
    }
}

impl Signature {
    /// Recover the signer of the message.
    pub fn recover(&self, message: &[u8]) -> Result<PublicKey, ec::Error> {
        let uncompressed = ec::recover(self.v, &self.r, &self.s, message)?;

        Ok(PublicKey::from_slice(&uncompressed[1..]).expect("The length is correct; qed"))
    }
}

/// Represents public part of the Ethereum key.
#[derive(Clone)]
pub struct PublicKey {
    public: [u8; 64],
    address: [u8; 20],
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("PublicKey")
            .field("address", &ToHex::to_hex::<String>(&self.address[..]))
            .field("public", &ToHex::to_hex::<String>(&self.public[..]))
            .finish()
    }
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
        address.copy_from_slice(&(&public[..]).keccak256()[12..]);

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

    /// Checks ECDSA validity of `signature` for `message` with this public key.
    /// Returns `Ok(true)` on success.
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> Result<bool, ec::Error> {
        ec::verify(&self.public, signature.v, &signature.r, &signature.s, message)
    }
}

/// Represents the private part of the Ethereum key
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// Valid secret (make sure to validate through secp256k1)
    secret: Protected,
}

impl SecretKey {
    /// Convert a raw bytes secret into Key
    pub fn from_raw(slice: &[u8]) -> Result<Self, ec::Error> {
        // verify correctness
        ec::verify_secret(slice)?;

        Ok(Self {
            secret: Protected::new(slice.to_vec()),
        })
    }

    /// Convert a keyfile crypto into Ethereum Key
    pub fn from_crypto(crypto: &Crypto, password: &Protected) -> Result<Self, Error> {
        let plain = crypto.decrypt(password)?;

        Self::from_raw(&plain).map_err(Error::Secp256k1)
    }

    /// Encrypt this secret key into Crypto object.
    pub fn to_crypto(&self, password: &Protected, iterations: u32) -> Result<Crypto, Error> {
        Crypto::encrypt(self.secret.as_ref(), password, iterations)
    }

    /// Public key
    pub fn public(&self) -> PublicKey {
        let uncompressed =
            ec::secret_to_public(self.secret.as_ref()).expect("The key is validated in the constructor; qed");

        PublicKey::from_slice(&uncompressed[1..]).expect("The length of the key is correct; qed")
    }

    /// Sign given 32-byte message with the key.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, ec::Error> {
        let (v, data) = ec::sign(self.secret.as_ref(), message)?;

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
    use crate::keyfile::KeyFile;
    use rustc_hex::{FromHex, ToHex};

    #[test]
    fn should_read_pbkdf_keyfile() {
        let keyfile: KeyFile = serde_json::from_str(include_str!("../res/wallet.json")).unwrap();
        let password = b"";
        let key = SecretKey::from_crypto(&keyfile.crypto, &Protected::new(password.to_vec())).unwrap();
        let pub_key = key.public();

        assert_eq!(
            pub_key.address().to_hex::<String>(),
            "005b3bcf82085eededd551f50de7892471ffb272"
        );
        assert_eq!(&pub_key.bytes().to_hex::<String>(), "782cc7dd72426893ae0d71477e41c41b03249a2b72e78eefcfe0baa9df604a8f979ab94cd23d872dac7bfa8d07d8b76b26efcbede7079f1c5cacd88fe9858f6e");
    }

    #[test]
    fn should_read_scrypt_keyfile() {
        let keyfile: KeyFile = serde_json::from_str(include_str!("../res/scrypt-wallet.json")).unwrap();
        let password = b"geth";
        let key = SecretKey::from_crypto(&keyfile.crypto, &Protected::new(password.to_vec())).unwrap();
        let pub_key = key.public();

        assert_eq!(
            pub_key.address().to_hex::<String>(),
            "8e049da484e853d92d118be16377ff616275d470"
        );
        assert_eq!(&pub_key.bytes().to_hex::<String>(), "e54553168b429c0407c5e4338f0a61fa7a515ff382ada9f323e313353c1904b0d8039f99e213778ba479196ef24c838e41dc77215c41895fe15e4de018d7d1dd");
    }

    #[test]
    fn should_derive_public_and_address_correctly() {
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();

        let pub_key = key.public();

        assert_eq!(&pub_key.bytes().to_hex::<String>(), "3fa8c08c65a83f6b4ea3e04e1cc70cbe3cd391499e3e05ab7dedf28aff9afc538200ff93e3f2b2cb5029f03c7ebee820d63a4c5a9541c83acebe293f54cacf0e");
        assert_eq!(
            pub_key.address().to_hex::<String>(),
            "00a329c0648769a73afac7f9381e08fb43dbea72"
        );
    }

    #[test]
    fn should_have_debug_impl() {
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();
        let pub_key = key.public();
        let signature = key.sign(&secret).unwrap();

        assert_eq!(format!("{:?}", key), "SecretKey { secret: Protected(77..183) }");
        assert_eq!(format!("{:?}", pub_key), "PublicKey { address: \"00a329c0648769a73afac7f9381e08fb43dbea72\", public: \"3fa8c08c65a83f6b4ea3e04e1cc70cbe3cd391499e3e05ab7dedf28aff9afc538200ff93e3f2b2cb5029f03c7ebee820d63a4c5a9541c83acebe293f54cacf0e\" }");
        assert_eq!(format!("{:?}", signature), "Signature { v: 0, r: \"8a4f2d73a2cc80cdfe27c6e3ab68de7913865a5968298731bee7b4673752fd76\", s: \"77c9027a03e635b730b3e3e593f968d0ef7cad1848cf0293be9d7aba56c71859\" }");
    }

    #[test]
    fn should_recover_succesfuly() {
        let v = 0u8;
        let r2: Vec<u8> = "319a63079d7cdd4e1ec99996f840253c1b0e41a4caf474602c43e83b5a8de183"
            .from_hex()
            .unwrap();
        let s2: Vec<u8> = "2e9424ac2ba94abc12a79349888545f26958c2fccc28d91f6dee72ab9c069738"
            .from_hex()
            .unwrap();
        let mut s = [0u8; 32];
        s.copy_from_slice(&s2);
        let mut r = [0u8; 32];
        r.copy_from_slice(&r2);

        let signature = Signature { v, s, r };
        let message: Vec<u8> = "044a19199dc40e61210715bea94bcb0fff4c8dfa1c20988ab7783fc82c802a9f"
            .from_hex()
            .unwrap();

        let pub_key = signature.recover(&message).unwrap();
        assert_eq!(format!("{:?}", pub_key), "PublicKey { address: \"00af8b5cc1f8d0e862b4f303c0fa59b3709c2bb3\", public: \"929acaa0a4a4246225162496cc18e50719bb057519a150a94cfef77ae5e0dd50786c54cfe05f564d2ef09aae0b587bf73b83f45636def775bbf9010dded0e235\" }");
    }

    #[test]
    fn should_convert_to_crypto_and_back() {
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();

        let pass = "hunter2".into();
        let crypto = key.to_crypto(&pass, 4096).unwrap();
        let key2 = SecretKey::from_crypto(&crypto, &pass).unwrap();

        assert_eq!(key.public().bytes().as_ref(), key2.public().bytes().as_ref());
    }

    #[test]
    fn test_sign_verify() {
        // given
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();
        let message: Vec<u8> = "12da94d92a71f7692013002513e5bc4a3180344cfe3292e2b54c15f9d4421965"
            .from_hex()
            .unwrap();

        // when
        let sig = key.sign(&message).unwrap();

        // then
        assert!(key.public().verify(&sig, &message).unwrap());
    }

    #[test]
    fn test_sign_verify_fail_for_other_key() {
        // given
        let secret: Vec<u8> = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_raw(&secret).unwrap();
        let other_secret: Vec<u8> = "2222222222222222222222222222222222222222222222222222222222222222"
            .from_hex()
            .unwrap();
        let other_key = SecretKey::from_raw(&other_secret).unwrap();
        let message: Vec<u8> = "12da94d92a71f7692013002513e5bc4a3180344cfe3292e2b54c15f9d4421965"
            .from_hex()
            .unwrap();

        // when
        let sig = key.sign(&message).unwrap();

        // then
        assert!(key.public().verify(&sig, &message).unwrap());
        assert!(!other_key.public().verify(&sig, &message).unwrap());
    }
}
