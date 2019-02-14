pub use self::secp256k1::*;

#[cfg(feature = "secp256k1-c")]
mod secp256k1 {
    /// Alias type for `secp256k1::Error`
    pub type Error = secp256k1::Error;

    pub fn verify_secret(secret: &[u8]) -> Result<(), Error> {
        secp256k1::SecretKey::from_slice(secret)?;
        Ok(())
    }

    pub fn secret_to_public(secret: &[u8]) -> Result<[u8; 65], Error> {
        use secp256k1::{SecretKey, PublicKey, Secp256k1};
        let sec = SecretKey::from_slice(secret)?;

        let context = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&context, &sec);
        
        Ok(pubkey.serialize_uncompressed())
    }

    /// Sign given 32-byte message hash with the key.
    pub fn sign(secret: &[u8], message: &[u8]) -> Result<(u8, [u8; 64]), Error> {
        use secp256k1::{SecretKey, Secp256k1, Message};
        let context = Secp256k1::new();

        let sec = SecretKey::from_slice(secret)?;
        let msg = Message::from_slice(message)?;
        let sig = context.sign_recoverable(&msg, &sec);

        let (rec_id, data) = sig.serialize_compact();

        Ok((rec_id.to_i32() as u8, data))
    }

    /// Recover the signer of the message.
    pub fn recover(v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<[u8; 65], Error> {
        use secp256k1::{RecoverableSignature, Message, RecoveryId, Secp256k1};

        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(r);
        data[32..64].copy_from_slice(s);

        let context = Secp256k1::new();
        let sig = RecoverableSignature::from_compact(&data, RecoveryId::from_i32(v as i32)?)?;
        let msg = Message::from_slice(message)?;
        let pubkey = context.recover(&msg, &sig)?;
        
        Ok(pubkey.serialize_uncompressed())
    }
}

#[cfg(not(feature = "secp256k1-c"))]
#[cfg(feature = "secp256k1-rs")]
mod secp256k1 {
    use std::fmt;

    /// Wrapper type around `libsecp256k1::Error`
    pub struct Error(libsecp256k1::Error);

    pub fn verify_secret(secret: &[u8]) -> Result<(), Error> {
        libsecp256k1::SecretKey::parse_slice(secret)?;
        Ok(())
    }

    pub fn secret_to_public(secret: &[u8]) -> Result<[u8; 65], Error> {
        use libsecp256k1::{SecretKey, PublicKey};
        let sec = SecretKey::parse_slice(secret)?;

        let pubkey = PublicKey::from_secret_key(&sec);
        
        Ok(pubkey.serialize())
    }

    /// Sign given 32-byte message hash with the key.
    pub fn sign(secret: &[u8], message: &[u8]) -> Result<(u8, [u8; 64]), Error> {
        use libsecp256k1::{SecretKey, Message};

        let sec = SecretKey::parse_slice(secret)?;
        let msg = Message::parse_slice(message)?;

        let (sig, rec_id) = libsecp256k1::sign(&msg, &sec)?;

        Ok((rec_id.serialize(), sig.serialize()))
    }

    /// Recover the signer of the message.
    pub fn recover(v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<[u8; 65], Error> {
        use libsecp256k1::{RecoveryId, Signature, Message};

        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(r);
        data[32..64].copy_from_slice(s);

        let rec_id = RecoveryId::parse(v)?;
        let sig = Signature::parse(&data);
        let msg = Message::parse_slice(message)?;
        let pubkey = libsecp256k1::recover(&msg, &sig, &rec_id)?;
        
        Ok(pubkey.serialize())
    }

    impl From<libsecp256k1::Error> for Error {
        fn from(err: libsecp256k1::Error) -> Error {
            Error(err)
        }
    }

    impl fmt::Debug for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, f)
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, f)
        }
    }
}
