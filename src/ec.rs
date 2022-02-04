pub use self::secp256k1::*;

#[cfg(not(feature = "pure-rust"))]
mod secp256k1 {
    /// `secp256k1::Error`
    pub use secp256k1::Error;

    pub fn verify_secret(secret: &[u8]) -> Result<(), Error> {
        secp256k1::SecretKey::from_slice(secret)?;
        Ok(())
    }

    pub fn secret_to_public(secret: &[u8]) -> Result<[u8; 65], Error> {
        let sec = secp256k1::SecretKey::from_slice(secret)?;
        let context = secp256k1::Secp256k1::signing_only();
        let pubkey = secp256k1::PublicKey::from_secret_key(&context, &sec);

        Ok(pubkey.serialize_uncompressed())
    }

    /// Sign given 32-byte message hash with the key.
    pub fn sign(secret: &[u8], message: &[u8]) -> Result<(u8, [u8; 64]), Error> {
        let sec = secp256k1::SecretKey::from_slice(secret)?;
        let msg = secp256k1::Message::from_slice(message)?;
        let sig = secp256k1::Secp256k1::signing_only().sign_ecdsa_recoverable(&msg, &sec);

        let (rec_id, data) = sig.serialize_compact();

        Ok((rec_id.to_i32() as u8, data))
    }

    fn to_recoverable_signature(
        v: u8,
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> Result<secp256k1::ecdsa::RecoverableSignature, Error> {
        let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(v as i32)?;

        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(r);
        data[32..64].copy_from_slice(s);

        secp256k1::ecdsa::RecoverableSignature::from_compact(&data, rec_id)
    }

    /// Recover the signer of the message.
    pub fn recover(v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<[u8; 65], Error> {
        let sig = to_recoverable_signature(v, r, s)?;
        let msg = secp256k1::Message::from_slice(message)?;
        let pubkey = secp256k1::Secp256k1::verification_only().recover_ecdsa(&msg, &sig)?;

        Ok(pubkey.serialize_uncompressed())
    }

    fn to_pubkey(public: &[u8]) -> Result<secp256k1::PublicKey, Error> {
        let mut pubkey = [4u8; 65];
        pubkey[1..65].copy_from_slice(public);
        secp256k1::PublicKey::from_slice(&pubkey)
    }

    /// Checks ECDSA validity of `signature(v ,r ,s)` for `message` with `public` key.
    /// Returns `Ok(true)` on success.
    pub fn verify(public: &[u8], v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<bool, Error> {
        let sig = to_recoverable_signature(v, r, s)?.to_standard();
        let msg = secp256k1::Message::from_slice(message)?;

        match secp256k1::Secp256k1::verification_only().verify_ecdsa(&msg, &sig, &to_pubkey(public)?) {
            Ok(_) => Ok(true),
            Err(Error::IncorrectSignature) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "pure-rust")]
mod secp256k1 {
    /// `libsecp256k1::Error`
    pub use libsecp256k1::Error;

    pub fn verify_secret(secret: &[u8]) -> Result<(), Error> {
        libsecp256k1::SecretKey::parse_slice(secret)?;
        Ok(())
    }

    pub fn secret_to_public(secret: &[u8]) -> Result<[u8; 65], Error> {
        let sec = libsecp256k1::SecretKey::parse_slice(secret)?;
        let pubkey = libsecp256k1::PublicKey::from_secret_key(&sec);

        Ok(pubkey.serialize())
    }

    /// Sign given 32-byte message hash with the key.
    pub fn sign(secret: &[u8], message: &[u8]) -> Result<(u8, [u8; 64]), Error> {
        let sec = libsecp256k1::SecretKey::parse_slice(secret)?;
        let msg = libsecp256k1::Message::parse_slice(message)?;

        let (sig, rec_id) = libsecp256k1::sign(&msg, &sec);

        Ok((rec_id.serialize(), sig.serialize()))
    }

    fn to_signature(r: &[u8; 32], s: &[u8; 32]) -> Result<libsecp256k1::Signature, Error> {
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(r);
        data[32..64].copy_from_slice(s);

        Ok(libsecp256k1::Signature::parse_standard(&data)?)
    }

    /// Recover the signer of the message.
    pub fn recover(v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<[u8; 65], Error> {
        let rec_id = libsecp256k1::RecoveryId::parse(v)?;
        let sig = to_signature(r, s)?;
        let msg = libsecp256k1::Message::parse_slice(message)?;
        let pubkey = libsecp256k1::recover(&msg, &sig, &rec_id)?;

        Ok(pubkey.serialize())
    }

    fn to_pubkey(public: &[u8]) -> Result<libsecp256k1::PublicKey, Error> {
        let mut pubkey = [4u8; 65];
        pubkey[1..65].copy_from_slice(public);
        libsecp256k1::PublicKey::parse(&pubkey)
    }

    /// Checks ECDSA validity of `signature(r, s)` for `message` with `public` key.
    /// Returns `Ok(true)` on success.
    pub fn verify(public: &[u8], _v: u8, r: &[u8; 32], s: &[u8; 32], message: &[u8]) -> Result<bool, Error> {
        let sig = to_signature(r, s)?;
        let msg = libsecp256k1::Message::parse_slice(message)?;

        Ok(libsecp256k1::verify(&msg, &sig, &to_pubkey(public)?))
    }
}
