use ethsign::{KeyFile, Protected};

fn main() {
    let file = std::fs::File::open("./res/wallet.json").unwrap();
    let key: KeyFile = serde_json::from_reader(file).unwrap();
    let password: Protected = "".into();
    let secret = key.to_secret_key(&password).unwrap();
    let message = [1_u8; 32];

    // Sign the message
    let signature = secret.sign(&message).unwrap();
    println!("{:?}", signature);

    // Recover the signer
    let public = signature.recover(&message).unwrap();
    println!("{:?}", public);

    #[cfg(feature = "export-private-key")]
    {
        //Do not print private key in that way in production code
        let private = secret.private();
        println!("Extracted private key: {}", hex::encode(private));
    }

    // Verify the signature
    let res = public.verify(&signature, &message).unwrap();
    println!("{}", if res { "signature correct" } else { "invalid signature" });
}
