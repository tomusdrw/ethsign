# ethsign

A library to read JSON keyfiles and sign Ethereum stuff.

Library by defaults hide private key from access,
but you can add --features export-private-key to export it.

## Usage:
```rust
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
```

A higher-level lib [`ethkey`](https://crates.io/crates/ethkey) facilitates managing key files and exposes `ethsign`: 

```toml
[dependencies]
ethkey = "0.3"
```

```rust
use ethkey::prelude::*;

fn main() {
    let key = EthAccount::load_or_generate("/tmp/path/to/keystore", "passwd")
        .expect("should load or generate new eth key");

    println!("{:?}", key.address());

    let message = [7_u8; 32];

    // sign the message
    let signature = key.sign(&message).unwrap();

    // verify the signature
    let result = key.verify(&signature, &message).unwrap();
    println!("{}", if result {"verification ok"} else {"wrong signature"});
}

