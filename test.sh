echo ""
echo "Running with C implementation of secp256k1"
echo "=========================================="
echo ""
cargo build || exit
cargo test || exit

echo ""
echo "Running with Rust implementation of secp256k1"
echo "============================================="
echo ""
cargo build --no-default-features --features secp256k1-rs || exit
cargo test --no-default-features --features secp256k1-rs || exit
