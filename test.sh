echo ""
echo "Running with default features"
echo "============================="
echo ""
cargo build || exit
cargo test || exit

echo ""
echo "Running with pure Rust dependencies"
echo "==================================="
echo ""
cargo build --no-default-features --features pure-rust || exit
cargo test --no-default-features --features pure-rust || exit
