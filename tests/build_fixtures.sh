#!/bin/bash
set -e

echo "Installing wasm32-unknown-unknown target..."
rustup target add wasm32-unknown-unknown

echo "Building v1..."
cd tests/fixtures/v1
cargo build --target wasm32-unknown-unknown --release
mkdir -p ../../wasm
cp target/wasm32-unknown-unknown/release/mock_contract_v1.wasm ../../wasm/v1.wasm

echo "Building v2..."
cd ../v2
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/mock_contract_v2.wasm ../../wasm/v2.wasm

echo "Building v3..."
cd ../v3
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/mock_contract_v3.wasm ../../wasm/v3.wasm

echo "Successfully built mock contracts into tests/wasm/!"
