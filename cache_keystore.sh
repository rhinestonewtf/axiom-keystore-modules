#!/bin/bash

# Set up error handling
set -e
echo "Starting Keystore Cache update process..."

# Step 1: Update the blockhash first
echo "Running UpdateBlockhash script..."
forge script script/UpdateKeystoreCache.s.sol:UpdateBlockhash --rpc-url https://sepolia.base.org --broadcast -vvvvv

# Step 2: Run the get_proof_data.sh script to generate the proof data
echo "Generating proof data..."
./get_proof_data.sh

# Step 3: Run the UpdateKeystoreStateRoot script
echo "Running UpdateKeystoreStateRoot script..."
forge script script/UpdateKeystoreCache.s.sol:UpdateKeystoreStateRoot --rpc-url https://sepolia.base.org --broadcast -vvvvv

echo "Keystore Cache update process completed successfully."