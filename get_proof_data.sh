#!/bin/bash

# Get the L1 block number from the precompile as uint256
echo "Fetching L1 block number from Base Sepolia..."
raw_output=$(cast call 0x4200000000000000000000000000000000000015 "number()(uint256)" --rpc-url https://sepolia.base.org)
echo "Raw output from precompile: $raw_output"

#Get the L1 block hash from the precompile as bytes32
echo "Fetching L1 block hash from Base Sepolia..."
raw_output_hash=$(cast call 0x4200000000000000000000000000000000000015 "hash()(bytes32)" --rpc-url https://sepolia.base.org)
echo "Raw output from precompile: $raw_output_hash"

# Extract just the number part (before any brackets)
l1_block_number=$(echo $raw_output | cut -d '[' -f1 | tr -d ' ')
# Convert to proper hex format for RPC calls
l1_block_number_hex=$(printf "0x%x" $l1_block_number)
echo "Block number in hex format: $l1_block_number_hex"

# Get the raw header for that specific block
echo "Fetching block header..."
header=$(cast rpc debug_getRawHeader "$l1_block_number_hex" --rpc-url https://rpc.therpc.io/ethereum-sepolia)
echo "Retrieved block header"

# Get the proof for that specific block
echo "Fetching storage proof..."
proof_result=$(cast rpc eth_getProof "0xd7304aA4F048B07f75347b84746211C196Fc2bEa" '["0xc94330da5d5688c06df0ade6bfd773c87249c0b9f38b25021e2c16ab9672d000"]' "$l1_block_number_hex" --rpc-url https://rpc.therpc.io/ethereum-sepolia)
echo "Retrieved storage proof"

# Extract the specific fields from the proof
storage_value=$(echo $proof_result | jq '.storageProof[0].value')
account_proof=$(echo $proof_result | jq '.accountProof')
storage_proof=$(echo $proof_result | jq '.storageProof[0].proof')

# Create the JSON file with properly formatted data
echo "{\"blockHeader\": $header, \"storageValue\": $storage_value, \"accountProof\": $account_proof, \"storageProof\": $storage_proof, \"l1BlockNumber\": "$l1_block_number", \"l1BlockHash\": \"$raw_output_hash\"}" > proof_data.json
echo "Proof data written to proof_data.json"