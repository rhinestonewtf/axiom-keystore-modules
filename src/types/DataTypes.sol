// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice Data structure for Keystore's Incremental Merkle Tree proofs
struct KeyMerkleProofData {
    /// @notice Whether this is an exclusion proof (true) or inclusion proof (false)
    bool isExclusion;
    /// @notice Extra data for exclusion proofs
    /// @dev Contains prevDummyByte, prevImtKey, salt, valueHash
    bytes exclusionExtraData;
    /// @notice The dummy byte of the next key in the tree
    bytes1 nextDummyByte;
    /// @notice The next key in the tree
    bytes32 nextImtKey;
    /// @notice The virtual key hash used for signature verification
    bytes32 vkeyHash;
    /// @notice The key data being verified
    bytes keyData;
    /// @notice The merkle proof path
    bytes32[] proof;
    /// @notice Bitmap indicating whether each node is on the left (1) or right (0)
    uint256 isLeft;
}

/// @notice Structure of the signature data
/// @dev Used for both UserOp validation and EIP-1271 validation
struct SignatureData {
    /// @notice The merkle proof for the key data
    KeyMerkleProofData keyDataProof;
    /// @notice The actual signatures for validation
    bytes signatures;
}

/// @notice Per-account installation data for validators
struct InstallationData {
    /// @notice Whether the validator has been initialized for this account
    bool initialized;
    /// @notice How long signatures remain valid after the state root timestamp
    uint48 invalidationTime;
    /// @notice The unique identifier for this account's keystore in the Keystore system
    bytes32 keystoreAddress;
}

/// @notice Data structure for storage proofs
struct StorageProof {
    /// @notice The RLP-encoded block header
    bytes blockHeader;
    /// @notice The value at the storage slot
    bytes32 storageValue;
    /// @notice The Merkle proof for the account
    bytes[] accountProof;
    /// @notice The Merkle proof for the storage slot
    bytes[] storageProof;
}
