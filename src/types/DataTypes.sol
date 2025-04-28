// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice Data structure for Keystore's Incremental Merkle Tree proofs
/// @dev Used to verify key data inclusion or exclusion in the keystore state
struct KeyMerkleProofData {
    /// @notice Whether this is an exclusion proof (true) or inclusion proof (false)
    bool isExclusion;
    /// @notice Extra data needed for exclusion proofs
    /// @dev Contains previous dummy byte, IMT key, salt, and value hash
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
    /// @notice Bitmap indicating whether each proof node is on the left (1) or right (0)
    uint256 isLeft;
}

/// @notice Structure of the signature data in a UserOperation
/// @dev Contained in the PackedUserOperation.signature field
struct SignatureData {
    /// @notice The merkle proof for the key data
    KeyMerkleProofData keyDataProof;
    /// @notice The actual signatures for validation
    bytes signatures;
}

/// @notice Per-account installation data for this validator
/// @dev Stored for each smart account that installs this validator
struct InstallationData {
    /// @notice Whether the validator has been initialized for this account
    bool initialized;
    /// @notice How long signatures remain valid after the state root timestamp
    uint48 invalidationTime;
    /// @notice The unique identifier for this account's keystore in the Keystore ZK rollup
    bytes32 keystoreAddress;
}
