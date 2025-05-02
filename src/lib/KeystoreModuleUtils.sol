// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Interfaces
import { IL1Block } from "@interfaces/IL1Block.sol";

// Libraries
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { RLPReader } from "@lib/vendor/RLPReader.sol";

// Types
import { KeyMerkleProofData, SignatureData, StorageProof } from "@types/DataTypes.sol";

/// @title KeystoreModuleUtils
/// @notice A library for Keystore-related operations, proof verification, and storage proof
/// verification
/// @dev Contains utilities for IMT proof processing and L1 state verification
library KeystoreModuleUtils {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Constant representing an active leaf in the IMT
    bytes1 internal constant ACTIVE_LEAF_BYTE = 0x01;

    /*//////////////////////////////////////////////////////////////
                           SIGNATURE PROCESSING
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes signature data from bytes
    /// @dev Uses assembly for efficient decoding without copying data
    /// @param signature The signature bytes to decode
    /// @return out The decoded SignatureData
    function decodeSignature(bytes calldata signature)
        internal
        pure
        returns (SignatureData calldata out)
    {
        /// @solidity memory-safe-assembly
        assembly {
            out := signature.offset
        }
    }

    /// @notice Extracts the stateless validator codehash from key data
    /// @dev The codehash is expected in the first 32 bytes
    /// @param keyData The key data to extract from
    /// @return codeHash The extracted creation code hash
    function getStatelessValidatorCodeHash(bytes calldata keyData)
        internal
        pure
        returns (bytes32 codeHash)
    {
        assembly {
            codeHash := calldataload(keyData.offset)
        }
    }

    /*//////////////////////////////////////////////////////////////
                              IMT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Parses the extra data for exclusion proofs
    /// @dev Extracts the components from packed exclusion extra data
    /// @param extraData The packed exclusion extra data
    /// @return prevDummyByte The dummy byte of the previous key
    /// @return prevImtKey The IMT key of the previous key
    /// @return salt The salt used for deriving the keystore address
    /// @return valueHash The hash of the value
    function parseExclusionExtraData(bytes calldata extraData)
        internal
        pure
        returns (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash)
    {
        /// @solidity memory-safe-assembly
        assembly {
            salt := calldataload(add(extraData.offset, 0x21))
            valueHash := calldataload(add(extraData.offset, 0x41))
            calldatacopy(0x1f, extraData.offset, 0x21)
            prevDummyByte := mload(0x1f)
            prevImtKey := mload(0x20)
        }
    }

    /// @notice Constructs an IMT leaf node
    /// @dev Formats the leaf node according to the IMT specification
    /// @param dummyByte Dummy byte for the current key
    /// @param imtKey The IMT key
    /// @param nextDummyByte Dummy byte for the next key
    /// @param nextImtKey The next IMT key
    /// @param valueHash The hash of the value
    /// @return The constructed leaf node hash
    function constructImtLeafNode(
        bytes1 dummyByte,
        bytes32 imtKey,
        bytes1 nextDummyByte,
        bytes32 nextImtKey,
        bytes32 valueHash
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                ACTIVE_LEAF_BYTE, // Should be active
                dummyByte,
                imtKey,
                nextDummyByte,
                nextImtKey,
                valueHash
            )
        );
    }

    /// @notice Processes a merkle proof against a leaf node
    /// @dev Computes the merkle root by traversing the proof path
    /// @param proof The merkle proof path
    /// @param leafNode The starting leaf node
    /// @param isLeft Bitmap indicating whether each node is on the left
    /// @return The computed merkle root
    function processMerkleProof(
        bytes32[] calldata proof,
        bytes32 leafNode,
        uint256 isLeft
    )
        internal
        pure
        returns (bytes32)
    {
        uint256 length = proof.length;
        bytes32 currentNode = leafNode;
        for (uint256 i = 0; i != length; ++i) {
            bool _isLeft = isLeft >> i & 1 == 1;
            if (_isLeft) currentNode = EfficientHashLib.hash(proof[i], currentNode);
            else currentNode = EfficientHashLib.hash(currentNode, proof[i]);
        }

        return currentNode;
    }
}
