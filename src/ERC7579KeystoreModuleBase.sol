// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Contracts
import { ERC7579ModuleBase } from "@rhinestone/modulekit/module-bases/ERC7579ModuleBase.sol";

// Interfaces
import { IKeystoreCache } from "@interfaces/IKeystoreCache.sol";

// Libraries
import { KeystoreModuleUtils } from "@lib/KeystoreModuleUtils.sol";

// Types
import {
    SignatureData, InstallationData, StorageProof, KeyMerkleProofData
} from "@types/DataTypes.sol";

/// @title ERC7579KeystoreModuleBase
/// @notice Base implementation for ERC-7579 modules that use
///         the Axiom Keystore as a cross-chain source of truth
/// @dev Extends ERC7579ModuleBase with Keystore-specific functionality for shared state
abstract contract ERC7579KeystoreModuleBase is ERC7579ModuleBase {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using KeystoreModuleUtils for *;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when the keystore address doesn't match
    error InvalidKeystoreAddress();

    /// @notice Error thrown when a proof claiming to be an exclusion proof isn't valid
    error NotAnExclusionProof();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Constant representing a non-dummy byte in the IMT
    bytes1 internal constant NON_DUMMY_BYTE = 0x01;

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice The address of the Keystore cache contract that manages state roots and blockhashes
    IKeystoreCache public immutable KEYSTORE_CACHE;

    /// @notice Siloing bytes used to namespace keystore addresses
    /// @dev Used to isolate different key-value mappings in a single IMT.
    ///      When storing [original_key, original_value] in the IMT, we compute:
    ///      key = keccak256(concat([silo_bytes, original_key]))
    ///      This creates a namespace for keys, preventing conflicts between different
    ///      applications or systems using the same IMT structure.
    bytes2 internal immutable SILOING_BYTES;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _keystoreCache, bytes2 _siloingBytes) {
        KEYSTORE_CACHE = IKeystoreCache(_keystoreCache);
        SILOING_BYTES = _siloingBytes;
    }

    /*//////////////////////////////////////////////////////////////
                              IMT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Processes key data and its proof against the IMT
    /// @dev Handles both inclusion and exclusion proofs
    /// @param keyDataProof The proof for the key data
    /// @param dataHash The hash of the key data
    /// @param keystoreAddress The keystore address from the account's installation data
    /// @return The derived IMT root, which should match a cached state root
    function processImtKeyData(
        KeyMerkleProofData calldata keyDataProof,
        bytes32 dataHash,
        bytes32 keystoreAddress
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 leafNode;
        if (keyDataProof.isExclusion) {
            // Handle exclusion proof
            (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash) =
                keyDataProof.exclusionExtraData.parseExclusionExtraData();

            // Derive and verify the keystore address
            bytes32 derivedKeystoreAddress =
                keccak256(abi.encodePacked(salt, dataHash, keyDataProof.vkeyHash));
            require(keystoreAddress == derivedKeystoreAddress, InvalidKeystoreAddress());

            // Construct the IMT key
            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, derivedKeystoreAddress));

            // Verify the exclusion proof is valid
            if (
                !(imtKey > prevImtKey || prevDummyByte == 0x00)
                    && !(imtKey < keyDataProof.nextImtKey || keyDataProof.nextDummyByte == 0x00)
            ) revert NotAnExclusionProof();

            // Construct the leaf node for verification
            leafNode = KeystoreModuleUtils.constructImtLeafNode({
                dummyByte: prevDummyByte,
                imtKey: prevImtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        } else {
            // Handle inclusion proof
            bytes32 valueHash = keccak256(abi.encodePacked(dataHash, keyDataProof.vkeyHash));
            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, keystoreAddress));

            // Construct the leaf node for verification
            leafNode = KeystoreModuleUtils.constructImtLeafNode({
                dummyByte: NON_DUMMY_BYTE,
                imtKey: imtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        }

        // Process the merkle proof to derive the root
        return keyDataProof.proof.processMerkleProof(leafNode, keyDataProof.isLeft);
    }
}
