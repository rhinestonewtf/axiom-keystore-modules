// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Interfaces
import { IL1Block } from "@interfaces/IL1Block.sol";

// Libraries
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { RLPReader } from "@lib/vendor/RLPReader.sol";
import { SecureMerkleTrie } from "@lib/vendor/SecureMerkleTrie.sol";

// Types
import { KeyMerkleProofData, SignatureData, StorageProof } from "@types/DataTypes.sol";

/// @title KeystoreUtils
/// @notice A library for Keystore-related operations, proof verification, and storage proof
/// verification
/// @dev Contains utilities for IMT proof processing and L1 state verification
library KeystoreUtils {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when the keystore address doesn't match
    error InvalidKeystoreAddress();

    /// @notice Error thrown when a proof claiming to be an exclusion proof isn't valid
    error NotAnExclusionProof();

    /// @notice Error thrown when block header is invalid
    error InvalidBlockHeader();

    /// @notice Error thrown when storage value doesn't match expected value
    error InvalidStorageValue();

    /// @notice Error thrown when block number is invalid
    error InvalidBlockNumber();

    /// @notice Error thrown when attempting to verify an exclusion proof for storage
    error CannotVerifyExclusionProof();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Constant representing a non-dummy byte in the IMT
    bytes1 internal constant NON_DUMMY_BYTE = 0x01;

    /// @notice Constant representing an active leaf in the IMT
    bytes1 internal constant ACTIVE_LEAF_BYTE = 0x01;

    /// @notice Siloing bytes used to namespace keystore addresses
    /// @dev Used to isolate different key-value mappings in a single IMT.
    ///      When storing [original_key, original_value] in the IMT, we compute:
    ///      key = keccak256(concat([silo_bytes, original_key]))
    ///      This creates a namespace for keys, preventing conflicts between different
    ///      applications or systems using the same IMT structure.
    bytes2 internal constant SILOING_BYTES = bytes2(0x7579);

    /// @notice The address of the L1Block predeploy contract on OP Stack chains
    /// @dev Used to fetch L1 blockhashes for verification
    address internal constant L1BLOCK = 0x4200000000000000000000000000000000000015;

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
        pure
        returns (bytes32)
    {
        bytes32 leafNode;
        if (keyDataProof.isExclusion) {
            // Handle exclusion proof
            (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash) =
                parseExclusionExtraData(keyDataProof.exclusionExtraData);

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
            leafNode = constructImtLeafNode({
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
            leafNode = constructImtLeafNode({
                dummyByte: NON_DUMMY_BYTE,
                imtKey: imtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        }

        // Process the merkle proof to derive the root
        return processMerkleProof(keyDataProof.proof, leafNode, keyDataProof.isLeft);
    }

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

    /*//////////////////////////////////////////////////////////////
                            L1 BLOCK OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fetches the current L1 blockhash using the L1Block precompile
    /// @return blockHash The current L1 blockhash
    function getL1Blockhash() internal returns (bytes32 blockHash) {
        bytes4 hashSelector = IL1Block.hash.selector;

        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, hashSelector)
            if iszero(call(gas(), L1BLOCK, 0, 0x00, 0x20, 0x00, 0x20)) { revert(0, 0) }
            blockHash := mload(0x00)
        }
    }

    /// @notice Extracts the timestamp from an RLP encoded block header
    /// @dev Uses Optimism's RLPReader library to properly decode the RLP-encoded block header
    /// @param blockHeader The RLP encoded block header
    /// @return timestamp The block timestamp as a uint48
    function extractTimestampFromBlockHeader(bytes calldata blockHeader)
        internal
        pure
        returns (uint48 timestamp)
    {
        // First, convert the bytes to an RLP item
        RLPReader.RLPItem memory item = RLPReader.toRLPItem(blockHeader);

        // The block header is a list, so we decode it into a list of items
        RLPReader.RLPItem[] memory headerFields = RLPReader.readList(item);

        // Extract the timestamp field
        timestamp = uint48(uint256(bytes32(RLPReader.readBytes(headerFields[11]))));
    }

    /*//////////////////////////////////////////////////////////////
                           STORAGE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies a storage slot value against a storage proof
    /// @param storageProof The storage proof to verify
    /// @param _address The address of the contract to verify
    /// @param storageSlot The storage slot to verify
    /// @return storageValue The verified storage value
    /// @return _blockhash The blockhash of the block containing the proof
    function verifyStorageSlot(
        StorageProof calldata storageProof,
        address _address,
        bytes32 storageSlot
    )
        internal
        pure
        returns (bytes32 storageValue, bytes32 _blockhash)
    {
        // Verify the storage slot
        _verifyStorageSlot(
            _address,
            storageSlot,
            storageProof.storageValue,
            storageProof.blockHeader,
            storageProof.accountProof,
            storageProof.storageProof
        );

        // Return the storage value and blockhash
        return (storageProof.storageValue, keccak256(storageProof.blockHeader));
    }

    /// @notice Internal function to verify a storage slot value
    /// @dev Verifies the account proof and storage proof against the state root
    /// @param _address The address of the contract to verify
    /// @param storageSlot The storage slot to verify
    /// @param storageValue The expected storage value
    /// @param blockHeader The RLP encoded block header
    /// @param accountProof The account proof
    /// @param storageProof The storage proof
    function _verifyStorageSlot(
        address _address,
        bytes32 storageSlot,
        bytes32 storageValue,
        bytes calldata blockHeader,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    )
        internal
        pure
    {
        // Cannot verify exclusion proofs (zero values)
        require(storageValue != bytes32(0), CannotVerifyExclusionProof());

        // Decode the block header and extract the state root
        RLPReader.RLPItem[] memory blockHeaderRlp = RLPReader.readList(blockHeader);
        // stateRoot is at index 3 in the block header
        bytes32 stateRoot = bytes32(RLPReader.readBytes(blockHeaderRlp[3]));

        // Verify the account against the state root
        bytes memory account =
            SecureMerkleTrie.get(abi.encodePacked(_address), accountProof, stateRoot);
        RLPReader.RLPItem[] memory accountRlp = RLPReader.readList(account);
        bytes32 storageRoot = bytes32(RLPReader.readBytes(accountRlp[2]));

        // Verify the storage value against the storage root
        bytes memory rlpSlotValue =
            SecureMerkleTrie.get(abi.encodePacked(storageSlot), storageProof, storageRoot);
        bytes memory bytesSlotValue = RLPReader.readBytes(rlpSlotValue);

        // We need to add padding to the slot value since they are encoded as uint256
        bytes32 provenStorageValue =
            bytes32(uint256(bytes32(bytesSlotValue)) >> (8 * (32 - bytesSlotValue.length)));

        // Verify the storage value matches the expected value
        require(provenStorageValue == storageValue, InvalidStorageValue());
    }
}
