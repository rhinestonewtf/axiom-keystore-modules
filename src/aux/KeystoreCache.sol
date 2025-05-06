// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Interfaces
import { IL1Block } from "@interfaces/IL1Block.sol";
import { IKeystoreCache } from "@interfaces/IKeystoreCache.sol";

// Libraries
import { RLPReader } from "@lib/vendor/RLPReader.sol";
import { SecureMerkleTrie } from "@lib/vendor/SecureMerkleTrie.sol";

// Types
import { StorageProof } from "@types/DataTypes.sol";

/// @title KeystoreCache
/// @notice A contract that manages the state roots and blockhashes for the Axiom Keystore
contract KeystoreCache is IKeystoreCache {
    /*//////////////////////////////////////////////////////////////
                               IMMUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice The address of the keystore bridge contract.
    address public immutable KEYSTORE_ROLLUP;

    /// @notice The storage slot of the keystore state root.
    bytes32 public immutable KEYSTORE_STORAGE_SLOT;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The address of the L1Block predeploy contract on OP Stack chains
    /// @dev Used to fetch L1 blockhashes for verification
    address internal constant L1BLOCK = 0x4200000000000000000000000000000000000015;

    /*//////////////////////////////////////////////////////////////
                              PROOF STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The latest cached keystore state root
    /// @dev Updated when a newer state root is cached
    bytes32 public latestKeystoreStateRoot;

    /// @notice Mapping from keystore state roots to their L1 block timestamps
    /// @dev Used to determine signature validity periods
    mapping(bytes32 keystoreStateRoot => uint256 l1BlockTimestamp) public keystoreStateRoots;

    /// @notice Mapping of cached L1 blockhashes
    mapping(bytes32 blockhash => bool isCached) public blockhashes;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the contract with the keystore rollup address and storage slot
    /// @param keystoreRollup The address of the keystore rollup contract
    /// @param keystoreStorageSlot The storage slot of the keystore state root
    constructor(address keystoreRollup, bytes32 keystoreStorageSlot) {
        KEYSTORE_ROLLUP = keystoreRollup;
        KEYSTORE_STORAGE_SLOT = keystoreStorageSlot;
    }

    /*//////////////////////////////////////////////////////////////
                             STATE ROOTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Caches the current L1 blockhash
    function cacheBlockhash() external {
        // Cache the blockhash
        bytes32 _blockhash = getL1Blockhash();
        emit BlockhashCached(_blockhash);
        blockhashes[_blockhash] = true;
    }

    /// @notice Caches a keystore state root from a storage proof
    /// @param storageProof The storage proof containing the keystore state root
    function cacheKeystoreStateRoot(StorageProof calldata storageProof) external {
        // Verify the storage proof
        (bytes32 keystoreStateRoot, bytes32 _blockhash) =
            verifyStorageSlot(storageProof, KEYSTORE_ROLLUP, KEYSTORE_STORAGE_SLOT);

        // Check if the blockhash is cached
        require(blockhashes[_blockhash], BlockhashNotFound(_blockhash));

        // Extract timestamp from block header
        uint48 blockTimestamp = extractTimestampFromBlockHeader(storageProof.blockHeader);

        // We don't want to allow older storage proofs to prevent frontrunning
        uint256 currentTimestamp = keystoreStateRoots[keystoreStateRoot];
        require(blockTimestamp >= currentTimestamp, StorageProofTooOld());

        // Update the timestamp for this state root
        keystoreStateRoots[keystoreStateRoot] = blockTimestamp;

        // Update the latest state root if newer
        uint256 latestTimestamp = keystoreStateRoots[latestKeystoreStateRoot];
        if (blockTimestamp > latestTimestamp) {
            latestKeystoreStateRoot = keystoreStateRoot;
        }
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

        // Extract the timestamp field (at index 11)
        bytes memory timestampBytes = RLPReader.readBytes(headerFields[11]);

        // Convert the bytes to a uint48
        for (uint8 i; i < timestampBytes.length; i++) {
            timestamp = (timestamp << 8) | uint8(timestampBytes[i]);
        }
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
