// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @title IKeystoreCache
/// @notice Interface for the KeystoreCache contract.
interface IKeystoreCache {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when a blockhash hasn't been cached
    /// @param _blockhash The uncached blockhash
    error BlockhashNotFound(bytes32 _blockhash);

    /// @notice Error thrown when a state root hasn't been cached
    /// @param stateRoot The uncached state root
    error StateRootNotFound(bytes32 stateRoot);

    /// @notice Error thrown when a storage proof is older than an existing one
    error StorageProofTooOld();

    /// @notice Error thrown when attempting to verify an exclusion proof for storage
    error CannotVerifyExclusionProof();

    /// @notice Error thrown when storage value doesn't match expected value
    error InvalidStorageValue();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a blockhash is cached
    /// @param _blockhash The cached blockhash
    event BlockhashCached(bytes32 _blockhash);

    /*//////////////////////////////////////////////////////////////
                              PROOF STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The latest cached keystore state root
    /// @dev Updated when a newer state root is cached
    function latestKeystoreStateRoot() external view returns (bytes32);

    /// @notice Mapping from keystore state roots to their L1 block timestamps
    /// @dev Used to determine signature validity periods
    /// @param keystoreStateRoot The keystore state root
    /// @return l1BlockTimestamp The L1 block timestamp associated with the state root
    function keystoreStateRoots(bytes32 keystoreStateRoot)
        external
        view
        returns (uint256 l1BlockTimestamp);

    /// @notice Mapping of cached L1 blockhashes
    /// @param blockhash The blockhash to check
    /// @return isCached Whether the blockhash is cached
    function blockhashes(bytes32 blockhash) external view returns (bool isCached);
}
