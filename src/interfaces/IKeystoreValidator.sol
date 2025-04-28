// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @title IKeystoreValidator
/// @notice Interface for the KeystoreValidator contract.
/// @dev This interface defines the functions and events for the KeystoreValidator contract
interface IKeystoreValidator {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when trying to initialize an already initialized smart account
    /// @param smartAccount The address of the smart account
    error AlreadyInitialized(address smartAccount);

    /// @notice Error thrown when a blockhash hasn't been cached
    /// @param _blockhash The uncached blockhash
    error BlockhashNotFound(bytes32 _blockhash);

    /// @notice Error thrown when a state root hasn't been cached
    /// @param stateRoot The uncached state root
    error StateRootNotFound(bytes32 stateRoot);

    /// @notice Error thrown for unsupported operations
    error UnsupportedOperation();

    /// @notice Error thrown when trying to register an already registered codeHash
    /// @param codeHash The already registered codeHash
    error AlreadyRegistered(bytes32 codeHash);

    /// @notice Error thrown when using an unregistered codeHash
    /// @param codeHash The unregistered codeHash
    error UnregisteredCodeHash(bytes32 codeHash);

    /// @notice Error thrown when a storage proof is older than an existing one
    error StorageProofTooOld();

    /// @notice Error thrown whe the consumer code hash is different from the one registered
    /// @param codeHash The expected code hash
    /// @param consumer The address of the deployed consumer
    error CodeHashMismatch(bytes32 codeHash, address consumer);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a blockhash is cached
    /// @param _blockhash The cached blockhash
    event BlockhashCached(bytes32 _blockhash);

    /// @notice Emitted when a key data consumer is registered
    /// @param codeHash The code hash of the consumer
    /// @param consumer The address of the deployed consumer
    event ConsumerRegistered(bytes32 codeHash, address consumer);
}
