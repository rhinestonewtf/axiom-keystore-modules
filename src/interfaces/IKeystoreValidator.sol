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

    /// @notice Error thrown for unsupported operations
    error UnsupportedOperation();

    /// @notice Error thrown when trying to register an already registered codeHash
    /// @param codeHash The already registered codeHash
    error AlreadyRegistered(bytes32 codeHash);

    /// @notice Error thrown when using an unregistered codeHash
    /// @param codeHash The unregistered codeHash
    error UnregisteredCodeHash(bytes32 codeHash);

    /// @notice Error thrown when a state root hasn't been cached
    /// @param stateRoot The uncached state root
    error StateRootNotFound(bytes32 stateRoot);

    /// @notice Error thrown whe the stateless validator code hash is different from the one
    ///         registered
    /// @param codeHash The expected code hash
    /// @param statelessValidator The address of the deployed stateless validator
    error CodeHashMismatch(bytes32 codeHash, address statelessValidator);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a stateless validator is registered
    /// @param codeHash The code hash of the stateless validator
    /// @param statelessValidator The address of the deployed stateless validator
    event StatelessValidatorRegistered(bytes32 codeHash, address statelessValidator);
}
