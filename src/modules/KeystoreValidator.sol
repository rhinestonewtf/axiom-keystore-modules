// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// Contracts
import { ERC7579ValidatorBase } from "@rhinestone/modulekit/module-bases/ERC7579ValidatorBase.sol";
import { ERC7579KeystoreModuleBase } from "@contracts/ERC7579KeystoreModuleBase.sol";

// Interfaces
import { IKeystoreValidator } from "@interfaces/IKeystoreValidator.sol";
import { IStatelessValidator } from
    "@rhinestone/modulekit/module-bases/interfaces/IStatelessValidator.sol";

// Types
import { SignatureData, InstallationData } from "@types/DataTypes.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { _packValidationData as _packValidationData4337 } from
    "@rhinestone/modulekit/external/ERC4337.sol";
import { ValidationData as ValidationData4337 } from
    "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

/// @title KeystoreValidator
/// @notice A validation module for ERC-7579 smart accounts that verifies user operations
///         using Axiom Keystore's Incremental Merkle Tree (IMT) for secure key management.
/// @dev This validator integrates with Axiom's Keystore system, which is a specialized ZK rollup
///      for key management. More information can be found at https://axiom.co/
contract KeystoreValidator is
    ERC7579ValidatorBase,
    ERC7579KeystoreModuleBase,
    IKeystoreValidator
{
    /*//////////////////////////////////////////////////////////////
                          STATELESS VALIDATORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping from registered code hashes to deployed statelessValidators
    mapping(bytes32 registeredCodeHash => IStatelessValidator statelessValidator) public
        statelessValidators;

    /*//////////////////////////////////////////////////////////////
                              ACCOUNT SATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping from account addresses to their installation data
    mapping(address account => InstallationData data) public accountData;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _keystoreCache,
        bytes2 _siloingBytes
    )
        ERC7579KeystoreModuleBase(_keystoreCache, _siloingBytes)
    { }

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Called when the module is installed in a smart account
    /// @dev Sets up the validator configuration for the smart account
    function onInstall(bytes calldata data) external override {
        // Fetch stored account data
        InstallationData storage $ = accountData[msg.sender];

        // Revert if the validator is already initialized
        require(!$.initialized, AlreadyInitialized(msg.sender));

        // Decode the installation data
        (uint48 invalidationTime, bytes32 keystoreAddress) = abi.decode(data, (uint48, bytes32));

        // Setup
        $.initialized = true;
        $.invalidationTime = invalidationTime;
        $.keystoreAddress = keystoreAddress;
    }

    /// @notice Called when the module is uninstalled from a smart account
    /// @dev Cleans up the validator configuration for the smart account
    function onUninstall(bytes calldata) external override {
        // Revert if the validator is not initialized
        require(accountData[msg.sender].initialized, NotInitialized(msg.sender));

        // Delete the account data
        delete accountData[msg.sender];
    }

    /// @notice Checks if the module is initialized for a smart account
    /// @param smartAccount The address of the smart account to check
    /// @return Whether the module is initialized
    function isInitialized(address smartAccount) external view returns (bool) {
        InstallationData storage $ = accountData[smartAccount];
        return $.initialized;
    }

    /// @notice Updates the invalidation time for a smart account
    /// @param invalidationTime The new invalidation time
    function updateInvalidationTime(uint48 invalidationTime) external {
        // Fetch stored account data
        InstallationData storage $ = accountData[msg.sender];
        // Revert if the validator is not initialized
        if (!$.initialized) revert NotInitialized(msg.sender);

        // Update the invalidation time
        $.invalidationTime = invalidationTime;
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a user operation using Keystore proofs
    /// @dev Main validation logic that verifies keyData against the keystore state root
    /// @param userOp The user operation to validate
    /// @param userOpHash The hash of the user operation
    /// @return ValidationData wrapping the validity timeframe
    /// @dev The validation timeline works as follows:
    ///      - validAfter = state root timestamp (when the key was proven to exist)
    ///      - validUntil = state root timestamp + invalidation time
    ///      This creates a time window during which signatures are considered valid,
    ///      preventing both replay attacks and signature expiration.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        public
        view
        override
        returns (ValidationData)
    {
        // Decode the signature data
        SignatureData calldata data = decodeSignature(userOp.signature);

        // Hash the key data for verification
        bytes32 dataHash = keccak256(data.keyDataProof.keyData);

        // Get the account's installation data
        InstallationData storage $ = accountData[userOp.sender];

        // Process the IMT proof to get the derived root block timestamp
        uint48 blockTimestamp = processImtKeyData(data.keyDataProof, dataHash, $.keystoreAddress);

        // Get and validate the statelessValidator
        bytes32 statelessValidatorCodeHash =
            getStatelessValidatorCodeHash(data.keyDataProof.keyData);
        IStatelessValidator statelessValidator = statelessValidators[statelessValidatorCodeHash];
        require(
            address(statelessValidator) != address(0),
            UnregisteredCodeHash(statelessValidatorCodeHash)
        );

        // Let the statelessValidator verify the signature
        statelessValidator.validateSignatureWithData(
            userOpHash, data.signatures, data.keyDataProof.keyData[32:]
        );

        // Return validation data with appropriate validity timeframe
        return ValidationData.wrap(
            _packValidationData4337(
                ValidationData4337({
                    aggregator: address(0),
                    validUntil: blockTimestamp + $.invalidationTime,
                    validAfter: blockTimestamp
                })
            )
        );
    }

    /// @notice Validates a signature according to EIP-1271
    /// @param sender The address that is requesting the signature validation
    /// @param hash The hash of the data that was signed
    /// @param data The signature and associated data to validate
    /// @return magicValue Either EIP1271_SUCCESS or EIP1271_FAILED as per EIP-1271
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        override
        returns (bytes4)
    {
        // Decode the signature data
        SignatureData calldata signatureData = decodeSignature(data);

        // Hash the key data for verification
        bytes32 dataHash = keccak256(signatureData.keyDataProof.keyData);

        // Get the account's installation data
        InstallationData storage $ = accountData[sender];

        // Process the IMT proof to get the derived root block timestamp
        uint48 blockTimestamp =
            processImtKeyData(signatureData.keyDataProof, dataHash, $.keystoreAddress);

        // Get and validate the statelessValidator code hash
        bytes32 statelessValidatorCodeHash =
            getStatelessValidatorCodeHash(signatureData.keyDataProof.keyData);
        IStatelessValidator statelessValidator = statelessValidators[statelessValidatorCodeHash];

        // Check if the statelessValidator is registered
        if (address(statelessValidator) == address(0)) {
            return EIP1271_FAILED;
        }

        // Let the statelessValidator verify the signature
        bool isValid = statelessValidator.validateSignatureWithData(
            hash, signatureData.signatures, signatureData.keyDataProof.keyData[32:]
        );

        // Early return if the signature is invalid
        if (!isValid) return EIP1271_FAILED;

        // Check timestamp validity
        uint256 currentTimestamp = block.timestamp;
        if (
            blockTimestamp == 0 || currentTimestamp < blockTimestamp
                || currentTimestamp > blockTimestamp + $.invalidationTime
        ) {
            return EIP1271_FAILED;
        }

        // Signature is valid
        return EIP1271_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                          STATELESS VALIDATORS
    //////////////////////////////////////////////////////////////*/

    /// @notice registers a stateless validator
    /// @param statelessValidator The address of the stateless validator contract
    /// @param bytecodeHash The bytecode hash of the stateless validator contract
    function registerStatelessValidator(
        address statelessValidator,
        bytes32 bytecodeHash
    )
        external
    {
        // Check if the statelessValidator is already registered
        require(
            statelessValidators[bytecodeHash] == IStatelessValidator(address(0)),
            AlreadyRegistered(bytecodeHash)
        );
        // Check if the code hash matches the statelessValidator's bytecode
        require(
            statelessValidator.codehash == bytecodeHash,
            CodeHashMismatch(statelessValidator.codehash, statelessValidator)
        );
        // Register the statelessValidator
        statelessValidators[bytecodeHash] = IStatelessValidator(statelessValidator);
        // Emit an event for the registration
        emit StatelessValidatorRegistered(bytecodeHash, address(statelessValidator));
    }

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
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the module is of a specific type
    /// @param moduleTypeId The module type ID to check against
    /// @return true if the module is of the given type
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == TYPE_VALIDATOR;
    }

    /// @notice Returns the name of the module
    function name() external pure returns (string memory) {
        return "KeystoreValidator";
    }

    /// @notice Returns the version of the module
    function version() external pure returns (string memory) {
        return "0.0.1";
    }
}
