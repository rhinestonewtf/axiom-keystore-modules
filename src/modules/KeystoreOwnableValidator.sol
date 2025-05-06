// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ERC7579KeystoreModuleBase } from "@contracts/ERC7579KeystoreModuleBase.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { SentinelList4337Lib, SENTINEL } from "sentinellist/SentinelList4337.sol";
import { LibSort } from "@solady/utils/LibSort.sol";
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "@solady/utils/ECDSA.sol";
import { SignatureData, InstallationData } from "@types/DataTypes.sol";
import { _packValidationData as _packValidationData4337 } from
    "@rhinestone/modulekit/external/ERC4337.sol";
import { ValidationData as ValidationData4337 } from
    "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

uint256 constant TYPE_STATELESS_VALIDATOR = 7;

contract KeystoreOwnableValidator is ERC7579ValidatorBase, ERC7579KeystoreModuleBase {
    using LibSort for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    event ModuleInitialized(address indexed account);
    event ModuleUninitialized(address indexed account);
    event ThresholdSet(address indexed account, uint256 threshold);
    event OwnerAdded(address indexed account, address owner);
    event OwnerRemoved(address indexed account, address owner);

    error ThresholdNotSet();
    error InvalidThreshold();
    error NotSortedAndUnique();
    error MaxOwnersReached();
    error InvalidOwner(address owner);
    error CannotRemoveOwner();
    error InvalidOwnerCount();

    // maximum number of owners per account
    uint256 constant MAX_OWNERS = 32;

    // Signature modes
    bytes1 constant SIGNATURE_MODE_SKIP_KEYSTORE = 0x00;
    bytes1 constant SIGNATURE_MODE_USE_KEYSTORE_PROOF = 0x01;
    bytes1 constant SIGNATURE_MODE_USE_AND_CACHE_KEYSTORE_STATE = 0x02;

    // account => owners
    SentinelList4337Lib.SentinelList owners;
    // account => threshold
    mapping(address account => uint256) public threshold;
    // account => ownerCount
    mapping(address => uint256) public ownerCount;
    // account => installation data
    mapping(address => InstallationData) public keystoreData;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONSTRUCTOR
    //////////////////////////////////////////////////////////////////////////*/

    constructor(
        address _keystoreCache,
        bytes2 _siloingBytes
    )
        ERC7579KeystoreModuleBase(_keystoreCache, _siloingBytes)
    { }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initializes the module with the threshold and owners
     * @dev data is encoded as follows: abi.encode(threshold, owners)
     *
     * @param data encoded data containing the threshold and owners
     */
    function onInstall(bytes calldata data) external override {
        // decode the threshold, owners and keystore address from the data
        (
            uint256 _threshold,
            address[] memory _owners,
            bytes32 _keystoreAddress,
            uint48 _invalidationTime
        ) = abi.decode(data, (uint256, address[], bytes32, uint48));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            revert NotSortedAndUnique();
        }

        // make sure the threshold is set
        if (_threshold == 0) {
            revert ThresholdNotSet();
        }

        // make sure the threshold is less than the number of owners
        uint256 ownersLength = _owners.length;
        if (ownersLength < _threshold) {
            revert InvalidThreshold();
        }

        // cache the account address
        address account = msg.sender;

        // set threshold
        threshold[account] = _threshold;

        // check if max owners is reached
        if (ownersLength > MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // set owner count
        ownerCount[account] = ownersLength;

        // initialize the owner list
        owners.init(account);

        // add owners to the list
        for (uint256 i = 0; i < ownersLength; i++) {
            address _owner = _owners[i];
            if (_owner == address(0)) {
                revert InvalidOwner(_owner);
            }
            owners.push(account, _owner);
        }

        // set the keystore data
        keystoreData[account] = InstallationData({
            initialized: _keystoreAddress != bytes32(0) && _invalidationTime != 0,
            invalidationTime: _invalidationTime,
            keystoreAddress: _keystoreAddress
        });

        emit ModuleInitialized(account);
    }

    /**
     * Handles the uninstallation of the module and clears the threshold and owners
     * @dev the data parameter is not used
     */
    function onUninstall(bytes calldata) external override {
        // cache the account address
        address account = msg.sender;

        // clear the owners
        owners.popAll(account);

        // remove the threshold
        threshold[account] = 0;

        // remove the owner count
        ownerCount[account] = 0;

        // remove the keystore data
        delete keystoreData[account];

        emit ModuleUninitialized(account);
    }

    /**
     * Checks if the module is initialized
     *
     * @param smartAccount address of the smart account
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) public view returns (bool) {
        return threshold[smartAccount] != 0;
    }

    /**
     * Checks if the keystore data is initialized
     *
     * @param smartAccount address of the smart account
     * @return true if the keystore data is initialized, false otherwise
     */
    function isKeystoreDataInitialized(address smartAccount) public view returns (bool) {
        return keystoreData[smartAccount].initialized;
    }

    /**
     * Sets the threshold for the account
     * @dev the function will revert if the module is not initialized
     *
     * @param _threshold uint256 threshold to set
     */
    function setThreshold(uint256 _threshold) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // make sure that the threshold is set
        if (_threshold == 0) {
            revert InvalidThreshold();
        }

        // make sure the threshold is less than the number of owners
        if (ownerCount[account] < _threshold) {
            revert InvalidThreshold();
        }

        // set the threshold
        threshold[account] = _threshold;

        emit ThresholdSet(account, _threshold);
    }

    /**
     * Adds an owner to the account
     * @dev will revert if the owner is already added
     *
     * @param owner address of the owner to add
     */
    function addOwner(address owner) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // revert if the owner is address(0)
        if (owner == address(0)) {
            revert InvalidOwner(owner);
        }

        // check if max owners is reached
        if (ownerCount[account] >= MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // increment the owner count
        ownerCount[account]++;

        // add the owner to the linked list
        owners.push(account, owner);

        emit OwnerAdded(account, owner);
    }

    /**
     * Removes an owner from the account
     * @dev will revert if the owner is not added or the previous owner is invalid
     *
     * @param prevOwner address of the previous owner
     * @param owner address of the owner to remove
     */
    function removeOwner(address prevOwner, address owner) external {
        // cache the account address
        address account = msg.sender;

        // check if an owner can be removed
        if (ownerCount[account] == threshold[account]) {
            // if the owner count is equal to the threshold, revert
            // this means that removing an owner would make the threshold unreachable
            revert CannotRemoveOwner();
        }

        // remove the owner
        owners.pop(account, prevOwner, owner);

        // decrement the owner count
        ownerCount[account]--;

        emit OwnerRemoved(account, owner);
    }

    /**
     * Returns the owners of the account
     *
     * @param account address of the account
     *
     * @return ownersArray array of owners
     */
    function getOwners(address account) external view returns (address[] memory ownersArray) {
        // get the owners from the linked list
        (ownersArray,) = owners.getEntriesPaginated(account, SENTINEL, MAX_OWNERS);
    }

    /**
     * Sets the keystore data for the account
     *
     * @param keystoreAddress address of the keystore
     * @param invalidationTime uint48 time after which the keystore data is invalid
     */
    function setKeystoreData(bytes32 keystoreAddress, uint48 invalidationTime) external {
        // cache the account address
        address account = msg.sender;

        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // set the keystore data
        keystoreData[account] = InstallationData({
            initialized: keystoreAddress != bytes32(0) && invalidationTime != 0,
            invalidationTime: invalidationTime,
            keystoreAddress: keystoreAddress
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates a user operation
     *
     * @param userOp PackedUserOperation struct containing the UserOperation
     * @param userOpHash bytes32 hash of the UserOperation
     *
     * @return ValidationData the UserOperation validation result
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData)
    {
        // Validate signature using the common config function
        (bool isValid, uint48 validAfter, uint48 validUntil) =
            _validateSignatureWithConfigAndCache(userOp.sender, userOpHash, userOp.signature);

        // Return validation result
        if (isValid) {
            // If we have time constraints, return them
            if (validAfter != 0 || validUntil != 0) {
                return ValidationData.wrap(
                    _packValidationData4337(
                        ValidationData4337({
                            aggregator: address(0),
                            validUntil: validUntil,
                            validAfter: validAfter
                        })
                    )
                );
            }
            // Otherwise return simple success
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /**
     * Validates an ERC-1271 signature with the sender
     *
     * @param hash bytes32 hash of the data
     * @param data bytes data containing the signatures
     *
     * @return bytes4 EIP1271_SUCCESS if the signature is valid, EIP1271_FAILED otherwise
     */
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // Cache the account address
        address account = msg.sender;
        // get the threshold and check that its set
        uint256 _threshold = threshold[account];
        if (_threshold == 0) {
            return EIP1271_FAILED;
        }

        // Validate signature using the common config function
        (bool isValid) = _validateSignatures(account, hash, data, _threshold);

        // Return the result
        if (isValid) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /**
     * Validates a signature with the data (stateless validation)
     *
     * @param hash bytes32 hash of the data
     * @param signature bytes data containing the signatures
     * @param data bytes data containing the data
     *
     * @return bool true if the signature is valid, false otherwise
     */
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool)
    {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            return false;
        }

        // check that threshold is set
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers = CheckSignatures.recoverNSignatures(
            ECDSA.toEthSignedMessageHash(hash), signature, _threshold
        );

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            (bool found,) = _owners.searchSorted(signers[i]);
            if (found) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Core signature validation function with keystore integration
     *
     * @param account The account to validate for
     * @param hash The hash to validate
     * @param data The signature data
     *
     * @return isValid Whether the signature is valid
     * @return validAfter Timestamp from which the signature is valid
     * @return validUntil Timestamp until which the signature is valid
     */
    function _validateSignatureWithConfigAndCache(
        address account,
        bytes32 hash,
        bytes calldata data
    )
        internal
        returns (bool isValid, uint48 validAfter, uint48 validUntil)
    {
        // Get the threshold and check that it's set
        uint256 _threshold = threshold[account];
        if (_threshold == 0) {
            return (false, 0, 0);
        }

        // Decode signature data
        SignatureData calldata signatureData = decodeSignature(data);

        // First byte of the signature data signifies usage mode
        bytes1 mode = bytes1(signatureData.signatures[0:1]);

        if (mode == SIGNATURE_MODE_SKIP_KEYSTORE) {
            // Skip keystore verification, just validate signatures
            bool signaturesValid =
                _validateSignatures(account, hash, signatureData.signatures[1:], _threshold);
            return (signaturesValid, 0, 0);
        } else {
            // Get account's installation data
            InstallationData storage installData = keystoreData[account];

            // Process keystore proof
            uint48 blockTimestamp;

            if (
                mode == SIGNATURE_MODE_USE_KEYSTORE_PROOF
                    || mode == SIGNATURE_MODE_USE_AND_CACHE_KEYSTORE_STATE
            ) {
                // Hash the key data for verification
                bytes32 dataHash = keccak256(signatureData.keyDataProof.keyData);

                // Process the IMT proof to get the derived root block timestamp
                blockTimestamp = processImtKeyData(
                    signatureData.keyDataProof, dataHash, installData.keystoreAddress
                );

                // Cache the state if requested
                if (mode == SIGNATURE_MODE_USE_AND_CACHE_KEYSTORE_STATE) {
                    // Extract owner and threshold data from keyData
                    (uint256 keystoreThreshold, address[] memory keystoreOwners) =
                        abi.decode(signatureData.keyDataProof.keyData, (uint256, address[]));

                    // Cache the owners and threshold
                    cacheOwnersAndThreshold(account, keystoreThreshold, keystoreOwners);
                }
            }

            // Validate signatures
            bool signaturesValid =
                _validateSignatures(account, hash, signatureData.signatures[1:], _threshold);

            if (!signaturesValid) {
                return (false, 0, 0);
            }

            // Check timestamp validity for keystore-based validation
            if (blockTimestamp > 0) {
                // For keystore, we have time bounds
                uint48 expirationTime = blockTimestamp + installData.invalidationTime;
                return (true, blockTimestamp, expirationTime);
            }

            // Simple success for non-keystore validation
            return (true, 0, 0);
        }
    }

    function _validateSignatures(
        address account,
        bytes32 hash,
        bytes calldata data,
        uint256 _threshold
    )
        internal
        view
        returns (bool)
    {
        // recover the signers from the signatures
        address[] memory signers =
            CheckSignatures.recoverNSignatures(ECDSA.toEthSignedMessageHash(hash), data, _threshold);

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            if (owners.contains(account, signers[i])) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, return false
        return false;
    }

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

    function cacheOwnersAndThreshold(
        address account,
        uint256 _threshold,
        address[] memory _owners
    )
        internal
    {
        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            revert NotSortedAndUnique();
        }

        // check that threshold is set
        if (_threshold == 0) {
            revert InvalidThreshold();
        }

        // check that the threshold is less than the number of owners
        if (ownerCount[account] < _threshold) {
            revert InvalidThreshold();
        }

        // cache the owner count
        ownerCount[account] = _owners.length;

        // Clear old owners
        owners.popAll(account);

        // cache the owners
        owners.init(account);
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_owners[i] == address(0)) {
                revert InvalidOwner(_owners[i]);
            }
            owners.push(account, _owners[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the type of the module
     *
     * @param typeID type of the module
     *
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() external pure virtual returns (string memory) {
        return "OwnableValidator";
    }

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}
