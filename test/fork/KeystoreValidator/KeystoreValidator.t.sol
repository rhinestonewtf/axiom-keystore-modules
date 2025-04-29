// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Contracts
import { KeystoreValidator } from "@contracts/KeystoreValidator.sol";
import { OwnableValidator } from "@rhinestone/core-modules/OwnableValidator/OwnableValidator.sol";

// Libraries
import { ModuleKitHelpers, AccountInstance } from "@rhinestone/modulekit/ModuleKit.sol";

// Test
import { Fork_Test } from "@test/fork/Fork.t.sol";

// Types
import { MODULE_TYPE_VALIDATOR } from
    "@rhinestone/modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { StorageProof } from "@types/DataTypes.sol";

// Utils
import { console } from "@forge-std/console.sol";
import { ProofUtils } from "@test/utils/ProofUtils.sol";

contract KeystoreValidator_Fork_Test is Fork_Test, ProofUtils {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for AccountInstance;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // The address of the L1Block contract
    address constant L1_BLOCK = 0x4200000000000000000000000000000000000015;

    // The address of the AxiomKeystoreRollup contract
    address constant AXIOM_KEYSTORE_ROLLUP = 0x829ce5730041De079995F7E7D9749E11F36Da0Bc;

    // keccak256(abi.encode(uint256(keccak256("axiom.storage.AxiomKeystoreRollup")) - 1)) &
    // ~bytes32(uint256(0xff))
    bytes32 private constant AXIOM_KEYSTORE_ROLLUP_STORAGE_LOCATION =
        0xc94330da5d5688c06df0ade6bfd773c87249c0b9f38b25021e2c16ab9672d000;

    // The keccak256 hash of the vkey
    bytes32 constant vkeyHash = keccak256("vkey");

    // Keystore salt
    bytes32 constant salt = 0x0000000000000000000000000000000000000000000000000000000000000000;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    // The address of the KeystoreValidator contract
    KeystoreValidator internal keystoreValidator;

    // A smart account instance
    AccountInstance internal account;

    // The address of the ownable validator
    address internal ownableValidator;

    // Default key data
    bytes internal keyData;

    // The address of the account in the keystore
    bytes32 internal keystoreAddress;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _forkBlockNumber,
        string memory _forkUrlOrAlias
    )
        Fork_Test(_forkBlockNumber, _forkUrlOrAlias)
    { }

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Setup base test
        super.setUp();

        // Deploy the KeystoreValidator contract
        keystoreValidator =
            new KeystoreValidator(AXIOM_KEYSTORE_ROLLUP, AXIOM_KEYSTORE_ROLLUP_STORAGE_LOCATION);

        // Label the KeystoreValidator contract
        vm.label(address(keystoreValidator), "KeystoreValidator");

        // Deploy the OwnableValidator contract
        ownableValidator = address(new OwnableValidator());
        vm.label(ownableValidator, "OwnableValidator");

        // Deploy account
        account = makeAccountInstance("KeystoreAccount");

        // Setup key data
        address[] memory owners = new address[](1);
        owners[0] = admin.addr;
        uint256 threshold = 1;
        // First 32 bytes are the codehash of the validator, then the abi-encoded data for
        // stateless validation
        keyData = abi.encodePacked(ownableValidator.codehash, abi.encode(threshold, owners));
        keystoreAddress = keccak256(abi.encodePacked(salt, keccak256(keyData), vkeyHash));
        console.log("Keystore Address:");
        console.logBytes32(keystoreAddress);

        // Register the stateless validator
        keystoreValidator.registerStatelessValidator(ownableValidator, ownableValidator.codehash);

        // Install the keystoreValidator
        account.installModule(
            MODULE_TYPE_VALIDATOR,
            address(keystoreValidator),
            abi.encode(100_000 days, keystoreAddress)
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withCachedL1Block(uint256 l1BlockHash) {
        // Set the block hash
        vm.store(L1_BLOCK, bytes32(uint256(0x02)), bytes32(l1BlockHash));
        keystoreValidator.cacheBlockhash();
        // Call the function
        _;
    }

    modifier withCachedKeystoreStateRoot(string memory path) {
        // Read the storage proof from the JSON file
        (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof) =
            readStorageProof("test/proofs/Exclusion.json");

        // Create the storage proof
        StorageProof memory proof = StorageProof({
            storageValue: bytes32(0x336d75dffb97c4132b4d9594dda1c38651477198b097d67d2c9368a097613107),
            blockHeader: blockHeader,
            accountProof: accountProof,
            storageProof: storageProof
        });

        // Cache the keystore state root
        keystoreValidator.cacheKeystoreStateRoot(proof);
        // Call the function
        _;
    }
}
