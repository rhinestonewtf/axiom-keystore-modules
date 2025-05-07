// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Contracts
import { KeystoreCache } from "@auxiliary/KeystoreCache.sol";

// Util
import { Script } from "@forge-std/Script.sol";
import { stdJson } from "@forge-std/StdJson.sol";
import { console } from "@forge-std/console.sol";

// Types
import { StorageProof } from "@types/DataTypes.sol";

contract UpdateKeystoreStateRoot is Script {
    using stdJson for string;

    KeystoreCache internal keystoreCache;

    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        keystoreCache = KeystoreCache(address(0xbE8877ab2B97e8Ca4A2d0Ae9B10ed12cC9646190));

        // Read the proof data file
        string memory proofDataJson = vm.readFile("proof_data.json");

        // Parse the proof data
        bytes memory blockHeader = proofDataJson.readBytes(".blockHeader");

        // Parse block hash
        bytes32 l1BlockHash = proofDataJson.readBytes32(".l1BlockHash");
        console.log("L1 Block Hash:");
        console.logBytes32(l1BlockHash);

        // Parse the storage proof components
        bytes32 storageValue = proofDataJson.readBytes32(".storageValue");
        bytes[] memory accountProof = proofDataJson.readBytesArray(".accountProof");
        bytes[] memory storageProof = proofDataJson.readBytesArray(".storageProof");

        // Create the storage proof
        StorageProof memory proof = StorageProof({
            storageValue: storageValue,
            blockHeader: blockHeader,
            accountProof: accountProof,
            storageProof: storageProof
        });

        // Cache the keystore state root
        keystoreCache.cacheKeystoreStateRoot(proof);

        vm.stopBroadcast();
    }
}

contract UpdateBlockhash is Script {
    KeystoreCache internal keystoreCache;

    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        keystoreCache = KeystoreCache(address(0xbE8877ab2B97e8Ca4A2d0Ae9B10ed12cC9646190));

        // Cache the L1 block hash
        keystoreCache.cacheBlockhash();

        vm.stopBroadcast();
    }
}
