// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Utils
import { stdJson as StdJson, StdCheats, Vm } from "forge-std/Test.sol";

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

/// @notice Utility contract to read storage proofs from JSON files.
contract ProofUtils is StdCheats {
    using StdJson for *;

    function readStorageProof(string memory filePath)
        public
        view
        returns (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof)
    {
        string memory json = vm.readFile(filePath);
        blockHeader = json.readBytes(".rlp_block_header");
        accountProof = json.readBytesArray(".storage_proof.accountProof");
        storageProof = json.readBytesArray(".storage_proof.storageProof[0].proof");
    }
}
