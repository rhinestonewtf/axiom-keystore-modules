// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Libraries
import { ModuleKitHelpers, AccountInstance } from "@rhinestone/modulekit/ModuleKit.sol";

// Tests
import { KeystoreValidator_Fork_Test } from "@test/fork/KeystoreValidator/KeystoreValidator.t.sol";

// Types
import { KeyMerkleProofData } from "@types/DataTypes.sol";
import { UserOpData } from "@rhinestone/modulekit/ModuleKit.sol";
import { PackedUserOperation } from "@rhinestone/modulekit/external/ERC4337.sol";

contract KeystoreValidator_ValidateUserOp_Fork_Test is
    KeystoreValidator_Fork_Test(135_222_922, "optimism")
{
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for AccountInstance;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Setup base test
        super.setUp();
    }

    /*//////////////////////////////////////////////////////////////
                                TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validateUserOp_with_exclusivityProof()
        public
        withCachedL1Block(0xdf57133cccabd6f973fae98d474da22d8be72bd3d3436a1211aa8f384520796e)
        withCachedKeystoreStateRoot(
            "test/proofs/Exclusivity.json",
            0xacf894f7c0801ad245b9804131d4cbb11d39b2050a393b97de50aacd1e5ede03
        )
    {
        // Create the proof array - using the sibling hashes from cast rpc keystore_getProof
        // 0xde9412a64e458b243e0a13bb0d33e98911824e5bea92de8d8c1255aa80227f37 "latest" --rpc-url
        // $KEYSTORE_RPC_URL | jq
        bytes32[] memory proof = new bytes32[](5);
        proof[0] = 0xaf005b651243ca95ea8580c7fb7129f35d5a81634578789b841658723f061518;
        proof[1] = 0x96f023dc0bce011d48eb3e262f651e611c1946af7f8bf7362ce6d872a87dfeab;
        proof[2] = 0x5737b7f9662dd2fed6073d06bdf4f10b47ec5ef196e77f20bc36bc7faae5b07a;
        proof[3] = 0xeb5f0d5ddd45f007e487b9f2b28bcd111102cacafc942c4965e379583651977e;
        proof[4] = 0xa1c2f4ae7e0433e044680c45617b32965d96080d22d7ca9e40d8dd6f98aea9c0;

        // Calculate isLeft value from the response (packing the isLeft bits)
        // siblings[0].isLeft = true
        // siblings[1].isLeft = false
        // siblings[2].isLeft = false
        // siblings[3].isLeft = false
        // siblings[4].isLeft = false
        // Binary: 00001 = 1 in decimal
        uint256 isLeft = 1;

        // Create the KeyMerkleProofData structure
        KeyMerkleProofData memory keyDataMerkleProof = KeyMerkleProofData({
            isExclusion: true,
            // Concatenated from leaf.keyPrefix + leaf.key + salt + keccak256(leaf.value)
            exclusionExtraData: abi.encodePacked(
                bytes1(0x01), //  leaf.keyPrefix
                bytes32(0x02856813f6b9bd77bea28521b0277bf2867e1a2358953d912fede9820369a9e5), // leaf.key
                salt, // salt
                keccak256(
                    abi.encode(
                        bytes32(0x0000000000000000000000000000000000000000000845951613fbb5ca776a2c)
                    )
                ) // leaf.value
            ),
            nextDummyByte: 0x01, //  leaf.nextKeyPrefix
            nextImtKey: 0x078fd8980f317673830cdb6a2498d109c98b6fdc1ca9f4f773eb6aeedb66ac49, //
                // leaf.nextKey
            vkeyHash: vkeyHash,
            keyData: keyData,
            proof: proof,
            isLeft: isLeft
        });

        // Create a UserOperation
        UserOpData memory userOpData = account.getExecOps({
            target: target,
            value: value,
            callData: "",
            txValidator: address(keystoreValidator)
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOpData.userOp;
        userOps[0].initCode = hex"";

        // Sign the UserOperation with the admin key
        bytes32 userOpHash = account.aux.entrypoint.getUserOpHash(userOps[0]);

        bytes memory userOpSig = adminSign(userOpHash);

        // Encode the final signature
        bytes memory sig = abi.encode(keyDataMerkleProof, userOpSig);
        userOps[0].signature = sig;

        // Record the previous balance of the target address
        uint256 prevBalance = target.balance;

        // Execute the UserOperation
        account.aux.entrypoint.handleOps(userOps, payable(admin.addr));

        // Verify that the transaction was successful by checking balance change
        assertEq(target.balance, prevBalance + value);
    }
}
