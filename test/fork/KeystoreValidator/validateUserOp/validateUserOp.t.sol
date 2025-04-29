// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Tests
import { KeystoreValidator_Fork_Test } from "@test/fork/KeystoreValidator/KeystoreValidator.t.sol";

contract KeystoreValidator_ValidateUserOp_Fork_Test is
    KeystoreValidator_Fork_Test(135_182_430, "optimism")
{
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
        withCachedL1Block(0x5be47f393780654f8c4dc490e0d8da6cc1da44f5da04362f1b62e2a809e20977)
        withCachedKeystoreStateRoot("test/proofs/Exclusivity.json")
    {
        uint256 test;
    }
}
