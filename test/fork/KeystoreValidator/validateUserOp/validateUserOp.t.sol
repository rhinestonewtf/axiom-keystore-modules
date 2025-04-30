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
        withCachedL1Block(0xdf57133cccabd6f973fae98d474da22d8be72bd3d3436a1211aa8f384520796e)
        withCachedKeystoreStateRoot("test/proofs/Exclusivity.json")
    {
        uint256 test;
    }
}
