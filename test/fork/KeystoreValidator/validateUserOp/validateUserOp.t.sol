// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Tests
import { KeystoreValidator_Fork_Test } from "@test/fork/KeystoreValidator/KeystoreValidator.t.sol";

contract KeystoreValidator_ValidateUserOp_Fork_Test is
    KeystoreValidator_Fork_Test(135_181_948, "optimism")
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

    function test_validateUserOp() public {
        uint256 blockNumber = 135_181_948;
    }
}
