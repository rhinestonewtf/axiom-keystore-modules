// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { RhinestoneModuleKit } from "@rhinestone/modulekit/ModuleKit.sol";
import { Vm } from "@forge-std/Vm.sol";

/// @notice An abstract base test contract that provides common test logic.
abstract contract Base_Test is Test, RhinestoneModuleKit {
    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice A wallet that represents an admin address.
    Vm.Wallet public admin;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Create the admin address.
        admin = vm.createWallet("admin");
        // Initialize the module kit.
        super.init();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sign a message with the admin's private key.
    /// @param hash The hash of the message to sign.
    /// @return signature The signature of the message.
    function signMessage(bytes32 hash) internal returns (bytes memory signature) {
        // Sign the message with the admin's private key.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(admin, hash);
        // Return the signature.
        return abi.encodePacked(r, s, v);
    }
}
