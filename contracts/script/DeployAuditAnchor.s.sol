// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

/// @notice Deploys an AuditAnchor with the committer address read from
///         env var COMMITTER_ADDRESS. Use:
///
///   forge script script/DeployAuditAnchor.s.sol \
///     --rpc-url $SEPOLIA_RPC_URL \
///     --private-key $DEPLOYER_PRIVATE_KEY \
///     --broadcast --verify
///
/// The deployer becomes `owner`; `committer` is the address the
/// Go service will sign anchor transactions from.
contract DeployAuditAnchor is Script {
    function run() external returns (AuditAnchor anchor) {
        address committer = vm.envAddress("COMMITTER_ADDRESS");
        vm.startBroadcast();
        anchor = new AuditAnchor(committer);
        vm.stopBroadcast();
        console.log("AuditAnchor deployed at:", address(anchor));
        console.log("Owner:", anchor.owner());
        console.log("Committer:", anchor.committer());
    }
}
