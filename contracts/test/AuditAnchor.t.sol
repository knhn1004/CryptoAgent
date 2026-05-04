// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

contract AuditAnchorTest is Test {
    AuditAnchor anchor;

    address owner = address(0xA11CE);
    address committer = address(0xB0B);
    address mallory = address(0xBADD);

    bytes32 constant ROOT_1 = bytes32(uint256(0xa1));
    bytes32 constant ROOT_2 = bytes32(uint256(0xa2));

    event AuditAnchored(
        uint256 indexed id, uint64 treeSize, bytes32 indexed root, uint64 blockNumber, uint64 timestamp
    );
    event CommitterChanged(address indexed previous, address indexed next);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        vm.prank(owner);
        anchor = new AuditAnchor(committer);
    }

    function test_constructor_sets_roles() public view {
        assertEq(anchor.owner(), owner);
        assertEq(anchor.committer(), committer);
        assertEq(anchor.count(), 0);
    }

    function test_constructor_rejects_zero_committer() public {
        vm.expectRevert(AuditAnchor.ZeroAddress.selector);
        new AuditAnchor(address(0));
    }

    function test_commit_emits_event() public {
        vm.roll(100);
        vm.expectEmit(true, true, true, true);
        emit AuditAnchored(0, 1, ROOT_1, 100, 1_700_000_000);
        vm.prank(committer);
        uint256 id = anchor.commit(1, ROOT_1, 1_700_000_000);
        assertEq(id, 0);
    }

    function test_commit_records_anchor() public {
        vm.roll(123);
        vm.prank(committer);
        anchor.commit(7, ROOT_1, 1_700_000_000);

        AuditAnchor.Anchor memory got = anchor.latest();
        assertEq(got.treeSize, 7);
        assertEq(got.root, ROOT_1);
        assertEq(got.timestamp, 1_700_000_000);
        assertEq(got.blockNumber, 123);
        assertEq(anchor.count(), 1);
    }

    function test_commit_rejects_non_committer() public {
        vm.prank(mallory);
        vm.expectRevert(AuditAnchor.NotCommitter.selector);
        anchor.commit(1, ROOT_1, 1);
    }

    function test_commit_rejects_empty_tree() public {
        vm.prank(committer);
        vm.expectRevert(AuditAnchor.EmptyTree.selector);
        anchor.commit(0, ROOT_1, 1);
    }

    function test_commit_rejects_shrinking_tree() public {
        vm.prank(committer);
        anchor.commit(10, ROOT_1, 1);
        vm.prank(committer);
        vm.expectRevert(abi.encodeWithSelector(AuditAnchor.TreeShrank.selector, uint64(10), uint64(9)));
        anchor.commit(9, ROOT_2, 2);
    }

    function test_commit_rejects_equal_tree() public {
        vm.prank(committer);
        anchor.commit(10, ROOT_1, 1);
        vm.prank(committer);
        vm.expectRevert(abi.encodeWithSelector(AuditAnchor.TreeShrank.selector, uint64(10), uint64(10)));
        anchor.commit(10, ROOT_1, 2);
    }

    function test_anchorAt_returns_history() public {
        vm.prank(committer);
        anchor.commit(1, ROOT_1, 1);
        vm.prank(committer);
        anchor.commit(2, ROOT_2, 2);
        AuditAnchor.Anchor memory a0 = anchor.anchorAt(0);
        AuditAnchor.Anchor memory a1 = anchor.anchorAt(1);
        assertEq(a0.root, ROOT_1);
        assertEq(a1.root, ROOT_2);
    }

    function test_latest_reverts_when_empty() public {
        vm.expectRevert(AuditAnchor.EmptyTree.selector);
        anchor.latest();
    }

    function test_setCommitter_owner_only() public {
        address next = address(0xCAFE);
        vm.prank(mallory);
        vm.expectRevert(AuditAnchor.NotOwner.selector);
        anchor.setCommitter(next);

        vm.prank(owner);
        anchor.setCommitter(next);
        assertEq(anchor.committer(), next);
    }

    function test_setCommitter_rejects_zero() public {
        vm.prank(owner);
        vm.expectRevert(AuditAnchor.ZeroAddress.selector);
        anchor.setCommitter(address(0));
    }

    function test_two_step_ownership() public {
        address next = address(0xFEED);
        vm.prank(owner);
        anchor.transferOwnership(next);
        assertEq(anchor.pendingOwner(), next);
        // Old owner is still owner until acceptance.
        assertEq(anchor.owner(), owner);

        // Wrong sender cannot accept.
        vm.prank(mallory);
        vm.expectRevert(AuditAnchor.NotPendingOwner.selector);
        anchor.acceptOwnership();

        vm.prank(next);
        anchor.acceptOwnership();
        assertEq(anchor.owner(), next);
        assertEq(anchor.pendingOwner(), address(0));
    }

    function test_committer_cannot_self_promote() public {
        vm.prank(committer);
        vm.expectRevert(AuditAnchor.NotOwner.selector);
        anchor.setCommitter(committer);
    }

    function test_setCommitter_emits_event() public {
        address next = address(0xCAFE);
        vm.expectEmit(true, true, true, true);
        emit CommitterChanged(committer, next);
        vm.prank(owner);
        anchor.setCommitter(next);
    }

    function test_transferOwnership_emits_event() public {
        address next = address(0xFEED);
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferStarted(owner, next);
        vm.prank(owner);
        anchor.transferOwnership(next);
    }

    function test_acceptOwnership_emits_event() public {
        address next = address(0xFEED);
        vm.prank(owner);
        anchor.transferOwnership(next);

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(owner, next);
        vm.prank(next);
        anchor.acceptOwnership();
    }
}
