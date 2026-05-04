// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title AuditAnchor
/// @notice On-chain witness for the off-chain RFC 6962 Merkle audit log.
///         A trusted committer periodically posts `(treeSize, root)` here
///         so any auditor can re-run RFC 6962 consistency proofs against
///         the live tree and detect rewrites the log operator can no
///         longer hide.
/// @dev    Designed to be deployed once per environment (Sepolia for the
///         class demo). The `committer` is the single allowed signer for
///         `commit`; ownership transfer is two-step to avoid bricking
///         the contract on a typo.
contract AuditAnchor {
    /// @notice Anchor record stored at index `id`.
    struct Anchor {
        uint64 treeSize; // RFC 6962 leaf count at commit time
        bytes32 root; // tree head hash (sha-256 in our impl)
        uint64 timestamp; // committer's wall clock at submission (informational)
        uint64 blockNumber; // chain block number — index key for off-chain readers
    }

    /// @notice Emitted once per successful commit. Indexers tail this.
    event AuditAnchored(
        uint256 indexed id, uint64 treeSize, bytes32 indexed root, uint64 blockNumber, uint64 timestamp
    );

    /// @notice Owner administers the committer set; cannot itself commit.
    address public owner;
    address public pendingOwner;

    /// @notice Trusted committer. Only this address may call `commit`.
    address public committer;

    /// @notice Append-only ledger of anchors. `anchors.length` is the
    ///         next id; older entries are never overwritten.
    Anchor[] private anchors;

    error NotOwner();
    error NotPendingOwner();
    error NotCommitter();
    error EmptyTree();
    error TreeShrank(uint64 last, uint64 next);
    error ZeroAddress();

    constructor(address initialCommitter) {
        if (initialCommitter == address(0)) revert ZeroAddress();
        owner = msg.sender;
        committer = initialCommitter;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyCommitter() {
        if (msg.sender != committer) revert NotCommitter();
        _;
    }

    /// @notice Commit a new anchor. Reverts if the tree size hasn't
    ///         strictly grown — anchors must be monotonic so RFC 6962
    ///         consistency proofs always have a smaller anchored size
    ///         to extend from.
    function commit(uint64 treeSize, bytes32 root, uint64 timestamp) external onlyCommitter returns (uint256 id) {
        if (treeSize == 0) revert EmptyTree();
        uint256 n = anchors.length;
        if (n > 0) {
            uint64 last = anchors[n - 1].treeSize;
            if (treeSize <= last) revert TreeShrank(last, treeSize);
        }
        id = n;
        anchors.push(
            Anchor({treeSize: treeSize, root: root, timestamp: timestamp, blockNumber: uint64(block.number)})
        );
        emit AuditAnchored(id, treeSize, root, uint64(block.number), timestamp);
    }

    /// @notice Read an anchor by id. Reverts with the default solc
    ///         out-of-bounds panic when id >= count.
    function anchorAt(uint256 id) external view returns (Anchor memory) {
        return anchors[id];
    }

    /// @notice Read the most-recent anchor. Reverts when no commits.
    function latest() external view returns (Anchor memory) {
        uint256 n = anchors.length;
        if (n == 0) revert EmptyTree();
        return anchors[n - 1];
    }

    /// @notice Total number of anchors ever committed.
    function count() external view returns (uint256) {
        return anchors.length;
    }

    /// @notice Rotate the committer. Owner-only; effective immediately.
    function setCommitter(address next) external onlyOwner {
        if (next == address(0)) revert ZeroAddress();
        committer = next;
    }

    /// @notice Begin a two-step ownership handover.
    function transferOwnership(address next) external onlyOwner {
        if (next == address(0)) revert ZeroAddress();
        pendingOwner = next;
    }

    /// @notice Pending owner accepts.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
