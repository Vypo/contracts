/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

pragma solidity ^0.6.5;

interface Exchange {
    function tokenToEthTransferOutput(uint256 eth_bought, uint256 max_tokens, uint256 deadline, address recipient) external returns (uint256  tokens_sold);
}

interface DaiToken {
    function balanceOf(address tokenOwner) external view returns (uint256);

    function permit(
        address holder,
        address spender,
        uint256 nonce,
        uint256 expiry,
        bool allowed,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function pull(address usr, uint wad) external;
    function push(address usr, uint wad) external;
    function approve(address usr, uint wad) external returns (bool);
}

/// @author Vypo Mouse
/// @title DaiEscrowTimeouts
/// @notice Holds Dai tokens in escrow until the buyer and seller agree to
///         release them. A relayer handles paying the transaction fees, and is
///         reimbursed when the funds are released.
/// @dev First construct the contract, specifying the buyer and seller addresses.
///      Then `initialize` the contract with signatures for Dai's `permit`. This
///      transfers Dai from the buyer to the escrow contract.
///
///      When the seller has completed their responsibilities, the relayer
///      calls `submit` on their behalf. If the seller does not complete their
///      tasks within ~30 days, anyone may call `submitPastDue` and refund the
///      buyer.
///
///      Once `submit` has been called, the buyer has ~30 days to call `review`.
///      If the buyer does not call `review`, anyone may call `reviewPastDue` to
///      release the funds to the seller.
///
///      When `review` is called, the buyer may choose to approve the submission
///      or not approve it. If the submission is approved, the funds are released
///      to the seller. If the buyer does not approve, the funds are locked
///      forever.
contract Escrow {
    enum Status {
        AwaitingWad,
        AwaitingSubmission,
        AwaitingReview,
        Complete,
        Locked
    }

    // keccak256("Review(bool _approve)")
    bytes32 public constant REVIEW_TYPEHASH = 0xfa5e0016fb62b8dffda8fd95249d438edcffd3689b40ac3b4281d4cf710609ae;

    // keccak256("Submit(bytes32 _submission)")
    bytes32 public constant SUBMIT_TYPEHASH = 0x62b607caa4d4e7fcbd31bf4c033cd30888b536567fadc83710fdf15f8d5cfc9e;

    // Mainnet //
    // DaiToken constant DAI = DaiToken(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    // Exchange constant UNISWAP = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);

    // Kovan //
    DaiToken constant DAI = DaiToken(0x4F96Fe3b7A6Cf9725f59d353F723c1bDb64CA6Aa);
    Exchange constant UNISWAP = Exchange(0x613639E23E91fd54d50eAfd6925AF2Ed6701A46b);

    uint constant TIMEOUT = 30 days;

    uint256 constant MAX_DAI_FOR_RELAYER = 5 ether;

    bytes32 public immutable domain_separator;

    address payable public immutable relayer;
    address immutable public seller;
    address immutable public buyer;

    uint immutable public wad;

    uint public initialized;
    uint public submitted;

    uint public relayer_owed;
    Status public status;

    modifier relayedGasCtor(uint _base) {
        uint at_start = gasleft();

        _;

        uint at_end = gasleft();

        relayer_owed += tx.gasprice * (_base + (at_start - at_end));
    }

    modifier relayedGas(uint _base) {
        uint at_start = gasleft();

        _;

        uint at_end = gasleft();

        if (tx.origin == relayer) {
            relayer_owed += tx.gasprice * (_base + (at_start - at_end));
        }
    }

    modifier onlyWhen(Status _status) {
        require(status == _status, "Fn not presently valid");
        _;
    }

    constructor(
        address _seller,
        address _buyer,
        uint _wad
    ) public relayedGasCtor(1039528) {
        require(_seller != address(0), "invalid seller");
        require(_buyer != address(0), "invalid buyer");

        uint8 chain_id;
        assembly {
            chain_id := chainid()
        }

        domain_separator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("escrow")),
            keccak256(bytes("1")),
            chain_id,
            address(this)
        ));

        wad = _wad;
        relayer = tx.origin;
        seller = _seller;
        buyer = _buyer;
        status = Status.AwaitingWad;
    }

    function initialize(
        uint256 nonce,
        uint256 expiry,
        uint8 v_allow,
        bytes32 r_allow,
        bytes32 s_allow,
        uint8 v_deny,
        bytes32 r_deny,
        bytes32 s_deny
    ) external onlyWhen(Status.AwaitingWad) relayedGas(0) {
        status = Status.AwaitingSubmission;

        initialized = block.timestamp;

        // Unlock buyer's Dai balance to transfer `wad` to this contract.
        DAI.permit(buyer, address(this), nonce, expiry, true, v_allow, r_allow, s_allow);

        // Transfer Dai from `buyer` to this contract.
        DAI.pull(buyer, wad);

        // Relock Dai balance of `buyer`.
        DAI.permit(buyer, address(this), nonce + 1, expiry, false, v_deny, r_deny, s_deny);
    }

    /// @notice Signal that the seller has taken too long. Pays outstanding fees
    ///         to `relayer` and transfers remaining Dai to `buyer`.
    function submitPastDue() external onlyWhen(Status.AwaitingSubmission) {
        require(block.timestamp >= (initialized + TIMEOUT), "not past due");

        // TODO: Track gas for `relayer_owed`

        resolve(buyer);
    }

    /// @notice Signal that the buyer has taken too long. Pays outstanding fees
    ///         to `relayer` and transfers remaining Dai to `seller`.
    function reviewPastDue() external onlyWhen(Status.AwaitingReview) {
        require(block.timestamp >= (submitted + TIMEOUT), "not past due");
        assert(submitted != 0);

        // TODO: Track gas for `relayer_owed`

        resolve(seller);
    }

    function submit(
        bytes32 _submission,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external onlyWhen(Status.AwaitingSubmission) relayedGas(0) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domain_separator,
            keccak256(abi.encode(SUBMIT_TYPEHASH, _submission))
        ));

        require(seller == ecrecover(digest, _v, _r, _s), "invalid-permit");

        status = Status.AwaitingReview;
        submitted = block.timestamp;
    }

    function review(
        bool _approve,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external onlyWhen(Status.AwaitingReview) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domain_separator,
            keccak256(abi.encode(REVIEW_TYPEHASH, _approve))
        ));

        require(buyer == ecrecover(digest, _v, _r, _s), "invalid-permit");

        // TODO: Track gas for `relayer_owed`

        if (_approve) {
            resolve(seller);
        } else {
            resolve(address(0));
        }
    }

    function forfeit() external {
        require(msg.sender == relayer, "relayer only");
        relayer_owed = 0;
    }

    function resolve(address dai_target) private {
        bool locked = dai_target == address(0);

        if (locked) {
            status = Status.Locked;
        } else {
            status = Status.Complete;
        }

        if (relayer_owed > 0) {
            uint owed = relayer_owed;
            relayer_owed = 0;

            bool approved = DAI.approve(address(UNISWAP), uint(-1));
            assert(approved);

            UNISWAP.tokenToEthTransferOutput(
                owed,
                MAX_DAI_FOR_RELAYER,
                block.timestamp,
                relayer
            );
        }

        if (!locked) {
            DAI.push(dai_target, DAI.balanceOf(address(this)));
        }
    }

    function cancel() external {
        require(status == Status.AwaitingWad || status == Status.Complete, "wrong status");
        require(msg.sender == relayer, "relayer only");
        initialized = 0;
        submitted = 0;
        selfdestruct(relayer);
    }

    function die() external {
        // XXX: FOR TESTING ONLY
        DAI.push(relayer, DAI.balanceOf(address(this)));
        selfdestruct(relayer);
    }
}
