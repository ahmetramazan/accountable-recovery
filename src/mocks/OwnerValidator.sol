// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IOwnerValidator} from "../interfaces/IERC7579.sol";

/// @notice Minimal ECDSA owner validator in the style of an ERC-7579 validator module: it keeps one
///         owner per account, and only the account itself can replace it.
contract OwnerValidator is IOwnerValidator {
    mapping(address account => address) public owner;

    function setOwner(address newOwner) external override {
        owner[msg.sender] = newOwner;
    }

    /// @notice Checks a raw ECDSA signature (r || s || v) of `hash` by the owner of `account`.
    function isValidSignatureFor(address account, bytes32 hash, bytes calldata sig) external view returns (bool) {
        if (sig.length != 65) return false;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return false;
        address signer = ecrecover(hash, v, r, s);
        return signer != address(0) && signer == owner[account];
    }
}
