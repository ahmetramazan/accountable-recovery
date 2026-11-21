// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Minimal subset of ERC-7579 used by the recovery module.
interface IERC7579Module {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IERC7579Account {
    /// @dev Mode 0x00..00 is a single call with default execution type; the execution calldata is
    ///      abi.encodePacked(target, value, callData).
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @dev Interface of the owner validator whose key the module replaces in Finalize.
interface IOwnerValidator {
    function setOwner(address newOwner) external;
}

uint256 constant MODULE_TYPE_EXECUTOR = 2;
