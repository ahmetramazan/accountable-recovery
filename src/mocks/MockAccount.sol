// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7579Account, IERC7579Module, IERC1271, MODULE_TYPE_EXECUTOR} from "../interfaces/IERC7579.sol";
import {OwnerValidator} from "./OwnerValidator.sol";

/// @notice Minimal modular account for tests and benchmarks. It supports executor modules,
///         single-call executeFromExecutor, and ERC-1271 through an ECDSA owner validator.
///         It is NOT a complete or secure ERC-7579 account.
contract MockAccount is IERC7579Account, IERC1271 {
    OwnerValidator public immutable validator;
    address public immutable admin;
    mapping(address module => bool) public isExecutor;

    constructor(OwnerValidator validator_, address initialOwner) {
        validator = validator_;
        admin = msg.sender;
        validator_.setOwner(initialOwner);
    }

    /// @dev For the tests only the deployer may install modules; a real account authorises this
    ///      through its validator.
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external {
        require(msg.sender == admin, "not admin");
        require(moduleTypeId == MODULE_TYPE_EXECUTOR, "only executors");
        isExecutor[module] = true;
        IERC7579Module(module).onInstall(initData);
    }

    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        override
        returns (bytes[] memory returnData)
    {
        require(isExecutor[msg.sender], "not executor");
        require(mode == bytes32(0), "unsupported mode");
        address target = address(bytes20(executionCalldata[0:20]));
        uint256 value = uint256(bytes32(executionCalldata[20:52]));
        bytes calldata data = executionCalldata[52:];
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        returnData = new bytes[](1);
        returnData[0] = ret;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        return validator.isValidSignatureFor(address(this), hash, signature) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function owner() external view returns (address) {
        return validator.owner(address(this));
    }
}
