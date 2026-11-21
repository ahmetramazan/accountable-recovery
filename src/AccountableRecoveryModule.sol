// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS} from "./BLS.sol";
import {
    IERC7579Module,
    IERC7579Account,
    IERC1271,
    IOwnerValidator,
    MODULE_TYPE_EXECUTOR
} from "./interfaces/IERC7579.sol";

/// @title Accountable key recovery with dispute windows (ERC-7579 executor module)
/// @notice Implements the account contract of Section 3.1 of the paper with the construction of
///         Section 4: a recovery request carries a threshold BLS approval sigma on (m, ct) and a
///         tracing ciphertext ct = (R, c, pi_R); it can be cancelled by the owner or disputed by the
///         auditor during a window of `delta` blocks, and is executed with Finalize afterwards.
/// @dev    One module instance serves every account that installs it. For each account the module
///         stores hashes of the public parameters (PK, PK_T and the list of evidence keys) instead of
///         the points themselves; each transaction passes the points it needs as calldata, which is
///         cheaper than reading 8 storage slots per point of G2. Rounds are block numbers.
contract AccountableRecoveryModule is IERC7579Module {
    // ------------------------------------------------------------------
    // Domain separation
    // ------------------------------------------------------------------

    /// @dev DST of H0 (threshold signatures: approvals and tagged messages).
    bytes internal constant DST_H0 = "AKR-V01-H0-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    /// @dev DST of H1 (evidence signatures, signatures under evidence keys, proofs of possession).
    bytes internal constant DST_H1 = "AKR-V01-H1-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;
    uint256 internal constant MAX_GUARDIANS = 256;

    // ------------------------------------------------------------------
    // Types and storage
    // ------------------------------------------------------------------

    /// @notice Tracing ciphertext ct = (R, c, pi_R) with pi_R = (A, z).
    struct Ciphertext {
        bytes R; // G1, 128 bytes
        bytes c; // AE ciphertext of the payload (beta, Y_1, ..., Y_n)
        bytes A; // G1, 128 bytes (Schnorr commitment)
        uint256 z; // Schnorr response
    }

    /// @notice Tracing proof pi = (K, pi_K) with pi_K = (U1, U2, z).
    struct TracingProof {
        bytes K; // G1, 128 bytes
        bytes U1; // G1
        bytes U2; // G1
        uint256 z;
    }

    /// @notice One condition of the governance policy: at least `k` guardians from `mask`
    ///         (bit i-1 of the mask stands for guardian i). A set satisfies the policy if it
    ///         satisfies every rule.
    struct Rule {
        uint256 mask;
        uint256 k;
    }

    struct Config {
        bytes32 pkHash; // keccak256(PK)
        bytes32 pkTHash; // keccak256(PK_T)
        bytes32 epkHash; // keccak256(EPK_1 || ... || EPK_n)
        bytes32 cgov; // commitment to the governance policy
        address validator; // validator module whose owner key Finalize replaces
        uint64 epoch;
        uint16 n;
        uint16 t;
        // pending request pend = (m, h(sigma, ct), r0); m = (account, newOwner, epoch)
        address pendOwner;
        uint64 pendRound;
        uint32 delta;
        bytes32 pendDigest;
    }

    mapping(address account => Config) internal _configs;

    // ------------------------------------------------------------------
    // Events and errors
    // ------------------------------------------------------------------

    event Requested(address indexed account, address indexed newOwner, uint64 epoch, bytes32 digest);
    event Cancelled(address indexed account, uint64 epoch);
    /// @param outcome bitmask of the evidence set for a policy dispute, or 0 for the outcome bad.
    event Disputed(address indexed account, uint64 epoch, bool bad, uint256 outcome);
    event Finalized(address indexed account, address indexed newOwner, uint64 epoch);
    event Advanced(address indexed account, uint64 epoch);
    event KeyUpdated(address indexed account, uint256 indexed guardian, uint64 epoch);

    error NotInstalled();
    error AlreadyInstalled();
    error BadParameters();
    error RequestPending();
    error NoRequestPending();
    error WindowClosed();
    error WindowOpen();
    error WrongPublicParameters();
    error InvalidApproval();
    error InvalidProof();
    error InvalidSignature();
    error DigestMismatch();
    error InvalidTracingProof();
    error NoViolation();
    error WrongPolicyOpening();

    // ------------------------------------------------------------------
    // ERC-7579 module interface
    // ------------------------------------------------------------------

    /// @param data abi.encode(PK, PK_T, EPKs, n, t, cgov, delta, validator)
    function onInstall(bytes calldata data) external override {
        Config storage cfg = _configs[msg.sender];
        if (cfg.n != 0) revert AlreadyInstalled();
        (
            bytes memory pk,
            bytes memory pkT,
            bytes memory epks,
            uint16 n,
            uint16 t,
            bytes32 cgov,
            uint32 delta,
            address validator
        ) = abi.decode(data, (bytes, bytes, bytes, uint16, uint16, bytes32, uint32, address));
        if (
            n == 0 || n > MAX_GUARDIANS || t == 0 || t > n || pk.length != BLS.G2_LEN || pkT.length != BLS.G1_LEN
                || epks.length != uint256(n) * BLS.G2_LEN || delta == 0 || validator == address(0)
        ) revert BadParameters();
        cfg.pkHash = keccak256(pk);
        cfg.pkTHash = keccak256(pkT);
        cfg.epkHash = keccak256(epks);
        cfg.cgov = cgov;
        cfg.validator = validator;
        cfg.n = n;
        cfg.t = t;
        cfg.delta = delta;
    }

    function onUninstall(bytes calldata) external override {
        delete _configs[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _configs[account].n != 0;
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getConfig(address account) external view returns (Config memory) {
        return _configs[account];
    }

    /// @notice Digest of the request m = (id, pk', e), where id = (chain, module, account).
    function requestDigest(address account, address newOwner, uint256 epoch) public view returns (bytes32) {
        return keccak256(abi.encodePacked("AKR.request", block.chainid, address(this), account, newOwner, epoch));
    }

    /// @notice Message signed by the owner to cancel the pending request m.
    function cancelDigest(bytes32 mDigest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("AKR.cancel", mDigest));
    }

    function advanceDigest(address account, uint256 epoch) public view returns (bytes32) {
        return keccak256(abi.encodePacked("AKR.advance", block.chainid, address(this), account, epoch));
    }

    function updateDigest(address account, uint256 epoch, uint256 i, bytes memory newEpk)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("AKR.update", block.chainid, address(this), account, epoch, i, newEpk));
    }

    function popDigest(address account, uint256 i, bytes memory newEpk) public view returns (bytes32) {
        return keccak256(abi.encodePacked("AKR.pop", block.chainid, address(this), account, i, newEpk));
    }

    // ------------------------------------------------------------------
    // Request
    // ------------------------------------------------------------------

    /// @notice Request(m, sigma, ct): stores pend = (m, h(sigma, ct), r) if Verify(pp, m, sigma, ct) = 1.
    function request(address account, address newOwner, bytes calldata pk, bytes calldata sigma, Ciphertext calldata ct)
        external
    {
        Config storage cfg = _configs[account];
        if (cfg.n == 0) revert NotInstalled();
        if (cfg.pendRound != 0) revert RequestPending();
        if (keccak256(pk) != cfg.pkHash) revert WrongPublicParameters();
        if (ct.R.length != BLS.G1_LEN || ct.A.length != BLS.G1_LEN || sigma.length != BLS.G1_LEN) {
            revert InvalidApproval();
        }
        bytes32 m = requestDigest(account, newOwner, cfg.epoch);
        bytes32 cHash = keccak256(ct.c);

        // Sch.Verify(R, (m, c), pi_R): g1^z * R^(-h) == A, with h = H4((m, c), R, A).
        {
            uint256 h = BLS.hashToScalar(abi.encodePacked("AKR.H4", m, ct.R, ct.A, cHash));
            (bool ok, bool eq) = BLS.checkTwoMsm(BLS.G1_GEN, ct.z, ct.R, BLS.R - h, ct.A);
            if (!ok || !eq) revert InvalidProof();
        }
        // TBLS.Verify(PK, (m, ct), sigma) with H0.
        {
            bytes32 mu = keccak256(abi.encodePacked("AKR.approve", m, ct.R, ct.A, ct.z, cHash));
            if (!BLS.verify(pk, abi.encodePacked(mu), sigma, DST_H0)) revert InvalidApproval();
        }

        bytes32 d = keccak256(abi.encodePacked(sigma, ct.R, ct.A, ct.z, ct.c));
        cfg.pendOwner = newOwner;
        cfg.pendRound = uint64(block.number);
        cfg.pendDigest = d;
        emit Requested(account, newOwner, cfg.epoch, d);
    }

    // ------------------------------------------------------------------
    // Cancel
    // ------------------------------------------------------------------

    /// @notice Cancel(phi): phi is checked by the account through ERC-1271, i.e. by its validator
    ///         and the current owner key.
    function cancel(address account, bytes calldata phi) external {
        Config storage cfg = _configs[account];
        _requireOpenWindow(cfg);
        bytes32 m = requestDigest(account, cfg.pendOwner, cfg.epoch);
        if (IERC1271(account).isValidSignature(cancelDigest(m), phi) != ERC1271_MAGIC) revert InvalidSignature();
        uint64 e = cfg.epoch;
        _clearAndAdvance(cfg);
        emit Cancelled(account, e);
    }

    // ------------------------------------------------------------------
    // Dispute
    // ------------------------------------------------------------------

    /// @notice Dispute(sigma, ct, pi, w). Succeeds if Judge outputs bad, or a set S that violates the
    ///         committed governance policy (opened by `policy` and `salt`); reverts otherwise.
    /// @param pkT the auditor key PK_T; @param epks EPK_1 || ... || EPK_n of the current epoch.
    function dispute(
        address account,
        bytes calldata sigma,
        Ciphertext calldata ct,
        TracingProof calldata pi,
        bytes calldata pkT,
        bytes calldata epks,
        bytes calldata policy,
        bytes32 salt
    ) external {
        Config storage cfg = _configs[account];
        _requireOpenWindow(cfg);
        if (keccak256(abi.encodePacked(sigma, ct.R, ct.A, ct.z, ct.c)) != cfg.pendDigest) revert DigestMismatch();
        if (keccak256(pkT) != cfg.pkTHash || keccak256(epks) != cfg.epkHash) revert WrongPublicParameters();
        if (pi.K.length != BLS.G1_LEN || pi.U1.length != BLS.G1_LEN || pi.U2.length != BLS.G1_LEN) {
            revert InvalidTracingProof();
        }

        // Judge, step 1: DLEQ.Verify(PK_T, R, K, pi_K), otherwise rej (the transaction reverts).
        {
            uint256 h = BLS.hashToScalar(abi.encodePacked("AKR.H3", pkT, ct.R, pi.K, pi.U1, pi.U2));
            (bool ok1, bool eq1) = BLS.checkTwoMsm(BLS.G1_GEN, pi.z, pkT, BLS.R - h, pi.U1);
            (bool ok2, bool eq2) = BLS.checkTwoMsm(ct.R, pi.z, pi.K, BLS.R - h, pi.U2);
            if (!ok1 || !eq1 || !ok2 || !eq2) revert InvalidTracingProof();
        }

        bytes32 m = requestDigest(account, cfg.pendOwner, cfg.epoch);
        // Judge, steps 2-4.
        (bool bad, uint256 sMask) = _judge(cfg, m, ct, pi.K, epks);

        if (!bad) {
            // Policy dispute: Viol(c_gov, S, w) = 1.
            if (keccak256(abi.encodePacked("AKR.gov", keccak256(policy), salt)) != cfg.cgov) {
                revert WrongPolicyOpening();
            }
            if (_satisfies(abi.decode(policy, (Rule[])), sMask)) revert NoViolation();
        }
        uint64 e = cfg.epoch;
        _clearAndAdvance(cfg);
        emit Disputed(account, e, bad, bad ? 0 : sMask);
    }

    /// @dev Decrypts c, parses the payload and checks the evidence signatures with one batched
    ///      pairing check: e(sum r_i Y_i, g2) = e(H1(m), sum r_i EPK_i), with coefficients r_i
    ///      derived by the contract from the dispute inputs.
    function _judge(Config storage cfg, bytes32 m, Ciphertext calldata ct, bytes calldata K, bytes calldata epks)
        internal
        view
        returns (bool bad, uint256 sMask)
    {
        uint256 n = cfg.n;
        uint256 nb = (n + 7) / 8;
        if (ct.c.length != nb + n * BLS.G1_LEN) return (true, 0);

        bytes memory p = _decrypt(keccak256(abi.encodePacked("AKR.kdf", ct.R, K)), ct.c);

        // beta: guardian i corresponds to bit (i-1) % 8 of byte (i-1) / 8.
        uint256 s;
        for (uint256 i = 0; i < n; ++i) {
            if ((uint8(p[i / 8]) >> (i % 8)) & 1 == 1) {
                sMask |= 1 << i;
                ++s;
            }
        }
        // Padding bits of beta must be zero.
        if (n % 8 != 0 && (uint8(p[nb - 1]) >> (n % 8)) != 0) return (true, 0);
        if (s < cfg.t) return (true, 0);

        bytes32 seed = keccak256(abi.encodePacked("AKR.batch", cfg.pendDigest, K));
        bytes memory g1in = new bytes(s * 160);
        bytes memory g2in = new bytes(s * 288);
        uint256 j;
        for (uint256 i = 0; i < n; ++i) {
            uint256 yOff = nb + i * BLS.G1_LEN; // offset of Y_{i+1} in p
            if (sMask & (1 << i) == 0) {
                // Y_i must be the identity (all zeros) for i not in S.
                bool zero;
                assembly ("memory-safe") {
                    let q := add(add(p, 32), yOff)
                    zero := iszero(or(or(mload(q), mload(add(q, 32))), or(mload(add(q, 64)), mload(add(q, 96)))))
                }
                if (!zero) return (true, 0);
                continue;
            }
            uint256 r = uint256(keccak256(abi.encodePacked(seed, i + 1))) >> 128;
            if (r == 0) r = 1;
            bytes calldata epk = epks[i * BLS.G2_LEN:(i + 1) * BLS.G2_LEN];
            assembly ("memory-safe") {
                let dst1 := add(add(g1in, 32), mul(j, 160))
                mcopy(dst1, add(add(p, 32), yOff), 128)
                mstore(add(dst1, 128), r)
                let dst2 := add(add(g2in, 32), mul(j, 288))
                calldatacopy(dst2, epk.offset, 256)
                mstore(add(dst2, 256), r)
            }
            ++j;
        }

        (bool okY, bytes memory ySum) = BLS.g1Msm(g1in);
        if (!okY) return (true, 0); // some Y_i is not in G1
        (bool okE, bytes memory eSum) = BLS.g2Msm(g2in);
        require(okE, "AKR: evidence keys");
        bytes memory h1 = BLS.hashToG1(abi.encodePacked(m), DST_H1);
        (bool okP, bool res) = BLS.pairing(bytes.concat(ySum, BLS.NEG_G2, h1, eSum));
        require(okP, "AKR: pairing");
        if (!res) return (true, 0);
        return (false, sMask);
    }

    /// @dev AE.Dec_k(c) = c XOR kappa(k), kappa(k) = h(ks, k, 1) || h(ks, k, 2) || ...
    function _decrypt(bytes32 k, bytes calldata c) internal pure returns (bytes memory p) {
        p = c;
        bytes memory pre = abi.encodePacked("AKR.ks", k, uint256(0)); // 6 + 32 + 32 = 70 bytes
        uint256 len = p.length;
        assembly ("memory-safe") {
            let data := add(p, 32)
            let preData := add(pre, 32)
            for { let off := 0 } lt(off, len) { off := add(off, 32) } {
                mstore(add(preData, 38), add(div(off, 32), 1))
                let ks := keccak256(preData, 70)
                mstore(add(data, off), xor(mload(add(data, off)), ks))
            }
        }
    }

    function _satisfies(Rule[] memory rules, uint256 sMask) internal pure returns (bool) {
        for (uint256 i = 0; i < rules.length; ++i) {
            if (_popcount(rules[i].mask & sMask) < rules[i].k) return false;
        }
        return true;
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            ++c;
        }
    }

    // ------------------------------------------------------------------
    // Finalize
    // ------------------------------------------------------------------

    /// @notice Finalize: after the window, replaces the owner key in the validator of the account.
    function finalize(address account) external {
        Config storage cfg = _configs[account];
        if (cfg.pendRound == 0) revert NoRequestPending();
        if (block.number < uint256(cfg.pendRound) + cfg.delta) revert WindowOpen();
        address newOwner = cfg.pendOwner;
        address validator = cfg.validator;
        uint64 e = cfg.epoch;
        _clearAndAdvance(cfg);
        IERC7579Account(account).executeFromExecutor(
            bytes32(0), abi.encodePacked(validator, uint256(0), abi.encodeCall(IOwnerValidator.setOwner, (newOwner)))
        );
        emit Finalized(account, newOwner, e);
    }

    // ------------------------------------------------------------------
    // Advance and UpdateKey
    // ------------------------------------------------------------------

    /// @notice Advance(sigma_a): starts a new epoch with a threshold signature on (advance, id, e).
    function advance(address account, bytes calldata pk, bytes calldata sigmaA) external {
        Config storage cfg = _configs[account];
        if (cfg.n == 0) revert NotInstalled();
        if (cfg.pendRound != 0) revert RequestPending();
        if (keccak256(pk) != cfg.pkHash) revert WrongPublicParameters();
        bytes32 mu = advanceDigest(account, cfg.epoch);
        if (!BLS.verify(pk, abi.encodePacked(mu), sigmaA, DST_H0)) revert InvalidSignature();
        uint64 e = cfg.epoch;
        cfg.epoch = e + 1;
        emit Advanced(account, e);
    }

    /// @notice UpdateKey(i, EPK_i', psi, phi_i, sigma_u): replaces the evidence key of guardian i.
    function updateKey(
        address account,
        uint256 i,
        bytes calldata newEpk,
        bytes calldata psi,
        bytes calldata phi,
        bytes calldata sigmaU,
        bytes calldata pk,
        bytes calldata epks
    ) external {
        Config storage cfg = _configs[account];
        if (cfg.n == 0) revert NotInstalled();
        if (cfg.pendRound != 0) revert RequestPending();
        if (i == 0 || i > cfg.n || newEpk.length != BLS.G2_LEN) revert BadParameters();
        if (keccak256(pk) != cfg.pkHash || keccak256(epks) != cfg.epkHash) revert WrongPublicParameters();

        bytes memory mu = abi.encodePacked(updateDigest(account, cfg.epoch, i, newEpk));
        // Threshold signature of the guardians on (update, id, e, i, EPK_i').
        if (!BLS.verify(pk, mu, sigmaU, DST_H0)) revert InvalidSignature();
        // Signature of guardian i under its current evidence key.
        if (!BLS.verify(epks[(i - 1) * BLS.G2_LEN:i * BLS.G2_LEN], mu, phi, DST_H1)) revert InvalidSignature();
        // Proof of possession of the new key.
        if (!BLS.verify(newEpk, abi.encodePacked(popDigest(account, i, newEpk)), psi, DST_H1)) {
            revert InvalidProof();
        }

        cfg.epkHash = keccak256(abi.encodePacked(epks[:(i - 1) * BLS.G2_LEN], newEpk, epks[i * BLS.G2_LEN:]));
        uint64 e = cfg.epoch;
        cfg.epoch = e + 1;
        emit KeyUpdated(account, i, e);
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    function _requireOpenWindow(Config storage cfg) internal view {
        if (cfg.pendRound == 0) revert NoRequestPending();
        if (block.number >= uint256(cfg.pendRound) + cfg.delta) revert WindowClosed();
    }

    function _clearAndAdvance(Config storage cfg) internal {
        cfg.pendOwner = address(0);
        cfg.pendRound = 0;
        cfg.pendDigest = bytes32(0);
        cfg.epoch += 1;
    }
}
