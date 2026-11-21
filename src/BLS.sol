// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BLS12-381 helpers on top of the EIP-2537 precompiles (Prague).
/// @notice Encodings follow EIP-2537: an element of Fp is 64 bytes (16 zero bytes followed by the
///         48-byte big-endian value), a point of G1 is 128 bytes (x || y), a point of G2 is 256 bytes
///         (x.c0 || x.c1 || y.c0 || y.c1), and the point at infinity is all zeros.
/// @dev    The MSM and pairing precompiles check membership in the prime-order subgroups; the
///         addition precompiles do not. A precompile that fails consumes all gas forwarded to it, so
///         every call forwards an explicit upper bound on its price and first checks that this bound
///         is really available. Otherwise the sender of a transaction could make a valid input fail
///         by providing too little gas.
library BLS {
    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);
    address internal constant G2MSM = address(0x0e);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);
    address internal constant MODEXP = address(0x05);

    /// @dev Order of G1, G2 and GT.
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @dev 2^256 mod R, used to reduce 512-bit hash outputs modulo R.
    uint256 internal constant TWO256_MOD_R = 0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe;

    /// @dev Base-field modulus p (48 bytes).
    bytes internal constant P_BYTES =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    /// @dev The negation of the generator of G2, so that e(a, g2) = e(b, Q) is checked as
    ///      e(a, -g2) * e(b, Q) = 1 with a single pairing call.
    bytes internal constant NEG_G2 =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    uint256 internal constant G1_LEN = 128;
    uint256 internal constant G2_LEN = 256;

    error InsufficientGas();

    // ------------------------------------------------------------------
    // Raw precompile calls
    // ------------------------------------------------------------------

    function _static(address precompile, bytes memory input, uint256 gasBound, uint256 outLen)
        private
        view
        returns (bool ok, bytes memory out)
    {
        // Make sure that a failure can only come from the input, not from a lack of gas.
        if (gasleft() < gasBound + gasBound / 63 + 5000) revert InsufficientGas();
        out = new bytes(outLen);
        assembly ("memory-safe") {
            ok := staticcall(gasBound, precompile, add(input, 32), mload(input), add(out, 32), outLen)
            if ok { ok := eq(returndatasize(), outLen) }
        }
    }

    /// @notice Multi-scalar multiplication in G1. `input` is k pairs (point || 32-byte scalar).
    function g1Msm(bytes memory input) internal view returns (bool ok, bytes memory out) {
        uint256 k = input.length / 160;
        // The price is k * 12000 * discount(k) / 1000 with discount(k) <= 1000.
        return _static(G1MSM, input, k * 12000, G1_LEN);
    }

    /// @notice Multi-scalar multiplication in G2. `input` is k pairs (point || 32-byte scalar).
    function g2Msm(bytes memory input) internal view returns (bool ok, bytes memory out) {
        uint256 k = input.length / 288;
        return _static(G2MSM, input, k * 22500, G2_LEN);
    }

    /// @notice Pairing check. `input` is k pairs (G1 point || G2 point). Returns (call ok, product == 1).
    function pairing(bytes memory input) internal view returns (bool ok, bool result) {
        uint256 k = input.length / 384;
        bytes memory out;
        (ok, out) = _static(PAIRING, input, 32600 * k + 37700, 32);
        if (ok) result = uint8(out[31]) == 1;
    }

    // ------------------------------------------------------------------
    // Hash to G1 (RFC 9380, BLS12381G1_XMD:SHA-256_SSWU_RO_)
    // ------------------------------------------------------------------

    /// @notice Hashes `msg` to G1 with domain separation tag `dst` (at most 255 bytes).
    /// @dev    hash_to_field with expand_message_xmd (SHA-256), reduction modulo p with MODEXP,
    ///         two calls of MAP_FP_TO_G1 (which includes cofactor clearing) and one G1ADD. Since
    ///         cofactor clearing is a homomorphism, clear(Q0) + clear(Q1) = clear(Q0 + Q1).
    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        (bytes memory u0, bytes memory u1) = _hashToField2(message, dst);
        (bool ok0, bytes memory q0) = _static(MAP_FP_TO_G1, u0, 5500, G1_LEN);
        (bool ok1, bytes memory q1) = _static(MAP_FP_TO_G1, u1, 5500, G1_LEN);
        require(ok0 && ok1, "BLS: map");
        (bool ok2, bytes memory h) = _static(G1ADD, bytes.concat(q0, q1), 375, G1_LEN);
        require(ok2, "BLS: add");
        return h;
    }

    function _hashToField2(bytes memory message, bytes memory dst)
        private
        view
        returns (bytes memory u0, bytes memory u1)
    {
        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));
        // msg_prime = Z_pad || msg || I2OSP(len_in_bytes = 128, 2) || I2OSP(0, 1) || DST_prime
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), message, uint16(128), uint8(0), dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), dstPrime));
        bytes32 b3 = sha256(abi.encodePacked(b0 ^ b2, uint8(3), dstPrime));
        bytes32 b4 = sha256(abi.encodePacked(b0 ^ b3, uint8(4), dstPrime));
        u0 = _modP(b1, b2);
        u1 = _modP(b3, b4);
    }

    /// @dev Reduces the 64-byte big-endian integer hi || lo modulo p and returns it as a 64-byte
    ///      EIP-2537 field element.
    function _modP(bytes32 hi, bytes32 lo) private view returns (bytes memory fe) {
        bytes memory input = abi.encodePacked(uint256(64), uint256(1), uint256(48), hi, lo, uint8(1), P_BYTES);
        bytes memory r48 = new bytes(48);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x05, add(input, 32), mload(input), add(r48, 32), 48)
        }
        require(ok, "BLS: modexp");
        fe = bytes.concat(bytes16(0), r48);
    }

    // ------------------------------------------------------------------
    // Scalars
    // ------------------------------------------------------------------

    /// @notice Reduces the 512-bit value keccak(seed || 0x00) || keccak(seed || 0x01) modulo R.
    function hashToScalar(bytes memory seed) internal pure returns (uint256) {
        uint256 a = uint256(keccak256(abi.encodePacked(seed, uint8(0))));
        uint256 b = uint256(keccak256(abi.encodePacked(seed, uint8(1))));
        return addmod(mulmod(a, TWO256_MOD_R, R), b % R, R);
    }

    // ------------------------------------------------------------------
    // Signatures
    // ------------------------------------------------------------------

    /// @notice BLS verification with signatures in G1 and keys in G2: e(sig, g2) = e(H(msg), pk).
    /// @dev    Returns false (and does not revert) if a point is not in its subgroup.
    function verify(bytes memory pk, bytes memory message, bytes memory sig, bytes memory dst)
        internal
        view
        returns (bool)
    {
        if (pk.length != G2_LEN || sig.length != G1_LEN) return false;
        bytes memory h = hashToG1(message, dst);
        (bool ok, bool res) = pairing(bytes.concat(sig, NEG_G2, h, pk));
        return ok && res;
    }

    /// @notice Checks g^a * X^b == Y in G1, i.e. one two-point MSM and a comparison.
    function checkTwoMsm(bytes memory g, uint256 a, bytes memory x, uint256 b, bytes memory y)
        internal
        view
        returns (bool ok, bool equal)
    {
        bytes memory out;
        (ok, out) = g1Msm(abi.encodePacked(g, a, x, b));
        if (ok) equal = keccak256(out) == keccak256(y);
    }
}
