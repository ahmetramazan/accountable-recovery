//! Thin safe wrappers around the blst bindings for BLS12-381, with the EIP-2537 encodings.

use blst::*;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use std::sync::OnceLock;

pub const DST_H0: &[u8] = b"AKR-V01-H0-BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub const DST_H1: &[u8] = b"AKR-V01-H1-BLS12381G1_XMD:SHA-256_SSWU_RO_";

const P_HEX: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
const R_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

pub fn order() -> &'static BigUint {
    static R: OnceLock<BigUint> = OnceLock::new();
    R.get_or_init(|| BigUint::parse_bytes(R_HEX.as_bytes(), 16).unwrap())
}

fn p_bytes() -> &'static [u8; 48] {
    static P: OnceLock<[u8; 48]> = OnceLock::new();
    P.get_or_init(|| hex::decode(P_HEX).unwrap().try_into().unwrap())
}

// ----------------------------------------------------------------------------
// Scalars
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar(pub BigUint);

impl Scalar {
    pub fn zero() -> Self {
        Scalar(BigUint::zero())
    }
    pub fn from_u64(v: u64) -> Self {
        Scalar(BigUint::from(v) % order())
    }
    pub fn random() -> Self {
        let mut b = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut b);
        Scalar(BigUint::from_bytes_be(&b) % order())
    }
    /// Reduces a big-endian byte string modulo r.
    pub fn from_be_bytes_wide(b: &[u8]) -> Self {
        Scalar(BigUint::from_bytes_be(b) % order())
    }
    pub fn add(&self, o: &Scalar) -> Scalar {
        Scalar((&self.0 + &o.0) % order())
    }
    pub fn sub(&self, o: &Scalar) -> Scalar {
        Scalar((&self.0 + order() - &o.0) % order())
    }
    pub fn mul(&self, o: &Scalar) -> Scalar {
        Scalar((&self.0 * &o.0) % order())
    }
    pub fn inv(&self) -> Scalar {
        assert!(!self.0.is_zero());
        Scalar(self.0.modpow(&(order() - BigUint::from(2u8)), order()))
    }
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }
    pub fn to_be32(&self) -> [u8; 32] {
        let v = self.0.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(&v);
        out
    }
    pub fn to_le32(&self) -> [u8; 32] {
        let mut out = self.to_be32();
        out.reverse();
        out
    }
}

// ----------------------------------------------------------------------------
// Field elements
// ----------------------------------------------------------------------------

fn fp_to_eip(fp: &blst_fp, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 64);
    out[..16].fill(0);
    unsafe { blst_bendian_from_fp(out[16..].as_mut_ptr(), fp) };
}

fn fp_from_eip(b: &[u8]) -> Option<blst_fp> {
    if b.len() != 64 || b[..16].iter().any(|&x| x != 0) {
        return None;
    }
    let v: &[u8] = &b[16..];
    if v >= &p_bytes()[..] {
        return None; // not reduced
    }
    let mut fp = blst_fp::default();
    unsafe { blst_fp_from_bendian(&mut fp, v.as_ptr()) };
    Some(fp)
}

// ----------------------------------------------------------------------------
// G1
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct G1(pub blst_p1);

impl G1 {
    pub fn generator() -> Self {
        unsafe { G1(*blst_p1_generator()) }
    }
    pub fn identity() -> Self {
        G1(blst_p1::default())
    }
    pub fn mul(&self, s: &Scalar) -> Self {
        let b = s.to_le32();
        let mut out = blst_p1::default();
        unsafe { blst_p1_mult(&mut out, &self.0, b.as_ptr(), 255) };
        G1(out)
    }
    pub fn add(&self, o: &G1) -> Self {
        let mut out = blst_p1::default();
        unsafe { blst_p1_add_or_double(&mut out, &self.0, &o.0) };
        G1(out)
    }
    pub fn neg(&self) -> Self {
        let mut out = self.0;
        unsafe { blst_p1_cneg(&mut out, true) };
        G1(out)
    }
    /// RFC 9380 hash to G1 (BLS12381G1_XMD:SHA-256_SSWU_RO_) with the given DST.
    pub fn hash(msg: &[u8], dst: &[u8]) -> Self {
        let mut out = blst_p1::default();
        unsafe {
            blst_hash_to_g1(&mut out, msg.as_ptr(), msg.len(), dst.as_ptr(), dst.len(), std::ptr::null(), 0)
        };
        G1(out)
    }
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p1_is_inf(&self.0) }
    }
    pub fn equals(&self, o: &G1) -> bool {
        unsafe { blst_p1_is_equal(&self.0, &o.0) }
    }
    pub fn affine(&self) -> blst_p1_affine {
        let mut a = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut a, &self.0) };
        a
    }
    pub fn to_eip(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        if self.is_identity() {
            return out;
        }
        let a = self.affine();
        fp_to_eip(&a.x, &mut out[..64]);
        fp_to_eip(&a.y, &mut out[64..]);
        out
    }
    /// Parses an EIP-2537 encoding and checks that the point lies in G1.
    pub fn from_eip(b: &[u8]) -> Option<Self> {
        if b.len() != 128 {
            return None;
        }
        if b.iter().all(|&x| x == 0) {
            return Some(G1::identity());
        }
        let a = blst_p1_affine { x: fp_from_eip(&b[..64])?, y: fp_from_eip(&b[64..])? };
        unsafe {
            if !blst_p1_affine_on_curve(&a) || !blst_p1_affine_in_g1(&a) {
                return None;
            }
            let mut p = blst_p1::default();
            blst_p1_from_affine(&mut p, &a);
            Some(G1(p))
        }
    }
}

// ----------------------------------------------------------------------------
// G2
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct G2(pub blst_p2);

impl G2 {
    pub fn generator() -> Self {
        unsafe { G2(*blst_p2_generator()) }
    }
    pub fn identity() -> Self {
        G2(blst_p2::default())
    }
    pub fn mul(&self, s: &Scalar) -> Self {
        let b = s.to_le32();
        let mut out = blst_p2::default();
        unsafe { blst_p2_mult(&mut out, &self.0, b.as_ptr(), 255) };
        G2(out)
    }
    /// Multiplication by a small integer (used in Horner evaluation of Feldman commitments).
    pub fn mul_small(&self, v: u64) -> Self {
        let b = v.to_le_bytes();
        let mut out = blst_p2::default();
        unsafe { blst_p2_mult(&mut out, &self.0, b.as_ptr(), 64) };
        G2(out)
    }
    pub fn add(&self, o: &G2) -> Self {
        let mut out = blst_p2::default();
        unsafe { blst_p2_add_or_double(&mut out, &self.0, &o.0) };
        G2(out)
    }
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p2_is_inf(&self.0) }
    }
    pub fn equals(&self, o: &G2) -> bool {
        unsafe { blst_p2_is_equal(&self.0, &o.0) }
    }
    pub fn affine(&self) -> blst_p2_affine {
        let mut a = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut a, &self.0) };
        a
    }
    /// EIP-2537 encoding x.c0 || x.c1 || y.c0 || y.c1.
    pub fn to_eip(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        if self.is_identity() {
            return out;
        }
        let a = self.affine();
        fp_to_eip(&a.x.fp[0], &mut out[..64]);
        fp_to_eip(&a.x.fp[1], &mut out[64..128]);
        fp_to_eip(&a.y.fp[0], &mut out[128..192]);
        fp_to_eip(&a.y.fp[1], &mut out[192..]);
        out
    }
}

// ----------------------------------------------------------------------------
// Pairing
// ----------------------------------------------------------------------------

/// Checks prod e(P_i, Q_i) = 1.
pub fn pairing_product_is_one(pairs: &[(G1, G2)]) -> bool {
    unsafe {
        let mut acc = *blst_fp12_one();
        for (p, q) in pairs {
            if p.is_identity() || q.is_identity() {
                continue;
            }
            let pa = p.affine();
            let qa = q.affine();
            let mut f = blst_fp12::default();
            blst_miller_loop(&mut f, &qa, &pa);
            let mut t = blst_fp12::default();
            blst_fp12_mul(&mut t, &acc, &f);
            acc = t;
        }
        let mut out = blst_fp12::default();
        blst_final_exp(&mut out, &acc);
        blst_fp12_is_one(&out)
    }
}

/// BLS verification with signatures in G1: e(sig, g2) = e(H(msg), pk).
pub fn bls_verify(pk: &G2, msg: &[u8], sig: &G1, dst: &[u8]) -> bool {
    let h = G1::hash(msg, dst);
    pairing_product_is_one(&[(sig.neg(), G2::generator()), (h, *pk)])
}

pub fn bls_sign(sk: &Scalar, msg: &[u8], dst: &[u8]) -> G1 {
    G1::hash(msg, dst).mul(sk)
}
