//! The accountable recovery scheme of Section 4 of the paper: setup (DKG), the two-round Approve
//! protocol, Combine, Trace and Judge, refresh-free key update, and the encodings that the
//! Solidity module uses for the same values.

use crate::abi::keccak;
use crate::bls::*;

// ----------------------------------------------------------------------------
// Encodings shared with the contract
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Domain {
    pub chain_id: u64,
    pub module: [u8; 20],
    pub account: [u8; 20],
}

fn u256(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

impl Domain {
    /// m = (id, pk', e), id = (chain, module, account).
    pub fn request_digest(&self, new_owner: &[u8; 20], epoch: u64) -> [u8; 32] {
        keccak(&cat(&[b"AKR.request", &u256(self.chain_id), &self.module, &self.account, new_owner, &u256(epoch)]))
    }
    pub fn advance_digest(&self, epoch: u64) -> [u8; 32] {
        keccak(&cat(&[b"AKR.advance", &u256(self.chain_id), &self.module, &self.account, &u256(epoch)]))
    }
    pub fn update_digest(&self, epoch: u64, i: usize, new_epk: &G2) -> [u8; 32] {
        keccak(&cat(&[
            b"AKR.update",
            &u256(self.chain_id),
            &self.module,
            &self.account,
            &u256(epoch),
            &u256(i as u64),
            &new_epk.to_eip(),
        ]))
    }
    pub fn pop_digest(&self, i: usize, new_epk: &G2) -> [u8; 32] {
        keccak(&cat(&[b"AKR.pop", &u256(self.chain_id), &self.module, &self.account, &u256(i as u64), &new_epk.to_eip()]))
    }
}

pub fn cancel_digest(m: &[u8; 32]) -> [u8; 32] {
    keccak(&cat(&[b"AKR.cancel", m]))
}

/// H3, H4: 512-bit hash reduced modulo r.
pub fn hash_to_scalar(seed: &[u8]) -> Scalar {
    let a = keccak(&cat(&[seed, &[0u8]]));
    let b = keccak(&cat(&[seed, &[1u8]]));
    Scalar::from_be_bytes_wide(&cat(&[&a, &b]))
}

fn schnorr_challenge(m: &[u8; 32], r: &G1, a: &G1, c: &[u8]) -> Scalar {
    hash_to_scalar(&cat(&[b"AKR.H4", m, &r.to_eip(), &a.to_eip(), &keccak(c)]))
}

fn dleq_challenge(pk_t: &G1, r: &G1, k: &G1, u1: &G1, u2: &G1) -> Scalar {
    hash_to_scalar(&cat(&[b"AKR.H3", &pk_t.to_eip(), &r.to_eip(), &k.to_eip(), &u1.to_eip(), &u2.to_eip()]))
}

fn kdf(r: &G1, k: &G1) -> [u8; 32] {
    keccak(&cat(&[b"AKR.kdf", &r.to_eip(), &k.to_eip()]))
}

/// AE.Enc_k = AE.Dec_k: XOR with h(ks, k, 1) || h(ks, k, 2) || ...
pub fn ae_xor(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (blk, chunk) in out.chunks_mut(32).enumerate() {
        let ks = keccak(&cat(&[b"AKR.ks", key, &u256(blk as u64 + 1)]));
        for (x, y) in chunk.iter_mut().zip(ks.iter()) {
            *x ^= y;
        }
    }
    out
}

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub r: G1,
    pub c: Vec<u8>,
    pub a: G1,
    pub z: Scalar,
}

impl Ciphertext {
    /// Size of ct as passed to the contract: R, A (uncompressed), c, z.
    pub fn size(&self) -> usize {
        128 + self.c.len() + 128 + 32
    }
}

#[derive(Clone, Debug)]
pub struct Approval {
    pub m: [u8; 32],
    pub new_owner: [u8; 20],
    pub epoch: u64,
    pub sigma: G1,
    pub ct: Ciphertext,
}

impl Approval {
    pub fn approve_digest(&self) -> [u8; 32] {
        approve_digest(&self.m, &self.ct)
    }
}

pub fn approve_digest(m: &[u8; 32], ct: &Ciphertext) -> [u8; 32] {
    keccak(&cat(&[b"AKR.approve", m, &ct.r.to_eip(), &ct.a.to_eip(), &ct.z.to_be32(), &keccak(&ct.c)]))
}

#[derive(Clone, Debug)]
pub struct TracingProof {
    pub k: G1,
    pub u1: G1,
    pub u2: G1,
    pub z: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Rej,
    Bad,
    Set(Vec<usize>),
}

/// "At least k guardians from mask" (bit i-1 = guardian i).
#[derive(Clone, Debug)]
pub struct Rule {
    pub members: Vec<usize>,
    pub k: u64,
}

pub fn mask_word(members: &[usize]) -> [u8; 32] {
    let mut w = [0u8; 32];
    for &i in members {
        let bit = i - 1;
        w[31 - bit / 8] |= 1 << (bit % 8);
    }
    w
}

pub fn policy_abi(rules: &[Rule]) -> Vec<u8> {
    use crate::abi::*;
    encode(&[Tok::StaticTupleArray(
        rules.iter().map(|r| vec![mask_word(&r.members), u256(r.k)]).collect(),
    )])
}

pub fn policy_allows(rules: &[Rule], s: &[usize]) -> bool {
    rules.iter().all(|r| s.iter().filter(|i| r.members.contains(i)).count() as u64 >= r.k)
}

// ----------------------------------------------------------------------------
// Setup: distributed key generation (joint Feldman over G2)
// ----------------------------------------------------------------------------

pub struct DkgOutput {
    pub shares: Vec<Scalar>, // shares[i-1] = F(i)
    pub pk: G2,
    pub vks: Vec<G2>, // PK_i = g2^{F(i)}
}

fn eval_poly(coeffs: &[Scalar], x: u64) -> Scalar {
    let xs = Scalar::from_u64(x);
    let mut acc = Scalar::zero();
    for c in coeffs.iter().rev() {
        acc = acc.mul(&xs).add(c);
    }
    acc
}

fn eval_commitments(comms: &[G2], x: u64) -> G2 {
    let mut acc = G2::identity();
    for c in comms.iter().rev() {
        acc = acc.mul_small(x).add(c);
    }
    acc
}

/// Runs the DKG of Section 4.1 for n parties with threshold t, with all parties honest, executing
/// every check that a party performs (the cost of the GJKR variant is the same up to the extra
/// Pedersen commitments of its first phase).
pub fn dkg(n: usize, t: usize) -> DkgOutput {
    let g2 = G2::generator();
    let polys: Vec<Vec<Scalar>> = (0..n).map(|_| (0..t).map(|_| Scalar::random()).collect()).collect();
    let comms: Vec<Vec<G2>> = polys.iter().map(|p| p.iter().map(|a| g2.mul(a)).collect()).collect();
    let mut shares = Vec::with_capacity(n);
    for j in 1..=n as u64 {
        let mut sk = Scalar::zero();
        for i in 0..n {
            let f = eval_poly(&polys[i], j);
            // party j checks g2^{F_i(j)} = prod_k A_ik^{j^k}
            assert!(g2.mul(&f).equals(&eval_commitments(&comms[i], j)), "DKG complaint");
            sk = sk.add(&f);
        }
        shares.push(sk);
    }
    let agg: Vec<G2> = (0..t).map(|k| comms.iter().fold(G2::identity(), |acc, c| acc.add(&c[k]))).collect();
    let pk = agg[0];
    let vks = (1..=n as u64).map(|j| eval_commitments(&agg, j)).collect();
    DkgOutput { shares, pk, vks }
}

// ----------------------------------------------------------------------------
// The system state known to the parties
// ----------------------------------------------------------------------------

pub struct System {
    pub dom: Domain,
    pub n: usize,
    pub t: usize,
    pub shares: Vec<Scalar>,
    pub pk: G2,
    pub vks: Vec<G2>,
    pub esks: Vec<Scalar>,
    pub epks: Vec<G2>,
    pub sk_t: Scalar,
    pub pk_t: G1,
    pub rules: Vec<Rule>,
    pub salt: [u8; 32],
}

impl System {
    pub fn setup(dom: Domain, n: usize, t: usize, rules: Vec<Rule>) -> System {
        let d = dkg(n, t);
        let esks: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        let epks = esks.iter().map(|s| G2::generator().mul(s)).collect();
        let sk_t = Scalar::random();
        let pk_t = G1::generator().mul(&sk_t);
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        System { dom, n, t, shares: d.shares, pk: d.pk, vks: d.vks, esks, epks, sk_t, pk_t, rules, salt }
    }

    pub fn cgov(&self) -> [u8; 32] {
        keccak(&cat(&[b"AKR.gov", &keccak(&policy_abi(&self.rules)), &self.salt]))
    }

    pub fn epks_concat(&self) -> Vec<u8> {
        self.epks.iter().flat_map(|e| e.to_eip()).collect()
    }

    pub fn payload_len(&self) -> usize {
        self.n.div_ceil(8) + 128 * self.n
    }

    // ---------------- Approve, round 1 ----------------

    /// Guardian i (1-based): evidence signature tau_i = H1(m)^{esk_i}.
    pub fn guardian_evidence(&self, i: usize, m: &[u8; 32]) -> G1 {
        bls_sign(&self.esks[i - 1], m, DST_H1)
    }

    /// Combiner: keeps the valid evidence signatures and forms ct = (R, c, pi_R).
    /// `forge` replaces the evidence of one guardian after the check (a malicious combiner).
    pub fn combiner_round1(
        &self,
        m: &[u8; 32],
        taus: &[(usize, G1)],
        forge: Option<usize>,
    ) -> Option<(Vec<usize>, Ciphertext)> {
        let mut s: Vec<usize> =
            taus.iter().filter(|(i, tau)| bls_verify(&self.epks[i - 1], m, tau, DST_H1)).map(|(i, _)| *i).collect();
        s.sort();
        if s.len() < self.t {
            return None;
        }
        let nb = self.n.div_ceil(8);
        let mut p = vec![0u8; self.payload_len()];
        for (i, tau) in taus {
            if !s.contains(i) {
                continue;
            }
            p[(i - 1) / 8] |= 1 << ((i - 1) % 8);
            let y = if forge == Some(*i) { G1::hash(b"not the request", DST_H1).mul(&self.esks[i - 1]) } else { *tau };
            p[nb + 128 * (i - 1)..nb + 128 * i].copy_from_slice(&y.to_eip());
        }
        Some((s, self.encrypt_payload(m, &p)))
    }

    pub fn encrypt_payload(&self, m: &[u8; 32], p: &[u8]) -> Ciphertext {
        let rho = Scalar::random();
        let r = G1::generator().mul(&rho);
        let k = self.pk_t.mul(&rho);
        let c = ae_xor(&kdf(&r, &k), p);
        let u = Scalar::random();
        let a = G1::generator().mul(&u);
        let h = schnorr_challenge(m, &r, &a, &c);
        let z = u.add(&h.mul(&rho));
        Ciphertext { r, c, a, z }
    }

    // ---------------- Approve, round 2 ----------------

    pub fn schnorr_verify(m: &[u8; 32], ct: &Ciphertext) -> bool {
        let h = schnorr_challenge(m, &ct.r, &ct.a, &ct.c);
        G1::generator().mul(&ct.z).equals(&ct.a.add(&ct.r.mul(&h)))
    }

    /// Guardian i: checks pi_R and returns the partial signature H0(m, ct)^{sk_i}.
    pub fn guardian_partial(&self, i: usize, m: &[u8; 32], ct: &Ciphertext) -> Option<G1> {
        if !Self::schnorr_verify(m, ct) {
            return None;
        }
        Some(bls_sign(&self.shares[i - 1], &approve_digest(m, ct), DST_H0))
    }

    // ---------------- Combine ----------------

    pub fn combine(&self, mu: &[u8; 32], partials: &[(usize, G1)]) -> Option<G1> {
        let mut valid: Vec<(usize, G1)> =
            partials.iter().filter(|(i, s)| bls_verify(&self.vks[i - 1], mu, s, DST_H0)).cloned().collect();
        valid.sort_by_key(|(i, _)| *i);
        if valid.len() < self.t {
            return None;
        }
        Some(lagrange_combine(&valid[..self.t]))
    }

    /// Threshold signature on a tagged message (advance, update) by the first t guardians.
    pub fn threshold_sign(&self, mu: &[u8; 32]) -> G1 {
        let partials: Vec<(usize, G1)> =
            (1..=self.t).map(|i| (i, bls_sign(&self.shares[i - 1], mu, DST_H0))).collect();
        lagrange_combine(&partials)
    }

    /// Runs Approve and Combine for request (newOwner, epoch) with approving set `set`.
    pub fn approve(&self, new_owner: [u8; 20], epoch: u64, set: &[usize], forge: Option<usize>) -> Approval {
        let m = self.dom.request_digest(&new_owner, epoch);
        let taus: Vec<(usize, G1)> = set.iter().map(|&i| (i, self.guardian_evidence(i, &m))).collect();
        let (s, ct) = self.combiner_round1(&m, &taus, forge).expect("not enough evidence");
        let partials: Vec<(usize, G1)> =
            s.iter().map(|&i| (i, self.guardian_partial(i, &m, &ct).expect("bad pi_R"))).collect();
        let sigma = self.combine(&approve_digest(&m, &ct), &partials).expect("combine");
        Approval { m, new_owner, epoch, sigma, ct }
    }

    /// The check of the contract, Verify(pp, m, sigma, ct).
    pub fn verify(&self, ap: &Approval) -> bool {
        Self::schnorr_verify(&ap.m, &ap.ct) && bls_verify(&self.pk, &ap.approve_digest(), &ap.sigma, DST_H0)
    }

    // ---------------- Trace and Judge ----------------

    pub fn trace(&self, ap: &Approval) -> TracingProof {
        let k = ap.ct.r.mul(&self.sk_t);
        let u = Scalar::random();
        let u1 = G1::generator().mul(&u);
        let u2 = ap.ct.r.mul(&u);
        let h = dleq_challenge(&self.pk_t, &ap.ct.r, &k, &u1, &u2);
        let z = u.add(&h.mul(&self.sk_t));
        TracingProof { k, u1, u2, z }
    }

    /// Judge with one pairing check per evidence signature (the contract batches them).
    pub fn judge(&self, ap: &Approval, pi: &TracingProof) -> Outcome {
        let r = &ap.ct.r;
        let h = dleq_challenge(&self.pk_t, r, &pi.k, &pi.u1, &pi.u2);
        let ok1 = G1::generator().mul(&pi.z).equals(&pi.u1.add(&self.pk_t.mul(&h)));
        let ok2 = r.mul(&pi.z).equals(&pi.u2.add(&pi.k.mul(&h)));
        if !ok1 || !ok2 {
            return Outcome::Rej;
        }
        if ap.ct.c.len() != self.payload_len() {
            return Outcome::Bad;
        }
        let p = ae_xor(&kdf(r, &pi.k), &ap.ct.c);
        let nb = self.n.div_ceil(8);
        let mut s = Vec::new();
        for i in 1..=self.n {
            let in_s = (p[(i - 1) / 8] >> ((i - 1) % 8)) & 1 == 1;
            let y = match G1::from_eip(&p[nb + 128 * (i - 1)..nb + 128 * i]) {
                Some(y) => y,
                None => return Outcome::Bad,
            };
            if in_s {
                if !bls_verify(&self.epks[i - 1], &ap.m, &y, DST_H1) {
                    return Outcome::Bad;
                }
                s.push(i);
            } else if !y.is_identity() {
                return Outcome::Bad;
            }
        }
        if self.n % 8 != 0 && (p[nb - 1] >> (self.n % 8)) != 0 {
            return Outcome::Bad;
        }
        if s.len() < self.t {
            return Outcome::Bad;
        }
        Outcome::Set(s)
    }

    // ---------------- UpdateKey ----------------

    /// Guardian i replaces its evidence key in epoch `epoch`; returns the transaction data.
    pub fn update_key(&self, i: usize, epoch: u64) -> KeyUpdate {
        let new_esk = Scalar::random();
        let new_epk = G2::generator().mul(&new_esk);
        let psi = bls_sign(&new_esk, &self.dom.pop_digest(i, &new_epk), DST_H1);
        let mu = self.dom.update_digest(epoch, i, &new_epk);
        let phi = bls_sign(&self.esks[i - 1], &mu, DST_H1);
        let sigma_u = self.threshold_sign(&mu);
        KeyUpdate { i, new_esk, new_epk, psi, phi, sigma_u }
    }

    pub fn apply_update(&mut self, u: &KeyUpdate) {
        self.esks[u.i - 1] = u.new_esk.clone();
        self.epks[u.i - 1] = u.new_epk;
    }
}

pub struct KeyUpdate {
    pub i: usize,
    pub new_esk: Scalar,
    pub new_epk: G2,
    pub psi: G1,
    pub phi: G1,
    pub sigma_u: G1,
}

/// sigma = prod sigma_i^{L_i(0)} over the given set.
pub fn lagrange_combine(partials: &[(usize, G1)]) -> G1 {
    let idx: Vec<u64> = partials.iter().map(|(i, _)| *i as u64).collect();
    let mut acc = G1::identity();
    for (i, s) in partials {
        let xi = Scalar::from_u64(*i as u64);
        let mut num = Scalar::from_u64(1);
        let mut den = Scalar::from_u64(1);
        for &j in &idx {
            if j == *i as u64 {
                continue;
            }
            let xj = Scalar::from_u64(j);
            num = num.mul(&xj);
            den = den.mul(&xj.sub(&xi));
        }
        acc = acc.add(&s.mul(&num.mul(&den.inv())));
    }
    acc
}
