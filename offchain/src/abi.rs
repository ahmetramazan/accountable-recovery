//! Minimal Solidity ABI encoder (enough for the calls of the module).

use sha3::{Digest, Keccak256};

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

#[derive(Clone, Debug)]
pub enum Tok {
    /// A static 32-byte word (uint, address, bytes32).
    Word([u8; 32]),
    /// Dynamic `bytes`.
    Bytes(Vec<u8>),
    /// A dynamic tuple (contains at least one dynamic member).
    Tuple(Vec<Tok>),
    /// A dynamic array of static tuples, e.g. Rule[].
    StaticTupleArray(Vec<Vec<[u8; 32]>>),
}

pub fn addr(a: &[u8; 20]) -> Tok {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    Tok::Word(w)
}

pub fn uint(v: u64) -> Tok {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    Tok::Word(w)
}

pub fn word(w: [u8; 32]) -> Tok {
    Tok::Word(w)
}

pub fn bytes(b: &[u8]) -> Tok {
    Tok::Bytes(b.to_vec())
}

fn is_dynamic(t: &Tok) -> bool {
    !matches!(t, Tok::Word(_))
}

fn pad32(len: usize) -> usize {
    len.div_ceil(32) * 32
}

fn encode_tok(t: &Tok) -> Vec<u8> {
    match t {
        Tok::Word(w) => w.to_vec(),
        Tok::Bytes(b) => {
            let mut out = uint(b.len() as u64).word_bytes();
            out.extend_from_slice(b);
            out.resize(32 + pad32(b.len()), 0);
            out
        }
        Tok::Tuple(items) => encode(items),
        Tok::StaticTupleArray(rows) => {
            let mut out = uint(rows.len() as u64).word_bytes();
            for r in rows {
                for w in r {
                    out.extend_from_slice(w);
                }
            }
            out
        }
    }
}

impl Tok {
    fn word_bytes(&self) -> Vec<u8> {
        match self {
            Tok::Word(w) => w.to_vec(),
            _ => unreachable!(),
        }
    }
}

/// abi.encode(items...)
pub fn encode(items: &[Tok]) -> Vec<u8> {
    let head_len = 32 * items.len();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for t in items {
        if is_dynamic(t) {
            head.extend_from_slice(&uint((head_len + tail.len()) as u64).word_bytes());
            tail.extend_from_slice(&encode_tok(t));
        } else {
            head.extend_from_slice(&encode_tok(t));
        }
    }
    head.extend_from_slice(&tail);
    head
}

/// Calldata for `signature` (e.g. "finalize(address)") with the given arguments.
pub fn call(signature: &str, items: &[Tok]) -> Vec<u8> {
    let mut out = keccak(signature.as_bytes())[..4].to_vec();
    out.extend_from_slice(&encode(items));
    out
}
