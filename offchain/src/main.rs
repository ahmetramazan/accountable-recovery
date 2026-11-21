//! akr: off-chain parties of accountable key recovery.
//!
//!   akr fixtures [--out PATH]                 test vectors for the Foundry tests
//!   akr bench-onchain [--rpc URL] [--out PATH] gas of every transaction on a local node (anvil)
//!   akr bench-offchain [--out PATH] [--reps N] running time of the off-chain algorithms

mod abi;
mod bls;
mod scheme;

use abi::{addr, bytes, call, keccak, uint, word, Tok};
use bls::G1;
use k256::ecdsa::{RecoveryId, SigningKey};
use scheme::*;
use serde_json::{json, Value};
use std::time::Instant;

// ----------------------------------------------------------------------------
// Calldata of the module
// ----------------------------------------------------------------------------

fn ct_tok(ct: &Ciphertext) -> Tok {
    Tok::Tuple(vec![bytes(&ct.r.to_eip()), bytes(&ct.c), bytes(&ct.a.to_eip()), word(ct.z.to_be32())])
}

fn request_call(sys: &System, ap: &Approval) -> Vec<u8> {
    call(
        "request(address,address,bytes,bytes,(bytes,bytes,bytes,uint256))",
        &[addr(&sys.dom.account), addr(&ap.new_owner), bytes(&sys.pk.to_eip()), bytes(&ap.sigma.to_eip()), ct_tok(&ap.ct)],
    )
}

fn dispute_call(sys: &System, ap: &Approval, pi: &TracingProof) -> Vec<u8> {
    call(
        "dispute(address,bytes,(bytes,bytes,bytes,uint256),(bytes,bytes,bytes,uint256),bytes,bytes,bytes,bytes32)",
        &[
            addr(&sys.dom.account),
            bytes(&ap.sigma.to_eip()),
            ct_tok(&ap.ct),
            Tok::Tuple(vec![bytes(&pi.k.to_eip()), bytes(&pi.u1.to_eip()), bytes(&pi.u2.to_eip()), word(pi.z.to_be32())]),
            bytes(&sys.pk_t.to_eip()),
            bytes(&sys.epks_concat()),
            bytes(&policy_abi(&sys.rules)),
            word(sys.salt),
        ],
    )
}

fn install_call(sys: &System, delta: u64, validator: &[u8; 20], module: &[u8; 20]) -> Vec<u8> {
    let data = abi::encode(&[
        bytes(&sys.pk.to_eip()),
        bytes(&sys.pk_t.to_eip()),
        bytes(&sys.epks_concat()),
        uint(sys.n as u64),
        uint(sys.t as u64),
        word(sys.cgov()),
        uint(delta),
        addr(validator),
    ]);
    call("installModule(uint256,address,bytes)", &[uint(2), addr(module), bytes(&data)])
}

// ----------------------------------------------------------------------------
// ECDSA owner key
// ----------------------------------------------------------------------------

fn owner_key(seed: &str) -> SigningKey {
    SigningKey::from_bytes(&keccak(seed.as_bytes()).into()).unwrap()
}

fn eth_address(k: &SigningKey) -> [u8; 20] {
    let pt = k.verifying_key().to_encoded_point(false);
    keccak(&pt.as_bytes()[1..])[12..].try_into().unwrap()
}

/// Raw ECDSA signature r || s || v (v in {27, 28}) of a 32-byte digest, with low s.
fn ecdsa_sign(k: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    let (mut sig, mut rec): (k256::ecdsa::Signature, RecoveryId) = k.sign_prehash_recoverable(digest).unwrap();
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
        rec = RecoveryId::new(!rec.is_y_odd(), rec.is_x_reduced());
    }
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + rec.to_byte());
    out
}

// ----------------------------------------------------------------------------
// Scenario: the life of an account, in the order of Section 3.1
// ----------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Target {
    Module,
    Account,
}

struct Step {
    name: String,
    target: Target,
    data: Vec<u8>,
    mine_before: u64,
    expect_success: bool,
}

struct Config {
    n: usize,
    t: usize,
    policy_set: usize, // |S| of the policy dispute
    bad_set: usize,    // |S| of the dispute with outcome bad
}

fn policy_rules(n: usize, t: usize) -> Vec<Rule> {
    // Governance policy: at least t guardians, and at least one of guardians 1 and 2 ("legal unit").
    vec![Rule { members: (1..=n).collect(), k: t as u64 }, Rule { members: vec![1, 2], k: 1 }]
}

fn scenario(cfg: &Config, dom: Domain, validator: [u8; 20], owner: &SigningKey, delta: u64) -> (System, Vec<Step>) {
    let mut sys = System::setup(dom, cfg.n, cfg.t, policy_rules(cfg.n, cfg.t));
    let new_owner: [u8; 20] = eth_address(&owner_key("akr new owner"));
    let mut steps = Vec::new();
    let mut push = |name: &str, target, data, mine_before, ok| {
        steps.push(Step { name: name.into(), target, data, mine_before, expect_success: ok })
    };
    let compliant: Vec<usize> = (1..=cfg.t).collect();

    push("Install", Target::Account, install_call(&sys, delta, &validator, &dom.module), 0, true);

    // epoch 0: request, then cancel by the owner
    let ap = sys.approve(new_owner, 0, &compliant, None);
    assert!(sys.verify(&ap));
    push("Request", Target::Module, request_call(&sys, &ap), 0, true);
    let phi = ecdsa_sign(owner, &cancel_digest(&ap.m));
    push("Cancel", Target::Module, call("cancel(address,bytes)", &[addr(&dom.account), bytes(&phi)]), 0, true);

    // epoch 1: request, a dispute of a compliant request fails, finalize after the window
    let ap = sys.approve(new_owner, 1, &compliant, None);
    push("Request (epoch 1)", Target::Module, request_call(&sys, &ap), 0, true);
    let pi = sys.trace(&ap);
    assert_eq!(sys.judge(&ap, &pi), Outcome::Set(compliant.clone()));
    push("Dispute of a compliant request (must revert)", Target::Module, dispute_call(&sys, &ap, &pi), 0, false);
    push("Finalize", Target::Module, call("finalize(address)", &[addr(&dom.account)]), delta, true);

    // epoch 2: advance
    let sig_a = sys.threshold_sign(&dom.advance_digest(2));
    push(
        "Advance",
        Target::Module,
        call("advance(address,bytes,bytes)", &[addr(&dom.account), bytes(&sys.pk.to_eip()), bytes(&sig_a.to_eip())]),
        0,
        true,
    );

    // epoch 3: guardian 3 replaces its evidence key
    let upd = sys.update_key(3, 3);
    let data = call(
        "updateKey(address,uint256,bytes,bytes,bytes,bytes,bytes,bytes)",
        &[
            addr(&dom.account),
            uint(3),
            bytes(&upd.new_epk.to_eip()),
            bytes(&upd.psi.to_eip()),
            bytes(&upd.phi.to_eip()),
            bytes(&upd.sigma_u.to_eip()),
            bytes(&sys.pk.to_eip()),
            bytes(&sys.epks_concat()),
        ],
    );
    push("UpdateKey", Target::Module, data, 0, true);
    sys.apply_update(&upd);

    // epoch 4: a request whose evidence set violates the governance policy, disputed
    let violating: Vec<usize> = (3..3 + cfg.policy_set).collect();
    assert!(!policy_allows(&sys.rules, &violating));
    let ap = sys.approve(new_owner, 4, &violating, None);
    push(&format!("Request (n={})", cfg.n), Target::Module, request_call(&sys, &ap), 0, true);
    let pi = sys.trace(&ap);
    assert_eq!(sys.judge(&ap, &pi), Outcome::Set(violating.clone()));
    push(&format!("Dispute, policy, |S|={}", cfg.policy_set), Target::Module, dispute_call(&sys, &ap, &pi), 0, true);

    // epoch 5: a malformed request (one forged evidence signature), disputed with outcome bad
    let set: Vec<usize> = (1..=cfg.bad_set).collect();
    let ap = sys.approve(new_owner, 5, &set, Some(cfg.bad_set));
    assert!(sys.verify(&ap));
    push(&format!("Request (n={}, |S|={})", cfg.n, cfg.bad_set), Target::Module, request_call(&sys, &ap), 0, true);
    let pi = sys.trace(&ap);
    assert_eq!(sys.judge(&ap, &pi), Outcome::Bad);
    push(&format!("Dispute, bad, |S|={}", cfg.bad_set), Target::Module, dispute_call(&sys, &ap, &pi), 0, true);

    (sys, steps)
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or(default.to_string())
}

// ----------------------------------------------------------------------------
// fixtures
// ----------------------------------------------------------------------------

fn fixed_addr(last: u16) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[16..18].copy_from_slice(&[0xc0, 0xde]);
    a[18..].copy_from_slice(&last.to_be_bytes());
    a
}

fn cmd_fixtures(args: &[String]) {
    let out = arg(args, "--out", "../fixtures/scenario_n7.json");
    let n: usize = arg(args, "--n", "7").parse().unwrap();
    let t: usize = arg(args, "--t", &((n + 1) / 2).to_string()).parse().unwrap();
    let module = fixed_addr(1);
    let validator = fixed_addr(2);
    let account = fixed_addr(3);
    let dom = Domain { chain_id: 31337, module, account };
    let owner = owner_key("akr owner");
    let cfg = Config { n, t, policy_set: t, bad_set: t };
    let delta = 10;
    let (_sys, steps) = scenario(&cfg, dom, validator, &owner, delta);
    let steps_json: Vec<Value> = steps
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "toAccount": s.target == Target::Account,
                "data": hex0x(&s.data),
                "mineBefore": s.mine_before,
                "expectSuccess": s.expect_success,
            })
        })
        .collect();
    let j = json!({
        "n": n, "t": t, "delta": delta,
        "module": hex0x(&module), "validator": hex0x(&validator), "account": hex0x(&account),
        "owner": hex0x(&eth_address(&owner)),
        "newOwner": hex0x(&eth_address(&owner_key("akr new owner"))),
        "steps": steps_json,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&j).unwrap()).unwrap();
    println!("wrote {} ({} steps)", out, steps.len());
}

// ----------------------------------------------------------------------------
// bench-onchain
// ----------------------------------------------------------------------------

struct Rpc {
    url: String,
    from: String,
}

impl Rpc {
    fn call(&self, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = ureq::post(&self.url).send_json(body).expect("rpc").into_json().unwrap();
        if let Some(e) = resp.get("error") {
            panic!("rpc {} failed: {}", method, e);
        }
        resp["result"].clone()
    }

    /// Sends a transaction and returns (success, gasUsed, contractAddress).
    fn send(&self, to: Option<&[u8; 20]>, data: &[u8]) -> (bool, u64, Option<String>) {
        let mut tx = json!({"from": self.from, "data": hex0x(data), "gas": "0xe4e1c0"}); // 15M
        if let Some(to) = to {
            tx["to"] = json!(hex0x(to));
        }
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction", "params": [tx]});
        let resp: Value = ureq::post(&self.url).send_json(body).expect("rpc").into_json().unwrap();
        let hash = match resp.get("result") {
            Some(h) if !h.is_null() => h.clone(),
            _ => return (false, 0, None), // rejected (e.g. reverted during submission)
        };
        let mut rc = Value::Null;
        for _ in 0..200 {
            rc = self.call("eth_getTransactionReceipt", json!([hash.clone()]));
            if !rc.is_null() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(!rc.is_null(), "no receipt for {}", hash);
        let ok = rc["status"].as_str() == Some("0x1");
        let gas = u64::from_str_radix(rc["gasUsed"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        (ok, gas, rc["contractAddress"].as_str().map(|s| s.to_string()))
    }

    fn deploy(&self, artifact: &str, ctor_args: &[u8]) -> [u8; 20] {
        let j: Value = serde_json::from_str(&std::fs::read_to_string(artifact).expect(artifact)).unwrap();
        let mut code = hex::decode(j["bytecode"]["object"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        code.extend_from_slice(ctor_args);
        let (ok, _, a) = self.send(None, &code);
        assert!(ok, "deploy {} failed", artifact);
        hex::decode(a.unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap()
    }
}

fn calldata_gas(data: &[u8]) -> u64 {
    data.iter().map(|&b| if b == 0 { 4 } else { 16 }).sum()
}

fn cmd_bench_onchain(args: &[String]) {
    let url = arg(args, "--rpc", "http://127.0.0.1:8545");
    let out = arg(args, "--out", "../results/onchain.json");
    let artifacts = arg(args, "--artifacts", "../out");
    let probe = Rpc { url: url.clone(), from: String::new() };
    let from = probe.call("eth_accounts", json!([]))[0].as_str().unwrap().to_string();
    let rpc = Rpc { url, from };
    let chain_id = u64::from_str_radix(rpc.call("eth_chainId", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap();

    let module = rpc.deploy(&format!("{artifacts}/AccountableRecoveryModule.sol/AccountableRecoveryModule.json"), &[]);
    let validator = rpc.deploy(&format!("{artifacts}/OwnerValidator.sol/OwnerValidator.json"), &[]);
    let owner = owner_key("akr owner");
    let delta = 10;

    let configs = [
        Config { n: 7, t: 4, policy_set: 4, bad_set: 4 },
        Config { n: 20, t: 10, policy_set: 10, bad_set: 20 },
        Config { n: 50, t: 25, policy_set: 25, bad_set: 50 },
    ];
    let mut results = Vec::new();
    for cfg in &configs {
        let ctor = abi::encode(&[addr(&validator), addr(&eth_address(&owner))]);
        let account = rpc.deploy(&format!("{artifacts}/MockAccount.sol/MockAccount.json"), &ctor);
        let dom = Domain { chain_id, module, account };
        let (sys, steps) = scenario(cfg, dom, validator, &owner, delta);
        println!("n = {}, t = {}  (|ct| = {} bytes)", cfg.n, cfg.t, 128 + sys.payload_len() + 128 + 32);
        for s in &steps {
            if s.mine_before > 0 {
                rpc.call("anvil_mine", json!([format!("0x{:x}", s.mine_before)]));
            }
            let to = if s.target == Target::Module { &module } else { &account };
            let (ok, gas, _) = rpc.send(Some(to), &s.data);
            assert_eq!(ok, s.expect_success, "unexpected result for step {} (n={})", s.name, cfg.n);
            if !s.expect_success {
                println!("  {:<44} reverted as expected", s.name);
                continue;
            }
            println!("  {:<44} {:>9} gas  (calldata {:>6} bytes, {:>6} gas)", s.name, gas, s.data.len(), calldata_gas(&s.data));
            results.push(json!({
                "n": cfg.n, "t": cfg.t, "step": s.name, "gasUsed": gas,
                "calldataBytes": s.data.len(), "calldataGas": calldata_gas(&s.data),
            }));
        }
    }
    if let Some(dir) = std::path::Path::new(&out).parent() {
        std::fs::create_dir_all(dir).ok();
    }
    std::fs::write(&out, serde_json::to_string_pretty(&json!({"chainId": chain_id, "delta": delta, "results": results})).unwrap())
        .unwrap();
    println!("wrote {}", out);
}

// ----------------------------------------------------------------------------
// bench-offchain
// ----------------------------------------------------------------------------

fn median_ms<F: FnMut()>(reps: usize, mut f: F) -> f64 {
    let mut v: Vec<f64> = (0..reps)
        .map(|_| {
            let t0 = Instant::now();
            f();
            t0.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn cmd_bench_offchain(args: &[String]) {
    let out = arg(args, "--out", "../results/offchain.json");
    let reps: usize = arg(args, "--reps", "10").parse().unwrap();
    let dom = Domain { chain_id: 1, module: fixed_addr(1), account: fixed_addr(3) };
    let new_owner = fixed_addr(9);
    let mut results = Vec::new();
    for (n, t) in [(7usize, 4usize), (20, 10), (50, 25)] {
        let dkg_reps = if n >= 50 { 3.max(reps / 5) } else { reps };
        let dkg_ms = median_ms(dkg_reps, || {
            dkg(n, t);
        });
        let sys = System::setup(dom, n, t, policy_rules(n, t));
        let m = dom.request_digest(&new_owner, 0);
        let set: Vec<usize> = (1..=t).collect();
        let taus: Vec<(usize, G1)> = set.iter().map(|&i| (i, sys.guardian_evidence(i, &m))).collect();
        let (s, ct) = sys.combiner_round1(&m, &taus, None).unwrap();
        let partials: Vec<(usize, G1)> = s.iter().map(|&i| (i, sys.guardian_partial(i, &m, &ct).unwrap())).collect();
        let mu = approve_digest(&m, &ct);
        let sigma = sys.combine(&mu, &partials).unwrap();
        let ap = Approval { m, new_owner, epoch: 0, sigma, ct: ct.clone() };
        let pi = sys.trace(&ap);
        assert_eq!(sys.judge(&ap, &pi), Outcome::Set(set.clone()));

        let g_r1 = median_ms(reps, || {
            sys.guardian_evidence(1, &m);
        });
        let c_r1 = median_ms(reps, || {
            sys.combiner_round1(&m, &taus, None);
        });
        let g_r2 = median_ms(reps, || {
            sys.guardian_partial(1, &m, &ct);
        });
        let comb = median_ms(reps, || {
            sys.combine(&mu, &partials);
        });
        let ver = median_ms(reps, || {
            sys.verify(&ap);
        });
        let tr = median_ms(reps, || {
            sys.trace(&ap);
        });
        let jd = median_ms(reps, || {
            sys.judge(&ap, &pi);
        });
        let ct_size = ct.size();
        println!(
            "n={n:>2} t={t:>2} |S|={t:>2}: DKG {dkg_ms:9.2} ms (all parties) | guardian r1 {g_r1:.3} ms, r2 {g_r2:.3} ms | combiner r1 {c_r1:.2} ms, Combine {comb:.2} ms | Verify {ver:.2} ms | Trace {tr:.2} ms | Judge {jd:.2} ms | |ct| {ct_size} B"
        );
        results.push(json!({
            "n": n, "t": t, "S": t,
            "dkgAllPartiesMs": dkg_ms, "dkgPerPartyMs": dkg_ms / n as f64,
            "guardianRound1Ms": g_r1, "guardianRound2Ms": g_r2,
            "combinerRound1Ms": c_r1, "combineMs": comb, "verifyMs": ver,
            "traceMs": tr, "judgeMs": jd, "ctBytes": ct_size,
        }));
    }
    if let Some(dir) = std::path::Path::new(&out).parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let cpu = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    std::fs::write(&out, serde_json::to_string_pretty(&json!({"cpu": cpu, "reps": reps, "results": results})).unwrap())
        .unwrap();
    println!("wrote {}", out);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("fixtures") => cmd_fixtures(&args),
        Some("bench-onchain") => cmd_bench_onchain(&args),
        Some("bench-offchain") => cmd_bench_offchain(&args),
        _ => eprintln!("usage: akr <fixtures|bench-onchain|bench-offchain> [options]"),
    }
}
