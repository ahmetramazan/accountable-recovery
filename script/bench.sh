#!/usr/bin/env bash
# Runs every measurement of Section 6 of the paper:
#   1. forge build + forge test (correctness of the module against the off-chain implementation)
#   2. gas of every transaction on a local Prague node (anvil), written to results/onchain.json
#   3. running time of the off-chain algorithms, written to results/offchain.json
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8545}
REPS=${REPS:-20}

echo "== build"
forge build
(cd offchain && cargo build --release)

echo "== fixtures and tests"
(cd offchain && ./target/release/akr fixtures --out ../fixtures/scenario_n7.json)
forge test

echo "== on-chain gas (anvil, hardfork prague)"
anvil --hardfork prague --port "$PORT" --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  cast chain-id --rpc-url "http://127.0.0.1:$PORT" >/dev/null 2>&1 && break
  sleep 0.2
done
(cd offchain && ./target/release/akr bench-onchain --rpc "http://127.0.0.1:$PORT" --out ../results/onchain.json)

echo "== off-chain timings"
(cd offchain && ./target/release/akr bench-offchain --reps "$REPS" --out ../results/offchain.json)

echo "== done: results/onchain.json, results/offchain.json"
