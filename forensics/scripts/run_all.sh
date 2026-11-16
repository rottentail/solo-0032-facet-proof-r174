#!/usr/bin/env bash
# Reproduce the entire Facet Proof forensic sample set end to end.
#
# Steps: start an isolated service on a private data root, generate evidence
# over real HTTP, produce controlled tampered *copies*, run the independent
# cross-source verification (resumable), and build the custody inventory.
#
# The service data root and every evidence directory are created fresh under
# forensics/ unless they already hold evidence; original bundles are never
# mutated. Usage:  bash forensics/scripts/run_all.sh [service-port]
set -euo pipefail

PORT="${1:-8796}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORENSICS="$(cd "$HERE/.." && pwd)"
WORKSPACE="$(cd "$FORENSICS/.." && pwd)"
DATA_ROOT="$FORENSICS/service-data"
VENV_PY="$FORENSICS/work/venv/bin/python"
LOG="$FORENSICS/work/service.log"

cd "$WORKSPACE"
mkdir -p "$FORENSICS/work" "$DATA_ROOT"

# Isolated interpreter for the untrusted-bundle reader. The venv only receives a
# .pth pointing at the workspace; no third-party package is installed.
if [ ! -x "$VENV_PY" ]; then
  python3 -m venv "$FORENSICS/work/venv"
  printf '%s\n' "$WORKSPACE" \
    > "$FORENSICS/work/venv/lib/python3.11/site-packages/facetproof-workspace.pth"
fi

# Start the service only if it is not already answering on the port.
if ! curl -sf "http://127.0.0.1:$PORT/facet/v1/health" >/dev/null 2>&1; then
  python3 -m facetproof --root "$DATA_ROOT" --host 127.0.0.1 --port "$PORT" \
    > "$LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$PORT/facet/v1/health" >/dev/null 2>&1 && break
    sleep 0.2
  done
  trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
fi
curl -s "http://127.0.0.1:$PORT/facet/v1/health"; echo

export FACETREADER_PYTHON="$VENV_PY"
export FACET_SERVICE_ROOT="$DATA_ROOT"

python3 -I "$HERE/generate_evidence.py"
python3 -I "$HERE/tamper_bundle.py"
python3 -I "$HERE/verify_cross_source.py"
python3 -I "$HERE/build_custody.py"

echo
echo "Done. See:"
echo "  $FORENSICS/FORENSICS.md"
echo "  $FORENSICS/evidence/reports/chain-of-custody.json"
echo "  $FORENSICS/evidence/reports/verification-summary.json"
echo "  $FORENSICS/work/check-ledger.jsonl"
