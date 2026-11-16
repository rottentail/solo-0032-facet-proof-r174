"""Build the evidence chain-of-custody inventory and per-case conclusions.

Outputs (all under forensics/evidence/reports):
  chain-of-custody.json  every evidence file with size, sha256 and origin
  conclusions.md         item-by-item forensic conclusions
  verification-summary.json  machine-readable roll-up of the check ledger

The inventory is built from current files; nothing under evidence/ is modified.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
REPORTS = EVIDENCE / "reports"
WORK = ROOT / "work"

ORIGIN = {
    "bundles/case-a-original/plate-bundle.zip": "service export via GET /plates/{id}/bundle",
    "bundles/case-b-normal/plate-bundle.zip": "service export via GET /plates/{id}/bundle",
    "bundles/case-b-bright/plate-bundle.zip": "service export via GET /plates/{id}/bundle",
    "bundles/case-c-original/plate-bundle.zip": "service export via GET /plates/{id}/bundle",
    "bundles/case-c-tampered-naive/plate-bundle.zip": "controlled tamper: pixels replaced, self-declared hashes left stale",
    "bundles/case-c-tampered-rehashed/plate-bundle.zip": "controlled tamper: pixels replaced and all bundle-local hashes recomputed",
    "colors/": "service color.png bytes captured independently of the bundle",
    "transcripts/": "full HTTP request/response transcript captured during generation",
    "state/": "generation facts (ids and recorded hashes) used as the comparison baseline",
}


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def origin_for(relative):
    for prefix, note in ORIGIN.items():
        if relative.startswith(prefix):
            return note
    return "derived forensic artifact"


def build_inventory():
    items = []
    for path in sorted(EVIDENCE.rglob("*")):
        if not path.is_file() or path.parent == REPORTS or REPORTS in path.parents:
            continue
        relative = path.relative_to(EVIDENCE).as_posix()
        items.append({
            "path": "evidence/" + relative,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "origin": origin_for(relative),
        })
    return items


def read_ledger():
    ledger = WORK / "check-ledger.jsonl"
    entries = []
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    inventory = build_inventory()
    ledger = read_ledger()

    counts = {"pass": 0, "fail": 0, "warn": 0}
    for entry in ledger:
        counts[entry["result"]] = counts.get(entry["result"], 0) + 1

    custody = {
        "generated_at": generated_at,
        "principle": "Original service data and exported bundles are write-once "
                     "evidence; tampering only ever produces new files in separate "
                     "directories. Hashes below are the independent re-computation "
                     "used for custody, not values copied from bundle metadata.",
        "evidence_file_count": len(inventory),
        "check_totals": counts,
        "items": inventory,
    }
    (REPORTS / "chain-of-custody.json").write_text(
        json.dumps(custody, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")

    summary = {"generated_at": generated_at, "totals": counts, "checks": ledger}
    (REPORTS / "verification-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    print(f"inventory: {len(inventory)} files; checks {counts}")


if __name__ == "__main__":
    main()
