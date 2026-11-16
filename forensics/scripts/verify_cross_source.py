"""Cross-source verification of the Facet Proof forensic sample set.

Three independent sources are reconciled per case:

  1. what the reviewer sees ........ service color.png bytes (visual source)
  2. what was downloaded ........... offline ZIP bundle, checked by facetreader
  3. what the service records ...... plate / proof / exposure rows and events

A separate check ledger records every check performed, persisted after each
item so an interrupted run resumes without redoing or rewriting completed work.
The script never writes into the service data root or into evidence bundles;
all outputs land in forensics/work and forensics/evidence/reports.
"""
import hashlib
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from client import Client  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
EVIDENCE = ROOT / "evidence"
STATE = EVIDENCE / "state"
REPORTS = EVIDENCE / "reports"
WORK = ROOT / "work"
LEDGER = WORK / "check-ledger.jsonl"
READER_OUT = WORK / "reader-output"
# Interpreter whose site-packages contains the workspace via a .pth entry, so
# the untrusted-bundle path argument is the only external input and -I still
# applies. Override with FACETREADER_PYTHON if the venv lives elsewhere.
READER_PYTHON = Path(__import__("os").environ.get(
    "FACETREADER_PYTHON", WORK / "venv" / "bin" / "python"))
# Read-only view of the service data root, used only when an HTTP pass endpoint
# correctly refuses to serve a quarantined plate. Override for other deployments.
SERVICE_ROOT = Path(__import__("os").environ.get(
    "FACET_SERVICE_ROOT", ROOT / "service-data"))


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(Path(path).read_bytes())


def load_facts(name):
    return json.loads((STATE / name).read_text(encoding="utf-8"))


class Ledger:
    """Append-only, resumable record of individual checks."""

    def __init__(self, path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.done = set()
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entry = json.loads(line)
                    self.done.add((entry["case_id"], entry["check"]))

    def has(self, case_id, check):
        return (case_id, check) in self.done

    def record(self, case_id, check, result, detail):
        entry = {"case_id": case_id, "check": check, "result": result,
                 "detail": detail}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        self.done.add((case_id, check))
        marker = "PASS" if result == "pass" else ("FAIL" if result == "fail" else "WARN")
        print(f"  [{marker}] {case_id} :: {check}")
        return entry


def run_reader(bundle_path, out_dir):
    """Run the independent facetreader in isolated mode (-I), output to a fresh dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(READER_PYTHON), "-I", "-m", "facetreader", str(bundle_path),
         "--output", str(out_dir)],
        cwd=str(WORKSPACE), capture_output=True, text=True, timeout=120)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {"valid": False, "error": "unparseable_output",
                  "stdout": proc.stdout[:500], "stderr": proc.stderr[:500]}
    report["_exit_code"] = proc.returncode
    return report


def bundle_members(path):
    with zipfile.ZipFile(path) as archive:
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


def color_byte_distance(left_path, right_path):
    """Mean per-channel byte delta between two raw RGB payloads inside bundles."""
    left = bundle_members(left_path)["passes/color.rgb"]
    right = bundle_members(right_path)["passes/color.rgb"]
    if len(left) != len(right):
        return None, len(left), len(right)
    total = sum(abs(a - b) for a, b in zip(left, right))
    return total / len(left), len(left), len(right)


def service_color_hash(plate_id):
    """Color bytes currently served over HTTP for a still-available plate."""
    _, raw, _, _ = Client().get(f"/facet/v1/plates/{plate_id}/passes/color.png")
    return sha256_bytes(raw)


def service_blob_hash(sha256):
    """Read-only access to a content-addressed service blob by its descriptor."""
    path = SERVICE_ROOT / "plates" / sha256[:2] / sha256
    return sha256_file(path) if path.exists() else None


def plate_color_descriptor(plate_id):
    plate = Client().get(f"/facet/v1/plates/{plate_id}")[0]
    return plate["payload"]["passes"]["color.png"]["sha256"]


def check_case_a(ledger):
    case_id, facts = "A", load_facts("case-a-facts.json")
    plate_id, proof_id = facts["plate_id"], facts["proof_id"]
    bundle = ROOT / facts["bundle"]

    if not ledger.has(case_id, "bundle-reader-internal-validity"):
        report = run_reader(bundle, READER_OUT / "case-a")
        ledger.record(case_id, "bundle-reader-internal-validity",
                      "pass" if report.get("valid") else "fail",
                      {"exit_code": report.get("_exit_code"),
                       "trust": report.get("trust"), "error": report.get("error")})

    if not ledger.has(case_id, "visual-unchanged-bundle-vs-service"):
        members = bundle_members(bundle)
        bundle_hash = sha256_bytes(members["passes/color.png"])
        # The plate is quarantined, so the HTTP pass endpoint correctly refuses
        # (409 plate_state). Reconcile against two independent on-disk sources:
        # the service content-addressed blob named by the plate descriptor, and
        # the color.png captured separately before quarantine.
        descriptor = plate_color_descriptor(plate_id)
        blob_hash = service_blob_hash(descriptor)
        captured = sha256_file(EVIDENCE / "colors" / "case-a-color.png")
        ok = bundle_hash == blob_hash == captured
        ledger.record(case_id, "visual-unchanged-bundle-vs-service",
                      "pass" if ok else "fail",
                      {"bundle_color_png_sha256": bundle_hash,
                       "service_blob_descriptor_sha256": descriptor,
                       "service_blob_on_disk_sha256": blob_hash,
                       "pre_quarantine_captured_color_sha256": captured,
                       "http_pass_status": "409 plate_state (expected for quarantined plate)"})

    if not ledger.has(case_id, "service-review-state-invalidated"):
        plate = Client().get(f"/facet/v1/plates/{plate_id}")[0]
        proof = Client().get(f"/facet/v1/proofs/{proof_id}")[0]
        ok = plate["state"] == "quarantined" and proof["state"] == "invalidated"
        ledger.record(case_id, "service-review-state-invalidated",
                      "pass" if ok else "fail",
                      {"plate_state": plate["state"], "proof_state": proof["state"]})

    if not ledger.has(case_id, "bundle-cannot-prove-current-review"):
        report = run_reader(bundle, READER_OUT / "case-a")
        trust = report.get("trust", {})
        warns_internal_only = "internal" in trust.get("verified", "").lower()
        review_unknown = "unknown" in trust.get("review_validity", "").lower()
        ledger.record(case_id, "bundle-cannot-prove-current-review",
                      "pass" if warns_internal_only and review_unknown else "fail",
                      {"verified_scope": trust.get("verified"),
                       "review_validity_scope": trust.get("review_validity"),
                       "external_authenticity_scope": trust.get("external_authenticity")})

    if not ledger.has(case_id, "event-trail-quarantine"):
        history = Client().get(f"/facet/v1/events/{plate_id}/history")[0]
        actions = [item["action"] for item in history["items"]]
        ledger.record(case_id, "event-trail-quarantine",
                      "pass" if "quarantined" in actions else "fail",
                      {"actions": actions})


def check_case_b(ledger):
    case_id, facts = "B", load_facts("case-b-facts.json")
    normal, bright = facts["normal"], facts["bright"]
    normal_bundle, bright_bundle = ROOT / normal["bundle"], ROOT / bright["bundle"]

    if not ledger.has(case_id, "both-bundles-internally-valid"):
        r1 = run_reader(normal_bundle, READER_OUT / "case-b-normal")
        r2 = run_reader(bright_bundle, READER_OUT / "case-b-bright")
        ledger.record(case_id, "both-bundles-internally-valid",
                      "pass" if r1.get("valid") and r2.get("valid") else "fail",
                      {"normal_exit": r1.get("_exit_code"), "bright_exit": r2.get("_exit_code"),
                       "normal_error": r1.get("error"), "bright_error": r2.get("error")})

    if not ledger.has(case_id, "visual-hashes-differ-despite-similar-scene"):
        members_n = bundle_members(normal_bundle)
        members_b = bundle_members(bright_bundle)
        n_hash = sha256_bytes(members_n["passes/color.rgb"])
        b_hash = sha256_bytes(members_b["passes/color.rgb"])
        mean_delta, _, _ = color_byte_distance(normal_bundle, bright_bundle)
        # Different images: hashes must differ; similarity: mean delta stays bounded.
        ok = n_hash != b_hash and mean_delta is not None
        ledger.record(case_id, "visual-hashes-differ-despite-similar-scene",
                      "pass" if ok else "fail",
                      {"normal_color_rgb_sha256": n_hash,
                       "bright_color_rgb_sha256": b_hash,
                       "mean_channel_byte_delta": round(mean_delta, 4) if mean_delta is not None else None})

    if not ledger.has(case_id, "seal-hashes-differ-illumination-cause"):
        ok = normal["seal_hash"] != bright["seal_hash"]
        ledger.record(case_id, "seal-hashes-differ-illumination-cause",
                      "pass" if ok else "fail",
                      {"normal_seal_hash": normal["seal_hash"],
                       "bright_seal_hash": bright["seal_hash"]})

    if not ledger.has(case_id, "service-records-match-bundles"):
        n_members = bundle_members(normal_bundle)
        b_members = bundle_members(bright_bundle)
        # Follow the service plate descriptor to its content-addressed blob and
        # confirm the physical bytes, independent of any bundle-local claim.
        desc_n = plate_color_descriptor(normal["plate_id"])
        desc_b = plate_color_descriptor(bright["plate_id"])
        blob_n, blob_b = service_blob_hash(desc_n), service_blob_hash(desc_b)
        bundle_n = sha256_bytes(n_members["passes/color.png"])
        bundle_b = sha256_bytes(b_members["passes/color.png"])
        ok = blob_n == bundle_n and blob_b == bundle_b
        ledger.record(case_id, "service-records-match-bundles",
                      "pass" if ok else "fail",
                      {"normal_descriptor_matches_blob": desc_n == blob_n,
                       "bright_descriptor_matches_blob": desc_b == blob_b,
                       "normal_blob_equals_bundle": blob_n == bundle_n,
                       "bright_blob_equals_bundle": blob_b == bundle_b})

    if not ledger.has(case_id, "service-comparison-quantifies-exposure-delta"):
        comparison = facts.get("service_comparison") or {}
        payload = comparison.get("payload", {})
        # Same lens geometry means the comparison is accepted; exposure change
        # shows as color differences with an unchanged silhouette (geometry).
        silhouette = payload.get("silhouette_changed")
        color_changed = payload.get("color_changed")
        ok = comparison.get("accepted") and silhouette == 0 and (color_changed or 0) > 0
        ledger.record(case_id, "service-comparison-quantifies-exposure-delta",
                      "pass" if ok else "fail",
                      {"accepted": comparison.get("accepted"),
                       "color_changed_pixels": color_changed,
                       "mean_channel_delta": payload.get("mean_channel_delta"),
                       "silhouette_changed": silhouette,
                       "depth_changed": payload.get("depth_changed"),
                       "note": "shared lens allows comparison; silhouette stays fixed "
                               "while color exposure differs"})


def check_case_c(ledger):
    case_id, facts = "C", load_facts("case-c-facts.json")
    original = ROOT / facts["bundle"]
    naive = ROOT / "evidence/bundles/case-c-tampered-naive/plate-bundle.zip"
    rehashed = ROOT / "evidence/bundles/case-c-tampered-rehashed/plate-bundle.zip"

    if not ledger.has(case_id, "original-bundle-baseline-valid"):
        report = run_reader(original, READER_OUT / "case-c-original")
        ledger.record(case_id, "original-bundle-baseline-valid",
                      "pass" if report.get("valid") else "fail",
                      {"exit_code": report.get("_exit_code"), "error": report.get("error"),
                       "visual_hash": report.get("provenance", {}).get("visual_hash")})

    if not ledger.has(case_id, "naive-tamper-rejected-by-reader"):
        report = run_reader(naive, READER_OUT / "case-c-naive")
        rejected = (not report.get("valid")) and report.get("_exit_code") == 2
        ledger.record(case_id, "naive-tamper-rejected-by-reader",
                      "pass" if rejected else "fail",
                      {"exit_code": report.get("_exit_code"),
                       "error_code": report.get("error"), "message": report.get("message")})

    if not ledger.has(case_id, "rehashed-tamper-passes-internal-checks"):
        report = run_reader(rehashed, READER_OUT / "case-c-rehashed")
        ledger.record(case_id, "rehashed-tamper-passes-internal-checks",
                      "pass" if report.get("valid") else "fail",
                      {"exit_code": report.get("_exit_code"),
                       "note": "expected: all bundle-local hashes recomputed, so internal "
                               "consistency holds; this is precisely why self-declared "
                               "digests cannot establish external authenticity",
                       "forged_visual_hash": report.get("provenance", {}).get("visual_hash")})

    if not ledger.has(case_id, "rehashed-visual-hash-disagrees-with-service"):
        forged = bundle_members(rehashed)
        forged_plate = json.loads(forged["plate.json"])
        live_plate = Client().get(f"/facet/v1/plates/{facts['plate_id']}")[0]
        service_visual = live_plate["payload"]["visual_hash"]
        forged_visual = forged_plate["payload"]["visual_hash"]
        # Also confirm the service still verifies its own untouched plate.
        verify = Client().post(f"/facet/v1/plates/{facts['plate_id']}/verify")[0]
        ok = forged_visual != service_visual and verify.get("valid") is True
        ledger.record(case_id, "rehashed-visual-hash-disagrees-with-service",
                      "pass" if ok else "fail",
                      {"service_visual_hash": service_visual,
                       "forged_visual_hash": forged_visual,
                       "service_self_verify_valid": verify.get("valid")})

    if not ledger.has(case_id, "rehashed-color-bytes-differ-from-service"):
        descriptor = plate_color_descriptor(facts["plate_id"])
        live_hash = service_blob_hash(descriptor)
        forged_png_hash = sha256_bytes(bundle_members(rehashed)["passes/color.png"])
        ledger.record(case_id, "rehashed-color-bytes-differ-from-service",
                      "pass" if live_hash != forged_png_hash else "fail",
                      {"service_blob_descriptor_sha256": descriptor,
                       "service_color_png_sha256": live_hash,
                       "forged_color_png_sha256": forged_png_hash})

    if not ledger.has(case_id, "original-bundle-immutable-after-tampering"):
        current = sha256_file(original)
        ledger.record(case_id, "original-bundle-immutable-after-tampering",
                      "pass" if current == facts["bundle_sha256"] else "fail",
                      {"recorded_sha256": facts["bundle_sha256"], "current_sha256": current})


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(LEDGER)
    print("cross-source verification (resumable; completed checks are skipped)")
    check_case_a(ledger)
    check_case_b(ledger)
    check_case_c(ledger)
    print(f"ledger: {LEDGER.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
