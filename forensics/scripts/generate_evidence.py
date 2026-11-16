"""Generate the Facet Proof digital-forensics sample set against a live service.

This script drives the real HTTP API (no in-process calls) and produces the
three evidence cases described in forensics/FORENSICS.md:

  A  review-invalidated: image bytes unchanged, accepted review later invalidated
  B  exposure-difference: visually similar images, different illumination exposure
  C  content-replaced: controlled tampering of offline bundles (two variants)

All network responses and exported bytes are captured read-only; the service
database and content-addressed blob store are the original evidence and are
never modified by this script (state changes happen only through the documented
HTTP workflow, which itself records events).

Resumable: a case is skipped if its marker file already exists, so an
interrupted run can be restarted without regenerating or rewriting evidence.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from client import Client, ServiceError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
BUNDLES = EVIDENCE / "bundles"
COLORS = EVIDENCE / "colors"
TRANSCRIPTS = EVIDENCE / "transcripts"
STATE = EVIDENCE / "state"

# Idempotency keys must be unique across generation runs; a run-scoped suffix
# keeps reruns (after evidence is deliberately reset) from colliding with keys
# the service already bound to an earlier, discarded exposure.
import time  # noqa: E402

RUN_ID = str(int(time.time()))

WIDTH = HEIGHT = 96

MESH = {
    "name": "forensic-wing",
    "vertices": [[-1, -1, 0], [1, -1, 0], [1, 1, 0], [-1, 1, 0], [0, 0, 1.2]],
    "faces": [[0, 1, 4], [1, 2, 4], [2, 3, 4], [3, 0, 4], [0, 3, 2], [0, 2, 1]],
}


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


class Recorder:
    """Persists every request/response pair so the HTTP trail is independently reviewable."""

    def __init__(self, case):
        self.case = case
        self.dir = TRANSCRIPTS / case
        self.dir.mkdir(parents=True, exist_ok=True)
        self.seq = 0

    def call(self, method, path, body=None, raw_download_name=None):
        self.seq += 1
        parsed, raw, mime, status = Client().request(method, path, body)
        entry = {"seq": self.seq, "method": method, "path": path,
                 "request_body": body, "status": status, "content_type": mime}
        if parsed is not None:
            entry["response_json"] = parsed
        else:
            entry["response_bytes_sha256"] = hashlib.sha256(raw).hexdigest()
            entry["response_bytes_size"] = len(raw)
            if raw_download_name:
                target = self.dir / raw_download_name
                target.write_bytes(raw)
                entry["saved_as"] = str(target.relative_to(ROOT))
        dump_json(self.dir / f"{self.seq:02d}-{method.lower()}-{slug(path)}.json", entry)
        return parsed, raw, mime, status

    def jcall(self, method, path, body=None):
        return self.call(method, path, body)[0]

    def rcall(self, method, path, body=None, raw_download_name=None):
        return self.call(method, path, body, raw_download_name)[1]


def slug(path):
    return "".join(c if c.isalnum() else "-" for c in path.strip("/"))[:60]


def run_worker(rec, label="worker-step"):
    parsed = rec.jcall("POST", "/facet/v1/worker/step")
    if parsed.get("state") != "succeeded":
        raise RuntimeError(f"{label} did not succeed: {parsed}")
    return parsed["plate"]


def make_seal(rec, assembly_name, illumination, pigment_color):
    mesh = rec.jcall("POST", "/facet/v1/meshes", MESH)
    pigment = rec.jcall("POST", "/facet/v1/pigments",
                          {"name": f"pigment-{assembly_name}", "color": pigment_color, "two_sided": True})
    assembly = rec.jcall("POST", "/facet/v1/assemblies",
                           {"name": assembly_name, "lens": {"eye": [3, 2, 4]}})
    assembly = rec.jcall("PUT", "/facet/v1/assemblies/" + assembly["id"],
                           {"revision": 1,
                            "placements": [{"key": "wing", "mesh_id": mesh["id"],
                                            "pigment_id": pigment["id"],
                                            "transform": {"euler": [0, 20, 0]}}],
                            "illumination": illumination})
    seal = rec.jcall("POST", "/facet/v1/assemblies/" + assembly["id"] + "/seal", {"revision": 2})
    return seal


def render(rec, seal, key):
    rec.call("POST", "/facet/v1/seals/" + seal["id"] + "/exposures",
             {"key": key, "width": WIDTH, "height": HEIGHT, "samples": 2})
    return run_worker(rec, key)


def save_bundle(rec, plate_id, case_bundle_dir):
    case_bundle_dir.mkdir(parents=True, exist_ok=True)
    target = case_bundle_dir / "plate-bundle.zip"
    raw = rec.rcall("GET", f"/facet/v1/plates/{plate_id}/bundle",
                      raw_download_name=target.name)
    target.write_bytes(raw)
    return target


def save_color(rec, plate_id, name):
    COLORS.mkdir(parents=True, exist_ok=True)
    raw = rec.rcall("GET", f"/facet/v1/plates/{plate_id}/passes/color.png",
                      raw_download_name=None)
    target = COLORS / name
    target.write_bytes(raw)
    return target


# ---------------------------------------------------------------- case A
def case_a():
    marker = STATE / "case-a.done"
    if marker.exists():
        print("case A: already generated, skipping")
        return
    rec = Recorder("case-a")
    seal = make_seal(rec, "case-a-invalidated-review",
                     {"ambient": 0.16, "lights": [{"direction": [1, 2, 3], "intensity": 0.8}]},
                     [0.12, 0.62, 0.61])
    plate = render(rec, seal, "case-a-exposure-" + RUN_ID)
    plate_id = plate["id"]
    save_color(rec, plate_id, "case-a-color.png")
    proof = rec.jcall("POST", f"/facet/v1/plates/{plate_id}/proofs",
                        {"note": "forensic sample: pre-quarantine acceptance"})
    rec.call("POST", "/facet/v1/proofs/" + proof["id"] + "/decide",
             {"state": "accepted", "note": "channels consistent, review accepted"})
    bundle_path = save_bundle(rec, plate_id, BUNDLES / "case-a-original")
    # Controlled service-side state change: bytes untouched, review invalidated.
    rec.call("POST", f"/facet/v1/plates/{plate_id}/quarantine",
             {"reason": "forensic control: isolate plate after acceptance"})
    after = rec.jcall("GET", f"/facet/v1/plates/{plate_id}")
    proof_after = rec.jcall("GET", "/facet/v1/proofs/" + proof["id"])
    dump_json(STATE / "case-a-facts.json", {
        "plate_id": plate_id, "seal_id": seal["id"], "proof_id": proof["id"],
        "bundle": str(bundle_path.relative_to(ROOT)),
        "bundle_sha256": sha256_file(bundle_path),
        "plate_state_after": after["state"], "proof_state_after": proof_after["state"],
        "visual_hash": plate["payload"]["visual_hash"],
        "seal_hash": plate["payload"]["seal_hash"],
    })
    marker.write_text("done\n", encoding="utf-8")
    print("case A: generated")


# ---------------------------------------------------------------- case B
def case_b():
    marker = STATE / "case-b.done"
    if marker.exists():
        print("case B: already generated, skipping")
        return
    rec = Recorder("case-b")
    # Same geometry, placement, lens and pigment; only illumination exposure differs.
    base_illum = {"ambient": 0.16, "lights": [{"direction": [1, 2, 3], "intensity": 0.8}]}
    bright_illum = {"ambient": 0.42, "lights": [{"direction": [1, 2, 3], "intensity": 2.4}]}
    seal_dark = make_seal(rec, "case-b-normal-exposure", base_illum, [0.12, 0.62, 0.61])
    seal_bright = make_seal(rec, "case-b-high-exposure", bright_illum, [0.12, 0.62, 0.61])
    plate_dark = render(rec, seal_dark, "case-b-normal-" + RUN_ID)
    plate_bright = render(rec, seal_bright, "case-b-bright-" + RUN_ID)
    save_color(rec, plate_dark["id"], "case-b-normal-color.png")
    save_color(rec, plate_bright["id"], "case-b-bright-color.png")
    bundle_dark = save_bundle(rec, plate_dark["id"], BUNDLES / "case-b-normal")
    bundle_bright = save_bundle(rec, plate_bright["id"], BUNDLES / "case-b-bright")
    # Both plates share lens geometry (illumination is outside the lens), so the
    # service comparison IS allowed and quantifies the exposure difference while
    # the silhouette/geometry stays identical. Capture it as a service-side fact.
    try:
        comparison = rec.jcall("POST", "/facet/v1/comparisons",
                               {"left": plate_dark["id"], "right": plate_bright["id"]})
        comparison_outcome = {"accepted": True, "comparison_id": comparison["id"],
                              "payload": comparison["payload"]}
    except ServiceError as exc:
        comparison_outcome = {"accepted": False, "status": exc.status, "payload": exc.payload}
    dump_json(STATE / "case-b-facts.json", {
        "normal": {"plate_id": plate_dark["id"], "seal_id": seal_dark["id"],
                   "bundle": str(bundle_dark.relative_to(ROOT)),
                   "bundle_sha256": sha256_file(bundle_dark),
                   "visual_hash": plate_dark["payload"]["visual_hash"],
                   "seal_hash": plate_dark["payload"]["seal_hash"],
                   "lens_hash": plate_dark["payload"]["lens_hash"]},
        "bright": {"plate_id": plate_bright["id"], "seal_id": seal_bright["id"],
                   "bundle": str(bundle_bright.relative_to(ROOT)),
                   "bundle_sha256": sha256_file(bundle_bright),
                   "visual_hash": plate_bright["payload"]["visual_hash"],
                   "seal_hash": plate_bright["payload"]["seal_hash"],
                   "lens_hash": plate_bright["payload"]["lens_hash"]},
        "service_comparison": comparison_outcome,
    })
    marker.write_text("done\n", encoding="utf-8")
    print("case B: generated")


# ---------------------------------------------------------------- case C
def case_c():
    marker = STATE / "case-c.done"
    if marker.exists():
        print("case C: already generated, skipping")
        return
    rec = Recorder("case-c")
    seal = make_seal(rec, "case-c-content-replaced",
                     {"ambient": 0.16, "lights": [{"direction": [1, 2, 3], "intensity": 0.8}]},
                     [0.12, 0.62, 0.61])
    plate = render(rec, seal, "case-c-exposure-" + RUN_ID)
    save_color(rec, plate["id"], "case-c-original-color.png")
    bundle_path = save_bundle(rec, plate["id"], BUNDLES / "case-c-original")
    dump_json(STATE / "case-c-facts.json", {
        "plate_id": plate["id"], "seal_id": seal["id"],
        "bundle": str(bundle_path.relative_to(ROOT)),
        "bundle_sha256": sha256_file(bundle_path),
        "visual_hash": plate["payload"]["visual_hash"],
        "seal_hash": plate["payload"]["seal_hash"],
    })
    marker.write_text("done\n", encoding="utf-8")
    print("case C: original generated (tampering is a separate, auditable step)")


def main():
    for directory in (BUNDLES, COLORS, TRANSCRIPTS, STATE):
        directory.mkdir(parents=True, exist_ok=True)
    # Health check proves we talk to the real service.
    health = Client().get("/facet/v1/health")[0]
    print("service health:", health)
    case_a()
    case_b()
    case_c()
    print("evidence generation complete")


if __name__ == "__main__":
    main()
