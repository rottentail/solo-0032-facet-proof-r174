"""Controlled tampering of an *offline copy* of a Facet Proof bundle.

The original bundle is opened read-only and never modified. Two attack variants
are written into separate empty directories:

  naive     replace color.png / color.rgb pixels but leave every self-declared
            digest untouched -> the reader rejects on the stale descriptor hash
            (and on PNG-vs-raw pixel disagreement for the raw channel).
  rehashed  replace the color content, re-encode a valid PNG, recompute the
            pass descriptors and the plate visual_hash, so every bundle-local
            hash chain is internally consistent -> the standalone reader still
            passes, demonstrating that its trust scope is internal consistency
            only. The forged visual_hash then disagrees with the service record.

Only standard-library modules are used. The PNG encoder here is independent of
both facetproof and facetreader.
"""
import hashlib
import io
import json
import struct
import sys
import zlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "evidence" / "bundles" / "case-c-original" / "plate-bundle.zip"
OUT_NAIVE = ROOT / "evidence" / "bundles" / "case-c-tampered-naive"
OUT_REHASHED = ROOT / "evidence" / "bundles" / "case-c-tampered-rehashed"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(
        ">I", zlib.crc32(kind + data) & 0xffffffff)


def encode_png(width, height, pixels):
    rows = b"".join(b"\x00" + pixels[y * width * 3:(y + 1) * width * 3]
                    for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header)
            + png_chunk(b"IDAT", zlib.compress(rows, 6)) + png_chunk(b"IEND", b""))


def replace_color_pixels(raw_rgb):
    """Channel swap R<->B plus a deterministic brightness fold on every pixel."""
    out = bytearray(len(raw_rgb))
    for i in range(0, len(raw_rgb), 3):
        r, g, b = raw_rgb[i], raw_rgb[i + 1], raw_rgb[i + 2]
        out[i] = (b + 40) % 256
        out[i + 1] = (255 - g) % 256
        out[i + 2] = (r + 40) % 256
    return bytes(out)


def read_bundle(path):
    with zipfile.ZipFile(io.BytesIO(path.read_bytes())) as archive:
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


def write_bundle(path, members):
    path.mkdir(parents=True, exist_ok=True)
    target = path / "plate-bundle.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            entry = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, members[name])
    target.write_bytes(buffer.getvalue())
    return target


def dimensions(plate):
    return plate["payload"]["width"], plate["payload"]["height"]


def tamper_naive(members):
    plate = json.loads(members["plate.json"])
    width, height = dimensions(plate)
    new_png = encode_png(width, height, replace_color_pixels(members["passes/color.rgb"]))
    # Metadata and descriptors deliberately left stale.
    members["passes/color.png"] = new_png
    return members


def tamper_rehashed(members):
    plate = json.loads(members["plate.json"])
    width, height = dimensions(plate)
    new_rgb = replace_color_pixels(members["passes/color.rgb"])
    new_png = encode_png(width, height, new_rgb)
    members["passes/color.rgb"] = new_rgb
    members["passes/color.png"] = new_png
    descriptors = plate["payload"]["passes"]
    for name, data in (("color.rgb", new_rgb), ("color.png", new_png)):
        descriptors[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    # Re-forge the manifest hash so every checksum *inside* the ZIP agrees.
    plate["payload"]["visual_hash"] = digest(descriptors)
    members["plate.json"] = canonical(plate)
    return members


def main():
    if not ORIGINAL.exists():
        raise SystemExit("original bundle missing; run generate_evidence.py first")
    original_hash = hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()
    for out, fn, label in ((OUT_NAIVE, tamper_naive, "naive"),
                           (OUT_REHASHED, tamper_rehashed, "rehashed")):
        if (out / "plate-bundle.zip").exists():
            print(f"{label}: already present, skipping")
            continue
        members = read_bundle(ORIGINAL)
        members = fn(members)
        target = write_bundle(out, members)
        print(f"{label}: wrote {target.relative_to(ROOT)} "
              f"sha256={hashlib.sha256(target.read_bytes()).hexdigest()[:16]}...")
    assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == original_hash, \
        "original bundle was modified during tampering"
    print("original bundle byte-identical after tampering:", original_hash)


if __name__ == "__main__":
    sys.exit(main())
