from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE_FORMAT = "nc25-source-baseline/v1"
ARTIFACT_TITLE = "# NC25OL source bundle"
BINARY_DOCX_PLACEHOLDER = (
    "[BINARY DOCX OMITTED FROM TEXT BODY; SIZE AND SHA256 ABOVE ARE "
    "AUTHORITATIVE. DETERMINISTIC SOURCE: /tools/build_universal_specification.py]"
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def require_external_output(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        return resolved
    raise ValueError("OUTPUT_MUST_BE_OUTSIDE_PACKAGE")


def load_bound_entries(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    manifest_path = root / "PACKAGE-MANIFEST.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    declared = manifest.get("files")
    if not isinstance(declared, list):
        raise ValueError("PACKAGE_MANIFEST_FILES")
    entries: dict[str, dict[str, Any]] = {}
    for item in declared:
        if not isinstance(item, dict):
            raise ValueError("PACKAGE_MANIFEST_ENTRY")
        relative = item.get("path")
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise ValueError("PACKAGE_MANIFEST_PATH")
        full_path = (root / relative).resolve()
        try:
            full_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("PACKAGE_MANIFEST_PATH_ESCAPE") from exc
        payload = full_path.read_bytes()
        size = len(payload)
        digest = sha256_hex(payload)
        if item.get("byte_length") != size or item.get("sha256") != digest:
            raise ValueError(f"PACKAGE_MANIFEST_BINDING:{relative}")
        entries[relative] = {
            "path": relative,
            "payload": payload,
            "size": size,
            "sha256": digest,
        }
    entries["PACKAGE-MANIFEST.json"] = {
        "path": "PACKAGE-MANIFEST.json",
        "payload": manifest_bytes,
        "size": len(manifest_bytes),
        "sha256": sha256_hex(manifest_bytes),
    }
    return [entries[path] for path in sorted(entries)]


def build_artifact(root: Path, output_path: Path) -> dict[str, Any]:
    root = root.resolve()
    output_path = require_external_output(root, output_path)
    entries = load_bound_entries(root)
    baseline_text = BASELINE_FORMAT + "\n" + "".join(
        f"/{entry['path']}\t{entry['size']}\t{entry['sha256']}\n"
        for entry in entries
    )
    baseline_sha = sha256_hex(baseline_text.encode("utf-8"))
    total_source_bytes = sum(entry["size"] for entry in entries)
    parts = [
        ARTIFACT_TITLE,
        "",
        f"Baseline format: {BASELINE_FORMAT}",
        f"Baseline SHA-256: {baseline_sha}",
        f"Files: {len(entries)}",
        f"Total source bytes: {total_source_bytes}",
        "",
    ]
    for entry in entries:
        parts.extend(
            [
                f"## FILE: /{entry['path']}",
                f"SIZE: {entry['size']}",
                f"SHA256: {entry['sha256']}",
                "CONTENT:",
            ]
        )
        if Path(entry["path"]).suffix.lower() == ".docx":
            parts.append(BINARY_DOCX_PLACEHOLDER)
        else:
            parts.append(entry["payload"].decode("utf-8").rstrip("\n"))
        parts.append("")
    artifact_bytes = ("\n".join(parts).rstrip("\n") + "\n").encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    temporary.write_bytes(artifact_bytes)
    temporary.replace(output_path)
    return {
        "format": "nc25-source-freeze/v1",
        "baseline_sha256": baseline_sha,
        "artifact_sha256": sha256_hex(artifact_bytes),
        "file_count": len(entries),
        "total_source_bytes": total_source_bytes,
        "artifact_bytes": len(artifact_bytes),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-output", type=Path)
    args = parser.parse_args()
    metadata = build_artifact(args.root, args.output)
    if args.metadata_output is not None:
        metadata_path = require_external_output(args.root, args.metadata_output)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print(f"BUNDLE_BASELINE_SHA256={metadata['baseline_sha256']}")
    print(f"BUNDLE_SHA256={metadata['artifact_sha256']}")
    print(f"BUNDLE_FILES={metadata['file_count']}")
    print(f"BUNDLE_SOURCE_BYTES={metadata['total_source_bytes']}")
    print(f"BUNDLE_BYTES={metadata['artifact_bytes']}")


if __name__ == "__main__":
    main()
