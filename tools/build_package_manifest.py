from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "PACKAGE-MANIFEST.json"
# Build output is excluded wherever it sits, because that is where it appears.
# The repository directory is excluded ONLY at the root, because that is the
# only place a repository directory belongs: matching the name at any depth
# meant `tools/.git/anything.py` was invisible to this manifest, to the
# verifier's coverage check, and to `git status` alike - a file could ship
# outside the hash-bound set with nothing saying so.
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache"}
REPOSITORY_DIRECTORY = ".git"
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".bak", ".tmp", ".orig", ".rej"}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        path.is_file()
        and relative.as_posix() != OUTPUT.name
        and relative.parts[:1] != (REPOSITORY_DIRECTORY,)
        and not (set(relative.parts) & EXCLUDED_PARTS)
        and path.suffix.lower() not in EXCLUDED_SUFFIXES
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def main() -> None:
    files = []
    for path in sorted(
        (item for item in ROOT.rglob("*") if included(item)),
        key=lambda item: item.relative_to(ROOT).as_posix(),
    ):
        files.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "byte_length": path.stat().st_size,
                "sha256": sha256(path),
            }
        )
    manifest = {
        "manifest_version": "1.0.0",
        "hash_algorithm": "SHA-256",
        "self_exclusion": "PACKAGE-MANIFEST.json is excluded to avoid recursive hashing; bind this manifest with the published archive digest and signature.",
        "files": files,
    }
    OUTPUT.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"PACKAGE_MANIFEST_FILES={len(files)}")


if __name__ == "__main__":
    main()
