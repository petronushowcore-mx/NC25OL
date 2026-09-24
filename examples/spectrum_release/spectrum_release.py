"""Release exact Spectrum sources after a local finite-fixture observation."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import subprocess
import sys
import zipfile

ROOT = Path(os.environ.get("NC25_LEDGER_ROOT", Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / "examples/spectrum_observation"))
sys.path.insert(0, str(ROOT / "examples/local_release"))
import spectrum_observation as observation
import scenario
from nc25_universal_ledger import ContractViolation, UniversalConnectionLedger, FixedClock, bind_fixture, canonical_json

require = observation.require
digest = observation.digest


def git_bytes(root, *args, input=None):
    result = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args],
                            input=input, capture_output=True, timeout=30)
    require(result.returncode == 0, "SOURCE_GIT")
    return result.stdout


def source_files(root, revision):
    """Read every committed regular file, requiring exact checkout/blob equality.

    Sources must remain quiescent. This is an observation, not an OS lock.
    Symlinks and gitlinks other than the two declared layers are unsupported.
    """
    root = Path(root).resolve()
    snapshot = observation.source_snapshot(root, revision)
    members, records = {}, []
    folded = set()
    for name, commit in snapshot["revisions"].items():
        prefix = "" if name == "spectrum" else "layers/" + name + "/"
        folder = root if not prefix else root / prefix
        rows = []
        for row in git_bytes(folder, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
            if not row:
                continue
            header, raw_path = row.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            relative = raw_path.decode("utf-8")
            if mode == "160000":
                require(name == "spectrum" and relative in {"layers/XIV", "layers/XV"}
                        and oid == snapshot["revisions"][relative.split("/")[1]], "SOURCE_GITLINK")
                continue
            require(mode in {"100644", "100755"} and kind == "blob", "SOURCE_FILE_TYPE")
            parts = PurePosixPath(relative).parts
            require(parts and not relative.startswith("/") and "\\" not in relative
                    and all(p not in {".", "..", ".git"} and ":" not in p for p in parts), "SOURCE_PATH")
            full = prefix + relative
            require(full.casefold() not in folded and not full.casefold().startswith("release/"), "SOURCE_PATH_COLLISION")
            folded.add(full.casefold())
            rows.append((full, mode, oid))
        data = io.BytesIO(git_bytes(folder, "cat-file", "--batch",
                                   input="".join(oid + "\n" for _, _, oid in rows).encode("ascii")))
        for full, mode, oid in rows:
            actual_oid, kind, size = data.readline().decode("ascii").split()
            require(actual_oid == oid and kind == "blob" and 0 <= int(size) <= 16 * 1024 * 1024,
                    "SOURCE_BLOB")
            raw = data.read(int(size))
            require(len(raw) == int(size) and data.read(1) == b"\n", "SOURCE_BLOB")
            file = root / full
            require(file.resolve().is_relative_to(root) and not file.is_symlink()
                    and file.is_file(), "SOURCE_FILE_PATH")
            require(file.read_bytes() == raw, "SOURCE_CHECKOUT_BYTES")
            members[full] = raw
            records.append({"path": full, "mode": mode, "git_blob": oid,
                            "size": len(raw), "sha256": digest(raw)})
        require(not data.read(), "SOURCE_BLOB_TRAILING")
    require(observation.source_snapshot(root, revision) == snapshot, "SOURCE_CHANGED")
    files = dict(observation.MODULES, runner="layers/XV/harness/xiv_stitch.py")
    require(all(path in members and digest(members[path]) == snapshot["source_sha256"][name]
                for name, path in files.items()), "SOURCE_MODULE_BINDING")
    return snapshot, sorted(records, key=lambda r: r["path"]), members


def zip_bytes(members, modes):
    """Fixed metadata; identical input bytes reproduce within one zlib runtime."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = int(modes.get(name, "100644"), 8) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw, compresslevel=9)
    return stream.getvalue()


def verify_archive(raw, expected):
    """Expected members come from pinned sources and this collection, not the ZIP."""
    require(type(raw) is bytes and 0 < len(raw) <= scenario.dr.MAX_BODY // 2, "ARCHIVE_SIZE")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(len(entries) == len(expected) and {e.filename for e in entries} == set(expected),
                    "ARCHIVE_MEMBERS")
            for entry in entries:
                wanted = expected[entry.filename]
                require(not entry.is_dir() and not (entry.flag_bits & 1)
                        and stat.S_ISREG(entry.external_attr >> 16), "ARCHIVE_FILE_TYPE")
                require(entry.file_size == len(wanted) and archive.read(entry) == wanted, "ARCHIVE_BYTES")
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise observation.Refusal("ARCHIVE_FORMAT") from exc


class PreparedRelease:
    """One local collection; immutable artifact bytes held by a trusted caller.

    The inactive observation context and the release engine must initially agree.
    Activation is a separate owner action on the release engine. The observation
    does not approve the document, issue a grant or become an execution permit.
    """
    def __init__(self, root, revision):
        self.root, self.revision = Path(root).resolve(), revision
        self.source, self.records, sources = source_files(self.root, revision)
        fixture = json.loads((ROOT / "profiles/document-release/reference-connection.json").read_bytes())
        profile, declaration, _, _ = bind_fixture(
            *(fixture[k] for k in ("profile", "declaration", "grant", "intent")))
        engine = UniversalConnectionLedger(profile, declaration, secrets.token_bytes(32),
            clock=FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc)))
        collector = observation.ObservationSession(engine, declaration["connector"]["connector_id"],
                                                   self.root, revision)
        self.report_bytes = collector.collect()
        self.report = collector.receive(self.report_bytes)
        require(self.report["observation"]["status"] == "VERIFIED", "OBSERVATION_NOT_VERIFIED")
        require(self.report["source"] == self.source, "OBSERVATION_SOURCE_BINDING")
        self.check_sources()
        self.manifest = {"format": "nc25ol-spectrum-source-release/v1",
            "scope": "ALL_COMMITTED_FILES_OF_SPECTRUM_AND_PINNED_XIV_XV",
            "source": self.source, "files": self.records,
            "observation_sha256": digest(self.report_bytes),
            "authority": "SEPARATE_SYNTHETIC_OWNER_DECISION_REQUIRED"}
        self.members = dict(sources, **{"release/observation.json": self.report_bytes,
                                       "release/manifest.json": canonical_json(self.manifest)})
        self.archive = zip_bytes(self.members, {r["path"]: r["mode"] for r in self.records})
        verify_archive(self.archive, self.members)
        self._archive_digest = digest(self.archive)
        self._session = None
        self._attempted = False

    def check_sources(self):
        current, records, _ = source_files(self.root, self.revision)
        require(current == self.source and records == self.records, "RELEASE_SOURCE_CHANGED")

    def open(self, directory):
        require(self._session is None, "RELEASE_SESSION_EXISTS")
        require(type(self.archive) is bytes and digest(self.archive) == self._archive_digest, "RELEASE_PACKAGE_CHANGED")
        session = scenario.DocumentSession(directory, self.archive,
            document_id="spectrum-source-release", idempotency_key="spectrum-release-1")
        registry = session.engine.registry_record(session.declaration["connector"]["connector_id"],
                                                   actor_scope="nc25.architect")
        require(registry == self.report["association"]["ledger_registry"], "RELEASE_CONTEXT_CHANGED")
        self._operation = canonical_json(session.op)
        self._session = session
        return session

    def submit(self, package):
        require(self._session is not None, "RELEASE_SESSION_REQUIRED")
        require(not self._attempted, "RELEASE_ALREADY_ATTEMPTED")
        require(type(package) is bytes and digest(package) == self._archive_digest, "RELEASE_PACKAGE_CHANGED")
        require(canonical_json(self._session.op) == self._operation, "RELEASE_OPERATION_CHANGED")
        require(scenario.dr.operation(self._session.op) == package, "RELEASE_PAYLOAD_CHANGED")
        self.check_sources()
        self._attempted = True
        return self._session.submit()


def run(root, revision, directory):
    directory = Path(directory).resolve()
    require(not directory.is_relative_to(ROOT) and not directory.is_relative_to(Path(root).resolve()),
            "OUTPUT_OUTSIDE_SOURCES")
    require(not directory.exists(), "RUN_DIRECTORY_EXISTS")
    prepared = PreparedRelease(root, revision)
    session = prepared.open(directory)
    try:
        session.start()
        # A green observation and the package are present, but authority is absent.
        try:
            session.submit()
        except ContractViolation as exc:
            require(exc.code == "DECLARATION_NOT_ACTIVE", "UNEXPECTED_ACTIVATION_REFUSAL")
        else:
            raise observation.Refusal("UNACTIVATED_RELEASE")
        require(session.target_counts() == (0, 0) and session.engine.structural_remaining == 400,
                "UNACTIVATED_EFFECT")
        session.activate()  # Explicit synthetic owner decision, independent of Spectrum.
        first = prepared.submit(prepared.archive)
        require(first.get("state") == "COMMITTED", "RELEASE_NOT_COMMITTED")
        target = session.read_client.call("GET", "/documents/spectrum-source-release")
        received = base64.b64decode(target["content_base64"], validate=True)
        require(received == prepared.archive, "TARGET_BYTES_CHANGED")
        verify_archive(received, prepared.members)
        session.reopen()
        replay = session.gateway.recover(session.op["idempotency_key"])
        require(replay == first and session.target_counts() == (1, 1)
                and session.engine.structural_remaining == 360, "REPLAY_CHANGED_EFFECT")
        report = {"format": "nc25ol-spectrum-local-release-result/v1", "status": "COMMITTED",
            "synthetic_authority": True, "synthetic_clock": "2026-08-01T10:00:00Z",
            "spectrum_observation": prepared.report["observation"], "source": prepared.source,
            "archive_sha256": digest(received), "archive_bytes": len(received),
            "source_file_count": len(prepared.records), "manifest_sha256": digest(canonical_json(prepared.manifest)),
            "observation_sha256": digest(prepared.report_bytes),
            "document_payload_hash": scenario.dr.payload_hash(session.op),
            "target_receipt": first["downstream"], "ledger_receipt": first["ledger_receipt"],
            "before_activation": "DECLARATION_NOT_ACTIVE", "recovery": "SAME_RECEIPT_ONE_EFFECT",
            "target_documents": 1, "target_receipts": 1,
            "structural_remaining": session.engine.structural_remaining,
            "full_regime_w": "NOT_EVALUATED", "live_witnesses_connected": False,
            "publicly_published": False}
        for name, raw in {"spectrum-source-release.zip": received,
                          "result.json": canonical_json(report)}.items():
            with (directory / name).open("xb") as output:
                output.write(raw)
        return report
    finally:
        session.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spectrum-root", required=True, type=Path)
    parser.add_argument("--spectrum-revision", required=True, help="Operator-selected full commit")
    parser.add_argument("--output", required=True, type=Path, help="New directory outside both source trees")
    args = parser.parse_args()
    result = run(args.spectrum_root, args.spectrum_revision, args.output)
    print(json.dumps({"status": result["status"], "archive_bytes": result["archive_bytes"],
                      "source_file_count": result["source_file_count"], "output": str(args.output)}))
