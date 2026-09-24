"""Build a deterministic, reviewable projection of the shipped DOCX artifact."""

from __future__ import annotations

import argparse
import hashlib
import posixpath
import sys
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_counts import spec_docx_name  # noqa: E402

sys.path.pop(0)

DEFAULT_DOCX = ROOT / spec_docx_name(ROOT)
DEFAULT_OUTPUT = ROOT / "DOCX-AUDIT-PROJECTION.md"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def clean_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def validate_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe DOCX member path: {name!r}")
    if posixpath.normpath(name) != name.rstrip("/"):
        raise ValueError(f"non-canonical DOCX member path: {name!r}")


def paragraph_text(paragraph: ET.Element) -> str:
    chunks: list[str] = []
    for node in paragraph.iter():
        name = local_name(node.tag)
        if name in {"t", "delText"} and node.text:
            chunks.append(node.text)
        elif name == "tab":
            chunks.append("\t")
        elif name in {"br", "cr"}:
            chunks.append("\n")
    return "".join(chunks).strip()


def visible_text(name: str, data: bytes) -> list[str]:
    if not (
        name == "word/document.xml"
        or name.startswith("word/header")
        or name.startswith("word/footer")
        or name in {"word/footnotes.xml", "word/endnotes.xml", "word/comments.xml"}
    ):
        return []
    root = ET.fromstring(data)
    return [text for paragraph in root.iter(f"{{{W_NS}}}p") if (text := paragraph_text(paragraph))]


def render_projection(docx_path: Path) -> bytes:
    source = docx_path.read_bytes()
    sections: list[str] = [
        "# DOCX Audit Projection",
        "",
        "This deterministic projection exposes the shipped DOCX text, package inventory,",
        "relationships, content types and core metadata. The package manifest identifies the binary.",
        "",
        "## Source binding",
        "",
        "- Format: `nc25-docx-audit-projection/v1`",
        f"- Source: `{docx_path.name}`",
        f"- Source bytes: `{len(source)}`",
        f"- Source SHA-256: `{sha256(source)}`",
        "- Generator: `tools/build_docx_audit_projection.py`",
        "",
    ]

    with zipfile.ZipFile(docx_path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("DOCX contains duplicate ZIP member names")
        for name in names:
            validate_member_name(name)
        members: dict[str, bytes] = {
            info.filename: archive.read(info)
            for info in infos
            if not info.is_dir()
        }

    sections.extend([
        "## ZIP member inventory",
        "",
        "| Member | Bytes | SHA-256 |",
        "|---|---:|---|",
    ])
    for name in sorted(members):
        data = members[name]
        sections.append(f"| `{clean_cell(name)}` | {len(data)} | `{sha256(data)}` |")

    sections.extend(["", "## Content types", "", "| Kind | Part or extension | Content type |", "|---|---|---|"])
    content_types = ET.fromstring(members["[Content_Types].xml"])
    content_rows: list[tuple[str, str, str]] = []
    for node in content_types:
        kind = local_name(node.tag)
        key = node.attrib.get("PartName", node.attrib.get("Extension", ""))
        content_rows.append((kind, key, node.attrib.get("ContentType", "")))
    for kind, key, content_type in sorted(content_rows):
        sections.append(f"| {clean_cell(kind)} | `{clean_cell(key)}` | `{clean_cell(content_type)}` |")

    sections.extend(["", "## Relationships", "", "| Relationships part | Id | Type | Target | Mode |", "|---|---|---|---|---|"])
    relationship_rows: list[tuple[str, str, str, str, str]] = []
    for name, data in members.items():
        if not name.endswith(".rels"):
            continue
        root = ET.fromstring(data)
        for node in root:
            relationship_rows.append((
                name,
                node.attrib.get("Id", ""),
                node.attrib.get("Type", ""),
                node.attrib.get("Target", ""),
                node.attrib.get("TargetMode", "Internal"),
            ))
    for row in sorted(relationship_rows):
        sections.append("| " + " | ".join(clean_cell(value) for value in row) + " |")

    sections.extend(["", "## Core properties", "", "| Property | Value |", "|---|---|"])
    core = members.get("docProps/core.xml")
    if core is None:
        sections.append("| `(absent)` |  |")
    else:
        properties = ET.fromstring(core)
        for node in sorted(properties, key=lambda item: local_name(item.tag)):
            sections.append(f"| {clean_cell(local_name(node.tag))} | {clean_cell(node.text or '')} |")

    text_parts: list[tuple[str, list[str]]] = []
    for name in sorted(members):
        paragraphs = visible_text(name, members[name])
        if paragraphs:
            text_parts.append((name, paragraphs))

    sections.extend(["", "## Visible text", ""])
    if not text_parts:
        sections.append("`(no visible WordprocessingML text found)`")
    for name, paragraphs in text_parts:
        sections.extend([f"### `{name}`", ""])
        for index, paragraph in enumerate(paragraphs, start=1):
            normalized = paragraph.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")
            sections.append(f"{index}. {normalized}")
        sections.append("")

    return ("\n".join(sections).rstrip() + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docx", type=Path, default=DEFAULT_DOCX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    docx = args.docx.resolve()
    payload = render_projection(docx)
    output = args.output.resolve()
    if args.check:
        if not output.exists() or output.read_bytes() != payload:
            raise SystemExit("DOCX_AUDIT_PROJECTION=STALE")
        print(f"DOCX_AUDIT_PROJECTION=CURRENT sha256={sha256(payload)}")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(
        "DOCX_AUDIT_PROJECTION=BUILT "
        f"source_sha256={sha256(docx.read_bytes())} "
        f"projection_sha256={sha256(payload)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
