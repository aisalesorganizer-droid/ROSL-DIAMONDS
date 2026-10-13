#!/usr/bin/env python3
"""V9 static symbol/RTTI survey for ROS Legacy's extracted ros64.exe.

This tool only reads the PE as bytes. It never executes, loads, or injects into it.
It inventories MSVC-decorated names, RTTI type names, namespace/scope clusters,
known reverse-engineering targets, PE section mapping, and CodeView/PDB identity.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_INPUT = Path(r"recon_out_v7\recon_v7_20261013_222227_683898\extracted\ros64.exe")
DEFAULT_OUT = Path("recon_out_v9")
MAX_FILE_SIZE = 1024 * 1024 * 1024
MAX_STRINGS = 1_000_000
MIN_STRING_LENGTH = 5

# Framework/third-party names are retained in full inventories, but excluded from
# the lower-noise custom-target shortlist when recognizable.
FRAMEWORK_RE = re.compile(
    r"cocos2d|cocostudio|cocosbuilder|std@@|flatbuffers|tinyxml2|tinyxml|rapidjson|"
    r"physx|Nv@@|FMOD|fmod|boost|protobuf|google::|grpc|openssl|sqlite|curl|zlib|"
    r"nlohmann|fmt::|absl::|ATL::|Microsoft::WRL",
    re.IGNORECASE,
)

RTTI_RE = re.compile(r"^\.\?A(?P<kind>W4|V|U|T)(?P<body>.+?)@@$")
# Names requested by the existing reverse-engineering context plus useful
# generic game-client categories. Results are leads, not proof of semantics.
TARGET_TERMS = [
    "ModelFxData", "world@neox", "neox@@", "Vehicle", "vehicle", "vehicl",
    "mount", "riding", "rideable", "Player", "player", "Character", "character",
    "Actor", "actor", "Entity", "entity", "World", "world", "GameObject",
    "GameData", "ModelData", "FxData", "Position", "position", "Rotation",
    "rotation", "Transform", "transform", "Coordinate", "coordinate", "Vec3",
    "Vector3", "Quaternion", "Velocity", "velocity", "Speed", "speed",
    "Movement", "movement", "Collision", "collision", "Physics", "physics",
    "Camera", "camera", "Target", "target", "Follow", "follow", "Track", "track",
    "Map", "map", "NavMesh", "PathFind", "NPC", "Monster", "Pet", "Inventory",
    "Item", "Skill", "Attack", "Buff", "Packet", "Network", "Socket", "Server",
    "Session", "Login", "Account", "Telemetry", "Radar", "Latitude", "Longitude",
]
TARGET_RE = re.compile("|".join(re.escape(x) for x in sorted(TARGET_TERMS, key=len, reverse=True)), re.IGNORECASE)
EXACT_ANCHOR_RE = re.compile(r"ModelFxData|world@neox|neox@@|Vehicle|vehicle|mount|riding|rideable", re.IGNORECASE)


def u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise ValueError(f"u16 outside file at {off}")
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ValueError(f"u32 outside file at {off}")
    return struct.unpack_from("<I", data, off)[0]


def cstring(data: bytes, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("ascii", errors="replace")


def scan_ascii_strings(data: bytes) -> list[dict[str, Any]]:
    pattern = re.compile(rb"[\x20-\x7E]{%d,}" % MIN_STRING_LENGTH)
    out: list[dict[str, Any]] = []
    for m in pattern.finditer(data):
        out.append({"offset": m.start(), "text": m.group().decode("ascii", errors="replace")})
        if len(out) > MAX_STRINGS:
            raise ValueError(f"Printable-string count exceeded safety cap ({MAX_STRINGS:,})")
    return out


def rtti_type(text: str) -> dict[str, str] | None:
    m = RTTI_RE.match(text)
    if not m:
        return None
    body = m.group("body")
    parts = [p for p in body.split("@") if p]
    if not parts:
        return None
    kind_code = m.group("kind")
    kind = {"V": "class", "U": "struct", "W4": "enum", "T": "union"}.get(kind_code, "unknown")
    # MSVC stores nested class/namespace components from inner to outer.
    qualified = "::".join(reversed(parts))
    return {"kind": kind, "raw_body": body, "qualified_name": qualified,
            "leaf_name": parts[0], "components_inner_to_outer": "|".join(parts)}


def decorated_symbol(text: str) -> bool:
    return text.startswith("?") and len(text) >= 6 and " " not in text and "\t" not in text and "\n" not in text


def scope_path(text: str) -> str | None:
    # Scope prefixes in MSVC decorated names end at the first @@. For example,
    # ?create@ExtPxManager@Blast@Nv@@... -> Nv::Blast::ExtPxManager.
    if not decorated_symbol(text):
        return None
    prefix = text.split("@@", 1)[0]
    parts = prefix.split("@")[1:]
    parts = [p for p in parts if p and p not in ("?",)]
    if not parts:
        return "<global-or-compiler-generated>"
    return "::".join(reversed(parts))


def map_pe(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Input does not have an MZ header")
    pe_off = u32(data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("PE signature or COFF header is invalid")
    coff = pe_off + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    timestamp = u32(data, coff + 4)
    optional_size = u16(data, coff + 16)
    opt = coff + 20
    if opt + optional_size > len(data) or optional_size < 96:
        raise ValueError("Optional header is outside file or too short")
    magic = u16(data, opt)
    if magic == 0x20B:
        bits, dir_start, num_dir_off = 64, 112, 108
    elif magic == 0x10B:
        bits, dir_start, num_dir_off = 32, 96, 92
    else:
        raise ValueError(f"Unsupported optional-header magic 0x{magic:04X}")
    if optional_size < dir_start:
        raise ValueError("Optional header does not hold standard data directories")
    entry_rva = u32(data, opt + 16)
    image_base = struct.unpack_from("<Q" if bits == 64 else "<I", data, opt + (24 if bits == 64 else 28))[0]
    size_image = u32(data, opt + 56)
    size_headers = u32(data, opt + 60)
    num_dirs = min(u32(data, opt + num_dir_off), 16, max(0, (optional_size - dir_start) // 8))
    dirs = []
    for i in range(num_dirs):
        dirs.append((u32(data, opt + dir_start + i * 8), u32(data, opt + dir_start + i * 8 + 4)))
    section_off = opt + optional_size
    if section_off + section_count * 40 > len(data):
        raise ValueError("Section table runs outside file")
    sections = []
    for i in range(section_count):
        off = section_off + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size = u32(data, off + 8)
        va = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_ptr = u32(data, off + 20)
        flags = u32(data, off + 36)
        valid = raw_ptr <= len(data) and raw_size <= len(data) - raw_ptr
        sections.append({"name": name, "virtual_size": virtual_size, "virtual_address": va,
                         "raw_size": raw_size, "raw_pointer": raw_ptr, "raw_range_valid": valid,
                         "executable": bool(flags & 0x20000000), "readable": bool(flags & 0x40000000),
                         "writable": bool(flags & 0x80000000), "characteristics_raw": f"0x{flags:08X}"})

    def rva_to_offset(rva: int, size: int = 1) -> int | None:
        if rva < size_headers and rva + size <= len(data):
            return rva
        for sec in sections:
            va = sec["virtual_address"]
            span = max(sec["virtual_size"], sec["raw_size"])
            delta = rva - va
            if 0 <= delta < span:
                if delta + size <= sec["raw_size"] and sec["raw_pointer"] + delta + size <= len(data):
                    return sec["raw_pointer"] + delta
                return None
        return None

    entry_section = next((s["name"] for s in sections
                          if s["virtual_address"] <= entry_rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"])), None)
    debug_info = []
    if len(dirs) > 6:
        debug_rva, debug_size = dirs[6]
        debug_off = rva_to_offset(debug_rva, min(debug_size, 28)) if debug_rva and debug_size >= 28 else None
        if debug_off is not None:
            for i in range(min(debug_size // 28, 4096)):
                off = debug_off + i * 28
                if off + 28 > len(data):
                    break
                _, ts, major, minor, typ, size, addr_raw, ptr_raw = struct.unpack_from("<IIHHIIII", data, off)
                if not any((ts, major, minor, typ, size, addr_raw, ptr_raw)):
                    continue
                item: dict[str, Any] = {"type": typ, "timestamp_raw": ts, "size": size,
                                        "address_of_raw_data": addr_raw, "pointer_to_raw_data": ptr_raw}
                if typ == 2 and ptr_raw + size <= len(data) and size >= 24 and data[ptr_raw:ptr_raw + 4] == b"RSDS":
                    guid = uuid.UUID(bytes_le=data[ptr_raw + 4:ptr_raw + 20])
                    age = u32(data, ptr_raw + 20)
                    path = cstring(data, ptr_raw + 24, min(4096, max(1, size - 24)))
                    item.update({"codeview": "RSDS", "guid": str(guid), "age": age, "pdb_path": path,
                                 "pdb_symbol_key": guid.hex + format(age, "x")})
                debug_info.append(item)
    try:
        timestamp_utc = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        timestamp_utc = None
    return {"file_size": len(data), "machine_raw": f"0x{machine:04X}",
            "machine": {0x8664: "AMD64/x64", 0x014C: "x86", 0xAA64: "ARM64"}.get(machine, "unknown"),
            "bits": bits, "optional_header_magic": f"0x{magic:04X}", "pe_offset": pe_off,
            "section_count": section_count, "timestamp_raw": timestamp, "timestamp_utc": timestamp_utc,
            "entry_point_rva": entry_rva, "entry_point_rva_hex": f"0x{entry_rva:08X}",
            "entry_point_section": entry_section, "image_base": image_base,
            "size_of_image": size_image, "size_of_headers": size_headers,
            "sections": sections, "debug_info": debug_info}


def scan_and_classify(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Counter[str]]:
    strings = scan_ascii_strings(data)
    rtti_rows: list[dict[str, Any]] = []
    symbol_rows: list[dict[str, Any]] = []
    target_rows: list[dict[str, Any]] = []
    scope_counts: Counter[str] = Counter()
    for row in strings:
        text = row["text"]
        rtti = rtti_type(text)
        if rtti:
            rtti_rows.append({"offset": row["offset"], "raw": text, **rtti,
                              "third_party_or_framework": bool(FRAMEWORK_RE.search(text))})
        if decorated_symbol(text):
            scope = scope_path(text)
            symbol_rows.append({"offset": row["offset"], "raw": text, "scope_path_candidate": scope,
                                "third_party_or_framework": bool(FRAMEWORK_RE.search(text))})
            if scope:
                scope_counts[scope] += 1
        if TARGET_RE.search(text):
            anchors = sorted({term for term in TARGET_TERMS if term.lower() in text.lower()}, key=str.lower)
            framework = bool(FRAMEWORK_RE.search(text))
            target_rows.append({"offset": row["offset"], "text": text, "matched_terms": "|".join(anchors),
                                "exact_anchor_match": bool(EXACT_ANCHOR_RE.search(text)),
                                "framework_filtered_candidate": not framework,
                                "third_party_or_framework": framework})
    return rtti_rows, symbol_rows, target_rows, strings, scope_counts


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_self_test() -> int:
    try:
        sample = (
            b"hello\x00"
            b".?AVModelFxData@world@neox@@\x00"
            b"??0Vec3@cocos2d@@QEAA@XZ\x00"
            b"?update@Vehicle@world@neox@@QEAAXXZ\x00"
        )
        strings = scan_ascii_strings(sample)
        texts = [x["text"] for x in strings]
        assert "hello" in texts
        assert any(t.startswith(".?AVModelFxData") for t in texts)
        type_info = next(rtti_type(t) for t in texts if t.startswith(".?AVModelFxData"))
        assert type_info["qualified_name"] == "neox::world::ModelFxData"
        assert any(decorated_symbol(t) for t in texts if t.startswith("??0Vec3"))
        assert any(TARGET_RE.search(t) for t in texts if "Vehicle" in t)
        # Minimal PE32+ fixture: DOS stub + PE signature + COFF + optional header + 1 section.
        b = bytearray(0x400)
        b[:2] = b"MZ"
        struct.pack_into("<I", b, 0x3C, 0x80)
        b[0x80:0x84] = b"PE\0\0"
        coff = 0x84
        struct.pack_into("<HHIIIHH", b, coff, 0x8664, 1, 1647863059, 0, 0, 240, 0x0022)
        opt = coff + 20
        struct.pack_into("<H", b, opt, 0x20B)
        struct.pack_into("<I", b, opt + 16, 0x1000)
        struct.pack_into("<Q", b, opt + 24, 0x140000000)
        struct.pack_into("<I", b, opt + 56, 0x2000)
        struct.pack_into("<I", b, opt + 60, 0x200)
        struct.pack_into("<I", b, opt + 108, 16)
        sec = opt + 240
        b[sec:sec + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", b, sec + 8, 0x100, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", b, sec + 36, 0x60000020)
        pe = map_pe(bytes(b))
        assert pe["machine"] == "AMD64/x64" and pe["entry_point_section"] == ".text"
        print("[PASS] ASCII string extraction and target matching")
        print("[PASS] MSVC RTTI namespace reconstruction")
        print("[PASS] decorated-symbol scope inventory")
        print("[PASS] PE32+ header/section mapping")
        return 0
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="path to extracted ros64.exe")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output root, default recon_out_v9")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        if not args.input.is_file():
            raise FileNotFoundError(f"Input not found: {args.input}; use --input <path> if needed")
        size = args.input.stat().st_size
        if size <= 0 or size > MAX_FILE_SIZE:
            raise ValueError(f"Input size outside safety bounds: {size:,} bytes")
        data = args.input.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        pe = map_pe(data)
        rtti_rows, symbol_rows, target_rows, strings, scope_counts = scan_and_classify(data)
        stamp = datetime.now().strftime("recon_v9_%Y%m%d_%H%M%S_%f")
        out_dir = args.out / stamp
        out_dir.mkdir(parents=True, exist_ok=False)

        custom_rtti = [r for r in rtti_rows if not r["third_party_or_framework"]]
        anchor_rows = [r for r in target_rows if r["exact_anchor_match"]]
        custom_targets = [r for r in target_rows if r["framework_filtered_candidate"]]
        scope_rows = [{"scope_path_candidate": scope, "symbol_count": count,
                       "third_party_or_framework": bool(FRAMEWORK_RE.search(scope))}
                      for scope, count in scope_counts.most_common()]
        write_csv(out_dir / "rtti_types.csv", sorted(rtti_rows, key=lambda r: r["offset"]),
                  ["offset", "kind", "qualified_name", "leaf_name", "raw_body", "components_inner_to_outer", "third_party_or_framework", "raw"])
        write_csv(out_dir / "mangled_symbols.csv", sorted(symbol_rows, key=lambda r: r["offset"]),
                  ["offset", "scope_path_candidate", "third_party_or_framework", "raw"])
        write_csv(out_dir / "symbol_scope_inventory.csv", scope_rows,
                  ["scope_path_candidate", "symbol_count", "third_party_or_framework"])
        write_csv(out_dir / "target_keyword_hits.csv", sorted(target_rows, key=lambda r: r["offset"]),
                  ["offset", "exact_anchor_match", "framework_filtered_candidate", "third_party_or_framework", "matched_terms", "text"])
        write_csv(out_dir / "custom_target_candidates.csv", sorted(custom_targets, key=lambda r: (not r["exact_anchor_match"], r["offset"])),
                  ["offset", "exact_anchor_match", "matched_terms", "text"])

        anchors = []
        for term in ["ModelFxData", "world@neox", "neox@@", "Vehicle", "vehicle", "mount", "riding", "rideable"]:
            found = [r for r in strings if term.lower() in r["text"].lower()]
            anchors.append({"term": term, "count": len(found), "samples": [{"offset": r["offset"], "text": r["text"][:300]} for r in found[:25]]})
        summary = {
            "input_path": str(args.input), "file_size": len(data), "sha256": digest,
            "pe": pe, "ascii_printable_string_count": len(strings),
            "rtti_descriptor_count": len(rtti_rows), "unique_rtti_qualified_names": len({r["qualified_name"] for r in rtti_rows}),
            "non_framework_rtti_count": len(custom_rtti),
            "decorated_symbol_count": len(symbol_rows), "unique_scope_path_candidates": len(scope_counts),
            "keyword_hit_count": len(target_rows), "non_framework_keyword_hit_count": len(custom_targets),
            "exact_anchor_hit_count": len(anchor_rows), "exact_anchor_terms": anchors,
            "pdb_records": [x for x in pe["debug_info"] if x.get("codeview") == "RSDS"],
            "interpretation_notes": [
                "PE/string/RTTI inspection only; target code was not executed.",
                "MSVC RTTI names are reconstructed by reversing encoded scope components; template types may need manual demangling.",
                "Decorated symbol scope paths are heuristics and may include classes as well as namespaces.",
                "Keyword hits and scope names are leads, not proof of runtime behavior.",
                "Framework filtering only suppresses common third-party names; unusual dependencies can remain in the custom shortlist."
            ]
        }
        write_json(out_dir / "symbol_survey.json", summary)
        report = [
            "ROS64 STATIC SYMBOL SURVEY V9", "=" * 80,
            f"Input: {args.input}", f"Size: {len(data):,} bytes", f"SHA-256: {digest}",
            f"Architecture: {pe['machine']} / PE{pe['bits']}", f"PE timestamp: {pe['timestamp_utc']}",
            f"Entry point: {pe['entry_point_rva_hex']} in section {pe['entry_point_section']}",
            f"Sections: {pe['section_count']}; declared image size: {pe['size_of_image']:,} bytes",
            f"ASCII strings: {len(strings):,}", f"RTTI descriptors: {len(rtti_rows):,} ({len(custom_rtti):,} outside recognized frameworks)",
            f"MSVC-decorated strings: {len(symbol_rows):,}; scope candidates: {len(scope_counts):,}",
            f"Target keyword hits: {len(target_rows):,}; lower-noise custom candidates: {len(custom_targets):,}",
            f"Exact high-priority anchor hits: {len(anchor_rows):,}", "", "PDB IDENTITY",
        ]
        pdb_records = summary["pdb_records"]
        if pdb_records:
            for record in pdb_records:
                report.append(f"PDB: {record.get('pdb_path')} | GUID={record.get('guid')} | age={record.get('age')} | key={record.get('pdb_symbol_key')}")
        else:
            report.append("No valid RSDS CodeView record found by V9 parser.")
        report.extend(["", "HIGH-PRIORITY ANCHOR COUNTS"])
        for item in anchors:
            report.append(f"{item['term']}: {item['count']}")
            for sample in item["samples"][:5]:
                report.append(f"  0x{sample['offset']:X}: {sample['text']}")
        report.extend(["", "OUTPUT FILES", "- symbol_survey.json: overall PE facts, anchor counts, PDB identity", "- rtti_types.csv: extracted MSVC RTTI class/struct/enum candidates", "- mangled_symbols.csv: decorated symbols and heuristic scope candidates", "- symbol_scope_inventory.csv: ranked scope-path candidates", "- target_keyword_hits.csv: all target-term matches (includes framework noise)", "- custom_target_candidates.csv: lower-noise filtered subset for manual review", "", "LIMITATIONS", *[f"- {n}" for n in summary["interpretation_notes"]]])
        (out_dir / "symbol_survey.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
        print("[COMPLETE] ROS64 static symbol survey v9 finished (no execution performed).")
        print(f"  Input: {args.input} ({len(data):,} bytes)")
        print(f"  SHA-256: {digest}")
        print(f"  RTTI descriptors: {len(rtti_rows):,}; non-framework candidates={len(custom_rtti):,}")
        print(f"  Decorated symbols: {len(symbol_rows):,}; scope candidates={len(scope_counts):,}")
        print(f"  Keyword hits: {len(target_rows):,}; lower-noise candidates={len(custom_targets):,}")
        print(f"  Exact anchors matched: {len(anchor_rows):,}")
        print(f"  Report: {out_dir / 'symbol_survey.txt'}")
        print(f"  JSON: {out_dir / 'symbol_survey.json'}")
        print(f"  RTTI: {out_dir / 'rtti_types.csv'}")
        print(f"  Candidate hits: {out_dir / 'custom_target_candidates.csv'}")
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
