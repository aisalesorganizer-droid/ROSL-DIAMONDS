#!/usr/bin/env python3
"""Static PE triage for ROS Legacy's extracted ros64.exe (V8).

This program only reads file bytes. It never loads or executes the target binary.
It parses PE32/PE32+ headers, sections, data directories, imports, exports,
CodeView debug paths, overlay/certificate ranges, entropy, and printable strings.
The parser is defensive and records parse errors instead of trusting malformed RVAs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_INPUT = Path(r"recon_out_v7\recon_v7_20261013_222227_683898\extracted\ros64.exe")
DEFAULT_OUT = Path("recon_out_v8")
MAX_IMPORT_DESCRIPTORS = 8192
MAX_THUNKS_PER_DLL = 200_000
MAX_EXPORTS = 300_000
MAX_DEBUG_ENTRIES = 4096
MAX_STRING_COUNT = 1_000_000

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "AMD64/x64",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA64",
}
SUBSYSTEM_NAMES = {
    0: "Unknown", 1: "Native", 2: "Windows GUI", 3: "Windows CUI",
    5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
    10: "EFI application", 11: "EFI boot service driver",
    12: "EFI runtime driver", 13: "EFI ROM", 14: "Xbox", 16: "Windows boot application",
}
DIR_NAMES = [
    "export", "import", "resource", "exception", "security_certificate",
    "base_relocation", "debug", "architecture", "global_ptr", "tls",
    "load_config", "bound_import", "iat", "delay_import", "clr_runtime",
    "reserved",
]
SECTION_FLAGS = [
    (0x00000020, "CODE"), (0x00000040, "INITIALIZED_DATA"),
    (0x00000080, "UNINITIALIZED_DATA"), (0x00000200, "INFO"),
    (0x00000800, "REMOVE"), (0x00001000, "COMDAT"),
    (0x02000000, "DISCARDABLE"), (0x04000000, "NOT_CACHED"),
    (0x08000000, "NOT_PAGED"), (0x10000000, "SHARED"),
    (0x20000000, "EXECUTE"), (0x40000000, "READ"), (0x80000000, "WRITE"),
]
CHAR_FLAGS = [
    (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"), (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"), (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"), (0x1000, "SYSTEM"),
    (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"),
]
STRING_HIT_RE = re.compile(
    r"vehicle|track|position|coord|world|\bmap\b|player|camera|entity|actor|model|"
    r"transform|matrix|network|packet|socket|server|target|navigation|pathfind|"
    r"collision|physics|movement|velocity|rotation|latitude|longitude|\bgps\b|radar|"
    r"\.pdb\b|\.dll\b|\.ini\b|\.pak\b|\.nfx\b|\.lua\b|\.json\b|"
    r"telemetry|rtti|vtable|neox|cocos2d|protobuf|grpc|websocket|https?://|"
    r"error|warning|exception|crash|debug|logger|trace|mysql|sql|postgres|redis",
    re.IGNORECASE,
)


class PEError(ValueError):
    pass


def need(data: bytes, off: int, size: int, label: str = "field") -> None:
    if off < 0 or size < 0 or off + size > len(data):
        raise PEError(f"{label} outside file: offset={off}, size={size}, file={len(data)}")


def u16(data: bytes, off: int) -> int:
    need(data, off, 2)
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    need(data, off, 4)
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    need(data, off, 8)
    return struct.unpack_from("<Q", data, off)[0]


def cstring(data: bytes, off: int, max_len: int = 4096) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, min(len(data), off + max_len))
    if end < 0:
        end = min(len(data), off + max_len)
    return data[off:end].decode("ascii", errors="replace")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def flags_to_names(value: int, flags: list[tuple[int, str]]) -> list[str]:
    return [name for bit, name in flags if value & bit]


def decode_pe(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("Missing or truncated DOS MZ header")
    pe_off = u32(data, 0x3C)
    need(data, pe_off, 24, "PE signature + COFF header")
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise PEError(f"Invalid PE signature at 0x{pe_off:X}")

    coff_off = pe_off + 4
    machine = u16(data, coff_off)
    n_sections = u16(data, coff_off + 2)
    timestamp = u32(data, coff_off + 4)
    ptr_sym = u32(data, coff_off + 8)
    num_syms = u32(data, coff_off + 12)
    opt_size = u16(data, coff_off + 16)
    characteristics = u16(data, coff_off + 18)
    opt = coff_off + 20
    need(data, opt, opt_size, "optional header")
    magic = u16(data, opt)
    if magic == 0x20B:
        bits, image_base, dir_start, num_dirs_off = 64, u64(data, opt + 24), 112, 108
        min_opt = 112
    elif magic == 0x10B:
        bits, image_base, dir_start, num_dirs_off = 32, u32(data, opt + 28), 96, 92
        min_opt = 96
    else:
        raise PEError(f"Unsupported optional-header magic 0x{magic:04X}")
    if opt_size < min_opt:
        raise PEError(f"Optional header too short for PE{bits}: {opt_size} < {min_opt}")

    entry_rva = u32(data, opt + 16)
    base_of_code = u32(data, opt + 20)
    if bits == 32:
        base_of_data = u32(data, opt + 24)
    else:
        base_of_data = None
    section_alignment = u32(data, opt + 32)
    file_alignment = u32(data, opt + 36)
    major_os = u16(data, opt + 40)
    minor_os = u16(data, opt + 42)
    major_subsystem = u16(data, opt + 48)
    minor_subsystem = u16(data, opt + 50)
    size_image = u32(data, opt + 56)
    size_headers = u32(data, opt + 60)
    checksum = u32(data, opt + 64)
    subsystem = u16(data, opt + 68)
    dll_chars = u16(data, opt + 70)
    number_dirs = u32(data, opt + num_dirs_off)
    available_dirs = max(0, (opt_size - dir_start) // 8)
    number_dirs = min(number_dirs, available_dirs, 16)

    dirs = []
    for i in range(number_dirs):
        rva = u32(data, opt + dir_start + i * 8)
        size = u32(data, opt + dir_start + i * 8 + 4)
        dirs.append({"index": i, "name": DIR_NAMES[i], "address": rva, "size": size,
                     "address_kind": "file_offset" if i == 4 else "RVA"})

    sec_off = opt + opt_size
    need(data, sec_off, n_sections * 40, "section table")
    sections = []
    for i in range(n_sections):
        off = sec_off + i * 40
        raw_name = data[off:off + 8]
        name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
        vsize = u32(data, off + 8)
        va = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_ptr = u32(data, off + 20)
        sec_chars = u32(data, off + 36)
        raw_valid = raw_ptr <= len(data) and raw_size <= max(0, len(data) - raw_ptr)
        raw_end = raw_ptr + raw_size if raw_valid else None
        sample = data[raw_ptr:raw_end] if raw_valid and raw_end is not None else b""
        sec = {
            "index": i + 1, "name": name, "virtual_size": vsize,
            "virtual_address": va, "raw_size": raw_size, "raw_pointer": raw_ptr,
            "raw_end_exclusive": raw_end, "raw_range_valid": raw_valid,
            "entropy": round(entropy(sample), 5), "characteristics_raw": f"0x{sec_chars:08X}",
            "characteristics": flags_to_names(sec_chars, SECTION_FLAGS),
            "executable": bool(sec_chars & 0x20000000),
            "readable": bool(sec_chars & 0x40000000),
            "writable": bool(sec_chars & 0x80000000),
        }
        if sec["executable"] and sec["writable"]:
            sec["warning"] = "section is both writable and executable"
        sections.append(sec)

    # RVA conversion uses declared virtual spans for lookup, but rejects padding
    # beyond the section's on-disk raw bytes.
    def rva_to_offset(rva: int, size: int = 1) -> int | None:
        if rva < size_headers and rva + size <= len(data):
            return rva
        for sec in sections:
            va = sec["virtual_address"]
            span = max(sec["virtual_size"], sec["raw_size"])
            if va <= rva < va + span:
                delta = rva - va
                if delta + size <= sec["raw_size"] and sec["raw_pointer"] + delta + size <= len(data):
                    return sec["raw_pointer"] + delta
                return None
        return None

    entry_section = None
    for sec in sections:
        if sec["virtual_address"] <= entry_rva < sec["virtual_address"] + max(sec["virtual_size"], sec["raw_size"]):
            entry_section = sec["name"]
            break

    try:
        timestamp_iso = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        timestamp_iso = None

    # Import table. All names are pulled only through validated file ranges.
    imports: list[dict[str, Any]] = []
    import_dir = dirs[1] if len(dirs) > 1 else {"address": 0, "size": 0}
    import_rva, import_size = import_dir["address"], import_dir["size"]
    if import_rva and import_size:
        imp_off = rva_to_offset(import_rva, 20)
        if imp_off is None:
            imports.append({"warning": "import directory RVA does not map to file bytes", "rva": import_rva, "size": import_size})
        else:
            max_desc = min(MAX_IMPORT_DESCRIPTORS, max(1, import_size // 20 + 1))
            for di in range(max_desc):
                desc_off = rva_to_offset(import_rva + di * 20, 20)
                if desc_off is None:
                    imports.append({"warning": "import descriptor array runs outside mapped file bytes"})
                    break
                oft, stamp, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", data, desc_off)
                if not any((oft, stamp, forwarder, name_rva, first_thunk)):
                    break
                name_off = rva_to_offset(name_rva, 1)
                dll_name = cstring(data, name_off) if name_off is not None else "<unmapped DLL name>"
                thunk_rva = oft or first_thunk
                thunk_off = rva_to_offset(thunk_rva, 8 if bits == 64 else 4) if thunk_rva else None
                syms = []
                if thunk_off is None:
                    if thunk_rva:
                        syms.append({"warning": "import thunk RVA does not map to file bytes", "rva": thunk_rva})
                else:
                    stride = 8 if bits == 64 else 4
                    ordinal_mask = 1 << (bits - 1)
                    for ti in range(MAX_THUNKS_PER_DLL):
                        to = rva_to_offset(thunk_rva + ti * stride, stride)
                        if to is None:
                            syms.append({"warning": "import thunk table runs outside mapped file bytes"})
                            break
                        val = int.from_bytes(data[to:to + stride], "little")
                        if val == 0:
                            break
                        if val & ordinal_mask:
                            syms.append({"ordinal": val & 0xFFFF})
                        else:
                            hint_name_rva = val & (ordinal_mask - 1)
                            hn_off = rva_to_offset(hint_name_rva, 2)
                            if hn_off is None:
                                syms.append({"warning": "import-by-name RVA unmapped", "rva": hint_name_rva})
                            else:
                                hint = u16(data, hn_off)
                                name = cstring(data, hn_off + 2)
                                syms.append({"name": name, "hint": hint})
                imports.append({"dll": dll_name, "original_first_thunk_rva": oft,
                                "first_thunk_rva": first_thunk, "symbols": syms,
                                "symbol_count": sum(1 for s in syms if "name" in s or "ordinal" in s)})
            else:
                imports.append({"warning": "import descriptor safety limit reached"})

    # Export table.
    exports: dict[str, Any] = {"present": False, "dll_name": None, "symbols": [], "count": 0}
    export_dir = dirs[0] if dirs else {"address": 0, "size": 0}
    er, es = export_dir["address"], export_dir["size"]
    if er and es:
        eo = rva_to_offset(er, 40)
        if eo is None:
            exports["warning"] = "export directory RVA does not map to file bytes"
        else:
            exports["present"] = True
            base = u32(data, eo + 16)
            n_funcs = min(u32(data, eo + 20), MAX_EXPORTS)
            n_names = min(u32(data, eo + 24), MAX_EXPORTS)
            funcs_rva, names_rva, ords_rva = u32(data, eo + 28), u32(data, eo + 32), u32(data, eo + 36)
            name_rva = u32(data, eo + 12)
            no = rva_to_offset(name_rva, 1) if name_rva else None
            exports["dll_name"] = cstring(data, no) if no is not None else None
            exports["ordinal_base"] = base
            exports["function_count"] = n_funcs
            exports["named_count"] = n_names
            fo = rva_to_offset(funcs_rva, 4 * n_funcs) if n_funcs else None
            no2 = rva_to_offset(names_rva, 4 * n_names) if n_names else None
            oo = rva_to_offset(ords_rva, 2 * n_names) if n_names else None
            if n_funcs and fo is None:
                exports["warning"] = "export function array unmapped"
            elif n_names and (no2 is None or oo is None):
                exports["warning"] = "export name/ordinal array unmapped"
            else:
                named = {}
                for i in range(n_names):
                    nrva = u32(data, no2 + 4 * i)
                    eo_name = rva_to_offset(nrva, 1)
                    ord_index = u16(data, oo + 2 * i)
                    if eo_name is not None and ord_index < n_funcs:
                        named[ord_index] = cstring(data, eo_name)
                out = []
                for i in range(n_funcs):
                    frva = u32(data, fo + 4 * i)
                    if frva == 0:
                        continue
                    forwarded = er <= frva < er + es
                    fwd_name = cstring(data, rva_to_offset(frva, 1)) if forwarded and rva_to_offset(frva, 1) is not None else None
                    out.append({"ordinal": base + i, "name": named.get(i), "rva": frva,
                                "forwarded": forwarded, "forward_target": fwd_name})
                exports["symbols"] = out
                exports["count"] = len(out)

    # Debug directory / CodeView PDB path.
    debug: list[dict[str, Any]] = []
    debug_dir = dirs[6] if len(dirs) > 6 else {"address": 0, "size": 0}
    dr, ds = debug_dir["address"], debug_dir["size"]
    if dr and ds:
        d_off = rva_to_offset(dr, 28)
        if d_off is None:
            debug.append({"warning": "debug directory RVA does not map to file bytes"})
        else:
            for i in range(min(ds // 28, MAX_DEBUG_ENTRIES)):
                o = d_off + i * 28
                if o + 28 > len(data):
                    debug.append({"warning": "truncated debug directory"})
                    break
                chars, stamp, maj, minv, typ, size, addr, ptr = struct.unpack_from("<IIHHIIII", data, o)
                item: dict[str, Any] = {"type": typ, "size": size, "timestamp": stamp,
                                        "address_of_raw_data": addr, "pointer_to_raw_data": ptr}
                if typ == 2 and ptr and size and ptr + size <= len(data):
                    cv = data[ptr:ptr + size]
                    if cv[:4] == b"RSDS" and len(cv) >= 24:
                        guid_b = cv[4:20]
                        # GUID fields in CodeView use mixed-endian Windows byte layout.
                        import uuid
                        item["codeview"] = "RSDS"
                        item["guid"] = str(uuid.UUID(bytes_le=guid_b))
                        item["age"] = u32(cv, 20)
                        item["pdb_path"] = cv[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
                    elif cv[:4] == b"NB10" and len(cv) >= 16:
                        item["codeview"] = "NB10"
                        item["offset"] = u32(cv, 4)
                        item["timestamp"] = u32(cv, 8)
                        item["age"] = u32(cv, 12)
                        item["pdb_path"] = cv[16:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
                debug.append(item)

    # Section / image range warnings and overlay computation.
    valid_ends = [s["raw_end_exclusive"] for s in sections if s["raw_range_valid"] and s["raw_size"]]
    max_raw_end = max([size_headers, *valid_ends], default=size_headers)
    overlay_offset = min(max_raw_end, len(data))
    overlay = data[overlay_offset:]
    anomalies = []
    if not any(s["raw_range_valid"] is False for s in sections):
        pass
    else:
        anomalies.append("One or more sections point outside file bounds")
    if entry_section is None and entry_rva != 0:
        anomalies.append("Entry point RVA did not land in a declared section")
    if size_image and size_image < max((s["virtual_address"] + max(s["virtual_size"], s["raw_size"]) for s in sections), default=0):
        anomalies.append("SizeOfImage is smaller than a declared section span")
    if any(s.get("warning") for s in sections):
        anomalies.extend(s["warning"] for s in sections if s.get("warning"))

    header = {
        "file_name": path.name,
        "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "mz_signature": True,
        "pe_signature": "PE\\0\\0",
        "pe_offset": pe_off,
        "machine_raw": f"0x{machine:04X}",
        "machine": MACHINE_NAMES.get(machine, "unknown"),
        "bits": bits,
        "section_count": n_sections,
        "coff_timestamp_raw": timestamp,
        "coff_timestamp_utc": timestamp_iso,
        "pointer_to_symbol_table": ptr_sym,
        "number_of_symbols": num_syms,
        "optional_header_magic": f"0x{magic:04X}",
        "optional_header_size": opt_size,
        "characteristics_raw": f"0x{characteristics:04X}",
        "characteristics": flags_to_names(characteristics, CHAR_FLAGS),
        "entry_point_rva": entry_rva,
        "entry_point_rva_hex": f"0x{entry_rva:08X}",
        "entry_point_section": entry_section,
        "base_of_code_rva": base_of_code,
        "base_of_data_rva": base_of_data,
        "image_base": image_base,
        "image_base_hex": f"0x{image_base:X}",
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "os_version": f"{major_os}.{minor_os}",
        "subsystem_version": f"{major_subsystem}.{minor_subsystem}",
        "size_of_image": size_image,
        "size_of_headers": size_headers,
        "checksum_field_raw": f"0x{checksum:08X}",
        "subsystem_raw": subsystem,
        "subsystem": SUBSYSTEM_NAMES.get(subsystem, "unknown"),
        "dll_characteristics_raw": f"0x{dll_chars:04X}",
        "dll_characteristics": [name for bit, name in [
            (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"),
            (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"),
            (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"),
            (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE")
        ] if dll_chars & bit],
        "data_directories": dirs,
        "sections": sections,
        "imports": imports,
        "import_dll_count": sum(1 for it in imports if "dll" in it),
        "import_symbol_count": sum(it.get("symbol_count", 0) for it in imports),
        "exports": exports,
        "debug_entries": debug,
        "overlay": {"offset": overlay_offset, "size": len(overlay),
                    "sha256": hashlib.sha256(overlay).hexdigest() if overlay else None,
                    "possible_overlay_present": bool(overlay)},
        "anomalies": anomalies,
        "parse_notes": [
            "Static file parsing only; no binary execution or dynamic loading.",
            "COFF timestamp is reported raw and UTC; timestamps can be absent or intentionally altered.",
            "Overlay bytes are measured after the end of declared headers/sections; this is a heuristic.",
        ],
    }
    return data, {"header": header, "imports": imports, "exports": exports, "debug": debug}


def scan_strings(data: bytes) -> dict[str, list[dict[str, Any]]]:
    ascii_pat = re.compile(rb"[\x20-\x7E]{5,}")
    utf16_pat = re.compile(rb"(?:[\x20-\x7E]\x00){5,}")
    ascii_rows: list[dict[str, Any]] = []
    utf16_rows: list[dict[str, Any]] = []
    seen = set()
    for match in ascii_pat.finditer(data):
        s = match.group().decode("ascii", errors="replace")
        key = ("ascii", match.start(), s)
        if key not in seen:
            ascii_rows.append({"offset": match.start(), "encoding": "ascii", "text": s})
            seen.add(key)
    for match in utf16_pat.finditer(data):
        try:
            s = match.group().decode("utf-16le", errors="replace")
        except UnicodeDecodeError:
            continue
        key = ("utf16le", match.start(), s)
        if key not in seen:
            utf16_rows.append({"offset": match.start(), "encoding": "utf-16le", "text": s})
            seen.add(key)
    if len(ascii_rows) + len(utf16_rows) > MAX_STRING_COUNT:
        raise PEError("Printable-string count exceeded safety cap")
    hits = []
    for row in sorted(ascii_rows + utf16_rows, key=lambda r: (r["offset"], r["encoding"])):
        if STRING_HIT_RE.search(row["text"]):
            hits.append(row)
    return {"ascii": ascii_rows, "utf16le": utf16_rows, "hits": hits}


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["offset", "encoding", "text"])
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="path to extracted ros64.exe")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output root (default: recon_out_v8)")
    parser.add_argument("--self-test", action="store_true", help="run synthetic parser/string tests")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        target = args.input
        if not target.is_file():
            raise FileNotFoundError(f"Input PE not found: {target}. Supply --input <path>.")
        data, result = decode_pe(target)
        strings = scan_strings(data)
        stamp = datetime.now().strftime("recon_v8_%Y%m%d_%H%M%S_%f")
        out_dir = args.out / stamp
        out_dir.mkdir(parents=True, exist_ok=False)
        header = result["header"]
        write_json(out_dir / "pe_static_summary.json", header)
        write_json(out_dir / "imports.json", result["imports"])
        write_json(out_dir / "exports.json", result["exports"])
        write_json(out_dir / "debug_info.json", result["debug"])
        write_rows(out_dir / "strings_ascii.csv", strings["ascii"])
        write_rows(out_dir / "strings_utf16le.csv", strings["utf16le"])
        write_rows(out_dir / "strings_hits.csv", strings["hits"])
        with (out_dir / "pe_static_summary.txt").open("w", encoding="utf-8") as fh:
            fh.write("ROS64.EXE STATIC TRIAGE V8\n" + "=" * 78 + "\n")
            for k in ("file_name", "file_size", "sha256", "md5", "machine", "bits", "section_count",
                      "coff_timestamp_raw", "coff_timestamp_utc", "pe_offset", "entry_point_rva_hex",
                      "entry_point_section", "image_base_hex", "size_of_image", "subsystem",
                      "import_dll_count", "import_symbol_count"):
                fh.write(f"{k}: {header.get(k)}\n")
            fh.write("\nSECTIONS\n" + "-" * 78 + "\n")
            for s in header["sections"]:
                fh.write(f"{s['index']:>2} {s['name']:<8} VA=0x{s['virtual_address']:08X} "
                         f"VSZ={s['virtual_size']:>10} RAW=0x{s['raw_pointer']:08X}+{s['raw_size']:>10} "
                         f"H={s['entropy']:.4f} flags={','.join(s['characteristics'])}\n")
                if s.get("warning"):
                    fh.write(f"   WARNING: {s['warning']}\n")
            fh.write("\nIMPORTS BY DLL\n" + "-" * 78 + "\n")
            for dll in result["imports"]:
                if "dll" not in dll:
                    fh.write(f"WARNING: {dll}\n")
                    continue
                names = [x.get("name", f"ordinal:{x.get('ordinal')}") for x in dll.get("symbols", [])
                         if "name" in x or "ordinal" in x]
                fh.write(f"{dll['dll']} ({len(names)} symbols)\n")
                for name in names:
                    fh.write(f"  {name}\n")
            fh.write("\nEXPORTS\n" + "-" * 78 + "\n")
            for e in result["exports"].get("symbols", []):
                fh.write(f"ordinal={e['ordinal']} name={e.get('name')} RVA=0x{e['rva']:08X}"
                         f" forwarded={e['forwarded']} target={e.get('forward_target')}\n")
            fh.write("\nDEBUG / CODEVIEW\n" + "-" * 78 + "\n")
            fh.write(json.dumps(result["debug"], indent=2, ensure_ascii=False) + "\n")
            fh.write("\nSTATIC STRING SCAN\n" + "-" * 78 + "\n")
            fh.write(f"ASCII strings: {len(strings['ascii'])}\nUTF-16LE strings: {len(strings['utf16le'])}\nKeyword hits: {len(strings['hits'])}\n")
            for row in strings["hits"][:2000]:
                fh.write(f"0x{row['offset']:08X} [{row['encoding']}] {row['text']}\n")
            fh.write("\nANOMALIES / WARNINGS\n" + "-" * 78 + "\n")
            if header["anomalies"]:
                for warning in header["anomalies"]:
                    fh.write(f"- {warning}\n")
            else:
                fh.write("No parser-level section/entry-point anomalies detected. This is not a security verdict.\n")
        print("[COMPLETE] ROS64 static triage v8 finished (no execution performed).")
        print(f"  Input: {target} ({len(data):,} bytes)")
        print(f"  SHA-256: {header['sha256']}")
        print(f"  Architecture: {header['machine']} / PE{header['bits']}")
        print(f"  PE timestamp: {header['coff_timestamp_utc'] or header['coff_timestamp_raw']}")
        print(f"  Sections: {header['section_count']}; imports: {header['import_dll_count']} DLLs / {header['import_symbol_count']} symbols")
        print(f"  Strings: ASCII={len(strings['ascii'])}; UTF-16LE={len(strings['utf16le'])}; keyword hits={len(strings['hits'])}")
        print(f"  Report: {out_dir / 'pe_static_summary.txt'}")
        print(f"  JSON: {out_dir / 'pe_static_summary.json'}")
        print(f"  String hits: {out_dir / 'strings_hits.csv'}")
        return 0
    except (OSError, ValueError, struct.error, PEError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


def run_self_test() -> int:
    # Build the smallest PE32+ fixture needed to verify our offsets and mappings.
    try:
        data = bytearray(0x400)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        coff = 0x84
        struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0x65A0BC00, 0, 0, 240, 0x0022)
        opt = coff + 20
        struct.pack_into("<H", data, opt, 0x20B)
        struct.pack_into("<I", data, opt + 16, 0x1000)  # entry point
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
        struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
        struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
        struct.pack_into("<HH", data, opt + 68, 3, 0x8160)
        struct.pack_into("<I", data, opt + 108, 16)
        sec = opt + 240
        data[sec:sec + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", data, sec + 8, 0x100, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", data, sec + 36, 0x60000020)
        data[0x200:0x206] = b"HELLO!"
        data[0x240:0x25D] = b"StaticVehiclePositionCheck\0"
        path = Path("__ros64_v8_selftest__.bin")
        path.write_bytes(data)
        try:
            parsed_data, result = decode_pe(path)
            assert result["header"]["machine"] == "AMD64/x64"
            assert result["header"]["entry_point_section"] == ".text"
            assert result["header"]["section_count"] == 1
            strings = scan_strings(parsed_data)
            assert any("StaticVehiclePositionCheck" in x["text"] for x in strings["ascii"])
            assert any("Vehicle" in x["text"] or "Position" in x["text"] for x in strings["hits"])
            print("[PASS] PE32+ COFF and optional-header parsing")
            print("[PASS] section table and entry-point section mapping")
            print("[PASS] safe printable-string scanning and keyword hits")
        finally:
            path.unlink(missing_ok=True)
        return 0
    except Exception as exc:
        print(f"[FAIL] V8 self-test: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
