#!/usr/bin/env python3
"""ROSLegacy NSISBI payload mapper/extractor v7.

This tool performs static, read-only analysis of the NSISBI installer and its
external .nsisbin sidecar. Default operation inventories file-extraction
instructions and maps them to length-prefixed sidecar records. It does not run
the installer and does not extract payloads unless --extract-name or
--extract-offset is explicitly supplied.

Confirmed format basis for the target build:
- NSISBI firstheader is 36 bytes and declares the sidecar size as low/high DWORDs.
- Each sidecar record has an 8-byte little-endian length word; bit 63 marks
  compression and the lower 63 bits give stored payload size.
- The compiled header's compressed payload uses a 3-byte little-endian length
  framing layer containing independent raw-DEFLATE blocks, terminated by a
  final 00 00 00. V5 already validated this on the real 559,820-byte header.
- The decoded header's file entries are 36-byte records (opcode + 8 DWORDs).
  Opcode 20 is treated as EW_EXTRACTFILE; each file data offset is params[2:4].
- The last File operand (params[7]) is preserved as raw and unclassified. V6 treated it as
  a per-file CRC without sufficient format-level confirmation; V7 does not assume that.

The target sidecar was not available in this authoring runtime, so any
individual game-file extraction must still be validated on the user's copy.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_DIR = Path(r"C:\Users\MAFIA\Downloads\Compressed\ROSLegacy\Diamonds")
DEFAULT_EXE = "ROSLegacy_Install_202609251811.exe"
DEFAULT_SIDECAR = "ROSLegacy_Install_202609251811.nsisbin"
DEFAULT_OUT = Path("recon_out_v7")

NSISBI_MARKER = b"\xef\xbe\xad\xdeNullsoftInst"
FH_SIG = 0xDEADBEEF
NSISBI_MAGIC_WORDS = (0x6C6C754E, 0x74666F73, 0x74736E49)
FIRSTHEADER_SIZE = 36
COMPRESSED_FLAG_64 = 1 << 63
LENGTH_MASK_63 = COMPRESSED_FLAG_64 - 1
MAX_HEADER_SIZE = 64 * 1024 * 1024
MAX_HEADER_FRAMES = 100_000
MAX_FILE_FRAME_SIZE = 64 * 1024 * 1024
ENTRY_SIZE = 36
PAGE_SIZE_UNICODE_NSISBI = 64
SECTION_FIXED_BYTES = 24
NSIS_MAX_STRLEN = 1024

# Core opcode names for the NSISBI/NSIS-3 family. The mapping for codes after
# 64 is intentionally labeled version-dependent; do not infer semantics from
# those names without validating against this installer's exact runtime.
OPCODE_NAMES = {
    0: "INVALID_OPCODE", 1: "RET", 2: "NOP_OR_GOTO", 3: "ABORT", 4: "QUIT",
    5: "CALL", 6: "UPDATETEXT_OR_DETAILPRINT", 7: "SLEEP", 8: "BRINGTOFRONT",
    9: "CHDETAILSVIEW", 10: "SETFILEATTRIBUTES", 11: "CREATEDIR_OR_SETOUTPATH",
    12: "IFFILEEXISTS", 13: "SETFLAG", 14: "IFFLAG", 15: "GETFLAG",
    16: "RENAME", 17: "GETFULLPATHNAME", 18: "SEARCHPATH", 19: "GETTEMPFILENAME",
    20: "EXTRACTFILE", 21: "EXTRACTSTUBFILE_VERSION_DEPENDENT",
    22: "VERIFYEXTERNALFILE_VERSION_DEPENDENT", 23: "DELETEFILE", 24: "MESSAGEBOX",
    25: "RMDIR", 26: "STRLEN", 27: "ASSIGNVAR_OR_STRCOPY", 28: "STRCMP",
    29: "READENVSTR_OR_EXPANDENVSTRINGS", 30: "INTCMP", 31: "INTOP", 32: "INTFMT",
    33: "PUSHPOP_OR_EXCHANGE", 34: "FINDWINDOW", 35: "SENDMESSAGE", 36: "ISWINDOW",
    37: "GETDLGITEM", 38: "SETCTLCOLORS", 39: "LOADANDSETIMAGE", 40: "CREATEFONT",
    41: "SHOWWINDOW", 42: "SHELLEXEC", 43: "EXECUTE", 44: "GETFILETIME",
    45: "GETDLLVERSION", 46: "REGISTERDLL_OR_PLUGIN_CALL", 47: "CREATESHORTCUT",
    48: "COPYFILES", 49: "REBOOT", 50: "WRITEINI", 51: "READINISTR", 52: "DELREG",
    53: "WRITEREG", 54: "READREGSTR", 55: "REGENUM", 56: "FCLOSE", 57: "FOPEN",
    58: "FPUTS_OR_FILEWRITE", 59: "FGETS_OR_FILEREAD", 60: "FSEEK", 61: "FINDCLOSE",
    62: "FINDNEXT", 63: "FINDFIRST", 64: "WRITEUNINSTALLER",
    65: "OPCODE_65_VERSION_DEPENDENT", 66: "OPCODE_66_VERSION_DEPENDENT",
    67: "OPCODE_67_VERSION_DEPENDENT", 68: "OPCODE_68_VERSION_DEPENDENT",
    69: "OPCODE_69_VERSION_DEPENDENT",
}

INTERNAL_VARS = [
    "CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP", "PLUGINSDIR",
    "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK", "_OUTDIR",
]
SHELL_NAMES = [
    "DESKTOP", "INTERNET", "SMPROGRAMS", "CONTROLS", "PRINTERS", "DOCUMENTS",
    "FAVORITES", "SMSTARTUP", "RECENT", "SENDTO", "BITBUCKET", "STARTMENU", None,
    "MUSIC", "VIDEOS", None, "DESKTOP", "DRIVES", "NETWORK", "NETHOOD", "FONTS",
    "TEMPLATES", "STARTMENU", "SMPROGRAMS", "SMSTARTUP", "DESKTOP", "APPDATA",
    "PRINTHOOD", "LOCALAPPDATA", "ALTSTARTUP", "ALTSTARTUP", "FAVORITES",
    "INTERNET_CACHE", "COOKIES", "HISTORY", "APPDATA", "WINDIR", "SYSDIR",
    "PROGRAM_FILES", "PICTURES", "PROFILE", "SYSTEMX86", "PROGRAM_FILESX86",
    "PROGRAM_FILES_COMMON", "PROGRAM_FILES_COMMONX8", "TEMPLATES", "DOCUMENTS",
    "ADMINTOOLS", "ADMINTOOLS", "CONNECTIONS", None, None, None, "MUSIC", "PICTURES",
    "VIDEOS", "RESOURCES", "RESOURCES_LOCALIZED", "COMMON_OEM_LINKS", "CDBURN_AREA",
    None, "COMPUTERSNEARME",
]


def u32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def human_size(value: int | None) -> str:
    if value is None:
        return "unknown"
    n = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_firstheader(exe_bytes: bytes) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    start = 0
    while True:
        marker = exe_bytes.find(NSISBI_MARKER, start)
        if marker < 0:
            break
        start = marker + 1
        header_off = marker - 4
        if header_off < 0 or header_off + FIRSTHEADER_SIZE > len(exe_bytes):
            continue
        raw = exe_bytes[header_off:header_off + FIRSTHEADER_SIZE]
        flags, sig = u32(raw, 0), u32(raw, 4)
        magic = tuple(u32(raw, 8 + 4 * i) for i in range(3))
        if sig != FH_SIG or magic != NSISBI_MAGIC_WORDS:
            continue
        low, high = u32(raw, 28), u32(raw, 32)
        candidates.append({
            "offset": header_off,
            "marker_offset": marker,
            "flags": flags,
            "flags_hex": f"0x{flags:08X}",
            "header_output_size": u32(raw, 20),
            "length_of_all_following_data": u32(raw, 24),
            "external_size_declared": (high << 32) | low,
            "external_size_low": low,
            "external_size_high": high,
        })
    if len(candidates) != 1:
        raise ValueError(f"Expected exactly one validated NSISBI firstheader; found {len(candidates)}")
    return candidates[0]


def decode_framed_raw_deflate(stored: bytes, expected_size: int | None, max_output: int) -> tuple[bytes, list[dict[str, int]]]:
    """Decode 3-byte LE compressed-length framing + independent raw-DEFLATE blocks."""
    pos = 0
    chunks: list[bytes] = []
    reports: list[dict[str, int]] = []
    total = 0
    terminator = False
    while pos < len(stored):
        if len(reports) >= MAX_HEADER_FRAMES:
            raise ValueError("Exceeded compressed-frame safety limit")
        if len(stored) - pos < 3:
            raise ValueError(f"Truncated three-byte frame prefix at offset {pos}")
        frame_offset = pos
        frame_len = stored[pos] | (stored[pos + 1] << 8) | (stored[pos + 2] << 16)
        pos += 3
        if frame_len == 0:
            if pos != len(stored):
                raise ValueError(f"Zero-length terminator at {frame_offset} is not at the end")
            terminator = True
            break
        if frame_len > len(stored) - pos:
            raise ValueError(f"Frame at {frame_offset} declares {frame_len} bytes beyond stream bounds")
        block = stored[pos:pos + frame_len]
        pos += frame_len
        try:
            decoded = zlib.decompress(block, wbits=-15)
        except zlib.error as exc:
            raise ValueError(f"Raw-DEFLATE decode failed in frame {len(reports)} at {frame_offset}: {exc}") from exc
        total += len(decoded)
        if total > max_output:
            raise ValueError(f"Decompressed data exceeded safety limit ({total} > {max_output})")
        chunks.append(decoded)
        reports.append({
            "index": len(reports), "framing_offset": frame_offset,
            "compressed_bytes": frame_len, "decoded_bytes": len(decoded),
        })
    if not terminator:
        raise ValueError("Missing final three-byte zero-length stream terminator")
    decoded_all = b"".join(chunks)
    if expected_size is not None and len(decoded_all) != expected_size:
        raise ValueError(f"Decoded {len(decoded_all)} bytes; expected {expected_size}")
    return decoded_all, reports


def decode_embedded_header(exe_bytes: bytes, firstheader: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    record_offset = firstheader["offset"] + FIRSTHEADER_SIZE
    if record_offset + 8 > len(exe_bytes):
        raise ValueError("Embedded header length prefix extends beyond installer")
    word = u64(exe_bytes, record_offset)
    compressed = bool(word & COMPRESSED_FLAG_64)
    stored_size = word & LENGTH_MASK_63
    body_offset = record_offset + 8
    body_end = body_offset + stored_size
    if body_end > len(exe_bytes):
        raise ValueError("Embedded header record body extends beyond installer")
    stored = exe_bytes[body_offset:body_end]
    expected = firstheader["header_output_size"]
    if expected <= 0 or expected > MAX_HEADER_SIZE:
        raise ValueError(f"Unreasonable decoded header size: {expected}")
    if compressed:
        decoded, blocks = decode_framed_raw_deflate(stored, expected, MAX_HEADER_SIZE)
        codec = "NSISBI framed raw-DEFLATE"
        terminator = True
    else:
        decoded, blocks = stored, [{"index": 0, "compressed_bytes": stored_size, "decoded_bytes": len(stored)}]
        codec, terminator = "uncompressed-copy", False
        if len(decoded) != expected:
            raise ValueError(f"Uncompressed header has {len(decoded)} bytes; expected {expected}")
    equation = FIRSTHEADER_SIZE + 8 + stored_size + 8 == firstheader["length_of_all_following_data"]
    summary = {
        "record_prefix_offset": record_offset,
        "record_prefix_hex": f"0x{word:016X}",
        "compressed": compressed,
        "stored_bytes": stored_size,
        "body_offset": body_offset,
        "body_end_exclusive": body_end,
        "codec": codec,
        "decoded_bytes": len(decoded),
        "expected_decoded_bytes": expected,
        "decoded_size_matches": len(decoded) == expected,
        "terminator_found": terminator,
        "framed_blocks": blocks,
        "decoded_sha256": sha256_bytes(decoded),
        "following_length_equation_matches": equation,
        "trailing_exe_bytes_after_record": len(exe_bytes) - body_end,
    }
    if not equation:
        raise ValueError("Firstheader following-length equation did not match; refusing to proceed")
    return decoded, summary


def parse_string_table(header: bytes, start: int, end: int) -> dict[int, str]:
    if start < 0 or end < start or end > len(header) or start % 2 or end % 2:
        raise ValueError(f"Invalid UTF-16 string-table bounds: start={start}, end={end}")
    result: dict[int, str] = {}
    pos = start
    while pos + 1 < end:
        q = pos
        while q + 1 < end and (header[q] != 0 or header[q + 1] != 0):
            q += 2
        if q > pos:
            try:
                text = header[pos:q].decode("utf-16-le", errors="replace")
            except UnicodeError:
                text = ""
            result[(pos - start) // 2] = text
        pos = q + 2
    return result


def resolve_nsis_string(value: str) -> str:
    """Resolve common NSIS-3 Unicode variable tokens without altering unknown tokens."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\x03" and i + 1 < len(value):
            code = ord(value[i + 1])
            if 0x80 <= code <= 0xFF:
                idx = code - 0x80
                if idx < 10:
                    out.append(f"${idx}")
                elif idx < 20:
                    out.append(f"$R{idx - 10}")
                elif idx < 20 + len(INTERNAL_VARS):
                    out.append(f"${INTERNAL_VARS[idx - 20]}")
                else:
                    out.append(f"$_{idx - (20 + len(INTERNAL_VARS))}_")
                i += 2
                continue
            out.append("[[NSIS_VAR]]")
            i += 1
            continue
        if ch == "\x02" and i + 1 < len(value):
            code = ord(value[i + 1])
            if 0x80 <= code <= 0xFF:
                idx = code - 0x80
                shell = SHELL_NAMES[idx] if idx < len(SHELL_NAMES) else None
                out.append(f"$SHELL:{shell}" if shell else f"$SHELL[{idx}]")
                i += 2
                continue
            out.append("[[NSIS_SHELL]]")
            i += 1
            continue
        if ch == "\x04" and i + 1 < len(value):
            out.append(f"[[NSIS_SKIP:{ord(value[i + 1])}]]")
            i += 2
            continue
        if ord(ch) < 0x20 and ch not in "\r\n\t":
            out.append(f"[[CTRL:{ord(ch):02X}]]")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def choose_header_layout(header: bytes) -> dict[str, Any]:
    """Validate 8-vs-7 block layouts using section, entry, strings, and lang-table boundaries."""
    if len(header) < 128:
        raise ValueError("Decoded header too short to contain expected metadata")
    flags = u32(header, 0)
    candidates: list[dict[str, Any]] = []
    for block_count in (8, 7):
        blocks = []
        for i in range(block_count):
            off = u32(header, 4 + i * 8)
            count = u32(header, 8 + i * 8)
            blocks.append({"index": i, "offset": off, "count": count})
        if block_count == 8:
            labels = ["pages", "sections", "entries", "strings", "language_tables", "control_colors", "font_data", "data"]
        else:
            labels = ["pages", "sections", "entries", "strings", "language_tables", "control_colors", "data"]
        for item, label in zip(blocks, labels):
            item["label"] = label
        pos_after_blocks = 4 + block_count * 8
        if pos_after_blocks + 16 > len(header):
            continue
        reg_root = u32(header, pos_after_blocks)
        reg_key_ptr = u32(header, pos_after_blocks + 4)
        reg_val_ptr = u32(header, pos_after_blocks + 8)
        # These build features appear in the observed header: background colors,
        # log-window colors, language table size, then license background.
        lang_size_pos = pos_after_blocks + 12 + 12 + 8
        if lang_size_pos + 4 > len(header):
            continue
        lang_table_size = u32(header, lang_size_pos)
        pages, sections, entries, strings = blocks[0:4]
        lang = blocks[4]
        colors = blocks[5]
        offsets_in_bounds = all(b["offset"] <= len(header) for b in blocks if b["count"] or b["offset"])
        entries_end = entries["offset"] + entries["count"] * ENTRY_SIZE
        entries_in_bounds = entries_end <= len(header) and entries_end == strings["offset"]
        ordered = pages["offset"] < sections["offset"] < entries["offset"] < strings["offset"] < lang["offset"] <= len(header)
        string_range = strings["offset"] <= lang["offset"] <= len(header) and (strings["offset"] % 2 == 0) and (lang["offset"] % 2 == 0)
        # Decode the registry pointers as string-table offsets if their bounds allow it.
        registry_refs_plausible = reg_key_ptr < max(1, (lang["offset"] - strings["offset"]) // 2) and reg_val_ptr < max(1, (lang["offset"] - strings["offset"]) // 2)
        language_end = lang["offset"] + lang["count"] * lang_table_size
        lang_size_matches = lang_table_size > 0 and language_end <= len(header)
        if colors["offset"]:
            lang_size_matches = lang_size_matches and language_end == colors["offset"]
        score = sum((offsets_in_bounds, entries_in_bounds, ordered, string_range, registry_refs_plausible, lang_size_matches))
        candidates.append({
            "block_count": block_count,
            "score_out_of_6": score,
            "blocks": blocks,
            "offsets_in_bounds": offsets_in_bounds,
            "entry_records_end_at_strings": entries_in_bounds,
            "ordered_primary_blocks": ordered,
            "string_range_bounds_plausible": string_range,
            "registry_string_refs_plausible": registry_refs_plausible,
            "lang_table_size": lang_table_size,
            "lang_table_end": language_end,
            "language_table_end_matches_next_block": lang_size_matches,
            "reg_root_key_raw": reg_root,
            "reg_key_string_index": reg_key_ptr,
            "reg_value_string_index": reg_val_ptr,
            "lang_table_size_field_offset": lang_size_pos,
        })
    if not candidates:
        raise ValueError("Could not construct any NSISBI header layout candidates")
    candidates.sort(key=lambda c: (c["score_out_of_6"], c["block_count"]), reverse=True)
    best = candidates[0]
    if best["score_out_of_6"] < 5:
        raise ValueError(f"No sufficiently consistent header-block layout: {[(x['block_count'], x['score_out_of_6']) for x in candidates]}")
    best["alternatives"] = candidates[1:]
    best["header_flags"] = flags
    best["page_record_size_assumed"] = PAGE_SIZE_UNICODE_NSISBI
    section_block = next(b for b in best["blocks"] if b["label"] == "sections")
    entries_block = next(b for b in best["blocks"] if b["label"] == "entries")
    best["section_record_size_assumed"] = ((entries_block["offset"] - section_block["offset"]) // section_block["count"]) if section_block["count"] else None
    return best


def parse_sections(header: bytes, layout: dict[str, Any]) -> list[dict[str, Any]]:
    blocks = {b["label"]: b for b in layout["blocks"]}
    b = blocks["sections"]
    entry_start = blocks["entries"]["offset"]
    if b["count"] == 0:
        return []
    stride = (entry_start - b["offset"]) // b["count"]
    if stride < SECTION_FIXED_BYTES + 2 or b["offset"] + stride * b["count"] > len(header):
        return [{"warning": f"Could not safely infer section record size; inferred stride={stride}", "offset": b["offset"], "count": b["count"]}]
    result = []
    for i in range(b["count"]):
        off = b["offset"] + i * stride
        name_bytes = header[off + SECTION_FIXED_BYTES:off + stride]
        terminator_at = len(name_bytes)
        for p in range(0, len(name_bytes) - 1, 2):
            if name_bytes[p] == 0 and name_bytes[p + 1] == 0:
                terminator_at = p
                break
        name = name_bytes[:terminator_at].decode("utf-16-le", errors="replace") if len(name_bytes) >= 2 else ""
        result.append({
            "index": i,
            "offset": off,
            "record_size": stride,
            "name_string_index": u32(header, off),
            "install_types": u32(header, off + 4),
            "flags": u32(header, off + 8),
            "code_entry_index": u32(header, off + 12),
            "code_entry_count": u32(header, off + 16),
            "size_kb_declared": u32(header, off + 20),
            "name_raw": name,
            "entry_range_end": u32(header, off + 12) + u32(header, off + 16),
        })
    return result


def scan_sidecar_records(sidecar: Path) -> list[dict[str, Any]]:
    size = sidecar.stat().st_size
    records: list[dict[str, Any]] = []
    off = 0
    with sidecar.open("rb") as fh:
        while off < size:
            fh.seek(off)
            prefix = fh.read(8)
            if len(prefix) != 8:
                raise ValueError(f"Truncated 8-byte sidecar record prefix at offset {off}")
            word = struct.unpack("<Q", prefix)[0]
            compressed = bool(word & COMPRESSED_FLAG_64)
            stored_size = word & LENGTH_MASK_63
            payload_offset = off + 8
            end = payload_offset + stored_size
            if end > size:
                raise ValueError(f"Sidecar record #{len(records)} at {off} overruns EOF: end={end}, size={size}")
            records.append({
                "index": len(records),
                "record_offset": off,
                "length_prefix_hex": f"0x{word:016X}",
                "compressed": compressed,
                "stored_size_bytes": stored_size,
                "payload_offset": payload_offset,
                "payload_end_exclusive": end,
            })
            off = end
            if len(records) > 1_000_000:
                raise ValueError("Sidecar record count exceeded hard safety limit")
    if off != size:
        raise ValueError(f"Sidecar record walk ended at {off}, not exact EOF {size}")
    return records


def extract_file_string_index(value: int, strings: dict[int, str]) -> dict[str, Any]:
    raw = strings.get(value)
    if raw is None:
        return {"string_index": value, "string_found": False, "raw": None, "resolved": None, "basename": None}
    resolved = resolve_nsis_string(raw)
    basename = re.split(r"[\\/]", resolved)[-1]
    basename = re.sub(r"\[\[CTRL:[0-9A-F]{2}\]\]", "", basename)
    return {"string_index": value, "string_found": True, "raw": raw, "resolved": resolved, "basename": basename}


def parse_file_instructions(header: bytes, layout: dict[str, Any], strings: dict[int, str]) -> tuple[list[dict[str, Any]], Counter[int]]:
    block = next(b for b in layout["blocks"] if b["label"] == "entries")
    instructions: list[dict[str, Any]] = []
    op_counts: Counter[int] = Counter()
    for i in range(block["count"]):
        off = block["offset"] + i * ENTRY_SIZE
        opcode = u32(header, off)
        op_counts[opcode] += 1
        params = [u32(header, off + 4 + k * 4) for k in range(8)]
        if opcode not in (20, 21):
            continue
        file_str = extract_file_string_index(params[1], strings)
        data_offset = (params[3] << 32) | params[2]
        instructions.append({
            "entry_index": i,
            "entry_offset_in_header": off,
            "opcode": opcode,
            "opcode_name": OPCODE_NAMES.get(opcode, f"OPCODE_{opcode}"),
            "overwrite_flag_raw": params[0],
            "filename": file_str,
            "data_offset": data_offset,
            "filetime_low_raw": params[4],
            "filetime_high_raw": params[5],
            "allow_ignore_raw": params[6],
            "param7_raw_unclassified": params[7],
            "params_raw": params,
        })
    return instructions, op_counts


def build_payload_manifest(records: list[dict[str, Any]], file_instructions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    record_map = {r["record_offset"]: {**r, "file_references": [], "reference_count": 0} for r in records}
    unmatched: list[dict[str, Any]] = []
    for ins in file_instructions:
        target = record_map.get(ins["data_offset"])
        if target is None:
            unmatched.append({"entry_index": ins["entry_index"], "data_offset": ins["data_offset"], "filename": ins["filename"].get("resolved")})
            continue
        ref = {
            "entry_index": ins["entry_index"],
            "opcode": ins["opcode"],
            "filename_string_index": ins["filename"]["string_index"],
            "filename_raw": ins["filename"]["raw"],
            "filename_resolved": ins["filename"]["resolved"],
            "filename_basename": ins["filename"]["basename"],
            "param7_raw_unclassified": ins["param7_raw_unclassified"],
            "overwrite_flag_raw": ins["overwrite_flag_raw"],
        }
        target["file_references"].append(ref)
        target["reference_count"] += 1
    manifest = []
    for offset in sorted(record_map):
        row = record_map[offset]
        refs = row["file_references"]
        expressions = list(dict.fromkeys(r["filename_resolved"] for r in refs if r["filename_resolved"] is not None))
        raw_names = list(dict.fromkeys(r["filename_raw"] for r in refs if r["filename_raw"] is not None))
        basenames = list(dict.fromkeys(r["filename_basename"] for r in refs if r["filename_basename"] is not None))
        param7_values = sorted({r["param7_raw_unclassified"] for r in refs})
        row.update({
            "filename_expressions": expressions,
            "filename_raw_values": raw_names,
            "basenames": basenames,
            "entry_indexes": sorted({r["entry_index"] for r in refs}),
            "param7_raw_values_unclassified": param7_values,
            "param7_raw_values_consistent": len(param7_values) <= 1,
            "referenced_by_file_instruction": bool(refs),
        })
        manifest.append(row)
    result = {
        "sidecar_record_count": len(records),
        "file_instruction_count": len(file_instructions),
        "unique_file_data_offsets": len({x["data_offset"] for x in file_instructions}),
        "matched_file_instructions": len(file_instructions) - len(unmatched),
        "unmatched_file_instruction_count": len(unmatched),
        "sidecar_records_without_file_instruction": sum(1 for x in manifest if not x["referenced_by_file_instruction"]),
        "unmatched_file_instructions": unmatched,
        "unreferenced_record_offsets": [x["record_offset"] for x in manifest if not x["referenced_by_file_instruction"]],
    }
    return manifest, result


def safe_output_filename(record: dict[str, Any], requested: str | None = None) -> str:
    names = record.get("basenames") or []
    candidate = requested or (names[0] if names else f"sidecar_record_{record['record_offset']}.bin")
    candidate = candidate.replace("\x00", "")
    candidate = re.sub(r"[<>:\"/\\|?*\x00-\x1F]", "_", candidate).strip(" .")
    if not candidate or candidate in (".", ".."):
        candidate = f"sidecar_record_{record['record_offset']}.bin"
    return candidate[:200]


def probe_extracted_file(path: Path) -> dict[str, Any]:
    """Non-executing structural probe. Does not claim semantic validity of file contents."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        first = fh.read(64)
        is_mz = first[:2] == b"MZ"
        result: dict[str, Any] = {
            "path": str(path),
            "size_bytes": size,
            "first_16_bytes_hex": first[:16].hex(" ").upper(),
            "mz_signature": is_mz,
            "kind": "unknown/binary",
            "pe_signature_valid": False,
        }
        if is_mz and len(first) >= 64:
            pe_offset = u32(first, 0x3C)
            result["pe_offset"] = pe_offset
            if pe_offset >= 64 and pe_offset + 24 <= size:
                fh.seek(pe_offset)
                pe_head = fh.read(24)
                if len(pe_head) == 24:
                    sig = pe_head[:4]
                    machine = u16(pe_head, 4)
                    section_count = u16(pe_head, 6)
                    timestamp = u32(pe_head, 8)
                    opt_size = u16(pe_head, 20)
                    opt_off = pe_offset + 24
                    fh.seek(opt_off)
                    optional = fh.read(min(opt_size, 128))
                    opt_magic = u16(optional, 0) if len(optional) >= 2 else None
                    pe_end = opt_off + opt_size
                    result.update({
                        "pe_signature": sig.decode("ascii", errors="replace"),
                        "pe_signature_valid": sig == b"PE\x00\x00" and pe_end <= size,
                        "machine_raw": f"0x{machine:04X}",
                        "machine_name": {0x014C: "x86", 0x8664: "AMD64/x64", 0xAA64: "ARM64", 0x01C0: "ARM"}.get(machine, "unknown"),
                        "section_count": section_count,
                        "coff_timestamp_raw": timestamp,
                        "optional_header_size": opt_size,
                        "optional_header_magic": None if opt_magic is None else f"0x{opt_magic:04X}",
                    })
                    if opt_magic in (0x10B, 0x20B) and len(optional) >= 60:
                        result["address_of_entry_point"] = u32(optional, 16)
                        result["size_of_image"] = u32(optional, 56)
                    result["kind"] = "PE executable/DLL candidate" if result["pe_signature_valid"] else "MZ file with invalid/truncated PE header"
            else:
                result["kind"] = "MZ file without in-bounds PE header"
        else:
            fh.seek(0)
            prefix = fh.read(min(size, 256))
            decoded = prefix.decode("utf-8", errors="replace")
            printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded)
            if decoded and printable / max(1, len(decoded)) >= 0.85:
                result["kind"] = "text-like data"
                result["text_prefix_escaped"] = decoded[:160].encode("unicode_escape").decode("ascii")
    return result


def u16(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def extract_sidecar_record(sidecar: Path, record: dict[str, Any], destination: Path, max_output_bytes: int) -> dict[str, Any]:
    """Stream one selected record, validate framing, compute digests, and probe file signatures."""
    stored_size = record["stored_size_bytes"]
    compressed = record["compressed"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite existing extraction: {destination}")
    partial = destination.with_suffix(destination.suffix + ".partial")
    crc = 0
    total_out = 0
    frames = 0
    terminator = not compressed
    remaining = stored_size
    try:
        with sidecar.open("rb") as src, partial.open("xb") as dst:
            src.seek(record["payload_offset"])
            if not compressed:
                while remaining:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Unexpected EOF in uncompressed sidecar record")
                    remaining -= len(chunk)
                    total_out += len(chunk)
                    if total_out > max_output_bytes:
                        raise ValueError(f"Output exceeded --max-output-bytes ({max_output_bytes})")
                    crc = zlib.crc32(chunk, crc)
                    dst.write(chunk)
            else:
                while remaining:
                    if remaining < 3:
                        raise ValueError("Truncated three-byte inner compression frame")
                    prefix = src.read(3)
                    if len(prefix) != 3:
                        raise ValueError("Could not read complete inner frame prefix")
                    remaining -= 3
                    frame_len = prefix[0] | (prefix[1] << 8) | (prefix[2] << 16)
                    if frame_len == 0:
                        if remaining != 0:
                            raise ValueError("Inner zero-length terminator is not at end of record")
                        terminator = True
                        break
                    if frame_len > MAX_FILE_FRAME_SIZE:
                        raise ValueError(f"Compressed inner frame too large ({frame_len} bytes); refusing")
                    if frame_len > remaining:
                        raise ValueError("Inner compressed frame overruns sidecar record")
                    block = src.read(frame_len)
                    if len(block) != frame_len:
                        raise ValueError("Truncated compressed inner frame")
                    remaining -= frame_len
                    try:
                        decoded = zlib.decompress(block, wbits=-15)
                    except zlib.error as exc:
                        raise ValueError(f"Raw-DEFLATE error in inner frame #{frames}: {exc}") from exc
                    frames += 1
                    total_out += len(decoded)
                    if total_out > max_output_bytes:
                        raise ValueError(f"Output exceeded --max-output-bytes ({max_output_bytes})")
                    crc = zlib.crc32(decoded, crc)
                    dst.write(decoded)
        if compressed and not terminator:
            raise ValueError("Compressed record did not end with the required three-byte terminator")
        actual_crc = crc & 0xFFFFFFFF
        digest = hashlib.sha256()
        with partial.open("rb") as check_fh:
            while True:
                chunk = check_fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        os.replace(partial, destination)
        return {
            "destination": str(destination),
            "record_offset": record["record_offset"],
            "record_index": record["index"],
            "compressed": compressed,
            "stored_size_bytes": stored_size,
            "decoded_size_bytes": total_out,
            "sha256": digest.hexdigest(),
            "crc32_actual": actual_crc,
            "crc32_actual_hex": f"0x{actual_crc:08X}",
            "crc32_validation_status": "computed_only; no per-file expected CRC field has been verified for this NSISBI build",
            "param7_raw_values_unclassified": record.get("param7_raw_values_unclassified") or [],
            "file_probe": probe_extracted_file(destination),
            "inner_compressed_frames": frames,
            "inner_terminator_found": terminator,
        }
    except Exception:
        try:
            if partial.exists():
                partial.unlink()
        except OSError:
            pass
        raise


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_reports(out_dir: Path, meta: dict[str, Any], manifest: list[dict[str, Any]], instructions: list[dict[str, Any]], op_counts: Counter[int], sections: list[dict[str, Any]], extraction: dict[str, Any] | None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "payload_manifest.json", {"metadata": meta, "payload_records": manifest})
    write_json(out_dir / "file_instructions.json", instructions)
    write_json(out_dir / "instruction_summary.json", {
        "total_entries": meta["entry_count"],
        "opcode_counts": [{"opcode": op, "opcode_name": OPCODE_NAMES.get(op, f"OPCODE_{op}"), "count": count} for op, count in sorted(op_counts.items())],
        "file_instruction_count": len(instructions),
        "file_instruction_opcode_counts": dict(Counter(str(x["opcode"]) for x in instructions)),
        "param7_raw_unclassified_summary": {
            "field_semantics": "unclassified; not treated as per-file CRC32",
            "count": len(instructions),
            "zero_count": sum(1 for x in instructions if x["param7_raw_unclassified"] == 0),
            "all_ones_count": sum(1 for x in instructions if x["param7_raw_unclassified"] == 0xFFFFFFFF),
            "unique_values": len({x["param7_raw_unclassified"] for x in instructions}),
            "most_common_values": [{"value": value, "hex": f"0x{value:08X}", "count": count} for value, count in Counter(x["param7_raw_unclassified"] for x in instructions).most_common(20)],
        },
        "sections": sections,
    })
    with (out_dir / "payload_manifest.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "record_index", "record_offset", "compressed", "stored_size_bytes", "payload_offset", "payload_end_exclusive",
            "reference_count", "referenced_by_file_instruction", "basenames", "filename_expressions", "entry_indexes",
            "param7_raw_values_unclassified", "param7_raw_values_consistent",
        ])
        writer.writeheader()
        for row in manifest:
            writer.writerow({key: (json.dumps(row.get(key), ensure_ascii=False) if isinstance(row.get(key), (list, dict)) else row.get(key)) for key in writer.fieldnames})
    summary = meta["payload_mapping"]
    lines = [
        "ROSLegacy NSISBI payload mapping v7",
        "=" * 78,
        f"Generated UTC: {meta['generated_utc']}",
        f"Installer: {meta['exe_path']} ({meta['installer_size_bytes']:,} bytes)",
        f"Sidecar: {meta['sidecar_path']} ({meta['sidecar_size_bytes']:,} bytes / {human_size(meta['sidecar_size_bytes'])})",
        "",
        "EMBEDDED HEADER VALIDATION",
        "-" * 78,
        f"Firstheader offset: {meta['firstheader']['offset']:,}",
        f"Firstheader flags: {meta['firstheader']['flags_hex']} (preserved raw; no unsupported interpretation)",
        f"Decoded header bytes: {meta['header_decode']['decoded_bytes']:,}",
        f"Header SHA-256: {meta['header_decode']['decoded_sha256']}",
        f"Eight-block layout score: {meta['header_layout']['score_out_of_6']}/6",
        f"Entry table: offset {meta['blocks']['entries']['offset']:,}, count {meta['entry_count']:,}, record size {ENTRY_SIZE}",
        f"String table: byte range [{meta['blocks']['strings']['offset']:,}, {meta['blocks']['language_tables']['offset']:,}), field count is preserved raw",
        f"Language-table size: {meta['header_layout']['lang_table_size']:,} bytes",
        "",
        "SIDECAR RECORD INDEX",
        "-" * 78,
        f"Records indexed: {summary['sidecar_record_count']:,}",
        f"Walk reached exact EOF: {meta['sidecar_walk_reached_eof']}",
        f"Compressed-flag records: {sum(1 for r in manifest if r['compressed']):,}",
        f"Uncompressed-flag records: {sum(1 for r in manifest if not r['compressed']):,}",
        f"File-extraction instructions (opcodes 20/21): {summary['file_instruction_count']:,}",
        f"Distinct instruction data offsets: {summary['unique_file_data_offsets']:,}",
        f"Matched instruction offsets: {summary['matched_file_instructions']:,}",
        f"Unmatched file-instruction offsets: {summary['unmatched_file_instruction_count']:,}",
        f"Sidecar records without a direct file-instruction reference: {summary['sidecar_records_without_file_instruction']:,}",
        "",
        "SELECTED TARGETS / INTERESTING NAMES",
        "-" * 78,
    ]
    targets = [x for x in manifest if any(re.search(r"(ros64\.exe|server_ip\.txt|version(_orig)?\.dll|Mirae Labs Launcher\.exe)", n, re.I) for n in (x.get("filename_expressions") or []) + (x.get("basenames") or []))]
    for x in targets[:100]:
        names = ", ".join(x.get("filename_expressions") or x.get("basenames") or ["(no filename reference)"])
        lines.append(f"@ {x['record_offset']:>12,}  {'compressed' if x['compressed'] else 'uncompressed':>12}  stored={x['stored_size_bytes']:>10,}  refs={x['reference_count']:>4}  {names}")
    if not targets:
        lines.append("No target names matched the report filters.")
    lines += [
        "",
        "EXTRACTION RESULT",
        "-" * 78,
        json.dumps(extraction, indent=2, ensure_ascii=False) if extraction else "No payload was extracted. Default operation is inventory-only.",
        "",
        "LIMITATIONS",
        "-" * 78,
        "The manifest maps compiled File instructions to exact sidecar record boundaries; it does not simulate every NSIS branch or prove the final installed destination for relative paths.",
        "CRC32 is reported as a computed digest only. V6 incorrectly treated params[7] as a per-file expected CRC; V7 preserves that operand as unclassified raw data until the target NSISBI runtime/compiler source confirms its meaning.",
        "PE signature probes are structural checks only; they do not execute files or prove safe behavior.",
        "Opcodes beyond the stable core are labeled version-dependent where the exact installer runtime mapping is not independently established.",
    ]
    (out_dir / "payload_mapping.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="ROSLegacy NSISBI static payload mapper and selective record extractor v7")
    ap.add_argument("--exe", metavar="PATH", help="Installer EXE; defaults to the known local installer")
    ap.add_argument("--bin", metavar="PATH", dest="sidecar", help="External .nsisbin sidecar; defaults to the known local sidecar")
    ap.add_argument("--out", metavar="PATH", default=str(DEFAULT_OUT), help="Output root directory (default: recon_out_v7)")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--extract-name", metavar="TEXT", help="Explicitly extract one uniquely matched filename or path substring")
    group.add_argument("--extract-offset", metavar="BYTES", type=int, help="Explicitly extract the record beginning at this sidecar byte offset")
    ap.add_argument("--max-output-bytes", type=int, default=4 * 1024**3, help="Maximum decoded bytes for one explicit extraction (default: 4 GiB)")
    ap.add_argument("--self-test", action="store_true", help="Run synthetic framing/index tests and exit")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()
    if args.max_output_bytes <= 0:
        ap.error("--max-output-bytes must be positive")

    exe = Path(args.exe) if args.exe else DEFAULT_DIR / DEFAULT_EXE
    sidecar = Path(args.sidecar) if args.sidecar else exe.parent / DEFAULT_SIDECAR
    if not exe.is_file():
        print(f"[ERROR] Installer not found: {exe}", file=sys.stderr)
        return 2
    if not sidecar.is_file():
        print(f"[ERROR] Sidecar not found: {sidecar}", file=sys.stderr)
        return 2

    try:
        exe_bytes = exe.read_bytes()
        firstheader = find_firstheader(exe_bytes)
        decoded_header, header_decode = decode_embedded_header(exe_bytes, firstheader)
        layout = choose_header_layout(decoded_header)
        if layout["block_count"] != 8:
            print(f"[ERROR] Stronger expected 8-block layout not selected; got {layout['block_count']}", file=sys.stderr)
            return 3
        blocks = {b["label"]: b for b in layout["blocks"]}
        entry_block = blocks["entries"]
        strings = parse_string_table(decoded_header, blocks["strings"]["offset"], blocks["language_tables"]["offset"])
        if entry_block["offset"] + entry_block["count"] * ENTRY_SIZE != blocks["strings"]["offset"]:
            raise ValueError("Entry table does not end exactly at the string-table offset")
        sections = parse_sections(decoded_header, layout)
        file_instructions, op_counts = parse_file_instructions(decoded_header, layout, strings)
        print("[INFO] Indexing sidecar record boundaries; no payload bodies are extracted by default.")
        records = scan_sidecar_records(sidecar)
        record_size = sidecar.stat().st_size
        declared_size_match = firstheader["external_size_declared"] == record_size
        if not declared_size_match:
            raise ValueError(f"Installer declares {firstheader['external_size_declared']:,} sidecar bytes but actual sidecar is {record_size:,}")
        manifest, mapping_summary = build_payload_manifest(records, file_instructions)
        record_by_offset = {x["record_offset"]: x for x in manifest}
        meta = {
            "tool": "nsis_recon_v7.py",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "read_only_inputs": True,
            "exe_path": str(exe.resolve()),
            "sidecar_path": str(sidecar.resolve()),
            "installer_size_bytes": len(exe_bytes),
            "sidecar_size_bytes": record_size,
            "sidecar_size_declared": firstheader["external_size_declared"],
            "sidecar_size_matches_declared": declared_size_match,
            "firstheader": firstheader,
            "header_decode": header_decode,
            "header_layout": layout,
            "blocks": blocks,
            "entry_count": entry_block["count"],
            "string_table_string_count": len(strings),
            "sidecar_record_count": len(records),
            "sidecar_walk_reached_eof": bool(records and records[-1]["payload_end_exclusive"] == record_size),
            "payload_mapping": mapping_summary,
        }
        extraction = None
        out_root = Path(args.out)
        stamp = datetime.now().strftime("recon_v7_%Y%m%d_%H%M%S_%f")
        out_dir = out_root / stamp
        # Persist the inventory even if a requested extraction selector is ambiguous.
        out_dir.mkdir(parents=True, exist_ok=False)

        selected = None
        selected_name = None
        selection_error = None
        if args.extract_offset is not None:
            selected = record_by_offset.get(args.extract_offset)
            if selected is None:
                selection_error = f"No sidecar record begins at offset {args.extract_offset:,}"
            else:
                selected_name = safe_output_filename(selected)
        elif args.extract_name:
            needle = args.extract_name.casefold()
            matches = []
            for item in manifest:
                all_names = (item.get("basenames") or []) + (item.get("filename_expressions") or []) + (item.get("filename_raw_values") or [])
                if any(needle == n.casefold() or needle in n.casefold() for n in all_names if isinstance(n, str)):
                    matches.append(item)
            if len(matches) != 1:
                choices = [{"record_offset": x["record_offset"], "basenames": x.get("basenames"), "filename_expressions": x.get("filename_expressions"), "reference_count": x["reference_count"]} for x in matches[:30]]
                selection_error = f"--extract-name matched {len(matches)} distinct records, expected exactly one. Candidates: {json.dumps(choices, ensure_ascii=False)}. Use --extract-offset to disambiguate."
            else:
                selected = matches[0]
                selected_name = safe_output_filename(selected)

        if selection_error:
            extraction = {"status": "not_extracted", "selection_error": selection_error}
            write_reports(out_dir, meta, manifest, file_instructions, op_counts, sections, extraction)
            print(f"[SELECTION ERROR] {selection_error}", file=sys.stderr)
            print(f"[SAVED] Inventory reports: {out_dir}")
            return 4

        if selected is not None:
            print(f"[INFO] Explicit extraction selected record #{selected['index']} at offset {selected['record_offset']:,} ({selected_name}).")
            try:
                extraction = extract_sidecar_record(sidecar, selected, out_dir / "extracted" / selected_name, args.max_output_bytes)
            except Exception as exc:
                extraction = {"status": "failed", "record_offset": selected["record_offset"], "error": str(exc)}
                write_reports(out_dir, meta, manifest, file_instructions, op_counts, sections, extraction)
                print(f"[EXTRACTION ERROR] {exc}", file=sys.stderr)
                print(f"[SAVED] Inventory reports: {out_dir}")
                return 5
        write_reports(out_dir, meta, manifest, file_instructions, op_counts, sections, extraction)

        print("[COMPLETE] NSISBI payload mapping v7 finished.")
        print(f"  Installer: {exe}")
        print(f"  Sidecar: {sidecar} ({human_size(record_size)})")
        print(f"  Header: {header_decode['decoded_bytes']:,} bytes; layout={layout['block_count']} blocks; score={layout['score_out_of_6']}/6")
        print(f"  Sidecar records: {len(records):,}; exact EOF={meta['sidecar_walk_reached_eof']}")
        print(f"  File instructions: {len(file_instructions):,}; unique data offsets={mapping_summary['unique_file_data_offsets']:,}")
        print(f"  Matched offsets: {mapping_summary['matched_file_instructions']:,}; unmatched instructions={mapping_summary['unmatched_file_instruction_count']:,}")
        print(f"  Sidecar records without direct File instruction: {mapping_summary['sidecar_records_without_file_instruction']:,}")
        if extraction and extraction.get("status") != "failed":
            print(f"  Extracted: {extraction['destination']} ({extraction['decoded_size_bytes']:,} bytes)")
            print(f"  CRC32 (computed only; expected field unverified): {extraction['crc32_actual_hex']}")
            probe = extraction.get("file_probe") or {}
            print(f"  File probe: {probe.get('kind', 'unavailable')}; PE signature valid={probe.get('pe_signature_valid', False)}; machine={probe.get('machine_name', 'n/a')}")
        print(f"  Report: {out_dir / 'payload_mapping.txt'}")
        print(f"  Manifest JSON: {out_dir / 'payload_manifest.json'}")
        return 0
    except (OSError, ValueError, struct.error, zlib.error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 3


def run_self_test() -> int:
    """Synthetic end-to-end tests for header parsing, mapping, and extraction."""
    import tempfile

    def put_u32(buf: bytearray, offset: int, value: int) -> None:
        struct.pack_into("<I", buf, offset, value & 0xFFFFFFFF)

    try:
        sample = (b"NSISBI framed DEFLATE test\x00" * 1000)
        comp = zlib.compressobj(level=6, wbits=-15)
        raw = comp.compress(sample) + comp.flush()
        framed = len(raw).to_bytes(3, "little") + raw + b"\x00\x00\x00"
        decoded, frames = decode_framed_raw_deflate(framed, len(sample), len(sample) + 1)
        assert decoded == sample and len(frames) == 1

        # Minimal structurally valid AMD64 PE-shaped buffer for the signature probe.
        pe_sample = bytearray(0x400)
        pe_sample[:2] = b"MZ"
        put_u32(pe_sample, 0x3C, 0x80)
        pe_sample[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHI", pe_sample, 0x84, 0x8664, 3, 123456789)
        struct.pack_into("<H", pe_sample, 0x94, 0xF0)
        struct.pack_into("<H", pe_sample, 0x98, 0x20B)
        put_u32(pe_sample, 0xA8, 0x1000)  # AddressOfEntryPoint
        put_u32(pe_sample, 0xD0, 0x5000)  # SizeOfImage

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pe_path = root / "synthetic.exe"
            pe_path.write_bytes(pe_sample)
            pe_probe = probe_extracted_file(pe_path)
            assert pe_probe["pe_signature_valid"] is True and pe_probe["machine_name"] == "AMD64/x64"
            sidecar = root / "test.nsisbin"
            # First sidecar record is compressed; second is uncompressed.
            record0 = struct.pack("<Q", COMPRESSED_FLAG_64 | len(framed)) + framed
            plain = b"plain payload\x00\x01"
            record1 = struct.pack("<Q", len(plain)) + plain
            sidecar_bytes = record0 + record1
            sidecar.write_bytes(sidecar_bytes)
            records = scan_sidecar_records(sidecar)
            assert len(records) == 2 and records[-1]["record_offset"] == len(record0)

            # Make a minimal synthetic 8-block NSISBI header with one File opcode.
            header = bytearray(2080)
            put_u32(header, 0, 0xA1)
            block_pairs = [
                (300, 1),       # pages
                (364, 1),       # sections
                (2000, 1),      # entries
                (2036, 0),      # strings: count is unused/zero in this build
                (2060, 1),      # language tables
                (2070, 0),      # control colors
                (0, 0),         # font data
                (0, 0),         # external data block lives outside this header
            ]
            for i, (off, count) in enumerate(block_pairs):
                put_u32(header, 4 + 8 * i, off)
                put_u32(header, 8 + 8 * i, count)
            put_u32(header, 68, 0x80000001)  # HKEY_CURRENT_USER
            put_u32(header, 72, 1)
            put_u32(header, 76, 2)
            put_u32(header, 100, 10)          # language-table record size
            # Section record: code begins at entry 0 and uses one 36-byte entry.
            put_u32(header, 364, 0)           # name pointer
            put_u32(header, 376, 0)           # code entry index
            put_u32(header, 380, 1)           # code entry count
            section_name = "Synthetic Section\x00".encode("utf-16-le")
            header[364 + SECTION_FIXED_BYTES:364 + SECTION_FIXED_BYTES + len(section_name)] = section_name
            # String-table indices are TCHAR (UTF-16 code-unit) offsets.
            string_bytes = "x\x00ros64.exe\x00".encode("utf-16-le")
            assert len(string_bytes) == 24
            header[2036:2036 + len(string_bytes)] = string_bytes
            # One 36-byte EW_EXTRACTFILE entry: filename string index 2, data at record 0.
            params = [0, 2, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFDB, 0x12345678]
            struct.pack_into("<9I", header, 2000, 20, *params)

            layout = choose_header_layout(bytes(header))
            assert layout["block_count"] == 8 and layout["score_out_of_6"] == 6
            strings = parse_string_table(bytes(header), 2036, 2060)
            assert strings[2] == "ros64.exe"
            sections = parse_sections(bytes(header), layout)
            assert sections[0]["name_raw"] == "Synthetic Section"
            file_instructions, op_counts = parse_file_instructions(bytes(header), layout, strings)
            assert op_counts[20] == 1 and len(file_instructions) == 1
            assert file_instructions[0]["filename"]["basename"] == "ros64.exe"
            assert file_instructions[0]["param7_raw_unclassified"] == 0x12345678
            manifest, mapping = build_payload_manifest(records, file_instructions)
            assert mapping["matched_file_instructions"] == 1
            assert mapping["sidecar_records_without_file_instruction"] == 1
            assert manifest[0]["basenames"] == ["ros64.exe"]

            # Build a synthetic EXE firstheader containing the same decoded header.
            comp_header = zlib.compressobj(level=6, wbits=-15)
            raw_header = comp_header.compress(bytes(header)) + comp_header.flush()
            framed_header = len(raw_header).to_bytes(3, "little") + raw_header + b"\x00\x00\x00"
            following = FIRSTHEADER_SIZE + 8 + len(framed_header) + 8
            sidecar_size = len(sidecar_bytes)
            firstheader_raw = struct.pack(
                "<9I", 0xF0, FH_SIG, *NSISBI_MAGIC_WORDS, len(header), following,
                sidecar_size & 0xFFFFFFFF, (sidecar_size >> 32) & 0xFFFFFFFF,
            )
            synthetic_exe = firstheader_raw + struct.pack("<Q", COMPRESSED_FLAG_64 | len(framed_header)) + framed_header + (b"\x00" * 8)
            fh = find_firstheader(synthetic_exe)
            decoded_header, decoded_summary = decode_embedded_header(synthetic_exe, fh)
            assert decoded_header == bytes(header) and decoded_summary["decoded_size_matches"]

            # Explicitly extract both records; CRC32 is a digest unless a verified expected field exists.
            records[0]["param7_raw_values_unclassified"] = [0x12345678]
            records[0]["basenames"] = ["sample.bin"]
            target = root / "sample.bin"
            result = extract_sidecar_record(sidecar, records[0], target, 1_000_000)
            assert target.read_bytes() == sample and result["crc32_actual"] == (zlib.crc32(sample) & 0xFFFFFFFF)
            records[1]["param7_raw_values_unclassified"] = [0x87654321]
            result2 = extract_sidecar_record(sidecar, records[1], root / "plain.bin", 1_000_000)
            assert (root / "plain.bin").read_bytes() == plain and result2["crc32_actual"] == (zlib.crc32(plain) & 0xFFFFFFFF)

        print("[PASS] raw-DEFLATE framed decode")
        print("[PASS] non-executing PE signature/machine probe")
        print("[PASS] 8-block header layout and Unicode string-table parsing")
        print("[PASS] section and File-entry parsing")
        print("[PASS] sidecar record indexing and entry-to-record mapping")
        print("[PASS] embedded firstheader validation and decode")
        print("[PASS] compressed extraction + computed digest; unverified operand preserved")
        print("[PASS] uncompressed extraction + computed digest; unverified operand preserved")
        return 0
    except Exception as exc:
        print(f"[FAIL] V7 synthetic self-test: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
