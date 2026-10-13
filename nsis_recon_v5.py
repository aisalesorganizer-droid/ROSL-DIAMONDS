#!/usr/bin/env python3
"""ROSLegacy NSISBI header decoder v5 (read-only inputs).

Purpose
-------
V4 established an exact 64-bit length-prefix walk across the external sidecar.
V5 proceeds one layer inward: it validates the installer's embedded NSISBI
firstheader, decodes the compressed installer header using NSISBI's 24-bit
block framing and raw-DEFLATE blocks, then inventories header block offsets and
extracts readable strings. It does NOT execute the installer or extract any
external game payloads.

The source-level format basis is NSISBI's fileform.c + mt_zlib_decompress.c:
compressed input is split into blocks, each prefixed by a 3-byte little-endian
compressed length; the bundled zlib decoder is initialized as raw DEFLATE.
This script requires the embedded header decode to match the exact output size
recorded in the firstheader before accepting the result.

Python 3.9+, standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zlib
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(r"C:\Users\MAFIA\Downloads\Compressed\ROSLegacy\Diamonds")
DEFAULT_EXE = "ROSLegacy_Install_202609251811.exe"
DEFAULT_SIDECAR = "ROSLegacy_Install_202609251811.nsisbin"
DEFAULT_OUT = Path("recon_out_v5")

NSISBI_MARKER = b"\xef\xbe\xad\xdeNullsoftInst"
FH_SIG = 0xDEADBEEF
NSISBI_MAGIC_WORDS = (0x6C6C754E, 0x74666F73, 0x74736E49)
FIRSTHEADER_SIZE = 36
COMPRESSED_FLAG_64 = 1 << 63
LENGTH_MASK_63 = COMPRESSED_FLAG_64 - 1
MAX_HEADER_SIZE = 64 * 1024 * 1024
MAX_STREAM_BLOCKS = 100_000


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


def find_firstheader(exe_bytes: bytes) -> dict[str, Any]:
    candidates = []
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
        flags = u32(raw, 0)
        sig = u32(raw, 4)
        magic = tuple(u32(raw, 8 + i * 4) for i in range(3))
        if sig != FH_SIG or magic != NSISBI_MAGIC_WORDS:
            continue
        header_out = u32(raw, 20)
        following = u32(raw, 24)
        data_low = u32(raw, 28)
        data_high = u32(raw, 32)
        candidates.append({
            "offset": header_off,
            "marker_offset": marker,
            "flags": flags,
            "flags_hex": f"0x{flags:08X}",
            "siginfo_hex": f"0x{sig:08X}",
            "magic_words_hex": [f"0x{x:08X}" for x in magic],
            "header_output_size": header_out,
            "length_of_all_following_data": following,
            "external_size_declared": (data_high << 32) | data_low,
            "external_size_low": data_low,
            "external_size_high": data_high,
            "bytes_after_firstheader_in_exe": len(exe_bytes) - (header_off + FIRSTHEADER_SIZE),
        })
    if len(candidates) != 1:
        raise ValueError(f"Expected one validated NSISBI firstheader; found {len(candidates)}")
    return candidates[0]


def decode_framed_raw_deflate(stored: bytes, expected_size: int) -> tuple[bytes, list[dict[str, int]]]:
    """Decode NSISBI MT-zlib framing: 3-byte LE compressed length + raw DEFLATE.

    A three-byte zero length marks end-of-stream and must be the final bytes.
    Each compressed block is independently initialized by NSISBI's decoder.
    """
    if expected_size <= 0 or expected_size > MAX_HEADER_SIZE:
        raise ValueError(f"Refusing unexpected header output size: {expected_size}")

    pos = 0
    chunks: list[bytes] = []
    block_reports: list[dict[str, int]] = []
    total_out = 0
    terminator_seen = False

    while pos < len(stored):
        if len(block_reports) >= MAX_STREAM_BLOCKS:
            raise ValueError("Exceeded block safety limit")
        if len(stored) - pos < 3:
            raise ValueError(f"Truncated 3-byte block prefix at compressed offset {pos}")

        record_offset = pos
        comp_len = stored[pos] | (stored[pos + 1] << 8) | (stored[pos + 2] << 16)
        pos += 3

        if comp_len == 0:
            if pos != len(stored):
                raise ValueError(f"Zero-length terminator at {record_offset} is not at end of stream")
            terminator_seen = True
            break

        if comp_len > len(stored) - pos:
            raise ValueError(
                f"Compressed block at {record_offset} declares {comp_len} bytes, "
                f"only {len(stored) - pos} remain"
            )

        block = stored[pos:pos + comp_len]
        pos += comp_len
        try:
            decoded = zlib.decompress(block, wbits=-15)
        except zlib.error as exc:
            raise ValueError(
                f"Raw-DEFLATE decode failed for framed block #{len(block_reports)} "
                f"at stored offset {record_offset}: {exc}"
            ) from exc

        total_out += len(decoded)
        if total_out > expected_size:
            raise ValueError(f"Decoded output exceeded declared header size ({total_out} > {expected_size})")
        chunks.append(decoded)
        block_reports.append({
            "index": len(block_reports),
            "framing_offset": record_offset,
            "compressed_bytes": comp_len,
            "decoded_bytes": len(decoded),
        })

    if not terminator_seen:
        raise ValueError("Missing required 3-byte zero-length stream terminator")
    decoded_all = b"".join(chunks)
    if len(decoded_all) != expected_size:
        raise ValueError(f"Decoded {len(decoded_all)} bytes, but firstheader declares {expected_size}")
    return decoded_all, block_reports


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    start = None
    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                out.append({"offset": start, "encoding": "ascii", "text": data[start:i].decode("ascii")})
            start = None
    if start is not None and len(data) - start >= min_len:
        out.append({"offset": start, "encoding": "ascii", "text": data[start:].decode("ascii")})
    return out


def extract_utf16le_ascii_strings(data: bytes, min_len: int = 4) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for alignment in (0, 1):
        pos = alignment
        while pos + 1 < len(data):
            if 0x20 <= data[pos] <= 0x7E and data[pos + 1] == 0:
                begin = pos
                chars = []
                while pos + 1 < len(data) and 0x20 <= data[pos] <= 0x7E and data[pos + 1] == 0:
                    chars.append(chr(data[pos]))
                    pos += 2
                if len(chars) >= min_len:
                    item = (begin, "".join(chars))
                    if item not in seen:
                        seen.add(item)
                        out.append({"offset": begin, "encoding": "utf-16le-ascii", "text": item[1]})
            else:
                pos += 2
    return out


def block_layout_candidates(header: bytes) -> list[dict[str, Any]]:
    """Try NSISBI header layouts with and without the optional font block.

    This reports plausible candidates; it does not silently assume one build's
    compile-time feature flags. Offsets are relative to the decompressed header.
    """
    results = []
    for block_count in (7, 8):
        table_end = 4 + block_count * 8
        if table_end > len(header):
            continue
        blocks = []
        for i in range(block_count):
            off = u32(header, 4 + i * 8)
            num = u32(header, 8 + i * 8)
            blocks.append({"index": i, "offset": off, "count": num})

        # Common visible installer build ordering: pages, sections, entries,
        # strings, language tables, control colours, optional font, data.
        labels7 = ["pages", "sections", "entries", "strings", "language_tables", "control_colors", "data"]
        labels8 = ["pages", "sections", "entries", "strings", "language_tables", "control_colors", "font_data", "data"]
        labels = labels7 if block_count == 7 else labels8
        for block, label in zip(blocks, labels):
            block["label"] = label

        nonzero_offsets = [b["offset"] for b in blocks if b["offset"] != 0]
        offsets_in_bounds = all(x < len(header) for x in nonzero_offsets)
        ordered_offsets = all(a <= b for a, b in zip(nonzero_offsets, nonzero_offsets[1:]))
        entry_block = blocks[2]
        entry_bytes_end = entry_block["offset"] + entry_block["count"] * 36
        entries_in_bounds = entry_block["count"] < 5_000_000 and entry_bytes_end <= len(header)
        strings_block = blocks[3]
        strings_bytes_end_utf16 = strings_block["offset"] + strings_block["count"] * 2
        strings_in_bounds_utf16 = strings_block["count"] < len(header) and strings_bytes_end_utf16 <= len(header)
        score = sum((offsets_in_bounds, ordered_offsets, entries_in_bounds, strings_in_bounds_utf16))
        results.append({
            "block_count": block_count,
            "score_out_of_4": score,
            "offsets_in_bounds": offsets_in_bounds,
            "ordered_nonzero_offsets": ordered_offsets,
            "entries_block_36_byte_records_in_bounds": entries_in_bounds,
            "utf16_string_table_in_bounds": strings_in_bounds_utf16,
            "blocks": blocks,
            "entries_block_end": entry_bytes_end,
            "strings_block_utf16_end": strings_bytes_end_utf16,
        })
    return sorted(results, key=lambda item: (item["score_out_of_4"], item["block_count"]), reverse=True)


def relevant_strings(strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"(ros|setup|\.exe|\.dll|\.json|\.ini|\.cfg|\.pak|\.zip|\.dat|\.bin|\.cab|\.lua|\.txt|"
        r"https?://|program files|appdata|server|install|uninstall|%[A-Z_]+%|mythgames|miraelabs|kamoteworks|manifest|patch|download|cdn)",
        re.IGNORECASE,
    )
    return [item for item in strings if pattern.search(item["text"])]


def write_reports(out_dir: Path, report: dict[str, Any], ascii_strings: list[dict[str, Any]], utf16_strings: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "header_decode.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    all_strings = sorted(ascii_strings + utf16_strings, key=lambda x: (x["offset"], x["encoding"]))
    relevant = relevant_strings(all_strings)
    lines = [
        "ROSLegacy NSISBI header decode v5",
        "=" * 76,
        f"Generated UTC: {report['generated_utc']}",
        f"Input EXE: {report['exe_path']}",
        f"Input sidecar: {report['sidecar_path']}",
        "",
        "HEADER / COMPRESSED STREAM VALIDATION",
        "-" * 76,
        f"Firstheader offset: {report['firstheader']['offset']}",
        f"Header flags: {report['firstheader']['flags_hex']} (raw only)",
        f"Declared decoded header size: {report['firstheader']['header_output_size']} bytes",
        f"Stored header record size: {report['stored_header_record']['stored_bytes']} bytes",
        f"Header record compressed flag: {report['stored_header_record']['compressed_flag']}",
        f"Inner compression codec: {report['header_decode']['codec']}",
        f"Inner blocks decoded: {len(report['header_decode']['blocks'])}",
        f"Decoded header bytes: {report['header_decode']['decoded_bytes']}",
        f"Exact decoded-size match: {report['header_decode']['decoded_size_matches']}",
        f"3-byte stream terminator found: {report['header_decode']['terminator_found']}",
        f"Following-data length equation matches: {report['integrity_checks']['firstheader_following_length_matches']}",
        f"Declared sidecar size matches actual: {report['integrity_checks']['external_size_matches']}",
        "",
        "HEADER BLOCK-LAYOUT CANDIDATES",
        "-" * 76,
    ]
    for cand in report["block_layout_candidates"]:
        lines.append(f"Candidate {cand['block_count']} blocks: score {cand['score_out_of_4']}/4")
        lines.append(f"  offsets in bounds={cand['offsets_in_bounds']}; ordered={cand['ordered_nonzero_offsets']}; entries bounds={cand['entries_block_36_byte_records_in_bounds']}; UTF-16 string range bounds={cand['utf16_string_table_in_bounds']}")
        for block in cand["blocks"]:
            lines.append(f"  {block['index']:>2} {block['label']:<18} offset={block['offset']:>8} count={block['count']}")
        lines.append("")
    lines += [
        "",
        f"Readable ASCII strings: {len(ascii_strings)}",
        f"Readable UTF-16LE ASCII strings: {len(utf16_strings)}",
        f"Relevant string candidates: {len(relevant)}",
        "-" * 76,
    ]
    for item in relevant:
        lines.append(f"@{item['offset']:>8} [{item['encoding']}] {item['text']}")
    lines += [
        "",
        "INTERPRETATION LIMITS",
        "-" * 76,
        "A valid header decode proves the compressed header was reconstructed, not that all NSIS instructions have been decompiled.",
        "String candidates are evidence for filenames/configs, but their position alone does not prove how an instruction uses them.",
        "No external payload file was extracted by this script.",
    ]
    (out_dir / "header_decode.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Full string inventory is useful for later instruction/string-index mapping.
    (out_dir / "header_strings.json").write_text(json.dumps(all_strings, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out_dir / "header_strings.txt").open("w", encoding="utf-8") as f:
        for item in all_strings:
            f.write(f"{item['offset']:>8} [{item['encoding']}] {item['text']}\n")


def run_self_test() -> None:
    sample = (b"synthetic NSISBI header test" * 250) + b"\x00\x00"
    comp = zlib.compressobj(level=9, wbits=-15)
    compressed = comp.compress(sample) + comp.flush()
    framed = len(compressed).to_bytes(3, "little") + compressed + b"\x00\x00\x00"
    recovered, blocks = decode_framed_raw_deflate(framed, len(sample))
    if recovered != sample or len(blocks) != 1:
        raise AssertionError("self-test failed")
    print(f"SELF-TEST OK: framed raw-DEFLATE roundtrip ({len(compressed)} stored -> {len(recovered)} decoded bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only NSISBI embedded-header decoder v5")
    parser.add_argument("--exe", help="Installer EXE path; defaults to the known ROSLegacy installer")
    parser.add_argument("--sidecar", help="External .nsisbin path; defaults to the known ROSLegacy sidecar")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output root directory (default: recon_out_v5)")
    parser.add_argument("--self-test", action="store_true", help="Test the framing/decoder using synthetic bytes only")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return 0

    exe = Path(args.exe) if args.exe else DEFAULT_DIR / DEFAULT_EXE
    if not exe.exists() and not args.exe:
        exe = Path(DEFAULT_EXE)
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
        header_size = firstheader["header_output_size"]
        if header_size <= 0 or header_size > MAX_HEADER_SIZE:
            raise ValueError(f"Unreasonable decoded header size: {header_size}")

        record_offset = firstheader["offset"] + FIRSTHEADER_SIZE
        if record_offset + 8 > len(exe_bytes):
            raise ValueError("Header record length prefix extends past the EXE")
        length_word = u64(exe_bytes, record_offset)
        is_compressed = bool(length_word & COMPRESSED_FLAG_64)
        stored_size = length_word & LENGTH_MASK_63
        body_offset = record_offset + 8
        if body_offset + stored_size > len(exe_bytes):
            raise ValueError("Header record payload extends past the EXE")
        stored_payload = exe_bytes[body_offset:body_offset + stored_size]
        if not is_compressed:
            if len(stored_payload) != header_size:
                raise ValueError("Uncompressed header record size does not match declared output size")
            decoded_header = stored_payload
            block_reports = [{"index": 0, "framing_offset": 0, "compressed_bytes": stored_size, "decoded_bytes": len(decoded_header)}]
            terminator_found = False
            codec = "uncompressed-copy"
        else:
            decoded_header, block_reports = decode_framed_raw_deflate(stored_payload, header_size)
            terminator_found = True
            codec = "NSISBI framed raw-DEFLATE"

        sidecar_size = sidecar.stat().st_size
        firstheader_end = firstheader["offset"] + firstheader["length_of_all_following_data"]
        record_end = body_offset + stored_size
        equation = FIRSTHEADER_SIZE + 8 + stored_size + 8 == firstheader["length_of_all_following_data"]
        report = {
            "tool": "nsis_recon_v5.py",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "read_only_inputs": True,
            "exe_path": str(exe.resolve()),
            "sidecar_path": str(sidecar.resolve()),
            "installer_size_bytes": len(exe_bytes),
            "sidecar_size_bytes": sidecar_size,
            "firstheader": firstheader,
            "stored_header_record": {
                "record_prefix_offset": record_offset,
                "record_prefix_hex": f"0x{length_word:016X}",
                "compressed_flag": is_compressed,
                "stored_bytes": stored_size,
                "body_offset": body_offset,
                "body_end_exclusive": record_end,
                "trailing_exe_bytes_after_record_body": len(exe_bytes) - record_end,
                "first_16_stored_bytes_hex": stored_payload[:16].hex(" "),
                "last_16_stored_bytes_hex": stored_payload[-16:].hex(" "),
            },
            "header_decode": {
                "codec": codec,
                "framing": "3-byte little-endian compressed length, then independent raw-DEFLATE block; 00 00 00 terminator",
                "blocks": block_reports,
                "decoded_bytes": len(decoded_header),
                "declared_output_bytes": header_size,
                "decoded_size_matches": len(decoded_header) == header_size,
                "terminator_found": terminator_found,
                "sha256": hashlib.sha256(decoded_header).hexdigest(),
                "first_128_bytes_hex": decoded_header[:128].hex(" "),
            },
            "integrity_checks": {
                "external_size_matches": firstheader["external_size_declared"] == sidecar_size,
                "firstheader_following_length_matches": equation,
                "archive_data_end_offset": firstheader_end,
                "header_record_end_offset": record_end,
                "bytes_between_header_record_and_archive_data_end": firstheader_end - record_end,
            },
            "block_layout_candidates": block_layout_candidates(decoded_header),
        }

        ascii_strings = extract_ascii_strings(decoded_header)
        utf16_strings = extract_utf16le_ascii_strings(decoded_header)
        out_root = Path(args.out)
        stamp = datetime.now().strftime("recon_v5_%Y%m%d_%H%M%S_%f")
        out_dir = out_root / stamp
        write_reports(out_dir, report, ascii_strings, utf16_strings)
        (out_dir / "decoded_header.bin").write_bytes(decoded_header)

        print("[COMPLETE] NSISBI embedded-header decoder v5 finished.")
        print(f"  Header offset: {firstheader['offset']:,}; flags={firstheader['flags_hex']}")
        print(f"  Stored bytes: {stored_size:,}; decoded bytes: {len(decoded_header):,}; expected: {header_size:,}")
        print(f"  Codec: {codec}; internal blocks: {len(block_reports)}")
        print(f"  External size matches sidecar: {report['integrity_checks']['external_size_matches']}")
        print(f"  Header following-length equation matches: {equation}")
        print(f"  Layout candidates: {[(x['block_count'], x['score_out_of_4']) for x in report['block_layout_candidates']]}")
        print(f"  Output: {out_dir.resolve()}")
        print("  Review header_decode.txt, header_strings.txt, and header_decode.json.")
        return 0
    except (OSError, ValueError, struct.error, zlib.error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        print("No external payload files were extracted. Inputs remain untouched.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
