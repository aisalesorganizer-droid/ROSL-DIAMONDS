#!/usr/bin/env python3
"""V13 generator for read-only WinDbg context probes around ModelFxData.

Reads the committed V12 disassembly log, collects constant data references from
ModelFxData slot 1, and emits a WinDbg command file to inspect likely key strings
and helper routines. The generated commands only read/disassemble memory.
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

DEFAULT_LOG = Path(r"recon_out_v12\windbg_disassembly_v12.log")
DEFAULT_OUT = Path("recon_out_v13")
TARGET_START = "UNIQUE 00000001`404AB480 aliases=ModelFxData_s1"

# Confirmed from the V12 disassembly: distinct data constants passed to the
# object/config reader, excluding known float constants and executable calls.
FALLBACK_DATA_REFS = [
    0x0000000141C2B5E0, 0x0000000141C2BAB8, 0x0000000141C19680,
    0x0000000141C2B838, 0x0000000141C2B7B8, 0x0000000141C2B7A8,
    0x0000000141C2BA70, 0x0000000141C2BA80, 0x0000000141C2B6A8,
    0x0000000141C2BAC8, 0x0000000141C2BAD8, 0x0000000141C2B650,
    0x0000000141C2B880, 0x0000000141C2BAE8, 0x0000000141C2BB08,
    0x0000000141C2BA90, 0x0000000141C2BAA8, 0x0000000141C2B0E8,
    0x0000000141C2BB30, 0x0000000141C2BB40,
]
HELPERS = [
    (0x00000001404A8430, "ModelFxData slot1 field conversion helper A"),
    (0x00000001404A8600, "ModelFxData slot1 field conversion helper B"),
    (0x000000014061B760, "ModelFxData slot1 collection or field helper"),
    (0x000000014061B6D0, "ModelFxData slot6 size-accounting helper"),
    (0x000000014040F810, "ModelFxData slot1 lookup helper"),
    (0x000000014049F1D0, "ModelFxData slot4 collection helper"),
]


def find_target_segment(log_text: str) -> str:
    start = log_text.find(TARGET_START)
    if start < 0:
        # tolerate alternate spaces/case in a future log, but retain strict address anchor
        match = re.search(r"UNIQUE\s+00000001`404AB480\s+aliases=ModelFxData_s1", log_text)
        if not match:
            raise ValueError(f"Cannot find target function anchor {TARGET_START!r} in V12 log")
        start = match.start()
    end = log_text.find("\nUNIQUE ", start + 1)
    return log_text[start:] if end < 0 else log_text[start:end]


def collect_data_refs(segment: str) -> list[int]:
    # Only capture read-only data references in the known 0x41C... image region.
    # Use bracket-contained LEA/MOV references so code targets are excluded.
    refs: list[int] = []
    for line in segment.splitlines():
        if not re.search(r"\b(?:lea|movss|movsd)\b", line, re.IGNORECASE):
            continue
        if "[" not in line or "]" not in line:
            continue
        for m in re.finditer(r"\(00000001`(41c[0-9a-fA-F]{5})\)", line):
            value = int("140000000" + m.group(1), 16) if False else int("00000001" + m.group(1), 16)
            if value not in refs:
                refs.append(value)
    return refs


def build_command_file(data_refs: list[int]) -> str:
    lines = [
        ".echo ============================================================================",
        ".echo V13 ModelFxData data-key and helper-function probe",
        ".echo Read-only WinDbg commands only. No target functions are called.",
        r".logopen C:\Users\MAFIA\Downloads\Compressed\ROSLegacy\Diamonds\recon_out_v13\windbg_context_v13.log",
        ".echo Confirm module base before interpreting addresses.",
        "lm m ros64",
        ".echo ============================================================================",
        ".echo STRING AND DATA CONSTANTS REFERENCED BY ModelFxData SLOT 1",
    ]
    for index, address in enumerate(data_refs, 1):
        addr = f"{address:016X}"
        windbg_addr = addr[:8] + "`" + addr[8:]
        lines.append(f".echo DATA_REF_{index:02d} {windbg_addr}")
        lines.append(f"da {windbg_addr}")
    lines += [
        ".echo ============================================================================",
        ".echo HELPER FUNCTIONS REACHED BY MODELFXDATA METHODS",
    ]
    for address, description in HELPERS:
        addr = f"{address:016X}"
        windbg_addr = addr[:8] + "`" + addr[8:]
        safe_desc = description.replace(";", ",")
        lines.append(f".echo TARGET {windbg_addr} {safe_desc}")
        lines.append(f"ln {windbg_addr}")
        lines.append(f"uf {windbg_addr}")
    lines += [
        ".logclose",
        ".echo V13 CONTEXT PROBE COMPLETE",
    ]
    return "\n".join(lines) + "\n"


def self_test() -> None:
    sample = """UNIQUE 00000001`404AB480 aliases=ModelFxData_s1
00000001`404ab4cf lea r8,[ros64!some_key (00000001`41c2b5e0)]
00000001`404ab555 movss xmm0,dword ptr [ros64!float_const (00000001`41bdc3e8)]
00000001`404ab4b9 mov rax,qword ptr [rcx]
UNIQUE 00000001`404AF320 aliases=ModelFxData_s3
"""
    seg = find_target_segment(sample)
    refs = collect_data_refs(seg)
    assert refs == [0x0000000141C2B5E0], refs
    commands = build_command_file(refs)
    assert "da 00000001`41C2B5E0" in commands
    assert "uf 00000001`404A8430" in commands
    assert ";" not in "\n".join(line for line in commands.splitlines() if line.startswith(".echo"))
    assert commands.endswith(".echo V13 CONTEXT PROBE COMPLETE\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="V12 WinDbg disassembly log")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        try:
            self_test()
        except Exception as exc:
            print(f"[FAIL] V13 context-probe self-test: {exc}", file=sys.stderr)
            return 1
        print("[PASS] ModelFxData slot-1 data-reference extraction")
        print("[PASS] WinDbg string and helper command generation")
        print("[PASS] .echo syntax and command-file safety")
        return 0
    try:
        if not args.log.is_file():
            raise FileNotFoundError(f"V12 log not found: {args.log}")
        log_text = args.log.read_text(encoding="utf-8", errors="replace")
        segment = find_target_segment(log_text)
        refs = collect_data_refs(segment)
        if not refs:
            refs = FALLBACK_DATA_REFS.copy()
            ref_source = "fallback constants validated from prior V12 log"
        else:
            # Include any constants visible in the log, plus previously validated
            # references that may fall beyond a clipped/truncated slot-1 listing.
            refs = list(dict.fromkeys(refs + FALLBACK_DATA_REFS))
            ref_source = "V12 function listing plus validated constants"
        args.out.mkdir(parents=True, exist_ok=True)
        command_path = args.out / "windbg_context_v13.txt"
        plan_path = args.out / "context_probe_plan.txt"
        json_path = args.out / "context_probe_plan.json"
        commands = build_command_file(refs)
        command_path.write_text(commands, encoding="utf-8", newline="\n")
        plan_lines = [
            "ROS64 V13 ModelFxData context probe",
            "=" * 72,
            f"V12 log: {args.log}",
            f"Data constants queued: {len(refs)}",
            f"Reference source: {ref_source}",
            f"Helper functions queued: {len(HELPERS)}",
            "",
            "Data references:",
            *[f"  0x{addr:016X}" for addr in refs],
            "",
            "Helper functions:",
            *[f"  0x{address:016X} - {description}" for address, description in HELPERS],
            "",
            "Execution: run the command file inside WinDbg after confirming lm m ros64 still starts at 0x140000000.",
            "Commands only read strings/symbols and disassemble; they do not call target functions.",
        ]
        plan_path.write_text("\n".join(plan_lines) + "\n", encoding="utf-8", newline="\n")
        import json
        payload = {
            "tool": "ros64_context_probe_v13",
            "input_log": str(args.log),
            "data_references": [f"0x{addr:016X}" for addr in refs],
            "helpers": [{"address": f"0x{address:016X}", "description": description} for address, description in HELPERS],
            "command_file": str(command_path),
            "report": str(plan_path),
            "read_only": True,
        }
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
        print("[COMPLETE] ROS64 V13 ModelFxData context probe generated (offline only).")
        print(f"  V12 log: {args.log}")
        print(f"  Data constants: {len(refs)}")
        print(f"  Helper functions: {len(HELPERS)}")
        print(f"  Plan: {plan_path}")
        print(f"  JSON: {json_path}")
        print(f"  WinDbg command file: {command_path}")
        print("  [NOTE] Execute the command file inside WinDbg, not cmd.exe; verify the module base first.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
