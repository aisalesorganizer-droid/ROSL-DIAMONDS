#!/usr/bin/env python3
"""Generate a read-only WinDbg survey of runtime MSVC type names in ros64.exe.

V14 broadens analysis beyond the previously captured ModelFxData RTTI region.
It scans the full mapped PE image for MSVC class (.?AV) and struct (.?AU)
name prefixes and displays each matching string. It does not call target code
or modify target memory.

Run this generator from the repository root, then execute the generated .txt
inside the existing WinDbg session only after checking `lm m ros64`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MODULE_BASE = 0x0000000140000000
MODULE_END = 0x0000000145AEA000
MODULE_SIZE = MODULE_END - MODULE_BASE
DEFAULT_OUT = Path("recon_out_v14")


def fmt_addr(value: int) -> str:
    return f"{value:016X}"


def build_commands(out_dir: Path, module_base: int = MODULE_BASE,
                   module_end: int = MODULE_END) -> str:
    size = module_end - module_base
    if size <= 0:
        raise ValueError("Module end must be greater than module base")
    log_path = (out_dir / "windbg_runtime_types_v14.log").resolve()
    # Use a simple Windows path: current repo path is known to contain no spaces.
    log_win = str(log_path).replace("/", "\\")
    base = fmt_addr(module_base)
    length = f"L{size:X}"
    lines = [
        ".echo ============================================================================",
        ".echo ROS64 V14 runtime MSVC type-name survey",
        ".echo READ-ONLY: search mapped image and display strings only",
        f".logopen {log_win}",
        ".echo Confirm ros64 module base and end before interpreting results",
        "lm m ros64",
        f".echo Expected base 0x{module_base:X} end 0x{module_end:X} size 0x{size:X}",
        f"!dh {base} -s",
        ".echo ============================================================================",
        ".echo MSVC CLASS TYPE NAMES (.?AV) ACROSS THE FULL IMAGE",
        f'.foreach ( classhit {{ s-[1]a {base} {length} ".?AV" }}) {{ da ${{classhit}} }}',
        ".echo ============================================================================",
        ".echo MSVC STRUCT TYPE NAMES (.?AU) ACROSS THE FULL IMAGE",
        f'.foreach ( structhit {{ s-[1]a {base} {length} ".?AU" }}) {{ da ${{structhit}} }}',
        ".echo ============================================================================",
        ".echo END V14 TYPE SURVEY",
        ".logclose",
    ]
    return "\n".join(lines) + "\n"


def build_plan(out_dir: Path, module_base: int = MODULE_BASE,
               module_end: int = MODULE_END) -> dict:
    size = module_end - module_base
    return {
        "tool": "ros64_runtime_type_survey_v14",
        "purpose": "Enumerate runtime MSVC RTTI class/struct names across the mapped ros64 image.",
        "repository_context": "Continue from V13 commit 3c9e1ed; V13 confirmed ModelFxData is visual-effect configuration rather than a demonstrated vehicle-tracking class.",
        "module": {
            "name": "ros64.exe",
            "base": f"0x{module_base:016X}",
            "end_exclusive": f"0x{module_end:016X}",
            "size": size,
            "size_hex": f"0x{size:X}",
        },
        "scans": [
            {"kind": "class", "prefix": ".?AV", "method": "WinDbg s-[1]a across full image, then da each hit"},
            {"kind": "struct", "prefix": ".?AU", "method": "WinDbg s-[1]a across full image, then da each hit"},
        ],
        "safety": "Read-only debugger commands. No function calls, breakpoints, memory writes, or execution-state changes are issued.",
        "interpretation": [
            "Confirm the actual ros64 base shown by lm m ros64 matches the expected base before running.",
            "The address shown by da for a type name normally points 0x10 bytes after the MSVC TypeDescriptor start; corroborate candidates before deriving hierarchy.",
            "Framework and compiler-generated types are expected. Prioritize game-specific namespaces and names related to world entities, movement, positions, tracking, mounts, vehicles, or simulation.",
            "A missing word such as Vehicle does not prove the feature is absent; names may be indirect, stripped, or implemented in another module.",
        ],
        "outputs": {
            "command_file": str((out_dir / "windbg_runtime_types_v14.txt").as_posix()),
            "log_file": str((out_dir / "windbg_runtime_types_v14.log").as_posix()),
            "plan_file": str((out_dir / "runtime_type_survey_plan.txt").as_posix()),
            "json_file": str((out_dir / "runtime_type_survey_plan.json").as_posix()),
        },
    }


def self_test() -> None:
    commands = build_commands(Path("recon_out_v14"))
    plan = build_plan(Path("recon_out_v14"))
    assert MODULE_SIZE == 0x5AEA000, f"Unexpected image size: {MODULE_SIZE:#x}"
    assert '.?AV' in commands and '.?AU' in commands
    assert 's-[1]a' in commands
    assert "da ${classhit}" in commands and "da ${structhit}" in commands
    assert "lm m ros64" in commands and "!dh" in commands
    assert all(";" not in line for line in commands.splitlines()), "Keep commands separated by newlines; do not place separators on .echo lines"
    forbidden_prefixes = (".writemem", ".readmem", "eb ", "eq ", "ed ", "call ")
    for line in commands.lower().splitlines():
        stripped = line.strip()
        assert not any(stripped.startswith(prefix) for prefix in forbidden_prefixes), (
            f"Unexpected modifying/execution command: {stripped}"
        )
    assert plan["module"]["base"] == "0x0000000140000000"
    assert plan["module"]["end_exclusive"] == "0x0000000145AEA000"
    print("[PASS] Full-image range matches the previously verified ros64 module range")
    print("[PASS] Class and struct prefix scans are generated")
    print("[PASS] Each scan hit is rendered through a read-only string display")
    print("[PASS] No memory-write or target-call commands are generated")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run generator checks and exit")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT, help="Output directory (default: recon_out_v14)")
    parser.add_argument("--module-base", type=lambda x: int(x, 0), default=MODULE_BASE)
    parser.add_argument("--module-end", type=lambda x: int(x, 0), default=MODULE_END)
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if args.module_end <= args.module_base:
        parser.error("--module-end must be greater than --module-base")

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    command_text = build_commands(out_dir, args.module_base, args.module_end)
    plan = build_plan(out_dir, args.module_base, args.module_end)
    command_path = out_dir / "windbg_runtime_types_v14.txt"
    plan_txt_path = out_dir / "runtime_type_survey_plan.txt"
    plan_json_path = out_dir / "runtime_type_survey_plan.json"
    command_path.write_text(command_text, encoding="utf-8", newline="\n")
    plan_txt_path.write_text(
        "ROS64 V14 RUNTIME TYPE SURVEY PLAN\n"
        + "=" * 76 + "\n"
        + f"Module base: {plan['module']['base']}\n"
        + f"Module end (exclusive): {plan['module']['end_exclusive']}\n"
        + f"Mapped image size: {plan['module']['size']} bytes ({plan['module']['size_hex']})\n\n"
        + "Scans:\n"
        + "  1. Runtime MSVC class type-name prefix .?AV\n"
        + "  2. Runtime MSVC struct type-name prefix .?AU\n\n"
        + "Run inside WinDbg, not cmd.exe. Confirm `lm m ros64` reports the expected module base first.\n"
        + "The command file enumerates matching strings across the loaded image; it does not execute target code.\n"
        + "After execution, commit the generated log and plan so the type names can be ranked for vehicle/movement tracking relevance.\n",
        encoding="utf-8", newline="\n")
    plan_json_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("[COMPLETE] ROS64 V14 runtime type survey command file generated.")
    print(f"  Module window: {plan['module']['base']} - {plan['module']['end_exclusive']} (exclusive)")
    print("  Scans: runtime MSVC class and struct name prefixes")
    print(f"  WinDbg command file: {command_path}")
    print(f"  Plan: {plan_txt_path}")
    print(f"  JSON: {plan_json_path}")
    print("  [NOTE] Execute the command file inside WinDbg, not cmd.exe; verify lm m ros64 first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
