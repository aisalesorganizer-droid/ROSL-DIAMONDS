#!/usr/bin/env python3
"""Generate a read-only WinDbg probe for ROS64 vehicle/tracking RTTI COLs.

V18 validates COL fields, dumps class hierarchy descriptors, and searches .rdata
for qword references to candidate COL addresses. It makes no target calls,
process-memory writes, breakpoints, or .foreach substitutions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MODULE_BASE = 0x140000000
MODULE_END = 0x145AEA000
RDATA_BASE = 0x141BD2000
RDATA_SIZE = 0x112DC6A

# Values are derived from V16's first TypeDescriptor-RVA hit per target.
# col = hit - 0x0C. CHD address = module base + the pClassDescriptor RVA
# shown at COL+0x10 in the V16 log.
CANDIDATES = [
    {"name": "AvatarVehicleFilter", "col": 0x1428C50B8, "chd": 0x1428C50E0, "priority": "vehicle avatar interpolation/filtering"},
    {"name": "AvatarVehicleVtimeFilter", "col": 0x1428C4F90, "chd": 0x1428C4FB8, "priority": "vehicle avatar time interpolation/filtering"},
    {"name": "DynamicVehicle4W", "col": 0x1428FEE30, "chd": 0x1428FEE58, "priority": "primary vehicle type"},
    {"name": "DynamicVehicleModelDelegate4W", "col": 0x1428FEEC8, "chd": 0x1428FEEF0, "priority": "vehicle model bridge/delegate"},
    {"name": "DynamicVehicleModelDelegate", "col": 0x1428FF680, "chd": 0x1428FF6A8, "priority": "generic vehicle model bridge/delegate"},
    {"name": "DynamicCharacter", "col": 0x1428FE9C0, "chd": 0x1428FE9E8, "priority": "related dynamic actor comparison"},
    {"name": "PhysicsModelActor", "col": 0x1428FD690, "chd": 0x1428FD6B8, "priority": "physics actor bridge"},
    {"name": "PhysicsModel", "col": 0x1428FD820, "chd": 0x1428FD848, "priority": "physics model"},
    {"name": "DynamicWorld", "col": 0x1428FCAF8, "chd": 0x1428FCB20, "priority": "dynamic physics world"},
    {"name": "DynamicBody", "col": 0x1428FCDB8, "chd": 0x1428FCDE0, "priority": "dynamic body comparison"},
    {"name": "SceneNode", "col": 0x1428E9198, "chd": 0x1428E91C0, "priority": "scene entity node"},
    {"name": "PositionProvider", "col": 0x1428E1858, "chd": 0x1428E1880, "priority": "position source/provider"},
    {"name": "SpaceNode", "col": 0x1428D4FF8, "chd": 0x1428D5020, "priority": "world-space entity node"},
    {"name": "AutoTracing", "col": 0x1428D9F78, "chd": 0x1428D9FA0, "priority": "tracking behavior data, verify whether a vftable exists"},
    {"name": "AutoTracingPos", "col": 0x1428D9FF8, "chd": 0x1428DA020, "priority": "position-tracking behavior data, verify whether a vftable exists"},
    {"name": "AutoMoving", "col": 0x1428D9F00, "chd": 0x1428D9F28, "priority": "automatic movement behavior data, verify whether a vftable exists"},
    {"name": "GameObject", "col": 0x1428D1B10, "chd": 0x1428CAAA8, "priority": "gameplay object"},
    {"name": "Transform", "col": 0x1428CDA28, "chd": 0x1428CDA50, "priority": "gameplay transform"},
    {"name": "World", "col": 0x1428D3BF0, "chd": 0x1428D3C18, "priority": "world container"},
    {"name": "Scene", "col": 0x1428D9DD0, "chd": 0x1428D9DF8, "priority": "scene container primary COL"},
]

# Same Scene type descriptor, distinct COL/self RVA in the V16 log.
ALTERNATE_COLS = [
    {"name": "Scene alternate COL", "col": 0x1428D9ED8, "chd": 0x1428D9DF8,
     "priority": "secondary COL candidate, inspect offset and references"},
]

# A known TypeDescriptor-RVA hit that is not shaped like a COL. This is included
# for field validation only; do not search it as a vftable locator.
NON_COL_CHECKS = [
    {"name": "GameObject non-COL matching reference", "address": 0x1428CAA74,
     "priority": "expected to fail COL signature / self checks"},
]


def hx(value: int, width: int = 16) -> str:
    return f"{value:0{width}X}"


def generate(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    command_path = (out_dir / "windbg_vehicle_vftable_probe_v18.txt").resolve()
    log_path = (out_dir / "windbg_vehicle_vftable_probe_v18.log").resolve()
    plan_txt = out_dir / "rtti_vehicle_vftable_probe_plan.txt"
    plan_json = out_dir / "rtti_vehicle_vftable_probe_plan.json"

    lines = [
        ".echo ============================================================================",
        ".echo ROS64 V18 vehicle/tracking COL and vftable-reference probe",
        ".echo READ-ONLY: no target calls, writes, breakpoints, or .foreach substitutions",
        f".logopen {log_path}",
        ".echo Confirm module range before interpreting results",
        "lm m ros64",
        f".echo Expected module base 0x{MODULE_BASE:016X} end-exclusive 0x{MODULE_END:016X}",
        f".echo Search range .rdata 0x{RDATA_BASE:016X} size 0x{RDATA_SIZE:X}",
        ".echo Each candidate COL should begin with DWORDs signature=1 offset=0 cdOffset=0",
        ".echo COL+0x0C is TypeDescriptor RVA COL+0x10 is CHD RVA COL+0x14 is pSelf RVA",
        ".echo Each CHD dump shows signature numBaseClasses and baseClassArray RVA",
        ".echo A qword search hit at SLOT may be the pointer immediately before a vftable",
        ".echo Validate with dq SLOT L3 and dps SLOT+8 L20 in a follow-up before disassembly",
        ".echo ============================================================================",
    ]

    for item in CANDIDATES:
        col = item["col"]
        chd = item["chd"]
        lines += [
            ".echo ----------------------------------------------------------------------------",
            f".echo TARGET {item['name']} PRIORITY {item['priority']}",
            f".echo COL 0x{col:016X} CHD 0x{chd:016X}",
            f"dd {hx(col)} L6",
            f"dd {hx(chd)} L3",
            f"s -q {hx(RDATA_BASE)} L{RDATA_SIZE:X} {hx(col)}",
        ]

    for item in ALTERNATE_COLS:
        lines += [
            ".echo ----------------------------------------------------------------------------",
            f".echo TARGET {item['name']} PRIORITY {item['priority']}",
            f".echo COL 0x{item['col']:016X} CHD 0x{item['chd']:016X}",
            f"dd {hx(item['col'])} L6",
            f"dd {hx(item['chd'])} L3",
            f"s -q {hx(RDATA_BASE)} L{RDATA_SIZE:X} {hx(item['col'])}",
        ]

    for item in NON_COL_CHECKS:
        lines += [
            ".echo ----------------------------------------------------------------------------",
            f".echo VALIDATION ONLY {item['name']} PRIORITY {item['priority']}",
            f"dd {hx(item['address'])} L6",
        ]

    lines += [".echo V18 COL and qword-reference probe complete", ".logclose", ""]
    # Critical WinDbg parser guard: semicolons split commands even in .echo strings.
    if any(";" in line for line in lines):
        raise ValueError("Generated WinDbg command file contains a semicolon command separator")
    command_path.write_text("\n".join(lines), encoding="ascii", newline="\n")

    all_records = CANDIDATES + ALTERNATE_COLS
    plan_lines = [
        "ROS64 V18 RTTI VEHICLE/TRACKING COL AND VFTABLE REFERENCE PLAN",
        "=" * 76,
        f"Module: 0x{MODULE_BASE:016X} - 0x{MODULE_END:016X} (exclusive)",
        f"Search range: 0x{RDATA_BASE:016X} size 0x{RDATA_SIZE:X}",
        f"Primary COLs: {len(CANDIDATES)}",
        f"Alternate COLs: {len(ALTERNATE_COLS)}",
        "",
        "For each COL, verify dd COL L6: signature=1, offset=0, cdOffset=0, TD RVA, CHD RVA, pSelf RVA.",
        "pSelf RVA must equal COL-MODULE_BASE. Then inspect each qword search hit SLOT with dq SLOT L3 and dps SLOT+8 L20.",
        "Do not treat a search hit alone as proof of a vftable; validate the neighboring values are plausible code pointers.",
        "",
    ]
    for item in all_records:
        plan_lines.append(f"{item['name']}: COL=0x{item['col']:016X} CHD=0x{item['chd']:016X} | {item['priority']}")
    plan_lines += ["", "Validation-only non-COL checks:"]
    for item in NON_COL_CHECKS:
        plan_lines.append(f"{item['name']}: address=0x{item['address']:016X} | {item['priority']}")
    plan_txt.write_text("\n".join(plan_lines) + "\n", encoding="utf-8", newline="\n")

    manifest = {
        "tool": "ros64_rtti_vehicle_vftable_probe_v18",
        "purpose": "Validate V16-derived x64 RTTI COL candidates, inspect CHDs, and search .rdata for qword references to candidate COL addresses.",
        "safety": "Read-only debugger commands. No target calls, memory writes, breakpoints, or .foreach token substitution.",
        "module": {"base": f"0x{MODULE_BASE:016X}", "end_exclusive": f"0x{MODULE_END:016X}", "size": MODULE_END - MODULE_BASE},
        "search_range": {"name": ".rdata", "base": f"0x{RDATA_BASE:016X}", "size": RDATA_SIZE, "end_exclusive": f"0x{RDATA_BASE + RDATA_SIZE:016X}"},
        "primary_candidate_count": len(CANDIDATES),
        "alternate_col_count": len(ALTERNATE_COLS),
        "candidates": [{**x, "col": f"0x{x['col']:016X}", "chd": f"0x{x['chd']:016X}", "search_command": f"s -q {hx(RDATA_BASE)} L{RDATA_SIZE:X} {hx(x['col'])}"} for x in CANDIDATES],
        "alternate_cols": [{**x, "col": f"0x{x['col']:016X}", "chd": f"0x{x['chd']:016X}"} for x in ALTERNATE_COLS],
        "non_col_validation_only": [{**x, "address": f"0x{x['address']:016X}"} for x in NON_COL_CHECKS],
        "command_file": str(command_path),
        "log_file": str(log_path),
    }
    plan_json.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("[COMPLETE] ROS64 V18 COL and vftable-reference probe generated.")
    print(f"  Primary COLs: {len(CANDIDATES)}")
    print(f"  Alternate COLs: {len(ALTERNATE_COLS)}")
    print(f"  Command file: {out_dir / command_path.name}")
    print(f"  Plan: {plan_txt}")
    print(f"  JSON: {plan_json}")
    print("  Execute the command file inside WinDbg after confirming `lm m ros64`.")


def self_test() -> None:
    assert MODULE_END - MODULE_BASE == 0x5AEA000
    assert RDATA_BASE + RDATA_SIZE == 0x142CFFC6A
    assert len(CANDIDATES) == 20
    assert len({x["col"] for x in CANDIDATES}) == len(CANDIDATES)
    assert all(MODULE_BASE < x["col"] < MODULE_END for x in CANDIDATES + ALTERNATE_COLS)
    probe = []
    for x in CANDIDATES + ALTERNATE_COLS:
        probe += [f"dd {hx(x['col'])} L6", f"dd {hx(x['chd'])} L3", f"s -q {hx(RDATA_BASE)} L{RDATA_SIZE:X} {hx(x['col'])}"]
    joined = "\n".join(probe)
    assert ".foreach" not in joined.lower()
    assert not any(";" in line for line in joined.splitlines())
    assert not any(token in joined.lower() for token in (" bp ", " eb ", " ew ", " ed ", " eq ", " call ", "!run"))
    assert all(re.fullmatch(r"dd [0-9A-F]+ L[36]", line) or re.fullmatch(r"s -q [0-9A-F]+ L[0-9A-F]+ [0-9A-F]+", line) for line in joined.splitlines())
    print("[PASS] Module and .rdata search range validate")
    print("[PASS] Exactly 20 primary COL candidates and one alternate COL are configured")
    print("[PASS] Every primary and alternate candidate is inside the loaded module")
    print("[PASS] Commands are direct read/search commands without .foreach token substitution")
    print("[PASS] Probe includes no target calls, memory writes, or breakpoints")
    assert all(";" not in item["priority"] for item in CANDIDATES + ALTERNATE_COLS + NON_COL_CHECKS)
    print("[PASS] All generated .echo text is free of semicolon command separators")


if __name__ == "__main__":
    import re

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run built-in generator checks")
    parser.add_argument("--out-dir", default="recon_out_v18", help="output directory (default: recon_out_v18)")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    generate(Path(args.out_dir))
