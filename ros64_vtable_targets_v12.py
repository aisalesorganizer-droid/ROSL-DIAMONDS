#!/usr/bin/env python3
"""V12: generate a focused WinDbg disassembly plan from V11 RTTI/vftable results.

This utility does not open or execute ros64.exe and does not attach to WinDbg.
It reads the V11 vtable_groups.csv, compares selected SfxBaseData-derived vftables,
then writes a WinDbg command script that disassembles the relevant virtual slots.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_GROUPS = Path(r"recon_out_v11\analysis\vtable_groups.csv")
DEFAULT_OUT = Path("recon_out_v12")
IMAGE_BASE = 0x140000000
TARGET_CLASS = "ModelFxData"
# ModelFxData gets all seven slots. These related classes are sampled at the
# class-specific slots 0, 1, and 6; slots 2-5 are shared in the V11 inventory.
COMPARISON_CLASSES = [
    "SfxBaseData",
    "DummyFxData",
    "FxGroupData",
    "ParticleModelFxData",
    "SpriteFxData",
    "MtlCtrlFxData",
]
SLOT_LABELS = {
    0: "slot0_destructor_candidate",
    1: "slot1_class_specific_virtual",
    2: "slot2_shared_candidate",
    3: "slot3_shared_candidate",
    4: "slot4_shared_candidate",
    5: "slot5_shared_candidate",
    6: "slot6_class_specific_virtual",
}
HEX_RE = re.compile(r"^0x([0-9a-fA-F]+)$")


def parse_hex(value: str, field: str) -> int:
    value = value.strip()
    m = HEX_RE.match(value)
    if not m:
        raise ValueError(f"Invalid hexadecimal value for {field}: {value!r}")
    return int(m.group(1), 16)


def load_groups(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"V11 group CSV not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {
            "group_index", "class_name", "col_address", "vtable_address",
            "function_count", "is_selected_target", "function_addresses",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("V11 group CSV missing fields: " + ", ".join(sorted(missing)))
        rows = []
        for line_no, row in enumerate(reader, start=2):
            try:
                addresses = [parse_hex(x, "function_addresses") for x in row["function_addresses"].split(";") if x.strip()]
                claimed = int(row["function_count"])
                if claimed != len(addresses):
                    # V11 can label long, unvalidated data tails as function pointers in
                    # one malformed group. We reject mismatch rows instead of relying on them.
                    row["count_consistent"] = False
                else:
                    row["count_consistent"] = True
                rows.append({
                    "group_index": int(row["group_index"]),
                    "class_name": row["class_name"],
                    "col_address": parse_hex(row["col_address"], "col_address"),
                    "vtable_address": parse_hex(row["vtable_address"], "vtable_address"),
                    "claimed_function_count": claimed,
                    "function_addresses": addresses,
                    "count_consistent": row["count_consistent"],
                    "is_selected_target": row["is_selected_target"].strip().lower() == "true",
                })
            except (ValueError, TypeError) as e:
                raise ValueError(f"Bad row {line_no} in {path}: {e}") from e
    return rows


def exact_class(row: dict[str, Any], class_name: str) -> bool:
    # A decorated name should end in @<class>@world@neox@@ for the concrete classes here.
    return row["class_name"] == f".?AV{class_name}@world@neox@@"


def choose_groups(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    wanted = [TARGET_CLASS, *COMPARISON_CLASSES]
    picked: dict[str, dict[str, Any]] = {}
    for name in wanted:
        matches = [r for r in rows if exact_class(r, name)]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one V11 vftable group for {name}, found {len(matches)}")
        row = matches[0]
        if not row["count_consistent"] or len(row["function_addresses"]) < 7:
            raise ValueError(f"V11 vftable group for {name} has inconsistent/short function list")
        picked[name] = row
    return picked


def build_plan(groups: dict[str, dict[str, Any]]) -> dict[str, Any]:
    # Address-level de-duplication is critical: inherited virtual functions often
    # share the exact same target across classes and should only be disassembled once.
    address_sources: dict[int, list[dict[str, Any]]] = defaultdict(list)
    class_slot_map: dict[str, list[dict[str, Any]]] = {}
    for name, group in groups.items():
        slots = []
        selected_indices: Iterable[int] = range(7) if name == TARGET_CLASS else (0, 1, 6)
        for index in selected_indices:
            address = group["function_addresses"][index]
            slot = {
                "class_name": name,
                "slot_index": index,
                "slot_label": SLOT_LABELS[index],
                "vtable_address": group["vtable_address"],
                "function_address": address,
            }
            slots.append(slot)
            address_sources[address].append(slot)
        class_slot_map[name] = slots

    # VTable contains seven slots; slot 2-5 are presumed shared only because the
    # actual V11 lists show exact identical addresses, not because of a name assumption.
    functions = []
    for address in sorted(address_sources):
        sources = address_sources[address]
        if not (IMAGE_BASE <= address < IMAGE_BASE + 0x10000000):
            raise ValueError(f"Candidate function address outside expected image range: 0x{address:X}")
        functions.append({
            "address": address,
            "aliases": [
                {"class_name": s["class_name"], "slot_index": s["slot_index"], "slot_label": s["slot_label"]}
                for s in sources
            ],
            "alias_count": len(sources),
        })
    return {
        "tool": "ros64_vtable_targets_v12",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "input_image_base_assumption": IMAGE_BASE,
        "target_class": TARGET_CLASS,
        "comparison_classes": COMPARISON_CLASSES,
        "selected_groups": {
            name: {
                "group_index": g["group_index"],
                "decorated_name": g["class_name"],
                "col_address": g["col_address"],
                "vtable_address": g["vtable_address"],
                "function_count": len(g["function_addresses"]),
                "function_addresses": g["function_addresses"],
            }
            for name, g in groups.items()
        },
        "class_slot_map": class_slot_map,
        "unique_function_targets": functions,
        "notes": [
            "Slot labels are provisional; disassembly must confirm semantics.",
            "Slot 0 is called a destructor candidate based on prior observed code pattern, not just its position.",
            "A valid runtime module base of 0x140000000 must be confirmed before interpreting these addresses.",
            "WinDbg uf output is inspection only; this script never calls or executes target functions.",
        ],
    }


def dbg_addr(value: int) -> str:
    return f"{value:016X}"[:8] + "`" + f"{value:016X}"[8:]


def write_outputs(plan: dict[str, Any], outdir: Path) -> tuple[Path, Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "disassembly_plan.json"
    csv_path = outdir / "disassembly_targets.csv"
    cmd_path = outdir / "windbg_disassembly_v12.txt"
    report_path = outdir / "disassembly_plan.txt"
    json_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["function_address", "alias_count", "aliases"])
        writer.writeheader()
        for fn in plan["unique_function_targets"]:
            aliases = "; ".join(f"{a['class_name']}.slot{a['slot_index']}" for a in fn["aliases"])
            writer.writerow({"function_address": f"0x{fn['address']:X}", "alias_count": fn["alias_count"], "aliases": aliases})

    log_path = (outdir / "windbg_disassembly_v12.log").resolve()
    cmd_lines = [
        ".echo ============================================================================",
        ".echo V12 focused virtual-function disassembly for ROS64",
        ".echo SAFETY: commands inspect memory and disassemble only, target functions are not called.",
        f".logopen {log_path}",
        ".echo Confirm the module base shown below is 00000001`40000000 before trusting addresses.",
        "lm m ros64",
        ".echo ============================================================================",
        ".echo VFTABLE SLOT COMPARISON (no duplicate disassembly in this section)",
    ]
    for name, group in plan["selected_groups"].items():
        cmd_lines.append(f".echo CLASS {name} vftable={dbg_addr(group['vtable_address'])} COL={dbg_addr(group['col_address'])}")
        indices = range(7) if name == TARGET_CLASS else (0, 1, 6)
        for i in indices:
            address = group["function_addresses"][i]
            cmd_lines.append(f".echo SLOT {i} {name} target={dbg_addr(address)}")
    cmd_lines += [".echo ============================================================================", ".echo UNIQUE FUNCTION DISASSEMBLY"]
    # Disassemble each distinct address once, while retaining all class/slot aliases.
    for fn in plan["unique_function_targets"]:
        aliases = "_".join(f"{a['class_name']}_s{a['slot_index']}" for a in fn["aliases"])
        cmd_lines.append(f".echo UNIQUE {dbg_addr(fn['address'])} aliases={aliases}")
        cmd_lines.append(f"ln {dbg_addr(fn['address'])}")
        cmd_lines.append(f"uf {dbg_addr(fn['address'])}")
    cmd_lines += [".logclose", ".echo V12 DISASSEMBLY COMPLETE", ""]
    cmd_path.write_text("\n".join(cmd_lines), encoding="ascii", newline="\n")

    lines = [
        "ROS64 VTABLE DISASSEMBLY PLAN V12",
        "=" * 78,
        f"Target class: {TARGET_CLASS}",
        f"Expected image base: 0x{IMAGE_BASE:X} (verify with WinDbg lm m ros64)",
        f"Selected class groups: {len(plan['selected_groups'])}",
        f"Unique disassembly targets: {len(plan['unique_function_targets'])}",
        "",
        "VFTABLE SLOT MAP",
    ]
    for name, group in plan["selected_groups"].items():
        lines.append(f"{name}: vftable=0x{group['vtable_address']:X}, COL=0x{group['col_address']:X}")
        inds = range(7) if name == TARGET_CLASS else (0, 1, 6)
        for i in inds:
            addr = group["function_addresses"][i]
            lines.append(f"  slot {i}: 0x{addr:X} ({SLOT_LABELS[i]})")
    lines += ["", "UNIQUE TARGETS"]
    for fn in plan["unique_function_targets"]:
        aliases = ", ".join(f"{a['class_name']}.slot{a['slot_index']}" for a in fn["aliases"])
        lines.append(f"0x{fn['address']:X} [{fn['alias_count']} aliases]: {aliases}")
    lines += ["", "NOTES", *[f"- {n}" for n in plan["notes"]], ""]
    report_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return json_path, csv_path, cmd_path, report_path


def synthetic_self_test() -> None:
    # Exercise the real CSV-loading and report-writing paths with a tiny fixture.
    classes = {
        "ModelFxData": (35, "0x1428DD1F8", "0x141C2A990", ["0x1404A3D40", "0x1404AB480", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A6DA0"]),
        "SfxBaseData": (25, "0x1428DCCD0", "0x141C2A710", ["0x1404A4300", "0x1404AD8B0", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A73F0"]),
        "DummyFxData": (26, "0x1428DCD48", "0x141C2A750", ["0x1404A3830", "0x1404AD8B0", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A73F0"]),
        "FxGroupData": (27, "0x1428DCDC8", "0x141C2A790", ["0x1404A38B0", "0x1404AD8B0", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A73F0"]),
        "ParticleModelFxData": (29, "0x1428DCEC8", "0x141C2A810", ["0x1404A3FF0", "0x1404ABFC0", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A7040"]),
        "SpriteFxData": (34, "0x1428DD178", "0x141C2A950", ["0x1404A4860", "0x1404AE3E0", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A76A0"]),
        "MtlCtrlFxData": (47, "0x1428DD818", "0x141C2AC90", ["0x1404A3D80", "0x1404AB890", "0x1404AF270", "0x1404AF320", "0x1404AF080", "0x1404A68C0", "0x1404A6EA0"]),
    }
    with tempfile.TemporaryDirectory(prefix="ros64_v12_test_") as tmp:
        root = Path(tmp)
        fixture = root / "vtable_groups.csv"
        with fixture.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "group_index", "class_name", "col_address", "vtable_address",
                "first_capture_slot_index", "function_count", "next_col_marker_index",
                "next_col_address", "is_selected_target", "function_addresses",
            ])
            writer.writeheader()
            for name, (idx, col, vt, funcs) in classes.items():
                writer.writerow({
                    "group_index": idx,
                    "class_name": f".?AV{name}@world@neox@@",
                    "col_address": col,
                    "vtable_address": vt,
                    "first_capture_slot_index": idx * 8 + 26,
                    "function_count": len(funcs),
                    "next_col_marker_index": idx * 8 + 33,
                    "next_col_address": "0x1428DDD000",
                    "is_selected_target": str(name == TARGET_CLASS),
                    "function_addresses": ";".join(funcs),
                })
        rows = load_groups(fixture)
        groups = choose_groups(rows)
        plan = build_plan(groups)
        target = plan["selected_groups"][TARGET_CLASS]
        assert target["function_addresses"][0] == 0x1404A3D40
        assert target["function_addresses"][6] == 0x1404A6DA0
        assert any(fn["address"] == 0x1404AF270 for fn in plan["unique_function_targets"])
        assert len(plan["unique_function_targets"]) < 22
        json_path, csv_path, cmd_path, report_path = write_outputs(plan, root / "out")
        assert all(p.is_file() and p.stat().st_size > 0 for p in (json_path, csv_path, cmd_path, report_path))
        commands = cmd_path.read_text(encoding="ascii")
        assert "uf 00000001`404A3D40" in commands
        assert ".logclose" in commands
        # WinDbg treats semicolons as command separators, including within .echo text.
        # Keep every .echo command free of semicolons so the command file parses cleanly.
        echo_lines = [line for line in commands.splitlines() if line.lstrip().lower().startswith(".echo")]
        assert echo_lines and all(";" not in line for line in echo_lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a focused WinDbg disassembly plan from V11 RTTI/vftable results")
    ap.add_argument("--groups", type=Path, default=DEFAULT_GROUPS, help="V11 vtable_groups.csv")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="V12 output directory")
    ap.add_argument("--self-test", action="store_true", help="Run synthetic plan-generation test")
    args = ap.parse_args()
    if args.self_test:
        try:
            synthetic_self_test()
        except Exception as exc:
            print(f"[FAIL] V12 plan generation: {exc}", file=sys.stderr)
            return 1
        print("[PASS] V11 vftable class selection and validation")
        print("[PASS] virtual-slot map and per-slot comparisons")
        print("[PASS] unique target de-duplication across inherited methods")
        print("[PASS] WinDbg command script generation and report files")
        print("[PASS] WinDbg .echo lines avoid command-separator semicolons")
        return 0
    try:
        rows = load_groups(args.groups)
        groups = choose_groups(rows)
        plan = build_plan(groups)
        json_path, csv_path, cmd_path, report_path = write_outputs(plan, args.out)
        print("[COMPLETE] ROS64 V12 WinDbg disassembly plan generated (offline only).")
        print(f"  V11 groups: {args.groups}")
        print(f"  Selected class groups: {len(groups)}")
        print(f"  Unique disassembly targets: {len(plan['unique_function_targets'])}")
        print(f"  Plan report: {report_path}")
        print(f"  JSON: {json_path}")
        print(f"  Targets CSV: {csv_path}")
        print(f"  WinDbg command file: {cmd_path}")
        print("  [NOTE] Confirm the module base in WinDbg before executing the generated commands.")
        return 0
    except (OSError, ValueError, csv.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
