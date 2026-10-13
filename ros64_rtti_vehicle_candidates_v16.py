#!/usr/bin/env python3
"""Generate direct, read-only WinDbg searches for vehicle/tracking RTTI references.

V16 fixes V15's .foreach parsing issue. V15 iterated over every token emitted by
`s -d`, including dumped data words, which led to invalid follow-up expressions.
V16 emits each `s -d` command directly. It does not interpolate search output or
invoke target code. Review the logged hit address and validate a candidate COL
by dumping six DWORDs from (hit address - 0x0C).
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

MODULE_BASE = 0x0000000140000000
MODULE_END = 0x0000000145AEA000
RTTI_SEARCH_BASE = MODULE_BASE + 0x1BD2000
RTTI_SEARCH_SIZE = 0x112DC6A
DEFAULT_OUT = Path("recon_out_v16")

# name_addr points at the decorated-name bytes in V14's `da` output.
# For MSVC x64 TypeDescriptor: TD = name address - 0x10.
CANDIDATES = [
    {"name": "AvatarVehicleFilter", "kind": "class", "name_addr": 0x00000001431A61F0,
     "decorated": ".?AVAvatarVehicleFilter@filter_2_0@bwclient@neox@@", "priority": "vehicle avatar interpolation/filtering"},
    {"name": "AvatarVehicleVtimeFilter", "kind": "class", "name_addr": 0x00000001431A6130,
     "decorated": ".?AVAvatarVehicleVtimeFilter@filter_2_0@bwclient@neox@@", "priority": "vehicle avatar time interpolation/filtering"},
    {"name": "DynamicVehicle4W", "kind": "class", "name_addr": 0x00000001431C9A88,
     "decorated": ".?AVDynamicVehicle4W@dynamics@neox@@", "priority": "primary vehicle type"},
    {"name": "DynamicVehicleModelDelegate4W", "kind": "class", "name_addr": 0x00000001431C9AC0,
     "decorated": ".?AVDynamicVehicleModelDelegate4W@dynamics@neox@@", "priority": "vehicle model bridge/delegate"},
    {"name": "DynamicVehicleModelDelegate", "kind": "class", "name_addr": 0x00000001431C9DD0,
     "decorated": ".?AVDynamicVehicleModelDelegate@dynamics@neox@@", "priority": "generic vehicle model bridge/delegate"},
    {"name": "DynamicCharacter", "kind": "class", "name_addr": 0x00000001431C9938,
     "decorated": ".?AVDynamicCharacter@dynamics@neox@@", "priority": "related dynamic actor comparison"},
    {"name": "PhysicsModelActor", "kind": "class", "name_addr": 0x00000001431C90B0,
     "decorated": ".?AVPhysicsModelActor@dynamics@neox@@", "priority": "physics actor bridge"},
    {"name": "PhysicsModel", "kind": "class", "name_addr": 0x00000001431C9188,
     "decorated": ".?AVPhysicsModel@dynamics@neox@@", "priority": "physics model"},
    {"name": "DynamicWorld", "kind": "class", "name_addr": 0x00000001431C8C48,
     "decorated": ".?AVDynamicWorld@dynamics@neox@@", "priority": "dynamic physics world"},
    {"name": "DynamicBody", "kind": "class", "name_addr": 0x0000000143158E10,
     "decorated": ".?AVDynamicBody@dynamics@neox@@", "priority": "dynamic body comparison"},
    {"name": "SceneNode", "kind": "class", "name_addr": 0x00000001431C03D0,
     "decorated": ".?AVSceneNode@world@neox@@", "priority": "scene entity node"},
    {"name": "PositionProvider", "kind": "class", "name_addr": 0x0000000143154310,
     "decorated": ".?AVPositionProvider@world@neox@@", "priority": "position source/provider"},
    {"name": "SpaceNode", "kind": "class", "name_addr": 0x00000001431B7B40,
     "decorated": ".?AVSpaceNode@world@neox@@", "priority": "world-space entity node"},
    {"name": "AutoTracing", "kind": "struct", "name_addr": 0x00000001431BA1E0,
     "decorated": ".?AUAutoTracing@SpaceNode@world@neox@@", "priority": "tracking behavior data"},
    {"name": "AutoTracingPos", "kind": "struct", "name_addr": 0x00000001431BA218,
     "decorated": ".?AUAutoTracingPos@SpaceNode@world@neox@@", "priority": "position-tracking behavior data"},
    {"name": "AutoMoving", "kind": "struct", "name_addr": 0x00000001431BA1A8,
     "decorated": ".?AUAutoMoving@SpaceNode@world@neox@@", "priority": "automatic movement behavior data"},
    {"name": "GameObject", "kind": "class", "name_addr": 0x00000001431AB7B8,
     "decorated": ".?AVGameObject@gameplay@@", "priority": "gameplay object"},
    {"name": "Transform", "kind": "class", "name_addr": 0x0000000143152480,
     "decorated": ".?AVTransform@gameplay@@", "priority": "gameplay transform"},
    {"name": "World", "kind": "class", "name_addr": 0x00000001431B7148,
     "decorated": ".?AVWorld@world@neox@@", "priority": "world container"},
    {"name": "Scene", "kind": "class", "name_addr": 0x00000001431BA150,
     "decorated": ".?AVScene@world@neox@@", "priority": "scene container"},
]


def fmt(value: int) -> str:
    return f"{value:016X}"


def record(item: dict) -> dict:
    name_addr = int(item["name_addr"])
    td_addr = name_addr - 0x10
    rva = td_addr - MODULE_BASE
    return {**item,
            "name_address": f"0x{name_addr:016X}",
            "type_descriptor_address": f"0x{td_addr:016X}",
            "type_descriptor_rva": f"0x{rva:08X}",
            "search_command": f"s -d {fmt(RTTI_SEARCH_BASE)} L{RTTI_SEARCH_SIZE:X} {rva:08X}"}


def build_commands(out_dir: Path) -> str:
    log_path = str((out_dir / "windbg_rtti_vehicle_candidates_v16.log").resolve()).replace("/", "\\")
    lines = [
        ".echo ============================================================================",
        ".echo V16 direct RTTI reference searches for vehicle and tracking types",
        ".echo READ-ONLY: direct search commands only, no .foreach token substitution",
        f".logopen {log_path}",
        ".echo Confirm the module range before interpreting results",
        "lm m ros64",
        f".echo Expected base 0x{MODULE_BASE:X} end 0x{MODULE_END:X} size 0x{MODULE_END-MODULE_BASE:X}",
        f".echo Search range .rdata 0x{RTTI_SEARCH_BASE:016X} size 0x{RTTI_SEARCH_SIZE:X}",
        ".echo Each s -d hit is the address of the matching TypeDescriptor RVA DWORD, expected at COL+0x0C.",
        ".echo To validate a hit H, run: dd H-C L6. The first DWORD should be 1 and final pSelf RVA should equal (COL-MODULE_BASE).",
    ]
    for item in CANDIDATES:
        rec = record(item)
        lines.extend([
            ".echo ============================================================================",
            f".echo TARGET {item['name']} [{item['kind']}] - {item['priority']}",
            f".echo DECORATED {item['decorated']}",
            f".echo NAME_ADDRESS {rec['name_address']}",
            f".echo TYPE_DESCRIPTOR {rec['type_descriptor_address']} RVA {rec['type_descriptor_rva']}",
            f"da {fmt(item['name_addr'])}",
            f"{rec['search_command']}",
        ])
    lines += [".echo ============================================================================", ".echo V16 direct RTTI searches complete", ".logclose"]
    return "\n".join(lines) + "\n"


def build_plan(out_dir: Path) -> dict:
    return {
        "tool": "ros64_rtti_vehicle_candidates_v16",
        "purpose": "Search read-only for MSVC x64 COL TypeDescriptor RVA fields associated with 20 vehicle, physics, tracking, movement, gameplay, and world candidates.",
        "fix_from_v15": "Removed .foreach around s -d; V15 accidentally iterated over all tokens of search output including data words, causing invalid addresses and 'Couldn't resolve error'.",
        "module": {"name": "ros64.exe", "base": f"0x{MODULE_BASE:016X}", "end_exclusive": f"0x{MODULE_END:016X}", "size": MODULE_END-MODULE_BASE},
        "search_range": {"name": ".rdata", "base": f"0x{RTTI_SEARCH_BASE:016X}", "size": RTTI_SEARCH_SIZE, "end_exclusive": f"0x{RTTI_SEARCH_BASE+RTTI_SEARCH_SIZE:016X}"},
        "candidate_count": len(CANDIDATES),
        "candidates": [record(x) for x in CANDIDATES],
        "interpretation": [
            "The search hit H is the address of the DWORD containing the TypeDescriptor RVA.",
            "The matching COL candidate begins at H-0x0C; inspect six DWORDs there.",
            "On a plausible x64 MSVC COL, signature should be 1, and pSelf at COL+0x14 should equal COL-MODULE_BASE. Validate before treating a hit as authoritative.",
            "COL presence does not yet prove a vftable reference; the next stage should search for aligned absolute qword references to each validated COL address.",
        ],
        "safety": "Read-only memory/string search and display; no target calls, memory writes, or breakpoints.",
        "outputs": {"command_file": (out_dir / "windbg_rtti_vehicle_candidates_v16.txt").as_posix(),
                    "log_file": (out_dir / "windbg_rtti_vehicle_candidates_v16.log").as_posix()},
    }


def self_test() -> None:
    assert MODULE_END - MODULE_BASE == 0x5AEA000
    assert RTTI_SEARCH_BASE == 0x0000000141BD2000
    assert len(CANDIDATES) == 20
    assert record(CANDIDATES[0])["type_descriptor_rva"] == "0x031A61E0"
    assert record(CANDIDATES[1])["type_descriptor_rva"] == "0x031A6120"
    commands = build_commands(DEFAULT_OUT)
    assert "s -d" in commands and "AvatarVehicleFilter" in commands and "DynamicVehicle4W" in commands
    assert ".foreach (" not in commands and "${tdfield}" not in commands
    assert "dd H-C L6" in commands
    assert sum(1 for line in commands.splitlines() if line.startswith("s -d ")) == len(CANDIDATES)
    forbidden = (".writemem", ".readmem", "eb ", "eq ", "ed ", "call ", "bp ", "bu ")
    for line in commands.lower().splitlines():
        stripped = line.strip()
        assert not any(stripped.startswith(p) for p in forbidden), f"Unexpected modifying/execution command: {stripped}"
        assert ";" not in line
    print("[PASS] Module and .rdata search window validate")
    print("[PASS] All 20 candidate TypeDescriptor RVAs are generated")
    print("[PASS] Searches are direct commands with no .foreach token substitution")
    print("[PASS] Commands contain no target calls, memory writes, or breakpoints")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    commands = build_commands(out)
    plan = build_plan(out)
    (out / "windbg_rtti_vehicle_candidates_v16.txt").write_text(commands, encoding="utf-8", newline="\n")
    (out / "rtti_vehicle_candidates_plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
    txt = [
        "ROS64 V16 RTTI VEHICLE/TRACKING CANDIDATE PLAN",
        "=" * 76,
        f"Module: {plan['module']['base']} - {plan['module']['end_exclusive']} (exclusive)",
        f"Search range: {plan['search_range']['base']} size 0x{RTTI_SEARCH_SIZE:X}",
        f"Candidate count: {len(CANDIDATES)}",
        "",
        "Fix: direct s -d searches; no .foreach over search output tokens.",
        "After execution, each result hit H identifies a possible TypeDescriptor RVA field.",
        "Validate with `dd H-C L6`; candidate COL is at H-0x0C.",
        "",
    ]
    txt.extend(f"{x['name']}: TD={x['type_descriptor_address']} RVA={x['type_descriptor_rva']} | {x['priority']}" for x in plan["candidates"])
    (out / "rtti_vehicle_candidates_plan.txt").write_text("\n".join(txt) + "\n", encoding="utf-8", newline="\n")
    print("[COMPLETE] ROS64 V16 direct RTTI reference probe generated.")
    print(f"  Candidates: {len(CANDIDATES)}")
    print(f"  Command file: {out / 'windbg_rtti_vehicle_candidates_v16.txt'}")
    print(f"  Plan: {out / 'rtti_vehicle_candidates_plan.txt'}")
    print(f"  JSON: {out / 'rtti_vehicle_candidates_plan.json'}")
    print("  Execute the command file inside WinDbg after confirming `lm m ros64`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
