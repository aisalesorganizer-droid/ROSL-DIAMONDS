#!/usr/bin/env python3
"""Generate a read-only WinDbg RTTI-reference probe for vehicle/tracking candidates.

Based on verified type-name hits in recon_out_v14/windbg_runtime_types_v14.log.
In MSVC x64 RTTI, a type-name string normally begins 0x10 bytes after the
TypeDescriptor. Complete Object Locators store the TypeDescriptor RVA at +0x0C.
This probe searches for those 32-bit RVAs and dumps the candidate COL records.
It does not modify memory, invoke target functions, or set breakpoints.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

MODULE_BASE = 0x0000000140000000
MODULE_END = 0x0000000145AEA000
# V14 !dh reports .rdata at RVA 0x1BD2000 with virtual size 0x112DC6A.
RTTI_SEARCH_BASE = MODULE_BASE + 0x1BD2000
RTTI_SEARCH_SIZE = 0x112DC6A
DEFAULT_OUT = Path("recon_out_v15")

# name_addr is the address of the name bytes, as seen in V14's `da` output.
# TD = name_addr - 0x10; COL pTypeDescriptor RVA = TD - MODULE_BASE.
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


def hx(value: int) -> str:
    return f"{value:016X}"


def target_record(item: dict) -> dict:
    name_addr = int(item["name_addr"])
    td_addr = name_addr - 0x10
    rva = td_addr - MODULE_BASE
    return {**item, "name_addr_hex": f"0x{name_addr:016X}",
            "type_descriptor_hex": f"0x{td_addr:016X}",
            "type_descriptor_rva_hex": f"0x{rva:08X}",
            "type_descriptor_rva_dword": f"{rva:08X}"}


def build_commands(out_dir: Path, module_base: int = MODULE_BASE,
                   module_end: int = MODULE_END) -> str:
    if module_end <= module_base:
        raise ValueError("Module end must be greater than module base")
    size = module_end - module_base
    log_path = str((out_dir / "windbg_rtti_vehicle_candidates_v15.log").resolve()).replace("/", "\\")
    lines = [
        ".echo ============================================================================",
        ".echo V15 RTTI candidate reference scan for vehicle and tracking types",
        ".echo READ-ONLY: searches mapped image and dumps candidate RTTI metadata only",
        f".logopen {log_path}",
        ".echo Confirm the module range before interpreting results",
        "lm m ros64",
        f".echo Expected base 0x{module_base:X} end 0x{module_end:X} size 0x{size:X}",
        ".echo For x64 MSVC RTTI, a name at TD+0x10 implies TD=name_address-0x10.",
        ".echo The COL TypeDescriptor RVA field is at COL+0x0C. A match hit is expected there.",
    ]
    for item in CANDIDATES:
        rec = target_record(item)
        lines += [
            ".echo ============================================================================",
            f".echo TARGET {item['name']} [{item['kind']}] - {item['priority']}",
            f".echo DECORATED {item['decorated']}",
            f".echo NAME_ADDRESS {rec['name_addr_hex']}",
            f".echo TYPE_DESCRIPTOR {rec['type_descriptor_hex']} RVA {rec['type_descriptor_rva_hex']}",
            f"da {hx(item['name_addr'])}",
            f"dps {hx(int(rec['type_descriptor_hex'],16))} L3",
            f".echo Search image for 32-bit TypeDescriptor RVA {rec['type_descriptor_rva_hex']}",
            f".foreach ( tdfield {{ s -d {hx(RTTI_SEARCH_BASE)} L{RTTI_SEARCH_SIZE:X} {rec['type_descriptor_rva_dword']} }}) {{ dd ${{tdfield}}-C L6 }}",
        ]
    lines += [
        ".echo ============================================================================",
        ".echo V15 RTTI candidate scan complete",
        ".logclose",
    ]
    return "\n".join(lines) + "\n"


def build_plan(out_dir: Path) -> dict:
    targets = [target_record(x) for x in CANDIDATES]
    return {
        "tool": "ros64_rtti_vehicle_candidates_v15",
        "purpose": "Locate MSVC x64 Complete Object Locator records whose TypeDescriptor RVA matches selected vehicle, physics, movement, or world type names from V14.",
        "module": {"name": "ros64.exe", "base": f"0x{MODULE_BASE:016X}",
                   "end_exclusive": f"0x{MODULE_END:016X}", "size": MODULE_END-MODULE_BASE},
        "rtti_search_window": {"section": ".rdata", "base": f"0x{RTTI_SEARCH_BASE:016X}",
                               "size": RTTI_SEARCH_SIZE, "end_exclusive": f"0x{RTTI_SEARCH_BASE+RTTI_SEARCH_SIZE:016X}"},
        "candidate_count": len(targets),
        "candidates": targets,
        "method": [
            "V14 `da` hits identify the name bytes. The TypeDescriptor is assumed at name_address minus 0x10, per MSVC layout.",
            "Search the mapped image for the TypeDescriptor RVA as a 32-bit value.",
            "For a hit at address H, inspect COL at H-0x0C with `dd H-C L6`; verify signature, pTypeDescriptor RVA, pClassDescriptor RVA, and pSelf RVA before using it.",
            "This pass does not yet infer the vftable. The next pass will search for absolute qword references to validated COL addresses.",
        ],
        "safety": "Read-only memory/string inspection commands; no function execution, memory writes, or breakpoints.",
        "outputs": {
            "command_file": str((out_dir / "windbg_rtti_vehicle_candidates_v15.txt").as_posix()),
            "log_file": str((out_dir / "windbg_rtti_vehicle_candidates_v15.log").as_posix()),
        },
    }


def self_test() -> None:
    assert MODULE_END - MODULE_BASE == 0x5AEA000
    assert RTTI_SEARCH_BASE == 0x0000000141BD2000
    assert RTTI_SEARCH_BASE <= 0x00000001428DD1F8 < RTTI_SEARCH_BASE + RTTI_SEARCH_SIZE
    assert len(CANDIDATES) >= 12
    seen = set()
    for item in CANDIDATES:
        rec = target_record(item)
        assert MODULE_BASE <= item["name_addr"] < MODULE_END
        assert rec["type_descriptor_hex"] == f"0x{item['name_addr']-0x10:016X}"
        assert int(rec["type_descriptor_rva_hex"], 16) == item["name_addr"] - 0x10 - MODULE_BASE
        assert rec["type_descriptor_rva_dword"] not in seen
        seen.add(rec["type_descriptor_rva_dword"])
    commands = build_commands(DEFAULT_OUT)
    assert "DynamicVehicle4W" in commands and "AutoTracingPos" in commands
    assert "s -d" in commands and "dd ${tdfield}-C L6" in commands
    assert "lm m ros64" in commands and ".logclose" in commands
    forbidden = (".writemem", ".readmem", "eb ", "eq ", "ed ", "call ", "bp ", "bu ")
    for line in commands.lower().splitlines():
        stripped = line.strip()
        assert not any(stripped.startswith(prefix) for prefix in forbidden), f"Unexpected modifying/execution command: {stripped}"
    assert all(";" not in line for line in commands.splitlines()), "Keep each WinDbg command on a separate line"
    print("[PASS] Candidate name addresses and module-relative TypeDescriptor RVAs validate")
    print("[PASS] Vehicle, physics, AutoTracing, gameplay, and world targets are included")
    print("[PASS] Generated commands search COL TypeDescriptor RVA fields and dump candidate metadata")
    print("[PASS] No memory-write, target-call, or breakpoint commands are generated")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run generator checks and exit")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    cmd = build_commands(out)
    plan = build_plan(out)
    command_path = out / "windbg_rtti_vehicle_candidates_v15.txt"
    plan_txt = out / "rtti_vehicle_candidates_plan.txt"
    plan_json = out / "rtti_vehicle_candidates_plan.json"
    command_path.write_text(cmd, encoding="utf-8", newline="\n")
    plan_txt.write_text(
        "ROS64 V15 RTTI VEHICLE/TRACKING CANDIDATE PLAN\n"
        + "=" * 76 + "\n"
        + f"Module base: {plan['module']['base']}\n"
        + f"Module end (exclusive): {plan['module']['end_exclusive']}\n"
        + f"Candidates: {len(CANDIDATES)}\n"
        + f".rdata search window: 0x{RTTI_SEARCH_BASE:016X} size 0x{RTTI_SEARCH_SIZE:X}\n\n"
        + "Targets:\n"
        + "".join(f"  {x['name']}: name={x['name_addr_hex']} TD={x['type_descriptor_hex']} RVA={x['type_descriptor_rva_hex']} ({x['priority']})\n" for x in plan['candidates'])
        + "\nRun the command file inside WinDbg after confirming `lm m ros64`.\n"
        + "Inspect each COL hit at H-0x0C and validate its fields before concluding the class has a vftable.\n"
        + "This pass only locates RTTI records; the following pass will map verified COLs to vftables.\n",
        encoding="utf-8", newline="\n")
    plan_json.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("[COMPLETE] ROS64 V15 RTTI vehicle/tracking candidate probe generated.")
    print(f"  Candidates: {len(CANDIDATES)}")
    print(f"  Command file: {command_path}")
    print(f"  Plan: {plan_txt}")
    print(f"  JSON: {plan_json}")
    print("  Execute the command file inside WinDbg, not CMD; verify `lm m ros64` first.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
