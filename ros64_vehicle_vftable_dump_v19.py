#!/usr/bin/env python3
"""Generate a read-only WinDbg probe to dump V18-derived ROS64 vftable candidates.

The candidate vftable starts eight bytes after a qword slot that V18 found
containing the matching Complete Object Locator (COL) pointer. These are still
candidate tables until the entries are checked for plausible code pointers.
No target calls, memory writes, breakpoints, or .foreach substitutions are used.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

MODULE_BASE = 0x140000000
MODULE_END = 0x145AEA000
RDATA_BASE = 0x141BD2000
RDATA_SIZE = 0x112DC6A
ENTRY_COUNT = 16

# Addresses transcribed from successful V18 `s -q` results.
# ref_slot contains the COL pointer; vftable candidate = ref_slot + 8.
TARGETS = [
    {"name":"AvatarVehicleFilter", "col":0x1428C50B8, "chd":0x1428C50E0, "ref_slot":0x141BFDF10, "priority":"vehicle avatar interpolation/filtering"},
    {"name":"AvatarVehicleVtimeFilter", "col":0x1428C4F90, "chd":0x1428C4FB8, "ref_slot":0x141BFDE00, "priority":"vehicle avatar time interpolation/filtering"},
    {"name":"DynamicVehicle4W", "col":0x1428FEE30, "chd":0x1428FEE58, "ref_slot":0x141D049C0, "priority":"primary vehicle type"},
    {"name":"DynamicVehicleModelDelegate4W", "col":0x1428FEEC8, "chd":0x1428FEEF0, "ref_slot":0x141D04A90, "priority":"vehicle model bridge/delegate"},
    {"name":"DynamicVehicleModelDelegate", "col":0x1428FF680, "chd":0x1428FF6A8, "ref_slot":0x141D06BB8, "priority":"generic vehicle model bridge/delegate"},
    {"name":"DynamicCharacter", "col":0x1428FE9C0, "chd":0x1428FE9E8, "ref_slot":0x141D04138, "priority":"related dynamic actor comparison"},
    {"name":"PhysicsModelActor", "col":0x1428FD690, "chd":0x1428FD6B8, "ref_slot":0x141D01748, "priority":"physics actor bridge"},
    {"name":"PhysicsModel", "col":0x1428FD820, "chd":0x1428FD848, "ref_slot":0x141D017B0, "priority":"physics model"},
    {"name":"DynamicWorld", "col":0x1428FCAF8, "chd":0x1428FCB20, "ref_slot":0x141D00590, "priority":"dynamic physics world"},
    {"name":"DynamicBody", "col":0x1428FCDB8, "chd":0x1428FCDE0, "ref_slot":0x141D00DB0, "priority":"dynamic body comparison"},
    {"name":"SceneNode", "col":0x1428E9198, "chd":0x1428E91C0, "ref_slot":0x141C409D8, "priority":"scene entity node"},
    {"name":"PositionProvider", "col":0x1428E1858, "chd":0x1428E1880, "ref_slot":0x141C31F18, "priority":"position source/provider"},
    {"name":"SpaceNode", "col":0x1428D4FF8, "chd":0x1428D5020, "ref_slot":0x141C137C0, "priority":"world-space entity node"},
    {"name":"AutoTracing", "col":0x1428D9F78, "chd":0x1428D9FA0, "ref_slot":0x141C23718, "priority":"tracking behavior data"},
    {"name":"AutoTracingPos", "col":0x1428D9FF8, "chd":0x1428DA020, "ref_slot":0x141C23738, "priority":"position-tracking behavior data"},
    {"name":"AutoMoving", "col":0x1428D9F00, "chd":0x1428D9F28, "ref_slot":0x141C23700, "priority":"automatic movement behavior data"},
    {"name":"GameObject", "col":0x1428D1B10, "chd":0x1428CAAA8, "ref_slot":0x141C08908, "priority":"gameplay object"},
    {"name":"Transform", "col":0x1428CDA28, "chd":0x1428CDA50, "ref_slot":0x141C06450, "priority":"gameplay transform"},
    {"name":"World", "col":0x1428D3BF0, "chd":0x1428D3C18, "ref_slot":0x141C0ED98, "priority":"world container"},
    {"name":"Scene primary", "col":0x1428D9DD0, "chd":0x1428D9DF8, "ref_slot":0x141C24C00, "priority":"scene primary subobject"},
    {"name":"Scene alternate offset 8", "col":0x1428D9ED8, "chd":0x1428D9DF8, "ref_slot":0x141C25420, "priority":"scene secondary subobject with offset 8"},
]

def hx(n:int)->str:
    return f"{n:016X}"

def generate(out_dir: Path)->None:
    out_dir.mkdir(parents=True, exist_ok=True)
    command_path=(out_dir/"windbg_vehicle_vftable_dump_v19.txt").resolve()
    log_path=(out_dir/"windbg_vehicle_vftable_dump_v19.log").resolve()
    plan_txt=out_dir/"vehicle_vftable_dump_plan.txt"
    plan_json=out_dir/"vehicle_vftable_dump_plan.json"
    lines=[
        ".echo ============================================================================",
        ".echo ROS64 V19 candidate vftable dump and RTTI hierarchy metadata",
        ".echo READ ONLY no target calls writes breakpoints or foreach substitution",
        f".logopen {log_path}",
        "lm m ros64",
        f".echo Expected module base 0x{MODULE_BASE:016X} end-exclusive 0x{MODULE_END:016X}",
        ".echo V18 found COL-pointer references in .rdata. Candidate vftable address is reference slot plus 8 bytes.",
        ".echo CHD has four DWORDs. The fourth DWORD is the base-class-array RVA.",
        f".echo Dumping up to {ENTRY_COUNT} qword entries per candidate table",
        ".echo ============================================================================",
    ]
    for t in TARGETS:
        table=t["ref_slot"]+8
        lines += [
            ".echo ----------------------------------------------------------------------------",
            f".echo TARGET {t['name']} PRIORITY {t['priority']}",
            f".echo COL 0x{hx(t['col'])} CHD 0x{hx(t['chd'])}",
            f".echo COL reference slot 0x{hx(t['ref_slot'])}",
            f".echo VFTABLE candidate 0x{hx(table)}",
            f"dd {hx(t['col'])} L6",
            f"dd {hx(t['chd'])} L4",
            f"dq {hx(t['ref_slot'])} L3",
            f"dq {hx(table)} L{ENTRY_COUNT:X}",
            f"dps {hx(table)} L{ENTRY_COUNT:X}",
        ]
    lines += [".echo V19 candidate vftable dump complete", ".logclose", ""]
    if any(";" in x for x in lines):
        raise ValueError("Generated command file contains semicolon command separators")
    command_path.write_text("\n".join(lines), encoding="ascii", newline="\n")
    plan_lines=[
        "ROS64 V19 VEHICLE VFTABLE CANDIDATE DUMP PLAN",
        "="*72,
        f"Module: 0x{MODULE_BASE:016X} - 0x{MODULE_END:016X} (exclusive)",
        f"Candidate tables: {len(TARGETS)}",
        f"Entries requested per candidate: {ENTRY_COUNT}",
        "V18 search hit contains a COL pointer at ref_slot. Candidate table address is ref_slot+8.",
        "Validate qword entries with dps output and ensure addresses resolve inside ros64 executable sections before disassembling.",
        "For Scene alternate offset 8, keep it separate from the primary Scene vftable.",
        "CHD command reads four DWORDs: signature, attributes, numBaseClasses, baseClassArray RVA.",
        "",
    ]
    for t in TARGETS:
        plan_lines.append(f"{t['name']}: COL=0x{hx(t['col'])} CHD=0x{hx(t['chd'])} ref_slot=0x{hx(t['ref_slot'])} table=0x{hx(t['ref_slot']+8)} | {t['priority']}")
    plan_txt.write_text("\n".join(plan_lines)+"\n",encoding="utf-8",newline="\n")
    manifest={
        "tool":"ros64_vehicle_vftable_dump_v19",
        "purpose":"Read-only dump of V18-derived candidate vftable entries and full four-DWORD CHD headers.",
        "safety":"No target function calls, memory writes, breakpoints, or .foreach substitutions.",
        "module":{"base":f"0x{MODULE_BASE:016X}","end_exclusive":f"0x{MODULE_END:016X}","size":MODULE_END-MODULE_BASE},
        "entry_count":ENTRY_COUNT,
        "target_count":len(TARGETS),
        "targets":[{**t,"col":f"0x{hx(t['col'])}","chd":f"0x{hx(t['chd'])}","ref_slot":f"0x{hx(t['ref_slot'])}","vftable_candidate":f"0x{hx(t['ref_slot']+8)}"} for t in TARGETS],
        "command_file":str(command_path),"log_file":str(log_path),
    }
    plan_json.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("[COMPLETE] ROS64 V19 candidate vftable dump generated.")
    print(f"  Targets: {len(TARGETS)}")
    print(f"  Entries per table: {ENTRY_COUNT}")
    print(f"  Command file: {out_dir / command_path.name}")
    print(f"  Plan: {plan_txt}")
    print(f"  JSON: {plan_json}")
    print("  Execute inside WinDbg after confirming lm m ros64.")

def self_test()->None:
    assert MODULE_END-MODULE_BASE==0x5AEA000
    assert RDATA_BASE+RDATA_SIZE==0x142CFFC6A
    assert len(TARGETS)==21
    assert len({t['name'] for t in TARGETS})==len(TARGETS)
    assert all(MODULE_BASE<t[k]<MODULE_END for t in TARGETS for k in ('col','chd','ref_slot'))
    assert all(MODULE_BASE<t['ref_slot']+8<MODULE_END for t in TARGETS)
    assert all(t['ref_slot']+8 not in (t['col'],t['chd']) for t in TARGETS)
    assert ENTRY_COUNT==16
    commands=[]
    for t in TARGETS:
        table=t['ref_slot']+8
        commands += [f"dd {hx(t['col'])} L6",f"dd {hx(t['chd'])} L4",f"dq {hx(t['ref_slot'])} L3",f"dq {hx(table)} L{ENTRY_COUNT:X}",f"dps {hx(table)} L{ENTRY_COUNT:X}"]
    assert '.foreach' not in '\n'.join(commands).lower()
    assert not any(';' in line for line in commands)
    assert not any(word in '\n'.join(commands).lower() for word in (' call ',' bp ',' eb ',' ew ',' ed ',' eq ',' !run'))
    assert len(commands)==len(TARGETS)*5
    print('[PASS] Module and addresses are within the expected loaded image')
    print('[PASS] All 21 candidate COL and reference-slot records are configured')
    print('[PASS] Candidate vftable addresses are calculated as reference slot plus 8')
    print('[PASS] Commands dump full four-DWORD CHD headers and 16 table entries')
    print('[PASS] Generated probe has no .foreach substitution or semicolon separators')
    print('[PASS] No target calls, memory writes, breakpoints, or execution commands')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true',help='run self-tests')
    parser.add_argument('--out-dir',default='recon_out_v19',help='output directory')
    args=parser.parse_args()
    if args.self_test:
        self_test()
    generate(Path(args.out_dir))
