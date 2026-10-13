#!/usr/bin/env python3
"""Generate a read-only WinDbg disassembly probe for ROS64 vehicle/tracking RTTI candidates."""
from pathlib import Path
import argparse, json, sys

BASE = 0x140000000
END = 0x145AEA000
OUT = Path('recon_out_v20')
LOG = OUT / 'windbg_vehicle_tracking_disassembly_v20.log'
CMD = OUT / 'windbg_vehicle_tracking_disassembly_v20.txt'
PLAN = OUT / 'vehicle_tracking_disassembly_plan.txt'
JSON = OUT / 'vehicle_tracking_disassembly_plan.json'

TARGETS = [
 ('DynamicVehicle4W', 0x1407F66A0,0x1407F7170,0x1407F79A0,0x1407F6530,0x1407F7D70,0x1407F6600,0x1407F77B0,0x1407F7410,0x1407F62D0,0x1407F7470,0x1407F62F0,0x1407F7440,0x1407F72F0,0x1407F6650,0x1407F6260,0x1407F6520),
 ('DynamicVehicleModelDelegate4W',0x14082A3F0,0x14082A380,0x14082A400,0x14082B4E0,0x140829F00,0x14082BCA0,0x140829520,0x14082B4D0,0x140829FC0,0x14082B3B0,0x140829000),
 ('DynamicVehicleModelDelegate',0x1408471F0,0x1408471E0,0x140847200,0x140847E90,0x140847110,0x140846F20,0x140848440,0x140845FF0,0x140847C50,0x140847010,0x140847B00,0x140845970),
 ('AvatarVehicleFilter',0x140266110,0x140266830,0x140266FC0,0x140267550,0x140258440,0x140267120,0x1402673F0,0x1402664E0,0x140266A10),
 ('AvatarVehicleVtimeFilter',0x140263720,0x140263E10,0x140264AE0,0x140265340,0x140258440,0x140264C40,0x1402651D0,0x140263AF0,0x140264380),
 ('AutoMoving_AutoTracing_AutoTracingPos',0x140431E10,0x140398400,0x140431E40,0x140398480,0x140431E70,0x1403940A0,0x140431EA0,0x1403940C0),
]
# COLs from V18. CHD base-class array is at CHD + 0x0C RVA field.
CHDS = [
 ('AvatarVehicleFilter_CHD',0x1428C50E0),('AvatarVehicleVtimeFilter_CHD',0x1428C4FB8),
 ('DynamicVehicle4W_CHD',0x1428FEE58),('DynamicVehicleModelDelegate4W_CHD',0x1428FEEF0),
 ('DynamicVehicleModelDelegate_CHD',0x1428FF6A8),('DynamicCharacter_CHD',0x1428FE9E8),
 ('PhysicsModelActor_CHD',0x1428FD6B8),('PhysicsModel_CHD',0x1428FD848),
 ('DynamicWorld_CHD',0x1428FCB20),('DynamicBody_CHD',0x1428FCDE0),
 ('SceneNode_CHD',0x1428E91C0),('PositionProvider_CHD',0x1428E1880),
 ('SpaceNode_CHD',0x1428D5020),('AutoTracing_CHD',0x1428D9FA0),
 ('AutoTracingPos_CHD',0x1428DA020),('AutoMoving_CHD',0x1428D9F28),
 ('GameObject_CHD',0x1428CAAA8),('Transform_CHD',0x1428CDA50),
 ('World_CHD',0x1428D3C18),('Scene_CHD',0x1428D9DF8),
]

def make_commands():
    lines = [
      '.echo ============================================================================',
      '.echo ROS64 V20 vehicle and tracking targeted disassembly',
      '.echo READ ONLY inspection only no target calls or memory writes',
      f'.logopen {LOG.resolve()}',
      'lm m ros64',
      '.echo Confirmed expected image base is 0x0000000140000000',
      '.echo First dump class hierarchy base-class-array references',
    ]
    for name, chd in CHDS:
        lines += [f'.echo CHD {name} at 0x{chd:016X}', f'dd 0x{chd:016X} L4', f'dd 0x{chd+0x0C:016X} L1']
    lines += ['.echo ============================================================================', '.echo Disassemble unique candidate virtual functions with unwind-based function boundaries']
    seen=set()
    for group, *addrs in TARGETS:
        lines.append(f'.echo TARGET GROUP {group}')
        for a in addrs:
            if a in seen: continue
            seen.add(a)
            if not (BASE <= a < END): raise ValueError(f'address outside image: {a:x}')
            lines += [f'.echo FUNCTION 0x{a:016X}', f'ln 0x{a:016X}', f'uf 0x{a:016X}']
    lines += ['.echo V20 targeted disassembly complete', '.logclose']
    return '\n'.join(lines)+'\n', seen

def self_test():
    cmd, seen = make_commands()
    tests = [
      ('Module and all code addresses are inside expected image', all(BASE <= a < END for _,*xs in TARGETS for a in xs)),
      ('Six priority target groups are configured', len(TARGETS)==6),
      ('All twenty CHD records are configured', len(CHDS)==20),
      ('Unique function candidates are disassembled once', cmd.count('.echo FUNCTION')==len(seen)),
      ('No .foreach substitution or semicolon command separators', '.foreach' not in cmd and all(';' not in line for line in cmd.splitlines())),
      ('No target calls, memory writes, breakpoints, or execution commands', not any(x in cmd.lower() for x in [' bp ', ' ba ', ' g\n', ' eb ', ' ew ', ' ed ', ' eq ', ' .call ']))
    ]
    for name, ok in tests: print(f'[{"PASS" if ok else "FAIL"}] {name}')
    if not all(ok for _,ok in tests): return 1
    print(f'[COMPLETE] V20 self-test passed. Unique function addresses: {len(seen)}')
    return 0

def generate():
    OUT.mkdir(parents=True, exist_ok=True)
    cmd, seen = make_commands()
    CMD.write_text(cmd, encoding='utf-8', newline='\n')
    plan = {'version':20,'image_base':hex(BASE),'image_end_exclusive':hex(END),'target_groups':[{'name':n,'addresses':[hex(a) for a in xs]} for n,*xs in TARGETS], 'chd_addresses':[{'name':n,'address':hex(a)} for n,a in CHDS], 'unique_function_count':len(seen),'commands_file':str(CMD),'log_file':str(LOG)}
    JSON.write_text(json.dumps(plan,indent=2),encoding='utf-8')
    PLAN.write_text('ROS64 V20 targeted disassembly plan\n\nUnique candidate function addresses: '+str(len(seen))+'\nGroups:\n'+'\n'.join('- '+n+': '+str(len(xs))+' candidates' for n,*xs in TARGETS)+'\n\nRead-only: ln and uf commands plus CHD data reads.\n',encoding='utf-8')
    print('[COMPLETE] ROS64 V20 targeted disassembly probe generated.')
    print(f'  Unique function addresses: {len(seen)}')
    print(f'  Command file: {CMD}')
    print(f'  Plan: {PLAN}')
    print(f'  JSON: {JSON}')

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--self-test',action='store_true'); args=p.parse_args()
    sys.exit(self_test() if args.self_test else (generate() or 0))
