#!/usr/bin/env python3
"""V10 offline analyzer for targeted WinDbg memory-region captures.

This tool does not attach to a process or execute the target. It analyzes three
binary regions exported with WinDbg .writemem and reconstructs the most likely
MSVC x64 RTTI chain around a known vtable and decorated class name.

Default regions match the V10 capture commands from the investigation:
  ModelFxData_typeinfo.bin base 0x00000001428DD000
  ModelFxData_vtable.bin   base 0x0000000141C2A000
  ModelFxData_name.bin     base 0x00000001431BB000
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TYPEINFO = Path(r"recon_out_v10\ModelFxData_typeinfo.bin")
DEFAULT_VTABLE = Path(r"recon_out_v10\ModelFxData_vtable.bin")
DEFAULT_NAME = Path(r"recon_out_v10\ModelFxData_name.bin")
DEFAULT_OUT = Path(r"recon_out_v10\analysis")
DEFAULT_TYPEINFO_BASE = 0x00000001428DD000
DEFAULT_VTABLE_BASE = 0x0000000141C2A000
DEFAULT_NAME_BASE = 0x00000001431BB000
DEFAULT_VTABLE_ADDRESS = 0x0000000141C2A990
TARGET_NAME = b".?AVModelFxData@world@neox@@"
MAX_REGION = 64 * 1024 * 1024


def u32(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"u32 read outside buffer at 0x{off:X}")
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    if off < 0 or off + 8 > len(buf):
        raise ValueError(f"u64 read outside buffer at 0x{off:X}")
    return struct.unpack_from("<Q", buf, off)[0]


def hexv(value: int | None) -> str | None:
    return None if value is None else f"0x{value:X}"


@dataclass
class Region:
    name: str
    path: Path
    base: int
    data: bytes

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def contains(self, address: int, size: int = 1) -> bool:
        return self.base <= address and address + size <= self.end

    def read(self, address: int, size: int) -> bytes | None:
        if not self.contains(address, size):
            return None
        start = address - self.base
        return self.data[start:start + size]

    def offset(self, address: int) -> int | None:
        if self.base <= address < self.end:
            return address - self.base
        return None


def load_region(name: str, path: Path, base: int) -> Region:
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {name} capture: {path}\n"
            "Export it from the same WinDbg session with .writemem first."
        )
    size = path.stat().st_size
    if size <= 0 or size > MAX_REGION:
        raise ValueError(f"{name} capture has unexpected size {size:,} bytes (limit {MAX_REGION:,})")
    data = path.read_bytes()
    return Region(name, path, base, data)


def locate(regions: list[Region], address: int, size: int = 1) -> tuple[Region, bytes] | None:
    for region in regions:
        chunk = region.read(address, size)
        if chunk is not None:
            return region, chunk
    return None


def scan_exact(data: bytes, value: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        pos = data.find(value, start)
        if pos < 0:
            break
        hits.append(pos)
        start = pos + 1
    return hits


def classify_pointer(value: int, regions: list[Region]) -> str:
    for region in regions:
        if region.base <= value < region.end:
            return f"inside {region.name}"
    return "outside supplied captures"


def parse_col(regions: list[Region], col_address: int) -> dict[str, Any] | None:
    located = locate(regions, col_address, 24)
    if located is None:
        return None
    _, raw = located
    signature, offset, cd_offset, td_rva, chd_rva, self_rva = struct.unpack("<6I", raw)
    result: dict[str, Any] = {
        "address": col_address,
        "signature": signature,
        "offset": offset,
        "cd_offset": cd_offset,
        "type_descriptor_rva": td_rva,
        "class_hierarchy_descriptor_rva": chd_rva,
        "self_rva": self_rva,
        "layout": "MSVC x64 RVA-style COL" if signature == 1 else "unconfirmed COL layout",
    }
    if signature == 1 and self_rva:
        image_base = col_address - self_rva
        result["inferred_image_base"] = image_base
        result["type_descriptor_address"] = image_base + td_rva
        result["class_hierarchy_descriptor_address"] = image_base + chd_rva
        result["self_rva_matches_address"] = image_base + self_rva == col_address
    return result


def parse_type_descriptor(regions: list[Region], address: int) -> dict[str, Any] | None:
    located = locate(regions, address, 16)
    if located is None:
        return None
    region, raw = located
    name_address = address + 16
    name_region = locate(regions, name_address, 1)
    decorated_name = None
    if name_region:
        rr, _ = name_region
        start = name_address - rr.base
        end = rr.data.find(b"\0", start, min(len(rr.data), start + 4096))
        if end >= 0:
            decorated_name = rr.data[start:end].decode("ascii", errors="replace")
    vftable_ptr = u64(raw, 0)
    spare_ptr = u64(raw, 8)
    plausible_pointer = 0x10000 <= vftable_ptr <= 0x00007FFFFFFFFFFF
    return {
        "address": address,
        "capture": region.name,
        "type_info_vftable_pointer": vftable_ptr,
        "spare_pointer": spare_ptr,
        "looks_like_type_descriptor": plausible_pointer,
        "decorated_name_address": name_address,
        "decorated_name": decorated_name,
        "looks_like_target": decorated_name == TARGET_NAME.decode("ascii"),
    }


def parse_chd(regions: list[Region], chd_address: int, image_base: int) -> dict[str, Any] | None:
    loc = locate(regions, chd_address, 16)
    if loc is None:
        return None
    _, raw = loc
    signature, attributes, num_bases, base_array_rva = struct.unpack("<4I", raw)
    result: dict[str, Any] = {
        "address": chd_address,
        "signature": signature,
        "attributes": attributes,
        "num_base_classes": num_bases,
        "base_class_array_rva": base_array_rva,
        "base_class_array_address": image_base + base_array_rva,
        "base_classes": [],
    }
    # Defensive limits prevent implausible counts from triggering large loops.
    if num_bases == 0 or num_bases > 4096:
        result["base_array_status"] = "not walked: implausible base-class count"
        return result
    array_address = image_base + base_array_rva
    array_loc = locate(regions, array_address, num_bases * 4)
    if array_loc is None:
        result["base_array_status"] = "outside supplied captures"
        return result
    _, array_raw = array_loc
    for i in range(num_bases):
        bcd_rva = u32(array_raw, i * 4)
        bcd_address = image_base + bcd_rva
        bcd_loc = locate(regions, bcd_address, 28)
        entry: dict[str, Any] = {"index": i, "bcd_rva": bcd_rva, "bcd_address": bcd_address}
        if bcd_loc is not None:
            _, bcd = bcd_loc
            td_rva, contained, mdisp, pdisp, vdisp, flags, nested_chd_rva = struct.unpack("<7I", bcd)
            entry.update({
                "type_descriptor_rva": td_rva,
                "type_descriptor_address": image_base + td_rva,
                "contained_bases": contained,
                "pmd": {"mdisp": mdisp if mdisp < 0x80000000 else mdisp - 0x100000000,
                        "pdisp": pdisp if pdisp < 0x80000000 else pdisp - 0x100000000,
                        "vdisp": vdisp if vdisp < 0x80000000 else vdisp - 0x100000000},
                "attributes": flags,
                "nested_class_hierarchy_rva": nested_chd_rva,
            })
            td = parse_type_descriptor(regions, image_base + td_rva)
            if td:
                entry["type_name"] = td.get("decorated_name")
        else:
            entry["status"] = "base descriptor outside supplied captures"
        result["base_classes"].append(entry)
    result["base_array_status"] = "walked"
    return result


def analyze(regions: list[Region], vtable_address: int) -> dict[str, Any]:
    report: dict[str, Any] = {
        "tool": "ros64_runtime_rtti_v10",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target_name": TARGET_NAME.decode("ascii"),
        "regions": [],
        "type_name_hits": [],
        "type_descriptors": [],
        "candidate_col_addresses": [],
        "col_candidates": [],
        "vtable": {"address": vtable_address, "slots": []},
        "findings": [],
    }
    for r in regions:
        report["regions"].append({"name": r.name, "path": str(r.path), "base": r.base,
                                  "end_exclusive": r.end, "size": len(r.data),
                                  "sha256": hashlib.sha256(r.data).hexdigest()})

    # Search target name in every capture and derive the standard x64 TypeDescriptor
    # address as the decorated name address minus its 16-byte type_info prefix.
    for r in regions:
        for pos in scan_exact(r.data, TARGET_NAME):
            name_addr = r.base + pos
            td_addr = name_addr - 16
            hit = {"name_address": name_addr, "capture": r.name, "capture_offset": pos,
                   "candidate_type_descriptor_address": td_addr}
            report["type_name_hits"].append(hit)
            td = parse_type_descriptor(regions, td_addr)
            if td and td["looks_like_type_descriptor"]:
                report["type_descriptors"].append(td)
                if td["type_info_vftable_pointer"]:
                    report["findings"].append(
                        f"Found target TypeDescriptor at 0x{td_addr:X}; name captured in {r.name}."
                    )

    # Walk the vtable's preceding pointer to its COL and parse RVA fields.
    ptr_loc = locate(regions, vtable_address - 8, 8)
    col_ptr = None
    if ptr_loc:
        _, b = ptr_loc
        col_ptr = u64(b, 0)
        report["vtable"]["preceding_pointer_address"] = vtable_address - 8
        report["vtable"]["preceding_pointer_value"] = col_ptr
        report["vtable"]["preceding_pointer_region_status"] = classify_pointer(col_ptr, regions)
        report["candidate_col_addresses"].append(col_ptr)
    else:
        report["findings"].append("Vtable[-1] address is not inside the supplied vtable capture.")

    # Also scan aligned qwords for pointers into likely RTTI memory; record all
    # address-like references to the known type descriptor, where possible.
    td_addresses = {int(x["address"]) for x in report["type_descriptors"]}
    for r in regions:
        for off in range(0, max(0, len(r.data) - 7), 8):
            value = u64(r.data, off)
            if value in td_addresses:
                report.setdefault("type_descriptor_references", []).append(
                    {"capture": r.name, "address": r.base + off, "value": value}
                )

    for col_addr in dict.fromkeys(report["candidate_col_addresses"]):
        col = parse_col(regions, col_addr)
        if not col:
            report["col_candidates"].append({"address": col_addr, "status": "COL bytes outside supplied captures"})
            continue
        col["status"] = "parsed"
        expected_td = col.get("type_descriptor_address")
        col["type_descriptor_matches_target"] = expected_td in td_addresses if expected_td is not None else False
        if col.get("class_hierarchy_descriptor_address") is not None:
            col["class_hierarchy_descriptor"] = parse_chd(
                regions, col["class_hierarchy_descriptor_address"], col["inferred_image_base"]
            )
        report["col_candidates"].append(col)
        if col.get("signature") == 1:
            report["findings"].append(
                f"COL candidate at 0x{col_addr:X}; inferred image base {hexv(col.get('inferred_image_base'))}; "
                f"TypeDescriptor match={col.get('type_descriptor_matches_target')} ."
            )

    # Capture function pointers from the supplied vtable region. These values are
    # only addresses; this tool does not disassemble or call them.
    vtable_region = next((r for r in regions if r.contains(vtable_address, 8)), None)
    if vtable_region:
        available = min(64, (vtable_region.end - vtable_address) // 8)
        start = vtable_address - vtable_region.base
        for index in range(available):
            value = u64(vtable_region.data, start + index * 8)
            report["vtable"]["slots"].append({"index": index, "slot_address": vtable_address + index * 8,
                                              "function_pointer": value,
                                              "capture_status": classify_pointer(value, regions)})
    else:
        report["findings"].append("Vtable address is outside supplied vtable capture.")

    if not report["type_name_hits"]:
        report["findings"].append("Target decorated type name was not found in supplied capture bytes.")
    if report["type_name_hits"] and not report["col_candidates"]:
        report["findings"].append("Target name found, but no COL parsed; verify capture bases and that all files came from one process session.")
    if not report.get("type_descriptor_references"):
        report["findings"].append("No aligned qword references to the target TypeDescriptor found in supplied regions.")
    return report


def write_outputs(report: dict[str, Any], outdir: Path) -> tuple[Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "runtime_rtti_analysis.json"
    txt_path = outdir / "runtime_rtti_analysis.txt"
    csv_path = outdir / "vtable_slots.csv"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "ROS64 RUNTIME RTTI CAPTURE ANALYSIS V10",
        "=" * 78,
        f"Target decorated name: {report['target_name']}",
        "",
        "CAPTURE REGIONS",
    ]
    for r in report["regions"]:
        lines.append(f"- {r['name']}: base=0x{r['base']:X}, end=0x{r['end_exclusive']:X}, size={r['size']:,}, SHA256={r['sha256']}")
    lines += ["", f"Target-name hits: {len(report['type_name_hits'])}",
              f"TypeDescriptors parsed: {len(report['type_descriptors'])}",
              f"COL candidates: {len(report['col_candidates'])}",
              f"Vtable slots read: {len(report['vtable']['slots'])}", "", "FINDINGS"]
    lines.extend(f"- {item}" for item in report["findings"])
    lines += ["", "TYPE DESCRIPTORS"]
    for td in report["type_descriptors"]:
        lines.append(f"- TD 0x{td['address']:X}; type_info_vftable=0x{td['type_info_vftable_pointer']:X}; "
                     f"name={td.get('decorated_name')!r}")
    lines += ["", "COMPLETE OBJECT LOCATORS"]
    for col in report["col_candidates"]:
        if col.get("status") != "parsed":
            lines.append(f"- 0x{col['address']:X}: {col['status']}")
            continue
        lines.append(f"- COL 0x{col['address']:X}: signature={col['signature']}, offset=0x{col['offset']:X}, "
                     f"cdOffset=0x{col['cd_offset']:X}, imageBase={hexv(col.get('inferred_image_base'))}, "
                     f"TD={hexv(col.get('type_descriptor_address'))}, CHD={hexv(col.get('class_hierarchy_descriptor_address'))}, "
                     f"target-TD-match={col.get('type_descriptor_matches_target')}")
        chd = col.get("class_hierarchy_descriptor")
        if chd:
            lines.append(f"  CHD 0x{chd['address']:X}: signature={chd['signature']}, attributes=0x{chd['attributes']:X}, "
                         f"base-count={chd['num_base_classes']}, base-array={hexv(chd['base_class_array_address'])}, "
                         f"status={chd.get('base_array_status')}")
            for b in chd.get("base_classes", []):
                lines.append(f"    [{b['index']}] type={b.get('type_name', '<not captured>')} BCD={hexv(b['bcd_address'])}")
    with txt_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "slot_address", "function_pointer", "capture_status"])
        writer.writeheader()
        for slot in report["vtable"]["slots"]:
            writer.writerow({k: hexv(slot[k]) if k in ("slot_address", "function_pointer") else slot[k] for k in writer.fieldnames})
    return txt_path, json_path, csv_path


def synthetic_self_test() -> None:
    # Build the three regions with a synthetic x64 COL, TypeDescriptor, and table.
    type_base = 0x00000001428DD000
    vt_base = 0x0000000141C2A000
    name_base = 0x00000001431BB000
    col_addr = 0x00000001428DD1F8
    td_addr = 0x00000001428DD220
    name_addr = td_addr + 16
    image_base = 0x0000000140000000
    type_data = bytearray(0x2000)
    struct.pack_into("<6I", type_data, col_addr - type_base, 1, 0, 0,
                     td_addr - image_base, 0x2900000, col_addr - image_base)
    struct.pack_into("<QQ", type_data, td_addr - type_base, 0x40001000, 0)
    type_data[name_addr - type_base:name_addr - type_base + len(TARGET_NAME)] = TARGET_NAME
    name_data = bytearray(0x2000)
    name_offset = 0xE30  # mirrors 0x00000001431BBE30 from the investigation notes
    name_data[name_offset:name_offset + len(TARGET_NAME)] = TARGET_NAME
    vt_data = bytearray(0x2000)
    struct.pack_into("<Q", vt_data, 0x990 - 8, col_addr)
    struct.pack_into("<4Q", vt_data, 0x990, 0x404A3D40, 0x404AB480, 0x404AF270, 0x404AF320)
    regions = [Region("typeinfo", Path("typeinfo.bin"), type_base, bytes(type_data)),
               Region("vtable", Path("vtable.bin"), vt_base, bytes(vt_data)),
               Region("name", Path("name.bin"), name_base, bytes(name_data))]
    # Here the target string is intentionally also present in the separate name region;
    # TD itself is located and readable in typeinfo.
    r = analyze(regions, 0x0000000141C2A990)
    assert r["type_name_hits"]
    assert r["type_descriptors"] and r["type_descriptors"][0]["looks_like_target"]
    assert r["col_candidates"] and r["col_candidates"][0].get("signature") == 1
    assert r["col_candidates"][0].get("inferred_image_base") == image_base
    assert len(r["vtable"]["slots"]) == 64


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline analysis of WinDbg-exported ros64.exe RTTI memory regions")
    parser.add_argument("--typeinfo", type=Path, default=DEFAULT_TYPEINFO)
    parser.add_argument("--vtable", type=Path, default=DEFAULT_VTABLE)
    parser.add_argument("--name", type=Path, default=DEFAULT_NAME)
    parser.add_argument("--typeinfo-base", type=lambda x: int(x, 0), default=DEFAULT_TYPEINFO_BASE)
    parser.add_argument("--vtable-base", type=lambda x: int(x, 0), default=DEFAULT_VTABLE_BASE)
    parser.add_argument("--name-base", type=lambda x: int(x, 0), default=DEFAULT_NAME_BASE)
    parser.add_argument("--vtable-address", type=lambda x: int(x, 0), default=DEFAULT_VTABLE_ADDRESS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT / "analysis")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        try:
            synthetic_self_test()
        except Exception as exc:
            print(f"[FAIL] runtime RTTI chain analysis: {exc}", file=sys.stderr)
            return 1
        print("[PASS] captured TypeDescriptor target-name resolution")
        print("[PASS] MSVC x64 Complete Object Locator RVA reconstruction")
        print("[PASS] vtable[-1] COL linking and vtable slot survey")
        return 0
    try:
        regions = [
            load_region("typeinfo", args.typeinfo, args.typeinfo_base),
            load_region("vtable", args.vtable, args.vtable_base),
            load_region("name", args.name, args.name_base),
        ]
        report = analyze(regions, args.vtable_address)
        txt, js, csv_path = write_outputs(report, args.out)
        print("[COMPLETE] ROS64 runtime RTTI capture analysis v10 finished (offline only).")
        print(f"  Target-name hits: {len(report['type_name_hits'])}")
        print(f"  TypeDescriptors: {len(report['type_descriptors'])}")
        print(f"  COL candidates: {len(report['col_candidates'])}")
        print(f"  Vtable slots read: {len(report['vtable']['slots'])}")
        print(f"  Report: {txt}")
        print(f"  JSON: {js}")
        print(f"  Vtable CSV: {csv_path}")
        for finding in report["findings"]:
            print(f"  [NOTE] {finding}")
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
