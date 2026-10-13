#!/usr/bin/env python3
"""V11 offline analysis of MSVC x64 RTTI and adjacent vftables in ROS64.

Reads only WinDbg .writemem captures. It does not attach to or execute the target.
Compared with V10, this version can ingest a lower hierarchy capture to resolve
base-class descriptors outside the original 0x1428DD000 capture, and it detects
Complete Object Locator (COL) pointers embedded between adjacent vftables so
metadata markers are not misreported as virtual-function slots.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TYPEINFO = Path(r"recon_out_v10\ModelFxData_typeinfo.bin")
DEFAULT_HIERARCHY = Path(r"recon_out_v11\ModelFxData_hierarchy.bin")
DEFAULT_VTABLE = Path(r"recon_out_v10\ModelFxData_vtable.bin")
DEFAULT_NAME = Path(r"recon_out_v10\ModelFxData_name.bin")
DEFAULT_OUT = Path(r"recon_out_v11\analysis")
DEFAULT_TYPEINFO_BASE = 0x00000001428DD000
DEFAULT_HIERARCHY_BASE = 0x00000001428DC000
DEFAULT_VTABLE_BASE = 0x0000000141C2A000
DEFAULT_NAME_BASE = 0x00000001431BB000
DEFAULT_VTABLE_ADDRESS = 0x0000000141C2A990
TARGET_NAME = ".?AVModelFxData@world@neox@@"
MAX_REGION = 64 * 1024 * 1024
NAME_RE = re.compile(r"^\.\?A(?:V|U|W4|T).+?@@$")


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


def signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


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


def load_region(name: str, path: Path, base: int) -> Region:
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {name} capture: {path}\n"
            "Export it from the same WinDbg process session before analysis."
        )
    size = path.stat().st_size
    if size <= 0 or size > MAX_REGION:
        raise ValueError(f"{name} capture has unexpected size {size:,} bytes (limit {MAX_REGION:,})")
    return Region(name, path, base, path.read_bytes())


def locate(regions: list[Region], address: int, size: int = 1) -> tuple[Region, bytes] | None:
    # Overlapping captures may be supplied. Prefer the more specific hierarchy
    # capture, whose bytes cover the previously missing lower memory as well as
    # the start of the V10 typeinfo region.
    for region in regions:
        raw = region.read(address, size)
        if raw is not None:
            return region, raw
    return None


def cstring_in_regions(regions: list[Region], address: int, limit: int = 4096) -> str | None:
    loc = locate(regions, address, 1)
    if not loc:
        return None
    region, _ = loc
    offset = address - region.base
    end = region.data.find(b"\0", offset, min(len(region.data), offset + limit))
    if end < 0:
        return None
    raw = region.data[offset:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.decode("ascii", errors="replace")


def parse_type_descriptor(regions: list[Region], address: int) -> dict[str, Any] | None:
    loc = locate(regions, address, 16)
    if not loc:
        return None
    _, raw = loc
    name_address = address + 16
    name = cstring_in_regions(regions, name_address)
    vftable_ptr = u64(raw, 0)
    spare_ptr = u64(raw, 8)
    plausible_pointer = 0x10000 <= vftable_ptr <= 0x00007FFFFFFFFFFF
    return {
        "address": address,
        "type_info_vftable_pointer": vftable_ptr,
        "spare_pointer": spare_ptr,
        "decorated_name_address": name_address,
        "decorated_name": name,
        "looks_like_type_descriptor": plausible_pointer and bool(name and NAME_RE.match(name)),
    }


def parse_col(regions: list[Region], col_address: int) -> dict[str, Any] | None:
    loc = locate(regions, col_address, 24)
    if not loc:
        return None
    _, raw = loc
    signature, offset, cd_offset, td_rva, chd_rva, self_rva = struct.unpack("<6I", raw)
    result: dict[str, Any] = {
        "address": col_address, "signature": signature, "offset": offset,
        "cd_offset": cd_offset, "type_descriptor_rva": td_rva,
        "class_hierarchy_descriptor_rva": chd_rva, "self_rva": self_rva,
        "layout": "MSVC x64 RVA-style COL" if signature == 1 else "unconfirmed COL layout",
    }
    if signature != 1 or self_rva == 0:
        return result
    image_base = col_address - self_rva
    td_address = image_base + td_rva
    chd_address = image_base + chd_rva
    td = parse_type_descriptor(regions, td_address)
    result.update({
        "inferred_image_base": image_base,
        "type_descriptor_address": td_address,
        "class_hierarchy_descriptor_address": chd_address,
        "self_rva_matches_address": image_base + self_rva == col_address,
        "type_descriptor": td,
        "type_name": td.get("decorated_name") if td else None,
        "valid_type_descriptor": bool(td and td.get("looks_like_type_descriptor")),
    })
    return result


def parse_chd(regions: list[Region], chd_address: int, image_base: int) -> dict[str, Any] | None:
    loc = locate(regions, chd_address, 16)
    if not loc:
        return None
    _, raw = loc
    signature, attributes, count, array_rva = struct.unpack("<4I", raw)
    out: dict[str, Any] = {
        "address": chd_address, "signature": signature, "attributes": attributes,
        "num_base_classes": count, "base_class_array_rva": array_rva,
        "base_class_array_address": image_base + array_rva, "base_classes": [],
    }
    if count == 0 or count > 4096:
        out["base_array_status"] = "not walked: implausible base-class count"
        return out
    array_loc = locate(regions, image_base + array_rva, count * 4)
    if not array_loc:
        out["base_array_status"] = "base-class pointer array outside supplied captures"
        return out
    _, array_raw = array_loc
    for i in range(count):
        bcd_rva = u32(array_raw, 4 * i)
        bcd_address = image_base + bcd_rva
        entry: dict[str, Any] = {"index": i, "bcd_rva": bcd_rva, "bcd_address": bcd_address}
        bcd_loc = locate(regions, bcd_address, 28)
        if not bcd_loc:
            entry["status"] = "base descriptor outside supplied captures"
            out["base_classes"].append(entry)
            continue
        _, bcd_raw = bcd_loc
        td_rva, contained, mdisp, pdisp, vdisp, flags, nested_chd_rva = struct.unpack("<7I", bcd_raw)
        td_address = image_base + td_rva
        td = parse_type_descriptor(regions, td_address)
        entry.update({
            "type_descriptor_rva": td_rva, "type_descriptor_address": td_address,
            "contained_bases": contained,
            "pmd": {"mdisp": signed32(mdisp), "pdisp": signed32(pdisp), "vdisp": signed32(vdisp)},
            "attributes": flags, "nested_class_hierarchy_rva": nested_chd_rva,
            "type_name": td.get("decorated_name") if td else None,
        })
        if td and not td.get("looks_like_type_descriptor"):
            entry["type_descriptor_note"] = "descriptor header/name did not pass heuristic validation"
        out["base_classes"].append(entry)
    out["base_array_status"] = "walked"
    return out


def candidate_col(regions: list[Region], address: int, expected_image_base: int = 0x0000000140000000) -> dict[str, Any] | None:
    col = parse_col(regions, address)
    if not col or col.get("signature") != 1:
        return None
    if not col.get("self_rva_matches_address") or col.get("inferred_image_base") != expected_image_base:
        return None
    # Type names are useful but not required: some adjacent descriptors may point
    # to TypeDescriptors outside the small name capture. Validate the CHD as well.
    td_addr = col.get("type_descriptor_address")
    chd_addr = col.get("class_hierarchy_descriptor_address")
    if not isinstance(td_addr, int) or not (expected_image_base <= td_addr < expected_image_base + 0x10000000):
        return None
    if not isinstance(chd_addr, int) or not (expected_image_base <= chd_addr < expected_image_base + 0x10000000):
        return None
    chd = parse_chd(regions, chd_addr, expected_image_base)
    if not chd or chd.get("signature") != 0 or not (1 <= chd.get("num_base_classes", 0) <= 4096):
        return None
    if chd.get("base_array_status") != "walked":
        return None
    col["class_hierarchy_descriptor"] = chd
    return col


def analyze(regions: list[Region], vtable_address: int, max_slots: int = 1024) -> dict[str, Any]:
    report: dict[str, Any] = {
        "tool": "ros64_runtime_rtti_v11", "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target_name": TARGET_NAME, "regions": [], "target_type_descriptor": None,
        "initial_col": None, "col_candidates": [], "vtable_groups": [], "vtable_slots": [],
        "selected_target_vtable": None, "findings": [],
    }
    for r in regions:
        report["regions"].append({"name": r.name, "path": str(r.path), "base": r.base,
                                  "end_exclusive": r.end, "size": len(r.data),
                                  "sha256": hashlib.sha256(r.data).hexdigest()})

    # Resolve the known target TypeDescriptor from its decorated name.
    target_td = None
    for r in regions:
        for m in re.finditer(re.escape(TARGET_NAME.encode("ascii")), r.data):
            td_addr = r.base + m.start() - 16
            td = parse_type_descriptor(regions, td_addr)
            if td and td.get("looks_like_type_descriptor") and td.get("decorated_name") == TARGET_NAME:
                target_td = td
                break
        if target_td:
            break
    report["target_type_descriptor"] = target_td
    if target_td:
        report["findings"].append(f"Target TypeDescriptor resolved at 0x{target_td['address']:X}.")
    else:
        report["findings"].append("Target TypeDescriptor not resolved; verify the same-session name capture and capture bases.")

    # vtable[-1] points to the COL for the selected table.
    prev = locate(regions, vtable_address - 8, 8)
    initial_col = None
    if prev:
        _, raw = prev
        initial_col = candidate_col(regions, u64(raw, 0))
    report["initial_col"] = initial_col
    if initial_col:
        report["findings"].append(
            f"Selected vftable COL at 0x{initial_col['address']:X} resolves class {initial_col.get('type_name')}; "
            f"inferred image base 0x{initial_col.get('inferred_image_base'):X}."
        )
    else:
        report["findings"].append("Selected vtable[-1] did not resolve to a validated COL.")

    vtable_region = next((r for r in regions if r.name == "vtable" and r.contains(vtable_address, 8)), None)
    if not vtable_region:
        report["findings"].append("Selected vftable address is outside the vtable capture.")
        return report

    qwords_available = len(vtable_region.data) // 8
    scan_count = min(max_slots, qwords_available)
    markers: dict[int, dict[str, Any]] = {}
    col_by_addr: dict[int, dict[str, Any]] = {}
    for idx in range(scan_count):
        value = u64(vtable_region.data, idx * 8)
        # Only qwords that point to a self-consistent COL are metadata markers.
        candidate = candidate_col(regions, value)
        if candidate:
            markers[idx] = candidate
            col_by_addr[candidate["address"]] = candidate

    report["col_candidates"] = sorted(col_by_addr.values(), key=lambda c: c["address"])
    # In an MSVC vftable array, a COL pointer is immediately before the first
    # function pointer. Adjacent vftables appear as [COL, function*, ...][COL,
    # function*, ...]. Build groups from each marker through the qword before the
    # next validated COL marker. This also captures vftables preceding the target.
    marker_indices = sorted(markers)
    for marker_pos, marker_idx in enumerate(marker_indices):
        next_idx = marker_indices[marker_pos + 1] if marker_pos + 1 < len(marker_indices) else scan_count
        start_idx = marker_idx + 1
        if start_idx >= next_idx:
            continue
        slots = []
        for idx in range(start_idx, next_idx):
            value = u64(vtable_region.data, idx * 8)
            slots.append({"index_in_capture": idx,
                          "slot_address": vtable_region.base + idx * 8,
                          "function_pointer": value})
        table_address = vtable_region.base + start_idx * 8
        is_target = table_address == vtable_address and initial_col is not None and markers[marker_idx]["address"] == initial_col["address"]
        group = {
            "group_index": len(report["vtable_groups"]),
            "class_name": markers[marker_idx].get("type_name"),
            "col_address": markers[marker_idx]["address"],
            "vtable_address": table_address,
            "first_capture_slot_index": start_idx,
            "function_count": len(slots),
            "function_slots": slots,
            "next_col_marker_index": next_idx if next_idx < scan_count else None,
            "next_col_address": markers[next_idx]["address"] if next_idx in markers else None,
            "is_selected_target": is_target,
        }
        report["vtable_groups"].append(group)
        if is_target:
            report["selected_target_vtable"] = {k: group[k] for k in
                ("group_index", "class_name", "col_address", "vtable_address", "function_count", "is_selected_target")}

    for idx in range(scan_count):
        value = u64(vtable_region.data, idx * 8)
        marker = markers.get(idx)
        report["vtable_slots"].append({
            "index_in_capture": idx,
            "slot_address": vtable_region.base + idx * 8,
            "value": value,
            "role": "COL pointer / vftable boundary" if marker else "function pointer or other qword",
            "class_name_from_col": marker.get("type_name") if marker else None,
        })

    selected_found = report.get("selected_target_vtable") is not None
    report["findings"].append(
        f"Scanned {scan_count} qwords across the full supplied vtable capture; detected {len(markers)} validated COL markers "
        f"and segmented {len(report['vtable_groups'])} adjacent vftable groups."
    )
    if selected_found:
        group = next(g for g in report["vtable_groups"] if g["is_selected_target"])
        report["findings"].append(
            f"Target vftable segmented as group {group['group_index']} with {group['function_count']} function-pointer entries; "
            "COL marker qwords are excluded from function slots."
        )
    else:
        report["findings"].append("The selected vftable was not matched to a segmented group; check capture alignment and session consistency.")
    if initial_col and initial_col.get("class_hierarchy_descriptor"):
        chd = initial_col["class_hierarchy_descriptor"]
        unresolved = [b for b in chd.get("base_classes", []) if b.get("status") == "base descriptor outside supplied captures"]
        if unresolved:
            report["findings"].append(
                f"{len(unresolved)} base-class descriptor(s) remain outside captures; ensure the lower hierarchy capture includes address 0x1428DCD20."
            )
    return report


def write_outputs(report: dict[str, Any], outdir: Path) -> tuple[Path, Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "runtime_rtti_analysis.json"
    txt_path = outdir / "runtime_rtti_analysis.txt"
    slots_path = outdir / "vtable_slots.csv"
    groups_path = outdir / "vtable_groups.csv"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "ROS64 RUNTIME RTTI AND ADJACENT VFTABLE ANALYSIS V11", "=" * 78,
        f"Target decorated name: {report['target_name']}", "", "CAPTURE REGIONS",
    ]
    for r in report["regions"]:
        lines.append(f"- {r['name']}: 0x{r['base']:X}-0x{r['end_exclusive'] - 1:X}; size={r['size']:,}; SHA256={r['sha256']}")
    lines += ["", "FINDINGS"] + [f"- {x}" for x in report["findings"]]
    lines += ["", "INITIAL VFTABLE / TYPE HIERARCHY"]
    col = report.get("initial_col")
    if col:
        lines.append(f"- COL 0x{col['address']:X}; class={col.get('type_name')}; image base={hexv(col.get('inferred_image_base'))}")
        chd = col.get("class_hierarchy_descriptor")
        if chd:
            lines.append(f"  CHD 0x{chd['address']:X}; base count={chd['num_base_classes']}; status={chd.get('base_array_status')}")
            for b in chd.get("base_classes", []):
                lines.append(f"    [{b['index']}] {b.get('type_name', '<unresolved>')} BCD=0x{b['bcd_address']:X}"
                             + (f" ({b['status']})" if b.get("status") else ""))
    else:
        lines.append("- Initial COL was not validated.")
    lines += ["", "ADJACENT VFTABLE GROUPS"]
    for g in report["vtable_groups"]:
        lines.append(f"- Group {g['group_index']}: {g.get('class_name') or '<unknown>'}; vftable=0x{g['vtable_address']:X}; "
                     f"functions={g['function_count']}; COL={hexv(g.get('col_address'))}" + (" [TARGET]" if g.get("is_selected_target") else ""))
        for s in g["function_slots"][:12]:
            lines.append(f"    [{s.get('index', s.get('index_in_capture', '?'))}] 0x{s['slot_address']:X} -> 0x{s['function_pointer']:X}")
        if len(g["function_slots"]) > 12:
            lines.append(f"    ... {len(g['function_slots']) - 12} additional function pointers in this group")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with slots_path.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["index_in_capture", "slot_address", "value", "role", "class_name_from_col"]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for row in report["vtable_slots"]:
            w.writerow({**row, "slot_address": hexv(row["slot_address"]), "value": hexv(row["value"])})
    with groups_path.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["group_index", "class_name", "col_address", "vtable_address", "first_capture_slot_index", "function_count", "next_col_marker_index", "next_col_address", "is_selected_target", "function_addresses"]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for g in report["vtable_groups"]:
            w.writerow({"group_index": g["group_index"], "class_name": g.get("class_name"),
                        "col_address": hexv(g.get("col_address")), "vtable_address": hexv(g["vtable_address"]),
                        "first_capture_slot_index": g["first_capture_slot_index"], "function_count": g["function_count"], "is_selected_target": g.get("is_selected_target", False),
                        "next_col_marker_index": g.get("next_col_marker_index"), "next_col_address": hexv(g.get("next_col_address")),
                        "function_addresses": ";".join(hexv(s["function_pointer"]) or "" for s in g["function_slots"])})
    return txt_path, json_path, slots_path, groups_path


def synthetic_self_test() -> None:
    image_base = 0x0000000140000000
    type_base = 0x00000001428DC000
    vt_base = 0x0000000141C2A000
    name_base = 0x00000001431BB000
    type_data = bytearray(0x2000)
    vt_data = bytearray(0x2000)
    name_data = bytearray(0x2000)

    # Two TypeDescriptors in the name capture.
    td1, td2 = name_base + 0xE20, name_base + 0xE50
    for addr, s in [(td1, TARGET_NAME), (td2, ".?AVVegCollisionSfxData@world@neox@@")]:
        struct.pack_into("<QQ", name_data, addr - name_base, 0x000000014289D630, 0)
        off = addr - name_base + 16
        name_data[off:off + len(s)] = s.encode("ascii")

    # ModelFxData CHD with two base descriptors: self and a captured base type.
    col1, chd1, array1, bcd1 = type_base + 0x11F8, type_base + 0x1220, type_base + 0x1238, type_base + 0x1250
    bcd_parent = type_base + 0xD20
    parent_td = name_base + 0xE88
    struct.pack_into("<QQ", name_data, parent_td - name_base, 0x000000014289D630, 0)
    parent_name = ".?AVBaseFxData@world@neox@@".encode("ascii")
    name_data[parent_td - name_base + 16:parent_td - name_base + 16 + len(parent_name)] = parent_name
    struct.pack_into("<6I", type_data, col1 - type_base, 1, 0, 0, td1 - image_base, chd1 - image_base, col1 - image_base)
    struct.pack_into("<4I", type_data, chd1 - type_base, 0, 0, 2, array1 - image_base)
    struct.pack_into("<2I", type_data, array1 - type_base, bcd1 - image_base, bcd_parent - image_base)
    struct.pack_into("<7I", type_data, bcd1 - type_base, td1 - image_base, 1, 0, 0xFFFFFFFF, 0, 0x40, chd1 - image_base)
    struct.pack_into("<7I", type_data, bcd_parent - type_base, parent_td - image_base, 0, 0, 0xFFFFFFFF, 0, 0x40, chd1 - image_base)

    # Second COL points to the second type and begins after two function slots.
    col2, chd2, array2, bcd2 = type_base + 0x1278, type_base + 0x12A0, type_base + 0x12B8, type_base + 0x12C0
    struct.pack_into("<6I", type_data, col2 - type_base, 1, 0, 0, td2 - image_base, chd2 - image_base, col2 - image_base)
    struct.pack_into("<4I", type_data, chd2 - type_base, 0, 0, 1, array2 - image_base)
    struct.pack_into("<I", type_data, array2 - type_base, bcd2 - image_base)
    struct.pack_into("<7I", type_data, bcd2 - type_base, td2 - image_base, 1, 0, 0xFFFFFFFF, 0, 0x40, chd2 - image_base)

    vtable_address = vt_base + 0x990
    struct.pack_into("<Q", vt_data, 0x988, col1)
    struct.pack_into("<3Q", vt_data, 0x990, 0x0000000140100000, 0x0000000140100010, col2)
    struct.pack_into("<3Q", vt_data, 0x9A8, 0x0000000140100020, 0x0000000140100030, 0x0000000140100040)
    regions = [Region("hierarchy", Path("hierarchy.bin"), type_base, bytes(type_data)),
               Region("vtable", Path("vtable.bin"), vt_base, bytes(vt_data)),
               Region("name", Path("name.bin"), name_base, bytes(name_data))]
    report = analyze(regions, vtable_address, max_slots=1024)
    assert report["target_type_descriptor"] and report["target_type_descriptor"]["address"] == td1, ("target td", report["target_type_descriptor"])
    assert report["initial_col"] and report["initial_col"]["type_name"] == TARGET_NAME, ("initial col", report["initial_col"])
    chd = report["initial_col"]["class_hierarchy_descriptor"]
    assert chd and len(chd["base_classes"]) == 2, ("chd", chd)
    assert chd["base_classes"][1].get("type_name") == ".?AVBaseFxData@world@neox@@", ("parent", chd["base_classes"][1])
    assert report["vtable_groups"] and any(g["function_count"] == 2 and g["is_selected_target"] for g in report["vtable_groups"]), ("groups", report["vtable_groups"])
    assert any(g["class_name"] == ".?AVVegCollisionSfxData@world@neox@@" for g in report["vtable_groups"]), ("groups2", report["vtable_groups"])

    # Regression: report generation must accept index_in_capture (the schema used
    # by analyze()) and must not fail on extra keys when writing the slot CSV.
    with tempfile.TemporaryDirectory(prefix="ros64_v11_report_test_") as temp_dir:
        output_paths = write_outputs(report, Path(temp_dir))
        assert len(output_paths) == 4 and all(p.is_file() and p.stat().st_size > 0 for p in output_paths), (
            "report writer", [str(p) for p in output_paths]
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline MSVC x64 RTTI and adjacent-vftable survey from WinDbg captures")
    parser.add_argument("--typeinfo", type=Path, default=DEFAULT_TYPEINFO)
    parser.add_argument("--hierarchy", type=Path, default=DEFAULT_HIERARCHY)
    parser.add_argument("--vtable", type=Path, default=DEFAULT_VTABLE)
    parser.add_argument("--name", type=Path, default=DEFAULT_NAME)
    parser.add_argument("--typeinfo-base", type=lambda x: int(x, 0), default=DEFAULT_TYPEINFO_BASE)
    parser.add_argument("--hierarchy-base", type=lambda x: int(x, 0), default=DEFAULT_HIERARCHY_BASE)
    parser.add_argument("--vtable-base", type=lambda x: int(x, 0), default=DEFAULT_VTABLE_BASE)
    parser.add_argument("--name-base", type=lambda x: int(x, 0), default=DEFAULT_NAME_BASE)
    parser.add_argument("--vtable-address", type=lambda x: int(x, 0), default=DEFAULT_VTABLE_ADDRESS)
    parser.add_argument("--max-slots", type=int, default=1024, help="maximum qword slots scanned from the beginning of the supplied vtable capture")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.max_slots < 1 or args.max_slots > 8192:
        print("[ERROR] --max-slots must be between 1 and 8192", file=sys.stderr)
        return 2
    if args.self_test:
        try:
            synthetic_self_test()
        except Exception as exc:
            print(f"[FAIL] V11 synthetic tests: {exc}", file=sys.stderr)
            return 1
        print("[PASS] MSVC x64 COL and image-base reconstruction")
        print("[PASS] class hierarchy and parent BCD resolution")
        print("[PASS] adjacent vftable COL-marker segmentation")
        print("[PASS] selected vftable identified within full capture")
        print("[PASS] report text/JSON/CSV generation and schema consistency")
        return 0
    try:
        # Order matters for overlapping captures: hierarchy is checked first.
        regions = [
            load_region("hierarchy", args.hierarchy, args.hierarchy_base),
            load_region("typeinfo", args.typeinfo, args.typeinfo_base),
            load_region("vtable", args.vtable, args.vtable_base),
            load_region("name", args.name, args.name_base),
        ]
        report = analyze(regions, args.vtable_address, args.max_slots)
        txt, js, slots, groups = write_outputs(report, args.out)
        print("[COMPLETE] ROS64 runtime RTTI + adjacent vftable analysis v11 finished (offline only).")
        print(f"  Target TypeDescriptor: {hexv(report['target_type_descriptor']['address']) if report.get('target_type_descriptor') else 'not resolved'}")
        initial = report.get("initial_col")
        if initial:
            chd = initial.get("class_hierarchy_descriptor") or {}
            print(f"  Initial class: {initial.get('type_name')}; base descriptors={chd.get('num_base_classes', 0)}")
            for b in chd.get("base_classes", []):
                print(f"    [{b['index']}] {b.get('type_name', '<unresolved>')} at {hexv(b['bcd_address'])}")
        print(f"  Validated adjacent COL markers: {len(report['col_candidates'])}")
        print(f"  Vftable groups segmented: {len(report['vtable_groups'])}")
        print(f"  Qword slots surveyed: {len(report['vtable_slots'])}")
        print(f"  Report: {txt}")
        print(f"  JSON: {js}")
        print(f"  Slot CSV: {slots}")
        print(f"  Group CSV: {groups}")
        for finding in report["findings"]:
            print(f"  [NOTE] {finding}")
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
