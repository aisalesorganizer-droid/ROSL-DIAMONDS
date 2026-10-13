#!/usr/bin/env python3
"""
=============================================================================
  ROSLegacy NSIS Recon v2
  Fixes : 7z cannot see the nsisbin (named .nsisbin, not .bin)
  Adds  : .bin alias unlock │ NSIS [0] script decode │ PE/magic scanner
           raw-offset extractor │ deep string scan
=============================================================================

Root-cause (v1 gap)
-------------------
  7z's NSIS plugin looks for  <stem>.bin  as the external data file.
  Our payload is named  .nsisbin  — so 7z never reads the 7.7 GB.
  --unlock creates a hardlink  <stem>.bin → .nsisbin  (no copy, no disk use)
  and immediately re-runs the inventory.

New modes
---------
  --unlock            Create .bin alias and re-run file listing
  --decode-nsis       Extract [0] bytecode block, dump all string table entries
                      (reveals install paths, registry keys, ExecWait commands,
                       update URLs — even before touching the nsisbin)
  --scan-nsisbin      Raw byte scan of nsisbin for interesting pattern strings
                      (works on NSIS-LZMA blocks that happen to be uncompressed,
                       or on uncompressed file entries like SetCompress-off PEs)
  --find-pe           Scan nsisbin for valid MZ/PE headers (uncompressed exes
                      stored with SetCompress off — usually includes the launcher)
  --extract-offset    Pull raw bytes at a known offset from the nsisbin
                      (use offsets from --find-pe to carve the launcher binary)
  --cleanup-alias     Remove the .bin hardlink created by --unlock

All v1 modes are preserved unchanged.

Usage
-----
  # Step 1 — unlock the nsisbin (one-time setup)
  python nsis_recon_v2.py --unlock --out .\\recon_out

  # Step 2 — decode the install script (fast, reveals all file paths & URLs)
  python nsis_recon_v2.py --decode-nsis --out .\\recon_out

  # Step 3 — find embedded executables in the nsisbin (finds launcher binary)
  python nsis_recon_v2.py --find-pe --out .\\recon_out

  # Step 4 — extract the launcher at the offset --find-pe reports
  python nsis_recon_v2.py --extract-offset 12345678 --out .\\recon_out

  # Step 5 — full config extraction now that the nsisbin is visible
  python nsis_recon_v2.py --extract-configs --out .\\recon_out

  # Raw string scan of the nsisbin (slower, skip if --decode-nsis gets the URLs)
  python nsis_recon_v2.py --scan-nsisbin --out .\\recon_out

Requirements
------------
  Python 3.8+
  7-Zip (7z.exe)
  .exe and .nsisbin in the same directory
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

# ─── CONFIG ──────────────────────────────────────────────────────────────────

DEFAULT_DIR = Path(r"C:\Users\MAFIA\Downloads\Compressed\ROSLegacy\Diamonds")
EXE_NAME    = "ROSLegacy_Install_202609251811.exe"
BIN_NAME    = "ROSLegacy_Install_202609251811.nsisbin"
DEFAULT_OUT = Path("recon_out")

RECON_EXTENSIONS = {
    "config":  {".json", ".ini", ".cfg", ".yaml", ".yml", ".xml", ".toml", ".env"},
    "script":  {".lua", ".py", ".js", ".ts", ".cs", ".nsi", ".nsh", ".bat", ".cmd"},
    "text":    {".txt", ".log", ".md", ".rtf", ".csv"},
    "exec":    {".exe", ".dll", ".so", ".pyd"},
    "data":    {".dat", ".bin", ".pak", ".db", ".sqlite", ".ldb"},
    "assets":  {".png", ".jpg", ".dds", ".tga", ".ogg", ".wav", ".mp3",
                ".fbx", ".obj", ".mesh", ".unity3d"},
    "archive": {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"},
}
ALL_RECON = {ext for exts in RECON_EXTENSIONS.values() for ext in exts}

# Patterns for game-relevant strings
INTERESTING_PATTERNS = [
    r"https?://[^\s\"'<>]{4,}",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r":[0-9]{4,5}\b",
    r"(server|host|endpoint|api|url|domain)\s*[=:]\s*\S+",
    r"(password|passwd|secret|token|key)\s*[=:]\s*\S+",
    r"(update|patch|manifest|version)[_\-]?[uUrRlL]{2,}",
    r"(game|world|zone|map|region)\s*\d+",
    r"mythgames?[^\s\"'<>]{0,50}",       # developer domain
    r"miraelabs?[^\s\"'<>]{0,50}",       # publisher domain
    r"kamoteworks?[^\s\"'<>]{0,50}",     # dev team domain
    r"roslega[^\s\"'<>]{0,50}",          # game name fragments
]

# File magic signatures to scan for in the nsisbin
FILE_MAGIC = {
    b"MZ":              "PE Executable (.exe/.dll)",
    b"PK\x03\x04":     "ZIP Archive",
    b"\x1f\x8b":       "GZip",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"Rar!\x1a\x07":   "RAR Archive",
    b"RIFF":           "RIFF (WAV/AVI/ANI)",
    b"\x89PNG\r\n":    "PNG Image",
    b"OggS":           "OGG Audio/Video",
    b"fLaC":           "FLAC Audio",
    b"ID3":            "MP3 (ID3 tag)",
    b"\xff\xfb":       "MP3 (sync frame)",
    b"MDMP":           "Minidump",
    b"BMSF":           "Valve BSP (map)",
    b"VBSP":           "Valve BSP v21+",
    b"SQLite format":  "SQLite Database",
}

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def find_7z() -> Path:
    for c in ["7z.exe",
              r"C:\Program Files\7-Zip\7z.exe",
              r"C:\Program Files (x86)\7-Zip\7z.exe"]:
        try:
            r = subprocess.run([c, "--help"], capture_output=True)
            if r.returncode == 0:
                return Path(c)
        except FileNotFoundError:
            continue
    return None


def run_7z(sevenz: Path, args: list) -> subprocess.CompletedProcess:
    cmd = [str(sevenz)] + args
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def parse_7z_list(raw: str) -> list:
    files, in_table, sep = [], False, 0
    for line in raw.splitlines():
        if line.startswith("---"):
            sep += 1
            in_table = (sep == 1)
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            files.append({
                "date": parts[0], "time": parts[1], "attr": parts[2],
                "size": int(parts[3]),
                "compressed": int(parts[4]) if parts[4].isdigit() else 0,
                "name": " ".join(parts[5:]),
            })
        except (ValueError, IndexError):
            continue
    return files


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def classify(name: str) -> str:
    ext = Path(name).suffix.lower()
    for cat, exts in RECON_EXTENSIONS.items():
        if ext in exts:
            return cat
    return "other"


def scan_strings(path: Path, patterns: list) -> list:
    hits = []
    compiled = [(p, re.compile(p.encode(), re.IGNORECASE)) for p in patterns]
    with open(path, "rb") as f:
        overlap = b""
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            data = overlap + chunk
            for label, rx in compiled:
                for m in rx.finditer(data):
                    val = m.group().decode("utf-8", errors="replace").strip()
                    if 4 < len(val) < 300:
                        hits.append((label, val))
            overlap = chunk[-256:]
    return hits


def print_inventory(files: list):
    total = sum(f["size"] for f in files)
    by_cat = defaultdict(lambda: {"count": 0, "size": 0})
    for f in files:
        cat = classify(f["name"])
        by_cat[cat]["count"] += 1
        by_cat[cat]["size"] += f["size"]

    print(f"\n{'='*70}")
    print(f"  INVENTORY  —  {len(files)} files  /  {human_size(total)} total")
    print(f"{'='*70}")
    print(f"  {'Category':<12} {'Files':>6}  {'Size':>12}")
    print(f"  {'-'*34}")
    for cat, info in sorted(by_cat.items()):
        print(f"  {cat:<12} {info['count']:>6}  {human_size(info['size']):>12}")
    print(f"{'='*70}\n")
    print(f"  {'Size':>12}  Name")
    print(f"  {'-'*60}")
    for f in sorted(files, key=lambda x: -x["size"])[:60]:
        print(f"  {human_size(f['size']):>12}  {f['name']}")
    if len(files) > 60:
        print(f"  ... and {len(files)-60} more (see inventory_full.json)")

# ─── V1 MODES (preserved) ────────────────────────────────────────────────────

def cmd_list(exe: Path, sevenz: Path) -> list:
    print(f"\n[LIST] Scanning {exe.name} …")
    r = run_7z(sevenz, ["l", str(exe)])
    if r.returncode != 0:
        print(f"  [ERROR] 7z failed:\n{r.stderr[:400]}")
        sys.exit(1)
    files = parse_7z_list(r.stdout)
    print_inventory(files)
    return files


def cmd_extract_configs(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    print(f"\n[EXTRACT-CONFIGS] Target: {exe.name}")
    files = parse_7z_list(run_7z(sevenz, ["l", str(exe)]).stdout)
    targets = [f["name"] for f in files
               if Path(f["name"]).suffix.lower() in
               RECON_EXTENSIONS["config"] | RECON_EXTENSIONS["script"] | RECON_EXTENSIONS["text"]]
    if not targets:
        print("  No config/script/text files found in inventory.")
        return
    print(f"  {len(targets)} config/script/text files found.")
    if dry_run:
        for t in targets:
            print(f"    [DRY] {t}")
        return
    out.mkdir(parents=True, exist_ok=True)
    for t in targets:
        r = run_7z(sevenz, ["e", str(exe), t, f"-o{out}", "-y"])
        state = "OK" if r.returncode == 0 else "FAIL"
        print(f"  [{state}] {t}")


def cmd_extract_file(exe: Path, sevenz: Path, target_path: str, out: Path, dry_run: bool):
    if dry_run:
        print(f"\n  [DRY RUN] Would extract: {target_path}")
        return
    out.mkdir(parents=True, exist_ok=True)
    r = run_7z(sevenz, ["e", str(exe), target_path, f"-o{out}", "-y"])
    extracted = out / Path(target_path).name
    if r.returncode == 0 and extracted.exists():
        print(f"\n  Extracted: {extracted}  ({human_size(extracted.stat().st_size)})")
    else:
        print(f"\n  [FAIL] File not found in archive or 7z error:\n{r.stderr[:300]}")
        print("  Hint: run --unlock first so 7z can see the nsisbin content.")


def cmd_extract_all(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    if dry_run:
        print(f"\n  [DRY RUN] Would extract all to: {out}")
        return
    print(f"\n[EXTRACT-ALL] Destination: {out}")
    print("  WARNING: 7.7 GB+ — will take a very long time.")
    out.mkdir(parents=True, exist_ok=True)
    r = run_7z(sevenz, ["x", str(exe), f"-o{out}", "-y"])
    print("  Done." if r.returncode == 0 else f"  FAIL:\n{r.stderr[:400]}")


def cmd_strings_v1(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    print("\n[STRINGS] Phase 1 — extract text files …")
    if not dry_run:
        cmd_extract_configs(exe, sevenz, out / "configs", dry_run=False)
    print("\n[STRINGS] Phase 2 — raw string scan of EXE …")
    hits = scan_strings(exe, INTERESTING_PATTERNS)
    if (out / "configs").exists():
        print("[STRINGS] Phase 3 — scan extracted configs …")
        for f in (out / "configs").rglob("*"):
            if f.is_file():
                hits += scan_strings(f, INTERESTING_PATTERNS)
    unique = list(dict.fromkeys(hits))
    by_pat = defaultdict(list)
    for label, val in unique:
        by_pat[label].append(val)
    print(f"\n{'='*70}\n  STRING RECON  —  {len(unique)} unique matches\n{'='*70}")
    for label, vals in by_pat.items():
        print(f"\n  [{label}]")
        for v in sorted(set(vals))[:50]:
            print(f"    {v}")
    if not dry_run:
        out.mkdir(exist_ok=True)
        rp = out / "strings_report.txt"
        with open(rp, "w", encoding="utf-8") as fp:
            fp.write("ROSLegacy String Recon Report\n" + "="*70 + "\n\n")
            for label, vals in by_pat.items():
                fp.write(f"[{label}]\n")
                for v in sorted(set(vals)):
                    fp.write(f"  {v}\n")
                fp.write("\n")
        print(f"\n  Report saved: {rp}")

# ─── V2 MODE 1: UNLOCK NSISBIN ───────────────────────────────────────────────

def cmd_unlock(exe: Path, nsisbin: Path, sevenz: Path, out: Path, dry_run: bool):
    """
    7z NSIS plugin looks for <stem>.bin as external data.
    Our file is .nsisbin — create a hardlink so 7z finds it without copying 7.7 GB.
    """
    print("\n[UNLOCK] Creating .bin alias for 7z NSIS plugin …")

    alias = exe.parent / (exe.stem + ".bin")

    if alias.exists():
        print(f"  [OK] Alias already exists: {alias.name}")
    elif dry_run:
        print(f"  [DRY] Would create: {alias.name} → {nsisbin.name}")
    else:
        # Try hardlink first (same inode, zero disk cost, same partition required)
        try:
            os.link(str(nsisbin), str(alias))
            print(f"  [OK] Hardlink created: {alias.name}  (zero disk cost)")
        except OSError as e:
            print(f"  [WARN] Hardlink failed ({e}). Trying symlink …")
            try:
                alias.symlink_to(nsisbin.name)
                print(f"  [OK] Symlink created: {alias.name} → {nsisbin.name}")
            except OSError as e2:
                print(f"  [FAIL] Cannot create alias: {e2}")
                print("         Ensure both files are on the same drive, or run as Administrator.")
                return

    # Re-run 7z list with alias in place
    print(f"\n[UNLOCK] Re-running 7z list with alias present …")
    r = run_7z(sevenz, ["l", str(exe)])
    files = parse_7z_list(r.stdout)

    if len(files) <= 6:
        print(f"  [PARTIAL] Still only {len(files)} entries visible.")
        print("  7z may not support this NSIS version/variant.")
        print("  Raw output from 7z:\n")
        print(r.stdout[:2000])
        print("\n  → Next step: run --decode-nsis to read the install script directly.")
        print("  → Or try UniExtract2 (github.com/Bioruebe/UniExtract2) for deeper NSIS support.")
    else:
        print(f"  [SUCCESS] Now seeing {len(files)} files (was 6 before alias) ✓")
        print_inventory(files)

        if not dry_run:
            out.mkdir(exist_ok=True)
            inv = {
                "exe": str(exe),
                "nsisbin": str(nsisbin),
                "alias": str(alias),
                "total_files": len(files),
                "total_size": sum(f["size"] for f in files),
                "files": files,
            }
            p = out / "inventory_full.json"
            p.write_text(json.dumps(inv, indent=2))
            print(f"\n  Full inventory saved: {p}")
            print("  → Run --extract-configs to pull server config files.")

    return files


def cmd_cleanup_alias(exe: Path):
    """Remove the .bin hardlink / symlink created by --unlock."""
    alias = exe.parent / (exe.stem + ".bin")
    if alias.exists() or alias.is_symlink():
        alias.unlink()
        print(f"  [OK] Removed alias: {alias.name}")
    else:
        print(f"  [OK] No alias to remove at {alias.name}")

# ─── V2 MODE 2: DECODE NSIS SCRIPT BLOCK ─────────────────────────────────────

def _extract_strings_from_binary(data: bytes, min_len: int = 5) -> list:
    """
    Extract both ASCII and UTF-16LE printable strings from a binary blob.
    Returns list of (encoding, string) tuples, deduped, sorted by length desc.
    """
    results = []

    # ASCII
    ascii_rx = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    for m in ascii_rx.finditer(data):
        s = m.group().decode("ascii", errors="replace").strip()
        if s:
            results.append(("ascii", s))

    # UTF-16LE — NSIS uses this for paths on Windows
    try:
        text = data.decode("utf-16-le", errors="replace")
        for part in text.split("\x00"):
            part = part.strip()
            if len(part) >= min_len and all(c.isprintable() or c in "\t\r\n" for c in part[:40]):
                results.append(("utf16", part))
    except Exception:
        pass

    # Deduplicate preserving encoding info
    seen, out = set(), []
    for enc, s in results:
        if s not in seen:
            seen.add(s)
            out.append((enc, s))
    return out


# Known NSIS string table patterns — helps filter noise
NSIS_INTERESTING = re.compile(
    r"(https?://|\\\\|%[A-Z_]+%|\.exe|\.dll|\.json|\.ini|\.cfg|\.xml"
    r"|registry|HKLM|HKCU|SOFTWARE\\|ExecWait|ShellExec"
    r"|mythgames|miraelabs|kamoteworks|roslega"
    r"|server|host|api|update|patch|manifest|download|cdn)",
    re.IGNORECASE,
)


def cmd_decode_nsis(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    """
    Extract the NSIS compiled script block ([0]) from the EXE and
    dump all readable strings — install paths, URLs, registry keys,
    ExecWait commands, server endpoints.

    The [0] block is the NSIS installer script in bytecode form.
    File paths and string constants are stored as readable UTF-16LE
    or ASCII in the string table within this block.
    """
    print("\n[DECODE-NSIS] Extracting NSIS compiled script block [0] …")

    block_dir = out / "nsis_blocks"
    block_file = block_dir / "[0]"

    if not dry_run:
        block_dir.mkdir(parents=True, exist_ok=True)
        # 7z can extract the [0] internal block from the EXE
        r = run_7z(sevenz, ["e", str(exe), "[0]", f"-o{block_dir}", "-y"])
        if r.returncode != 0 or not block_file.exists():
            print(f"  [FAIL] Could not extract [0] block.\n{r.stderr[:300]}")
            print("  → Try: 7z e ROSLegacy_Install_202609251811.exe -o.\\recon_out\\nsis_blocks -y")
            return

        size = block_file.stat().st_size
        print(f"  [OK] Block size: {human_size(size)}")
        data = block_file.read_bytes()
    else:
        print("  [DRY] Would extract [0] from EXE and scan strings.")
        return

    # ── Parse the NSIS header (if present) ────────────────────────────────
    # NSIS header starts with these 4 bytes after decompression:
    # The [0] block as stored by 7z is the raw compressed blob.
    # We scan it for string artifacts regardless of compression.

    print("  [OK] Scanning block for string artifacts …")
    all_strings = _extract_strings_from_binary(data, min_len=5)

    # Partition: interesting vs noise
    interesting = [(enc, s) for enc, s in all_strings if NSIS_INTERESTING.search(s)]
    all_printable = [(enc, s) for enc, s in all_strings if len(s) >= 8]

    print(f"\n  Total strings extracted : {len(all_strings)}")
    print(f"  High-interest strings   : {len(interesting)}")

    print(f"\n{'='*70}")
    print(f"  NSIS SCRIPT — HIGH-INTEREST STRINGS")
    print(f"{'='*70}")
    if interesting:
        for enc, s in interesting:
            print(f"  [{enc:5}] {s}")
    else:
        print("  (none — block may be compressed; see all-strings dump)")

    print(f"\n{'='*70}")
    print(f"  NSIS SCRIPT — ALL PRINTABLE STRINGS (first 150)")
    print(f"{'='*70}")
    for enc, s in all_printable[:150]:
        print(f"  [{enc:5}] {s}")
    if len(all_printable) > 150:
        print(f"  … {len(all_printable)-150} more in nsis_script_strings.txt")

    # Save
    report_path = out / "nsis_script_strings.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"NSIS Script String Dump — {exe.name}\n{'='*70}\n\n")
        f.write("=== HIGH-INTEREST ===\n")
        for enc, s in interesting:
            f.write(f"[{enc}] {s}\n")
        f.write("\n=== ALL PRINTABLE ===\n")
        for enc, s in all_printable:
            f.write(f"[{enc}] {s}\n")
    print(f"\n  Saved: {report_path}")

    # Hint if block looks compressed
    printable_ratio = len([b for b in data if 0x20 <= b <= 0x7E]) / max(len(data), 1)
    if printable_ratio < 0.20 and len(interesting) == 0:
        print(f"\n  [NOTE] Block appears compressed (only {printable_ratio:.0%} printable bytes).")
        print("  The NSIS [0] block is LZMA-compressed — 7z stores it compressed.")
        print("  → To decompress it: run the installer to a sandbox and capture")
        print("    the decompressed script from memory, OR use NSIS Decompiler:")
        print("    https://github.com/simdsoft/NSIS-Decompiler")
        print("    or nsis7z: https://github.com/nicowillis/nsis7z")

# ─── V2 MODE 3: RAW SCAN OF NSISBIN ─────────────────────────────────────────

def cmd_scan_nsisbin(nsisbin: Path, out: Path, dry_run: bool):
    """
    Raw byte scan of the 7.7 GB nsisbin for interesting patterns.

    NSIS-LZMA compresses the bulk of the payload, so most of the file
    is entropy-high ciphertext. However:
      - The NSIS data header (first ~512 B) is NOT compressed
      - Files stored with  SetCompress off  appear as raw bytes
      - Block boundary records (sizes, CRCs) are stored uncompressed
    We scan all 7.7 GB streaming in 4 MB chunks.
    """
    print(f"\n[SCAN-NSISBIN] Raw pattern scan of {nsisbin.name} …")
    print(f"  File: {human_size(nsisbin.stat().st_size)} — scanning in 4 MB chunks")
    print("  Tip: run --find-pe after this to also check for uncompressed executables.\n")

    if dry_run:
        print("  [DRY] Would scan nsisbin for URL/IP/server strings.")
        return

    hits = scan_strings(nsisbin, INTERESTING_PATTERNS)
    unique = list(dict.fromkeys(hits))
    by_pat = defaultdict(list)
    for label, val in unique:
        by_pat[label].append(val)

    print(f"\n{'='*70}")
    print(f"  NSISBIN RAW STRING SCAN  —  {len(unique)} unique matches")
    print(f"{'='*70}")
    if not unique:
        print("  (No matches — payload is fully compressed. Use --decode-nsis instead.)")
    for label, vals in by_pat.items():
        print(f"\n  [{label}]")
        for v in sorted(set(vals))[:50]:
            print(f"    {v}")

    out.mkdir(exist_ok=True)
    rp = out / "nsisbin_strings.txt"
    with open(rp, "w", encoding="utf-8") as f:
        f.write(f"ROSLegacy nsisbin Raw String Scan\n{'='*70}\n\n")
        for label, vals in by_pat.items():
            f.write(f"[{label}]\n")
            for v in sorted(set(vals)):
                f.write(f"  {v}\n")
            f.write("\n")
    print(f"\n  Report saved: {rp}")

# ─── V2 MODE 4: PE / FILE MAGIC SCANNER ─────────────────────────────────────

def _validate_pe(data: bytes, rel_off: int) -> dict | None:
    """
    Check if data[rel_off] looks like a real PE header.
    Returns dict with PE metadata if valid, None if not.
    """
    if data[rel_off:rel_off+2] != b"MZ":
        return None
    if rel_off + 0x40 > len(data):
        return None
    try:
        pe_ptr = struct.unpack_from("<I", data, rel_off + 0x3C)[0]
        if not (0x40 <= pe_ptr <= 0x400):
            return None
        pe_hdr = rel_off + pe_ptr
        if pe_hdr + 24 > len(data):
            return None
        if data[pe_hdr:pe_hdr+4] != b"PE\x00\x00":
            return None
        machine = struct.unpack_from("<H", data, pe_hdr + 4)[0]
        n_sections = struct.unpack_from("<H", data, pe_hdr + 6)[0]
        opt_magic = struct.unpack_from("<H", data, pe_hdr + 24)[0] if pe_hdr + 26 <= len(data) else 0
        arch = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(machine, f"unknown({machine:#x})")
        kind = {0x10B: "PE32", 0x20B: "PE32+"}.get(opt_magic, "PE?")

        size_of_image = 0
        if pe_hdr + 24 + 60 <= len(data) and opt_magic == 0x10B:   # PE32
            size_of_image = struct.unpack_from("<I", data, pe_hdr + 24 + 56)[0]
        elif pe_hdr + 24 + 72 <= len(data) and opt_magic == 0x20B:  # PE32+
            size_of_image = struct.unpack_from("<I", data, pe_hdr + 24 + 56)[0]

        return {
            "arch": arch, "kind": kind,
            "sections": n_sections,
            "size_of_image": size_of_image,
        }
    except (struct.error, IndexError):
        return None


def cmd_find_pe(nsisbin: Path, out: Path, dry_run: bool,
                max_scan_gb: float = 9.0):
    """
    Scan the nsisbin for valid PE (MZ) headers and other file magic.

    NSIS can store files with  SetCompress off  — those appear verbatim.
    Large executables like the game launcher are often stored uncompressed
    because re-compressing an already-compressed binary gains nothing.
    """
    total_bytes = nsisbin.stat().st_size
    scan_limit = min(total_bytes, int(max_scan_gb * 1024**3))

    print(f"\n[FIND-PE] Scanning {nsisbin.name} for file magic …")
    print(f"  File size   : {human_size(total_bytes)}")
    print(f"  Scan limit  : {human_size(scan_limit)}")
    print(f"  Looking for : {', '.join(FILE_MAGIC.values())[:80]} …\n")

    if dry_run:
        print("  [DRY] Would scan nsisbin for PE headers.")
        return

    chunk_size  = 4 * 1024 * 1024   # 4 MB
    overlap_sz  = 512                # bytes kept between chunks
    pe_hits     = []
    magic_hits  = defaultdict(list)
    offset      = 0
    overlap     = b""
    last_pct    = -1

    # Build a single byte-string scan target from all magic keys
    # (We'll scan for each magic in the combined buffer manually)
    sorted_magic = sorted(FILE_MAGIC.keys(), key=len, reverse=True)

    with open(nsisbin, "rb") as f:
        while offset < scan_limit:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            data = overlap + chunk
            base = offset - len(overlap)

            for magic in sorted_magic:
                pos = 0
                while True:
                    idx = data.find(magic, pos)
                    if idx == -1:
                        break
                    abs_off = base + idx
                    label = FILE_MAGIC[magic]

                    if magic == b"MZ":
                        meta = _validate_pe(data, idx)
                        if meta:
                            pe_hits.append({
                                "offset": abs_off,
                                "label": label,
                                **meta,
                            })
                            magic_hits["PE Executable"].append(abs_off)
                    else:
                        magic_hits[label].append(abs_off)
                    pos = idx + 1

            overlap = chunk[-overlap_sz:]
            offset += len(chunk)

            pct = int(offset * 100 / scan_limit)
            if pct != last_pct and pct % 5 == 0:
                print(f"  Progress: {pct:>3}%  ({human_size(offset)} / {human_size(scan_limit)})",
                      end="\r", flush=True)
                last_pct = pct

    print(f"\n  Scan complete.\n")
    print(f"{'='*70}")
    print(f"  FILE MAGIC RESULTS")
    print(f"{'='*70}")

    for label, offsets in sorted(magic_hits.items()):
        print(f"\n  {label}: {len(offsets)} occurrence(s)")
        for off in offsets[:8]:
            print(f"    @ {off:>12,}  ({human_size(off)})")
        if len(offsets) > 8:
            print(f"    … {len(offsets)-8} more")

    if pe_hits:
        print(f"\n{'='*70}")
        print(f"  VALID PE EXECUTABLES  ({len(pe_hits)} found)")
        print(f"{'='*70}")
        for h in pe_hits:
            img = f"  SizeOfImage={human_size(h['size_of_image'])}" if h["size_of_image"] else ""
            print(f"  [{h['arch']}/{h['kind']}] offset {h['offset']:>12,}"
                  f"  ({human_size(h['offset'])})  sections={h['sections']}{img}")

        print(f"\n  Extract the first PE (likely launcher):")
        first = pe_hits[0]
        extract_sz = max(first["size_of_image"] or 0, 30 * 1024 * 1024)
        print(f"  python nsis_recon_v2.py --extract-offset {first['offset']}"
              f" --extract-size {extract_sz} --out .\\recon_out")
    else:
        print("\n  No valid PE executables found with raw bytes.")
        print("  The nsisbin appears fully LZMA-compressed.")
        print("  → Use --unlock and then --extract-configs to get the launcher.")

    if not dry_run:
        out.mkdir(exist_ok=True)
        report = {
            "nsisbin": str(nsisbin),
            "scanned_bytes": offset,
            "pe_executables": pe_hits,
            "file_magic_hits": {k: v[:100] for k, v in magic_hits.items()},
        }
        rp = out / "pe_scan_report.json"
        rp.write_text(json.dumps(report, indent=2))
        print(f"\n  Report saved: {rp}")


# ─── V2 MODE 5: EXTRACT RAW OFFSET ───────────────────────────────────────────

def cmd_extract_offset(nsisbin: Path, offset: int, size: int, out: Path):
    """
    Pull raw bytes at a known offset from the nsisbin.
    Use offsets from --find-pe to carve out embedded executables.
    """
    print(f"\n[EXTRACT-OFFSET] nsisbin @ offset {offset:,}  size {human_size(size)} …")
    out.mkdir(parents=True, exist_ok=True)

    out_name = f"carved_{offset:016x}.bin"
    out_file = out / out_name

    with open(nsisbin, "rb") as f:
        f.seek(offset)
        data = f.read(size)

    out_file.write_bytes(data)
    print(f"  Written: {out_file}  ({human_size(len(data))})")
    print(f"  First 32 bytes: {data[:32].hex(' ')}")

    # Sniff the magic
    for magic, label in FILE_MAGIC.items():
        if data[:len(magic)] == magic:
            print(f"  Detected: {label}")
            break

    # For PE: rename to .exe and suggest next steps
    if data[:2] == b"MZ":
        exe_path = out / f"carved_{offset:016x}.exe"
        out_file.rename(exe_path)
        print(f"  Renamed to: {exe_path.name}")
        print(f"\n  Next steps:")
        print(f"  1. Open in Ghidra or Cutter for static analysis")
        print(f"  2. Run: python nsis_recon_v2.py --strings"
              f" --exe \"{exe_path}\"  (if it's the launcher)")
        print(f"  3. Check imports for WinHttp/URLDownload calls → server endpoints")
        print(f"  4. Check strings for mythgames.net / update server URLs")

# ─── V2 MODE 6: FULL RECON PIPELINE ──────────────────────────────────────────

def cmd_full_recon(exe: Path, nsisbin: Path, sevenz: Path, out: Path, dry_run: bool):
    """Run all phases in recommended order."""
    print("\n" + "="*70)
    print("  ROSLegacy FULL RECON PIPELINE")
    print("="*70)

    print("\n>>> Phase 1: Unlock nsisbin")
    cmd_unlock(exe, nsisbin, sevenz, out, dry_run)

    print("\n>>> Phase 2: Decode NSIS install script")
    cmd_decode_nsis(exe, sevenz, out, dry_run)

    print("\n>>> Phase 3: Scan for embedded PE executables")
    cmd_find_pe(nsisbin, out, dry_run)

    print("\n>>> Phase 4: Extract configs (if Phase 1 unlocked the nsisbin)")
    cmd_extract_configs(exe, sevenz, out / "configs", dry_run)

    print("\n>>> Phase 5: String recon on EXE")
    cmd_strings_v1(exe, sevenz, out, dry_run)

    print("\n" + "="*70)
    print("  FULL RECON COMPLETE — check recon_out/ for all reports")
    print("="*70)

# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="ROSLegacy NSIS Recon v2 — nsisbin unlock + PE scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Recommended order:
              1. python nsis_recon_v2.py --unlock
              2. python nsis_recon_v2.py --decode-nsis
              3. python nsis_recon_v2.py --find-pe
              4. python nsis_recon_v2.py --extract-offset <offset> --extract-size <bytes>
              5. python nsis_recon_v2.py --extract-configs   (after unlock succeeds)
        """)
    )

    ap.add_argument("--exe",    metavar="PATH", help="Path to .exe installer (auto-detected)")
    ap.add_argument("--bin",    metavar="PATH", help="Path to .nsisbin file (auto-detected)")
    ap.add_argument("--out",    metavar="PATH", default=str(DEFAULT_OUT), help="Output directory")
    ap.add_argument("--7z",     metavar="PATH", dest="sevenz", help="Path to 7z.exe")
    ap.add_argument("--dry-run",action="store_true", help="Preview without writing files")

    # Extraction offset params (for --extract-offset)
    ap.add_argument("--extract-offset", metavar="BYTES", type=int,
                    help="Byte offset in nsisbin to extract from (output of --find-pe)")
    ap.add_argument("--extract-size", metavar="BYTES", type=int, default=30*1024*1024,
                    help="Bytes to read from --extract-offset (default: 30 MB)")

    group = ap.add_mutually_exclusive_group(required=True)
    # v1 modes
    group.add_argument("--list",            action="store_true")
    group.add_argument("--strings",         action="store_true")
    group.add_argument("--extract-configs", action="store_true")
    group.add_argument("--extract-file",    metavar="PATH")
    group.add_argument("--extract-all",     action="store_true")
    group.add_argument("--report",          action="store_true")
    # v2 modes
    group.add_argument("--unlock",          action="store_true",
                        help="[NEW] Create .bin alias so 7z can read the nsisbin, re-run listing")
    group.add_argument("--decode-nsis",     action="store_true",
                        help="[NEW] Extract [0] block and dump NSIS script strings")
    group.add_argument("--scan-nsisbin",    action="store_true",
                        help="[NEW] Raw pattern scan of the nsisbin for URLs/IPs/credentials")
    group.add_argument("--find-pe",         action="store_true",
                        help="[NEW] Scan nsisbin for valid PE headers (uncompressed executables)")
    group.add_argument("--do-extract-offset", action="store_true", dest="do_extract_offset",
                        help="[NEW] Extract raw bytes at --extract-offset from the nsisbin")
    group.add_argument("--cleanup-alias",   action="store_true",
                        help="[NEW] Remove the .bin hardlink created by --unlock")
    group.add_argument("--full-recon",      action="store_true",
                        help="[NEW] Run all phases in order (unlock → decode → find-pe → configs → strings)")

    args = ap.parse_args()
    out  = Path(args.out)

    # ── Resolve EXE ──────────────────────────────────────────────────────────
    if args.exe:
        exe = Path(args.exe)
    else:
        exe = DEFAULT_DIR / EXE_NAME
        if not exe.exists():
            exe = Path(EXE_NAME)
    if not exe.exists():
        print(f"[ERROR] Cannot find EXE. Expected: {DEFAULT_DIR / EXE_NAME}")
        sys.exit(1)

    # ── Resolve nsisbin ──────────────────────────────────────────────────────
    if args.bin:
        nsisbin = Path(args.bin)
    else:
        nsisbin = exe.parent / BIN_NAME
    nsisbin_ok = nsisbin.exists()
    if nsisbin_ok:
        print(f"[OK] nsisbin: {nsisbin.name}  ({human_size(nsisbin.stat().st_size)})")
    else:
        print(f"[WARN] nsisbin not found at {nsisbin}")

    # ── Resolve 7z ───────────────────────────────────────────────────────────
    sevenz = Path(args.sevenz) if args.sevenz else find_7z()
    if not sevenz and args.unlock is not True:
        # 7z not needed for pure nsisbin scanning modes
        pass
    if sevenz:
        print(f"[OK] 7z: {sevenz}")
    elif args.list or args.strings or args.extract_configs or args.extract_file \
         or args.extract_all or args.report or args.unlock or args.decode_nsis \
         or args.full_recon:
        print("[ERROR] 7z.exe not found. Install 7-Zip or pass --7z PATH")
        sys.exit(1)

    print(f"[OK] EXE: {exe}")
    print(f"[OK] Out: {out}\n")

    # ── Dispatch ─────────────────────────────────────────────────────────────

    # v1
    if args.list:
        cmd_list(exe, sevenz)
    elif args.strings:
        cmd_strings_v1(exe, sevenz, out, args.dry_run)
    elif args.extract_configs:
        cmd_extract_configs(exe, sevenz, out / "configs", args.dry_run)
    elif args.extract_file:
        cmd_extract_file(exe, sevenz, args.extract_file, out, args.dry_run)
    elif args.extract_all:
        cmd_extract_all(exe, sevenz, out, args.dry_run)
    elif args.report:
        files = cmd_list(exe, sevenz)
        if not args.dry_run:
            out.mkdir(exist_ok=True)
            rp = out / "inventory.json"
            rp.write_text(json.dumps({
                "exe": str(exe), "total_files": len(files),
                "total_size": sum(f["size"] for f in files), "files": files,
            }, indent=2))
        cmd_strings_v1(exe, sevenz, out, args.dry_run)

    # v2
    elif args.unlock:
        if not nsisbin_ok:
            print("[ERROR] nsisbin not found — cannot create alias.")
            sys.exit(1)
        cmd_unlock(exe, nsisbin, sevenz, out, args.dry_run)

    elif args.decode_nsis:
        cmd_decode_nsis(exe, sevenz, out, args.dry_run)

    elif args.scan_nsisbin:
        if not nsisbin_ok:
            print("[ERROR] nsisbin not found.")
            sys.exit(1)
        cmd_scan_nsisbin(nsisbin, out, args.dry_run)

    elif args.find_pe:
        if not nsisbin_ok:
            print("[ERROR] nsisbin not found.")
            sys.exit(1)
        cmd_find_pe(nsisbin, out, args.dry_run)

    elif args.do_extract_offset:
        if args.extract_offset is None:
            print("[ERROR] --extract-offset requires --extract-offset BYTES")
            sys.exit(1)
        if not nsisbin_ok:
            print("[ERROR] nsisbin not found.")
            sys.exit(1)
        cmd_extract_offset(nsisbin, args.extract_offset, args.extract_size, out)

    elif args.cleanup_alias:
        cmd_cleanup_alias(exe)

    elif args.full_recon:
        if not nsisbin_ok:
            print("[WARN] nsisbin not found — some phases will be skipped.")
        cmd_full_recon(exe, nsisbin, sevenz, out, args.dry_run)


if __name__ == "__main__":
    main()
