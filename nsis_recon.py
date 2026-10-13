#!/usr/bin/env python3
"""
=============================================================================
  ROSLegacy NSIS Recon & Extractor
  Target : ROSLegacy_Install_202609251811.nsisbin  (~7.7 GB)
  Mode   : Read-only recon + selective extraction (zero execution)
  Author : Generated for private RE analysis
=============================================================================

Usage examples
--------------
  # 1. Full file inventory (names, sizes, types) — fastest first step
  python nsis_recon.py --list

  # 2. String recon on already-extracted files
  python nsis_recon.py --strings

  # 3. Pull only config / script / text files (*.json *.ini *.cfg *.xml *.lua *.yaml)
  python nsis_recon.py --extract-configs

  # 4. Pull a single file by path (path shown in --list output)
  python nsis_recon.py --extract-file "game\\config\\server.json"

  # 5. Pull everything into an output folder (slow, uses disk space equal to 7.7 GB)
  python nsis_recon.py --extract-all --out D:\\extracted

  # 6. Summary report only (file types, structure, interesting strings) 
  python nsis_recon.py --report

Flags
-----
  --exe PATH      Override path to the installer EXE (auto-detected by default)
  --bin PATH      Override path to the .nsisbin file  (auto-detected by default)
  --out PATH      Output directory for extractions    (default: .\recon_out)
  --7z  PATH      Override path to 7z.exe             (auto-detected)
  --dry-run       Show what would be extracted without writing anything

Requirements
------------
  Python 3.8+
  7-Zip (7z.exe) — must be installed or on PATH
  Windows (script designed for the target environment)
  The .exe and .nsisbin MUST be in the same directory — NSIS loads them together
"""

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

# ─── CONFIG ──────────────────────────────────────────────────────────────────

DEFAULT_DIR   = Path(r"C:\Users\MAFIA\Downloads\Compressed\ROSLegacy\Diamonds")
EXE_NAME      = "ROSLegacy_Install_202609251811.exe"
BIN_NAME      = "ROSLegacy_Install_202609251811.nsisbin"
DEFAULT_OUT   = Path("recon_out")

# File categories we care about in a game install
RECON_EXTENSIONS = {
    "config":  {".json", ".ini", ".cfg", ".yaml", ".yml", ".xml", ".toml", ".env"},
    "script":  {".lua", ".py", ".js", ".ts", ".cs", ".nsi", ".nsh"},
    "text":    {".txt", ".log", ".md", ".rtf", ".csv"},
    "exec":    {".exe", ".dll", ".so", ".pyd"},
    "data":    {".dat", ".bin", ".pak", ".db", ".sqlite", ".ldb"},
    "assets":  {".png", ".jpg", ".dds", ".tga", ".ogg", ".wav", ".mp3",
                ".fbx", ".obj", ".mesh", ".unity3d"},
    "archive": {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"},
}

# Flat set for fast lookup
ALL_RECON = {ext for exts in RECON_EXTENSIONS.values() for ext in exts}

# Strings that hint at game-server / network config
INTERESTING_PATTERNS = [
    r"https?://[^\s\"'<>]{4,}",                  # URLs
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",       # IP addresses
    r":[0-9]{4,5}\b",                              # port numbers
    r"(server|host|endpoint|api|url|domain)\s*[=:]\s*\S+",  # key=value hints
    r"(password|passwd|secret|token|key)\s*[=:]\s*\S+",     # credentials (flag, not store)
    r"(update|patch|manifest|version)[_\-]?[uUrRlL]{2,}",   # update server hints
    r"(game|world|zone|map|region)\s*\d+",         # game world references
]

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def find_7z() -> Path:
    """Locate 7z.exe — checks PATH then common install locations."""
    candidates = [
        "7z.exe",
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for c in candidates:
        try:
            r = subprocess.run([c, "--help"], capture_output=True)
            if r.returncode == 0:
                return Path(c)
        except FileNotFoundError:
            continue
    return None


def run_7z(sevenz: Path, args: list) -> subprocess.CompletedProcess:
    """Run 7z and return CompletedProcess; always capture output."""
    cmd = [str(sevenz)] + args
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def parse_7z_list(raw: str) -> list[dict]:
    """
    Parse the output of `7z l <file>` into a list of file dicts.
    Returns list of {date, time, attr, size, compressed, name}
    """
    files = []
    in_table = False
    separator_count = 0

    for line in raw.splitlines():
        if line.startswith("---"):
            separator_count += 1
            in_table = (separator_count == 1)
            continue
        if not in_table:
            continue
        # NSIS listing line format (fixed-width):
        # 2024-09-18 09:00:14 .....        31744        31744  .text
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            entry = {
                "date": parts[0],
                "time": parts[1],
                "attr": parts[2],
                "size": int(parts[3]),
                "compressed": int(parts[4]) if parts[4].isdigit() else 0,
                "name": " ".join(parts[5:]),
            }
            files.append(entry)
        except (ValueError, IndexError):
            continue
    return files


def human_size(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def classify(name: str) -> str:
    """Return category string for a filename."""
    ext = Path(name).suffix.lower()
    for cat, exts in RECON_EXTENSIONS.items():
        if ext in exts:
            return cat
    return "other"


def scan_strings(path: Path, patterns: list[str]) -> list[tuple[str, str]]:
    """
    Stream a binary file and pull matching strings.
    Returns list of (pattern_label, matched_string).
    """
    hits = []
    compiled = [(p, re.compile(p.encode(), re.IGNORECASE)) for p in patterns]
    chunk_size = 1024 * 1024  # 1 MB chunks

    with open(path, "rb") as f:
        overlap = b""
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            data = overlap + chunk
            for label, rx in compiled:
                for m in rx.finditer(data):
                    val = m.group().decode("utf-8", errors="replace").strip()
                    if 4 < len(val) < 300:
                        hits.append((label, val))
            # Keep last 256 bytes as overlap to catch cross-chunk matches
            overlap = chunk[-256:]
    return hits


# ─── MODES ───────────────────────────────────────────────────────────────────

def cmd_list(exe: Path, sevenz: Path) -> list[dict]:
    """List all files in the NSIS installer. Returns file list."""
    print(f"\n[LIST] Scanning {exe.name} …")
    r = run_7z(sevenz, ["l", str(exe)])
    if r.returncode != 0:
        print(f"  [ERROR] 7z failed:\n{r.stderr[:400]}")
        sys.exit(1)

    files = parse_7z_list(r.stdout)

    # Stats
    total_size = sum(f["size"] for f in files)
    by_cat = defaultdict(lambda: {"count": 0, "size": 0})
    for f in files:
        cat = classify(f["name"])
        by_cat[cat]["count"] += 1
        by_cat[cat]["size"] += f["size"]

    print(f"\n{'='*70}")
    print(f"  INVENTORY  —  {len(files)} files  /  {human_size(total_size)} total")
    print(f"{'='*70}")
    print(f"  {'Category':<12} {'Files':>6}  {'Size':>10}")
    print(f"  {'-'*34}")
    for cat, stats in sorted(by_cat.items()):
        print(f"  {cat:<12} {stats['count']:>6}  {human_size(stats['size']):>10}")
    print(f"{'='*70}\n")

    print(f"  {'Size':>10}  Name")
    print(f"  {'-'*60}")
    for f in files:
        flag = "  ← CONFIG" if classify(f["name"]) == "config" else \
               "  ← EXEC"   if classify(f["name"]) == "exec"   else \
               "  ← DATA"   if classify(f["name"]) == "data"   else ""
        print(f"  {human_size(f['size']):>10}  {f['name']}{flag}")

    return files


def cmd_extract_configs(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    """Extract only config/script/text files — fast, low disk usage."""
    print(f"\n[EXTRACT-CONFIGS] Target: {exe.name}")
    r = run_7z(sevenz, ["l", str(exe)])
    files = parse_7z_list(r.stdout)

    targets = [
        f["name"] for f in files
        if classify(f["name"]) in ("config", "script", "text")
    ]

    if not targets:
        print("  No config/script/text files found in inventory.")
        return

    print(f"  Found {len(targets)} config/script/text files:")
    for t in targets:
        print(f"    {t}")

    if dry_run:
        print("\n  [DRY RUN] No files written.")
        return

    out.mkdir(parents=True, exist_ok=True)
    for target in targets:
        print(f"\n  Extracting: {target}")
        r2 = run_7z(sevenz, ["e", str(exe), target, f"-o{out}", "-y"])
        if r2.returncode == 0:
            print(f"    → OK")
        else:
            print(f"    → FAIL: {r2.stderr[:200]}")

    print(f"\n  Configs extracted to: {out}")


def cmd_extract_file(exe: Path, sevenz: Path, target_path: str, out: Path, dry_run: bool):
    """Extract a single file by name."""
    if dry_run:
        print(f"\n  [DRY RUN] Would extract: {target_path}")
        return
    out.mkdir(parents=True, exist_ok=True)
    r = run_7z(sevenz, ["e", str(exe), target_path, f"-o{out}", "-y"])
    if r.returncode == 0:
        extracted = out / Path(target_path).name
        print(f"\n  Extracted to: {extracted}")
        if extracted.exists():
            print(f"  Size: {human_size(extracted.stat().st_size)}")
    else:
        print(f"\n  FAIL:\n{r.stderr[:400]}")


def cmd_extract_all(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    """Extract entire archive to output directory."""
    if dry_run:
        print(f"\n  [DRY RUN] Would extract all to: {out}")
        return
    print(f"\n[EXTRACT-ALL] Destination: {out}")
    print("  WARNING: 7.7 GB+ extraction — this will take a while.")
    out.mkdir(parents=True, exist_ok=True)
    r = run_7z(sevenz, ["x", str(exe), f"-o{out}", "-y"])
    if r.returncode == 0:
        print("  Done.")
    else:
        print(f"  FAIL:\n{r.stderr[:400]}")


def cmd_strings(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    """
    Two-phase string recon:
    1. Extract text/config/script files first (small, fast)
    2. Scan each for interesting patterns
    Also scans the EXE + nsisbin for raw string artifacts
    """
    print("\n[STRINGS] Phase 1 — extract text files …")
    if not dry_run:
        cmd_extract_configs(exe, sevenz, out / "configs", dry_run=False)

    # Phase 2: scan the EXE itself (uncompressed PE sections have plaintext)
    print("\n[STRINGS] Phase 2 — raw string scan of EXE …")
    hits = scan_strings(exe, INTERESTING_PATTERNS)

    # Phase 3: scan extracted text files
    if (out / "configs").exists():
        print("[STRINGS] Phase 3 — scan extracted configs …")
        for f in (out / "configs").rglob("*"):
            if f.is_file():
                hits += scan_strings(f, INTERESTING_PATTERNS)

    # Deduplicate
    unique_hits = list(dict.fromkeys(hits))

    print(f"\n{'='*70}")
    print(f"  STRING RECON  —  {len(unique_hits)} unique matches")
    print(f"{'='*70}")

    by_pattern = defaultdict(list)
    for label, val in unique_hits:
        by_pattern[label].append(val)

    for label, vals in by_pattern.items():
        print(f"\n  [{label}]")
        for v in sorted(set(vals))[:50]:  # cap at 50 per pattern
            print(f"    {v}")

    # Save report
    if not dry_run:
        report_path = out / "strings_report.txt"
        out.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as fp:
            fp.write("ROSLegacy String Recon Report\n")
            fp.write("=" * 70 + "\n\n")
            for label, vals in by_pattern.items():
                fp.write(f"[{label}]\n")
                for v in sorted(set(vals)):
                    fp.write(f"  {v}\n")
                fp.write("\n")
        print(f"\n  Report saved: {report_path}")


def cmd_report(exe: Path, sevenz: Path, out: Path, dry_run: bool):
    """Full summary report: inventory + file tree + string hits."""
    files = cmd_list(exe, sevenz)

    print("\n[REPORT] Building file tree …")
    tree = defaultdict(list)
    for f in files:
        parts = Path(f["name"]).parts
        folder = str(Path(*parts[:-1])) if len(parts) > 1 else "(root)"
        tree[folder].append((parts[-1], f["size"]))

    print(f"\n{'='*70}")
    print("  DIRECTORY TREE")
    print(f"{'='*70}")
    for folder in sorted(tree.keys()):
        print(f"\n  📁 {folder}/")
        for name, size in sorted(tree[folder]):
            ext = Path(name).suffix.lower()
            icon = "⚙️" if ext in RECON_EXTENSIONS["config"] else \
                   "📦" if ext in RECON_EXTENSIONS["exec"]   else \
                   "📄" if ext in RECON_EXTENSIONS["text"]   else \
                   "🎮" if ext in RECON_EXTENSIONS["assets"] else "  "
            print(f"    {icon} {name:<45} {human_size(size):>10}")

    # Save report JSON
    if not dry_run:
        out.mkdir(parents=True, exist_ok=True)
        report = {
            "exe": str(exe),
            "total_files": len(files),
            "total_size": sum(f["size"] for f in files),
            "files": files,
        }
        rp = out / "inventory.json"
        rp.write_text(json.dumps(report, indent=2))
        print(f"\n  Inventory JSON saved: {rp}")

    cmd_strings(exe, sevenz, out, dry_run)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="ROSLegacy NSIS Recon & Extractor — read-only analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python nsis_recon.py --list
              python nsis_recon.py --extract-configs
              python nsis_recon.py --extract-file "game\\config\\server.json"
              python nsis_recon.py --report --out D:\\recon_output
              python nsis_recon.py --extract-all --out D:\\full_extract --dry-run
        """)
    )
    ap.add_argument("--exe",      metavar="PATH", help="Path to the .exe installer")
    ap.add_argument("--bin",      metavar="PATH", help="Path to the .nsisbin file (auto-detected)")
    ap.add_argument("--out",      metavar="PATH", default=str(DEFAULT_OUT), help="Output directory")
    ap.add_argument("--7z",       metavar="PATH", dest="sevenz", help="Path to 7z.exe")
    ap.add_argument("--dry-run",  action="store_true", help="Preview actions without writing files")

    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--list",            action="store_true", help="List all files in the installer")
    group.add_argument("--strings",         action="store_true", help="String recon on EXE + extracted configs")
    group.add_argument("--extract-configs", action="store_true", help="Extract config/script/text files only")
    group.add_argument("--extract-file",    metavar="PATH",      help="Extract a specific file by path")
    group.add_argument("--extract-all",     action="store_true", help="Extract entire archive (slow, ~7.7 GB)")
    group.add_argument("--report",          action="store_true", help="Full recon report (inventory + strings)")

    args = ap.parse_args()

    # ── Resolve paths ──────────────────────────────────────────────────────────
    out = Path(args.out)

    # EXE path
    if args.exe:
        exe = Path(args.exe)
    else:
        exe = DEFAULT_DIR / EXE_NAME
    if not exe.exists():
        # Try current directory
        exe = Path(EXE_NAME)
    if not exe.exists():
        print(f"[ERROR] Cannot find installer EXE.\n"
              f"  Expected: {DEFAULT_DIR / EXE_NAME}\n"
              f"  Tip: run from the same folder as the EXE, or pass --exe PATH")
        sys.exit(1)

    # nsisbin path — must be in same directory as EXE
    nsisbin = exe.parent / BIN_NAME
    if not nsisbin.exists():
        print(f"[WARNING] .nsisbin not found at {nsisbin}")
        print("  7z will still work if the EXE is a monolithic installer.\n")
    else:
        sz = nsisbin.stat().st_size
        print(f"[OK] Found nsisbin: {nsisbin.name}  ({human_size(sz)})")

    # 7z path
    sevenz_path = Path(args.sevenz) if args.sevenz else find_7z()
    if not sevenz_path:
        print("[ERROR] 7z.exe not found.\n"
              "  Install 7-Zip from https://www.7-zip.org/\n"
              "  Or pass --7z \"C:\\path\\to\\7z.exe\"")
        sys.exit(1)
    print(f"[OK] Using 7z: {sevenz_path}")
    print(f"[OK] EXE: {exe}")
    print(f"[OK] Output: {out}\n")

    # ── Dispatch ───────────────────────────────────────────────────────────────
    if args.list:
        cmd_list(exe, sevenz_path)

    elif args.strings:
        cmd_strings(exe, sevenz_path, out, args.dry_run)

    elif args.extract_configs:
        cmd_extract_configs(exe, sevenz_path, out / "configs", args.dry_run)

    elif args.extract_file:
        cmd_extract_file(exe, sevenz_path, args.extract_file, out, args.dry_run)

    elif args.extract_all:
        cmd_extract_all(exe, sevenz_path, out, args.dry_run)

    elif args.report:
        cmd_report(exe, sevenz_path, out, args.dry_run)


if __name__ == "__main__":
    main()
