#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) - fim.py
Detects modified, deleted, added files using MD5/SHA256 hashing
and identifies files disguised with fake extensions via MIME analysis.
"""

import os
import sys
import json
import hashlib
import argparse
import datetime
import mimetypes
from pathlib import Path

# Try importing python-magic for deep MIME detection
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# ─────────────────────────────────────────────
# ANSI color codes for terminal output
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────
# Suspicious extension mismatches to flag
# ─────────────────────────────────────────────
EXTENSION_MIME_MAP = {
    ".jpg":  ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".png":  ["image/png"],
    ".gif":  ["image/gif"],
    ".bmp":  ["image/bmp"],
    ".pdf":  ["application/pdf"],
    ".txt":  ["text/plain"],
    ".html": ["text/html"],
    ".xml":  ["text/xml", "application/xml"],
    ".zip":  ["application/zip"],
    ".gz":   ["application/gzip"],
    ".mp3":  ["audio/mpeg"],
    ".mp4":  ["video/mp4"],
    ".exe":  ["application/x-dosexec", "application/x-msdownload"],
    ".dll":  ["application/x-dosexec", "application/x-msdownload"],
    ".py":   ["text/x-python", "text/plain"],
    ".sh":   ["text/x-shellscript", "text/plain"],
    ".doc":  ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
}


def compute_hashes(filepath: str) -> dict:
    """Compute MD5 and SHA256 hashes for a file."""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "md5":    md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except (PermissionError, OSError) as e:
        return {"md5": None, "sha256": None, "error": str(e)}


def detect_mime_type(filepath: str) -> str:
    """Detect true MIME type using python-magic (libmagic) or fallback."""
    if MAGIC_AVAILABLE:
        try:
            return magic.from_file(filepath, mime=True)
        except Exception:
            pass
    # Fallback to mimetypes module (extension-based, less reliable)
    mime, _ = mimetypes.guess_type(filepath)
    return mime or "application/octet-stream"


def is_mime_mismatch(filepath: str, detected_mime: str) -> bool:
    """Check if a file's extension doesn't match its true MIME type."""
    ext = Path(filepath).suffix.lower()
    if ext not in EXTENSION_MIME_MAP:
        return False
    expected_mimes = EXTENSION_MIME_MAP[ext]
    return detected_mime not in expected_mimes


def scan_directory(directory: str, exclude_dirs: list = None) -> dict:
    """
    Walk a directory and collect file metadata.
    Returns a dict: {relative_path: {md5, sha256, size, mtime, mime}}
    """
    exclude_dirs = exclude_dirs or []
    baseline = {}
    directory = os.path.abspath(directory)

    for root, dirs, files in os.walk(directory):
        # Remove excluded directories in-place to skip them
        dirs[:] = [
            d for d in dirs
            if os.path.join(root, d) not in [os.path.abspath(e) for e in exclude_dirs]
            and d not in [os.path.basename(e) for e in exclude_dirs]
        ]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)

            try:
                stat      = os.stat(filepath)
                hashes    = compute_hashes(filepath)
                mime_type = detect_mime_type(filepath)
                mismatch  = is_mime_mismatch(filepath, mime_type)

                baseline[rel_path] = {
                    "md5":           hashes["md5"],
                    "sha256":        hashes["sha256"],
                    "size":          stat.st_size,
                    "mtime":         stat.st_mtime,
                    "mime_type":     mime_type,
                    "mime_mismatch": mismatch,
                    "scan_time":     datetime.datetime.now().isoformat(),
                }
            except Exception as e:
                baseline[rel_path] = {"error": str(e)}

    return baseline


def save_baseline(baseline: dict, output_file: str):
    """Save baseline to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"{GREEN}[+] Baseline saved → {output_file}{RESET}")
    print(f"    {len(baseline)} files indexed.")


def load_baseline(baseline_file: str) -> dict:
    """Load baseline from a JSON file."""
    with open(baseline_file, "r") as f:
        return json.load(f)


def compare_baselines(old: dict, new: dict) -> dict:
    """
    Compare two baseline snapshots.
    Returns categorized findings: modified, deleted, added, mime_mismatch.
    """
    results = {
        "modified":      [],
        "deleted":       [],
        "added":         [],
        "mime_mismatch": [],
        "errors":        [],
    }

    old_paths = set(old.keys())
    new_paths = set(new.keys())

    # Deleted files
    for path in old_paths - new_paths:
        results["deleted"].append(path)

    # Added files
    for path in new_paths - old_paths:
        entry = new[path]
        results["added"].append({
            "path":      path,
            "sha256":    entry.get("sha256"),
            "mime_type": entry.get("mime_type"),
            "mismatch":  entry.get("mime_mismatch", False),
        })
        if entry.get("mime_mismatch"):
            results["mime_mismatch"].append({
                "path":          path,
                "extension":     Path(path).suffix,
                "detected_mime": entry.get("mime_type"),
                "reason":        "Newly added file with fake extension",
            })

    # Modified files
    for path in old_paths & new_paths:
        o = old[path]
        n = new[path]

        if "error" in o or "error" in n:
            results["errors"].append(path)
            continue

        changed_fields = []
        if o.get("sha256") != n.get("sha256"):
            changed_fields.append("sha256")
        if o.get("md5") != n.get("md5"):
            changed_fields.append("md5")
        if o.get("size") != n.get("size"):
            changed_fields.append("size")

        if changed_fields:
            results["modified"].append({
                "path":         path,
                "changed":      changed_fields,
                "old_sha256":   o.get("sha256"),
                "new_sha256":   n.get("sha256"),
                "old_size":     o.get("size"),
                "new_size":     n.get("size"),
            })

        # MIME mismatch check (existing file)
        if n.get("mime_mismatch"):
            results["mime_mismatch"].append({
                "path":          path,
                "extension":     Path(path).suffix,
                "detected_mime": n.get("mime_type"),
                "reason":        "Extension does not match file content",
            })

    return results


def print_report(results: dict, verbose: bool = False):
    """Print a formatted terminal report of findings."""
    total_issues = (
        len(results["modified"])
        + len(results["deleted"])
        + len(results["added"])
        + len(results["mime_mismatch"])
    )

    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  FILE INTEGRITY MONITOR — SCAN REPORT{RESET}")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'═'*60}{RESET}\n")

    # ── Modified ──
    print(f"{BOLD}{YELLOW}[!] MODIFIED FILES: {len(results['modified'])}{RESET}")
    for item in results["modified"]:
        print(f"  {YELLOW}→ {item['path']}{RESET}")
        if verbose:
            print(f"      Old SHA256: {item['old_sha256']}")
            print(f"      New SHA256: {item['new_sha256']}")
            print(f"      Changed:    {', '.join(item['changed'])}")

    # ── Deleted ──
    print(f"\n{BOLD}{RED}[-] DELETED FILES: {len(results['deleted'])}{RESET}")
    for path in results["deleted"]:
        print(f"  {RED}→ {path}{RESET}")

    # ── Added ──
    print(f"\n{BOLD}{GREEN}[+] ADDED FILES: {len(results['added'])}{RESET}")
    for item in results["added"]:
        flag = f" {RED}⚠ MIME MISMATCH{RESET}" if item.get("mismatch") else ""
        print(f"  {GREEN}→ {item['path']}{flag}{RESET}")
        if verbose:
            print(f"      SHA256:    {item['sha256']}")
            print(f"      MIME type: {item['mime_type']}")

    # ── MIME Mismatches ──
    print(f"\n{BOLD}{RED}[⚠] DISGUISED FILES (MIME MISMATCH): {len(results['mime_mismatch'])}{RESET}")
    for item in results["mime_mismatch"]:
        print(f"  {RED}→ {item['path']}{RESET}")
        print(f"      Extension:     {item['extension']}")
        print(f"      True MIME:     {item['detected_mime']}")
        print(f"      Reason:        {item['reason']}")

    # ── Summary ──
    print(f"\n{BOLD}{'─'*60}{RESET}")
    status = f"{RED}⚠ ANOMALIES DETECTED{RESET}" if total_issues else f"{GREEN}✓ ALL CLEAR{RESET}"
    print(f"  Status: {status}")
    print(f"  Total issues: {total_issues}")
    print(f"{BOLD}{'═'*60}{RESET}\n")


def save_report(results: dict, output_file: str):
    """Save scan report to a JSON file."""
    report = {
        "scan_time": datetime.datetime.now().isoformat(),
        "summary": {
            "modified":      len(results["modified"]),
            "deleted":       len(results["deleted"]),
            "added":         len(results["added"]),
            "mime_mismatch": len(results["mime_mismatch"]),
        },
        "details": results,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"{GREEN}[+] Report saved → {output_file}{RESET}")


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — detect hidden malware and file tampering",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── baseline ──
    b_parser = subparsers.add_parser("baseline", help="Create a new baseline snapshot")
    b_parser.add_argument("directory",   help="Directory to monitor")
    b_parser.add_argument("-o", "--output", default="baseline.json", help="Output file (default: baseline.json)")
    b_parser.add_argument("-e", "--exclude", nargs="*", default=[], help="Directories to exclude")

    # ── scan ──
    s_parser = subparsers.add_parser("scan", help="Scan and compare against baseline")
    s_parser.add_argument("directory",   help="Directory to scan")
    s_parser.add_argument("-b", "--baseline", default="baseline.json", help="Baseline file to compare (default: baseline.json)")
    s_parser.add_argument("-r", "--report",   default=None,             help="Save JSON report to file")
    s_parser.add_argument("-e", "--exclude",  nargs="*", default=[],   help="Directories to exclude")
    s_parser.add_argument("-v", "--verbose",  action="store_true",      help="Show detailed diff output")

    # ── mime-check ──
    m_parser = subparsers.add_parser("mime-check", help="Scan for disguised files only (no baseline needed)")
    m_parser.add_argument("directory",  help="Directory to scan")
    m_parser.add_argument("-e", "--exclude", nargs="*", default=[], help="Directories to exclude")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # ── Run: baseline ──
    if args.command == "baseline":
        print(f"{CYAN}[*] Creating baseline for: {args.directory}{RESET}")
        if not MAGIC_AVAILABLE:
            print(f"{YELLOW}[!] python-magic not found. MIME detection limited to extension-based fallback.{RESET}")
        data = scan_directory(args.directory, args.exclude)
        save_baseline(data, args.output)

    # ── Run: scan ──
    elif args.command == "scan":
        if not os.path.exists(args.baseline):
            print(f"{RED}[!] Baseline file not found: {args.baseline}{RESET}")
            sys.exit(1)
        print(f"{CYAN}[*] Loading baseline: {args.baseline}{RESET}")
        old_baseline = load_baseline(args.baseline)
        print(f"{CYAN}[*] Scanning: {args.directory}{RESET}")
        if not MAGIC_AVAILABLE:
            print(f"{YELLOW}[!] python-magic not found. MIME detection limited to extension-based fallback.{RESET}")
        new_baseline = scan_directory(args.directory, args.exclude)
        results      = compare_baselines(old_baseline, new_baseline)
        print_report(results, verbose=args.verbose)
        if args.report:
            save_report(results, args.report)

    # ── Run: mime-check ──
    elif args.command == "mime-check":
        print(f"{CYAN}[*] Running MIME-only disguise detection on: {args.directory}{RESET}")
        if not MAGIC_AVAILABLE:
            print(f"{YELLOW}[!] python-magic not installed. Deep MIME detection unavailable.{RESET}")
            print(f"    Install with: pip install python-magic  (Linux/Mac)")
            print(f"                  pip install python-magic-bin  (Windows)\n")
        data = scan_directory(args.directory, args.exclude)
        flagged = [(p, m) for p, m in data.items() if m.get("mime_mismatch")]
        if flagged:
            print(f"\n{BOLD}{RED}[⚠] DISGUISED FILES FOUND: {len(flagged)}{RESET}\n")
            for path, meta in flagged:
                print(f"  {RED}→ {path}{RESET}")
                print(f"      Extension:  {Path(path).suffix}")
                print(f"      True MIME:  {meta['mime_type']}")
        else:
            print(f"\n{GREEN}[✓] No disguised files detected.{RESET}")
        print()


if __name__ == "__main__":
    main()
