#!/usr/bin/env python3
"""Join the parts in src/ into the single vt-quarantine script that ships.

vt-quarantine is one file on purpose: installs, updates and their signatures cover
exactly one file, and nothing can slip a module in beside it. The source is split
into parts to keep it readable; each part is plain code that sees the names of the
parts before it, as if they were one file (they are, once joined).

    python3 tools/bundle.py          write vt-quarantine
    python3 tools/bundle.py --check  fail if vt-quarantine isn't what src/ makes
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "vt-quarantine"
# In this order: a part may use, at import time, only what the parts before it define.
PARTS = (
    "common",      # constants, paths, logging
    "net",         # HTTPS and the pinned packages fetched at first run
    "notify",      # notifications on Linux, Windows and macOS
    "vt",          # VirusTotal requests and the rate limit
    "fullscreen",  # holding notifications back while something is fullscreen
    "quarantine",  # locking, checking and moving downloads
    "updates",     # signed self-updates
    "browsers",    # pointing browsers at the quarantine folder
    "keystore",    # the API key in the system's password store
    "install",     # --install, --uninstall, autostart, the macOS app
    "cli",         # --scan, run() and the command line
)
HEADER = "#: "  # a part's leading "#: " lines describe the part; they're left out


def part(name):
    lines = (ROOT / "src" / f"{name}.py").read_text(encoding="utf-8").splitlines(keepends=True)
    while lines and lines[0].startswith(HEADER):
        lines.pop(0)
    return "".join(lines).strip("\n") + "\n"


def bundle():
    return "\n\n".join(part(name) for name in PARTS)


def main():
    text = bundle()
    if sys.argv[1:] == ["--check"]:
        if OUT.read_text(encoding="utf-8") != text:
            sys.exit("vt-quarantine doesn't match src/: run python3 tools/bundle.py and commit it")
        return
    if sys.argv[1:]:
        sys.exit(__doc__)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    OUT.chmod(0o755)


if __name__ == "__main__":
    main()
