#!/usr/bin/env python3
"""Build the macOS app on Linux (or anywhere with Python 3.9+):

    dist/vt-quarantine-<version>-macos.zip   VirusTotal Quarantine.app

The app carries the program and its own Python for Apple silicon and Intel Macs
(python-build-standalone, downloaded here once and checked against the pinned
SHA-256s), so a Mac needs neither Python nor Apple's developer tools. Opening the
app installs vt-quarantine into ~/Library/Application Support/vt-quarantine; the
app itself can then be kept (opening it again offers to remove vt-quarantine) or
thrown away. It's unsigned, so the first open needs Open Anyway.
"""
import hashlib
import importlib.util
import os
import plistlib
import re
import shutil
import stat
import struct
import tarfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DIST = ROOT / "dist"
BUILD = DIST / "build" / "macos"

APP_NAME = "VirusTotal Quarantine"
BUNDLE_ID = "io.github.arianarahimi.vt-quarantine"
PY_VERSION = "3.14.10"
PBS_TAG = "20261026"
PY_BUILDS = {  # arch as `uname -m` says it: (python-build-standalone target, SHA-256)
    "arm64": ("aarch64-apple-darwin", "30a18bcb9ab75e485b4bf4e5d783dde165571e7e42c56dff47a2d2c5345183a4"),
    "x86_64": ("x86_64-apple-darwin", "01cedae5d4a66ac570e13cb35fa570d0e79ba8e9affd4518a5d85b6c2b98ff10"),
}
# Parts of Python the program never uses.
# (python3 has Python built in, so libpython is only for embedding it elsewhere.)
DROP = ("include", "share", "lib/pkgconfig", "lib/tcl*", "lib/tk*", "lib/itcl*", "lib/thread*",
        "lib/libtcl*", "lib/libpython*", "lib/python3.14/test", "lib/python3.14/idlelib",
        "lib/python3.14/tkinter", "lib/python3.14/turtledemo", "lib/python3.14/ensurepip",
        "lib/python3.14/site-packages", "lib/python3.14/pydoc_data", "lib/python3.14/config-*",
        "lib/python3.14/lib-dynload/_tkinter*")

LAUNCHER = """#!/bin/sh
# Opening the app: this Mac's Python from the bundle runs the installer.
res="$(cd "$(dirname "$0")/../Resources" && pwd)"
case "$(uname -m)" in
  arm64) py="$res/python-arm64/bin/python3" ;;
  *) py="$res/python-x86_64/bin/python3" ;;
esac
exec "$py" "$res/vt-quarantine.py" --install-app
"""


def version():
    m = re.search(r'^VERSION = "([0-9.]+)"$', (ROOT / "vt-quarantine").read_text(), re.M)
    return m.group(1)


def windows_build():
    """windows/build.py, for the shield icon it draws."""
    spec = importlib.util.spec_from_file_location("winbuild", ROOT / "windows" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def icns():
    """The shield as an .icns: 128 and 256 pixel PNGs."""
    w = windows_build()
    body = b""
    for kind, size in ((b"ic07", 128), (b"ic08", 256)):
        data = w.png(size, w.shield_rgba(size))
        body += kind + struct.pack(">I", len(data) + 8) + data
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def python_tree(arch):
    """This arch's Python, unpacked without symlinks or unused parts."""
    target, sha = PY_BUILDS[arch]
    name = f"cpython-{PY_VERSION}+{PBS_TAG}-{target}-install_only.tar.gz"
    cached = BUILD / name
    BUILD.mkdir(parents=True, exist_ok=True)
    if not cached.exists() or hashlib.sha256(cached.read_bytes()).hexdigest() != sha:
        url = f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/{name}"
        print(f"downloading {name}")
        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310  # nosec B310  # fixed https URL
            data = r.read()
        if hashlib.sha256(data).hexdigest() != sha:
            raise SystemExit(f"{name} doesn't match its pinned SHA-256")
        cached.write_bytes(data)
    out = BUILD / f"python-{arch}"
    shutil.rmtree(out, ignore_errors=True)
    with tarfile.open(cached) as tar:
        tar.extractall(BUILD / f"unpack-{arch}", filter="data") if hasattr(tarfile, "data_filter") \
            else tar.extractall(BUILD / f"unpack-{arch}")  # noqa: S202  # nosec B202  # pinned archive
    shutil.move(str(BUILD / f"unpack-{arch}" / "python"), out)
    shutil.rmtree(BUILD / f"unpack-{arch}")
    for pattern in DROP:
        for path in out.glob(pattern):
            shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()
    python = (out / "bin" / "python3").resolve().read_bytes()  # only python3, as one file
    shutil.rmtree(out / "bin")
    (out / "bin").mkdir()
    (out / "bin" / "python3").write_bytes(python)
    (out / "bin" / "python3").chmod(0o755)
    for path in sorted(out.rglob("*")):  # a symlink becomes a copy of what it points to
        if path.is_symlink():
            real = path.resolve()
            path.unlink()
            if real.is_file():
                shutil.copy2(real, path)
    return out


def info_plist(ver):
    return plistlib.dumps({
        "CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME, "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": "vt-quarantine", "CFBundleIconFile": "vt-quarantine.icns",
        "CFBundlePackageType": "APPL", "CFBundleShortVersionString": ver, "CFBundleVersion": ver,
        "LSMinimumSystemVersion": "11.0", "LSUIElement": True,  # no Dock icon while it installs
        "NSHumanReadableCopyright": "MIT License",
    })


def add(z, path, arcname):
    """Into the zip with its Unix permissions, so the app still runs once unzipped."""
    mode = path.stat().st_mode
    info = zipfile.ZipInfo(arcname + ("/" if path.is_dir() else ""), date_time=(2026, 1, 1, 0, 0, 0))
    info.external_attr = (stat.S_IFDIR | 0o755 if path.is_dir() else stat.S_IFREG | (mode & 0o777)) << 16
    if path.is_dir():
        z.writestr(info, b"")
    else:
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, path.read_bytes())


def main():
    ver = version()
    app = BUILD / f"{APP_NAME}.app"
    shutil.rmtree(app, ignore_errors=True)
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    res = contents / "Resources"
    res.mkdir()
    (contents / "Info.plist").write_bytes(info_plist(ver))
    launcher = contents / "MacOS" / "vt-quarantine"
    launcher.write_text(LAUNCHER)
    launcher.chmod(0o755)
    (res / "vt-quarantine.icns").write_bytes(icns())
    shutil.copyfile(ROOT / "vt-quarantine", res / "vt-quarantine.py")
    for arch in PY_BUILDS:
        shutil.move(str(python_tree(arch)), res / f"python-{arch}")
    DIST.mkdir(exist_ok=True)
    out = DIST / f"vt-quarantine-{ver}-macos.zip"
    with zipfile.ZipFile(out, "w") as z:
        for path in [app, *sorted(app.rglob("*"))]:
            add(z, path, path.relative_to(BUILD).as_posix())
    print(f"{out} ({out.stat().st_size // 1024 // 1024} MB)")


if __name__ == "__main__":
    os.umask(0o022)
    main()
