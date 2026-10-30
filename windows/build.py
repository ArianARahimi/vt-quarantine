#!/usr/bin/env python3
"""Build the Windows installer on Linux (or anywhere with the tools):

    dist/vt-quarantine-<version>.msi   the program with its own copy of Python

The Python is python.org's embeddable package, downloaded here once (and checked
against PY_SHA256), and the packages the program needs on Windows come along as
the wheels pinned in it (checked against its own hashes). So installing downloads
and runs nothing, and neither does the first start. The Python is private to the
program: nothing else sees it, and it goes when the program is removed.

Needs wixl (from msitools) on PATH, or set WIXL.
Arch: pacman -S msitools. Debian/Ubuntu: apt install wixl.
"""
import hashlib
import html
import importlib.machinery
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import urllib.request
import uuid
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DIST = ROOT / "dist"
BUILD = DIST / "build"

# Stable for the life of the program: Windows Installer recognizes upgrades by it.
UPGRADE_CODE = "{6F0C5D2B-8E4A-4B7F-9C1D-3A5E7B9D1F24}"
# Per-version product codes, derived so the same version always gets the same one.
PRODUCT_NS = uuid.UUID("2C9A4E61-7B3D-4F85-A0E2-5D8C1B6F9A37")
COMPONENT_GUID = "{A47E2C19-5B8D-4E3F-9F61-0C2D4B8A6E15}"

PY_VERSION = "3.14.10"
PY_ZIP = f"python-{PY_VERSION}-embed-amd64.zip"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/{PY_ZIP}"
PY_SHA256 = "90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159"


def version():
    m = re.search(r'^VERSION = "([0-9.]+)"$', (ROOT / "vt-quarantine").read_text(), re.M)
    return m.group(1)


# --- Icon: a shield with a tick, drawn here so no binary lives in the repo ----------

def segment_distance(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return ((px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2) ** 0.5


def shield_rgba(size):
    s = 4  # supersampling
    n = size * s
    out = bytearray()
    for y in range(size):
        for x in range(size):
            hit = tick = 0
            for sy in range(s):
                for sx in range(s):
                    u = (x * s + sx + 0.5) / n
                    v = (y * s + sy + 0.5) / n
                    # Shield: flat top, straight sides, then curving into a point.
                    half = 0.40 if v < 0.55 else 0.40 * (1 - ((v - 0.55) / 0.40) ** 1.6)
                    inside = 0.06 <= v <= 0.95 and abs(u - 0.5) <= max(half, 0)
                    hit += inside
                    if inside:  # tick: two round-ended strokes
                        tick += min(segment_distance(u, v, 0.31, 0.50, 0.45, 0.64),
                                    segment_distance(u, v, 0.45, 0.64, 0.69, 0.38)) < 0.055
            a = hit / (s * s)
            t = tick / max(hit, 1)
            # Blue that gets lighter towards the top, white tick.
            r0, g0, b0 = (37 + 30 * (1 - y / size), 99 + 40 * (1 - y / size), 235)
            r = round(r0 + (255 - r0) * t)
            g = round(g0 + (255 - g0) * t)
            b = round(b0 + (255 - b0) * t)
            out += bytes((r, g, b, round(255 * a)))
    return bytes(out)


def png(size, rgba):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\0" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def dib(size, rgba):
    """Classic BMP icon image (bottom-up BGRA plus an empty AND mask)."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = b"".join(
        bytes((rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]))
        for y in reversed(range(size)) for i in range(y * size * 4, (y + 1) * size * 4, 4))
    mask = b"\0" * (((size + 31) // 32) * 4 * size)
    return header + pixels + mask


def make_icon(path):
    images = [(sz, png(sz, shield_rgba(sz)) if sz == 256 else dib(sz, shield_rgba(sz)))
              for sz in (16, 24, 32, 48, 256)]
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for sz, data in images:
        entries += struct.pack("<BBBBHHII", sz % 256, sz % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    path.write_bytes(head + entries + b"".join(d for _, d in images))


# --- Python -------------------------------------------------------------------------

def python_files():
    """The embeddable Python, unpacked: [(file id, name, path)], pythonw.exe as "Pythonw"."""
    cached = BUILD / PY_ZIP
    if not cached.exists() or hashlib.sha256(cached.read_bytes()).hexdigest() != PY_SHA256:
        print(f"Downloading {PY_URL}")
        with urllib.request.urlopen(PY_URL, timeout=60) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != PY_SHA256:
            sys.exit(f"{PY_ZIP} from python.org isn't the file it should be (SHA-256 mismatch)")
        cached.write_bytes(data)
    out = BUILD / "python"
    shutil.rmtree(out, ignore_errors=True)
    with zipfile.ZipFile(cached) as z:
        names = sorted(z.namelist())
        if any("/" in n or "\\" in n or n.startswith(".") for n in names):
            sys.exit(f"{PY_ZIP} has folders in it, which this build doesn't expect")
        z.extractall(out)
    return [("Pythonw" if n == "pythonw.exe" else f"Py{i}", n, out / n) for i, n in enumerate(names)]


def program():
    loader = importlib.machinery.SourceFileLoader("vtq", str(ROOT / "vt-quarantine"))
    vtq = importlib.util.module_from_spec(importlib.util.spec_from_loader("vtq", loader))
    loader.exec_module(vtq)
    return vtq


def wheel_files():
    """The pinned Windows wheels for the bundled Python: [(file id, name, path)]."""
    vtq = program()
    cp = "cp" + "".join(PY_VERSION.split(".")[:2])
    tags = [f"{cp}-{cp}-win_amd64", f"{cp}-abi3-win_amd64", "py3-none-any", "py2.py3-none-any"]
    out = BUILD / "wheels"
    out.mkdir(exist_ok=True)
    found = []
    for _module, name, files in vtq.WHEELS["win32"]:
        by_tag = {"-".join(f[:-len(".whl")].split("-")[-3:]): (f, sha) for f, sha in files.items()}
        filename, sha = next((by_tag[t] for t in tags if t in by_tag), (None, None))
        if not filename:
            sys.exit(f"no pinned {name} wheel for Python {PY_VERSION} on 64-bit Windows")
        path = out / filename
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            print(f"Downloading {filename}")
            path.write_bytes(vtq.download_wheel(name, filename, sha))  # checks the hash
        found.append((f"Whl{len(found)}", filename, path))
    return found


# --- MSI ---------------------------------------------------------------------------

def wxs(ver, icon, script, python, wheels):
    nl = "\n"
    py_files = nl.join(f'            <File Id="{fid}" Name={quoteattr(name)} Source={quoteattr(str(path))}/>'
                       for fid, name, path in python)
    whl_files = nl.join(f'            <File Id="{fid}" Name={quoteattr(name)} Source={quoteattr(str(path))}/>'
                        for fid, name, path in wheels)
    # A new Python, or new wheels, is a new component, so an upgrade replaces it cleanly.
    py_guid = uuid.uuid5(PRODUCT_NS, f"python {PY_ZIP}")
    whl_guid = uuid.uuid5(PRODUCT_NS, "wheels " + " ".join(name for _, name, _ in wheels))
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="{{{uuid.uuid5(PRODUCT_NS, ver)}}}" Name="VirusTotal Quarantine" Language="1033"
           Version="{ver}" Manufacturer="vt-quarantine" UpgradeCode="{UPGRADE_CODE}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perUser"
             Description="VirusTotal Quarantine {ver}" Comments="Checks browser downloads with VirusTotal"/>
    <MajorUpgrade DowngradeErrorMessage="A newer version of VirusTotal Quarantine is already installed."/>
    <Media Id="1" Cabinet="vtq.cab" EmbedCab="yes"/>
    <Icon Id="vtq.ico" SourceFile={quoteattr(str(icon))}/>
    <Property Id="ARPPRODUCTICON" Value="vtq.ico"/>
    <Property Id="ARPNOMODIFY" Value="1"/>
    <Property Id="ARPNOREPAIR" Value="1"/>
    <Property Id="ARPURLINFOABOUT" Value="https://github.com/ArianARahimi/vt-quarantine"/>
    <Property Id="ARPHELPLINK" Value="https://github.com/ArianARahimi/vt-quarantine#readme"/>
    <Condition Message="VirusTotal Quarantine needs 64-bit Windows.">Installed OR VersionNT64</Condition>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="LocalAppDataFolder">
        <Directory Id="INSTALLDIR" Name="vt-quarantine">
          <Component Id="Main" Guid="{COMPONENT_GUID}">
            <File Id="Script" Name="vt-quarantine.py" Source={quoteattr(str(script))}/>
            <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="Python" Type="string" Value="[#Pythonw]" KeyPath="yes"/>
            <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="Version" Type="string" Value="{ver}"/>
            <RegistryValue Root="HKCU" Key="Software\\Microsoft\\Windows\\CurrentVersion\\Run" Name="vt-quarantine"
                           Type="string" Value="&quot;[#Pythonw]&quot; &quot;[#Script]&quot;"/>
            <RegistryValue Root="HKCU" Key="Software\\Classes\\AppUserModelId\\vt-quarantine" Name="DisplayName"
                           Type="string" Value="VirusTotal Quarantine"/>
            <RemoveFolder Id="RemoveInstallDir" On="uninstall"/>
          </Component>
          <Directory Id="PYTHONDIR" Name="python">
            <Component Id="Python" Guid="{{{py_guid}}}">
              <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="PythonVersion" Type="string"
                             Value="{PY_VERSION}" KeyPath="yes"/>
{py_files}
              <RemoveFolder Id="RemovePythonDir" On="uninstall"/>
            </Component>
          </Directory>
          <Directory Id="WHEELSDIR" Name="wheels">
            <Component Id="Wheels" Guid="{{{whl_guid}}}">
              <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="Wheels" Type="string"
                             Value="{whl_guid}" KeyPath="yes"/>
{whl_files}
              <RemoveFolder Id="RemoveWheelsDir" On="uninstall"/>
            </Component>
          </Directory>
        </Directory>
      </Directory>
    </Directory>
    <CustomAction Id="SetPython" Property="PYTHONW" Value="[#Pythonw]"/>
    <!-- Stop the running copy; on a real uninstall also undo the browser setup and delete
         the API key, settings, log and downloaded packages (an upgrade keeps them). -->
    <CustomAction Id="Purge" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot; --uninstall --purge"
                  Execute="deferred" Impersonate="yes" Return="ignore"/>
    <CustomAction Id="StopForUpgrade" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot; --uninstall --keep-data"
                  Execute="deferred" Impersonate="yes" Return="ignore"/>
    <CustomAction Id="Start" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot;" Return="asyncNoWait"/>
    <!-- Started from the installer window too: whether starting it from the install
         itself works on real Windows is untested (a second copy just exits). -->
    <InstallUISequence>
      <Custom Action="SetPython" After="CostFinalize"/>
      <Custom Action="Start" After="ExecuteAction">NOT REMOVE</Custom>
    </InstallUISequence>
    <InstallExecuteSequence>
      <Custom Action="SetPython" After="CostFinalize"/>
      <Custom Action="Purge" Before="RemoveFiles">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="StopForUpgrade" Before="RemoveFiles">REMOVE="ALL" AND UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="Start" After="InstallFinalize">NOT REMOVE</Custom>
    </InstallExecuteSequence>
    <Feature Id="Complete" Level="1"><ComponentRef Id="Main"/><ComponentRef Id="Python"/><ComponentRef Id="Wheels"/></Feature>
  </Product>
</Wix>
"""


def quoteattr(value):
    return '"' + html.escape(value, quote=True) + '"'


def run(cmd):
    print("+", " ".join(map(str, cmd)))
    subprocess.run(cmd, check=True)


def main():
    if len(sys.argv) > 2 or sys.argv[1:] not in ([], ["msi"]):
        sys.exit(__doc__)
    ver = version()
    BUILD.mkdir(parents=True, exist_ok=True)
    icon = BUILD / "vt-quarantine.ico"
    make_icon(icon)
    msi = DIST / f"vt-quarantine-{ver}.msi"
    source = BUILD / "wxs"
    source.write_text(wxs(ver, icon, ROOT / "vt-quarantine", python_files(), wheel_files()))
    run([os.environ.get("WIXL", "wixl"), "-a", "x64", "-o", msi, source])
    print(f"Built {msi}")


if __name__ == "__main__":
    sys.exit(main())
