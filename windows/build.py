#!/usr/bin/env python3
"""Build the Windows installers on Linux (or anywhere with the tools):

    dist/vt-quarantine-<version>.msi        the program itself (needs Python 3.11+)
    dist/vt-quarantine-<version>-setup.exe  installs Python first if it's missing,
                                            asks for the API key, then runs the .msi

Needs wixl (from msitools) and makensis (NSIS) on PATH, or set WIXL / MAKENSIS.
Arch: pacman -S msitools, nsis from the AUR. Debian/Ubuntu: apt install wixl nsis.

    build.py          both
    build.py msi      just the .msi
    build.py setup    just setup.exe, around the .msi already in dist/ (so the
                      .msi can be signed first: setup.exe carries it inside)
"""
import html
import os
import re
import struct
import subprocess
import sys
import uuid
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
OLDEST, NEWEST = 11, 19  # Python 3.x minor versions to look for


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


# --- MSI ---------------------------------------------------------------------------

def python_searches():
    """Registry places Python installs list themselves (PEP 514), newest first,
    this user's own before everyone's."""
    found = []
    for minor in range(NEWEST, OLDEST - 1, -1):
        for suffix in ("", "-arm64", "-32"):
            tag = f"3.{minor}{suffix}"
            for root, win64 in (("HKCU", False), ("HKLM", True), ("HKLM", False)):
                found.append((tag, root, win64))
    return found


def wxs(ver, icon, script):
    props, picks, ui, execute = [], [], [], []
    prev = "PickSaved"
    for i, (tag, root, win64) in enumerate(python_searches()):
        prop = f"PYW{i}"
        props.append(
            f'    <Property Id="{prop}">\n'
            f'      <RegistrySearch Id="Py{i}" Root="{root}" Key="Software\\Python\\PythonCore\\{tag}\\InstallPath"'
            f' Name="WindowedExecutablePath" Type="raw"{" Win64=" + quoteattr("yes") if win64 else ""}/>\n'
            f'    </Property>')
        picks.append(f'    <CustomAction Id="Pick{i}" Property="PYTHONW" Value="[{prop}]"/>')
        # The Microsoft Store Python keeps registry writes to itself, so
        # notifications and autostart wouldn't work from it.
        cond = f'NOT PYTHONW AND {prop} AND NOT ({prop} ~&gt;&lt; "\\WindowsApps\\")'
        for seq in (ui, execute):
            seq.append(f'      <Custom Action="Pick{i}" After="{prev}">{cond}</Custom>')
        prev = f"Pick{i}"
    for seq in (ui, execute):
        # Uninstalling uses the Python it was installed with, while that still exists.
        seq.insert(0, '      <Custom Action="PickSaved" After="AppSearch">Installed AND NOT PYTHONW AND SAVEDPYTHONW</Custom>')
    nl = "\n"
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
    <Property Id="SAVEDPYTHONW">
      <RegistrySearch Id="Saved" Root="HKCU" Key="Software\\vt-quarantine" Name="Python" Type="raw"/>
    </Property>
{nl.join(props)}
    <CustomAction Id="PickSaved" Property="PYTHONW" Value="[SAVEDPYTHONW]"/>
{nl.join(picks)}
    <Condition Message="VirusTotal Quarantine needs Python 3.{OLDEST} or newer from python.org. Use vt-quarantine-{ver}-setup.exe, which installs it for you, or install Python from https://www.python.org/downloads/ first.">Installed OR PYTHONW</Condition>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="LocalAppDataFolder">
        <Directory Id="INSTALLDIR" Name="vt-quarantine">
          <Component Id="Main" Guid="{COMPONENT_GUID}">
            <File Id="Script" Name="vt-quarantine.py" Source={quoteattr(str(script))}/>
            <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="Python" Type="string" Value="[PYTHONW]" KeyPath="yes"/>
            <RegistryValue Root="HKCU" Key="Software\\vt-quarantine" Name="Version" Type="string" Value="{ver}"/>
            <RegistryValue Root="HKCU" Key="Software\\Microsoft\\Windows\\CurrentVersion\\Run" Name="vt-quarantine"
                           Type="string" Value="&quot;[PYTHONW]&quot; &quot;[#Script]&quot;"/>
            <RegistryValue Root="HKCU" Key="Software\\Classes\\AppUserModelId\\vt-quarantine" Name="DisplayName"
                           Type="string" Value="VirusTotal Quarantine"/>
            <RemoveFolder Id="RemoveInstallDir" On="uninstall"/>
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <!-- Stop the running copy; on a real uninstall also undo the browser setup and delete
         the API key, settings, log and downloaded packages (an upgrade keeps them).
         Never fails the uninstall (Python may be gone already). -->
    <CustomAction Id="Purge" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot; --uninstall --purge"
                  Execute="deferred" Impersonate="yes" Return="ignore"/>
    <CustomAction Id="StopForUpgrade" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot; --uninstall --keep-data"
                  Execute="deferred" Impersonate="yes" Return="ignore"/>
    <CustomAction Id="Start" Property="PYTHONW" ExeCommand="&quot;[#Script]&quot;" Return="asyncNoWait"/>
    <InstallUISequence>
{nl.join(ui)}
    </InstallUISequence>
    <InstallExecuteSequence>
{nl.join(execute)}
      <Custom Action="Purge" Before="RemoveFiles">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="StopForUpgrade" Before="RemoveFiles">REMOVE="ALL" AND UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="Start" After="InstallFinalize">NOT REMOVE</Custom>
    </InstallExecuteSequence>
    <Feature Id="Complete" Level="1"><ComponentRef Id="Main"/></Feature>
  </Product>
</Wix>
"""


def quoteattr(value):
    return '"' + html.escape(value, quote=True) + '"'


def run(cmd):
    print("+", " ".join(map(str, cmd)))
    subprocess.run(cmd, check=True)


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if len(sys.argv) > 2 or what not in ("all", "msi", "setup"):
        sys.exit(__doc__)
    ver = version()
    BUILD.mkdir(parents=True, exist_ok=True)
    icon = BUILD / "vt-quarantine.ico"
    make_icon(icon)
    msi = DIST / f"vt-quarantine-{ver}.msi"
    exe = DIST / f"vt-quarantine-{ver}-setup.exe"
    if what in ("all", "msi"):
        source = BUILD / "wxs"
        source.write_text(wxs(ver, icon, ROOT / "vt-quarantine"))
        run([os.environ.get("WIXL", "wixl"), "-o", msi, source])
        print(f"Built {msi}")
    if what in ("all", "setup"):
        if not msi.exists():
            sys.exit(f"{msi} is missing: build it first (build.py msi)")
        run([os.environ.get("MAKENSIS", "makensis"), "-V2", "-INPUTCHARSET", "UTF8",
             f"-DVERSION={ver}", f"-DMSI={msi}", f"-DICON={icon}", f"-DOUTFILE={exe}",
             f"-DOLDEST={OLDEST}", f"-DNEWEST={NEWEST}", HERE / "setup.nsi"])
        print(f"Built {exe}")


if __name__ == "__main__":
    sys.exit(main())
