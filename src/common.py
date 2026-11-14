#!/usr/bin/env python3
"""Hold browser downloads in a quarantine folder until VirusTotal has checked them.

Clean files (0 malicious, 0 suspicious) are moved to the Downloads folder
automatically. Flagged, unknown or failed files stay in quarantine and raise a
notification asking what to do.

Runs on Linux (freedesktop notifications over D-Bus), Windows 10/11 (toast
notifications) and macOS (dialogs). Needs only Python: the few packages it uses
are downloaded on first run, checked against pinned SHA-256 hashes and kept in
its own folder. Installed from a Linux package (.deb/.rpm/Arch), it uses the
distribution's packages instead and downloads nothing.
"""
# Built from the parts in src/ by tools/bundle.py: change those, not this file.
import argparse
import collections
import configparser
import contextlib
import hashlib
import html
import io
import json
import os
import platform
import re
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zipfile
from pathlib import Path
from queue import Queue

VERSION = "2.4.2"
WINDOWS = sys.platform == "win32"
MACOS = sys.platform == "darwin"
# Full paths: Windows looks for a bare program name in the current folder first.
# Asked from Windows below (not %SystemRoot%, which anything setting our environment could point elsewhere).
WINDOWS_DIR = Path(r"C:\Windows")
SYSTEM32 = WINDOWS_DIR / "System32"
HOME = Path.home()
APP = "VirusTotal Quarantine"
VT_HOST = "www.virustotal.com"
VT_UPLOAD_HOST = "bigfiles.virustotal.com"  # where /files/upload_url points
API = f"https://{VT_HOST}/api/v3"
USER_AGENT = f"vt-quarantine/{VERSION}"

POLL_SECONDS = 0.5  # looking at the quarantine folder costs next to nothing
STABLE_SECONDS = 1  # a download that hasn't changed for this long is finished
UPDATE_CHECK_SECONDS = 24 * 3600
CONFIRM_DETECTIONS = 10  # "Mark as safe" asks twice from this many malicious verdicts
QUEUED_RECHECK_SECONDS = 60      # file known to VT but its analysis is still queued
ANALYSIS_POLL_SECONDS = 30       # after an upload
REQUESTS_PER_MINUTE = 4          # free public API limit
DIRECT_UPLOAD_MAX = 32 * 1024**2  # larger files need an upload URL
UPLOAD_MAX = 650 * 1024**2
ANALYSIS_TIMEOUT = 20 * 60
MIN_ENGINES = 20          # 0 detections from fewer engines than this is no verdict
STALE_DAYS = 30           # a clean verdict older than this gets a rescan for next time

# Unknown files of these types are uploaded without asking; anything else
# (documents, media, archives, disk images, ...) asks first, since uploads can be
# downloaded by VT subscribers and an archive may hold private files.
AUTO_UPLOAD_EXT = {
    ".exe", ".msi", ".msix", ".appx", ".dll", ".scr", ".com", ".cpl", ".sys",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk",
    ".jar", ".apk", ".appimage", ".run", ".sh", ".py", ".pl", ".deb", ".rpm",
    ".flatpak", ".snap", ".pkg", ".dmg", ".command", ".app",
}
EXECUTABLE_MAGIC = (b"MZ", b"\x7fELF", b"#!", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Downloads still in progress: Firefox (.part), Chrome/Edge/Brave/Vivaldi
# (.crdownload), Opera (.opdownload), Safari (.download), old Edge (.partial).
PARTIAL_SUFFIXES = (".part", ".crdownload", ".opdownload", ".download", ".partial")
# Folder metadata the file manager may drop into the quarantine folder.
IGNORED_NAMES = {"desktop.ini", "thumbs.db", ".directory", ".ds_store"}
# Chrome, Edge and Brave download into "<random uuid>.tmp" while their "Save as" box
# is open or a warning waits for an answer, and rename it when that's settled.
CHROMIUM_PENDING = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp")

# Third-party packages, pinned to exact wheels: (module to import, PyPI name,
# {wheel filename: SHA-256}). They are fetched from PyPI on first run (the Windows
# .msi brings them along in BUNDLED_WHEELS), checked against these hashes and unpacked
# into lib_dir(); nothing is installed system-wide.
# macOS needs none.
WHEELS = {
    'linux': [
        ('jeepney.io.threading', 'jeepney', {
            'jeepney-0.9.0-py3-none-any.whl':
                '97e5714520c16fc0a45695e5365a2e11b81ea79bba796e26f9f1d178cb182683',
        }),
    ],
    'win32': [
        ('typing_extensions', 'typing-extensions', {
            'typing_extensions-4.16.0-py3-none-any.whl':
                '481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8',
        }),
        ('truststore', 'truststore', {
            'truststore-0.10.5-py3-none-any.whl':
                '9aaaedaefaf06d8b206278cf8b5012bc897f485a874503501e12d776df78951c',
        }),
        ('winrt.runtime', 'winrt-runtime', {
            'winrt_runtime-4.0.3-cp311-cp311-win32.whl':
                '8dab9b3f240891ae5b331f62277cb48a387777cb6f9099b5409b2ac4822fb5f9',
            'winrt_runtime-4.0.3-cp311-cp311-win_amd64.whl':
                'ce15973dec334f553e13fa135625e977d07bedede5e1b95fb09cbc2f390e097e',
            'winrt_runtime-4.0.3-cp311-cp311-win_arm64.whl':
                'f9d15e89d44d5af8023d74c283cf2b3c67be0369985a029e72abd3c411aaaa65',
            'winrt_runtime-4.0.3-cp312-cp312-win32.whl':
                '2f7d0824c2e85cb71a638a1e0e957ff3d5967ddce45caa1e9ce0b70bc6995a6a',
            'winrt_runtime-4.0.3-cp312-cp312-win_amd64.whl':
                'a4edf47f42d8eaf6e4160a45da37d980bf99a286a3289188ae49c99dec19ee79',
            'winrt_runtime-4.0.3-cp312-cp312-win_arm64.whl':
                '7d2d6c4b640a16d05e2b3a0b89f85bd884d780d49e178b88267abf15ffdad2c5',
            'winrt_runtime-4.0.3-cp313-cp313-win32.whl':
                '25d969baeacd12828632e2bc81cb264b4d455165b9b9ac5eedbdd92ba45b1614',
            'winrt_runtime-4.0.3-cp313-cp313-win_amd64.whl':
                'e270f9520630c3515d5326c0b52fa1cbcffb9f335bc5e374c213307e0d053f4b',
            'winrt_runtime-4.0.3-cp313-cp313-win_arm64.whl':
                'e00e8ad8106b0e8c0d559c85317df1d333469a61747ee09ed3c803d31323b96f',
            'winrt_runtime-4.0.3-cp314-cp314-win32.whl':
                'fee35995e7dfb083b5024d7a11d63ad2d2c74e7a9fc6a58dcdede52c1f0a321d',
            'winrt_runtime-4.0.3-cp314-cp314-win_amd64.whl':
                '03d76d06172b6f5bb6312aa24f0d25761b1e45fe2b7c3c0b4ad0cd73a06bb293',
            'winrt_runtime-4.0.3-cp314-cp314-win_arm64.whl':
                '9731462174346a2ede57660b9d521e41a16cd7e59890dc292c4250c42d1642a9',
            'winrt_runtime-4.0.3-cp314-cp314t-win32.whl':
                'dc545f834a3dd2bcc69512193677f0918788ccce4871ca24937aa6f171ea7112',
            'winrt_runtime-4.0.3-cp314-cp314t-win_amd64.whl':
                'b0b06be21eb17248ce32d43a4a027ba22651065f9af5b42c3454575766879e1e',
            'winrt_runtime-4.0.3-cp314-cp314t-win_arm64.whl':
                '2b8d6a55d695e54a25e262a6d1134c510a1e291cf2c3d141990a8c209f87dc40',
            'winrt_runtime-4.0.3-cp315-cp315-win32.whl':
                'ff7920a2d42734c545984ef671376713ce09f8e59fc9a5b420395406e2c1eea7',
            'winrt_runtime-4.0.3-cp315-cp315-win_amd64.whl':
                '403a80372f33635851814760d1acd6d8bbdb0dedff7812203d0dd4cfba809e8b',
            'winrt_runtime-4.0.3-cp315-cp315-win_arm64.whl':
                '52eb937ab71e39ddf798f16dfe47d572a8c097ac6d1eb2ddb700fc7977591241',
            'winrt_runtime-4.0.3-cp315-cp315t-win32.whl':
                '325a701c70e32b31139bf650c31fa352f4eae108fb0488aad074fb7026b1e650',
            'winrt_runtime-4.0.3-cp315-cp315t-win_amd64.whl':
                'f0e5ce8fc5e6453fbad7ed3197010586337a9a4d42fce29847d8a5573f29d8e9',
            'winrt_runtime-4.0.3-cp315-cp315t-win_arm64.whl':
                '9580aaf167a9e1d9d790b57e9dfaa5499c8a625bd85f3872a5097915d25f1c24',
        }),
        ('winrt.windows.foundation', 'winrt-Windows.Foundation', {
            'winrt_windows_foundation-4!10.0.28000.2705-py3-none-any.whl':
                'b409530668b101cb17b3a6ce02061b9839665c92b64b0563c106186d87562571',
        }),
        ('winrt.windows.foundation.collections', 'winrt-Windows.Foundation.Collections', {
            'winrt_windows_foundation_collections-4!10.0.28000.2705-py3-none-any.whl':
                'f2169228644b86d752dca6f4ba0bb55ee27c5cc1062f3a3f0fbb375f48894bd7',
        }),
        ('winrt.windows.storage.streams', 'winrt-Windows.Storage.Streams', {
            'winrt_windows_storage_streams-4!10.0.28000.2705-py3-none-any.whl':
                '2824e516e328c9ba76ffc7926431255b124b4a9f52c656f0b1e0056a7f8ca7b8',
        }),
        ('winrt.windows.data.xml.dom', 'winrt-Windows.Data.Xml.Dom', {
            'winrt_windows_data_xml_dom-4!10.0.28000.2705-py3-none-any.whl':
                '5784183aca5a7f0f297e21789de34312702207e767954dc96d4197588c714a5a',
        }),
        ('winrt.windows.ui.notifications', 'winrt-Windows.UI.Notifications', {
            'winrt_windows_ui_notifications-4!10.0.28000.2705-py3-none-any.whl':
                '909fdfe7dc7418adc59029fa723f24db5b28836bc017d791b03e4e7cda02117c',
        }),
    ],
}



def env_dir(var, default):
    value = os.environ.get(var)
    return Path(value) if value and os.path.isabs(value) else default


def known_folder(guid, fallback):
    """A Windows known folder. Asked for directly rather than through %APPDATA% and
    friends, which aren't the user's own when started by the installer service."""
    import ctypes
    folder_id = ctypes.create_string_buffer(uuid.UUID(guid).bytes_le, 16)
    path = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(folder_id, 0, None, ctypes.byref(path)) == 0:
        try:
            return Path(path.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(path)
    return fallback


def xdg_config():  # Linux; looked up each time (HOME can change in tests)
    return env_dir("XDG_CONFIG_HOME", HOME / ".config")


if WINDOWS:
    WINDOWS_DIR = known_folder("F38BF404-1D43-42F2-9305-67DE0B28FC23", WINDOWS_DIR)  # FOLDERID_Windows
    SYSTEM32 = known_folder("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7", SYSTEM32)  # FOLDERID_System
    HOME = known_folder("5E6C858F-0E22-4760-9AFE-EA3317B67173", HOME)  # FOLDERID_Profile
    CONFIG_DIR = known_folder("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D",  # FOLDERID_RoamingAppData
                              HOME / "AppData" / "Roaming") / "vt-quarantine"
    DATA_DIR = known_folder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091",  # FOLDERID_LocalAppData
                            HOME / "AppData" / "Local") / "vt-quarantine"
elif MACOS:
    CONFIG_DIR = DATA_DIR = HOME / "Library" / "Application Support" / "vt-quarantine"
else:
    CONFIG_DIR = xdg_config() / "vt-quarantine"
    DATA_DIR = env_dir("XDG_DATA_HOME", HOME / ".local" / "share") / "vt-quarantine"


def downloads_dir():
    """The user's Downloads folder, which may have been moved or renamed."""
    if WINDOWS:
        # FOLDERID_Downloads; Explorer lets users move this folder anywhere.
        return known_folder("374DE290-123F-4565-9164-39C4925E467B", HOME / "Downloads")
    if not MACOS:
        user_dirs = xdg_config() / "user-dirs.dirs"
        try:
            m = re.search(r'^XDG_DOWNLOAD_DIR="([^"]*)"', user_dirs.read_text(), re.M)
        except (OSError, UnicodeDecodeError):
            m = None
        if m:
            path = Path(m.group(1).replace("$HOME", str(HOME)))
            # Pointing it at $HOME itself means "no Downloads folder" (xdg-user-dirs).
            if path.is_absolute() and path != HOME:
                return path
    return HOME / "Downloads"


RELEASE_DIR = downloads_dir()
QUARANTINE = RELEASE_DIR / ".quarantine"
KEY_FILE = CONFIG_DIR / "api_key"  # plain text: only where there's no password store
DPAPI_FILE = CONFIG_DIR / "api_key.dpapi"  # Windows: encrypted for this Windows account
KEY_CHANGED = CONFIG_DIR / "api_key.changed"  # touched by --set-key
KEY_ASKED = CONFIG_DIR / "api_key.asked"  # Windows, macOS: the key window opened by itself once
LIB_ROOT = DATA_DIR / "lib"
BUNDLED_WHEELS = Path(__file__).resolve().parent / "wheels"  # put there by the .msi
LOG_FILE = DATA_DIR / "vt-quarantine.log"
INSTALLED_SCRIPT = DATA_DIR / "vt-quarantine.py"
MAC_PYTHON = DATA_DIR / "python" / "bin" / "vt-quarantine"  # the macOS app's Python, under the name macOS lists
APP_PLACE = CONFIG_DIR / "app-path"  # macOS: where the app is kept; putting it in the Trash uninstalls
UNINSTALLER = HOME / "Applications" / "Uninstall VirusTotal Quarantine.app"
APP_BUNDLE_ID = "io.github.arianarahimi.vt-quarantine"

# The systemd journal timestamps lines itself; anywhere else they need their own.
log_timestamps = "JOURNAL_STREAM" not in os.environ


def log(msg):
    if log_timestamps:
        msg = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(msg, flush=True)


def setup_logging():
    """Under pythonw.exe there is no console (sys.stdout is None): log to a file."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if LOG_FILE.stat().st_size > 1024**2:
            os.replace(LOG_FILE, LOG_FILE.with_name(LOG_FILE.name + ".1"))
    except OSError:
        pass
    sys.stdout = sys.stderr = open(LOG_FILE, "a", buffering=1, encoding="utf-8")


def refuse_root():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        sys.exit("Don't run vt-quarantine as root: run it as the user whose downloads it checks.")
