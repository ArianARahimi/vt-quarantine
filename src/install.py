#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Setup commands --------------------------------------------------------------

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\vt-quarantine"
SETUP_KEY = r"Software\vt-quarantine"  # written by the Windows installer (.msi)
AUMID_KEY = r"Software\Classes\AppUserModelId\vt-quarantine"
UNIT_FILE = env_dir("XDG_CONFIG_HOME", HOME / ".config") / "systemd" / "user" / "vt-quarantine.service"
UNIT_MARKER = "# Written by vt-quarantine --install"
PACKAGED_UNIT = Path("/usr/lib/systemd/user/vt-quarantine.service")
LAUNCH_AGENT_LABEL = "vt-quarantine"
LAUNCH_AGENT = HOME / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"


SIGNUP_URL = "https://www.virustotal.com/gui/join-us"
KEY_PAGE_URL = "https://www.virustotal.com/gui/my-apikey"
GUIDE_URL = "https://github.com/ArianARahimi/vt-quarantine#install"


def key_window():
    """Windows and macOS: run the key window (on Windows without a console) and
    wait for it; True if a key was saved, which is then picked up straight away."""
    pythonw = Path(sys.executable).with_name("pythonw.exe") if WINDOWS else Path(sys.executable)
    return subprocess.run([str(pythonw if pythonw.exists() else sys.executable),
                           str(Path(__file__).resolve()), "--key-window"]).returncode == 0


def parse_key(text):
    """The API key in pasted text (spaces and line breaks dropped), or None."""
    key = re.sub(r"\s", "", text or "")
    return key if re.fullmatch(r"[0-9a-fA-F]{64}", key) else None


def set_key():
    import getpass
    key = parse_key(getpass.getpass(f"VirusTotal API key (from {KEY_PAGE_URL}, input hidden): "))
    if not key:
        sys.exit("That doesn't look like a VirusTotal API key (64 hex characters).")
    print(f"Saved in {save_key(key)}.")


MAC_KEY_DIALOG = """on run argv
    set r to display dialog (item 2 of argv) with title (item 3 of argv) default answer "" with hidden answer buttons {"Get a key", "Cancel", "Save"} default button "Save" cancel button "Cancel" with icon caution
    return (button returned of r) & linefeed & (text returned of r)
end run"""


def mac_key_dialog():
    """macOS: ask for the API key in a dialog (osascript, built in), the answer
    hidden like a password. True if a key was saved."""
    text = ("VirusTotal Quarantine needs your free VirusTotal API key to check your downloads.\n\n"
            "1. Sign in to VirusTotal, or create a free account.\n"
            "2. Open your API key page and copy the key (Get a key opens it).\n"
            "3. Paste it here:")
    while True:
        r = subprocess.run(["osascript", "-e", MAC_KEY_DIALOG, "vtq", text, f"{APP}: API key"],
                           capture_output=True, text=True)
        if r.returncode:  # Cancel, or closed
            return False
        button, _, answer = r.stdout.rstrip("\n").partition("\n")
        if button == "Get a key":
            open_url(KEY_PAGE_URL)
            continue
        key = parse_key(answer)
        if not key:
            text = ("That isn't an API key. It's 64 letters and numbers: use the Copy button "
                    "on your API key page.\n\nPaste it here:")
            continue
        try:
            save_key(key)
        except Exception as e:
            text = f"Could not save it: {e}\n\nPaste it here to try again:"
            continue
        return True


def key_dialog():
    """Windows: a small window to paste the API key into (hidden like a password),
    with the steps to get one. Plain Win32 through ctypes. True if a key was saved."""
    import ctypes
    from ctypes import wintypes as w
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    DLGPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
    for name, res, args in (
            ("DialogBoxIndirectParamW", LRESULT, (w.HINSTANCE, ctypes.c_void_p, w.HWND, DLGPROC, w.LPARAM)),
            ("GetDlgItem", w.HWND, (w.HWND, ctypes.c_int)),
            ("SendMessageW", LRESULT, (w.HWND, w.UINT, w.WPARAM, w.LPARAM)),
            ("SetDlgItemTextW", w.BOOL, (w.HWND, ctypes.c_int, w.LPCWSTR)),
            ("GetWindowTextW", ctypes.c_int, (w.HWND, w.LPWSTR, ctypes.c_int)),
            ("IsDlgButtonChecked", w.UINT, (w.HWND, ctypes.c_int)),
            ("InvalidateRect", w.BOOL, (w.HWND, ctypes.c_void_p, w.BOOL)),
            ("SetFocus", w.HWND, (w.HWND,)),
            ("SetForegroundWindow", w.BOOL, (w.HWND,)),
            ("SetWindowPos", w.BOOL, (w.HWND, w.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.UINT)),
            ("SetTimer", ctypes.c_size_t, (w.HWND, ctypes.c_size_t, w.UINT, ctypes.c_void_p)),
            ("KillTimer", w.BOOL, (w.HWND, ctypes.c_size_t)),
            ("EndDialog", w.BOOL, (w.HWND, LRESULT)),
            ("GetSysColorBrush", w.HANDLE, (ctypes.c_int,)),
            ("LoadImageW", w.HANDLE, (w.HINSTANCE, w.LPCWSTR, w.UINT, ctypes.c_int, ctypes.c_int, w.UINT))):
        fn = getattr(user32, name)
        fn.restype, fn.argtypes = res, args
    kernel32.GetModuleHandleW.restype, kernel32.GetModuleHandleW.argtypes = w.HMODULE, (w.LPCWSTR,)

    class ACTCTXW(ctypes.Structure):
        _fields_ = [("cbSize", w.ULONG), ("dwFlags", w.DWORD), ("lpSource", w.LPCWSTR),
                    ("wProcessorArchitecture", w.USHORT), ("wLangId", w.WORD),
                    ("lpAssemblyDirectory", w.LPCWSTR), ("lpResourceName", w.LPCWSTR),
                    ("lpApplicationName", w.LPCWSTR), ("hModule", w.HMODULE)]

    class INITCOMMONCONTROLSEX(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("dwICC", w.DWORD)]

    class NMHDR(ctypes.Structure):
        _fields_ = [("hwndFrom", w.HWND), ("idFrom", ctypes.c_size_t), ("code", w.UINT)]

    # Today's look and the link control need Common Controls 6, which Python's
    # own manifest doesn't ask for: ask for it here.
    manifest = Path(tempfile.gettempdir()) / f"vt-quarantine-{os.getpid()}.manifest"
    manifest.write_text(
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><dependency>'
        '<dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" '
        'version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>'
        '</dependentAssembly></dependency></assembly>')
    kernel32.CreateActCtxW.restype = w.HANDLE
    ctx = ACTCTXW(ctypes.sizeof(ACTCTXW), 0, str(manifest))
    handle = kernel32.CreateActCtxW(ctypes.byref(ctx))
    manifest.unlink(missing_ok=True)
    cookie = ctypes.c_size_t()
    if handle and handle != w.HANDLE(-1).value:
        kernel32.ActivateActCtx(w.HANDLE(handle), ctypes.byref(cookie))
    with contextlib.suppress(AttributeError):  # Windows 10 1703+: sharp on high-DPI screens
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    comctl32 = ctypes.WinDLL("comctl32")
    gdi32 = ctypes.WinDLL("gdi32")
    gdi32.SetTextColor.argtypes = gdi32.SetBkMode.argtypes = (w.HDC, w.DWORD)
    comctl32.InitCommonControlsEx(ctypes.byref(INITCOMMONCONTROLSEX(8, 0x8000 | 0x4000)))  # LINK, STANDARD

    (INTRO, STEP1, STEP2, STEP3, EDIT, SHOW, ERROR, NOTE, GUIDE) = range(100, 109)
    IDOK, IDCANCEL = 1, 2
    links = {STEP1: SIGNUP_URL, STEP2: KEY_PAGE_URL, GUIDE: GUIDE_URL}
    BUTTON, EDIT_CLASS, STATIC = 0x80, 0x81, 0x82
    TABSTOP, GROUP = 0x10000, 0x20000
    # (class, text, id, x, y, width, height, style, extended style) in dialog units
    items = [
        (STATIC, "VirusTotal Quarantine needs your free VirusTotal API key to check your downloads.",
         INTRO, 10, 9, 236, 18, 0, 0),
        ("SysLink", "1.  Sign in to VirusTotal, or <a>create a free account</a>.", STEP1, 10, 33, 236, 10, TABSTOP, 0),
        ("SysLink", "2.  Open <a>your API key page</a> and copy the key.", STEP2, 10, 46, 236, 10, TABSTOP, 0),
        (STATIC, "3.  Paste it here:", STEP3, 10, 59, 236, 10, 0, 0),
        (EDIT_CLASS, "", EDIT, 10, 71, 188, 14, TABSTOP | GROUP | 0x20 | 0x80, 0x200),  # PASSWORD, AUTOHSCROLL
        (BUTTON, "Show", SHOW, 206, 73, 40, 10, TABSTOP | 3, 0),  # AUTOCHECKBOX
        (STATIC, "", ERROR, 10, 89, 236, 18, 0, 0),
        (STATIC, "It's stored encrypted for your Windows account and only ever sent to VirusTotal.",
         NOTE, 10, 108, 236, 18, 0, 0),
        ("SysLink", "<a>Step-by-step guide</a>", GUIDE, 10, 135, 110, 10, TABSTOP, 0),
        (BUTTON, "Save", IDOK, 142, 132, 50, 14, TABSTOP | GROUP | 1, 0),  # DEFPUSHBUTTON
        (BUTTON, "Cancel", IDCANCEL, 196, 132, 50, 14, TABSTOP, 0),
    ]

    def wstr(text):
        return text.encode("utf-16-le") + b"\0\0"

    # DLGTEMPLATEEX: POPUP | CAPTION | SYSMENU | MODALFRAME | CENTER | SETFONT; shown in the taskbar
    data = struct.pack("<HHIIIHhhhh", 1, 0xFFFF, 0, 0x40000, 0x80C80000 | 0x80 | 0x800 | 0x40,
                       len(items), 0, 0, 256, 156)
    data += b"\0\0\0\0" + wstr(f"{APP}: API key") + struct.pack("<HHBB", 9, 400, 0, 1) + wstr("Segoe UI")
    for cls, text, ident, x, y, cx, cy, style, exstyle in items:
        data += b"\0" * (-len(data) % 4)
        data += struct.pack("<IIIhhhhI", 0, exstyle, 0x50000000 | style, x, y, cx, cy, ident)  # CHILD | VISIBLE
        data += (struct.pack("<HH", 0xFFFF, cls) if isinstance(cls, int) else wstr(cls)) + wstr(text) + b"\0\0"
    template = ctypes.create_string_buffer(data)

    saved = []
    error_brush = user32.GetSysColorBrush(15)  # COLOR_BTNFACE, the dialog's background

    def item(hwnd, ident):
        return user32.GetDlgItem(hwnd, ident)

    @DLGPROC
    def proc(hwnd, msg, wparam, lparam):
        try:
            if msg == 0x110:  # WM_INITDIALOG
                icon = Path(__file__).resolve().with_name("vt-quarantine.ico")
                for size, kind in ((16, 0), (32, 1)):  # WM_SETICON small, big
                    hicon = user32.LoadImageW(None, str(icon), 1, size, size, 0x10) if icon.exists() else None
                    if hicon:
                        user32.SendMessageW(hwnd, 0x80, kind, hicon)
                edit = item(hwnd, EDIT)
                user32.SendMessageW(edit, 0xC5, 256, 0)  # EM_SETLIMITTEXT
                cue = ctypes.create_unicode_buffer("Paste your API key")
                user32.SendMessageW(edit, 0x1501, 1, ctypes.addressof(cue))  # EM_SETCUEBANNER
                # Opened by a program in the background, Windows won't bring it to the front:
                # on top of everything for a moment, then an ordinary window again.
                if not user32.SetForegroundWindow(hwnd):
                    user32.SetWindowPos(hwnd, w.HWND(-1), 0, 0, 0, 0, 0x1 | 0x2 | 0x10)  # TOPMOST, no size/move/activate
                    user32.SetTimer(hwnd, 1, 700, None)
                user32.SetFocus(edit)
                return 0  # focus set by hand
            if msg == 0x113 and wparam == 1:  # WM_TIMER
                user32.KillTimer(hwnd, 1)
                user32.SetWindowPos(hwnd, w.HWND(-2), 0, 0, 0, 0, 0x1 | 0x2 | 0x10)  # NOTOPMOST
                return 1
            if msg == 0x111:  # WM_COMMAND
                ident = wparam & 0xFFFF
                if ident == EDIT and wparam >> 16 == 0x300:  # EN_CHANGE: the old complaint is moot
                    user32.SetDlgItemTextW(hwnd, ERROR, "")
                    return 1
                if ident == SHOW:
                    edit = item(hwnd, EDIT)
                    user32.SendMessageW(edit, 0xCC, 0 if user32.IsDlgButtonChecked(hwnd, SHOW) else 0x25CF, 0)
                    user32.InvalidateRect(edit, None, True)
                    return 1
                if ident == IDOK:
                    buf = ctypes.create_unicode_buffer(300)
                    user32.GetWindowTextW(item(hwnd, EDIT), buf, 300)
                    key = parse_key(buf.value)
                    if not key:
                        user32.SetDlgItemTextW(
                            hwnd, ERROR, "That isn't an API key. It's 64 letters and numbers: "
                            "use the Copy button on your API key page." if buf.value.strip() else
                            "Paste your API key first.")
                        user32.SetFocus(item(hwnd, EDIT))
                        return 1
                    try:
                        save_key(key)
                    except Exception as e:
                        user32.SetDlgItemTextW(hwnd, ERROR, f"Could not save it: {e}")
                        return 1
                    saved.append(True)
                    user32.EndDialog(hwnd, IDOK)
                    return 1
                if ident == IDCANCEL:  # also Esc and the close button
                    user32.EndDialog(hwnd, IDCANCEL)
                    return 1
            if msg == 0x4E:  # WM_NOTIFY
                hdr = NMHDR.from_address(lparam)
                if hdr.idFrom in links and hdr.code in (2**32 - 2, 2**32 - 4):  # NM_CLICK, NM_RETURN
                    open_url(links[hdr.idFrom])
                    return 1
            if msg == 0x138 and lparam == item(hwnd, ERROR):  # WM_CTLCOLORSTATIC
                gdi32.SetTextColor(wparam, 0x1C2BC4)  # red (BGR)
                gdi32.SetBkMode(wparam, 1)  # transparent
                return error_brush
        except Exception as e:
            log(f"API key window: {e}")
        return 0

    if user32.DialogBoxIndirectParamW(kernel32.GetModuleHandleW(None), template, None, proc, 0) == -1:
        log(f"could not open the API key window (error {ctypes.get_last_error()})")
    return bool(saved)


def acquire_lock():
    """Take the single-instance lock (kept until the process exits); None if another
    instance holds it."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    f = open(DATA_DIR / "lock", "a+")
    try:
        if WINDOWS:
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def copy_self():
    """Install a copy of this script next to its data, so autostart keeps working
    if the downloaded copy is moved or deleted."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).resolve()
    if src != INSTALLED_SCRIPT.resolve():
        tmp = INSTALLED_SCRIPT.with_name(INSTALLED_SCRIPT.name + ".new")
        shutil.copyfile(src, tmp)
        os.replace(tmp, INSTALLED_SCRIPT)
    return INSTALLED_SCRIPT


def packaged():
    """Installed by a Linux package: the program is in /usr/bin and the package
    provides the systemd user service."""
    return (not WINDOWS and not MACOS and PACKAGED_UNIT.exists()
            and Path(__file__).resolve().parent == Path("/usr/bin"))


def systemd_quote(arg):
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def systemctl(*args, check=True):
    return subprocess.run(["systemctl", "--user", *args], check=check, capture_output=True, text=True)


def autostart_linux(script):
    if UNIT_FILE.exists() and UNIT_MARKER not in UNIT_FILE.read_text():
        sys.exit(f"{UNIT_FILE} exists and wasn't written by --install; leaving it alone.")
    UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    UNIT_FILE.write_text(f"""{UNIT_MARKER}
[Unit]
Description=VirusTotal check for browser downloads
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart={systemd_quote(sys.executable)} {systemd_quote(str(script))}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=graphical-session.target
""")
    systemctl("daemon-reload")
    systemctl("enable", "vt-quarantine.service")
    systemctl("restart", "vt-quarantine.service")
    return "journalctl --user -u vt-quarantine -f"


def autostart_linux_packaged():
    """Turn on the service the package installed, for this user only."""
    if UNIT_FILE.exists():
        if UNIT_MARKER not in UNIT_FILE.read_text():
            sys.exit(f"{UNIT_FILE} would be used instead of the packaged service; "
                     "remove it first (and the copy of vt-quarantine it starts).")
        # Left by --install of a downloaded copy; the package replaces it.
        systemctl("disable", "vt-quarantine.service", check=False)
        UNIT_FILE.unlink()
        INSTALLED_SCRIPT.unlink(missing_ok=True)
    systemctl("daemon-reload")
    systemctl("enable", "vt-quarantine.service")
    systemctl("restart", "vt-quarantine.service")
    return "journalctl --user -u vt-quarantine -f"


def app_bundle():
    """The macOS app this copy runs from, or None."""
    here = Path(__file__).resolve().parent
    if MACOS and here.name == "Resources" and here.parent.name == "Contents":
        return here.parent.parent
    return None


def installed_version():
    try:
        m = re.search(r'^VERSION = "([0-9.]+)"$', INSTALLED_SCRIPT.read_text(), re.M)
    except (OSError, UnicodeDecodeError):
        return None
    return parse_version(m.group(1)) if m else None


def copy_app_python(bundle):
    """The app's Python for this Mac, next to the program's data. Copied as plain
    files, so the download's quarantine flag doesn't come along."""
    arch = "arm64" if platform.machine() == "arm64" else "x86_64"
    dest = MAC_PYTHON.parent.parent
    new = dest.with_name("python.new")
    shutil.rmtree(new, ignore_errors=True)
    shutil.copytree(bundle / "Contents" / "Resources" / f"python-{arch}", new, copy_function=shutil.copy)
    shutil.copy(new / "bin" / "python3", new / "bin" / MAC_PYTHON.name)
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(new, dest)


def install_app():
    """Opening the macOS app: install from it, or, with this version (or a newer
    one) installed already, say so and offer to remove it."""
    dialogs = MacNotifier()

    def tell(title, text, buttons=(("ok", "OK"),)):
        return dialogs.notify(title, text, "critical", "", list(buttons))

    bundle = app_bundle()
    if move_to_applications(bundle):
        return 0  # it opens again from there
    installed = installed_version()
    if LAUNCH_AGENT.exists() and installed and installed >= parse_version(VERSION):
        remember_app_place(bundle)
        if tell(f"{APP} is running", f"Every download saved to {QUARANTINE} is checked on VirusTotal "
                "before it reaches your Downloads folder.", [("ok", "OK"), ("remove", "Uninstall…")]) == "remove" \
                and tell("Remove vt-quarantine?", "Your browsers get their download folder back, and your API key "
                         "and settings are deleted. Files in quarantine stay where they are.",
                         [("cancel", "Cancel"), ("remove", "Remove")]) == "remove":
            with contextlib.redirect_stdout(io.StringIO()):
                uninstall()
            tell("vt-quarantine is removed", "You can move this app to the Trash.")
        return 0
    try:
        copy_app_python(bundle)
        with contextlib.redirect_stdout(io.StringIO()):
            install()
    except (OSError, SystemExit) as e:
        tell(f"{APP} couldn't be installed", str(getattr(e, "code", None) or e))
        return 1
    removal = ("To remove it, drag VirusTotal Quarantine to the Trash, or open Uninstall VirusTotal Quarantine."
               if remember_app_place(bundle) else
               "Move this app to your Applications folder: then dragging it to the Trash removes vt-quarantine. "
               "Or open Uninstall VirusTotal Quarantine (in Applications) any time.")
    tell(f"{APP} is running", "It starts by itself when you sign in, and checks every download before it "
         f"reaches your Downloads folder.\n\n{removal}")
    return 0


def in_applications(bundle):
    """Kept in an Applications folder (not run from Downloads, which macOS runs
    from a temporary copy)."""
    path = str(bundle)
    return "/AppTranslocation/" not in path and \
        (path.startswith("/Applications/") or path.startswith(str(HOME / "Applications") + "/"))


def is_our_app(bundle):
    import plistlib
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as f:
            return plistlib.load(f).get("CFBundleIdentifier") == APP_BUNDLE_ID
    except (OSError, ValueError):
        return False


def move_to_applications(bundle):
    """Opened where Safari unpacked it (Downloads): move the app to Applications, so
    the Trash can remove vt-quarantine, and open it from there. Returns whether it did."""
    if bundle is None or in_applications(bundle):
        return False
    original = HOME / "Downloads" / f"{APP}.app"
    if not is_our_app(original):
        return False
    folder = Path("/Applications") if os.access("/Applications", os.W_OK) else HOME / "Applications"
    target = folder / original.name
    try:
        folder.mkdir(exist_ok=True)
        if target.exists():
            if not is_our_app(target):
                return False
            shutil.rmtree(target)  # an older copy
        shutil.move(str(original), str(target))
        # Moved by anything but Finder, macOS would keep running it from a temporary
        # copy. It's been allowed to open (it's running), so the download mark can go.
        subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(target)], capture_output=True)
        subprocess.Popen(["open", "-n", str(target)])  # -n: this copy is still running
    except OSError as e:
        log(f"could not move the app to {folder}: {e}")
        return False
    return True


def remember_app_place(bundle):
    """Note where the app is kept, so putting it in the Trash uninstalls. Returns
    whether it's somewhere that works."""
    if bundle is None or not in_applications(bundle):
        return False
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    APP_PLACE.write_text(str(bundle))
    return True


def app_copies():
    """Where Spotlight knows the app to be (not in the Trash)."""
    try:
        out = subprocess.run(["mdfind", f"kMDItemCFBundleIdentifier == '{APP_BUNDLE_ID}'"],
                             capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [Path(line) for line in out.splitlines() if line.endswith(".app") and "/.Trash/" not in line]


def app_thrown_away(missing_before):
    """One check of the kept app: True once it has been gone (and nowhere else)
    for two checks in a row, which means it went in the Trash."""
    try:
        place = Path(APP_PLACE.read_text().strip())
    except OSError:
        return False
    if place.exists():
        return False
    moved = [copy for copy in app_copies() if copy.exists() and in_applications(copy)]
    if moved:
        APP_PLACE.write_text(str(moved[0]))
        log(f"the app moved to {moved[0]}")
        return False
    return missing_before


def watch_app():
    """macOS, background: the app put in the Trash removes vt-quarantine."""
    missing = False
    while True:
        time.sleep(60 if not missing else 120)
        try:
            was_missing = missing
            missing = not Path(APP_PLACE.read_text().strip()).exists() if APP_PLACE.exists() else False
            if missing and app_thrown_away(was_missing):
                log("the app is in the Trash: removing vt-quarantine")
                with contextlib.redirect_stdout(io.StringIO()):
                    uninstall(stop=False)
                subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCH_AGENT_LABEL}"],
                               capture_output=True)  # last: this ends the program
                return
        except Exception as e:
            log(f"app check failed: {e}")


UNINSTALLER_SCRIPT = """#!/bin/sh
# Opens vt-quarantine's own uninstall question.
exec {python} {script} --uninstall-app
"""


def make_uninstaller():
    """macOS: "Uninstall VirusTotal Quarantine" in ~/Applications, a few lines of
    script that run the installed copy's uninstall."""
    import plistlib
    import shlex
    python = MAC_PYTHON if MAC_PYTHON.exists() else Path(sys.executable)
    new = UNINSTALLER.with_name(UNINSTALLER.name + ".new")
    shutil.rmtree(new, ignore_errors=True)
    (new / "Contents" / "MacOS").mkdir(parents=True)
    (new / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleName": UNINSTALLER.stem, "CFBundleIdentifier": APP_BUNDLE_ID + ".uninstall",
        "CFBundleExecutable": "uninstall", "CFBundlePackageType": "APPL", "CFBundleVersion": VERSION,
        "CFBundleShortVersionString": VERSION, "LSUIElement": True}))
    launcher = new / "Contents" / "MacOS" / "uninstall"
    launcher.write_text(UNINSTALLER_SCRIPT.format(python=shlex.quote(str(python)),
                                                  script=shlex.quote(str(INSTALLED_SCRIPT))))
    launcher.chmod(0o755)
    bundle = app_bundle()
    icon = bundle / "Contents" / "Resources" / "vt-quarantine.icns" if bundle else None
    if icon and icon.exists():
        (new / "Contents" / "Resources").mkdir()
        shutil.copy(icon, new / "Contents" / "Resources" / "vt-quarantine.icns")
        with open(new / "Contents" / "Info.plist", "rb") as f:
            info = plistlib.load(f)
        info["CFBundleIconFile"] = "vt-quarantine.icns"
        (new / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
    shutil.rmtree(UNINSTALLER, ignore_errors=True)
    os.replace(new, UNINSTALLER)


def uninstall_app():
    """The uninstaller app: ask, then remove everything (the app too)."""
    dialogs = MacNotifier()
    if dialogs.notify("Remove vt-quarantine?", "Your browsers get their download folder back, and your API key "
                      "and settings are deleted. Files in quarantine stay where they are.", "critical", "",
                      [("cancel", "Cancel"), ("remove", "Remove")]) != "remove":
        return 0
    with contextlib.redirect_stdout(io.StringIO()):
        uninstall()
    dialogs.notify("vt-quarantine is removed", "", "critical", "", [("ok", "OK")])
    return 0


def autostart_macos(script):
    import plistlib
    LAUNCH_AGENT.parent.mkdir(parents=True, exist_ok=True)
    with open(LAUNCH_AGENT, "wb") as f:
        plistlib.dump({
            "Label": LAUNCH_AGENT_LABEL,
            "ProgramArguments": [str(MAC_PYTHON if MAC_PYTHON.exists() else sys.executable), str(script)],
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Interactive",
            "StandardOutPath": str(LOG_FILE),
            "StandardErrorPath": str(LOG_FILE),
        }, f)
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", f"{domain}/{LAUNCH_AGENT_LABEL}"], capture_output=True)
    subprocess.run(["launchctl", "bootstrap", domain, str(LAUNCH_AGENT)], check=True, capture_output=True)
    return str(LOG_FILE)


def autostart_windows(script):
    """Per-user Run key (no admin needed), then start it now."""
    import winreg
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "vt-quarantine", 0, winreg.REG_SZ, f'"{pythonw}" "{script}"')
    # Listed under Settings > Apps, so it can be removed like any other program.
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY, 0, winreg.KEY_SET_VALUE) as key:
        for name, value in (("DisplayName", APP), ("DisplayVersion", VERSION),
                            ("Publisher", "vt-quarantine"), ("InstallLocation", str(DATA_DIR)),
                            ("UninstallString", f'"{sys.executable}" "{script}" --uninstall')):
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        for name in ("NoModify", "NoRepair"):
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 1)
    stop_running()  # an older copy, so the new one can take over
    subprocess.Popen([str(pythonw), str(script)], close_fds=True, cwd=str(DATA_DIR),
                     creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
    return str(LOG_FILE)


def stop_running():
    """Stop a running instance found through the lock (Windows has no service manager here)."""
    import signal
    lock = acquire_lock()
    if lock:
        lock.close()  # nothing running
        return
    # The lock is held, so the pid file belongs to the running instance.
    try:
        pid = int((DATA_DIR / "pid").read_text())
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            lock = acquire_lock()
            if lock:
                lock.close()
                break
            time.sleep(0.1)
        print(f"Stopped the running copy (pid {pid}).")
    except (OSError, ValueError) as e:
        print(f"Could not stop the running copy ({e}).")


def setup_installed():
    if not WINDOWS:
        return False
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETUP_KEY))
        return True
    except OSError:
        return False


def install():
    refuse_root()
    if setup_installed():
        sys.exit("vt-quarantine was installed with its Windows installer (.msi). Run a newer one to\n"
                 "update, or remove it under Settings > Apps first.")
    if WINDOWS and "WindowsApps" in sys.executable:
        print("Warning: this is the Microsoft Store Python, which may keep the autostart and\n"
              "notification settings to itself. If vt-quarantine doesn't start at sign-in,\n"
              "install Python from https://www.python.org/downloads/ and run this again.")
    print("Checking requirements...")
    if not install_requirements():
        sys.exit("The packages it needs are missing (see above)." if packaged() else
                 "Could not download the required packages (see above). Check your connection and try again.")
    try:
        make_notifier()  # fails early if notifications can't work; on Windows registers the toast name
    except Exception as e:
        sys.exit(f"Notifications don't work here ({e}), and vt-quarantine needs them to ask you things.")
    try:
        if not read_key():
            if MACOS:
                mac_key_dialog()  # Cancel: it asks again when it starts
            else:
                set_key()
    except KeyStoreLocked:
        print("Your API key is in your password store, which stayed locked; vt-quarantine\n"
              "will ask to unlock it when it starts.")
    make_quarantine()
    if packaged():
        logs = autostart_linux_packaged()
        removal = ("To turn it off: vt-quarantine --uninstall\n"
                   "(then remove the vt-quarantine package with your package manager)")
    else:
        script = copy_self()
        if WINDOWS:
            logs = autostart_windows(script)
        elif MACOS:
            logs = autostart_macos(script)
            make_uninstaller()
        else:
            logs = autostart_linux(script)
        remove_old_libs()
        removal = "To remove it later: run this script with --uninstall"
    print(f"""
vt-quarantine is running and starts automatically when you sign in.

It sets up {'Safari, ' if MACOS else ''}Chrome, Edge, Brave, Opera, Chromium, Vivaldi, Firefox,
Waterfox, LibreWolf and Floorp by itself: restart any that are open.
Any other browser: set its download folder to
    {QUARANTINE}

Log: {logs}
{removal}""")


def updating():
    """An update this copy started within the last quarter of an hour (Windows)."""
    try:
        return time.time() - UPDATING_MARKER.stat().st_mtime < 15 * 60
    except OSError:
        return False


def remove_mac_apps():
    """The uninstaller, and the app where it was kept (if it's still ours)."""
    shutil.rmtree(UNINSTALLER, ignore_errors=True)
    try:
        bundle = Path(APP_PLACE.read_text().strip())
    except OSError:
        return
    if is_our_app(bundle) and in_applications(bundle):
        shutil.rmtree(bundle, ignore_errors=True)


def uninstall(keep_data=False, stop=True):
    keep_data = keep_data or updating()
    if WINDOWS:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "vt-quarantine")
        except FileNotFoundError:
            pass
        for path in (AUMID_KEY, UNINSTALL_KEY):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except FileNotFoundError:
                pass
        stop_running()
    elif MACOS:
        if stop:  # not when the program removes itself (it stops last)
            subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCH_AGENT_LABEL}"], capture_output=True)
        LAUNCH_AGENT.unlink(missing_ok=True)
    elif UNIT_FILE.exists():
        if UNIT_MARKER not in UNIT_FILE.read_text():
            sys.exit(f"{UNIT_FILE} wasn't written by --install; remove it yourself.")
        systemctl("disable", "--now", "vt-quarantine.service", check=False)
        UNIT_FILE.unlink()
        systemctl("daemon-reload", check=False)
    elif packaged():
        systemctl("disable", "--now", "vt-quarantine.service", check=False)
    INSTALLED_SCRIPT.unlink(missing_ok=True)
    print("vt-quarantine is stopped and no longer starts at sign-in.")
    if packaged():
        print("The program itself stays installed; remove the vt-quarantine package to remove it.")
    if keep_data:  # stopped for an upgrade, which keeps everything
        return
    # Forget everything: browser settings put back, files in quarantine unlocked, and
    # the API key, settings, log and downloaded packages deleted. Never the downloads.
    left = undo_browser_setup()
    unlock_quarantine()
    forget_key()
    if MACOS:
        remove_mac_apps()
    for d in (CONFIG_DIR, DATA_DIR):
        shutil.rmtree(d, ignore_errors=True)
    if not left:
        with contextlib.suppress(OSError):
            QUARANTINE.rmdir()  # only if empty
    if WINDOWS and QUARANTINE.is_dir():
        # Left behind (with files, or because a browser still saves there): in sight,
        # so nothing seems lost.
        set_hidden(QUARANTINE, False)
    print("Deleted your API key, settings and log.")
    if QUARANTINE.is_dir() and any(QUARANTINE.iterdir()):
        print(f"Files still in quarantine are unlocked and left in place: {QUARANTINE}")


def check():
    """Fetch what's missing and make sure notifications work, without running."""
    print(f"vt-quarantine {VERSION}, Python {platform.python_version()} on {sys.platform}\n"
          f"quarantine folder: {QUARANTINE}\nmoved to:          {RELEASE_DIR}\n"
          f"API key:           {key_status()}\n"
          f"packages folder:   {lib_dir() if pinned_wheels() else '(none needed)'}")
    if not install_requirements():
        return 1
    global api_key
    with contextlib.suppress(KeyStoreLocked):
        api_key = read_key()
    if api_key:  # informational: a failed check doesn't fail --check
        print(f"VirusTotal requests: {quota_line()}")
    try:
        make_notifier()
    except Exception as e:
        print(f"notifications: NOT working ({type(e).__name__}: {e})")
        return 1
    print("notifications: ok")
    return 0


def test_notification():
    global notifier
    if not install_requirements():
        return 1
    notifier = make_notifier()
    choice = notifier.notify("Test notification", "Pick a button to check that they work.",
                             "critical", "dialog-question", [("one", "One"), ("two", "Two")])
    print(f"You picked: {choice or '(dismissed)'}")
    return 0
