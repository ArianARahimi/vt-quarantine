#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Browser setup -----------------------------------------------------------------
# Every browser profile found is pointed at the quarantine folder: Firefox-based ones
# through user.js, Chromium-based ones through their Preferences file (while closed),
# Safari through `defaults`. A default browser that can't be set up gets a notification
# telling how. --uninstall puts everything back as it was.

BROWSER_SETUP = CONFIG_DIR / "browser-setup.json"  # what the browser setup changed
USER_JS_BEGIN = "// vt-quarantine: begin (vt-quarantine --uninstall removes this)"
USER_JS_END = "// vt-quarantine: end"
USER_JS_RESTORE = ("// vt-quarantine was uninstalled while this browser was open: these lines put the\n"
                   "// download settings back as they were. Delete them once it has restarted.")
DOWNLOAD_PREFS = ("browser.download.folderList", "browser.download.dir", "browser.download.useDownloadDir",
                  "browser.download.lastDir", "browser.download.lastDir.savePerSite")
PREF_LINE = re.compile(r'^\s*user_pref\("([^"\\]+)",\s*(.*?)\);[ \t]*$', re.M)
BROWSER_HELP = f"https://github.com/{REPO}/blob/stable/docs/GUIDE.md#browser-setup"


def firefox_profile_roots():
    """(browser, folder that may hold a profiles.ini) for Firefox and browsers built on it."""
    if WINDOWS:
        base = Path(os.environ.get("APPDATA") or HOME / "AppData" / "Roaming")
        return [("Firefox", base / "Mozilla" / "Firefox"), ("Waterfox", base / "Waterfox"),
                ("LibreWolf", base / "librewolf"), ("Floorp", base / "Floorp")]
    if MACOS:
        base = HOME / "Library" / "Application Support"
        return [("Firefox", base / "Firefox"), ("Waterfox", base / "Waterfox"),
                ("LibreWolf", base / "librewolf"), ("Floorp", base / "Floorp")]
    flatpak = HOME / ".var" / "app"
    return [("Firefox", HOME / ".mozilla" / "firefox"),
            ("Firefox", xdg_config() / "mozilla" / "firefox"),
            ("Firefox", HOME / "snap" / "firefox" / "common" / ".mozilla" / "firefox"),
            ("Firefox", flatpak / "org.mozilla.firefox" / ".mozilla" / "firefox"),
            ("Waterfox", HOME / ".waterfox"),
            ("Waterfox", flatpak / "net.waterfox.waterfox" / ".waterfox"),
            ("LibreWolf", HOME / ".librewolf"),
            ("LibreWolf", flatpak / "io.gitlab.librewolf-community" / ".librewolf"),
            ("Floorp", HOME / ".floorp"),
            ("Floorp", flatpak / "one.ablaze.floorp" / ".floorp")]


def firefox_profiles(only=None):
    """(browser, profile folder) for every profile listed in a profiles.ini (of the
    browser named `only`, if given)."""
    found = []
    for browser, root in firefox_profile_roots():
        if only and browser != only:
            continue
        ini = configparser.ConfigParser(interpolation=None)
        try:
            ini.read(root / "profiles.ini", encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError) as e:
            log(f"could not read {root / 'profiles.ini'}: {e}")
            continue
        for section in ini.sections():
            if not section.startswith("Profile") or not ini.get(section, "Path", fallback=""):
                continue
            path = ini.get(section, "Path")
            folder = root / path if ini.get(section, "IsRelative", fallback="1") == "1" else Path(path)
            if folder.is_dir() and all(folder != f for _, f in found):
                found.append((browser, folder))
    return found


def read_prefs(file):
    """{pref: value as written} from a prefs.js or user.js (later lines win)."""
    try:
        return dict(PREF_LINE.findall(file.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError):
        return {}


def js_string(value):
    return json.dumps(str(value), ensure_ascii=False)


def same_path(value):
    """Is this (a str) the quarantine folder?"""
    return isinstance(value, str) and os.path.normcase(os.path.normpath(value)) == \
        os.path.normcase(os.path.normpath(str(QUARANTINE)))


def is_quarantine(value):
    """Is this pref value (a JS string) the quarantine folder?"""
    try:
        return same_path(json.loads(value))
    except (TypeError, ValueError):
        return False


def write_json(path, data):
    tmp = path.with_name(path.name + ".vtq-new")
    tmp.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def read_handlers(folder):
    """A Firefox-based profile's handlers.json as a dict ({} if missing or empty)."""
    try:
        text = (folder / "handlers.json").read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    data = json.loads(text) if text.strip() else {}  # empty: no file types set yet
    if not isinstance(data, dict):
        raise ValueError("handlers.json isn't an object")
    return data


def setup_firefox_profile(folder):
    """Point one profile's downloads at the quarantine folder. Returns its earlier
    values of those settings, or None if it was pointed there already."""
    user_js = folder / "user.js"
    current = {**read_prefs(folder / "prefs.js"), **read_prefs(user_js)}
    if current.get("browser.download.folderList") == "2" and is_quarantine(current.get("browser.download.dir")):
        return None
    before = {k: v for k, v in read_prefs(folder / "prefs.js").items() if k in DOWNLOAD_PREFS}
    q = js_string(QUARANTINE)
    block = [USER_JS_BEGIN,
             'user_pref("browser.download.folderList", 2);',
             f'user_pref("browser.download.dir", {q});',
             'user_pref("browser.download.useDownloadDir", true);',
             # Save As dialogs start there too, not in the last folder used on a site.
             f'user_pref("browser.download.lastDir", {q});',
             'user_pref("browser.download.lastDir.savePerSite", false);',
             USER_JS_END]
    try:
        text = user_js.read_text(encoding="utf-8")
    except FileNotFoundError:
        text = ""
    if text and not text.endswith("\n"):
        text += "\n"
    user_js.write_text(text + "\n".join(block) + "\n", encoding="utf-8")
    return before


def profile_in_use(folder):
    """Is a browser running with this profile? (It rewrites prefs.js when it quits.)"""
    lock = folder / ("parent.lock" if WINDOWS else ".parentlock")
    try:
        if WINDOWS:
            # The browser holds it open without sharing.
            with open(lock, "r+"):
                return False
        import fcntl
        with open(lock, "r+") as f:
            try:
                fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.lockf(f, fcntl.LOCK_UN)
            return False
    except FileNotFoundError:
        return False
    except PermissionError:
        return True


def firefox_auto_open_off(folder):
    """Firefox-based: file types set to open in an app without asking ("Always open
    similar files") are saved instead, since they'd open before they're checked.
    Returns {type: its handler before} for those changed. Only while it's closed."""
    data = read_handlers(folder)
    changed = {}
    types = data.get("mimeTypes")
    for mime, handler in (types.items() if isinstance(types, dict) else ()):
        # 2: a chosen app, 4: the system's default app; 3 (in the browser) is left.
        if isinstance(handler, dict) and handler.get("action") in (2, 4) and not handler.get("ask"):
            changed[mime] = dict(handler)
            handler["action"] = 0  # save
    if changed:
        write_json(folder / "handlers.json", data)
    return changed


def undo_firefox_handlers(folder, before):
    """Put back the file handlers firefox_auto_open_off() changed, where they're
    still "save" (only with the browser closed: it keeps its own copy)."""
    if not before or profile_in_use(folder):
        return
    try:
        data = read_handlers(folder)
    except (OSError, ValueError):
        return
    types = data.get("mimeTypes")
    if not isinstance(types, dict):
        return
    for mime, handler in before.items():
        if isinstance(types.get(mime), dict) and types[mime].get("action") == 0:
            types[mime] = handler
    write_json(folder / "handlers.json", data)


def undo_firefox_profile(folder, before):
    """Take the setup out of user.js and put the earlier download settings back."""
    user_js = folder / "user.js"
    try:
        text = user_js.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    text = re.sub(rf"^{re.escape(USER_JS_BEGIN)}\n.*?^{re.escape(USER_JS_END)}\n?", "", text, flags=re.M | re.S)
    # The browser copied the settings into prefs.js, so taking them out of user.js
    # isn't enough. While it's closed, prefs.js can be put back as it was.
    prefs = folder / "prefs.js"
    if not profile_in_use(folder):
        try:
            lines = prefs.read_text(encoding="utf-8").splitlines(keepends=True)
        except FileNotFoundError:
            lines = []
        except (OSError, UnicodeDecodeError):
            lines = None
        if lines is not None:
            kept = [line for line in lines
                    if not (m := PREF_LINE.match(line)) or m.group(1) not in DOWNLOAD_PREFS]
            kept += [f'user_pref("{k}", {v});\n' for k, v in before.items()]
            if lines:
                prefs.write_text("".join(kept), encoding="utf-8")
            if text.strip():
                user_js.write_text(text, encoding="utf-8")
            else:
                user_js.unlink()  # it only ever held the setup
            return
    # Open: it would write its current settings back over prefs.js when it quits, so
    # set the earlier ones (or the defaults) through user.js once more.
    defaults = {"browser.download.folderList": "1", "browser.download.useDownloadDir": "true",
                "browser.download.lastDir": js_string(RELEASE_DIR),
                "browser.download.lastDir.savePerSite": "true"}
    own = dict(PREF_LINE.findall(text))  # the user's own settings, left in charge
    restore = [f'user_pref("{k}", {before.get(k, defaults.get(k))});' for k in DOWNLOAD_PREFS
               if k not in own and (k in before or k in defaults)]
    if text and not text.endswith("\n"):
        text += "\n"
    user_js.write_text(text + "\n".join([USER_JS_RESTORE, *restore]) + "\n", encoding="utf-8")


def chromium_roots():
    """(browser, user data folder) for the Chromium-based browsers set up from outside
    (Opera keeps its own in the roaming part of AppData)."""
    if WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or HOME / "AppData" / "Local")
        roaming = Path(os.environ.get("APPDATA") or HOME / "AppData" / "Roaming")
        return [("Chrome", base / "Google" / "Chrome" / "User Data"),
                ("Edge", base / "Microsoft" / "Edge" / "User Data"),
                ("Chrome", base / "Google" / "Chrome Beta" / "User Data"),
                ("Chrome", base / "Google" / "Chrome SxS" / "User Data"),
                ("Chromium", base / "Chromium" / "User Data"),
                ("Brave", base / "BraveSoftware" / "Brave-Browser" / "User Data"),
                ("Vivaldi", base / "Vivaldi" / "User Data"),
                ("Opera", roaming / "Opera Software" / "Opera Stable"),
                ("Opera GX", roaming / "Opera Software" / "Opera GX Stable")]
    if MACOS:
        base = HOME / "Library" / "Application Support"
        return [("Chrome", base / "Google" / "Chrome"), ("Chrome", base / "Google" / "Chrome Beta"),
                ("Edge", base / "Microsoft Edge"),
                ("Chromium", base / "Chromium"), ("Brave", base / "BraveSoftware" / "Brave-Browser"),
                ("Vivaldi", base / "Vivaldi"), ("Opera", base / "com.operasoftware.Opera"),
                ("Opera GX", base / "com.operasoftware.OperaGX")]
    config = xdg_config()
    flatpak = HOME / ".var" / "app"
    return [("Chrome", config / "google-chrome"), ("Chrome", config / "google-chrome-beta"),
            ("Chrome", config / "google-chrome-unstable"), ("Chromium", config / "chromium"),
            ("Brave", config / "BraveSoftware" / "Brave-Browser"), ("Vivaldi", config / "vivaldi"),
            ("Opera", config / "opera"), ("Opera", flatpak / "com.opera.Opera" / "config" / "opera"),
            ("Edge", config / "microsoft-edge"), ("Edge", flatpak / "com.microsoft.Edge" / "config" / "microsoft-edge"),
            ("Chrome", flatpak / "com.google.Chrome" / "config" / "google-chrome"),
            ("Chromium", flatpak / "org.chromium.Chromium" / "config" / "chromium"),
            ("Brave", flatpak / "com.brave.Browser" / "config" / "BraveSoftware" / "Brave-Browser"),
            ("Chromium", HOME / "snap" / "chromium" / "common" / "chromium")]


def chromium_profiles():
    """(browser, user data folder, Preferences file) for every profile of every
    Chromium-based browser that has been started."""
    found = []
    for browser, root in chromium_roots():
        try:
            names = list(json.loads((root / "Local State").read_text(encoding="utf-8"))
                         .get("profile", {}).get("info_cache", {})) or ["Default"]
        except (OSError, ValueError, AttributeError):
            continue  # never started
        for name in names:
            prefs = root / name / "Preferences"
            if not prefs.is_file() and name == "Default":
                prefs = root / "Preferences"  # older Opera: the profile is the folder itself
            if prefs.is_file():
                found.append((browser, root, prefs))
    return found


# Edge on Windows: its Startup boost keeps it running with no window, so it's
# ended (only then) to change its settings.
def windows_processes():
    """Windows: {pid: (exe name, parent pid)} of every running process."""
    import ctypes
    from ctypes import wintypes as w

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", w.DWORD),
                    ("cntThreads", w.DWORD), ("th32ParentProcessID", w.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", w.DWORD), ("szExeFile", w.WCHAR * 260)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel32.CloseHandle.argtypes = (w.HANDLE,)
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    found = {}
    entry = PROCESSENTRY32W(ctypes.sizeof(PROCESSENTRY32W))
    ok = kernel32.Process32FirstW(w.HANDLE(snap), ctypes.byref(entry))
    while ok:
        found[entry.th32ProcessID] = (entry.szExeFile.lower(), entry.th32ParentProcessID)
        ok = kernel32.Process32NextW(w.HANDLE(snap), ctypes.byref(entry))
    kernel32.CloseHandle(w.HANDLE(snap))
    return found


def visible_window_pids():
    """Windows: the processes with a visible window on this desktop, or None if
    this program can't see the desktop (then it can't tell)."""
    import ctypes
    from ctypes import wintypes as w
    user32 = ctypes.WinDLL("user32")
    user32.GetShellWindow.restype = w.HWND
    if not user32.GetShellWindow():
        return None
    pids = set()

    @ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    def each(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            pid = w.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    user32.EnumWindows(each, 0)
    return pids


def end_edge_in_background():
    """Windows: Edge's Startup boost keeps it running with no window, so it's never
    closed long enough to be set up. If that's all that runs of it, end it (it
    starts again with Edge, or at the next sign-in) and return True."""
    import ctypes
    procs = windows_processes()
    edge = {pid for pid, (name, _) in procs.items() if name == "msedge.exe"}
    if not edge:
        return False
    shown = visible_window_pids()
    if shown is None or edge & shown:
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    for pid in edge:
        if procs[pid][1] in edge:
            continue  # a helper: goes with the main one
        handle = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if handle:
            kernel32.TerminateProcess(ctypes.c_void_p(handle), 0)
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    log("ended Edge's window-less Startup boost process to change its settings")
    return True


def wait_closed(root, seconds=10):
    """Wait for a browser that was just ended to let go of its lock."""
    for _ in range(int(seconds / 0.2)):
        if not chromium_running(root):
            return True
        time.sleep(0.2)
    return False


def mark_clean_exit(prefs):
    """After ending Edge that way: its profile says it quit normally, so it doesn't
    offer to restore pages it never showed."""
    data = json.loads(prefs.read_text(encoding="utf-8"))
    profile = data.setdefault("profile", {})
    if isinstance(profile, dict) and profile.get("exit_type") != "Normal":
        profile["exit_type"] = "Normal"
        profile["exited_cleanly"] = True
        write_json(prefs, data)


def edge_on_windows(browser):
    return WINDOWS and browser == "Edge"


def end_edge(root):
    """Edge never closes for good (Startup boost): end it while it has no window."""
    return end_edge_in_background() and wait_closed(root)


def flatpak_app(folder):
    """The Flatpak app a folder under ~/.var/app belongs to, if it does."""
    try:
        return Path(folder).relative_to(HOME / ".var" / "app").parts[0]
    except (ValueError, IndexError):
        return None


def chromium_running(root):
    """Is the browser using this user data folder running? (It writes Preferences
    from memory, so changes made meanwhile would be lost.)"""
    if WINDOWS:
        try:  # held open without sharing while it runs
            with open(root / "lockfile", "r+"):
                return False
        except FileNotFoundError:
            return False
        except PermissionError:
            return True
    # A symlink to "<host>-<pid>", removed when it quits. One left behind by a crash
    # names a process that's gone (checked the way the browser itself does).
    try:
        target = os.readlink(root / "SingletonLock")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    app = flatpak_app(root)
    if app:  # its pid is the sandbox's own: ask Flatpak
        try:
            out = subprocess.run(["flatpak", "ps", "--columns=application"], capture_output=True,
                                 text=True, timeout=20, check=True).stdout
        except (OSError, subprocess.SubprocessError):
            return True
        return app in out.split()
    host, _, pid = target.rpartition("-")
    if host != platform.node() or not pid.isdigit():
        return True  # another computer sharing the folder: can't tell
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except OSError:
        pass  # exists, someone else's
    return True


CHROMIUM_PREFS = ("download.default_directory", "download.directory_upgrade",
                  "download.prompt_for_download", "download.extensions_to_open",
                  "savefile.default_directory")


def chromium_download(prefs):
    """The "download" section of a Chromium Preferences file ({} if unreadable)."""
    try:
        data = json.loads(prefs.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    download = data.get("download") if isinstance(data, dict) else None
    return download if isinstance(download, dict) else {}


def chromium_points_here(prefs):
    return same_path(chromium_download(prefs).get("default_directory"))


def setup_chromium_profile(prefs):
    """Downloads (and Save as) of a closed Chromium-based browser profile go to
    quarantine, without asking where. Returns the settings it had ({pref: value}),
    or None if it already pointed there."""
    data = json.loads(prefs.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not a preferences file")
    download, savefile = data.get("download"), data.get("savefile")
    download = download if isinstance(download, dict) else {}
    savefile = savefile if isinstance(savefile, dict) else {}
    if same_path(download.get("default_directory")):
        return None
    sections = {"download": download, "savefile": savefile}
    before = {}
    for key in CHROMIUM_PREFS:
        section, name = key.split(".")
        if name in sections[section]:
            before[key] = sections[section][name]
    # No type opens by itself ("Always open files of this type"): it would open
    # before it's checked.
    download.update(default_directory=str(QUARANTINE), directory_upgrade=True, prompt_for_download=False,
                    extensions_to_open="")
    savefile["default_directory"] = str(QUARANTINE)
    data["download"], data["savefile"] = download, savefile
    write_json(prefs, data)
    return before


def chromium_wants_auto_open(prefs):
    return bool(chromium_download(prefs).get("extensions_to_open"))


def chromium_auto_open_off(prefs):
    """Empty a closed Chromium-based browser's list of file types it opens by itself
    once downloaded. True if there was one."""
    data = json.loads(prefs.read_text(encoding="utf-8"))
    download = data.get("download") if isinstance(data, dict) else None
    if not isinstance(download, dict) or not download.get("extensions_to_open"):
        return False
    download["extensions_to_open"] = ""
    write_json(prefs, data)
    return True


def undo_chromium_profile(prefs, before):
    """Put back what setup_chromium_profile() changed, unless the download folder was
    changed since. Only with the browser closed (it would write over the change)."""
    data = json.loads(prefs.read_text(encoding="utf-8"))
    download = data.get("download") if isinstance(data, dict) else None
    if not isinstance(download, dict) or not same_path(download.get("default_directory")):
        return  # changed by hand since: leave it
    for key in CHROMIUM_PREFS:
        section, name = key.split(".")
        part = data.setdefault(section, {})
        if key in before:
            part[name] = before[key]
        else:
            part.pop(name, None)
        if not part:
            del data[section]
    write_json(prefs, data)


# Safari (macOS) keeps its settings in a preferences domain that `defaults` can change
# while it's closed: where downloads go, and whether "safe" files open by themselves.
SAFARI = "com.apple.Safari"
SAFARI_KEYS = ("DownloadsPath", "AutoOpenSafeDownloads")


def safari_running():
    return subprocess.run(["pgrep", "-x", "Safari"], capture_output=True).returncode == 0


def safari_settings():
    """The current values of SAFARI_KEYS (None for one that isn't set)."""
    import plistlib
    out = subprocess.run(["defaults", "export", SAFARI, "-"], capture_output=True, check=True).stdout
    data = plistlib.loads(out) if out.strip() else {}
    return {key: data.get(key) for key in SAFARI_KEYS}


def safari_set(key, value):
    """Set one Safari setting, or remove it (value None) so Safari's default applies."""
    if value is None:
        subprocess.run(["defaults", "delete", SAFARI, key], capture_output=True)
        return
    kind = "-bool" if isinstance(value, bool) else "-string"
    subprocess.run(["defaults", "write", SAFARI, key, kind, str(value).lower() if kind == "-bool" else value],
                   capture_output=True, check=True)


def setup_safari():
    """Downloads into quarantine and no opening by themselves. Returns what was there."""
    before = safari_settings()
    safari_set("DownloadsPath", str(QUARANTINE))
    safari_set("AutoOpenSafeDownloads", False)
    return before


def undo_safari(before):
    if safari_settings().get("DownloadsPath") == str(QUARANTINE):  # not if changed by hand since
        safari_set("DownloadsPath", before.get("DownloadsPath"))
    safari_set("AutoOpenSafeDownloads", before.get("AutoOpenSafeDownloads"))


# Keywords in what the system names its default browser (a .desktop file on Linux, a
# ProgId on Windows, a bundle id on macOS), most specific first.
BROWSER_NAMES = (("waterfox", "Waterfox"), ("librewolf", "LibreWolf"), ("floorp", "Floorp"),
                 ("firefox", "Firefox"), ("chromium", "Chromium"), ("chrome", "Chrome"),
                 ("brave", "Brave"), ("edge", "Edge"), ("vivaldi", "Vivaldi"), ("operagx", "Opera GX"),
                 ("opera", "Opera"),
                 ("safari", "Safari"))
FIREFOX_BASED = ("Firefox", "Waterfox", "LibreWolf", "Floorp")


def default_browser_id():
    """What the system opens web links with."""
    if WINDOWS:
        import winreg
        key = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            return winreg.QueryValueEx(k, "ProgId")[0]
    if MACOS:
        import plistlib
        plist = HOME / "Library" / "Preferences" / "com.apple.LaunchServices" / \
            "com.apple.launchservices.secure.plist"
        with contextlib.suppress(FileNotFoundError), open(plist, "rb") as f:
            for handler in plistlib.load(f).get("LSHandlers", []):
                if handler.get("LSHandlerURLScheme") == "https":
                    return handler.get("LSHandlerRoleAll", "")
        return "com.apple.safari"  # nothing chosen
    for cmd in (["xdg-settings", "get", "default-web-browser"],
                ["xdg-mime", "query", "default", "x-scheme-handler/https"]):
        if shutil.which(cmd[0]):
            found = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
            if found:
                return found
    return ""


def default_browser():
    """The default browser's name, or None if it isn't one this knows."""
    try:
        ident = default_browser_id().lower().replace(" ", "")  # "Opera GXStable"
    except Exception as e:
        log(f"could not find the default browser: {e}")
        return None
    return next((name for key, name in BROWSER_NAMES if key in ident), None)


def names(items):
    """"Chrome", "Chrome and Brave", "Chrome, Brave and Firefox"."""
    items = list(dict.fromkeys(items))
    return " and ".join(items) if len(items) < 3 else ", ".join(items[:-1]) + " and " + items[-1]


def browser_pass(record):
    """Send downloads of every browser profile not seen before to quarantine. A
    profile is set up once: if its folder is changed by hand later, that stays.
    Downloads opening by themselves are turned off again whenever a set-up browser
    is closed. Returns (browsers set up now, browsers waiting to be closed, browsers
    covered)."""
    record.setdefault("firefox", [])
    record.setdefault("chromium", [])
    set_up, waiting, covered = [], [], []
    setup_new_firefox(record, set_up, waiting, covered)
    firefox_auto_open_pass(record)
    chromium_auto_open_pass(record)
    setup_new_chromium(record, set_up, waiting, covered)
    if MACOS:
        safari_pass(record, set_up, waiting, covered)
    return set_up, waiting, covered


def safari_pass(record, set_up, waiting, covered):
    covered.append("Safari")
    if safari_running():
        if "safari" not in record:
            waiting.append("Safari")
        return
    try:
        if "safari" not in record:
            record["safari"] = {"before": setup_safari()}
            log("set up Safari")
            set_up.append("Safari")
        elif safari_settings().get("AutoOpenSafeDownloads") is not False:
            safari_set("AutoOpenSafeDownloads", False)
            log("Safari: safe downloads no longer open by themselves")
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        log(f"could not set up Safari: {e}")


def setup_new_firefox(record, set_up, waiting, covered):
    done = {entry["profile"] for entry in record["firefox"]}
    for browser, folder in firefox_profiles():
        covered.append(browser)
        if str(folder) in done:
            continue
        try:
            before = setup_firefox_profile(folder)
        except (OSError, ValueError) as e:
            log(f"could not set up {browser} profile {folder}: {e}")
            continue
        if before is not None:
            record["firefox"].append({"profile": str(folder), "before": before})
            log(f"set up {browser} profile {folder}")
            # Taken from user.js at its next start.
            (waiting if profile_in_use(folder) else set_up).append(browser)


handler_errors = set()  # (folder, error) already logged: the pass runs every few minutes


def firefox_auto_open_pass(record):
    for entry in record["firefox"]:
        folder = Path(entry["profile"])
        if not folder.is_dir() or profile_in_use(folder):
            continue
        try:
            for mime, handler in firefox_auto_open_off(folder).items():
                entry.setdefault("handlers_before", {}).setdefault(mime, handler)
                log(f"{folder.name}: {mime} downloads no longer open by themselves")
        except (OSError, ValueError) as e:
            if (folder, str(e)) not in handler_errors:
                handler_errors.add((folder, str(e)))
                log(f"could not read the file handlers of {folder}: {e}")


def chromium_auto_open_pass(record):
    for entry in record["chromium"]:
        prefs = Path(entry["prefs"])
        root = prefs.parent.parent
        if not prefs.is_file():
            continue
        try:
            if chromium_running(root):
                # Edge is ended only once it has saved a list of types to open.
                if not (edge_on_windows(entry.get("browser")) and chromium_wants_auto_open(prefs)
                        and end_edge(root)):
                    continue
                mark_clean_exit(prefs)
            if chromium_auto_open_off(prefs):
                log(f"{prefs.parent}: downloads no longer open by themselves")
        except (OSError, ValueError) as e:
            log(f"could not read {prefs}: {e}")


def setup_new_chromium(record, set_up, waiting, covered):
    done = {entry["prefs"] for entry in record["chromium"]}
    for browser, root, prefs in chromium_profiles():
        covered.append(browser)
        if str(prefs) in done or chromium_points_here(prefs):
            continue
        if chromium_running(root):  # asked once: on Flatpak each check starts a process
            if not (edge_on_windows(browser) and end_edge(root)):
                waiting.append(browser)
                continue
            with contextlib.suppress(OSError, ValueError):
                mark_clean_exit(prefs)
        try:
            before = setup_chromium_profile(prefs)
        except (OSError, ValueError) as e:
            log(f"could not set up {browser} profile {prefs.parent}: {e}")
            continue
        if before is not None:
            record["chromium"].append({"browser": browser, "prefs": str(prefs), "before": before})
            log(f"set up {browser} profile {prefs.parent}")
            set_up.append(browser)


# --- When a set-up browser stops saving into quarantine --------------------------------
# Its download folder changed in its own settings. That's the user's call: one notice
# per folder, "Put it back" or "Keep it", and nothing changes without an answer.
# Only profiles seen saving into quarantine count, so one set up while it was open
# (and not restarted yet) isn't mistaken for a change.

def firefox_browser(folder):
    """Which Firefox-based browser a profile folder belongs to."""
    for browser, root in firefox_profile_roots():
        if root in Path(folder).parents:
            return browser
    return "Firefox"


def firefox_folder(folder):
    """Where a profile saves downloads (None: quarantine). Open, its prefs.js is current;
    closed, user.js decides again at the next start."""
    prefs = read_prefs(folder / "prefs.js")
    if not profile_in_use(folder):
        prefs.update(read_prefs(folder / "user.js"))
    kind = prefs.get("browser.download.folderList", "1")
    if kind == "2":
        value = prefs.get("browser.download.dir")
        if is_quarantine(value):
            return None
        try:
            return str(json.loads(value))
        except (TypeError, ValueError):
            return "another folder"
    return str(DESKTOP_DIR if kind == "0" else RELEASE_DIR)


def chromium_folder(prefs):
    folder = chromium_download(prefs).get("default_directory")
    if same_path(folder):
        return None
    return folder if isinstance(folder, str) and folder else str(RELEASE_DIR)


def safari_folder():
    folder = safari_settings().get("DownloadsPath")
    return None if same_path(folder) else str(folder or RELEASE_DIR)


def remove_user_js_block(folder):
    """Take vt-quarantine's lines out of a profile's user.js."""
    user_js = folder / "user.js"
    try:
        text = user_js.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    text = re.sub(rf"^{re.escape(USER_JS_BEGIN)}\n.*?^{re.escape(USER_JS_END)}\n?", "", text, flags=re.M | re.S)
    if text.strip():
        user_js.write_text(text, encoding="utf-8")
    else:
        user_js.unlink()


def drift_checks(record):
    """(record entry, browser, where it saves now, is it open) for each set-up browser."""
    for entry in record.get("firefox", []):
        folder = Path(entry["profile"])
        if folder.is_dir():
            yield entry, firefox_browser(folder), lambda f=folder: firefox_folder(f), lambda f=folder: profile_in_use(f)
    for entry in record.get("chromium", []):
        prefs = Path(entry["prefs"])
        if prefs.is_file():
            yield (entry, entry.get("browser", "Your browser"), lambda p=prefs: chromium_folder(p),
                   lambda p=prefs: chromium_running(p.parent.parent))
    if MACOS and isinstance(record.get("safari"), dict):
        yield record["safari"], "Safari", safari_folder, safari_running


def drift_pass(record):
    for entry, browser, where, is_open in drift_checks(record):
        try:
            if entry.get("put_back") and not is_open():
                point_back(entry, browser)
                continue
            folder = where()
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            log(f"could not read {browser}'s download folder: {e}")
            continue
        if folder is None:
            entry["confirmed"] = True
            continue
        if not entry.get("confirmed") or entry.get("drift_answered") == folder:
            continue
        entry["drift_answered"] = folder
        log(f"{browser} now saves downloads to {folder}")
        wait_for_free_screen("browser notice")
        choice = notifier.notify(f"{browser} no longer downloads into quarantine",
                                 f"Its downloads now go to <b>{html.escape(folder)}</b> and aren't held "
                                 "until VirusTotal has checked them.", "normal", "dialog-warning",
                                 [("back", "Put it back"), ("keep", "Keep it")])
        try:
            if choice == "back":
                entry["put_back"] = True
                entry.pop("kept", None)
                if is_open():
                    if "profile" in entry:
                        point_back(entry, browser)  # user.js: taken at its next start anyway
                    else:
                        notifier.tell(f"{browser} goes back to quarantine once it's closed", "", "security-high")
                else:
                    point_back(entry, browser)
            else:  # "Keep it", or the notice closed: the choice stays
                entry["kept"] = True
                if "profile" in entry:
                    remove_user_js_block(Path(entry["profile"]))  # or its next start would undo it
                log(f"{browser}: kept saving downloads to {folder}")
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            log(f"could not change {browser}'s download folder: {e}")


def point_back(entry, browser):
    """Downloads of this browser go to quarantine again."""
    entry.pop("put_back", None)
    if "profile" in entry:
        folder = Path(entry["profile"])
        if setup_firefox_profile(folder) is not None or profile_in_use(folder):
            notifier.tell(f"{browser} downloads into quarantine again", f"Restart {browser} for this to take effect.",
                          "security-high")
            return
    elif "prefs" in entry:
        setup_chromium_profile(Path(entry["prefs"]))
    else:
        safari_set("DownloadsPath", str(QUARANTINE))
    log(f"{browser} downloads into quarantine again")
    notifier.tell(f"{browser} downloads into quarantine again", "", "security-high")


def save_browser_record(record):
    BROWSER_SETUP.parent.mkdir(parents=True, exist_ok=True)
    BROWSER_SETUP.write_text(json.dumps(record, indent=1))


def setup_browsers():
    """The first run: every browser's downloads go to quarantine, with one
    notification at most. Only a default browser that can't be set up from outside
    (or hasn't been started yet) brings the steps to do it by hand.
    Returns whether a browser still has to be closed for its setup."""
    browser = default_browser()
    record = {"browser": browser, "firefox": [], "chromium": []}
    set_up, waiting, covered = browser_pass(record)
    save_browser_record(record)
    wait_for_free_screen("browser setup")
    if browser not in covered:
        ask_to_set_folder(browser)
    elif set_up or waiting:
        restart = f"Restart {names(waiting)} for this to take effect." if waiting else \
            "Each download is checked before it reaches your Downloads folder."
        notifier.notify(f"Downloads from {names(set_up + waiting)} now go to quarantine",
                        restart, "normal", "security-high")
    return bool(waiting)


def ask_to_set_folder(browser):
    """For a browser that can't be set up from outside (or isn't known)."""
    folder = html.escape(str(QUARANTINE))
    if browser == "Safari":
        steps = "In Safari: Settings → General → File download location → Other."
    elif browser in FIREFOX_BASED:
        steps = f"In {browser}: Settings → General → Downloads → Save files to → Browse."
    elif browser:
        steps = f"In {browser}: Settings → Downloads → Location → Change."
    else:
        steps = "In your browser's settings, change where downloads are saved."
    while True:
        choice = notifier.notify(f"Set {browser or 'your browser'} to download into quarantine",
                                 f"{steps}\nChoose this folder:\n<b>{folder}</b>", "critical",
                                 "folder-download", [("copy", "Copy folder"), ("help", "Help")])
        if choice == "help":
            open_url(BROWSER_HELP)
            time.sleep(2)  # so a repeated click doesn't land on the next popup
            continue
        if choice == "copy" and not copy_to_clipboard(str(QUARANTINE)):
            notifier.notify("Couldn't copy the folder", f"Type it in instead:\n<b>{folder}</b>",
                            "normal", "dialog-warning")
        return


def watch_browsers():
    """Background: the first run's setup, then quietly the same for browsers that
    were open (once they close), installed later, or given a new profile."""
    try:
        waiting = setup_browsers() if not BROWSER_SETUP.exists() else True
    except Exception as e:
        log(f"browser setup failed: {e}")
        waiting = True
    while True:
        # Often while a browser is waiting to be closed: it may be opened again soon.
        time.sleep(2 if waiting else 300)
        try:
            try:
                record = json.loads(BROWSER_SETUP.read_text())
            except (OSError, ValueError):
                record = {}
            before = json.dumps(record, sort_keys=True)
            _, still, _ = browser_pass(record)
            drift_pass(record)
            if json.dumps(record, sort_keys=True) != before:
                save_browser_record(record)
            waiting = bool(still) or any(e.get("put_back") for e, *_ in drift_checks(record))
        except Exception as e:
            log(f"browser setup failed: {e}")


def undo_browser_setup():
    """Put every browser's download settings back. Returns the browsers that were
    open, which still save into the quarantine folder."""
    left = []
    try:
        record = json.loads(BROWSER_SETUP.read_text())
    except (OSError, ValueError):
        return left
    for entry in record.get("firefox", []):
        folder = Path(entry["profile"])
        if folder.is_dir():
            if entry.get("kept"):
                remove_user_js_block(folder)  # its download folder is the user's own choice now
            else:
                undo_firefox_profile(folder, entry.get("before", {}))
            undo_firefox_handlers(folder, entry.get("handlers_before", {}))
            print(f"Put back the download settings of {folder}")
    if MACOS and "safari" in record:
        if safari_running():
            print(f"Safari is open, so its downloads still go to {QUARANTINE}: change that in "
                  "Safari → Settings → General → File download location")
            left.append("Safari")
        else:
            try:
                undo_safari(record["safari"].get("before", {}))
                print("Put back Safari's download settings")
            except (OSError, ValueError, subprocess.CalledProcessError) as e:
                print(f"Could not put back Safari's download settings: {e}")
                left.append("Safari")
    for entry in record.get("chromium", []):
        prefs = Path(entry["prefs"])
        if not prefs.is_file():
            continue
        browser = entry.get("browser", "the browser")
        if chromium_running(prefs.parent.parent):
            print(f"{browser} is open, so its downloads still go to {QUARANTINE}: "
                  f"change that in its settings (Downloads)")
            left.append(browser)
            continue
        try:
            undo_chromium_profile(prefs, entry.get("before", {}))
            print(f"Put back the download settings of {prefs.parent}")
        except (OSError, ValueError) as e:
            print(f"Could not put back the download settings of {prefs.parent}: {e}")
            left.append(browser)
    return left
