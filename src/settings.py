#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Settings ----------------------------------------------------------------------

WATCH_TEXT = {
    "move": "taken into quarantine, checked, and put back where you saved them",
    "check": "checked where they are; only a flagged one brings a notification",
    "off": "left alone (only the quarantine folder is checked)",
}
KEY_SAVED = threading.Event()  # a key was saved, or Quit chosen: wait_for_key looks again at once
tray = None  # the Windows tray icon, set in run()


def settings():
    """The settings: opening the app again (Start menu, app menu, Launchpad). On Windows
    that's the tray icon's menu; elsewhere a few notifications in a row."""
    setup_logging()
    started = start_if_stopped()
    if WINDOWS and show_tray_menu(wait=15 if started else 3):
        return 0
    install_requirements()
    dialogs = make_notifier()
    mode = watch_mode()
    choice = dialogs.notify(f"{APP} settings",
                            (f"{APP} wasn't running, so it was started. " if started else "") +
                            "Downloads saved outside quarantine (with Save As, or a download folder "
                            f"changed in the browser) are now {WATCH_TEXT[mode]}.",
                            "critical", "preferences-system",
                            [("move", "Move into quarantine"), ("check", "Check only"), ("off", "Off")])
    if choice in WATCH_MODES:
        set_watch_mode(choice)
        mode = choice
    if MACOS and mode != "off":
        allow = dialogs.notify("Also watch Desktop and Documents?",
                               "macOS asks once for permission to read them. Downloads, Music, Pictures "
                               "and Movies are watched either way.", "critical", "",
                               [("no", "No"), ("yes", "Yes")])
        if allow == "yes":
            MAC_PRIVATE_WATCH.parent.mkdir(parents=True, exist_ok=True)
            MAC_PRIVATE_WATCH.touch()
        elif allow == "no":
            MAC_PRIVATE_WATCH.unlink(missing_ok=True)
    while mode != "off":
        lists = read_watch_list()
        standard = "Downloads, Music, Pictures and Movies" if MACOS and not MAC_PRIVATE_WATCH.exists() else \
            "Downloads, Desktop, Documents, Music, Pictures and Videos"
        what = dialogs.notify("Watched folders",
                              f"{standard}, plus {len(lists['added'])} you added and {len(lists['learned'])} "
                              "learned from where your browsers last saved with Save As.", "critical", "folder",
                              [("add", "Add a folder…"), ("forget", "Forget extra folders"), ("done", "Done")])
        if what == "add":
            folder = pick_folder()
            if folder is False:
                dialogs.notify("No folder picker here", "Add one from a terminal instead:\n"
                               "vt-quarantine --add-folder FOLDER", "normal", "dialog-information")
            elif folder and (problem := add_folder(folder)):
                dialogs.notify("Can't watch that folder", html.escape(problem), "normal", "dialog-warning")
            choice = choice or what
            continue
        if what == "forget":
            forget_folders()
            choice = choice or what
            continue
        break
    if choice:
        dialogs.tell("Settings saved", f"Downloads saved outside quarantine are {WATCH_TEXT[mode]}.",
                     "security-high")
    return 0


def pick_folder():
    """The system's own folder picker: the folder, None if cancelled, False if there's none."""
    prompt = f"Choose a folder for {APP} to watch"
    if MACOS:
        # "activate": in front, with the keyboard, like the other dialogs.
        r = subprocess.run(["osascript", "-e", "on run argv\nactivate\nreturn POSIX path of (choose folder with "
                            "prompt (item 1 of argv))\nend run", prompt], capture_output=True, text=True)
        return (r.stdout.strip() or None) if r.returncode == 0 else None
    if WINDOWS:
        return windows_pick_folder(prompt)
    for cmd in (["kdialog", "--title", prompt, "--getexistingdirectory", str(HOME)],
                ["zenity", "--file-selection", "--directory", f"--title={prompt}"]):
        if shutil.which(cmd[0]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            return (r.stdout.strip() or None) if r.returncode == 0 else None
    return False


def windows_pick_folder(title):
    """Windows' own folder dialog (shell32), with no helper program."""
    import ctypes
    from ctypes import wintypes as w

    class BrowseInfo(ctypes.Structure):
        _fields_ = [("hwndOwner", w.HWND), ("pidlRoot", ctypes.c_void_p), ("pszDisplayName", w.LPWSTR),
                    ("lpszTitle", w.LPCWSTR), ("ulFlags", w.UINT), ("lpfn", ctypes.c_void_p),
                    ("lParam", w.LPARAM), ("iImage", ctypes.c_int)]

    shell32, ole32 = ctypes.WinDLL("shell32"), ctypes.WinDLL("ole32")
    shell32.SHBrowseForFolderW.restype = ctypes.c_void_p
    shell32.SHBrowseForFolderW.argtypes = (ctypes.POINTER(BrowseInfo),)
    shell32.SHGetPathFromIDListW.argtypes = (ctypes.c_void_p, w.LPWSTR)
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    user32 = ctypes.WinDLL("user32")
    user32.SetWindowPos.argtypes = (w.HWND, w.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.UINT)
    user32.SetForegroundWindow.argtypes = (w.HWND,)

    @ctypes.WINFUNCTYPE(ctypes.c_int, w.HWND, w.UINT, w.LPARAM, w.LPARAM)
    def on_event(hwnd, msg, lparam, data):
        # Opened from a notification, the dialog would come up behind other windows:
        # put it above them once (topmost, then not), then ask for the keyboard.
        if msg == 1:  # BFFM_INITIALIZED
            flags = 0x0001 | 0x0002 | 0x0040  # SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW
            user32.SetWindowPos(hwnd, w.HWND(-1), 0, 0, 0, 0, flags)
            user32.SetWindowPos(hwnd, w.HWND(-2), 0, 0, 0, 0, flags)
            user32.SetForegroundWindow(hwnd)
        return 0

    ole32.CoInitialize(None)
    name = ctypes.create_unicode_buffer(260)
    # BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
    info = BrowseInfo(None, None, ctypes.cast(name, w.LPWSTR), title, 0x0001 | 0x0040,
                      ctypes.cast(on_event, ctypes.c_void_p), 0, 0)
    pidl = shell32.SHBrowseForFolderW(ctypes.byref(info))
    if not pidl:
        return None
    path = ctypes.create_unicode_buffer(260)
    ok = shell32.SHGetPathFromIDListW(pidl, path)
    ole32.CoTaskMemFree(pidl)
    return path.value if ok and path.value else None


# --- Tray icon (Windows) ---------------------------------------------------------------

TRAY_CLASS = "vt-quarantine-tray"
WM_TRAY = 0x8001       # WM_APP + 1: the icon was clicked
WM_SHOW_MENU = 0x8002  # sent by the Start menu entry
MODE_LABELS = (("move", "Move into quarantine"), ("check", "Check only"), ("off", "Off"))


def tray_menu(mode, extras, startup, waiting_for_key, can_update):
    """The menu as (id, label, flags) rows, (label, rows) for a submenu, None for a line."""
    rows = [(2, "Open quarantine folder", set())]
    if waiting_for_key:
        rows.append((3, "Enter API key…", set()))
    modes = [(10 + i, label, {"radio", "checked"} if m == mode else {"radio"}) for i, (m, label) in enumerate(MODE_LABELS)]
    folders = [(20, "Add a folder…", set()), (21, "Forget extra folders", set() if extras else {"grayed"})]
    rows += [None, ("Downloads saved elsewhere", modes), ("Watched folders", folders), None,
             (30, "Start with Windows", {"checked"} if startup else set())]
    if can_update:
        rows.append((40, "Check for updates", set()))
    return rows + [None, (50, "Quit", set())]


class Tray:
    """The icon by the clock: its tooltip says what it's doing, and clicking it opens
    the settings. Plain Win32 through ctypes, on a thread of its own."""

    def __init__(self):
        self.status, self.waiting_for_key = "Starting…", False
        self.updater = None  # set once run() has one
        self.busy = lambda: False  # set by run(): a download is being checked
        self.quit = threading.Event()
        self.hwnd = None
        self.ready = threading.Event()

    def start(self):
        threading.Thread(target=self.loop, daemon=True).start()
        self.ready.wait(5)

    def set_status(self, status, waiting_for_key=False):
        if (status, waiting_for_key) != (self.status, self.waiting_for_key):
            self.status, self.waiting_for_key = status, waiting_for_key
            self.notify_icon(1)  # NIM_MODIFY

    def act(self, ident):
        """A menu choice, on a thread of its own (dialogs wait)."""
        try:
            if ident == 2:
                os.startfile(QUARANTINE)  # our own folder, in Explorer  # noqa: S606  # nosec B606
            elif ident == 3:
                if key_window():
                    KEY_SAVED.set()
            elif 10 <= ident < 10 + len(MODE_LABELS):
                set_watch_mode(MODE_LABELS[ident - 10][0])
            elif ident == 20:
                folder = pick_folder()
                if folder and (problem := add_folder(folder)):
                    notifier.tell("Can't watch that folder", html.escape(problem), "dialog-warning")
                elif folder:
                    notifier.tell("Watching another folder", html.escape(folder), "security-high")
            elif ident == 21:
                forget_folders()
            elif ident == 30:
                set_startup(not startup_enabled())
            elif ident == 40 and self.updater:
                self.updater.check(asked=True)
            elif ident == 50 and self.confirm_quit():
                self.quit.set()
                KEY_SAVED.set()
        except Exception as e:
            log(f"tray: {e}")

    def menu_rows(self):
        lists = read_watch_list()
        return tray_menu(watch_mode(), bool(lists["added"] or lists["learned"]), startup_enabled(),
                         self.waiting_for_key, self.updater is not None)

    # The Win32 side: untestable off Windows, so it only draws and passes clicks on.

    def win32(self):
        import ctypes
        from ctypes import wintypes as w
        LRESULT = ctypes.c_ssize_t
        self.WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", w.UINT), ("lpfnWndProc", self.WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE), ("hIcon", w.HICON),
                        ("hCursor", w.HANDLE), ("hbrBackground", w.HBRUSH), ("lpszMenuName", w.LPCWSTR),
                        ("lpszClassName", w.LPCWSTR)]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT), ("uFlags", w.UINT),
                        ("uCallbackMessage", w.UINT), ("hIcon", w.HICON), ("szTip", w.WCHAR * 128),
                        ("dwState", w.DWORD), ("dwStateMask", w.DWORD), ("szInfo", w.WCHAR * 256),
                        ("uVersion", w.UINT), ("szInfoTitle", w.WCHAR * 64), ("dwInfoFlags", w.DWORD),
                        ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", w.HICON)]

        class NOTIFYICONIDENTIFIER(ctypes.Structure):
            _fields_ = [("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT), ("guidItem", ctypes.c_byte * 16)]

        u, s, k = ctypes.WinDLL("user32"), ctypes.WinDLL("shell32"), ctypes.WinDLL("kernel32")
        for dll, name, res, args in (
                (u, "DefWindowProcW", LRESULT, (w.HWND, w.UINT, w.WPARAM, w.LPARAM)),
                (u, "RegisterClassW", w.ATOM, (ctypes.POINTER(WNDCLASSW),)),
                (u, "CreateWindowExW", w.HWND, (w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int,
                                                ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID)),
                (u, "GetMessageW", w.BOOL, (ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT)),
                (u, "TranslateMessage", w.BOOL, (ctypes.POINTER(w.MSG),)),
                (u, "DispatchMessageW", LRESULT, (ctypes.POINTER(w.MSG),)),
                (u, "RegisterWindowMessageW", w.UINT, (w.LPCWSTR,)),
                (u, "LoadImageW", w.HANDLE, (w.HINSTANCE, w.LPCWSTR, w.UINT, ctypes.c_int, ctypes.c_int, w.UINT)),
                (u, "LoadIconW", w.HICON, (w.HINSTANCE, ctypes.c_void_p)),
                (u, "GetSystemMetrics", ctypes.c_int, (ctypes.c_int,)),
                (u, "CreatePopupMenu", w.HMENU, ()),
                (u, "AppendMenuW", w.BOOL, (w.HMENU, w.UINT, ctypes.c_size_t, w.LPCWSTR)),
                (u, "CheckMenuRadioItem", w.BOOL, (w.HMENU, w.UINT, w.UINT, w.UINT, w.UINT)),
                (u, "TrackPopupMenu", ctypes.c_int, (w.HMENU, w.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                                     w.HWND, ctypes.c_void_p)),
                (u, "DestroyMenu", w.BOOL, (w.HMENU,)),
                (u, "GetCursorPos", w.BOOL, (ctypes.POINTER(w.POINT),)),
                (u, "SetForegroundWindow", w.BOOL, (w.HWND,)),
                (u, "PostMessageW", w.BOOL, (w.HWND, w.UINT, w.WPARAM, w.LPARAM)),
                (u, "MessageBoxW", ctypes.c_int, (w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT)),
                (s, "Shell_NotifyIconW", w.BOOL, (w.DWORD, ctypes.POINTER(NOTIFYICONDATAW))),
                (s, "Shell_NotifyIconGetRect", ctypes.c_long, (ctypes.POINTER(NOTIFYICONIDENTIFIER),
                                                               ctypes.POINTER(w.RECT))),
                (k, "GetModuleHandleW", w.HMODULE, (w.LPCWSTR,))):
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = res, args
        return ctypes, w, u, s, k, WNDCLASSW, NOTIFYICONDATAW, NOTIFYICONIDENTIFIER

    def loop(self):
        try:
            ctypes, w, u, s, k, WNDCLASSW, self.NID, self.NII = self.win32()
            self.ctypes, self.u, self.s = ctypes, u, s
            instance = k.GetModuleHandleW(None)
            taskbar_created = u.RegisterWindowMessageW("TaskbarCreated")  # Explorer restarted: add it again

            def proc(hwnd, msg, wparam, lparam):
                if msg == WM_TRAY and lparam in (0x0202, 0x0205):  # WM_LBUTTONUP, WM_RBUTTONUP
                    self.show_menu(at_icon=False)
                elif msg == WM_SHOW_MENU:
                    self.show_menu(at_icon=True)
                elif msg == taskbar_created:
                    self.notify_icon(0)
                return u.DefWindowProcW(hwnd, msg, wparam, lparam)

            self.proc = self.WNDPROC(proc)  # kept, or ctypes frees it while Windows still calls it
            u.RegisterClassW(ctypes.byref(WNDCLASSW(0, self.proc, 0, 0, instance, None, None, None, None, TRAY_CLASS)))
            # A hidden top-level window: a message-only one wouldn't hear that Explorer restarted.
            self.hwnd = u.CreateWindowExW(0, TRAY_CLASS, APP, 0, 0, 0, 0, 0, None, None, instance, None)
            size = u.GetSystemMetrics(49)  # SM_CXSMICON
            icon = Path(__file__).resolve().with_name("vt-quarantine.ico")
            self.icon = (u.LoadImageW(None, str(icon), 1, size, size, 0x10) if icon.exists() else None) \
                or u.LoadIconW(None, ctypes.c_void_p(32512))  # IMAGE_ICON, LR_LOADFROMFILE; IDI_APPLICATION
            self.notify_icon(0)  # NIM_ADD
        except Exception as e:
            log(f"no tray icon: {e}")
            return
        finally:
            self.ready.set()
        msg = w.MSG()
        while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))

    def notify_icon(self, action):
        """NIM_ADD (0), NIM_MODIFY (1) or NIM_DELETE (2), with the status as the tooltip."""
        if not self.hwnd:
            return
        data = self.NID()
        data.cbSize, data.hWnd, data.uID = self.ctypes.sizeof(data), self.hwnd, 1
        data.uFlags, data.uCallbackMessage, data.hIcon = 0x1 | 0x2 | 0x4, WM_TRAY, self.icon  # message, icon, tip
        data.szTip = f"{APP}\n{self.status}"[:127]
        self.s.Shell_NotifyIconW(action, self.ctypes.byref(data))

    def remove(self):
        self.notify_icon(2)

    def show_menu(self, at_icon):
        ctypes, u = self.ctypes, self.u
        w = ctypes.wintypes
        menu = self.build_menu(self.menu_rows())
        point = w.POINT()
        u.GetCursorPos(ctypes.byref(point))
        if at_icon:  # opened from the Start menu: by the icon, not wherever the mouse is
            ident, rect = self.NII(), w.RECT()
            ident.cbSize, ident.hWnd, ident.uID = ctypes.sizeof(ident), self.hwnd, 1
            if self.s.Shell_NotifyIconGetRect(ctypes.byref(ident), ctypes.byref(rect)) == 0:
                point.x, point.y = (rect.left + rect.right) // 2, rect.top
        u.SetForegroundWindow(self.hwnd)  # or the menu wouldn't close on a click elsewhere
        # TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN
        choice = u.TrackPopupMenu(menu, 0x100 | 0x80 | 0x2 | 0x20, point.x, point.y, 0, self.hwnd, None)
        u.PostMessageW(self.hwnd, 0, 0, 0)  # WM_NULL, so the next click opens it again
        u.DestroyMenu(menu)
        if choice:
            threading.Thread(target=self.act, args=(choice,), daemon=True).start()

    def build_menu(self, rows):
        u = self.u
        menu = u.CreatePopupMenu()
        for row in rows:
            if row is None:
                u.AppendMenuW(menu, 0x800, 0, None)  # MF_SEPARATOR
            elif len(row) == 2:
                u.AppendMenuW(menu, 0x10, self.build_menu(row[1]), row[0])  # MF_POPUP: freed with its menu
            else:
                ident, label, flags = row
                checked = "checked" in flags and "radio" not in flags
                u.AppendMenuW(menu, (0x1 if "grayed" in flags else 0) | (0x8 if checked else 0), ident, label)
        radios = [r[0] for r in rows if r and len(r) == 3 and "radio" in r[2]]
        chosen = [r[0] for r in rows if r and len(r) == 3 and {"radio", "checked"} <= r[2]]
        if radios and chosen:
            u.CheckMenuRadioItem(menu, radios[0], radios[-1], chosen[0], 0)  # a dot, MF_BYCOMMAND
        return menu

    def confirm_quit(self):
        busy = " The download being checked is finished first." if self.busy() else ""
        # MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND; IDYES = 6
        return self.u.MessageBoxW(None, f"New downloads will wait in quarantine, unchecked, until {APP} runs "
                                  f"again (at sign-in, or from the Start menu).{busy}", f"Quit {APP}?",
                                  0x4 | 0x30 | 0x100 | 0x10000) == 6


def show_tray_menu(wait):
    """Windows: open the running copy's tray menu (from the Start menu entry). False if
    no tray icon turned up within wait seconds."""
    import ctypes
    from ctypes import wintypes as w
    u = ctypes.WinDLL("user32")
    u.FindWindowW.restype, u.FindWindowW.argtypes = w.HWND, (w.LPCWSTR, w.LPCWSTR)
    u.GetWindowThreadProcessId.argtypes = (w.HWND, ctypes.POINTER(w.DWORD))
    u.AllowSetForegroundWindow.argtypes = (w.DWORD,)
    u.PostMessageW.argtypes = (w.HWND, w.UINT, w.WPARAM, w.LPARAM)
    deadline = time.monotonic() + wait
    while not (hwnd := u.FindWindowW(TRAY_CLASS, None)):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.25)
    pid = w.DWORD()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    u.AllowSetForegroundWindow(pid.value)  # this process was just opened, so it may hand that on
    return bool(u.PostMessageW(hwnd, WM_SHOW_MENU, 0, 0))
