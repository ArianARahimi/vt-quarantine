#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Notifications -------------------------------------------------------------

def strip_markup(text):
    """Plain text from the <b>-and-entities markup notification bodies are built with.
    Everything user-controlled was html.escape()d, so the only tags are our own."""
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def show_in_folder(path):
    """Open the folder holding path, with the file selected where the system allows."""
    try:
        if WINDOWS:
            # A path can't contain quotes on Windows, and explorer wants exactly this form.
            subprocess.Popen(f'"{WINDOWS_DIR / "explorer.exe"}" /select,"{path}"')
        elif MACOS:
            subprocess.Popen(["open", "-R", str(path)])
        else:
            open_url(str(path.parent))
    except OSError as e:
        log(f"could not open the folder of {path}: {e}")


def open_url(url):
    try:
        if not WINDOWS and not MACOS and shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", url])
        else:
            webbrowser.open(url)
    except Exception as e:
        log(f"could not open {url}: {e}")


class Notifier:
    """Common front end. Backends implement _show() and close().

    _show(summary, body, urgency, icon, actions, expire, on_event) displays a
    notification and returns a handle for close(); on_event(key) is called with
    an action key when a button is pressed, and with "" when it's dismissed.
    """

    def notify(self, summary, body, urgency="normal", icon="security-medium", actions=(), expire=None):
        """Show a notification; with actions, block until one is chosen and return its key
        ("" if the notification was dismissed, None if it could not be shown)."""
        done = threading.Event()
        choice = []

        def on_event(key):
            if not choice:
                choice.append(key)
            done.set()

        try:
            handle = self._show(summary, body, urgency, icon, actions, expire, on_event if actions else None)
        except Exception as e:
            log(f"could not show notification {summary!r}: {e}")
            return None
        if not actions:
            return ""
        done.wait()
        self.forget(handle)
        return choice[0]

    def forget(self, handle):
        """Stop tracking a notification that has been answered."""

    # Can a notification carry a button without waiting for an answer? (Not on
    # macOS, where buttons need a dialog.)
    transient_buttons = True

    def tell(self, summary, body, icon, actions=(), on_action=None, expire=6000):
        """Short note that goes away by itself and blocks nothing; on_action(key)
        runs if one of its buttons is pressed."""
        if not self.transient_buttons:
            actions = ()

        def on_event(key):
            if key and on_action:
                on_action(key)
        try:
            handle = self._show(summary, body, "low", icon, actions, expire, on_event if actions else None)
        except Exception as e:
            log(f"could not show notification {summary!r}: {e}")
            return
        if actions:
            # Don't hold on to notes that are never answered: let go of each after
            # two minutes (checked whenever another one is shown).
            lock = self.__dict__.setdefault("_told_lock", threading.Lock())
            told = self.__dict__.setdefault("_told", [])
            now = time.monotonic()
            with lock:
                told.append((now + 120, handle))
                expired = [h for t, h in told if t <= now]
                told[:] = [(t, h) for t, h in told if t > now]
            for h in expired:
                self.forget(h)

    def show(self, summary, body, icon, actions, on_action):
        """Non-blocking notification that stays up until close(); on_action(key) runs
        when a button is pressed. Returns a handle, or None if it couldn't be shown."""
        def on_event(key):
            if key:
                on_action(key)
        try:
            return self._show(summary, body, "normal", icon, actions, 0, on_event)
        except Exception as e:
            log(f"could not show notification {summary!r}: {e}")
            return None


class FreedesktopNotifier(Notifier):
    """org.freedesktop.Notifications over D-Bus (KDE Plasma, GNOME, dunst, ...)."""

    URGENCY = {"low": 0, "normal": 1, "critical": 2}

    def __init__(self):
        from jeepney import DBusAddress
        self.addr = DBusAddress("/org/freedesktop/Notifications",
                                bus_name="org.freedesktop.Notifications",
                                interface="org.freedesktop.Notifications")
        self.cond = threading.Condition()
        self.waiting = {}  # notification id -> on_event, until it's closed
        self.connect()

    def connect(self):
        from jeepney import MatchRule, message_bus
        from jeepney.io.threading import DBusRouter, Proxy, open_dbus_connection
        old = getattr(self, "router", None)
        if old is not None:
            old.close()
            old.conn.close()
        self.router = DBusRouter(open_dbus_connection("SESSION"))
        signals = Queue()
        bus = Proxy(message_bus, self.router, timeout=10)
        self.filters = []
        for member in ("ActionInvoked", "NotificationClosed"):
            rule = MatchRule(type="signal", interface=self.addr.interface,
                             path=self.addr.object_path, member=member)
            bus.AddMatch(rule)
            self.filters.append(self.router.filter(rule, queue=signals))
        threading.Thread(target=self.dispatch, args=(signals,), daemon=True).start()
        caps = self.call("GetCapabilities")[0]
        self.markup = "body-markup" in caps
        if "actions" not in caps:
            log("warning: the notification server doesn't support buttons; "
                "files that need a decision will stay in quarantine")

    def call(self, method, signature=None, body=()):
        from jeepney import new_method_call
        from jeepney.wrappers import unwrap_msg
        msg = new_method_call(self.addr, method, signature, body)
        return unwrap_msg(self.router.send_and_get_reply(msg, timeout=10))

    def dispatch(self, signals):
        while True:
            # ActionInvoked carries (id, action key), NotificationClosed (id, reason).
            try:
                nid, arg = signals.get().body
            except ValueError:
                continue
            with self.cond:
                on_event = self.waiting.get(nid)
                if isinstance(arg, int):
                    self.waiting.pop(nid, None)
            if on_event:
                try:
                    on_event(arg if isinstance(arg, str) else "")
                except Exception as e:
                    log(f"notification callback failed: {e}")

    def _show(self, summary, body, urgency, icon, actions, expire, on_event):
        args = ("susssasa{sv}i",
                (APP, 0, icon, summary, body if self.markup else strip_markup(body),
                 [s for pair in actions for s in pair],
                 {"urgency": ("y", self.URGENCY[urgency])},
                 -1 if expire is None else expire))
        try:
            return self.register(args, on_event)
        except Exception:
            # The session bus connection may have dropped; reconnect once.
            self.connect()
            return self.register(args, on_event)

    def register(self, args, on_event):
        # Hold the lock across the call so a signal for the new id can't be
        # dispatched before the id is in self.waiting.
        with self.cond:
            nid = self.call("Notify", *args)[0]
            if on_event:
                self.waiting[nid] = on_event
        return nid

    def forget(self, nid):
        # Servers normally report the notification closed after a button press,
        # but a "resident" one may stay open; don't keep waiting for that.
        with self.cond:
            self.waiting.pop(nid, None)

    def close(self, nid):
        self.forget(nid)
        try:
            self.call("CloseNotification", "u", (nid,))
        except Exception as e:
            log(f"could not close notification: {e}")


class WindowsNotifier(Notifier):
    """Toast notifications through the Windows Runtime (Windows 10 and 11)."""

    APP_ID = "vt-quarantine"
    GROUP = "vt-quarantine"

    def __init__(self):
        import winreg
        from winrt.windows.ui.notifications import ToastNotificationManager
        # Windows only shows toasts from an unpackaged program under an
        # AppUserModelID registered like this (the name is what the toast shows).
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUMID_KEY) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP)
        manager = ToastNotificationManager.get_default()
        self.notifier = manager.create_toast_notifier(self.APP_ID)
        self.lock = threading.Lock()
        # Toasts must stay referenced, or their events stop firing.
        self.live = {}

    def _show(self, summary, body, urgency, icon, actions, expire, on_event):
        from xml.etree.ElementTree import Element, SubElement, tostring
        from winrt.windows.data.xml.dom import XmlDocument
        from winrt.windows.ui.notifications import (
            ToastActivatedEventArgs, ToastDismissalReason, ToastNotification)

        toast = Element("toast")
        if actions and (urgency == "critical" or expire == 0):
            # Stays on screen until a button is pressed (like a critical or
            # never-expiring notification on Linux); needs at least one button.
            toast.set("scenario", "reminder")
        binding = SubElement(SubElement(toast, "visual"), "binding", {"template": "ToastGeneric"})
        SubElement(binding, "text").text = summary
        SubElement(binding, "text").text = strip_markup(body)
        if actions:
            buttons = SubElement(toast, "actions")
            for key, label in actions:
                SubElement(buttons, "action",
                           {"content": label, "arguments": key, "activationType": "background"})
        SubElement(toast, "audio", {"src": "ms-winsoundevent:Notification.Default"}
                   if urgency == "critical" else {"silent": "true"})

        doc = XmlDocument()
        doc.load_xml(tostring(toast, encoding="unicode"))
        native = ToastNotification(doc)
        tag = uuid.uuid4().hex[:16]
        native.tag = tag
        native.group = self.GROUP

        def finish(key):
            with self.lock:
                self.live.pop(tag, None)
            if on_event:
                on_event(key)

        def activated(sender, args):
            # A click on the toast body (not a button) brings no action key.
            finish(args.as_(ToastActivatedEventArgs).arguments if args else "")

        def dismissed(sender, args):
            # A toast that timed out (or was hidden by Focus assist) moved to the
            # notification centre, where its buttons still work: keep waiting.
            if args is None or args.reason == ToastDismissalReason.USER_CANCELED:
                finish("")

        def failed(sender, args):
            log(f"toast failed: {args.error_code.value if args else 'unknown error'}")
            finish("")

        native.add_activated(activated)
        native.add_dismissed(dismissed)
        native.add_failed(failed)
        with self.lock:
            self.live[tag] = native
        self.notifier.show(native)
        return tag

    def forget(self, tag):
        with self.lock:
            self.live.pop(tag, None)

    def close(self, tag):
        with self.lock:
            native = self.live.pop(tag, None)
        if native is not None:
            try:
                self.notifier.hide(native)
            except Exception as e:
                log(f"could not close notification: {e}")


class MacNotifier(Notifier):
    """macOS, through osascript (built in): a dialog when a decision is needed,
    a Notification Center banner otherwise."""

    transient_buttons = False

    # Text goes in as arguments, never into the script source, so a filename
    # can't inject AppleScript. The first argument is a fixed word so osascript
    # never mistakes a title starting with "-" for an option. "activate": so the
    # first click on a button counts.
    DIALOG = """on run argv
    activate
    set r to display dialog (item 3 of argv) with title (item 2 of argv) buttons (items 4 thru -1 of argv) with icon caution giving up after 86400
    if gave up of r then return ""
    return button returned of r
end run"""
    BANNER = """on run argv
    display notification (item 3 of argv) with title (item 2 of argv)
end run"""

    def __init__(self):
        if not shutil.which("osascript"):
            raise RuntimeError("osascript not found")

    def _show(self, summary, body, urgency, icon, actions, expire, on_event):
        text = strip_markup(body)
        if not (actions and on_event and expire != 0):
            # No answer needed (a progress note can't carry buttons here).
            subprocess.run(["osascript", "-e", self.BANNER, "vtq", summary, text], capture_output=True)
            return None
        # A dialog has room for three buttons, which is all ask() ever uses.
        labels = [label for _, label in actions][:3]
        r = subprocess.run(["osascript", "-e", self.DIALOG, "vtq", summary, text, *labels],
                           capture_output=True, text=True)
        label = r.stdout.strip()
        on_event(next((key for key, text in actions if text == label), ""))
        return None

    def close(self, handle):
        pass


def make_notifier():
    if WINDOWS:
        return WindowsNotifier()
    if MACOS:
        return MacNotifier()
    if sys.platform.startswith("linux") or "bsd" in sys.platform:
        return FreedesktopNotifier()
    raise RuntimeError(f"unsupported platform {sys.platform}")


notifier = None  # set in run()


def windows_clipboard(text):
    """Put text on the Windows clipboard (Win32, no helper program)."""
    import ctypes
    from ctypes import wintypes as w
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.CreateWindowExW.restype = w.HWND
    user32.CreateWindowExW.argtypes = (w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID)
    user32.DestroyWindow.argtypes = user32.OpenClipboard.argtypes = (w.HWND,)
    user32.SetClipboardData.restype = w.HANDLE
    user32.SetClipboardData.argtypes = (w.UINT, w.HANDLE)
    kernel32.GlobalAlloc.restype = w.HGLOBAL
    kernel32.GlobalAlloc.argtypes = (w.UINT, ctypes.c_size_t)
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = kernel32.GlobalUnlock.argtypes = kernel32.GlobalFree.argtypes = (w.HGLOBAL,)
    data = text.encode("utf-16-le") + b"\0\0"
    # The clipboard needs an owner window, or what's put there may be refused: a
    # hidden message-only one.
    window = user32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, w.HWND(-3), None, None, None)
    try:
        for _ in range(20):  # another program may hold the clipboard for a moment
            if user32.OpenClipboard(window):
                break
            time.sleep(0.05)
        else:
            return False
        try:
            user32.EmptyClipboard()
            memory = kernel32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
            if not memory:
                return False
            ctypes.memmove(kernel32.GlobalLock(memory), data, len(data))
            kernel32.GlobalUnlock(memory)
            if not user32.SetClipboardData(13, memory):  # CF_UNICODETEXT; the system owns it once set
                kernel32.GlobalFree(memory)
                return False
            return True
        finally:
            user32.CloseClipboard()
    finally:
        if window:
            user32.DestroyWindow(window)


def copy_to_clipboard(text):
    """True if the text is now on the clipboard."""
    try:
        if WINDOWS:
            return windows_clipboard(text)
        if MACOS:
            return subprocess.run(["pbcopy"], input=text.encode(), capture_output=True,
                                  timeout=10).returncode == 0
        # These keep running to hold the text, so don't wait on their output.
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            if shutil.which(cmd[0]):
                return subprocess.run(cmd, input=text.encode(), stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        from jeepney import DBusAddress, MessageType, new_method_call
        from jeepney.io.blocking import open_dbus_connection
        klipper = DBusAddress("/klipper", bus_name="org.kde.klipper", interface="org.kde.klipper.klipper")
        with open_dbus_connection("SESSION") as conn:
            reply = conn.send_and_get_reply(new_method_call(klipper, "setClipboardContents", "s", (text,)),
                                            timeout=10)
        return reply.header.message_type == MessageType.method_return
    except Exception as e:
        log(f"could not copy to the clipboard: {e}")
        return False
