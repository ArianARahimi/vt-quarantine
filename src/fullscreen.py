#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Fullscreen --------------------------------------------------------------------
# Notifications that aren't about a download (an update, the first-run setup) wait
# while something fills the screen (a game, a video, a presentation) and show as soon
# as it's gone. Download notifications always show: someone who is downloading things
# isn't absorbed in a game.

FULLSCREEN_RECHECK_SECONDS = 5
KWIN_SCRIPT = """\
const full = workspace.windowList().some(w => w.fullScreen && !w.minimized &&
    (w.onAllDesktops || w.desktops.some(d => d.id === workspace.currentDesktop.id)));
callDBus(%s, "/vtq", "local.vtq", "fullscreen", %s, full);
"""


def windows_fullscreen():
    import ctypes
    state = ctypes.c_int()
    if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) != 0:
        return False
    # 2: a fullscreen app, 3: a Direct3D game in exclusive fullscreen, 4: presentation mode
    return state.value in (2, 3, 4)


def kwin_fullscreen():
    """Ask KDE's window manager whether a visible window is fullscreen. None if
    it isn't there to ask."""
    from jeepney import DBusAddress, MatchRule, new_method_call, new_method_return
    from jeepney.bus_messages import message_bus
    from jeepney.io.blocking import open_dbus_connection
    from jeepney.wrappers import unwrap_msg
    with open_dbus_connection("SESSION") as conn:
        if not unwrap_msg(conn.send_and_get_reply(message_bus.NameHasOwner("org.kde.KWin"), timeout=5))[0]:
            return None
        token = uuid.uuid4().hex
        folder = Path(tempfile.mkdtemp(prefix="vtq-kwin-"))
        script = folder / "fullscreen.js"
        script.write_text(KWIN_SCRIPT % (json.dumps(conn.unique_name), json.dumps(token)))
        scripting = DBusAddress("/Scripting", bus_name="org.kde.KWin", interface="org.kde.kwin.Scripting")
        name = f"vt-quarantine-{token}"
        try:
            with conn.filter(MatchRule(type="method_call", path="/vtq")) as calls:
                sid = unwrap_msg(conn.send_and_get_reply(
                    new_method_call(scripting, "loadScript", "ss", (str(script), name)), timeout=5))[0]
                if sid < 0:
                    return None
                run = DBusAddress(f"/Scripting/Script{sid}", bus_name="org.kde.KWin",
                                  interface="org.kde.kwin.Script")
                conn.send(new_method_call(run, "run"))
                deadline = time.monotonic() + 5
                while True:
                    call = conn.recv_until_filtered(calls, timeout=max(0.1, deadline - time.monotonic()))
                    conn.send(new_method_return(call))
                    if call.body and call.body[0] == token:
                        return bool(call.body[1])
        finally:
            with contextlib.suppress(Exception):
                conn.send_and_get_reply(new_method_call(scripting, "unloadScript", "s", (name,)), timeout=5)
            shutil.rmtree(folder, ignore_errors=True)


def x11_fullscreen():
    """Is the active X11 window fullscreen? (Needs xprop.)"""
    if not os.environ.get("DISPLAY") or not shutil.which("xprop"):
        return False
    active = subprocess.run(["xprop", "-root", "_NET_ACTIVE_WINDOW"], capture_output=True,
                            text=True, timeout=5).stdout
    m = re.search(r"window id # (0x[0-9a-fA-F]+)", active)
    if not m or int(m.group(1), 16) == 0:
        return False
    state = subprocess.run(["xprop", "-id", m.group(1), "_NET_WM_STATE"], capture_output=True,
                           text=True, timeout=5).stdout
    return "_NET_WM_STATE_FULLSCREEN" in state


def screen_taken():
    """Is a fullscreen window (a game, a video, a presentation) in front right now?"""
    try:
        if WINDOWS:
            return windows_fullscreen()
        if MACOS:
            return False
        kwin = kwin_fullscreen()
        return x11_fullscreen() if kwin is None else kwin
    except Exception as e:
        log(f"could not tell whether something is fullscreen: {e}")
        return False


def wait_for_free_screen(what):
    """Wait while something is fullscreen. True if it had to."""
    waited = False
    while screen_taken():
        if not waited:
            log(f"{what} waits until nothing is fullscreen")
            waited = True
        time.sleep(FULLSCREEN_RECHECK_SECONDS)
    return waited
