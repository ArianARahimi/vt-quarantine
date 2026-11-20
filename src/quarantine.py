#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Files ---------------------------------------------------------------------

def _open_nofollow(path):
    if not hasattr(os, "O_NOFOLLOW"):  # Windows
        if os.path.islink(path):
            raise OSError(f"refusing to follow symbolic link {path}")
        return open(path, "rb")
    return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")


def open_nofollow(path):
    """Open a quarantined file for reading, refusing a symlink swapped in after the
    directory scan. A locked file is unlocked just long enough to open it; what's
    already open stays readable."""
    try:
        return _open_nofollow(path)
    except PermissionError:
        unlock_file(path)
        try:
            return _open_nofollow(path)
        finally:
            lock_file(path)


# Files waiting in quarantine are locked, so nothing opens them by accident (the
# browser's list of downloads, a double-click, a thumbnail) until they're cleared.
UMASK = os.umask(0o022)
os.umask(UMASK)
EVERYONE = "*S-1-1-0"  # Windows: deny reading to everyone, this user included
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def lock_file(path):
    try:
        if WINDOWS:
            subprocess.run([str(SYSTEM32 / "icacls.exe"), str(path), "/deny", f"{EVERYONE}:(RD)"], capture_output=True,
                           check=True, creationflags=NO_WINDOW)
        elif stat.S_ISREG(os.lstat(path).st_mode):
            os.chmod(path, 0)
    except (OSError, subprocess.CalledProcessError) as e:
        log(f"could not lock {path.name}: {e}")


def unlock_file(path):
    try:
        if WINDOWS:
            subprocess.run([str(SYSTEM32 / "icacls.exe"), str(path), "/remove:d", EVERYONE], capture_output=True,
                           check=True, creationflags=NO_WINDOW)
        elif stat.S_ISREG(os.lstat(path).st_mode):
            os.chmod(path, 0o666 & ~UMASK)
    except (OSError, subprocess.CalledProcessError) as e:
        log(f"could not unlock {path.name}: {e}")


def unlock_quarantine():
    """Unlock everything still in quarantine (when uninstalling)."""
    with contextlib.suppress(OSError), os.scandir(QUARANTINE) as entries:
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                unlock_file(Path(entry.path))


def make_quarantine():
    """The quarantine folder, readable only by this user (on Windows the Downloads
    folder it lives in already is) and hidden (the dot already does that elsewhere)."""
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    if not WINDOWS:
        os.chmod(QUARANTINE, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions  # owner only
        return
    set_hidden(QUARANTINE, True)


def set_hidden(path, hidden):
    """Windows: hide or show a file or folder in Explorer."""
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    attrs = kernel32.GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF or bool(attrs & 2) == hidden:
        return
    if not kernel32.SetFileAttributesW(str(path), attrs | 2 if hidden else attrs & ~2):
        log(f"could not {'hide' if hidden else 'show'} {path} (error {ctypes.get_last_error()})")


def signature(path):
    """Changes whenever the file's contents may have changed."""
    st = os.stat(path, follow_symlinks=False)
    return st.st_size, st.st_mtime_ns, st.st_ino


def retry_locked(action):
    """Windows won't move or delete a file that another program (the browser,
    an antivirus scan) still has open, so give it a moment to let go."""
    for attempt in range(15):
        try:
            return action()
        except PermissionError:
            if not WINDOWS or attempt == 14:
                raise
            time.sleep(2)


def sha256(path, opener=None):
    h = hashlib.sha256()
    with (opener or open_nofollow)(path) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def partial_nearby(folder):
    """Any download still in progress in this folder."""
    try:
        return any(e.name.lower().endswith(PARTIAL_SUFFIXES) for e in os.scandir(folder))
    except OSError:
        return False


def wait_complete(path):
    """Wait until the browser has finished writing; False if the file went away."""
    part = path.with_name(path.name + ".part")
    last, empty_for = None, 0
    while True:
        try:
            st = path.stat()
        except FileNotFoundError:
            return False
        sig = (st.st_size, st.st_mtime_ns)
        # Firefox makes an empty placeholder, and its .part may have a random name
        # (when the name came from a redirect), so an empty file waits for every
        # partial download here, and a while longer.
        busy = part.exists() or (st.st_size == 0 and partial_nearby(path.parent))
        empty_for = empty_for + STABLE_SECONDS if sig == last and st.st_size == 0 else 0
        if not busy and sig == last and (st.st_size or empty_for >= EMPTY_SECONDS):
            return True
        last = None if busy else sig
        # Browsers only give a download its own name once it's finished; waiting for
        # it to stop changing is for anything else that saves there.
        time.sleep(STABLE_SECONDS)


FICLONE = 0x40049409  # Linux: share the data with a new file (Btrfs, XFS), no copying
RELEASED = {}  # files this program just moved out of quarantine -> when: not taken in again
RELEASED_LOCK = threading.Lock()
RELEASED_SECONDS = 60  # a released file turns up in the next look or two, if at all
RELEASED_SHAS = DATA_DIR / "released.json"  # contents cleared before: taken in again, they'd only come back
RELEASED_SHAS_MAX = 1000
ORIGINS_LOCK = threading.Lock()


def note_released(path):
    with RELEASED_LOCK:
        RELEASED[path] = time.monotonic()


def forget_released(path):
    with RELEASED_LOCK:
        RELEASED.pop(path, None)


def just_released(path):
    """Moved out of quarantine by this program a moment ago."""
    now = time.monotonic()
    with RELEASED_LOCK:
        for p in [p for p, t in RELEASED.items() if now - t > RELEASED_SECONDS]:
            del RELEASED[p]
        return path in RELEASED


def read_released_shas():
    try:
        data = json.loads(RELEASED_SHAS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [x for x in data if isinstance(x, str)] if isinstance(data, list) else []


def remember_released(sha):
    with ORIGINS_LOCK:
        shas = [x for x in read_released_shas() if x != sha] + [sha]
        RELEASED_SHAS.parent.mkdir(parents=True, exist_ok=True)
        tmp = RELEASED_SHAS.with_name(RELEASED_SHAS.name + ".new")
        tmp.write_text(json.dumps(shas[-RELEASED_SHAS_MAX:]), encoding="utf-8")
        os.replace(tmp, RELEASED_SHAS)


def prune_origins():
    """At start: forget where files came from that are no longer in quarantine
    (deleted by hand, or the program stopped while taking one in)."""
    with ORIGINS_LOCK:
        data = read_origins()
        kept = {name: folder for name, folder in data.items() if (QUARANTINE / name).exists()}
        if kept != data:
            tmp = ORIGINS.with_name(ORIGINS.name + ".new")
            tmp.write_text(json.dumps(kept), encoding="utf-8")
            os.replace(tmp, ORIGINS)


def read_origins():
    try:
        data = json.loads(ORIGINS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def set_origin(name, folder):
    """Remember (or with folder None, forget) where a file in quarantine came from."""
    with ORIGINS_LOCK:
        data = read_origins()
        if folder is None:
            if data.pop(name, None) is None:
                return
        else:
            data[name] = str(folder)
        ORIGINS.parent.mkdir(parents=True, exist_ok=True)
        tmp = ORIGINS.with_name(ORIGINS.name + ".new")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, ORIGINS)


def release_dir(path):
    """Where a file goes out of quarantine: the folder it was taken from, if that's
    still one of the folders watched for it (a tampered record can't point anywhere
    else), or Downloads."""
    origin = read_origins().get(path.name)
    if origin:
        folder = Path(origin)
        if folder in watched_folders(any_mode=True) and folder.is_dir():
            return folder
    return RELEASE_DIR


def place_name(folder):
    return "Downloads" if folder == RELEASE_DIR else folder.name


def copy_out(path, folder, suffix=""):
    """A new file in folder holding what path holds right now: (the file, its SHA-256).
    A program that still has path open goes on writing to the old file, not this one."""
    fd, tmp = tempfile.mkstemp(prefix=".vtq-", suffix=suffix, dir=folder)
    tmp = Path(tmp)
    try:
        with os.fdopen(fd, "w+b") as out, open_nofollow(path) as src:
            try:
                if not sys.platform.startswith("linux"):
                    raise OSError
                import fcntl
                fcntl.ioctl(out.fileno(), FICLONE, src.fileno())
            except OSError:
                shutil.copyfileobj(src, out, 1 << 20)
            out.seek(0)  # hashed as it landed, whichever way it got there
            h = hashlib.sha256()
            for chunk in iter(lambda: out.read(1 << 20), b""):
                h.update(chunk)
        shutil.copystat(path, tmp, follow_symlinks=False)  # times, and on Linux where it came from
        if MACOS:
            copy_mac_attributes(path, tmp)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp, h.hexdigest()


def copy_mac_attributes(path, copy):
    """macOS: what the download carries along (where it's from, when), and above all
    the mark Gatekeeper goes by: without that one the copy isn't handed out."""
    xattr = "/usr/bin/xattr"
    listed = subprocess.run([xattr, str(path)], capture_output=True, text=True, check=True).stdout
    for name in listed.splitlines():
        must = name == "com.apple.quarantine"  # others may be the system's own to set
        value = subprocess.run([xattr, "-px", name, str(path)], capture_output=True, text=True, check=must)
        if value.returncode == 0:
            try:  # (a value too big for a command line can't be passed on)
                subprocess.run([xattr, "-wx", name, "".join(value.stdout.split()), str(copy)],
                               capture_output=True, check=must)
            except OSError:
                if must:
                    raise


def win_move(src, dest):
    """Windows: move a file, across drives too, keeping its streams (the mark that it
    came from the internet lives in one; a plain copy would drop it)."""
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.MoveFileExW(str(src), str(dest), 0x2):  # MOVEFILE_COPY_ALLOWED
        raise ctypes.WinError(ctypes.get_last_error())


def nobody_has_open(path):
    """Windows: raises (PermissionError) while any program has the file open. One that
    opened it allowing others to delete it could be moved along with its file, and go
    on writing to it in Downloads."""
    import ctypes
    from ctypes import wintypes as w
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = w.HANDLE
    kernel32.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE)
    kernel32.CloseHandle.argtypes = (w.HANDLE,)
    # GENERIC_READ, shared with no one, OPEN_EXISTING
    handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
    if handle in (None, w.HANDLE(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel32.CloseHandle(handle)


def release(path, sha=None):
    """Move a file to Downloads, or back to the folder it was taken from. None (and it
    stays) if it no longer holds what was checked (sha). What arrives is a copy made
    and hashed here, so nothing that still has the download open can add to it
    afterwards. Windows moves the file itself (a copy would lose the mark that it came
    from the internet), once no program has it open."""
    folder = release_dir(path)
    dest = folder / path.name
    n = 1
    while dest.exists():
        dest = folder / f"{path.stem} ({n}){path.suffix}"
        n += 1
    note_released(dest)
    unlock_file(path)
    try:
        if WINDOWS:
            copied = retry_locked(lambda: sha256(path)) if sha else None
            changed = sha and copied != sha
            if not changed:
                retry_locked(lambda: (nobody_has_open(path), win_move(path, dest)))
        else:
            tmp, copied = copy_out(path, folder)
            changed = sha and copied != sha
            if changed:
                tmp.unlink()
            else:
                os.replace(tmp, dest)
                path.unlink()
    except BaseException:
        forget_released(dest)
        lock_file(path)
        raise
    if changed:
        forget_released(dest)
        lock_file(path)
        log(f"{path.name} changed after it was checked, checking again")
        return None
    set_origin(path.name, None)
    if copied:
        try:
            remember_released(copied)
        except OSError as e:
            log(f"could not note {path.name} as cleared: {e}")
    log(f"moved {path.name} to {dest}")
    return dest


def delete(path):
    retry_locked(lambda: path.unlink(missing_ok=True))
    if path.parent == QUARANTINE:
        set_origin(path.name, None)
    log(f"deleted {path.name}")


def should_auto_upload(path, opener=None):
    if path.suffix.lower() in AUTO_UPLOAD_EXT:
        return True
    with (opener or open_nofollow)(path) as f:
        return f.read(4).startswith(EXECUTABLE_MAGIC)


def flagged_by(results):
    """(engine, what it calls the file) for each engine that flags it."""
    return [(eng, r.get("result") or r["category"]) for eng, r in (results or {}).items()
            if r.get("category") in ("malicious", "suspicious")]


def counts(stats):
    """Malicious, suspicious and total engine counts of an analysis."""
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    return stats.get("malicious", 0), stats.get("suspicious", 0), total


def verdict_line(name, stats, results):
    """One log line: the counts and which engines flag the file."""
    bad, sus, total = counts(stats)
    flagged = "; ".join(f"{eng}: {label}" for eng, label in flagged_by(results))
    return f"verdict on {name}: {bad}/{total} malicious, {sus} suspicious" + (f" ({flagged})" if flagged else "")


def classify(stats, tags):
    """clean, flagged, no_engines, few_engines (most gave up or can't read the file: a
    file padded to be huge gets past them that way) or encrypted (engines can't see
    inside a password-protected archive). In the last two, 0 detections means nothing."""
    bad, sus, total = counts(stats)
    if not total:
        return "no_engines"
    if bad or sus:
        return "flagged"
    gave_up = sum(stats.get(k, 0) for k in ("timeout", "confirmed-timeout", "failure"))
    if total < MIN_ENGINES or gave_up > total:
        return "few_engines"
    return "encrypted" if "encrypted" in (tags or ()) else "clean"


def detection_summary(stats, results):
    bad, sus, total = counts(stats)
    lines = [f"<b>{bad}/{total}</b> engines say malicious" + (f", {sus} suspicious" if sus else "")]
    flagged = flagged_by(results)
    for eng, label in flagged[:6]:
        lines.append(f"• {html.escape(eng)}: {html.escape(label)}")
    if len(flagged) > 6:
        lines.append(f"• …and {len(flagged) - 6} more")
    return bad, sus, total, "\n".join(lines)


def is_candidate(name):
    lower = name.lower()
    return not (lower.endswith(PARTIAL_SUFFIXES) or lower in IGNORED_NAMES or CHROMIUM_PENDING.fullmatch(lower))


SAFE_LIST = CONFIG_DIR / "marked-safe"


def marked_safe(sha):
    """Was this exact file (by SHA-256) marked safe before?"""
    try:
        lines = SAFE_LIST.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    return any(line.split(maxsplit=1)[:1] == [sha] for line in lines)


def remember_safe(sha, name):
    SAFE_LIST.parent.mkdir(parents=True, exist_ok=True)
    with open(SAFE_LIST, "a") as f:
        f.write(f"{sha}  {' '.join(name.split())}\n")


def tell_moved(summary, body, dest):
    notifier.tell(summary, body, "security-high", [("folder", "Open folder")],
                  lambda key: show_in_folder(dest))


def lookup(name, sha, queued=None):
    """VirusTotal's file object once it has a finished analysis, or None if VT doesn't
    know the file. While VT still has it queued, calls queued() once and keeps asking."""
    deadline = time.monotonic() + ANALYSIS_TIMEOUT
    while time.monotonic() < deadline:
        r = vt("GET", f"/files/{sha}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        # A file still queued on VT has all-zero stats and no analysis date.
        if attrs.get("last_analysis_date"):
            return refreshed(name, sha, attrs)
        if queued:
            log(f"{name} is known to VT but not analysed yet, waiting")
            queued()
            queued = None
        time.sleep(QUEUED_RECHECK_SECONDS)
    raise RuntimeError("VirusTotal has no finished analysis yet")


def refreshed(name, sha, attrs):
    """attrs as they are, after asking VirusTotal to rescan a clean verdict that's old:
    VT doesn't rescan by itself, and engines may have learned about the file since.
    The file isn't held for it (a free key's rescan can take hours); the next lookup
    of the file gets the new verdict."""
    days = int((time.time() - attrs["last_analysis_date"]) // 86400)
    bad, sus, total = counts(attrs["last_analysis_stats"])
    if days < STALE_DAYS or bad or sus or not total:
        return attrs
    log(f"{name}: VirusTotal's verdict is {days} days old, asking for a rescan for next time")
    try:
        vt("POST", f"/files/{sha}/analyse").raise_for_status()
    except Exception as e:
        log(f"rescan request for {name} failed: {e}")
    return attrs


def wait_analysis(analysis, name):
    """Wait for an analysis (upload or rescan) to finish: (stats, results)."""
    deadline = time.monotonic() + ANALYSIS_TIMEOUT
    status = None
    while time.monotonic() < deadline:
        time.sleep(ANALYSIS_POLL_SECONDS)
        r = vt("GET", f"/analyses/{analysis}")
        if r.status_code == 404:  # VirusTotal can take a moment to list a new analysis
            log(f"analysis of {name}: not listed yet")
            continue
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        if attrs["status"] != status:
            status = attrs["status"]
            log(f"analysis of {name}: {status}")
        if attrs["status"] == "completed":
            return attrs["stats"], attrs.get("results")
    raise RuntimeError("VirusTotal analysis timed out")


def upload(path, sha):
    """Upload a file and wait for its analysis: (stats, results, tags)."""
    log(f"uploading {path.name}")
    url = "/files"
    if path.stat().st_size > DIRECT_UPLOAD_MAX:
        r = vt("GET", "/files/upload_url")
        r.raise_for_status()
        url = r.json()["data"]
    r = vt("POST", url, upload=path)
    r.raise_for_status()
    log(f"uploaded {path.name}, waiting for analysis")
    stats, results = wait_analysis(r.json()["data"]["id"], path.name)
    # The analysis object has no tags; the file object says if it is encrypted.
    r = vt("GET", f"/files/{sha}")
    r.raise_for_status()
    return stats, results, r.json()["data"]["attributes"].get("tags")


class Quarantine:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = set()  # being processed
        self.held = set()    # waiting on the user, notification dismissed
        self.asking = threading.Lock()  # one question on screen at a time

    def scan(self):
        if not QUARANTINE.is_dir():
            log("the quarantine folder was deleted: making it again")
            make_quarantine()
        for entry in os.scandir(QUARANTINE):
            if not is_candidate(entry.name) or not entry.is_file(follow_symlinks=False):
                continue
            path = Path(entry.path)
            with self.lock:
                if path in self.active or path in self.held:
                    continue
                self.active.add(path)
            threading.Thread(target=self.handle, args=(path,), daemon=True).start()
        with self.lock:
            self.held = {p for p in self.held if p.exists()}

    def handle(self, path):
        hold = False
        try:
            if wait_complete(path):
                lock_file(path)
                hold = self.check(path)
        except Exception as e:
            log(f"error on {path.name}: {e}")
            hold = self.ask(path, None, "Scan failed",
                            f"{html.escape(path.name)}\n{html.escape(str(e))}",
                            "dialog-error", [("retry", "Retry")])
        finally:
            with self.lock:
                self.active.discard(path)
                if hold and path.exists():
                    self.held.add(path)

    @staticmethod
    def scanning(path, sha, note=""):
        return Progress("Scanning on VirusTotal", f"{html.escape(path.name)} stays in quarantine until "
                        f"the scan finishes{note}.", sha)

    def check(self, path):
        """Returns True if the file was left in quarantine for the user."""
        sig = signature(path)
        sha = sha256(path)
        log(f"checking {path.name} {sha}")
        progress = None

        def queued():
            nonlocal progress
            progress = self.scanning(path, sha)

        try:
            attrs = lookup(path.name, sha, queued)
            if attrs is None:
                return self.unknown(path, sha, sig)
            return self.verdict(path, sha, sig, attrs["last_analysis_stats"],
                                attrs.get("last_analysis_results"), attrs.get("tags"))
        finally:
            if progress:
                progress.close()

    def unknown(self, path, sha, sig):
        name = html.escape(path.name)
        size = path.stat().st_size
        if size > UPLOAD_MAX:
            return self.no_verdict(path, sha, sig, "Not on VirusTotal",
                            f"{name} is unknown and too large to upload ({size // 1024**2} MB).",
                            "dialog-warning", report=False)
        if not should_auto_upload(path):
            choice = self.no_verdict(path, sha, sig, "Not on VirusTotal",
                              f"{name} is unknown to VirusTotal. Upload it for scanning? "
                              "(Uploaded files can be downloaded by VT subscribers.)",
                              "dialog-question", [("upload", "Upload")], report=False)
            if choice != "upload":
                return choice
        progress = self.scanning(path, sha, " (usually a few minutes)")
        try:
            stats, results, tags = upload(path, sha)
        finally:
            progress.close()
        return self.verdict(path, sha, sig, stats, results, tags)

    def verdict(self, path, sha, sig, stats, results, tags=None):
        log(verdict_line(path.name, stats, results))
        bad, _, total, body = detection_summary(stats, results)
        name = html.escape(path.name)
        kind = classify(stats, tags)
        if kind == "no_engines":
            return self.no_verdict(path, sha, sig, "No engines could scan this file",
                                   f"{name} got no verdict from any engine.", "dialog-warning")
        if kind == "few_engines":
            return self.no_verdict(path, sha, sig, "Too few engines scanned this file",
                                   f"{name} was only scanned by {total} engines; the rest couldn't "
                                   f"(0/{total} means little here).", "dialog-warning")
        if kind == "encrypted":  # a common way to slip malware past scanners
            return self.no_verdict(path, sha, sig, "Encrypted archive",
                                   f"{name} is password-protected, so VirusTotal could not scan its "
                                   f"contents (0/{total} means nothing here).", "dialog-warning")
        if kind == "clean":
            return self.release_unchanged(path, sha, sig, "Clean, moved to {}",
                                          f"{{name}} (0/{total} detections)")
        return self.ask(path, sha, f"⚠ Flagged: {path.name}", body, "security-low",
                        flagged=True, detections=bad)

    def no_verdict(self, path, sha, sig, summary, body, icon, extra=(), report=True):
        """Ask about a file VirusTotal has no verdict on (unknown, unscannable or
        encrypted), unless it was marked safe before. Only these are remembered:
        a flagged file always warns, so a mis-click can't wave it through for good."""
        if not marked_safe(sha):
            return self.ask(path, sha, summary, body, icon, extra, report)
        log(f"{path.name} was marked safe before")
        return self.release_unchanged(path, sha, sig, "Marked safe before, moved to {}", "{name}")

    @staticmethod
    def release_unchanged(path, sha, sig, summary, body):
        """Move a cleared file to Downloads, unless it was written to since it was
        hashed (the verdict is for other contents: the next scan checks it again).
        {name} in body becomes the name it got there, "(1)" and all."""
        if signature(path) != sig:
            log(f"{path.name} changed while being checked, checking again")
        elif dest := release(path, sha):
            tell_moved(summary.format(place_name(dest.parent)), body.format(name=html.escape(dest.name)), dest)
        return False

    def ask(self, *args, **kwargs):
        """Questions come one after another, not all at once: the next is shown as soon
        as the one before is answered (or closed). Files waiting their turn stay
        locked in quarantine."""
        with self.asking:
            return self._ask(*args, **kwargs)

    def _ask(self, path, sha, summary, body, icon, extra=(), report=True, flagged=False, detections=0):
        """Prompt until the user picks an action. Returns True if the file stays held,
        or the chosen extra action key.

        Where there's a VirusTotal report, "Mark as safe" only appears once it has
        been opened, in a new last place, so no button ever moves under the cursor."""
        safe = ("release", "Mark as safe")
        if sha and report:
            actions = [("report", "Show report"), *extra, ("delete", "Delete")]
        else:
            actions = [*extra, ("delete", "Delete"), safe]
        while True:
            choice = notifier.notify(summary, body, "critical", icon, actions)
            if choice == "report":
                open_url(report_url(sha))
                if safe not in actions:
                    actions.append(safe)
                time.sleep(2)  # so a repeated click doesn't land on the next popup
                continue
            if choice == "release" and detections >= CONFIRM_DETECTIONS:
                time.sleep(2)
                # Same three places again: "Move anyway" is where "Mark as safe" was.
                choice = notifier.notify(
                    f"Move {path.name} anyway?",
                    f"<b>{detections}</b> engines say it is malicious. In Downloads it "
                    "opens like any other file.",
                    "critical", icon, [("back", "Back"), ("delete", "Delete"), ("release", "Move anyway")])
                if choice == "back":
                    continue
            if choice == "release":
                dest = release(path, sha)
                if not dest:
                    return False  # changed: picked up again by the next scan
                if flagged:
                    tell_moved(f"Moved to {place_name(dest.parent)}", f"{html.escape(path.name)}\nIt's still flagged: "
                               "if you download it again, you'll be warned again.", dest)
                    return False
                if sha:
                    remember_safe(sha, path.name)
                tell_moved(f"Marked safe, moved to {place_name(dest.parent)}", html.escape(path.name), dest)
                return False
            if choice == "delete":
                delete(path)
                notifier.tell("Deleted", html.escape(path.name), "user-trash-full")
                return False
            if choice == "retry":
                return False  # picked up again by the next scan
            if choice:
                return choice
            log(f"holding {path.name} (notification dismissed)")
            return True


# --- Files saved outside quarantine ---------------------------------------------------
# A Save As box, or a download folder changed in the browser, puts a download straight
# into another folder. Downloads that land in the user's own folders (top level) are
# taken into quarantine at once, checked like any other, and go back to where they were
# saved once they're clean or marked safe ("move", the default). "check" only looks them
# up where they are and warns about flagged ones; "off" leaves them alone.
# Only downloads count, never the user's own files: what the system marks as coming from
# the internet through a browser (Windows, macOS), or what a browser has just finished
# saving (Linux: its "name.part" or ".crdownload" file renamed to the final name).

SHORTCUT_EXT = {".lnk", ".url", ".desktop", ".webloc"}  # made by installers; hold local paths
CLOUD_PLACEHOLDER = 0x1000 | 0x40000 | 0x400000  # Windows: offline, recall on open / on data access
WATCH_MODES = ("move", "check", "off")
NO_FOLDER_WATCH = CONFIG_DIR / "no-folder-watch"  # the earlier way to turn it off


def watch_mode():
    try:
        mode = FOLDER_WATCH.read_text().strip()
    except OSError:
        return "off" if NO_FOLDER_WATCH.exists() else "move"
    return mode if mode in WATCH_MODES else "move"


def set_watch_mode(mode):
    FOLDER_WATCH.parent.mkdir(parents=True, exist_ok=True)
    FOLDER_WATCH.write_text(mode)
    NO_FOLDER_WATCH.unlink(missing_ok=True)


def watched_folders(any_mode=False):
    """Downloads, the user's own folders, and the folders added in the settings or
    learned from the browsers' last Save As folder. On macOS, Desktop and Documents only
    when allowed in the settings: reading them brings up a permission prompt of their own."""
    if not any_mode and watch_mode() == "off":
        return []
    kinds = ("DOCUMENTS", "MUSIC", "PICTURES", "VIDEOS")
    desktop = [DESKTOP_DIR]
    if MACOS and not MAC_PRIVATE_WATCH.exists():
        kinds, desktop = ("MUSIC", "PICTURES", "VIDEOS"), []
    folders = [RELEASE_DIR, *desktop, *(user_dir(k) for k in kinds)]
    lists = read_watch_list()
    folders += [Path(f) for f in lists["added"] + lists["learned"]]
    return [f for f in dict.fromkeys(folders) if f not in (QUARANTINE, HOME)]


def read_watch_list():
    """{"added": [...], "learned": [...]}: folders as strings, oldest first."""
    try:
        data = json.loads(WATCH_LIST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {k: [f for f in data.get(k, []) if isinstance(f, str)] for k in ("added", "learned")}


def save_watch_list(data):
    WATCH_LIST.parent.mkdir(parents=True, exist_ok=True)
    tmp = WATCH_LIST.with_name(WATCH_LIST.name + ".new")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, WATCH_LIST)


def system_folders():
    if WINDOWS:
        found = [WINDOWS_DIR, HOME / "AppData"]
        for guid in ("905E63B6-C1BF-494E-B29C-65B732D3D21A", "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E",
                     "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"):  # Program Files (x86), ProgramData
            found.append(known_folder(guid, WINDOWS_DIR))
        return found
    found = [Path("/", name) for name in ("bin", "boot", "dev", "etc", "lib", "lib64", "opt", "proc", "root", "sbin",
                                          "srv", "sys", "usr", "var", "tmp", "System", "Library", "Applications",
                                          "private")]
    run = Path("/run")
    return found + [run / name for name in ("user", "lock", "systemd", "dbus")] + [HOME / "Library", HOME / ".config",
                                                                                   HOME / ".local", HOME / ".cache"]


def safe_folder(folder):
    """A folder that may be watched: an existing folder that isn't the home folder,
    a system folder, vt-quarantine's own or the quarantine folder, or inside one of
    those. (A watched folder is where files may be put back.)"""
    try:
        folder = Path(os.path.abspath(folder))
        if not folder.is_dir():
            return False
    except (OSError, ValueError):
        return False
    if folder == HOME or folder.parent == folder:  # the home folder, a drive's root
        return False
    inside = [folder, *folder.parents]
    for blocked in (QUARANTINE, CONFIG_DIR, DATA_DIR, *system_folders()):
        if blocked in inside:
            return False
    if MACOS and not MAC_PRIVATE_WATCH.exists() and any(p in inside for p in (DESKTOP_DIR, HOME / "Documents")):
        return False  # would bring up a permission prompt nobody asked for
    return True


def add_folder(folder, learned=False):
    """Watch one more folder. Returns why not (a sentence), or None."""
    folder = Path(os.path.abspath(folder))
    if not safe_folder(folder):
        return f"{folder} can't be watched (a system folder, the home folder itself or not a folder)."
    if folder in watched_folders(any_mode=True):
        return None
    data = read_watch_list()
    if learned:
        data["learned"] = [f for f in data["learned"] if f != str(folder)] + [str(folder)]
    else:
        data["learned"] = [f for f in data["learned"] if f != str(folder)]
        data["added"].append(str(folder))
    while len(data["added"]) + len(data["learned"]) > MAX_EXTRA_FOLDERS:
        if not data["learned"]:
            data["added"].pop()
            return f"At most {MAX_EXTRA_FOLDERS} folders can be added."
        data["learned"].pop(0)  # the oldest learned one makes room
    save_watch_list(data)
    log(f"watching {folder} too ({'learned from a browser' if learned else 'added in the settings'})")
    return None


def forget_folders():
    save_watch_list({"added": [], "learned": []})


def outside_name(name):
    """Worth a look by its name: not hidden, not still downloading, not a shortcut."""
    return not name.startswith(".") and is_candidate(name) and Path(name).suffix.lower() not in SHORTCUT_EXT


def outside_size(st):
    """A regular file's size, or -1: anything else, or a cloud file only listed here
    (reading it would download it)."""
    if not stat.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & CLOUD_PLACEHOLDER:
        return -1
    return st.st_size


def marked_download(path):
    """Does the system say a browser downloaded this file?"""
    if WINDOWS:
        try:
            with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return False
        m = re.search(r"^ZoneId=(\d+)", text, re.M)
        if not m or int(m.group(1)) < 3:  # 3: internet, 4: restricted sites
            return False
        # Unpacked by Explorer from a downloaded archive: the archive is named, not a website.
        referrer = re.search(r"^ReferrerUrl=(.*)$", text, re.M)
        return not (referrer and not re.search(r"^HostUrl=", text, re.M)
                    and not referrer.group(1).strip().lower().startswith(("http:", "https:")))
    if MACOS:
        r = subprocess.run(["/usr/bin/xattr", "-p", "com.apple.quarantine", str(path)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False
        # "flags;time;agent;id": sandboxed apps mark their own files too, so it takes a
        # known browser as the agent, or a download address (any browser saves one).
        agent = r.stdout.split(";")[2].lower().replace(" ", "") if r.stdout.count(";") >= 2 else ""
        if any(key in agent for key, _ in BROWSER_NAMES):
            return True
        return subprocess.run(["/usr/bin/xattr", "-p", "com.apple.metadata:kMDItemWhereFroms", str(path)],
                              capture_output=True).returncode == 0
    try:
        return bool(os.getxattr(path, "user.xdg.origin.url", follow_symlinks=False))  # Chromium on Linux
    except (OSError, AttributeError):
        return False


def browser_save_folders(file):
    """Folders a browser profile last saved to: Save As, or a download folder of its
    own (not quarantine)."""
    found = []
    try:
        if file.name == "prefs.js":
            prefs = read_prefs(file)
            values = [prefs.get("browser.download.lastDir")]
            if prefs.get("browser.download.folderList") == "2":
                values.append(prefs.get("browser.download.dir"))
            for value in values:
                if value and not is_quarantine(value):
                    folder = json.loads(value)
                    if isinstance(folder, str) and folder:
                        found.append(folder)
        else:
            data = json.loads(file.read_text(encoding="utf-8"))
            for section in ("savefile", "download"):
                folder = (data.get(section) or {}).get("default_directory") if isinstance(data, dict) else None
                if isinstance(folder, str) and folder and not same_path(folder):
                    found.append(folder)
    except (OSError, ValueError, AttributeError):
        return []
    return found


class FinishedDownloads:
    """Linux: files a browser just finished saving in the watched folders, through
    inotify: its partial file ("name.part", ".crdownload", ...) renamed to the final
    name. Firefox-based browsers mark nothing on Linux, so this is how they're seen."""

    MOVED_FROM, MOVED_TO, IGNORED = 0x40, 0x80, 0x8000

    def __init__(self):
        import ctypes
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify isn't available")
        self.folders = {}  # watch descriptor -> folder
        self.partial = {}  # rename cookie -> partial name
        self.done = set()  # finished downloads not looked at yet

    def watch(self, folders):
        for folder in folders:
            if folder not in self.folders.values():
                wd = self.libc.inotify_add_watch(self.fd, os.fsencode(folder), self.MOVED_FROM | self.MOVED_TO)
                if wd >= 0:
                    self.folders[wd] = folder

    def read(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            pos = 0
            while pos + 16 <= len(data):
                wd, mask, cookie, size = struct.unpack_from("iIII", data, pos)
                name = os.fsdecode(data[pos + 16:pos + 16 + size].rstrip(b"\0"))
                pos += 16 + size
                folder = self.folders.get(wd)
                if folder is None:
                    continue
                if mask & self.IGNORED:  # the folder is gone (deleted, unmounted): watched again once back
                    del self.folders[wd]
                elif mask & self.MOVED_FROM and name.lower().endswith(PARTIAL_SUFFIXES):
                    self.partial[cookie] = name
                elif mask & self.MOVED_TO and self.partial.pop(cookie, None) is not None and outside_name(name):
                    self.done.add(folder / name)
            if len(self.partial) > 1000:  # renames whose other half was never seen
                self.partial.clear()

    def take(self):
        done, self.done = self.done, set()
        return done


class Outside:
    def __init__(self, q):
        self.q = q          # its questions and ours take turns on screen
        self.seen = {}      # folder -> {name: size} at the last look
        self.queue = Queue()
        self.queued = set()
        self.full_logged = False
        self.sources = {}   # browser settings file -> its time at the last look
        self.fresh = set()  # folders learned just now: a download already in them counts
        self.finished = None
        if not (WINDOWS or MACOS):
            try:
                self.finished = FinishedDownloads()
            except OSError as e:
                log(f"can't watch folders for finished downloads: {e}")

    def scan(self):
        if watch_mode() == "off":
            self.seen.clear()  # turned on again, what was saved meanwhile isn't new
            if self.finished:
                self.finished.read()
                self.finished.take()
            return
        self.learn()
        folders = watched_folders()
        found = []
        if self.finished:
            self.finished.watch(folders)
            self.finished.read()
            for path in self.finished.take():
                try:
                    size = outside_size(os.stat(path, follow_symlinks=False))
                except OSError:
                    continue
                if path.parent in folders and size > 0:
                    found.append(path)
        seen = {}
        for folder in folders:
            try:
                with os.scandir(folder) as entries:
                    entries = list(entries)
            except OSError:
                continue
            before, now = self.seen.get(folder), {}
            first_look = before is None and folder in self.fresh
            self.fresh.discard(folder)
            for entry in entries:
                name = entry.name
                if not outside_name(name):
                    continue
                if before and before.get(name):  # seen before, not empty: not looked at again
                    now[name] = before[name]
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                now[name] = size = outside_size(st)
                if size <= 0:
                    continue
                path = Path(entry.path)
                # New, or an empty placeholder just filled in (Firefox makes one when a
                # download starts and renames its .part over it at the end). A file
                # that's edited later isn't taken again.
                if before is not None and marked_download(path):
                    found.append(path)
                elif first_look and time.time() - st.st_mtime < LEARN_WINDOW and marked_download(path):
                    found.append(path)  # the Save As that taught us this folder
            seen[folder] = now
        self.seen = seen
        for path in dict.fromkeys(found):
            if just_released(path):
                forget_released(path)
            elif path not in self.queued:
                self.enqueue(path)

    def learn(self):
        """Watch the folders the set-up browsers last saved to with Save As, or were set
        to download into (a changed download folder the user kept)."""
        try:
            record = json.loads(BROWSER_SETUP.read_text())
        except (OSError, ValueError):
            return
        files = [Path(e["profile"]) / "prefs.js" for e in record.get("firefox", []) if isinstance(e, dict) and "profile" in e]
        files += [Path(e["prefs"]) for e in record.get("chromium", []) if isinstance(e, dict) and "prefs" in e]
        for file in files:
            try:
                mtime = file.stat().st_mtime_ns
            except OSError:
                continue
            if self.sources.get(file) == mtime:
                continue
            first = file not in self.sources  # at start: those saves happened before
            self.sources[file] = mtime
            for folder in browser_save_folders(file):
                new = Path(os.path.abspath(folder)) not in watched_folders(any_mode=True)
                if add_folder(folder, learned=True) is None and new and not first:
                    self.fresh.add(Path(os.path.abspath(folder)))

    def enqueue(self, path):
        if self.queue.qsize() >= OUTSIDE_QUEUE_MAX:
            if not self.full_logged:
                log(f"too many new downloads in {path.parent} at once: not taking the rest")
                self.full_logged = True
            return
        self.full_logged = False
        self.queued.add(path)
        self.queue.put(path)

    def work(self):
        """Background: deal with queued downloads one at a time."""
        while True:
            path = self.queue.get()
            try:
                if wait_complete(path) and not just_released(path) and not self.cleared_before(path):
                    if watch_mode() == "move":
                        self.take_in(path)
                    elif watch_mode() == "check":
                        self.check(path)
            except Exception as e:
                log(f"error on {path}: {e}")
            finally:
                forget_released(path)
                self.queued.discard(path)

    @staticmethod
    def cleared_before(path):
        """The same contents went through quarantine already (a released download copied
        or moved to another folder)."""
        shas = read_released_shas()
        if shas and sha256(path, _open_nofollow) in shas:
            log(f"{path} was cleared before: leaving it")
            return True
        return False

    @staticmethod
    def take_in(path):
        """Move a download into quarantine (locked there like any other), remembering
        the folder it was saved to: it goes back there once it's clean or marked safe."""
        make_quarantine()
        dest = QUARANTINE / path.name
        n = 1
        while dest.exists() or dest.name in read_origins():
            dest = QUARANTINE / f"{path.stem} ({n}){path.suffix}"
            n += 1
        set_origin(dest.name, path.parent)  # first: quarantine may pick the file up at once
        try:
            if WINDOWS:
                # From another drive this is a copy: made under a name quarantine ignores.
                tmp = QUARANTINE / f".vtq-{uuid.uuid4().hex}.part"
                retry_locked(lambda: win_move(path, tmp))
                try:
                    os.replace(tmp, dest)
                except OSError:
                    win_move(tmp, path)
                    raise
            else:
                import errno
                try:
                    os.rename(path, dest)
                except OSError as e:
                    if e.errno != errno.EXDEV:
                        raise
                    # Another disk: copied in under a name quarantine ignores until it's whole.
                    tmp, _ = copy_out(path, QUARANTINE, suffix=".part")
                    os.replace(tmp, dest)
                    path.unlink()
        except BaseException:
            set_origin(dest.name, None)
            raise
        lock_file(dest)
        log(f"took {path} into quarantine")

    def check(self, path):
        sha = sha256(path, _open_nofollow)
        log(f"checking {path} (saved outside quarantine) {sha}")
        attrs = lookup(path.name, sha)
        if attrs is None:
            if path.stat().st_size > UPLOAD_MAX or not should_auto_upload(path, _open_nofollow):
                log(f"{path.name} is unknown to VirusTotal (not uploaded)")
                return
            stats, results, tags = upload(path, sha)
        else:
            stats, results, tags = attrs["last_analysis_stats"], attrs.get("last_analysis_results"), attrs.get("tags")
        log(verdict_line(path.name, stats, results))
        if classify(stats, tags) == "flagged":
            self.warn(path, sha, stats, results)

    def warn(self, path, sha, stats, results):
        _, _, _, body = detection_summary(stats, results)
        with self.q.asking:
            while path.exists():
                choice = notifier.notify(f"⚠ Flagged: {path.name}",
                                         f"{body}\nIt was saved to {html.escape(place_name(path.parent))} "
                                         "without going through quarantine.",
                                         "critical", "security-low", [("report", "Show report"), ("delete", "Delete")])
                if choice == "report":
                    open_url(report_url(sha))
                    time.sleep(2)  # so a repeated click doesn't land on the next popup
                    continue
                if choice == "delete":
                    delete(path)
                    notifier.tell("Deleted", html.escape(path.name), "user-trash-full")
                else:
                    log(f"left {path.name} where it is (notification dismissed)")
                return
