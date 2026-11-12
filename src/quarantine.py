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
        os.chmod(QUARANTINE, 0o700)
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


def sha256(path):
    h = hashlib.sha256()
    with open_nofollow(path) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_complete(path):
    """Wait until the browser has finished writing; False if the file went away."""
    part = path.with_name(path.name + ".part")
    last = None
    while True:
        try:
            st = path.stat()
        except FileNotFoundError:
            return False
        sig = (st.st_size, st.st_mtime_ns)
        if not part.exists() and sig == last:
            return True
        last = None if part.exists() else sig
        # Browsers only give a download its own name once it's finished; waiting for
        # it to stop changing is for anything else that saves there.
        time.sleep(STABLE_SECONDS)


FICLONE = 0x40049409  # Linux: share the data with a new file (Btrfs, XFS), no copying


def copy_out(path, folder):
    """A new file in folder holding what path holds right now: (the file, its SHA-256).
    A program that still has path open goes on writing to the old file, not this one."""
    fd, tmp = tempfile.mkstemp(prefix=".vtq-", dir=folder)
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
    """Move a file to Downloads. None (and it stays) if it no longer holds what was
    checked (sha). What arrives is a copy made and hashed here, so nothing that still
    has the download open can add to it afterwards. Windows moves the file itself (a
    copy would lose the mark that it came from the internet), once no program has
    it open."""
    dest = RELEASE_DIR / path.name
    n = 1
    while dest.exists():
        dest = RELEASE_DIR / f"{path.stem} ({n}){path.suffix}"
        n += 1
    unlock_file(path)
    try:
        if WINDOWS:
            changed = sha and retry_locked(lambda: sha256(path)) != sha
            if not changed:
                retry_locked(lambda: (nobody_has_open(path), shutil.move(path, dest)))
        else:
            tmp, copied = copy_out(path, RELEASE_DIR)
            changed = sha and copied != sha
            if changed:
                tmp.unlink()
            else:
                os.replace(tmp, dest)
                path.unlink()
    except BaseException:
        lock_file(path)
        raise
    if changed:
        lock_file(path)
        log(f"{path.name} changed after it was checked, checking again")
        return None
    log(f"moved {path.name} to {dest}")
    return dest


def delete(path):
    retry_locked(lambda: path.unlink(missing_ok=True))
    log(f"deleted {path.name}")


def should_auto_upload(path):
    if path.suffix.lower() in AUTO_UPLOAD_EXT:
        return True
    with open_nofollow(path) as f:
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
            return self.release_unchanged(path, sha, sig, "Clean — moved to Downloads",
                                          f"{name} (0/{total} detections)")
        return self.ask(path, sha, f"⚠ Flagged: {path.name}", body, "security-low",
                        flagged=True, detections=bad)

    def no_verdict(self, path, sha, sig, summary, body, icon, extra=(), report=True):
        """Ask about a file VirusTotal has no verdict on (unknown, unscannable or
        encrypted), unless it was marked safe before. Only these are remembered:
        a flagged file always warns, so a mis-click can't wave it through for good."""
        if not marked_safe(sha):
            return self.ask(path, sha, summary, body, icon, extra, report)
        log(f"{path.name} was marked safe before")
        return self.release_unchanged(path, sha, sig, "Marked safe before — moved to Downloads",
                                      html.escape(path.name))

    @staticmethod
    def release_unchanged(path, sha, sig, summary, body):
        """Move a cleared file to Downloads, unless it was written to since it was
        hashed (the verdict is for other contents: the next scan checks it again)."""
        if signature(path) != sig:
            log(f"{path.name} changed while being checked, checking again")
        elif dest := release(path, sha):
            tell_moved(summary, body, dest)
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
                    tell_moved("Moved to Downloads", f"{html.escape(path.name)}\nIt's still flagged: "
                               "if you download it again, you'll be warned again.", dest)
                    return False
                if sha:
                    remember_safe(sha, path.name)
                tell_moved("Marked safe — moved to Downloads", html.escape(path.name), dest)
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
