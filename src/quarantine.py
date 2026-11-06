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


def release(path):
    unlock_file(path)
    dest = RELEASE_DIR / path.name
    n = 1
    while dest.exists():
        dest = RELEASE_DIR / f"{path.stem} ({n}){path.suffix}"
        n += 1
    retry_locked(lambda: shutil.move(path, dest))
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
            return attrs
        if queued:
            log(f"{name} is known to VT but not analysed yet, waiting")
            queued()
            queued = None
        time.sleep(QUEUED_RECHECK_SECONDS)
    raise RuntimeError("VirusTotal has no finished analysis yet")


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
    analysis = r.json()["data"]["id"]
    log(f"uploaded {path.name}, waiting for analysis")
    deadline = time.monotonic() + ANALYSIS_TIMEOUT
    status = None
    while time.monotonic() < deadline:
        time.sleep(ANALYSIS_POLL_SECONDS)
        r = vt("GET", f"/analyses/{analysis}")
        if r.status_code == 404:  # VirusTotal can take a moment to list a new analysis
            log(f"analysis of {path.name}: not listed yet")
            continue
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        if attrs["status"] != status:
            status = attrs["status"]
            log(f"analysis of {path.name}: {status}")
        if attrs["status"] == "completed":
            # The analysis object has no tags; the file object says if it is encrypted.
            r = vt("GET", f"/files/{sha}")
            r.raise_for_status()
            return attrs["stats"], attrs.get("results"), r.json()["data"]["attributes"].get("tags")
    raise RuntimeError("VirusTotal analysis timed out")


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

    def check(self, path):
        """Returns True if the file was left in quarantine for the user."""
        sig = signature(path)
        sha = sha256(path)
        log(f"checking {path.name} {sha}")
        progress = None

        def queued():
            nonlocal progress
            progress = Progress("Scanning on VirusTotal",
                                f"{html.escape(path.name)} stays in quarantine until "
                                "the scan finishes.", sha)

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
        progress = Progress("Scanning on VirusTotal",
                            f"{html.escape(path.name)} stays in quarantine until the scan "
                            "finishes (usually a few minutes).", sha)
        try:
            stats, results, tags = upload(path, sha)
        finally:
            progress.close()
        return self.verdict(path, sha, sig, stats, results, tags)

    def verdict(self, path, sha, sig, stats, results, tags=None):
        log(verdict_line(path.name, stats, results))
        bad, sus, total, body = detection_summary(stats, results)
        if total == 0:
            return self.no_verdict(path, sha, sig, "No engines could scan this file",
                            f"{html.escape(path.name)} got no verdict from any engine.",
                            "dialog-warning")
        if bad == 0 and sus == 0 and "encrypted" in (tags or ()):
            # Engines can't see inside a password-protected archive, so 0 detections
            # means nothing; this is a common way to slip malware past scanners.
            return self.no_verdict(path, sha, sig, "Encrypted archive",
                            f"{html.escape(path.name)} is password-protected, so VirusTotal "
                            f"could not scan its contents (0/{total} means nothing here).",
                            "dialog-warning")
        if bad == 0 and sus == 0:
            if signature(path) != sig:
                # Written to since it was hashed: the verdict is for other contents.
                log(f"{path.name} changed while being checked, checking again")
                return False
            dest = release(path)
            tell_moved("Clean — moved to Downloads", f"{html.escape(path.name)} (0/{total} detections)", dest)
            return False
        return self.ask(path, sha, f"⚠ Flagged: {path.name}", body, "security-low",
                        flagged=True, detections=bad)

    def no_verdict(self, path, sha, sig, summary, body, icon, extra=(), report=True):
        """Ask about a file VirusTotal has no verdict on (unknown, unscannable or
        encrypted), unless it was marked safe before. Only these are remembered:
        a flagged file always warns, so a mis-click can't wave it through for good."""
        if not marked_safe(sha):
            return self.ask(path, sha, summary, body, icon, extra, report)
        if signature(path) != sig:
            log(f"{path.name} changed while being checked, checking again")
            return False
        log(f"{path.name} was marked safe before")
        dest = release(path)
        tell_moved("Marked safe before — moved to Downloads", html.escape(path.name), dest)
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
                dest = release(path)
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
