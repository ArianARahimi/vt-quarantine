#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Updates -----------------------------------------------------------------------

REPO = "ArianARahimi/vt-quarantine"
# Release downloads redirect from github.com to these; nothing else is followed.
UPDATE_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com",
                "release-assets.githubusercontent.com"}
UPDATE_MAX_BYTES = 64 * 1024**2
# Ed25519 keys whose signature on a release's SHA256SUMS makes it installable. The
# private key stays on the maintainer's computer, so whoever controls the GitHub
# repository still can't push code to anyone. A new key is added by a release
# signed with an old one.
RELEASE_KEYS = (
    "703f6d9f2f1df368340fe0ef973a427cf938c16c65187f66b5409b3c713f57d5",  # 2026-10-29
)
NO_AUTO_UPDATE = CONFIG_DIR / "no-auto-update"
QUIET_UPDATES = CONFIG_DIR / "quiet-updates"  # --auto-update quiet: no note after an update
UPDATED_MARKER = DATA_DIR / "updated"
# Windows: an update's .msi removes this copy the way an uninstall would. Windows says
# it's an upgrade (so the data stays), but not every Windows Installer does (Wine).
UPDATING_MARKER = DATA_DIR / "updating"
DECLINED_UPDATE = CONFIG_DIR / "declined-update"  # a version the user said no to


def ed25519_verify(public, message, signature):
    """Ed25519 signature check (RFC 8032, section 6), so updates need no crypto
    package. Only ever checks; nothing here signs or handles secrets."""
    p = 2**255 - 19
    order = 2**252 + 27742317777372353535851937790883648493
    d = -121665 * pow(121666, p - 2, p) % p
    sqrt_m1 = pow(2, (p - 1) // 4, p)

    def add(a, b):
        e = (a[1] - a[0]) * (b[1] - b[0]) % p
        f = (a[1] + a[0]) * (b[1] + b[0]) % p
        g = 2 * a[3] * b[3] * d % p
        h = 2 * a[2] * b[2] % p
        e, f, g, h = f - e, h - g, h + g, f + e
        return (e * f % p, g * h % p, f * g % p, e * h % p)

    def mul(n, point):
        result = (0, 1, 1, 0)
        while n:
            if n & 1:
                result = add(result, point)
            point = add(point, point)
            n >>= 1
        return result

    def same(a, b):
        return (a[0] * b[2] - b[0] * a[2]) % p == 0 and (a[1] * b[2] - b[1] * a[2]) % p == 0

    def recover_x(y, sign):
        if y >= p:
            return None
        x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
        if x2 % p == 0:
            return None if sign else 0
        x = pow(x2, (p + 3) // 8, p)
        if (x * x - x2) % p:
            x = x * sqrt_m1 % p
        if (x * x - x2) % p:
            return None
        return p - x if (x & 1) != sign else x

    def decompress(raw):
        y = int.from_bytes(raw, "little")
        sign, y = y >> 255, y & ((1 << 255) - 1)
        x = recover_x(y, sign)
        return None if x is None else (x, y, 1, x * y % p)

    if len(public) != 32 or len(signature) != 64:
        return False
    base_y = 4 * pow(5, p - 2, p) % p
    base_x = recover_x(base_y, 0)
    base = (base_x, base_y, 1, base_x * base_y % p)
    a, r = decompress(public), decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= order:
        return False
    if same(mul(8, a), (0, 1, 1, 0)):
        return False  # a small-order key, which any signature fits (as libsodium refuses)
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % order
    return same(mul(s, base), add(r, mul(h, a)))


class GitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in UPDATE_HOSTS:
            raise RuntimeError(f"update download redirected to {parts.scheme}://{parts.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


github_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_context), GitHubRedirects)


def use_system_tls():
    """Windows: check certificates the way Windows does (truststore), which fetches
    root certificates it doesn't have yet. Python's own check only sees the few a
    fresh Windows starts with, which can leave out VirusTotal's. Needs the pinned
    packages, so it's switched on once they're in."""
    global vt_opener, pypi_opener, github_opener
    if not WINDOWS:
        return
    try:
        import truststore
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception as e:
        log(f"can't check certificates through Windows ({e}), using Python's own list")
        return
    vt_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirects)
    pypi_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    github_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), GitHubRedirects)


def github_get(url, limit=UPDATE_MAX_BYTES):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in UPDATE_HOSTS:
        raise RuntimeError(f"refusing to fetch an update from {parts.scheme}://{parts.hostname}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/vnd.github+json"})
    with github_opener.open(req, timeout=120) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"{url} is larger than expected")
    return data


def parse_version(text):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(map(int, m.groups())) if m else None


def update_kind():
    """How this copy was installed, which decides how it updates (None: it doesn't)."""
    script = Path(__file__).resolve()
    if (script.parent / ".git").exists():
        return None  # a development checkout: git updates it
    if packaged():
        return "package"
    if WINDOWS and setup_installed():
        return "msi"
    if script == INSTALLED_SCRIPT.resolve():
        return "script"
    return None


def package_format():
    """The package manager that installed /usr/bin/vt-quarantine."""
    for fmt, cmd in (("arch", ["pacman", "-Qqo"]), ("deb", ["dpkg-query", "-S"]), ("rpm", ["rpm", "-qf"])):
        if shutil.which(cmd[0]) and subprocess.run([*cmd, "/usr/bin/vt-quarantine"],
                                                   capture_output=True).returncode == 0:
            return fmt
    return None


def update_asset(kind, version):
    v = "{}.{}.{}".format(*version)
    if kind == "script":
        return f"vt-quarantine-{v}.py"
    if kind == "msi":
        return f"vt-quarantine-{v}.msi"
    return {"deb": f"vt-quarantine_{v}-1_all.deb", "rpm": f"vt-quarantine-{v}-1.noarch.rpm",
            "arch": f"vt-quarantine-{v}-1-any.pkg.tar.zst"}.get(package_format())


def declined_version():
    try:
        return parse_version(DECLINED_UPDATE.read_text().strip())
    except (OSError, UnicodeDecodeError):
        return None


def find_update(kind, skip=None):
    """The newest stable release if it's newer than this one and than `skip`: (version,
    asset name, verified asset bytes, release page). None if there's nothing to install."""
    release = json.loads(github_get(f"https://api.github.com/repos/{REPO}/releases/latest", 1024**2))
    version = parse_version(release.get("tag_name"))
    if release.get("draft") or release.get("prerelease") or not version or version <= parse_version(VERSION):
        return None
    if skip and version <= skip:
        return None
    urls = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    name = update_asset(kind, version)
    if not name or not {name, "SHA256SUMS", "SHA256SUMS.sig"} <= urls.keys():
        log(f"version {release['tag_name']} has no signed {name or 'package for this system'}")
        return None
    sums = github_get(urls["SHA256SUMS"], 1024**2)
    signature = github_get(urls["SHA256SUMS.sig"], 1024)
    if not any(ed25519_verify(bytes.fromhex(key), sums, signature) for key in RELEASE_KEYS):
        raise RuntimeError(f"the signature on version {release['tag_name']} is not valid; not installing it")
    expected = {}
    for line in sums.decode().splitlines():
        digest, _, file = line.partition("  ")
        expected[file.lstrip("*")] = digest
    data = github_get(urls[name])
    if hashlib.sha256(data).hexdigest() != expected.get(name):
        raise RuntimeError(f"{name} doesn't match the signed checksum; not installing it")
    return version, name, data, release.get("html_url", "")


class Updater:
    """Checks for a new release once a day. Installs it right away where it can do
    that unattended (this program's own copy, or the Windows installer); a Linux
    package needs the administrator password, so that asks first. Restarting is
    left to run(), which does it while nothing is being checked."""

    def __init__(self):
        self.restart = threading.Event()
        self.next_check = time.monotonic() + 300  # not in the rush of signing in

    def due(self):
        return time.monotonic() >= self.next_check

    def check(self):
        self.next_check = time.monotonic() + UPDATE_CHECK_SECONDS
        kind = update_kind()
        if not kind or NO_AUTO_UPDATE.exists() or not RELEASE_KEYS:
            return
        # Neither ask nor install in the middle of a game: wait it out (in this
        # thread), then go ahead straight away.
        wait_for_free_screen("the update check")
        try:
            # Someone who said no to a version isn't asked again until the next one.
            found = find_update(kind, declined_version() if kind == "package" else None)
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            log(f"update check failed: {e}")
            return
        if found:
            self.install(kind, *found)

    def install(self, kind, version, name, data, page):
        v = "{}.{}.{}".format(*version)
        if kind == "script":
            UPDATED_MARKER.write_text(v)
            tmp = INSTALLED_SCRIPT.with_name(INSTALLED_SCRIPT.name + ".new")
            tmp.write_bytes(data)
            os.replace(tmp, INSTALLED_SCRIPT)
        elif kind == "msi":
            msi = DATA_DIR / name
            msi.write_bytes(data)
            UPDATED_MARKER.write_text(v)
            UPDATING_MARKER.write_text(v)
            # It stops this copy and starts the new one; cmd starts it again once the
            # install is done, should that not have worked (a second copy just exits).
            pythonw = Path(sys.executable).with_name("pythonw.exe")
            steps = (f'start "" /wait "{SYSTEM32 / "msiexec.exe"}" /i "{msi}" /qn /norestart'
                     f' & start "" "{pythonw}" "{INSTALLED_SCRIPT}"')
            subprocess.Popen(f'"{SYSTEM32 / "cmd.exe"}" /d /s /c "{steps}"', close_fds=True, cwd=str(DATA_DIR),
                             creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            log(f"installing version {v}")
            return
        else:
            # Stays up until answered (a passing popup is easy to miss), and reading
            # the release notes doesn't use up the offer.
            while True:
                choice = notifier.notify(f"vt-quarantine {v} is available",
                                         "Installing it asks for your administrator password.",
                                         "critical", "system-software-update",
                                         [("update", "Update"), ("notes", "What's new")])
                if choice != "notes":
                    break
                open_url(page)
                time.sleep(2)  # so a repeated click doesn't land on the next popup
            if choice == "":
                self.decline(v)
            if choice != "update":
                return  # None (couldn't be shown): offered again at the next check
            if not self.install_package(v, name, data):
                return
            UPDATED_MARKER.write_text(v)
        log(f"updated to version {v}")
        self.restart.set()

    def decline(self, v):
        """Closing the offer (or the password prompt) means no to this version."""
        log(f"version {v} declined; the next release will be offered")
        try:
            DECLINED_UPDATE.parent.mkdir(parents=True, exist_ok=True)
            DECLINED_UPDATE.write_text(v)
        except OSError as e:
            log(f"could not save that: {e}")

    def install_package(self, v, name, data):
        folder = Path(tempfile.mkdtemp(prefix="vt-quarantine-update-"))
        try:
            package = folder / name
            package.write_bytes(data)
            # The package manager runs as root and must be able to read it; others
            # may read it too (it's public), but only this user can change it.
            os.chmod(folder, 0o755)  # noqa: S103  # nosec B103
            os.chmod(package, 0o644)
            cmd = {"deb": ["apt-get", "install", "-y"], "rpm": ["dnf", "install", "-y"],
                   "arch": ["pacman", "-U", "--noconfirm"]}[package_format()]
            r = subprocess.run(["pkexec", *cmd, str(package)], capture_output=True, text=True)
            if r.returncode == 126:  # the password prompt was closed
                self.decline(v)
                return False
            if r.returncode:
                log(f"package update failed: {r.stderr.strip()[-500:]}")
                notifier.notify("Update not installed", "It failed; vt-quarantine will try "
                                "again tomorrow.", "normal", "dialog-error")
                return False
            return True
        except (OSError, KeyError) as e:
            log(f"package update failed: {e}")
            return False
        finally:
            shutil.rmtree(folder, ignore_errors=True)


def restart(lock):
    """Run the updated program in place of this one."""
    script = str(Path(__file__).resolve())
    if WINDOWS:
        lock.close()  # so the new copy can take it
        subprocess.Popen([sys.executable, script], close_fds=True, cwd=str(DATA_DIR),
                         creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        os._exit(0)
    # Same process, so systemd and launchd keep tracking it; the lock file
    # descriptor isn't inherited, so the new program takes the lock afresh.
    os.execv(sys.executable, [sys.executable, script])  # noqa: S606  # nosec B606


def set_auto_update(state):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    for marker, wanted in ((NO_AUTO_UPDATE, state == "off"), (QUIET_UPDATES, state == "quiet")):
        if wanted:
            marker.touch()
        else:
            marker.unlink(missing_ok=True)
    if state == "off":
        print("Automatic updates are off. vt-quarantine won't contact GitHub.")
    elif state == "quiet":
        print("Automatic updates are on, without a notification when one is installed.\n"
              "(A Linux package still asks first: installing it needs your password.)")
    else:
        print("Automatic updates are on: vt-quarantine checks GitHub for a new release once a day.")
    if update_kind() is None:
        print("(This copy doesn't update itself: it's a development checkout or wasn't set up "
              "with --install or an installer.)")
