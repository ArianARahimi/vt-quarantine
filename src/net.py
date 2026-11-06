#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- HTTPS -----------------------------------------------------------------------

def ssl_context():
    context = ssl.create_default_context()
    # The python.org macOS build doesn't use the system's certificates unless its
    # "Install Certificates" step was run; macOS keeps a bundle at /etc/ssl/cert.pem.
    if MACOS and not context.cert_store_stats()["x509_ca"] and os.path.exists("/etc/ssl/cert.pem"):
        context.load_verify_locations("/etc/ssl/cert.pem")
    return context


class NoRedirects(urllib.request.HTTPRedirectHandler):
    # The VirusTotal API doesn't redirect; following one would send the API key
    # wherever it points.
    def redirect_request(self, *args, **kwargs):
        return None


_context = ssl_context()
vt_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_context), NoRedirects)
pypi_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_context))


class Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def json(self):
        return json.loads(self.body)

    def raise_for_status(self):
        if self.status_code >= 300:
            try:
                detail = ": " + self.json()["error"]["message"]
            except Exception:
                detail = ""
            raise RuntimeError(f"VirusTotal returned HTTP {self.status_code}{detail}")


def multipart(f, filename):
    """Stream an upload as multipart/form-data without reading it all into memory."""
    boundary = uuid.uuid4().hex
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    size = os.fstat(f.fileno()).st_size

    def body():
        yield head
        yield from iter(lambda: f.read(1 << 20), b"")
        yield tail

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}",
               "Content-Length": str(len(head) + size + len(tail))}
    return body(), headers


def upload_name(path):
    """VT shows submission names to subscribers, so send a generic one. The
    extension is kept (it helps the scan) but cut down to letters and digits, so
    a crafted filename can't break out of the multipart header."""
    ext = re.sub(r"[^a-z0-9]", "", path.suffix.lower())[:16]
    return "sample." + ext if ext else "sample"


api_key = ""  # set in run()


def http_request(method, url, upload=None):
    headers = {"x-apikey": api_key, "Accept": "application/json", "User-Agent": USER_AGENT}
    data = None
    if upload is not None:
        data, extra = multipart(*upload)
        headers.update(extra)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with vt_opener.open(req, timeout=600 if upload else 60) as resp:
            return Response(resp.status, resp.read())
    except urllib.error.HTTPError as e:
        with e:
            return Response(e.code, e.read())


# --- Runtime installation of packages ------------------------------------------

def wheel_tags():
    """Wheel tags (python-abi-platform) this interpreter can load, best first.
    Only what the pinned wheels need: CPython on Windows, plus pure Python."""
    tags = []
    if WINDOWS and platform.python_implementation() == "CPython":
        machine = platform.machine().upper()
        if struct.calcsize("P") == 4:
            plat = "win32"
        elif machine in ("ARM64", "AARCH64"):
            plat = "win_arm64"
        else:
            plat = "win_amd64"
        cp = "cp{}{}".format(*sys.version_info[:2])
        tags += [f"{cp}-{cp}-{plat}", f"{cp}-abi3-{plat}"]
    return tags + ["py3-none-any", "py2.py3-none-any"]


def pick_wheel(files):
    """The (filename, sha256) of the best wheel for this interpreter, or None."""
    by_tag = {"-".join(name[:-len(".whl")].split("-")[-3:]): (name, sha) for name, sha in files.items()}
    for tag in wheel_tags():
        if tag in by_tag:
            return by_tag[tag]
    return None


def pinned_wheels():
    return WHEELS.get("linux" if sys.platform.startswith("linux") else sys.platform, [])


def pin_id():
    """Identifies the wheel set (and so the folder they are unpacked into)."""
    return hashlib.sha256(json.dumps([pick_wheel(files) for _, _, files in pinned_wheels()])
                          .encode()).hexdigest()


def bundled_wheel(filename, sha):
    """The wheel as the Windows installer brought it, if it's there and intact."""
    try:
        data = (BUNDLED_WHEELS / filename).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(data).hexdigest() != sha:
        log(f"bundled {filename} does not match its pinned SHA-256; downloading it instead")
        return None
    return data


def download_wheel(name, filename, sha):
    """Fetch one wheel from PyPI and check its hash; returns the bytes."""
    project = re.sub(r"[-_.]+", "-", name).lower()
    req = urllib.request.Request(f"https://pypi.org/simple/{project}/", headers={
        "Accept": "application/vnd.pypi.simple.v1+json", "User-Agent": USER_AGENT})
    with pypi_opener.open(req, timeout=60) as resp:
        index = json.load(resp)
    url = next((f["url"] for f in index["files"] if f["filename"] == filename), None)
    if not url or urllib.parse.urlsplit(url).scheme != "https":
        raise RuntimeError(f"{filename} is not on PyPI")
    with pypi_opener.open(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}),
                          timeout=300) as resp:
        data = resp.read()
    if hashlib.sha256(data).hexdigest() != sha:
        raise RuntimeError(f"{filename} does not match its pinned SHA-256; refusing to install it")
    return data


def unpack_wheel(data, filename, dest):
    """Unpack a (verified) wheel. The pinned wheels are plain packages, which is
    all pip would do with them too; anything else is refused."""
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        for name in wheel.namelist():
            parts = name.replace("\\", "/").split("/")
            if name.startswith(("/", "\\")) or ":" in name or ".." in parts or parts[0].endswith(".data"):
                raise RuntimeError(f"{filename} contains an unexpected path {name!r}")
        wheel.extractall(dest)


def lib_dir():
    """Where the pinned packages for this Python go; a new pin set gets a new folder,
    so upgrading never touches files a running copy has loaded."""
    return LIB_ROOT / "py{}.{}-{}".format(*sys.version_info[:2], pin_id()[:16])


def remove_old_libs():
    """Delete package folders left by older versions (for this Python version)."""
    current = lib_dir()
    prefix = "py{}.{}-".format(*sys.version_info[:2])
    try:
        old = [d for d in LIB_ROOT.iterdir() if d.name.startswith(prefix) and d != current]
    except OSError:
        return
    for d in old:
        shutil.rmtree(d, ignore_errors=True)


def install_requirements():
    """Make the pinned packages importable (fetching them into lib_dir() if needed)
    and start using them. Returns False (after logging why) if that didn't work."""
    if not _install_requirements():
        return False
    use_system_tls()
    return True


def _install_requirements():
    wheels = pinned_wheels()
    if not wheels:
        return True
    if packaged():
        # Package dependencies, kept up to date by the distribution.
        import importlib
        for module, name, _files in wheels:
            try:
                importlib.import_module(module)
            except ImportError:
                log(f"{name} is missing: reinstall the vt-quarantine package, "
                    f"or install python3-{name} (python-{name} on Arch)")
                return False
        return True
    target = lib_dir()
    if str(target) not in sys.path:
        # Ahead of site-packages, so the pinned versions are the ones used.
        sys.path.insert(0, str(target))
    if target.is_dir():  # only ever appears complete (renamed into place)
        return True
    try:
        LIB_ROOT.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="staging-", dir=LIB_ROOT))
        try:
            for _module, name, files in wheels:
                picked = pick_wheel(files)
                if not picked:
                    raise RuntimeError(f"no pinned {name} wheel for this Python "
                                       f"({platform.python_version()}, {platform.machine()})")
                data = bundled_wheel(*picked)
                if data is None:
                    log(f"downloading {picked[0]}")
                    data = download_wheel(name, *picked)
                unpack_wheel(data, picked[0], staging)
            try:
                os.replace(staging, target)
            except OSError:
                if not target.is_dir():  # not just another copy finishing first
                    raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
        log(f"could not install packages: {e}")
        return False
    import importlib
    importlib.invalidate_caches()
    log(f"installed {', '.join(name for _, name, _ in wheels)} into {target}")
    return True
