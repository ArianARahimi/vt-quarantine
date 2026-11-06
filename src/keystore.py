#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- API key -------------------------------------------------------------------------
# The key is kept in the system's own password store: on Windows encrypted for this
# Windows account (DPAPI), on macOS in the Keychain, on Linux in the Secret Service
# (KWallet, GNOME Keyring). So it's unreadable from a copied disk, a backup or another
# account. Without a store it stays in a file only this user can read. A key put into
# that file (by hand, or by the old Windows setup) is moved into the store.

class KeyStoreLocked(Exception):
    """The key is in a password store that's locked, and it wasn't unlocked."""


class DpapiStore:
    name = "Windows' protected storage"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    @staticmethod
    def crypt(data, protect):
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        buf = ctypes.create_string_buffer(data, len(data))
        src, out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
        crypt32 = ctypes.windll.crypt32
        call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        # 1: CRYPTPROTECT_UI_FORBIDDEN
        if not call(ctypes.byref(src), "vt-quarantine API key" if protect else None, None, None, None, 1,
                    ctypes.byref(out)):
            raise OSError(ctypes.GetLastError(), "Windows couldn't " + ("protect" if protect else "unprotect")
                          + " the key")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))

    def get(self):
        try:
            return self.crypt(DPAPI_FILE.read_bytes(), False).decode().strip()
        except FileNotFoundError:
            return ""

    def put(self, key):
        DPAPI_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DPAPI_FILE.with_name(DPAPI_FILE.name + ".new")
        tmp.write_bytes(self.crypt(key.encode(), True))
        os.replace(tmp, DPAPI_FILE)

    def delete(self):
        DPAPI_FILE.unlink(missing_ok=True)


class KeychainStore:
    name = "the macOS Keychain"
    ITEM = ["-a", "vt-quarantine", "-s", "vt-quarantine"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def get(self):
        r = subprocess.run(["security", "find-generic-password", *self.ITEM, "-w"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 44:  # not there
            return ""
        if r.returncode:
            raise OSError(r.stderr.strip() or f"security exited with {r.returncode}")
        return r.stdout.strip()

    def put(self, key):
        # Given through stdin, so it never shows in the list of running programs.
        # (It's 64 hex digits: nothing in it needs quoting.)
        r = subprocess.run(["security", "-i"], capture_output=True, text=True, timeout=60,
                           input=f'add-generic-password -U {" ".join(self.ITEM)} '
                                 f'-l "VirusTotal API key (vt-quarantine)" -w {key}\n')
        if r.returncode:
            raise OSError(r.stderr.strip() or f"security exited with {r.returncode}")

    def delete(self):
        subprocess.run(["security", "delete-generic-password", *self.ITEM], capture_output=True, timeout=60)


class SecretServiceStore:
    """The freedesktop Secret Service. The key travels over this user's own session
    bus, so a plain session is enough."""

    name = "your system's password store (Secret Service)"
    BUS = "org.freedesktop.secrets"
    PREFIX = "org.freedesktop.Secret."
    ATTRIBUTES = {"application": "vt-quarantine"}

    def __enter__(self):
        from jeepney.io.blocking import open_dbus_connection
        self.conn = open_dbus_connection("SESSION")
        try:
            self.session = self.call("/org/freedesktop/secrets", "Service", "OpenSession", "sv",
                                     ("plain", ("s", "")))[1]
        except Exception:
            self.conn.close()
            raise
        return self

    def __exit__(self, *exc):
        self.conn.close()

    def call(self, path, interface, method, signature=None, body=()):
        from jeepney import DBusAddress, new_method_call
        from jeepney.wrappers import unwrap_msg
        address = DBusAddress(path, bus_name=self.BUS, interface=self.PREFIX + interface)
        return unwrap_msg(self.conn.send_and_get_reply(new_method_call(address, method, signature, body),
                                                       timeout=30))

    def prompt(self, path):
        """Show the store's own prompt (to unlock it, say); False if it was closed."""
        if path == "/":
            return True
        from jeepney import MatchRule, message_bus
        from jeepney.wrappers import unwrap_msg
        rule = MatchRule(type="signal", interface=self.PREFIX + "Prompt", member="Completed", path=path)
        with self.conn.filter(rule) as completed:
            unwrap_msg(self.conn.send_and_get_reply(message_bus.AddMatch(rule), timeout=10))
            self.call(path, "Prompt", "Prompt", "s", ("",))
            dismissed, _result = self.conn.recv_until_filtered(completed, timeout=600).body
        return not dismissed

    def unlock(self, paths):
        _unlocked, prompt = self.call("/org/freedesktop/secrets", "Service", "Unlock", "ao", (paths,))
        if not self.prompt(prompt):
            raise KeyStoreLocked("the password store stayed locked")

    def items(self):
        unlocked, locked = self.call("/org/freedesktop/secrets", "Service", "SearchItems", "a{ss}",
                                     (self.ATTRIBUTES,))
        if locked:
            self.unlock(locked)
        return list(unlocked) + list(locked)

    def get(self):
        items = self.items()
        if not items:
            return ""
        secrets = self.call("/org/freedesktop/secrets", "Service", "GetSecrets", "aoo",
                            (items[:1], self.session))[0]
        return bytes(secrets[items[0]][2]).decode().strip()

    def put(self, key):
        collection = self.call("/org/freedesktop/secrets", "Service", "ReadAlias", "s", ("default",))[0]
        if collection == "/":
            raise OSError("there's no default keyring")
        self.unlock([collection])
        properties = {self.PREFIX + "Item.Label": ("s", "VirusTotal API key (vt-quarantine)"),
                      self.PREFIX + "Item.Attributes": ("a{ss}", self.ATTRIBUTES)}
        _item, prompt = self.call(collection, "Collection", "CreateItem", "a{sv}(oayays)b",
                                  (properties, (self.session, b"", key.encode(), "text/plain"), True))
        if not self.prompt(prompt):
            raise KeyStoreLocked("the key wasn't saved")

    def delete(self):
        for item in self.items():
            self.prompt(self.call(item, "Item", "Delete")[0])


_said_no_store = False


def key_store():
    """The password store to keep the key in, or None (then it stays in KEY_FILE)."""
    global _said_no_store
    if WINDOWS:
        return DpapiStore()
    if MACOS:
        return KeychainStore()
    try:
        with SecretServiceStore():
            pass
        return SecretServiceStore()
    except Exception as e:
        if not _said_no_store:  # a plain key is read again before every request
            _said_no_store = True
            log(f"no password store ({e}); the API key stays in {KEY_FILE}")
        return None


def read_plain_key():
    try:
        return KEY_FILE.read_text().strip()
    except (OSError, UnicodeDecodeError):
        return ""


def write_plain_key(key):
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")
    if not WINDOWS:
        os.chmod(KEY_FILE, 0o600)


def read_key():
    """The saved API key ("" if there's none). A key found in the plain file is moved
    into the password store. Raises KeyStoreLocked if the store stayed locked."""
    plain = read_plain_key()
    store = key_store()
    if store is None:
        return plain
    try:
        with store:
            if not plain:
                return store.get()
            store.put(plain)
            if store.get() == plain:
                KEY_FILE.unlink(missing_ok=True)
                log(f"moved the API key into {store.name}")
            return plain
    except KeyStoreLocked:
        if plain:
            return plain
        raise
    except Exception as e:
        log(f"could not use {store.name}: {e}")
        return plain


def key_status():
    try:
        key = read_key()
    except KeyStoreLocked:
        return "in a locked password store"
    if not key:
        return "MISSING"
    store = key_store()
    return f"saved in {store.name}" if store and not KEY_FILE.exists() else f"saved in {KEY_FILE}"


def save_key(key):
    """Keep the key in the password store (or the plain file); returns where it went."""
    store = key_store()
    if store is not None:
        try:
            with store:
                store.put(key)
                if store.get() == key:
                    KEY_FILE.unlink(missing_ok=True)
                    where = store.name
                else:
                    raise OSError("it didn't read back the same")
        except Exception as e:
            log(f"could not use {store.name}: {e}")
            write_plain_key(key)
            where = str(KEY_FILE)
    else:
        write_plain_key(key)
        where = str(KEY_FILE)
    KEY_CHANGED.parent.mkdir(parents=True, exist_ok=True)
    KEY_CHANGED.touch()
    return where


def forget_key():
    store = key_store()
    if store is not None:
        try:
            with store:
                store.delete()
        except Exception as e:
            log(f"could not remove the key from {store.name}: {e}")
    for f in (KEY_FILE, DPAPI_FILE, KEY_CHANGED):
        f.unlink(missing_ok=True)


_key_seen = None


def key_changed():
    """Has a new key been saved since the last look? (A key is read from the store
    once, not before every request: a store that has locked itself in the meantime
    would ask for its password at a random moment.)"""
    global _key_seen
    try:
        stamp = KEY_CHANGED.stat().st_mtime_ns
    except OSError:
        stamp = None
    changed = stamp != _key_seen or KEY_FILE.exists()
    _key_seen = stamp
    return changed
