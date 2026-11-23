#!/usr/bin/env python3
"""Check that every file of a release holds only what the tagged source and its pins make.

    tools/check_release.py TREE ASSET...

TREE is the source at the release tag (git archive). Linux packages must hold exactly the
files linux/build.sh installs, each equal to the tag's copy, and no install scripts. The
macOS zip is rebuilt from the tag (pinned Pythons) and compared file by file. The MSI's
files must be the tag's program, the pinned Python and wheels, and its tables (custom
actions, registry, shortcuts, folders, removals) must be what windows/build.py writes; any
other table must be empty. Run by tools/sign-release.sh; exits 1 if anything differs.
Pinned downloads are cached in VTQ_BUILD_CACHE (checked against their pins on every use).
"""
import importlib.util
import io
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET  # nosec B405  # parses the XML the tag's own build script writes
import zipfile
import zlib
from pathlib import Path

CACHE = Path(os.environ.get("VTQ_BUILD_CACHE") or Path.home() / ".cache" / "vt-quarantine-release")


class Mismatch(Exception):
    pass


def expect(ok, what):
    if not ok:
        raise Mismatch(what)


# --- Icons: drawn by windows/build.py and stored as PNG, whose zlib output varies by version.

def png_pixels(data):
    expect(data[:8] == b"\x89PNG\r\n\x1a\n", "icon image isn't a PNG")
    pos, head, idat = 8, None, b""
    while pos < len(data):
        n, kind = struct.unpack_from(">I4s", data, pos)
        body = data[pos + 8:pos + 8 + n]
        pos += 12 + n
        if kind == b"IHDR":
            head = body
        elif kind == b"IDAT":
            idat += body
        elif kind != b"IEND":
            raise Mismatch(f"unexpected PNG chunk {kind!r}")
    return head, zlib.decompress(idat)


def icns_images(data):
    expect(data[:4] == b"icns", "not an icns file")
    out, pos = [], 8
    while pos < len(data):
        kind, n = struct.unpack_from(">4sI", data, pos)
        out.append((kind, png_pixels(data[pos + 8:pos + n])))
        pos += n
    return out


def ico_images(data):
    _, kind, count = struct.unpack_from("<HHH", data)
    expect(kind == 1, "not an ico file")
    out = []
    for i in range(count):
        entry = data[6 + 16 * i:22 + 16 * i]
        size, offset = struct.unpack_from("<II", entry, 8)
        image = data[offset:offset + size]
        out.append((entry[:8], png_pixels(image) if image[:4] == b"\x89PNG" else image))
    return out


# --- Archives

def tar_members(data):
    """(name, TarInfo, bytes or None) of any archive bsdtar reads, rewritten as plain tar."""
    tar = subprocess.run(["bsdtar", "-cf", "-", "--format=pax", "@-"], input=data, capture_output=True, check=True).stdout
    out = []
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as t:
        for m in t.getmembers():
            name = m.name[2:] if m.name.startswith("./") else m.name
            out.append((name.rstrip("/"), m, t.extractfile(m).read() if m.isreg() else None))
    return out


def ar_members(data):
    expect(data[:8] == b"!<arch>\n", "not an ar archive")
    out, pos = [], 8
    while pos < len(data):
        head = data[pos:pos + 60]
        name, size = head[:16].decode().strip().rstrip("/"), int(head[48:58])
        out.append((name, data[pos + 60:pos + 60 + size]))
        pos += 60 + size + size % 2
    return out


def linux_files(tree, license_path):
    """What linux/build.sh installs: {path: (bytes, mode)}."""
    program = (tree / "vt-quarantine").read_bytes()
    program = program.replace(b"#!/usr/bin/env python3\n", b"#!/usr/bin/python3\n", 1)
    linux = tree / "linux"
    return {
        "usr/bin/vt-quarantine": (program, 0o755),
        "usr/lib/systemd/user/vt-quarantine.service": ((linux / "vt-quarantine.service").read_bytes(), 0o644),
        "usr/share/applications/vt-quarantine.desktop": ((linux / "vt-quarantine.desktop").read_bytes(), 0o644),
        "usr/share/polkit-1/actions/io.github.arianarahimi.vt-quarantine.update.policy":
            ((linux / "vt-quarantine.policy").read_bytes(), 0o644),
        "usr/share/doc/vt-quarantine/README.md": ((tree / "README.md").read_bytes(), 0o644),
        "usr/share/doc/vt-quarantine/user.js": ((tree / "browser" / "user.js").read_bytes(), 0o644),
        license_path: ((tree / "LICENSE").read_bytes(), 0o644),
    }


def check_payload(members, expected, allowed_extra=()):
    """Exactly the expected files (bytes, mode, root-owned); folders only above them."""
    parents = set()
    for p in expected:
        for parent in Path(p).parents:
            parents.add(str(parent))
    found = {}
    for name, m, data in members:
        if name in ("", ".") or name in allowed_extra:
            continue
        expect(m.uid == 0 and m.gid == 0, f"{name} isn't owned by root")
        if m.isdir():
            expect(name in parents, f"unexpected folder {name}")
            continue
        expect(m.isreg(), f"{name} isn't a regular file")
        expect(name not in found, f"{name} is in the package twice")
        found[name] = (data, m.mode & 0o7777)
    expect(set(found) == set(expected), f"files differ: extra {sorted(set(found) - set(expected))}, "
                                        f"missing {sorted(set(expected) - set(found))}")
    for name, (data, mode) in expected.items():
        expect(found[name][0] == data, f"{name} differs from the tag")
        expect(found[name][1] == mode, f"{name} has mode {found[name][1]:o}, not {mode:o}")


def tree_version(tree):
    for line in (tree / "vt-quarantine").read_text(encoding="utf-8").splitlines():
        if line.startswith('VERSION = "'):
            return line.split('"')[1]
    raise Mismatch("no VERSION in the tag's program")


def check_deb(tree, data):
    members = ar_members(data)
    names = [n for n, _ in members]
    expect(len(names) == 3 and names[0] == "debian-binary" and names[1].startswith("control.tar")
           and names[2].startswith("data.tar"), f"unexpected .deb members {names}")
    expect(members[0][1] == b"2.0\n", "unexpected debian-binary")
    control = [(n, m, d) for n, m, d in tar_members(members[1][1]) if n not in ("", ".")]
    expect([n for n, _, _ in control] == ["control"] and control[0][1].isreg(),
           f"control.tar holds {[n for n, _, _ in control]}: install scripts or other files")
    fields = {}
    for line in control[0][2].decode().splitlines():
        if line and not line.startswith(" "):
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    allowed = {"Package", "Version", "Architecture", "Maintainer", "Installed-Size", "Depends", "Section",
               "Priority", "Homepage", "Description"}
    expect(set(fields) <= allowed, f"unexpected control fields {sorted(set(fields) - allowed)}")
    v = tree_version(tree)
    for key, value in (("Package", "vt-quarantine"), ("Version", f"{v}-1"), ("Architecture", "all"),
                       ("Depends", "python3 (>= 3.9), python3-jeepney")):
        expect(fields.get(key) == value, f"control {key} is {fields.get(key)!r}")
    check_payload(tar_members(members[2][1]), linux_files(tree, "usr/share/doc/vt-quarantine/copyright"))


# RPM header tags rpmbuild writes for this package; anything else (install scripts,
# triggers, their interpreters) is refused rather than recognized by number.
RPM_TAGS = {63, 100, 1000, 1001, 1002, 1004, 1005, 1006, 1007, 1009, 1014, 1016, 1020, 1021, 1022, 1028, 1030,
            1033, 1034, 1035, 1036, 1037, 1039, 1040, 1044, 1045, 1047, 1048, 1049, 1050, 1064, 1095, 1096,
            1097, 1112, 1113, 1116, 1117, 1118, 1122, 1124, 1125, 1126, 1132, 1140, 1141, 1142, 1143, 1144,
            1145, 5011, 5062, 5092, 5093, 5097}
RPM_SCRIPTS = {1023, 1024, 1025, 1026, 1065, 1079, 1085, 1086, 1087, 1088, 1091, 1092, 1151, 1152, 1153, 1154,
               5066, 5067, 5076, 5077, 5104, 5105, 5106, 5107}


def rpm_header(data, off):
    expect(data[off:off + 3] == b"\x8e\xad\xe8", "not an RPM header")
    count, size = struct.unpack_from(">II", data, off + 8)
    index, store = off + 16, off + 16 + 16 * count
    tags = {}
    for i in range(count):
        tag, kind, o, _ = struct.unpack_from(">IIII", data, index + 16 * i)
        tags[tag] = data[store + o:data.index(b"\0", store + o)].decode() if kind in (6, 9) else None
    return tags, store + size


def check_rpm(tree, data):
    expect(data[:4] == b"\xed\xab\xee\xdb", "not an RPM")
    _, end = rpm_header(data, 96)
    tags, _ = rpm_header(data, end + (-end) % 8)
    scripts = sorted(set(tags) & RPM_SCRIPTS)
    expect(not scripts, f"the .rpm has install scripts or triggers (tags {scripts})")
    unknown = sorted(set(tags) - RPM_TAGS)
    expect(not unknown, f"unexpected RPM header tags {unknown}")
    v = tree_version(tree)
    expect((tags[1000], tags[1001], tags[1002]) == ("vt-quarantine", v, "1"), "wrong name, version or release")
    check_payload(tar_members(data), linux_files(tree, "usr/share/licenses/vt-quarantine/LICENSE"))


def check_arch(tree, data):
    members = tar_members(data)
    meta = {n: d for n, m, d in members if n.startswith(".")}
    expect(set(meta) == {".PKGINFO", ".BUILDINFO", ".MTREE"},
           f"package metadata is {sorted(meta)}: an .INSTALL script or other extra")
    info = [line.partition(" = ") for line in meta[".PKGINFO"].decode().splitlines() if line and not line.startswith("#")]
    keys = {k for k, _, _ in info}
    allowed = {"pkgname", "pkgbase", "xdata", "pkgver", "pkgdesc", "url", "builddate", "packager", "size", "arch",
               "license", "depend"}
    expect(keys <= allowed, f"unexpected .PKGINFO keys {sorted(keys - allowed)}")
    values = {}
    for k, _, val in info:
        values.setdefault(k, set()).add(val)
    v = tree_version(tree)
    for key, want in (("pkgname", {"vt-quarantine"}), ("pkgver", {f"{v}-1"}), ("arch", {"any"}),
                      ("depend", {"python>=3.9", "python-jeepney"})):
        expect(values.get(key) == want, f".PKGINFO {key} is {values.get(key)}")
    check_payload([x for x in members if not x[0].startswith(".")],
                  linux_files(tree, "usr/share/licenses/vt-quarantine/LICENSE"))


# --- macOS: the app rebuilt from the tag, compared file by file

def rebuilt_zip(tree):
    zips = list((tree / "dist").glob("vt-quarantine-*-macos.zip"))
    if not zips:
        env = dict(os.environ, VTQ_MACOS_CACHE=str(CACHE / "macos"))
        subprocess.run([sys.executable, "-I", str(tree / "macos" / "build.py")], cwd=tree, env=env, check=True,
                       stdout=subprocess.DEVNULL)
        zips = list((tree / "dist").glob("vt-quarantine-*-macos.zip"))
    return zips[0]


def zip_files(path):
    out = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            expect(info.filename not in out, f"{info.filename} is in the zip twice")
            data = z.read(info)  # also refuses a local header that names another file
            if info.filename.endswith(".icns"):
                data = icns_images(data)
            out[info.filename] = (info.external_attr, data)
    return out


def check_zip(tree, data):
    with tempfile.NamedTemporaryFile(suffix=".zip") as f:
        f.write(data)
        f.flush()
        got = zip_files(f.name)
    want = zip_files(rebuilt_zip(tree))
    expect(set(got) == set(want), f"files differ: extra {sorted(set(got) - set(want))[:5]}, "
                                  f"missing {sorted(set(want) - set(got))[:5]}")
    for name in want:
        expect(got[name][0] == want[name][0], f"{name} has other permissions")
        expect(got[name][1] == want[name][1], f"{name} differs from the rebuilt app")


# --- Windows: the MSI's files and tables

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Msi:
    """Tables and streams of an MSI, read through 7z (compound file and cabinet)."""

    def __init__(self, path):
        self.path = path
        listing = subprocess.run(["7z", "l", "-slt", "-tCompound", path], capture_output=True, text=True,
                                 check=True).stdout
        self.streams = {line[7:] for line in listing.splitlines() if line.startswith("Path = ")} - {path}
        pool, data = self.stream("!_StringPool"), self.stream("!_StringData")
        expect(not struct.unpack_from("<I", pool)[0] & 0x80000000, "MSI with long string references")
        self.strings, pos = [""], 0
        for i in range(4, len(pool), 4):
            size, refs = struct.unpack_from("<HH", pool, i)
            expect(size or not refs, "MSI with a long string")
            self.strings.append(data[pos:pos + size].decode("utf-8"))
            pos += size
        columns = {}
        for t, num, name, kind in self.read("_Columns", [0x800, 2, 0x800, 2]):
            columns.setdefault(t, []).append((num, name, kind))
        self.columns = {t: [(n, k) for _, n, k in sorted(c)] for t, c in columns.items()}
        raw = self.stream("!_Tables")
        self.tables = [self.strings[int.from_bytes(raw[i:i + 2], "little")] for i in range(0, len(raw), 2)]

    def stream(self, name):
        return subprocess.run(["7z", "e", "-tCompound", "-so", self.path, name], capture_output=True,
                              check=True).stdout

    def read(self, table, kinds):
        raw = self.stream("!" + table) if "!" + table in self.streams else b""
        widths = [2 if k & 0x800 else k & 0xFF for k in kinds]
        rows = len(raw) // sum(widths) if raw else 0
        expect(rows * sum(widths) == len(raw), f"MSI table {table} has a broken size")
        out, off = [[None] * len(kinds) for _ in range(rows)], 0
        for c, (w, k) in enumerate(zip(widths, kinds)):
            for r in range(rows):
                v = int.from_bytes(raw[off:off + w], "little")
                off += w
                out[r][c] = self.strings[v] if k & 0x800 else (None if v == 0 else v ^ (1 << (8 * w - 1)))
        return out

    def rows(self, table):
        cols = self.columns.get(table)
        if cols is None:
            return []
        names = [n for n, _ in cols]
        return [dict(zip(names, r)) for r in self.read(table, [k for _, k in cols])]

    def cab_files(self):
        out = subprocess.run(["7z", "l", "-slt", self.path], capture_output=True, text=True, check=True).stdout
        return {line[7:] for line in out.splitlines() if line.startswith("Path = ")} - {self.path, "vtq.cab"}

    def cab_file(self, name):
        return subprocess.run(["7z", "e", "-so", self.path, name], capture_output=True, check=True).stdout


# Tables the installer fills; any other table must be empty.
MSI_TABLES = {"AdminExecuteSequence", "AdminUISequence", "AdvtExecuteSequence", "Component", "CustomAction",
              "Directory", "Feature", "FeatureComponents", "File", "Icon", "InstallExecuteSequence",
              "InstallUISequence", "LaunchCondition", "Media", "MsiFileHash", "Property", "Registry", "RemoveFile",
              "Shortcut", "Upgrade", "_Validation"}
WIXL_PROPERTIES = {"UpgradeCode", "Manufacturer", "ProductLanguage", "ProductCode", "ProductName", "ProductVersion",
                   "SecureCustomProperties"}


def msi_expected(tree, work):
    """What the tag's windows/build.py puts in the MSI: (wxs root, {file id: (name, bytes)})."""
    build = load_module(tree / "windows" / "build.py", "vtq_windows_build")
    build.BUILD = CACHE / "windows"
    build.BUILD.mkdir(parents=True, exist_ok=True)
    icon = work / "vt-quarantine.ico"
    build.make_icon(icon)
    python, wheels = build.python_files(), build.wheel_files()
    text = build.wxs(build.version(), icon, tree / "vt-quarantine", python, wheels)
    files = {"Script": ("vt-quarantine.py", (tree / "vt-quarantine").read_bytes()),
             "AppIcon": ("vt-quarantine.ico", icon.read_bytes())}
    for fid, name, path in python + wheels:
        files[fid] = (name, path.read_bytes())
    return ET.fromstring(text), files  # noqa: S314  # nosec B314  # the tag's own build script wrote it


def check_msi(tree, data):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        msi_path = work / "release.msi"
        msi_path.write_bytes(data)
        msi = Msi(str(msi_path))
        root, files = msi_expected(tree, work)
        ns = {"w": "http://schemas.microsoft.com/wix/2006/wi"}
        q = "{http://schemas.microsoft.com/wix/2006/wi}"

        allowed_streams = {"!" + t for t in msi.tables} | {"!_StringPool", "!_StringData", "!_Columns", "!_Tables",
                                                          "vtq.cab", "Icon.vtq.ico", "[5]SummaryInformation"}
        expect(msi.streams <= allowed_streams, f"unexpected MSI streams {sorted(msi.streams - allowed_streams)}")
        for table in msi.tables:
            expect(table in MSI_TABLES or not msi.rows(table), f"MSI table {table} isn't empty")

        # Files: names, components and every byte.
        parent = {}
        for el in root.iter():
            for child in el:
                parent[child] = el
        comp_of = {f.get("Id"): parent[f].get("Id") for f in root.iter(q + "File")}
        got = {r["File"]: r for r in msi.rows("File")}
        expect(set(got) == set(files) == set(comp_of), f"MSI files differ: {sorted(set(got) ^ set(files))}")
        expect(msi.cab_files() == set(files), "the cabinet doesn't hold exactly the listed files")
        for fid, (name, content) in files.items():
            expect(got[fid]["FileName"].split("|")[-1] == name, f"MSI file {fid} is named {got[fid]['FileName']}")
            expect(got[fid]["Component_"] == comp_of[fid], f"MSI file {fid} is in another component")
            stored = msi.cab_file(fid)
            same = ico_images(stored) == ico_images(content) if fid == "AppIcon" else stored == content
            expect(same, f"MSI file {fid} ({name}) differs from the tag and its pins")
        expect(ico_images(msi.stream("Icon.vtq.ico")) == ico_images(files["AppIcon"][1]), "MSI icon differs")
        expect([r["Name"] for r in msi.rows("Icon")] == ["vtq.ico"], "unexpected MSI icons")

        # Custom actions: same names, sources and commands; only "run from a property" kinds.
        want = {(c.get("Id"), c.get("Property"), c.get("ExeCommand") if c.get("ExeCommand") is not None else c.get("Value"))
                for c in root.iter(q + "CustomAction")}
        rows = msi.rows("CustomAction")
        expect({(r["Action"], r["Source"], r["Target"]) for r in rows} == want and len(rows) == len(want),
               "MSI custom actions differ from windows/build.py")
        expect(all(r["Type"] & 0x3F in (50, 51) for r in rows), "an MSI custom action of another kind")
        for seq in ("InstallExecuteSequence", "InstallUISequence"):
            customs = {(c.get("Action"), (c.text or "").strip()) for c in root.iterfind(f"w:Product/w:{seq}/w:Custom", ns)}
            mine = {(r["Action"], r["Condition"]) for r in msi.rows(seq) if r["Action"] in {a for a, _, _ in want}}
            expect(mine == customs, f"{seq} runs custom actions differently from windows/build.py")

        # Registry, shortcuts, folders, removals: exactly what the source says.
        roots = {"HKCU": 1, "HKLM": 2}
        want = sorted((roots[r.get("Root")], r.get("Key"), r.get("Name"),
                       ("#" + r.get("Value")) if r.get("Type") == "integer" else r.get("Value"))
                      for r in root.iter(q + "RegistryValue"))
        got_reg = sorted((r["Root"], r["Key"], r["Name"], r["Value"]) for r in msi.rows("Registry"))
        expect(got_reg == want, "MSI registry values differ from windows/build.py")
        want = sorted((parent[parent[s]].get("Id"), s.get("Name"), s.get("Target"), s.get("Arguments"),
                       s.get("WorkingDirectory")) for s in root.iter(q + "Shortcut"))
        got_sc = sorted((r["Directory_"], r["Name"].split("|")[-1], r["Target"], r["Arguments"], r["WkDir"])
                        for r in msi.rows("Shortcut"))
        expect(got_sc == want, "MSI shortcuts differ from windows/build.py")
        want = sorted((d.get("Id"), "" if parent[d].tag == q + "Product" else parent[d].get("Id"), d.get("Name") or ".")
                      for d in root.iter(q + "Directory"))
        got_dir = sorted((r["Directory"], r["Directory_Parent"], r["DefaultDir"].split("|")[-1])
                         for r in msi.rows("Directory"))
        expect(got_dir == want, "MSI folders differ from windows/build.py")
        want = sorted((f.get("Id"), parent[f].get("Id"), parent[parent[f]].get("Id")) for f in root.iter(q + "RemoveFolder"))
        got_rm = sorted((r["FileKey"], r["Component_"], r["DirProperty"]) for r in msi.rows("RemoveFile"))
        expect(got_rm == want and all(not r["FileName"] for r in msi.rows("RemoveFile")),
               "MSI file removals differ from windows/build.py")

        # Properties and upgrades: only the source's own and the ones wixl always adds.
        product = root.find("w:Product", ns)
        props = {r["Property"]: r["Value"] for r in msi.rows("Property")}
        mine = {p.get("Id"): p.get("Value") for p in product.iterfind("w:Property", ns)}
        expect(set(props) <= set(mine) | WIXL_PROPERTIES, f"unexpected MSI properties {sorted(set(props) - set(mine) - WIXL_PROPERTIES)}")
        expect(all(props.get(k) == v for k, v in mine.items()), "MSI property values differ from windows/build.py")
        expect(props.get("ProductVersion") == product.get("Version") and props.get("UpgradeCode") == product.get("UpgradeCode"),
               "MSI version or upgrade code differs")
        expect(all(r["UpgradeCode"] == product.get("UpgradeCode") for r in msi.rows("Upgrade")), "MSI upgrades another product")
        expect([r["Cabinet"] for r in msi.rows("Media")] == ["#vtq.cab"], "unexpected MSI media")


def check_py(tree, data):
    expect(data == (tree / "vt-quarantine").read_bytes(), "doesn't hold the program at the tag")


KINDS = ((".py", check_py), (".deb", check_deb), (".rpm", check_rpm), (".pkg.tar.zst", check_arch),
         (".zip", check_zip), (".msi", check_msi))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    tree = Path(sys.argv[1]).resolve()
    failed = False
    for asset in sys.argv[2:]:
        check = next((c for suffix, c in KINDS if asset.endswith(suffix)), None)
        try:
            expect(check is not None, "unknown kind of file")
            check(tree, Path(asset).read_bytes())
            print(f"  ok  {asset}")
        except (Mismatch, OSError, ValueError, KeyError, IndexError, struct.error, zlib.error,
                tarfile.TarError, zipfile.BadZipFile, ET.ParseError, subprocess.CalledProcessError) as e:
            failed = True
            print(f"  NO  {asset}: {e}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
