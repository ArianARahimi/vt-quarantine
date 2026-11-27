#!/bin/sh
# Signs a draft release made by the "Installers and packages" workflow, so that
# installed copies accept it as an update, then offers to publish it.
#   tools/sign-release.sh v2.1.0
# Needs gh (logged in), openssl, python3, bsdtar, 7z, the tag fetched locally and the key
# from make-release-key.sh. Nothing downloaded is ever run: the checks use the source at
# the local tag, and every file must hold only what that source and its pins make.
set -eu
tag=${1:?usage: tools/sign-release.sh vX.Y.Z}
repo=ArianARahimi/vt-quarantine
key=${VTQ_RELEASE_KEY:-$HOME/.config/vt-quarantine-release/release-key.pem}
root=$(cd "$(dirname "$0")/.." && pwd)
for tool in bsdtar 7z; do
    command -v "$tool" >/dev/null || { echo "$tool is needed to look inside the packages."; exit 1; }
done
work=$(mktemp -d)
trusted=$(mktemp -d)
trap 'rm -rf "$work" "$trusted"' EXIT
git -C "$root" show "$tag:vt-quarantine" > "$trusted/vt-quarantine.py" 2>/dev/null ||
    { echo "No $tag here: git fetch --tags first."; exit 1; }
mkdir "$trusted/tree"
git -C "$root" archive "$tag" | tar -x -C "$trusted/tree"

if [ "$(gh release view "$tag" -R "$repo" --json isDraft --jq .isDraft)" != true ]; then
    echo "$tag is not a draft release."
    exit 1
fi
# Only what's on stable is released ("behind" or "identical": the tag is part of it).
case $(gh api "repos/$repo/compare/stable...$tag" --jq .status) in
    behind|identical) ;;
    *) echo "$tag isn't on the stable branch. Releases are made from stable only."; exit 1 ;;
esac
gh release download "$tag" -R "$repo" -D "$work"
cd "$work"
rm -f SHA256SUMS.sig
# A draft signed before carries a date line from then; it gets a new one below.
grep -v '^# signed ' SHA256SUMS > SHA256SUMS.tmp || true
mv SHA256SUMS.tmp SHA256SUMS

# Sign only what was checked: every file matches, and nothing is left unlisted.
sha256sum --strict -c SHA256SUMS
listed=$(awk '{print $2}' SHA256SUMS | sort)
# shellcheck disable=SC2010  # release file names have no spaces or newlines
present=$(ls | grep -vx SHA256SUMS | sort)
if [ "$listed" != "$present" ]; then
    echo "SHA256SUMS doesn't list exactly the files in the release."
    exit 1
fi

# Sign only what was reviewed: every file holds only what the source at the tag and its
# pins make (programs, package files, the Pythons and wheels, the MSI's tables), and Linux
# packages have no install scripts. A new kind of file is refused until it's added there.
echo "Comparing every file with the source at $tag (pinned downloads are cached):"
# shellcheck disable=SC2086  # one argument per release file, as above
if ! python3 -I -B "$root/tools/check_release.py" "$trusted/tree" $present; then
    echo "Not signing."
    exit 1
fi
echo "Every file holds only what $tag makes."

# Signed first, so the passphrase is asked for straight away instead of after minutes of
# VirusTotal checks (a passphrase pasted early lands on the screen). The signature stays
# here until VirusTotal has passed every file; if it doesn't, it's deleted with $work.
# The signed date lets installed copies notice when GitHub keeps serving an old release.
echo "# signed $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> SHA256SUMS
echo "Signing (asks for the key's passphrase, if it has one):"
openssl pkeyutl -sign -rawin -inkey "$key" -in SHA256SUMS -out SHA256SUMS.sig

# The program in this release must accept the signature, or it couldn't update
# to the release after it either. (The local copy: the same bytes, never the download.)
python3 -I -B - "$trusted/vt-quarantine.py" <<'EOF'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("vtq", sys.argv[1])
spec = importlib.util.spec_from_loader("vtq", loader)
vtq = importlib.util.module_from_spec(spec)
loader.exec_module(vtq)
sums, sig = open("SHA256SUMS", "rb").read(), open("SHA256SUMS.sig", "rb").read()
if not any(vtq.ed25519_verify(bytes.fromhex(k), sums, sig) for k in vtq.RELEASE_KEYS):
    sys.exit("The program in this release doesn't accept this key (check RELEASE_KEYS).")
print("Signature checks out with the release's own RELEASE_KEYS.")
EOF

# A program that checks downloads on VirusTotal can't ship anything VirusTotal flags.
# Uses the API key vt-quarantine has saved (or the file in VTQ_VT_KEY_FILE); files
# VirusTotal hasn't seen are uploaded, as anyone downloading them would.
echo "Checking every file on VirusTotal (a few minutes for new files):"
# shellcheck disable=SC2010,SC2046  # one argument per release file, as above
python3 -I -B - "$trusted/vt-quarantine.py" $(ls | grep -vxE 'SHA256SUMS(\.sig)?') <<'EOF'
import hashlib, importlib.machinery, importlib.util, json, os, sys, time, urllib.error, urllib.parse, urllib.request, uuid
loader = importlib.machinery.SourceFileLoader("vtq", sys.argv[1])
spec = importlib.util.spec_from_loader("vtq", loader)
vtq = importlib.util.module_from_spec(spec)
loader.exec_module(vtq)
key_file = os.environ.get("VTQ_VT_KEY_FILE")
key = open(key_file).read().strip() if key_file else vtq.read_key()
if not key:
    sys.exit("No VirusTotal API key: save one with vt-quarantine --set-key, or set VTQ_VT_KEY_FILE.")

def api(path, data=None, headers=()):
    # A path under the API, or a full address VirusTotal handed out (its big-file uploads).
    url = path if path.startswith("https://") else "https://www.virustotal.com/api/v3/" + path
    if urllib.parse.urlsplit(url).hostname not in ("www.virustotal.com", "bigfiles.virustotal.com"):
        sys.exit(f"VirusTotal pointed somewhere unexpected: {url}")
    server_errors = 0
    while True:
        req = urllib.request.Request(url, data, {"x-apikey": key, **dict(headers)})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (500, 502, 503, 504) and server_errors < 4:  # VirusTotal having a moment
                server_errors += 1
                print(f"  (VirusTotal answered {e.code}, trying again in 30 s)", flush=True)
                time.sleep(30)
                continue
            if e.code != 429:  # the free API allows 4 a minute
                raise
        time.sleep(20)

def upload(name, data):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    url = "files"
    if len(data) > 32 * 1024 * 1024:
        url = api("files/upload_url")["data"]   # a full address on bigfiles.virustotal.com
    return api(url, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})["data"]["id"]

bad = []
for name in sys.argv[2:]:
    data = open(name, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    report = api(f"files/{sha}")
    if report is None:
        analysis = upload(name, data)
        while True:
            time.sleep(30)
            status = api(f"analyses/{analysis}")  # None until VirusTotal lists it
            if status and status["data"]["attributes"]["status"] == "completed":
                break
    # The file's own report can lag behind the analysis (or still be queued):
    # wait for one with a date and some engines in it.
    for _ in range(20):
        report = api(f"files/{sha}")
        attrs = report["data"]["attributes"] if report else {}
        stats = attrs.get("last_analysis_stats", {})
        if attrs.get("last_analysis_date") and stats.get("undetected", 0) + stats.get("harmless", 0) + \
                stats.get("malicious", 0) + stats.get("suspicious", 0):
            break
        time.sleep(30)
    flags = {engine: r["result"] for engine, r in attrs.get("last_analysis_results", {}).items()
             if r["category"] in ("malicious", "suspicious")}
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    print(f"  {len(flags)}/{total}  {name}" + (f"  {flags}" if flags else ""))
    if flags or total == 0:
        bad.append(f"{name}: https://www.virustotal.com/gui/file/{sha}")
if bad:
    sys.exit("Nothing uploaded, the signature is discarded. VirusTotal flags:\n  " + "\n  ".join(bad) +
             "\nFix it, or report the false positive to those engines, then run this again.")
EOF

# Only now, with every file clean, does the signature leave this computer.
gh release upload "$tag" SHA256SUMS SHA256SUMS.sig --clobber -R "$repo"
printf 'Publish %s now? Installed copies update to it within a day. [y/N] ' "$tag"
read -r answer
if [ "$answer" = y ]; then
    gh release edit "$tag" -R "$repo" --draft=false --latest
    echo "Published."
else
    echo "Left as a signed draft. Publish it on GitHub when ready."
fi
