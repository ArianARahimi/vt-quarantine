#!/bin/sh
# Signs a draft release made by the "Installers and packages" workflow, so that
# installed copies accept it as an update, then offers to publish it.
#   tools/sign-release.sh v2.1.0
# Needs gh (logged in), openssl, python3 and the key from make-release-key.sh.
set -eu
tag=${1:?usage: tools/sign-release.sh vX.Y.Z}
repo=ArianARahimi/vt-quarantine
key=${VTQ_RELEASE_KEY:-$HOME/.config/vt-quarantine-release/release-key.pem}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

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

# Sign only what was checked: every file matches, and nothing is left unlisted.
sha256sum --strict -c SHA256SUMS
listed=$(awk '{print $2}' SHA256SUMS | sort)
present=$(ls | grep -vx SHA256SUMS | sort)
if [ "$listed" != "$present" ]; then
    echo "SHA256SUMS doesn't list exactly the files in the release."
    exit 1
fi

# A program that checks downloads on VirusTotal can't ship anything VirusTotal flags.
# Uses the API key vt-quarantine has saved (or the file in VTQ_VT_KEY_FILE); files
# VirusTotal hasn't seen are uploaded, as anyone downloading them would.
echo "Checking every file on VirusTotal (a few minutes for new files):"
python3 -I - "vt-quarantine-${tag#v}.py" $(ls | grep -vx SHA256SUMS) <<'EOF'
import hashlib, importlib.machinery, importlib.util, json, os, sys, time, urllib.error, urllib.request, uuid
loader = importlib.machinery.SourceFileLoader("vtq", sys.argv[1])
spec = importlib.util.spec_from_loader("vtq", loader)
vtq = importlib.util.module_from_spec(spec)
loader.exec_module(vtq)
key_file = os.environ.get("VTQ_VT_KEY_FILE")
key = open(key_file).read().strip() if key_file else vtq.read_key()
if not key:
    sys.exit("No VirusTotal API key: save one with vt-quarantine --set-key, or set VTQ_VT_KEY_FILE.")

def api(path, data=None, headers=()):
    while True:
        req = urllib.request.Request("https://www.virustotal.com/api/v3/" + path, data,
                                     {"x-apikey": key, **dict(headers)})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code != 429:  # the free API allows 4 a minute
                raise
        time.sleep(20)

def upload(name, data):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    url = "files"
    if len(data) > 32 * 1024 * 1024:
        url = api("files/upload_url")["data"].split("/api/v3/", 1)[1]
    return api(url, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})["data"]["id"]

bad = []
for name in sys.argv[2:]:
    data = open(name, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    report = api(f"files/{sha}")
    if report is None:
        analysis = upload(name, data)
        while api(f"analyses/{analysis}")["data"]["attributes"]["status"] != "completed":
            time.sleep(30)
        report = api(f"files/{sha}")
    attrs = report["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    flags = {engine: r["result"] for engine, r in attrs["last_analysis_results"].items()
             if r["category"] in ("malicious", "suspicious")}
    total = stats["malicious"] + stats["suspicious"] + stats["harmless"] + stats["undetected"]
    print(f"  {len(flags)}/{total}  {name}" + (f"  {flags}" if flags else ""))
    if flags or total == 0:
        bad.append(f"{name}: https://www.virustotal.com/gui/file/{sha}")
if bad:
    sys.exit("Not signed. VirusTotal flags:\n  " + "\n  ".join(bad) +
             "\nFix it, or report the false positive to those engines, then run this again.")
EOF

echo "Signing (asks for the key's passphrase, if it has one):"
openssl pkeyutl -sign -rawin -inkey "$key" -in SHA256SUMS -out SHA256SUMS.sig

# The program in this release must accept the signature, or it couldn't update
# to the release after it either.
python3 -I - "vt-quarantine-${tag#v}.py" <<'EOF'
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

gh release upload "$tag" SHA256SUMS.sig -R "$repo"
printf 'Publish %s now? Installed copies update to it within a day. [y/N] ' "$tag"
read -r answer
if [ "$answer" = y ]; then
    gh release edit "$tag" -R "$repo" --draft=false --latest
    echo "Published."
else
    echo "Left as a signed draft. Publish it on GitHub when ready."
fi
