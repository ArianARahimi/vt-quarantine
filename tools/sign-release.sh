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
