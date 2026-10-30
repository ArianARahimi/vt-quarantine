#!/bin/sh
# Makes the Ed25519 key that signs releases. Run it once, in a terminal (it asks
# for a passphrase). Installed copies only update to releases signed with a key
# listed in RELEASE_KEYS in vt-quarantine, so keep the key and its passphrase
# backed up somewhere safe: without them, no update can reach installed copies.
set -eu
key=${VTQ_RELEASE_KEY:-$HOME/.config/vt-quarantine-release/release-key.pem}
if [ -e "$key" ]; then
    echo "$key already exists."
    exit 1
fi
mkdir -p "$(dirname "$key")"
chmod 700 "$(dirname "$key")"
umask 077
openssl genpkey -algorithm ed25519 -aes-256-cbc -out "$key"
echo "Now the passphrase once more, to read out the public key:"
openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n' > "$key.pub.hex"
echo
echo "Private key (keep it secret, back it up): $key"
echo "Public key, for RELEASE_KEYS in vt-quarantine: $(cat "$key.pub.hex")"
