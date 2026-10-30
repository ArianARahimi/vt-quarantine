# Development

Everything here is for building, releasing or running vt-quarantine from
source. For installing it, see the [README](../README.md#install).

## Running from a git checkout (Linux, systemd)

To keep the program in `~/.local/bin` (for example as a symlink into a git
checkout) instead of using `--install`:

```sh
install -Dm755 vt-quarantine ~/.local/bin/vt-quarantine
install -Dm644 systemd/vt-quarantine.service ~/.config/systemd/user/vt-quarantine.service
~/.local/bin/vt-quarantine --set-key
systemctl --user daemon-reload
systemctl --user enable --now vt-quarantine.service
```

A git checkout never updates itself.

## Configuration

Settings are constants at the top of `vt-quarantine`: poll interval, rate
limit, upload size limits, analysis timeout, and the list of file types that
are uploaded without asking.

## Building the Windows installer

`python3 windows/build.py` makes `vt-quarantine-<version>.msi` in `dist/`, with
python.org's embeddable Python inside. It runs on Linux and needs `wixl` (from
msitools) on the PATH; on Debian or Ubuntu: `apt install wixl`. The pinned
Python version and its SHA-256 are at the top of
[`windows/build.py`](../windows/build.py). When Python has a security fix,
update the pin and release: installed copies get the new Python with the
update. There's no setup.exe on purpose: an unsigned installer that downloads
and runs Python is what antivirus heuristics call a downloader trojan, and
2.1.2's was flagged.

## Building the Linux packages

`linux/build.sh deb`, `linux/build.sh rpm` or `linux/build.sh arch` builds the
package into `dist/` with each distribution's own tools: `dpkg-deb` on Debian
or Ubuntu, `rpmbuild` on Fedora, `makepkg` on Arch (not as root).

## Branches

| Branch | What's on it |
|---|---|
| `master` | Development. Every push runs CI (builds every installer and package, installs and removes the packages on five distributions). |
| `stable` | Only commits that passed everything below. Releases are made from it, and it's what **Code → Download ZIP** gives people. |

A commit goes to `stable` only when all of these have passed on it:

1. **Locally:** unit tests, linters (ruff, bandit, vermin), an end-to-end run
   against real VirusTotal, and the Windows installers under Wine (install,
   reinstall, uninstall). The pre-push hook runs all of them for every push to
   `stable` and every version tag, and blocks the push if one fails.
2. **On GitHub:** the CI run for that commit on `master`. A repository rule
   refuses a push to `stable` until it has passed, and refuses force-pushes and
   deleting the branch.
3. **By hand:** anything new that tests can't reach (a new kind of
   notification, a new installer step) has been tried on a real desktop.

Then: `git push origin master:stable` (a fast-forward; nothing is committed to
`stable` directly).

## Releasing

Pushing a version tag on `stable` makes GitHub Actions build and test everything
again and put it all on a **draft** release with a `SHA256SUMS` file. Nothing is
public until the draft is signed and published. A tag that isn't on `stable` is
refused by the pre-push hook, by the release job and by the signing script.

1. **Once:** `tools/make-release-key.sh` makes the release key (it asks for a
   passphrase) and prints its public half, which goes into `RELEASE_KEYS` in
   `vt-quarantine`. Back up the key and passphrase: without them no update can
   reach installed copies.
2. On `master`: set `VERSION` in `vt-quarantine`, commit and push. Once CI has
   passed, `git push origin master:stable`.
3. `git tag vX.Y.Z stable && git push origin vX.Y.Z`. The tag must match
   `VERSION`.
4. `tools/sign-release.sh vX.Y.Z` checks every file against `SHA256SUMS` and
   on VirusTotal (uploading the ones it hasn't seen; any engine flagging any
   file stops the release), signs it, confirms the release's own program accepts the signature, uploads
   `SHA256SUMS.sig` and offers to publish.
