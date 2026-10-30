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

## Building the Windows installers

`python3 windows/build.py` makes `vt-quarantine-<version>-setup.exe` and
`vt-quarantine-<version>.msi` in `dist/`. It runs on Linux and needs `wixl`
(from msitools) and `makensis` (NSIS) on the PATH; on Debian or Ubuntu:
`apt install wixl nsis`. The pinned Python version and its hashes are at the
top of [`windows/setup.nsi`](../windows/setup.nsi).

## Building the Linux packages

`linux/build.sh deb`, `linux/build.sh rpm` or `linux/build.sh arch` builds the
package into `dist/` with each distribution's own tools: `dpkg-deb` on Debian
or Ubuntu, `rpmbuild` on Fedora, `makepkg` on Arch (not as root).

## Releasing

Pushing a version tag makes GitHub Actions build every installer and package,
install and remove the packages on Debian 13, Ubuntu 24.04 and 22.04, Fedora 45
and Arch, and put everything on a **draft** release with a `SHA256SUMS` file.
Nothing is public until the draft is signed and published.

1. **Once:** `tools/make-release-key.sh` makes the release key (it asks for a
   passphrase) and prints its public half, which goes into `RELEASE_KEYS` in
   `vt-quarantine`. Back up the key and passphrase: without them no update can
   reach installed copies.
2. Set `VERSION` in `vt-quarantine`, commit, then
   `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag must match `VERSION`.
3. `tools/sign-release.sh vX.Y.Z` checks every file against `SHA256SUMS`,
   signs it, confirms the release's own program accepts the signature, uploads
   `SHA256SUMS.sig` and offers to publish.
