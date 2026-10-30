<h1 align="center">vt-quarantine</h1>

<p align="center">
  <b>Every download gets checked on VirusTotal before it reaches your Downloads folder.</b><br>
  Clean files move on by themselves. Anything flagged waits for you.
</p>

<p align="center">
  <a href="https://github.com/ArianARahimi/vt-quarantine/releases/latest">Download</a> ·
  <a href="#install">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#privacy-and-security">Privacy</a> ·
  <a href="#known-issues">Known issues</a>
</p>

<p align="center">
  <img src="docs/notifications.png" width="332"
       alt="Notifications: a flagged setup.exe (66/68 engines) and an encrypted archive, both with Show report / Delete buttons, and a clean file moved to Downloads automatically, with an Open folder button">
</p>

- **Free and open source** (MIT), for **Windows 10/11, Linux and macOS**
- **Lightweight:** one small background program, no window, no tray icon.
  Everything happens in notifications.
- **Easy to set up:** an installer that brings what it needs, and your default
  browser is set up for you if it's Firefox-based
- **Careful by default:** files are locked until they're checked, private files
  are never uploaded without asking, and a flagged file can't leave quarantine
  until you've seen its report

## Install

You need a free **VirusTotal API key**:
[sign up](https://www.virustotal.com/gui/join-us), then copy the key from
[your API key page](https://www.virustotal.com/gui/my-apikey). vt-quarantine
asks for it when it first starts.

### Windows

Download **`vt-quarantine-<version>.msi`** from
[Releases](https://github.com/ArianARahimi/vt-quarantine/releases/latest) and
run it. It installs for your account only, without administrator rights, and
starts right away: a notification asks for your API key (**Enter key**).

Windows may warn that the publisher is unknown: click **More info → Run
anyway**.

<details>
<summary>What the <code>.msi</code> installs</summary>

The program and its own copy of Python: python.org's official "embeddable"
Python (about 12 MB), checked against a pinned SHA-256 when the installer is
built. It's private to vt-quarantine: nothing is added to PATH or the registry
for it, it doesn't touch any Python you installed yourself, and it's removed
along with vt-quarantine. Installing downloads and runs nothing.

Every release file is checked on VirusTotal before it's published, and a
release that any engine flags isn't published.

Deployment tools can install it silently: `msiexec /i vt-quarantine-<version>.msi /qn`.
</details>

### Linux

Download the package for your distribution from
[Releases](https://github.com/ArianARahimi/vt-quarantine/releases/latest) and
install it:

| Distribution | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install ./vt-quarantine_<version>-1_all.deb` |
| Fedora | `sudo dnf install ./vt-quarantine-<version>-1.noarch.rpm` |
| Arch | `sudo pacman -U vt-quarantine-<version>-1-any.pkg.tar.zst` |

Then run **`vt-quarantine --install`** as yourself (not with `sudo`). It asks
for your API key and starts the program whenever you sign in.

On any other distribution, download this repository (**Code → Download ZIP**),
extract it, and run `sh install.sh`.

### macOS

Download this repository (**Code → Download ZIP**), extract it, and
double-click **`install.command`**. The first time, right-click it and choose
**Open**.

### Browser setup

Your browser needs to save downloads into the quarantine folder. The first time
vt-quarantine runs, it takes care of your **default browser**:

- **Firefox, Waterfox, LibreWolf or Floorp** is set up for you, in every
  profile. Restart it for this to take effect.
- **Any other browser** can't be changed safely from outside, so one
  notification shows the folder with a **Copy folder** button. Paste it into the
  browser's download setting (see below).

Other browsers you use need the same setting by hand. Uninstalling puts the
Firefox settings back as they were.

<details>
<summary>Setting the folder by hand</summary>


| System | Quarantine folder |
|---|---|
| Windows | `%USERPROFILE%\Downloads\.quarantine` (inside your Downloads folder, wherever it lives) |
| macOS | `~/Downloads/.quarantine` |
| Linux | `~/Downloads/.quarantine` (follows `XDG_DOWNLOAD_DIR`) |

- **Chrome, Edge, Brave, Vivaldi, Opera:** Settings → Downloads → Location →
  Change. Turn off "Ask where to save each file".
- **Firefox, Waterfox, LibreWolf:** Settings → General → Downloads → Save files
  to → Browse. Or add [`browser/user.js`](browser/user.js) to your profile's
  `user.js`, which also makes Save As dialogs start in the quarantine folder.
- **Safari:** Settings → General → File download location → Other.

Folders starting with a dot are hidden in the folder picker. Press
<kbd>⌘</kbd><kbd>⇧</kbd><kbd>.</kbd> on macOS or <kbd>Ctrl</kbd><kbd>H</kbd>
on Linux to show them.
</details>

To check that notifications work, run `vt-quarantine --test-notification`.

## How it works

Your browser saves each download into the quarantine folder. Once the download
has finished, vt-quarantine **locks** it, so nothing can open it by accident (a
click in the browser's download list, a double-click, a thumbnail), and looks
up its SHA-256 hash on VirusTotal:

| Result | What happens |
|---|---|
| ✅ Clean (0 detections) | Moved to Downloads, with a short note and an **Open folder** button |
| ⚠️ Flagged by any engine | Held. The notification lists the engines (see [Flagged files](#flagged-files)) |
| 🔒 Password-protected archive | Held, because engines can't see inside, so "0 detections" means nothing |
| ❔ Unknown program, script or installer | Uploaded to VirusTotal for a scan, then handled as above |
| ❔ Unknown document, archive, disk image, … | Asks first: **Upload**, **Delete** or **Mark as safe** (see [Privacy](#privacy-and-security)) |

While VirusTotal scans a file, which can take a few minutes, a "Scanning on
VirusTotal" notification stays up. A file that changes after it was checked is
checked again, and a file whose check fails (no connection, API limit used up)
is never moved to Downloads.

### Flagged files

A flagged file can't leave quarantine until you've looked at its report:

1. At first there are only **Show report** and **Delete**.
2. After **Show report**, a third button appears: **Mark as safe**. The other
   two stay where they were, so a quick click never lands on the wrong one.
3. If 10 or more engines call it malicious, **Mark as safe** asks once more:
   **Back**, **Delete** or **Move anyway**, again in the same places.

A flagged file you let through isn't remembered. If you download it again, you
get the warning again.

### Mark as safe

For files VirusTotal has no verdict on (unknown files you chose not to upload,
files no engine could scan, password-protected archives), **Mark as safe** is
remembered by the file's SHA-256 hash, so that exact file skips the question
next time. It's still looked up on VirusTotal each time, and if it has been
flagged since, you get the warning. `vt-quarantine --forget-safe` clears the
list.

If you close a notification without choosing, the file stays locked in
quarantine until the program restarts (at your next sign-in) and asks again. To
take a file out, use the notification: one moved out by hand stays locked.

### Games and other fullscreen apps

While a game, a video or a presentation fills the screen, vt-quarantine keeps
everything that isn't about a download to itself: update offers, update notes
and the first-run browser setup wait, and appear the moment the fullscreen app
is gone. Updates aren't installed in the middle of a game either.

Notifications about downloads still show straight away: if you're downloading
something, you're not absorbed in a game.

## Updates

Once a day, vt-quarantine asks GitHub for the newest release. It only installs
one whose file list carries a valid signature from the release key, and only
files that match that list. The key never leaves the maintainer's computer, so
even someone who took over the GitHub account couldn't push code to you.

| Installed with | How it updates |
|---|---|
| Windows `.msi` | Silently: downloads the new `.msi` and installs it |
| `install.sh`, `install.command` or `--install` | Silently: replaces itself and restarts, never in the middle of a check |
| Linux package | Asks first, because installing needs your password |

After an update, a short note says so. When a Linux package update is offered,
**What's new** opens the release notes, and closing the question means "not
this version": you're asked again only when the next one comes out.
`vt-quarantine --auto-update off` stops update checks completely.

## Privacy and security

- **Only a hash is sent for known files.** VirusTotal never sees their contents
  or names, though it does see which API key asked.
- **Uploads aren't private.** Paying VirusTotal subscribers can download
  uploaded files, so only programs, scripts and installers upload
  automatically. Documents, media and archives ask first. Uploads are named
  `sample.<ext>`, not by their real name, and are tied to your API key.
- **No telemetry.** The program talks to VirusTotal, to PyPI once on first run,
  and to GitHub once a day for updates (only your IP address and the program's
  version reach GitHub). Nothing else.
- **Your API key is kept in your system's password store:** encrypted for your
  Windows account, in the macOS Keychain, or in KWallet / GNOME Keyring on
  Linux. A copied disk, a backup or another account can't read it. Where
  there's no password store, it's in a file only you can read. It's asked for
  once, and only ever sent to VirusTotal, over HTTPS with redirects refused.
- **Dependencies are pinned.** Besides Python, it needs
  [jeepney](https://pypi.org/project/jeepney/) on Linux and the
  [winrt](https://pypi.org/project/winrt-runtime/) packages on Windows. They
  come from your Linux distribution's package, or are downloaded from PyPI and
  checked against SHA-256 hashes built into the program. No pip, nothing
  installed system-wide.
- **Quarantine is private.** On Linux and macOS only you can open the folder
  (on Windows your Downloads folder already is), and each file in it is locked
  until it's cleared.
- **Hardened against tricks:** filenames are treated as plain text everywhere,
  links planted in the quarantine folder are ignored, only one copy runs at a
  time, and it refuses to run as root. On Windows, moved files keep their
  "downloaded from the internet" mark, so SmartScreen and Office stay cautious.

## Limitations

- **A clean result isn't a guarantee.** New or targeted malware often has no
  detections yet. VirusTotal is one layer of protection, not a sandbox.
- **Only the quarantine folder is covered.** Other browsers, profiles and tools,
  and Save As dialogs pointed at another folder, skip it.
- **"Always open similar files" opens a download before it's checked.** A
  browser that opens files of a type automatically does so the moment the
  download finishes, before vt-quarantine can lock it. Turn that off in the
  browser's download settings.
- **Programs already running as you are out of scope.** They can write to the
  quarantine folder or change vt-quarantine itself.
- **The free API allows 4 lookups a minute and 500 a day.** vt-quarantine paces
  itself; if the quota runs out, files wait in quarantine.
- **macOS support is the newest** and has had the least real-world use. Its
  browser setup, file locking and Keychain storage haven't run on a Mac yet.
- **Waiting for fullscreen apps works on Windows, KDE Plasma and X11 desktops.**
  GNOME on Wayland and macOS give programs no way to tell, so there nothing
  waits.

## Known issues

<details>
<summary><b>Windows</b>: only tested under Wine, not yet on a real PC</summary>

Anything Wine can't do, or that only behaves like Windows on a real machine, is
unverified:

- **Notifications have never been shown on real Windows.** Wine can't display
  toast notifications, so the buttons (Show report / Delete / Mark as safe,
  Enter key), notifications that stay on screen until answered, and what
  happens when one is dismissed or goes to the notification centre are all
  untested. This is the part most likely to need fixes.
- **Automatic updates have only run under Wine.** Downloading the new `.msi`
  and installing it silently passed there, with the program's own code.
- **Keeping the API key encrypted (DPAPI) has only run under Wine.**
- **Waiting for fullscreen games hasn't run on real Windows.** It asks Windows
  the same question Windows asks before showing its own notifications
  (`SHQueryUserNotificationState`), which Wine doesn't answer the way Windows
  does.
- **Locking files and the browser setup haven't run on real Windows.** Locking
  uses `icacls` to deny reading, and Copy folder uses PowerShell; under Wine
  both are only partly there. Both are covered by unit tests only.
- **The installer is unsigned.** SmartScreen shows "Windows protected your
  PC" (More info → Run anyway) until it's code-signed.
- **64-bit Windows only.** The `.msi` carries 64-bit Python and refuses to
  install on 32-bit Windows. Windows on ARM should run it through emulation,
  but that's untested.
- **Starting right after installing is untested on real Windows.** The `.msi`
  starts it from the install and again from the installer window, and an
  automatic update starts it once more after installing; under Wine only the
  silent paths could be tested. If it doesn't start, it will at the next
  sign-in.
- **Upgrading by running a newer `.msi` by hand relies on Windows saying it's
  an upgrade.** Wine doesn't, so there the old version's uninstall step deleted
  the API key. Automatic updates leave the program a note and keep everything
  either way. Upgrading a 2.1.2-or-older setup.exe install by hand lost the key
  under Wine too (a notification then asks for it again).
- **The "Enter key" window is untested.** If no API key is set, a notification
  button opens a window to type it in, which depends on notifications working.
- **Windows Installer's window without dialogs is untested.** The `.msi` has no
  pages of its own; Windows should show only a progress bar.
- **Version 2.1.2 and older don't update to 2.2.0 by themselves on Windows.**
  They look for a `setup.exe`, which releases no longer have. Install the `.msi`
  over them once.
- **Under Wine only:** Apps-list entries are stored in a different registry
  location. Not expected on real Windows.
</details>

<details>
<summary><b>Linux packages</b>: only the Arch package has run on a real desktop</summary>

- **The .deb and .rpm haven't run on a desktop with notifications yet.** GitHub
  Actions installs and removes each package on Debian 13, Ubuntu 24.04 and
  22.04, Fedora 45 and Arch, and checks that it finds the distribution's
  jeepney. The Arch package has run on KDE Plasma, including an update through
  the notification.
- **Other RPM-based distributions are untested.** On openSUSE the dependency
  names may differ. RHEL, Alma and Rocky Linux need EPEL for `python3-jeepney`.
- **An update from your package manager takes effect at your next sign-in.**
  `systemctl --user restart vt-quarantine` switches straight away. Updates
  through the notification restart it themselves.
- **Setup for a Chrome-family default browser has only been tested in unit
  tests.** The default browser is found through `xdg-settings`.
- **Remove the package only after `vt-quarantine --uninstall`.** Otherwise it
  keeps running until you sign out, and systemd warns about a leftover link.
</details>

## Reference

<details>
<summary><b>Commands</b></summary>

```
vt-quarantine                     run (what autostart does)
vt-quarantine --install           set up, ask for the API key, start at sign-in
vt-quarantine --uninstall         stop, undo the browser setup, forget everything
vt-quarantine --set-key           save or replace the API key
vt-quarantine --check             fetch missing packages and check notifications
vt-quarantine --test-notification show a test notification with buttons
vt-quarantine --auto-update off   stop checking for updates (on: start again)
vt-quarantine --forget-safe       forget the files you marked safe
vt-quarantine --version
```

On Windows, run these with the program's own Python in a Command Prompt, for
example to change the API key or to troubleshoot:

```
"%LOCALAPPDATA%\vt-quarantine\python\python.exe" "%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py" --set-key
"%LOCALAPPDATA%\vt-quarantine\python\python.exe" "%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py" --check
```
</details>

<details>
<summary><b>Where things live</b></summary>

| | Windows | macOS | Linux |
|---|---|---|---|
| Program | `%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py` (its Python in `python\`) | `~/Library/Application Support/vt-quarantine/` | `/usr/bin/vt-quarantine` (package) or `~/.local/share/vt-quarantine/` |
| API key | `%APPDATA%\vt-quarantine\api_key.dpapi` (encrypted for your account) | Keychain, item "vt-quarantine" | KWallet / GNOME Keyring, or `~/.config/vt-quarantine/api_key` without one |
| Files marked safe | `%APPDATA%\vt-quarantine\marked-safe` | `~/Library/Application Support/vt-quarantine/marked-safe` | `~/.config/vt-quarantine/marked-safe` |
| Log | `%LOCALAPPDATA%\vt-quarantine\vt-quarantine.log` | `~/Library/Application Support/vt-quarantine/vt-quarantine.log` | `journalctl --user -u vt-quarantine -f` |
| Autostart | `HKCU\…\CurrentVersion\Run` | `~/Library/LaunchAgents/vt-quarantine.plist` | `~/.config/systemd/user/vt-quarantine.service` |

If a download never shows up in Downloads, check the log and the quarantine
folder.
</details>

<details>
<summary><b>Notifications on each platform</b></summary>

- **Windows:** toast notifications. Ones that need a decision stay on screen
  until you press a button.
- **Linux:** standard desktop notifications (KDE Plasma, GNOME, dunst, …). The
  notification service must support buttons.
- **macOS:** a dialog when a decision is needed, a Notification Center banner
  otherwise. A dialog with no answer within a day counts as closed.
</details>

## Uninstall

- **Windows:** Settings → Apps → **VirusTotal Quarantine** → Uninstall. This
  removes everything, its own Python too. If you installed version 2.1.2 or
  older, the Python its setup installed stays (listed separately in Apps;
  remove it there if nothing else uses it).
- **macOS and Linux:** run `vt-quarantine --uninstall`. Then remove a Linux
  package with `sudo apt remove vt-quarantine`, `sudo dnf remove vt-quarantine`
  or `sudo pacman -R vt-quarantine`.

Uninstalling forgets everything: your API key, files marked safe, settings and
log are deleted, and the Firefox setup is undone. If a Firefox-based browser is
open at the time, a few lines in its `user.js` put the settings back once it
restarts; they say they're safe to delete afterwards. Files still in quarantine
are unlocked and left in place, never deleted. Browsers you set up by hand need
their download folder set back by hand.

## Contributing

Building the installers and packages, and how releases are made and signed:
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License

[MIT](LICENSE)
