# vt-quarantine guide

The details behind the [README](../README.md): how browsers are set up, what happens to each download, updates, privacy, and every command and file.

## Browser setup

Your browsers need to save downloads into the quarantine folder. vt-quarantine
sets up **every browser it finds**, in every profile, by itself:

- **Chrome, Edge, Brave, Opera, Opera GX, Chromium and Vivaldi** while they're
  closed. One that's open is set up the moment you close it, so restart it once.
  "Ask where to save each file" is turned off, since a save box lets a download
  land anywhere. Edge never quite closes on Windows (Startup boost keeps it
  running without a window), so vt-quarantine ends that window-less process to
  change the setting; it starts again with Edge.
- **Firefox, Waterfox, LibreWolf and Floorp** take the setting at their next
  start.
- **Safari** (macOS) while it's closed, like Chrome. "Open “safe” files after
  downloading" is turned off too.
- A browser you install or start for the first time later is set up quietly.
- **Files opening by themselves once downloaded** ("Always open files of this
  type", "Always open similar files") is turned off, since they'd open before
  they're checked, and turned off again if it's switched on later.

Each profile is set up once: if you change its download folder afterwards, that
stays. One notification says what was set up. Only a **default browser that
can't be set up from outside** (one it doesn't know) gets a
notification with the folder and a **Copy folder** button instead; paste it into
the browser's download setting (see below). Uninstalling puts every browser's
settings back as they were.

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

A clean verdict more than 30 days old is checked again first: VirusTotal doesn't
rescan files by itself, and engines may have learned about the file since. If
that rescan fails or takes over 5 minutes, the old verdict counts.

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
`vt-quarantine --auto-update quiet` keeps updating without the notification
afterwards (a Linux package still asks first, since installing it needs your
password); `vt-quarantine --auto-update off` stops update checks completely.

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
  come from your Linux distribution's package, inside the Windows `.msi`, or
  are downloaded from PyPI, and are checked against SHA-256 hashes built into
  the program either way. No pip, nothing installed system-wide.
- **Quarantine is private.** On Linux and macOS only you can open the folder
  (on Windows your Downloads folder already is), and each file in it is locked
  until it's cleared.
- **Hardened against tricks:** filenames are treated as plain text everywhere,
  links planted in the quarantine folder are ignored, only one copy runs at a
  time, and it refuses to run as root. On Windows, moved files keep their
  "downloaded from the internet" mark, so SmartScreen and Office stay cautious.

## Reference

<details>
<summary><b>Commands</b></summary>

```
vt-quarantine                          run (what autostart does)
vt-quarantine -S, --scan PATH...       check files, or the files in a folder, and print
                                       the verdicts and which engines flag them
vt-quarantine -I, --install            set up, ask for the API key, start at sign-in
vt-quarantine -U, --uninstall          stop, undo the browser setup, forget everything
vt-quarantine -K, --set-key            save or replace the API key
    --json                             with --scan: print the results as JSON
vt-quarantine -C, --check              fetch missing packages, show how much of the
                                       API quota is used, and check notifications
vt-quarantine -T, --test-notification  show a test notification with buttons
vt-quarantine -A, --auto-update off    stop checking for updates (on: start again;
                                       quiet: update without a notification)
vt-quarantine -F, --forget-safe        forget the files you marked safe
vt-quarantine -V, --version
```

`--scan` only reports: nothing is moved, locked or deleted. Unknown programs are
uploaded to VirusTotal; other unknown files only after you answer yes (uploads can
be downloaded by VT subscribers). It exits with 0 if every file is clean, 1 if any
is flagged, and 2 otherwise (unknown, no verdict or an error), so scripts can use
it. Subfolders aren't scanned. It shares the free API's 4 lookups a minute with the
running program. With `--json`, stdout is a JSON list with one entry per file
(`path`, `verdict`: `clean`, `flagged` or `no_verdict`, and when there is one,
`reason`, `sha256`, `malicious`, `engines`, `flagged_by` and `report`); progress
goes to stderr.

On Windows, run these with the program's own Python in a Command Prompt, for
example to change the API key or to troubleshoot:

```
"%LOCALAPPDATA%\vt-quarantine\python\python.exe" "%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py" --set-key
"%LOCALAPPDATA%\vt-quarantine\python\python.exe" "%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py" --check
"%LOCALAPPDATA%\vt-quarantine\python\python.exe" "%LOCALAPPDATA%\vt-quarantine\vt-quarantine.py" --scan "%USERPROFILE%\Desktop\file.exe"
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

## Uninstall details

- **Windows:** installed with version 2.1.2 or older, the Python its setup
  installed stays (listed separately in Apps; remove it there if nothing else uses it).
- **Firefox-based browsers open while uninstalling:** a few lines in their
  `user.js` put the settings back once they restart; they say they're safe to
  delete afterwards.
- **Browsers you set up by hand** need their download folder set back by hand.
- **macOS:** dragging the app to the Trash removes vt-quarantine a few minutes
  later (it checks once a minute, and twice before acting, in case the app was
  only moved). Uninstall VirusTotal Quarantine does it at once.

## Contributing

Building the installers and packages, and how releases are made and signed:
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
