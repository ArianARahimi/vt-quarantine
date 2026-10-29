# vt-quarantine

Holds browser downloads in a quarantine folder until VirusTotal has checked
them. Clean files move to `~/Downloads` on their own. Anything flagged waits
for you to decide.

A small Python daemon for Linux desktops, run as a systemd user service and
driven through desktop notifications.

## How it works

1. The browser saves every download to `~/Downloads/.quarantine`.
2. The daemon waits for the download to finish (no `.part` file, size stable),
   hashes it, and looks up the SHA-256 on VirusTotal (API v3).
3. Then, depending on the result:

| Result | What happens |
|---|---|
| 0 malicious, 0 suspicious | Moved to `~/Downloads`, with a short "Clean — released" notification |
| Flagged by any engine | Critical notification listing the engines, with **Release** / **Delete** / **Open report** buttons |
| Unknown executable or archive | Uploaded to VirusTotal automatically, then handled as above |
| Unknown other file (documents, media, …) | Asks before uploading, because VirusTotal subscribers can download uploaded files |
| Known but still queued on VT | Waits for the analysis. VT returns all-zero stats for a queued file, and those are never treated as clean |

While a scan is running, a "Scanning on VirusTotal" notification with an
**Open report** button stays up. VirusTotal scans can take several minutes.

If you dismiss a notification, the file stays in quarantine until the service
restarts.

The free public API allows 4 requests a minute and 500 a day. The daemon
spaces out its requests to stay under that limit and waits out any 429
responses.

## Requirements

- Python 3 with `requests`
- `notify-send` from libnotify 0.8 or newer (needs `--action` and `-p`)
- `gdbus` (glib2) and `xdg-open`
- A notification daemon that supports actions (KDE Plasma, GNOME, dunst, …)
- A free [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)

On Arch: `pacman -S python-requests libnotify glib2 xdg-utils`

## Install

```sh
install -Dm755 vt-quarantine ~/.local/bin/vt-quarantine
install -Dm644 systemd/vt-quarantine.service ~/.config/systemd/user/vt-quarantine.service

mkdir -p ~/.config/vt-quarantine
install -m600 /dev/null ~/.config/vt-quarantine/api_key
$EDITOR ~/.config/vt-quarantine/api_key   # paste your API key

systemctl --user daemon-reload
systemctl --user enable --now vt-quarantine.service
```

Then point the browser's download folder at `~/Downloads/.quarantine`. In
Firefox-based browsers, append [`browser/user.js`](browser/user.js) to your
profile's `user.js`, or set the download folder in Settings.

## Logs

```sh
journalctl --user -u vt-quarantine -f
```

If a download never shows up in `~/Downloads`, check the log and
`~/Downloads/.quarantine`.

## Configuration

Settings are constants at the top of `vt-quarantine`: folders, poll interval,
rate limit, upload size limits, analysis timeout, and the list of file types
that are uploaded without asking.

## License

MIT
