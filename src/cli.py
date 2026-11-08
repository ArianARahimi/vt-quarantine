#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- Scan command ------------------------------------------------------------------
# `vt-quarantine --scan` checks files anywhere, on demand, and only reports: nothing is
# moved, locked or deleted. Same rule as for downloads: unknown programs are uploaded,
# other unknown files only after a yes.

SCAN_CODES = {"clean": 0, "flagged": 1, "no_verdict": 2}  # also the exit codes
scan_out = sys.stdout  # where progress goes: stderr with --json, so stdout is only JSON


def plain(text):
    """Filenames and engine labels made safe to print: no control characters."""
    return "".join(c if c.isprintable() else "?" for c in str(text))


def scan_note(msg):
    print(plain(msg), file=scan_out, flush=True)


def scan_log(msg):
    scan_note("  " + msg)


def scan_targets(targets):
    """Each file given, and the files directly inside each folder given."""
    files = []
    for target in targets:
        path = Path(target).expanduser()
        if path.is_dir():
            files += sorted(p for p in path.iterdir()
                            if is_candidate(p.name) and p.is_file() and not p.is_symlink())
        else:
            files.append(path)
    return files


def confirm_upload():
    if not sys.stdin or not sys.stdin.isatty():
        return False
    print("  Unknown to VirusTotal. Upload it? Uploaded files can be downloaded "
          "by VT subscribers. [y/N] ", end="", file=sys.stderr, flush=True)
    return input().strip().lower() in ("y", "yes")


def scan_file(path):
    """Check one file: what VirusTotal says, as --json prints it."""
    if not path.exists():
        return {"verdict": "no_verdict", "reason": "not_found"}
    if path.is_symlink() or not path.is_file():
        return {"verdict": "no_verdict", "reason": "not_a_file"}
    sha = sha256(path)
    size = path.stat().st_size
    result = {"sha256": sha, "size": size}
    attrs = lookup(path.name, sha, lambda: None)
    if attrs is None:
        if size > UPLOAD_MAX:
            return {**result, "verdict": "no_verdict", "reason": "too_large"}
        if not should_auto_upload(path) and not confirm_upload():
            return {**result, "verdict": "no_verdict", "reason": "not_uploaded"}
        stats, results, tags = upload(path, sha)
    else:
        stats, results, tags = (attrs["last_analysis_stats"], attrs.get("last_analysis_results"),
                                attrs.get("tags"))
    bad, sus, total = counts(stats)
    result.update(malicious=bad, suspicious=sus, engines=total,
                  flagged_by=dict(flagged_by(results)), report=report_url(sha))
    kind = classify(stats, tags)
    if kind in ("clean", "flagged"):
        return {**result, "verdict": kind}
    return {**result, "verdict": "no_verdict", "reason": kind}


def print_result(r):
    """The text form of a scan_file() result (the file name is already printed)."""
    reason = r.get("reason")
    if r["verdict"] == "clean":
        print(f"  clean: 0/{r['engines']}")
    elif r["verdict"] == "flagged":
        print(f"  FLAGGED: {r['malicious']}/{r['engines']} malicious"
              + (f", {r['suspicious']} suspicious" if r["suspicious"] else ""))
        for eng, label in r["flagged_by"].items():
            print(f"    {plain(eng)}: {plain(label)}")
    else:
        print({
            "not_found": "  not found",
            "not_a_file": "  skipped: not a regular file",
            "too_large": f"  NOT ON VIRUSTOTAL, and too large to upload ({r.get('size', 0) // 1024**2} MB)",
            "not_uploaded": "  NOT ON VIRUSTOTAL (not uploaded)",
            "no_engines": "  NO VERDICT: no engine could scan it",
            "encrypted": f"  NO VERDICT: password-protected, so its contents weren't scanned "
                         f"(0/{r.get('engines')} means nothing here)",
            "error": f"  error: {plain(r.get('error'))}",
        }[reason])
    if "report" in r:
        print(f"  report: {r['report']}")


def scan(targets, as_json=False):
    """--scan: 0 if every file is clean, 1 if any is flagged, else 2 (unknown, no
    verdict or an error)."""
    global api_key, log, scan_out
    scan_out = sys.stderr if as_json else sys.stdout
    log = scan_note  # e.g. packages being fetched: never on stdout with --json
    files = scan_targets(targets)
    if not files:
        print("Nothing to scan.", file=scan_out)
        if as_json:
            print("[]")
        return SCAN_CODES["no_verdict"]
    if not install_requirements():
        return SCAN_CODES["no_verdict"]
    try:
        api_key = read_key()
    except KeyStoreLocked:
        print("The API key is in a locked password store: unlock it and try again.", file=scan_out)
        return SCAN_CODES["no_verdict"]
    if not api_key:
        print("No VirusTotal API key: save one with vt-quarantine --set-key first.", file=scan_out)
        return SCAN_CODES["no_verdict"]
    log = scan_log  # progress (uploading, rate limit) under the file it's about
    results = []
    for i, path in enumerate(files):
        if i:
            print(file=scan_out)
        print(plain(path), file=scan_out, flush=True)
        try:
            r = scan_file(path)
        except Exception as e:
            r = {"verdict": "no_verdict", "reason": "error", "error": str(e)}
        if not as_json:
            print_result(r)
        results.append({"path": str(path), **r})
    if as_json:
        print(json.dumps(results, indent=2))
    codes = {SCAN_CODES[r["verdict"]] for r in results}
    return SCAN_CODES["flagged"] if SCAN_CODES["flagged"] in codes else max(codes)


# --- Main --------------------------------------------------------------------

def run():
    global notifier, api_key
    refuse_root()
    setup_logging()
    lock = acquire_lock()
    if not lock:
        log("already running")
        return 0
    (DATA_DIR / "pid").write_text(str(os.getpid()))
    UPDATING_MARKER.unlink(missing_ok=True)  # it went through, or didn't
    make_quarantine()

    while not install_requirements():
        log("retrying in a minute")
        time.sleep(60)

    while True:
        try:
            notifier = make_notifier()
            break
        except Exception as e:
            # At login the notification service may not be up yet.
            log(f"notifications unavailable ({e}), retrying")
            time.sleep(10)

    warned = False
    while not (api_key := startup_key()):
        if not warned:
            warned = True
            log(f"no API key at {KEY_FILE}")
            wait_for_free_screen("the API key warning")
            if WINDOWS or MACOS:
                # Right after installing: the key window itself, once. After that (or if it's
                # closed without a key) a notification that opens it.
                if not KEY_ASKED.exists():
                    KEY_ASKED.parent.mkdir(parents=True, exist_ok=True)
                    KEY_ASKED.touch()
                    if key_window():
                        continue
                choice = notifier.notify("No VirusTotal API key",
                                         "Downloads stay quarantined until you enter one.",
                                         "critical", "dialog-error", [("key", "Enter key")])
                if choice == "key" and key_window():
                    continue
            else:
                notifier.notify("No VirusTotal API key",
                                f"Run “vt-quarantine --set-key” or put your key in {html.escape(str(KEY_FILE))}.\n"
                                "Downloads stay quarantined until then.",
                                "critical", "dialog-error")
        time.sleep(30)

    q = Quarantine()
    log(f"vt-quarantine {VERSION} watching {QUARANTINE}")
    try:
        updated_to = UPDATED_MARKER.read_text().strip()
        UPDATED_MARKER.unlink()
    except OSError:
        updated_to = None
    if updated_to == VERSION:  # not when the update didn't go through
        threading.Thread(target=tell_updated, daemon=True).start()
    for pattern in ("vt-quarantine-*.msi", "vt-quarantine-*-setup.exe"):  # left by Windows updates
        for old in DATA_DIR.glob(pattern):
            with contextlib.suppress(OSError):
                old.unlink()
    threading.Thread(target=watch_browsers, daemon=True).start()
    if MACOS:
        threading.Thread(target=watch_app, daemon=True).start()
    updater = Updater()
    while True:
        try:
            q.scan()
        except Exception as e:
            log(f"scan error: {e}")
        if updater.due():
            threading.Thread(target=updater.check, daemon=True).start()
        if updater.restart.is_set():
            with q.lock:
                idle = not q.active
            if idle:  # never in the middle of checking a download
                log("restarting into the new version")
                restart(lock)
        time.sleep(POLL_SECONDS)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-V", "--version", action="version", version=f"vt-quarantine {VERSION}")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", "--scan", nargs="+", metavar="PATH",
                       help="check files, or the files in a folder, on VirusTotal and print the "
                            "verdicts (nothing is moved); exit code 0 clean, 1 flagged, 2 no verdict")
    parser.add_argument("--json", action="store_true",
                        help="with --scan: print the results as JSON (progress goes to stderr)")
    group.add_argument("-I", "--install", action="store_true",
                       help="set everything up and start at sign-in (asks for the API key if needed)")
    group.add_argument("-U", "--uninstall", action="store_true",
                       help="stop, undo the browser setup and delete the API key and all settings")
    parser.add_argument("--purge", action="store_true", help=argparse.SUPPRESS)  # what --uninstall does now
    parser.add_argument("--keep-data", action="store_true",
                        help=argparse.SUPPRESS)  # installers stopping the old copy for an upgrade
    group.add_argument("--install-app", action="store_true",
                       help=argparse.SUPPRESS)  # macOS: opening VirusTotal Quarantine.app
    group.add_argument("--uninstall-app", action="store_true",
                       help=argparse.SUPPRESS)  # macOS: opening Uninstall VirusTotal Quarantine
    group.add_argument("-K", "--set-key", action="store_true", help="save your VirusTotal API key")
    group.add_argument("--key-window", action="store_true",
                       help=argparse.SUPPRESS)  # Windows: the "Enter key" notification's window
    group.add_argument("-C", "--check", action="store_true",
                       help="download missing packages, show how much of the API quota is "
                            "used and check that notifications work")
    group.add_argument("-T", "--test-notification", action="store_true",
                       help="show a notification with buttons and print which one you pick")
    group.add_argument("-F", "--forget-safe", action="store_true",
                       help="forget the files you marked safe (they get checked again)")
    group.add_argument("-A", "--auto-update", choices=("on", "quiet", "off"),
                       help="daily update check: on (the default), quiet (no notification "
                            "after updating) or off")
    args = parser.parse_args()
    if args.json and not args.scan:
        parser.error("--json only goes with --scan")
    if args.scan:
        return scan(args.scan, args.json)
    if args.install:
        return install()
    if args.install_app:
        return install_app()
    if args.uninstall_app:
        return uninstall_app()
    if (args.purge or args.keep_data) and not args.uninstall:
        parser.error("--purge and --keep-data only go with --uninstall")
    if args.uninstall:
        return uninstall(keep_data=args.keep_data)
    if args.set_key:
        return set_key()
    if args.key_window:
        return 0 if (key_dialog() if WINDOWS else MACOS and mac_key_dialog()) else 1
    if args.check:
        return check()
    if args.test_notification:
        return test_notification()
    if args.auto_update:
        return set_auto_update(args.auto_update)
    if args.forget_safe:
        SAFE_LIST.unlink(missing_ok=True)
        print("Forgotten: files you marked safe get checked like any other again.")
        return 0
    return run()


if __name__ == "__main__":
    sys.exit(main())
