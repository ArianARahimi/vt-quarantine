#: Part of vt-quarantine. tools/bundle.py joins the parts in src/ into the one
#: vt-quarantine script, so names from the parts before this one are in scope.

# --- VirusTotal ------------------------------------------------------------------

class RateLimiter:
    """At most `per_minute` requests in any minute (with a second to spare): a few
    downloads at once are all checked straight away, only a longer run waits."""

    def __init__(self, per_minute, window=61):
        self.per_minute = per_minute
        self.window = window
        self.lock = threading.Lock()
        self.sent = collections.deque()

    def wait(self):
        # Holding the lock while sleeping is deliberate: it serialises callers.
        with self.lock:
            while True:
                now = time.monotonic()
                while self.sent and self.sent[0] <= now - self.window:
                    self.sent.popleft()
                if len(self.sent) < self.per_minute:
                    break
                time.sleep(self.sent[0] + self.window - now)
            self.sent.append(now)


limiter = RateLimiter(REQUESTS_PER_MINUTE)


def vt(method, url, upload=None):
    """Rate-limited VirusTotal request; retries when the minute quota is hit."""
    global api_key
    if key_changed():  # a new key works without a restart
        with contextlib.suppress(KeyStoreLocked):
            api_key = read_key() or api_key
    if not url.startswith("http"):
        url = API + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != VT_HOST:
        raise RuntimeError(f"refusing to send the API key to {parts.scheme}://{parts.hostname}")
    for _ in range(6):
        limiter.wait()
        if upload:
            with open_nofollow(upload) as f:
                r = http_request(method, url, (f, upload_name(upload)))
        else:
            r = http_request(method, url)
        if r.status_code != 429:
            return r
        log("rate limited, waiting a minute")
        time.sleep(60)
    raise RuntimeError("VirusTotal quota exceeded (daily limit is 500 requests)")


def report_url(sha):
    return f"https://{VT_HOST}/gui/file/{sha}"


class Progress:
    """Non-blocking notification that stays up while a scan runs, with an
    "Show report" button; close() removes it once there is a verdict."""

    def __init__(self, summary, body, sha):
        url = report_url(sha)
        self.handle = notifier.show(summary, body, "cloud-upload", [("report", "Show report")],
                                    lambda key: key == "report" and open_url(url))

    def close(self):
        if self.handle is not None:
            notifier.close(self.handle)
