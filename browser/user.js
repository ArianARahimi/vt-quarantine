// Append to <profile>/user.js in Firefox / Waterfox / LibreWolf. Every download
// then lands in the quarantine folder, where vt-quarantine picks it up.
// Set both paths to the quarantine folder that `vt-quarantine --check` prints:
//   Linux:   "/home/YOUR_USER/Downloads/.quarantine"
//   macOS:   "/Users/YOUR_USER/Downloads/.quarantine"
//   Windows: "C:\\Users\\YOUR_USER\\Downloads\\.quarantine"  (backslashes doubled)
user_pref("browser.download.folderList", 2);
user_pref("browser.download.dir", "/home/YOUR_USER/Downloads/.quarantine");
user_pref("browser.download.useDownloadDir", true);
// Save As dialogs start in quarantine too, instead of the last folder used
// on that site. A folder you pick there is used until the browser restarts.
user_pref("browser.download.lastDir", "/home/YOUR_USER/Downloads/.quarantine");
user_pref("browser.download.lastDir.savePerSite", false);
