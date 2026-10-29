// Append to <profile>/user.js in Firefox / Waterfox / LibreWolf. Every download
// then lands in the quarantine folder, where vt-quarantine picks it up.
// Set the path to the quarantine folder that `vt-quarantine --check` prints:
//   Linux:   "/home/YOUR_USER/Downloads/.quarantine"
//   macOS:   "/Users/YOUR_USER/Downloads/.quarantine"
//   Windows: "C:\\Users\\YOUR_USER\\Downloads\\.quarantine"  (backslashes doubled)
user_pref("browser.download.folderList", 2);
user_pref("browser.download.dir", "/home/YOUR_USER/Downloads/.quarantine");
user_pref("browser.download.useDownloadDir", true);
