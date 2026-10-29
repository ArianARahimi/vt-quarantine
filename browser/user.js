// Append to <profile>/user.js in Firefox / Waterfox / LibreWolf, replacing
// YOUR_USER with your username. Every download then lands in the quarantine
// folder, where vt-quarantine picks it up.
user_pref("browser.download.folderList", 2);
user_pref("browser.download.dir", "/home/YOUR_USER/Downloads/.quarantine");
user_pref("browser.download.useDownloadDir", true);
