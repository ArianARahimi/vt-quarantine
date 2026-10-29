#!/bin/sh
# One-click install for Linux and macOS: checks for Python 3.9 or newer, then
# sets up vt-quarantine.
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1 &&
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    exec python3 ./vt-quarantine --install
fi
echo "vt-quarantine needs Python 3.9 or newer."
if [ "$(uname -s)" = Darwin ]; then
    echo "Install it with:  xcode-select --install   (or from https://www.python.org/downloads/)"
elif command -v apt-get >/dev/null 2>&1; then
    echo "Install it with:  sudo apt-get install python3"
elif command -v dnf >/dev/null 2>&1; then
    echo "Install it with:  sudo dnf install python3"
elif command -v pacman >/dev/null 2>&1; then
    echo "Install it with:  sudo pacman -S python"
elif command -v zypper >/dev/null 2>&1; then
    echo "Install it with:  sudo zypper install python3"
fi
exit 1
