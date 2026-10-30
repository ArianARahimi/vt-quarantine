#!/bin/sh
# Builds a Linux package of vt-quarantine with the distribution's own tools, into dist/:
#   linux/build.sh deb     on Debian or Ubuntu (dpkg-deb)
#   linux/build.sh rpm     on Fedora (rpmbuild, from rpm-build)
#   linux/build.sh arch    on Arch (makepkg; not as root)
# Installed from a package, the program uses the distribution's jeepney instead of
# downloading it, and each user turns it on with `vt-quarantine --install`.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
version=$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$root/vt-quarantine")
release=1
summary="Holds browser downloads in quarantine until VirusTotal has checked them"
url=https://github.com/ArianARahimi/vt-quarantine
maintainer="Arian Rahimi <67279657+ArianARahimi@users.noreply.github.com>"
dist=$root/dist
mkdir -p "$dist"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The files every package installs, under $1; the license goes to $2.
stage() {
    install -Dm755 "$root/vt-quarantine" "$1/usr/bin/vt-quarantine"
    # The distribution's Python, not whichever python3 comes first on PATH.
    sed -i '1s|^#!/usr/bin/env python3$|#!/usr/bin/python3|' "$1/usr/bin/vt-quarantine"
    install -Dm644 "$here/vt-quarantine.service" "$1/usr/lib/systemd/user/vt-quarantine.service"
    install -Dm644 "$root/README.md" "$1/usr/share/doc/vt-quarantine/README.md"
    install -Dm644 "$root/browser/user.js" "$1/usr/share/doc/vt-quarantine/user.js"
    install -Dm644 "$root/LICENSE" "$1$2"
}

description="Clean files move to your Downloads folder on their own; anything flagged
waits for you to decide, through desktop notifications. Each user turns it on
with \"vt-quarantine --install\", which also asks for the VirusTotal API key."

case ${1:-} in
deb)
    stage "$work/deb" /usr/share/doc/vt-quarantine/copyright
    mkdir "$work/deb/DEBIAN"
    {
        echo "Package: vt-quarantine"
        echo "Version: $version-$release"
        echo "Architecture: all"
        echo "Maintainer: $maintainer"
        echo "Installed-Size: $(du -sk --exclude=DEBIAN "$work/deb" | cut -f1)"
        echo "Depends: python3 (>= 3.9), python3-jeepney"
        echo "Section: utils"
        echo "Priority: optional"
        echo "Homepage: $url"
        echo "Description: $summary"
        echo "$description" | sed 's/^/ /'
    } > "$work/deb/DEBIAN/control"
    out=$dist/vt-quarantine_$version-${release}_all.deb
    dpkg-deb --root-owner-group -Zxz --build "$work/deb" "$out" >/dev/null
    ;;
rpm)
    stage "$work/rpm-root" /usr/share/licenses/vt-quarantine/LICENSE
    cat > "$work/vt-quarantine.spec" <<EOF
Name: vt-quarantine
Version: $version
Release: $release
Summary: $summary
License: MIT
URL: $url
BuildArch: noarch
Requires: python3 >= 3.9
Requires: python3-jeepney

%description
$description

%install
cp -a "$work/rpm-root/." %{buildroot}/

%files
/usr/bin/vt-quarantine
/usr/lib/systemd/user/vt-quarantine.service
%doc /usr/share/doc/vt-quarantine
%license /usr/share/licenses/vt-quarantine/LICENSE
EOF
    rpmbuild -bb --quiet --define "_topdir $work/rpmbuild" --define "_rpmdir $dist" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        "$work/vt-quarantine.spec"
    out=$dist/vt-quarantine-$version-$release.noarch.rpm
    ;;
arch)
    stage "$work/arch/root" /usr/share/licenses/vt-quarantine/LICENSE
    cat > "$work/arch/PKGBUILD" <<EOF
pkgname=vt-quarantine
pkgver=$version
pkgrel=$release
pkgdesc="$summary"
arch=(any)
url=$url
license=(MIT)
depends=('python>=3.9' python-jeepney)
options=(!debug !strip)
package() {
    cp -dr --no-preserve=ownership "\$startdir/root/." "\$pkgdir/"
}
EOF
    # -d: build without python-jeepney installed here; pacman installs it with the package.
    (cd "$work/arch" && PKGDEST=$dist PACKAGER=$maintainer PKGEXT=.pkg.tar.zst makepkg -d -f >/dev/null)
    out=$dist/vt-quarantine-$version-$release-any.pkg.tar.zst
    ;;
*)
    sed -n '2,7s/^# //p' "$0"
    exit 2
    ;;
esac
echo "Built $out"
