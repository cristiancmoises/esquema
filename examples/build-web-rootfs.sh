#!/bin/sh
# build-web-rootfs.sh — assemble a BusyBox web rootfs for Esquema.
#
# Creates a minimal root filesystem containing a full BusyBox userland
# (httpd + ~400 applets), the standard mount points, and a /www to serve.
# BusyBox is dynamically linked against the Guix glibc, so the container
# bind-mounts /gnu/store read-only at run time (see examples/deploy-web.scm).
#
# Usage:  examples/build-web-rootfs.sh [dest]      # default: examples/rootfs-web
#         BUSYBOX=/path/to/busybox examples/build-web-rootfs.sh
set -eu

dest="${1:-examples/rootfs-web}"

# Locate a busybox binary: $BUSYBOX, else the store, else `guix build busybox`.
bb="${BUSYBOX:-}"
if [ -z "$bb" ]; then
    for d in /gnu/store/*busybox*/bin/busybox; do [ -x "$d" ] && bb="$d" && break; done
fi
if [ -z "$bb" ] || [ ! -x "$bb" ]; then
    bb="$(guix build busybox 2>/dev/null | head -1)/bin/busybox"
fi
[ -x "$bb" ] || { echo "error: no busybox found — 'guix install busybox' or set BUSYBOX=" >&2; exit 1; }

mkdir -p "$dest"/bin "$dest"/www "$dest"/gnu/store "$dest"/proc "$dest"/dev "$dest"/tmp "$dest"/etc
cp -f "$bb" "$dest/bin/busybox"
chmod 755 "$dest/bin/busybox"

# A full userland: symlink every applet (httpd, sh, id, ls, …) to busybox.
for a in $("$dest/bin/busybox" --list); do ln -sf busybox "$dest/bin/$a"; done

# Minimal /etc so tools like `id`/`hostname` are happy.
[ -f "$dest/etc/passwd" ] || printf 'root:x:0:0:root:/root:/bin/sh\n' > "$dest/etc/passwd"
[ -f "$dest/etc/hosts" ]  || printf '127.0.0.1 localhost\n'          > "$dest/etc/hosts"

# Default landing page (kept if you already have one).
if [ ! -f "$dest/www/index.html" ]; then
    cat > "$dest/www/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Esquema</title>
<h1>🔥 Served from inside an Esquema container</h1>
<p>rootless · seccomp · every capability dropped</p>
HTML
fi

echo "web rootfs ready: $dest   (busybox: $bb)"
echo "put your site in $dest/www/ , then deploy with examples/deploy-web.scm"
