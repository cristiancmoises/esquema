#!/bin/sh
# build-rootfs.sh — assemble a minimal, self-contained demo rootfs.
#
# Copies a statically-linked bash into <dest>/bin/sh so the container needs
# no /gnu/store bind. Usage: examples/build-rootfs.sh [dest]
set -eu

dest="${1:-examples/rootfs-min}"

# Locate a static bash: prefer $ESQUEMA_TEST_SHELL, else search the store.
shell="${ESQUEMA_TEST_SHELL:-}"
if [ -z "$shell" ]; then
    for d in /gnu/store/*bash-static*/bin/bash; do
        [ -x "$d" ] && shell="$d" && break
    done
fi
if [ -z "$shell" ] || [ ! -x "$shell" ]; then
    echo "error: no static bash found; install with 'guix install bash-static'" >&2
    echo "       or set ESQUEMA_TEST_SHELL=/path/to/static/sh" >&2
    exit 1
fi

mkdir -p "$dest"/bin "$dest"/proc "$dest"/dev "$dest"/tmp "$dest"/etc
cp "$shell" "$dest"/bin/sh
chmod 0755 "$dest"/bin/sh

cat > "$dest"/hello.sh <<'EOF'
echo "Hello from inside an Esquema container!"
echo "  hostname : $(</proc/sys/kernel/hostname)"
echo "  uid/euid : $UID / $EUID  (root-in-namespace, mapped to your host uid)"
echo "  pids seen : $(set -- /proc/[0-9]*; echo $#)"
while read -r k v _; do
  case $k in CapEff:) echo "  caps      : $v (all zero = every capability dropped)";; esac
done < /proc/self/status
while read -r k v _; do
  case $k in Seccomp:) echo "  seccomp   : mode $v (2 = BPF filter active)";; esac
done < /proc/self/status
EOF

echo "Built demo rootfs at: $dest"
echo "Run it with:  guix shell -m manifest.scm -- \\"
echo "  guile -L scheme -c '(use-modules (esquema runtime)(esquema container)) \\"
echo "    (run-container (make-container \"demo\" \"$PWD/$dest\" (list \"/bin/sh\" \"/hello.sh\")))'"
