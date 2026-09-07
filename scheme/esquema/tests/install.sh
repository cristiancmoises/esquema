#!/bin/sh
# Exercise the installed interface without repository or loader-path fallbacks.
set -eu

srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/esquema-install.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
make_cmd=${MAKE:-make}
guile_cmd=${GUILE:-guile}
guile_version=$("$guile_cmd" --no-auto-compile -c '(display (effective-version))')
expected_version=$(sed -n 's/^#define ESQUEMA_VERSION_STRING "\([^"]*\)"/\1/p' "$srcdir/c/esquema.h")

# Explicit paths isolate these checks from a packager's inherited make flags.
install_action() {
    action=$1
    target_prefix=$2
    target_libdir=$3
    target_stage=$4
    "$make_cmd" -s -C "$srcdir" "$action" PREFIX="$target_prefix" \
        LIBDIR="$target_libdir" INCLUDEDIR="$target_prefix/include" \
        DATADIR="$target_prefix/share" DOCDIR="$target_prefix/share/doc/esquema" \
        GUILE_SITE_DIR="$target_prefix/share/guile/site/$guile_version" \
        DESTDIR="$target_stage"
}

# A package staging directory must not leak into the installed configuration.
install_action install /usr /usr/lib "$scratch/stage"
staged_site="$scratch/stage/usr/share/guile/site/$guile_version"
test -f "$scratch/stage/usr/lib/libesquema.so"
test -f "$scratch/stage/usr/include/esquema.h"
test -f "$scratch/stage/usr/share/doc/esquema/README.md"
test -f "$scratch/stage/usr/share/doc/esquema/LICENSE"
test ! -e "$staged_site/esquema/tests"
GUILE_AUTO_COMPILE=0 "$guile_cmd" -L "$staged_site" -c \
  '(use-modules (esquema library-path)) (exit (if (string=? %installed-libdir "/usr/lib") 0 1))'
install_action uninstall /usr /usr/lib "$scratch/stage"
test ! -e "$scratch/stage/usr/lib/libesquema.so"
test ! -e "$scratch/stage/usr/include/esquema.h"
test ! -e "$staged_site/esquema"
test ! -e "$scratch/stage/usr/share/doc/esquema"

# Cover a prefix containing spaces and a nonstandard library subdirectory.
prefix="$scratch/custom prefix"
site="$prefix/share/guile/site/$guile_version"
install_action install "$prefix" "$prefix/lib64/esquema" ""
mkdir "$scratch/unrelated"
cd "$scratch/unrelated"
unset ESQUEMA_LIBDIR GUILE_LOAD_PATH GUILE_LOAD_COMPILED_PATH LD_LIBRARY_PATH
mkdir -p "$scratch/compiled/esquema"
GUILE_AUTO_COMPILE=0 "$guile_cmd" -L "$site" -c \
  '(use-modules (system base compile))
   (let ((source (cadr (command-line))) (output (caddr (command-line))))
     (for-each
      (lambda (name)
        (compile-file (string-append source "/esquema/" name ".scm")
                      #:output-file (string-append output "/esquema/" name ".go")))
      (list "constants" "container" "library-path" "ffi" "sandbox" "runtime")))' \
  "$site" "$scratch/compiled"
GUILE_AUTO_COMPILE=0 "$guile_cmd" -L "$site" -C "$scratch/compiled" -c \
  '(use-modules (esquema ffi) (esquema runtime))
   (exit (if (and (= 42 (esquema-init))
                  (string=? (esquema-version) (cadr (command-line)))) 0 1))' \
  "$expected_version"
install_action uninstall "$prefix" "$prefix/lib64/esquema" ""
test ! -e "$prefix/lib64/esquema/libesquema.so"
test ! -e "$site/esquema"
printf '%s\n' 'install: staged and custom-prefix checks passed'
