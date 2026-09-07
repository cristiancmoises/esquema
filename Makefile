# Esquema — rootless Guile-native container runtime.
#
# Build/test inside the Guix environment:
#   guix shell -m manifest.scm -- make check
#
# Guix's gcc-toolchain does not provide the built-in make default, `cc`.
ifeq ($(origin CC),default)
CC        = gcc
endif
CC       ?= gcc
PKG_CONFIG ?= pkg-config
INSTALL  ?= install
CSTD     ?= -std=gnu11
WARN     ?= -Wall -Wextra -Werror -Wshadow -Wpointer-arith \
            -Wformat=2 -Wformat-security -Wstrict-prototypes -Wmissing-prototypes
# Probe the target compiler: -fcf-protection is unavailable on e.g. AArch64.
cc-option = $(shell $(CC) $(CPPFLAGS) $(CFLAGS) $(1) -Werror -x c -c /dev/null \
                    -o /dev/null >/dev/null 2>&1 && printf '%s' '$(1)')
HARDEN   ?= -fstack-protector-strong $(call cc-option,-fstack-clash-protection) \
            $(call cc-option,-fcf-protection)
OPT      ?= -O2
SECCOMP_CFLAGS = $(shell $(PKG_CONFIG) --cflags libseccomp)
SECCOMP_LIBS   = $(shell $(PKG_CONFIG) --libs libseccomp)

CPPFLAGS ?= -D_FORTIFY_SOURCE=2
CFLAGS   ?= $(OPT)
LDFLAGS  ?= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDLIBS   ?=

SRCS      = $(wildcard c/*.c)
HDRS      = c/esquema.h c/internal.h
LIB       = libesquema.so

GUILE    ?= guile
SCM_DIR   = scheme
TEST_DIR  = scheme/esquema/tests
SCM_FILES = $(filter-out $(SCM_DIR)/esquema/test-ffi.scm,$(wildcard $(SCM_DIR)/esquema/*.scm))
DOC_FILES = $(wildcard README*.md LICENSE* LICENSING*.md NOTICE)
DOC_GUIDES = $(wildcard docs/*.md)
GUILE_EFFECTIVE_VERSION ?= $(shell $(GUILE) --no-auto-compile -c '(display (effective-version))')
PREFIX   ?= /usr/local
LIBDIR   ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DATADIR  ?= $(PREFIX)/share
DOCDIR   ?= $(DATADIR)/doc/esquema
GUILE_SITE_DIR ?= $(DATADIR)/guile/site/$(GUILE_EFFECTIVE_VERSION)
DESTDIR  ?=
export ESQUEMA_LIBDIR := $(CURDIR)

.PHONY: all lib install uninstall smoke check test test-install test-security test-perf test-c test-audit \
        cppcheck static asan ubsan sanitize clean help

all: lib

lib: $(LIB)

$(LIB): $(SRCS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CSTD) $(WARN) $(HARDEN) -fPIC $(SECCOMP_CFLAGS) \
	  $(SRCS) -o $@ -shared $(LDFLAGS) $(LDLIBS) $(SECCOMP_LIBS)

## install: install library, C header, Scheme modules and docs (PREFIX, DESTDIR supported)
install: lib
	$(INSTALL) -d "$(DESTDIR)$(LIBDIR)" "$(DESTDIR)$(INCLUDEDIR)" \
	  "$(DESTDIR)$(GUILE_SITE_DIR)/esquema" "$(DESTDIR)$(DOCDIR)"
	$(INSTALL) -m 755 $(LIB) "$(DESTDIR)$(LIBDIR)/$(LIB)"
	$(INSTALL) -m 644 c/esquema.h "$(DESTDIR)$(INCLUDEDIR)/esquema.h"
	$(INSTALL) -m 644 $(SCM_FILES) "$(DESTDIR)$(GUILE_SITE_DIR)/esquema/"
	$(GUILE) --no-auto-compile -c \
	  '(format #t "(define-module (esquema library-path) #:export (%installed-libdir))~%(define %installed-libdir ~s)~%" (cadr (command-line)))' \
	  "$(LIBDIR)" > "$(DESTDIR)$(GUILE_SITE_DIR)/esquema/library-path.scm"
	chmod 644 "$(DESTDIR)$(GUILE_SITE_DIR)/esquema/library-path.scm"
	$(INSTALL) -m 644 $(DOC_FILES) "$(DESTDIR)$(DOCDIR)/"
	$(if $(DOC_GUIDES),$(INSTALL) -d "$(DESTDIR)$(DOCDIR)/docs" && $(INSTALL) -m 644 $(DOC_GUIDES) "$(DESTDIR)$(DOCDIR)/docs/",:)

## uninstall: remove installed Esquema files (use the same paths as install)
uninstall:
	rm -f "$(DESTDIR)$(LIBDIR)/$(LIB)" "$(DESTDIR)$(INCLUDEDIR)/esquema.h" \
	  $(foreach f,$(notdir $(SCM_FILES)),"$(DESTDIR)$(GUILE_SITE_DIR)/esquema/$(f)") \
	  "$(DESTDIR)$(GUILE_SITE_DIR)/esquema/library-path.scm" \
	  $(foreach f,$(notdir $(DOC_FILES)),"$(DESTDIR)$(DOCDIR)/$(f)") \
	  $(foreach f,$(notdir $(DOC_GUIDES)),"$(DESTDIR)$(DOCDIR)/docs/$(f)")
	-rmdir "$(DESTDIR)$(GUILE_SITE_DIR)/esquema"
	$(if $(DOC_GUIDES),-rmdir "$(DESTDIR)$(DOCDIR)/docs",:)
	-rmdir "$(DESTDIR)$(DOCDIR)"

## smoke: build the library and confirm the FFI loads (esquema-init == 42)
smoke: lib
	GUILE_AUTO_COMPILE=0 $(GUILE) -L $(SCM_DIR) \
	  -c '(use-modules (esquema ffi)) (exit (if (= 42 (esquema-init)) 0 1))'
	@echo "smoke: OK (FFI loads, esquema-init == 42)"

## check: build, C tests, functional + security suites, static analysis
check: lib test-c test-install test test-security test-audit

## test-install: verify staged/custom-prefix installs and installed FFI loading
test-install: lib
	+GUILE="$(GUILE)" $(SHELL) $(TEST_DIR)/install.sh

## test: SRFI-64 functional suite
test: lib
	GUILE_AUTO_COMPILE=0 $(GUILE) -L $(SCM_DIR) $(TEST_DIR)/functional.scm

## test-security: isolation / escape attempts (positive+negative controls)
test-security: lib
	GUILE_AUTO_COMPILE=0 $(GUILE) -L $(SCM_DIR) $(TEST_DIR)/security.scm

## test-perf: startup latency / overhead / leak guard
test-perf: lib
	GUILE_AUTO_COMPILE=0 $(GUILE) -L $(SCM_DIR) $(TEST_DIR)/performance.scm

## test-c: C-level primitive tests (seccomp SIGSYS kill, cap drop, validation)
test-c: lib
	$(CC) -std=gnu11 -Wall -Wextra -O2 -pthread -I c \
	  $(TEST_DIR)/c/test_primitives.c -L. -lesquema -o .test_primitives
	LD_LIBRARY_PATH=$(CURDIR) ./.test_primitives
	rm -f .test_primitives

## test-audit: static analysis (cppcheck)
test-audit: cppcheck
	@echo "audit: static analysis passed"

## cppcheck: static analysis, findings are errors
cppcheck:
	cppcheck --enable=warning,performance,portability --error-exitcode=1 \
	  --inline-suppr --std=c11 --quiet -I c c/

## static: gcc -fanalyzer deep static analysis
static:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CSTD) $(WARN) $(HARDEN) $(SECCOMP_CFLAGS) -fanalyzer \
	  -fsyntax-only $(SRCS)

## sanitize: build library + C tests under ASan+UBSan (with leak detection)
sanitize:
	$(CC) $(CSTD) $(WARN) -fPIC -g -O1 \
	  -fsanitize=address,undefined -fno-omit-frame-pointer \
	  $(SECCOMP_CFLAGS) $(SRCS) -shared -o libesquema-asan.so $(LDLIBS) $(SECCOMP_LIBS)
	$(CC) -std=gnu11 -g -O1 -pthread -fsanitize=address,undefined -fno-omit-frame-pointer \
	  -I c $(TEST_DIR)/c/test_primitives.c libesquema-asan.so $(SECCOMP_LIBS) \
	  -o .test_primitives_asan
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	  LD_LIBRARY_PATH=$(CURDIR) ./.test_primitives_asan
	rm -f .test_primitives_asan libesquema-asan.so
	@echo "sanitize: ASan+UBSan clean"

## asan: alias retained for convenience
asan: sanitize

clean:
	rm -f $(LIB) libesquema-asan.so .test_primitives .test_primitives_asan

help:
	@grep -E '^##' Makefile | sed 's/## //'
