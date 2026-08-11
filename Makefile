# Esquema — rootless Guile-native container runtime.
#
# Build/test inside the pinned environment:
#   guix shell -m manifest.scm -- make check
#
CC        = gcc
CSTD      = -std=gnu11
WARN      = -Wall -Wextra -Werror -Wshadow -Wpointer-arith \
            -Wformat=2 -Wformat-security -Wstrict-prototypes -Wmissing-prototypes
HARDEN    = -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection \
            -fcf-protection -fPIC
OPT      ?= -O2
SECCOMP_CFLAGS = $(shell pkg-config --cflags libseccomp)
SECCOMP_LIBS   = $(shell pkg-config --libs libseccomp)

CFLAGS   ?= $(CSTD) $(WARN) $(HARDEN) $(OPT) $(SECCOMP_CFLAGS)
LDFLAGS  ?= -shared -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDLIBS   ?= $(SECCOMP_LIBS)

SRCS      = $(wildcard c/*.c)
HDRS      = c/esquema.h c/internal.h
LIB       = libesquema.so

GUILE    ?= guile
SCM_DIR   = scheme
TEST_DIR  = scheme/esquema/tests
export ESQUEMA_LIBDIR = $(CURDIR)

.PHONY: all lib smoke check test test-security test-perf test-c test-audit \
        cppcheck static asan ubsan sanitize clean help

all: lib

lib: $(LIB)

$(LIB): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

## smoke: build the library and confirm the FFI loads (esquema-init == 42)
smoke: lib
	GUILE_AUTO_COMPILE=0 $(GUILE) -L $(SCM_DIR) \
	  -c '(use-modules (esquema ffi)) (exit (if (= 42 (esquema-init)) 0 1))'
	@echo "smoke: OK (FFI loads, esquema-init == 42)"

## check: build, C tests, functional + security suites, static analysis
check: lib test-c test test-security test-audit

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
	$(CC) $(CSTD) $(WARN) $(HARDEN) $(OPT) $(SECCOMP_CFLAGS) -fanalyzer \
	  -fsyntax-only $(SRCS)

## sanitize: build library + C tests under ASan+UBSan (with leak detection)
sanitize:
	$(CC) $(CSTD) $(WARN) -fPIC -g -O1 \
	  -fsanitize=address,undefined -fno-omit-frame-pointer \
	  $(SECCOMP_CFLAGS) $(SRCS) -shared -o libesquema-asan.so $(LDLIBS)
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
