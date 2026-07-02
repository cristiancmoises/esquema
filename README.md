# Esquema — a Guile-native container runtime

**Esquema** is a minimal, security-first, **rootless** container runtime built
natively in Scheme. It integrates with **GNU Guix** and **Shepherd** to give
reproducible, strongly-isolated environments without a daemon, without root,
and without YAML — just declarative Scheme.

Containers are **first-class Scheme objects**. Isolation is **explicit,
fine-grained and secure by default**.

---

## Security model

Esquema confines an untrusted payload behind defence-in-depth. Every layer is
applied, in the correct order, inside a `clone`/`fork` child that runs only
async-signal-safe C between `fork` and `execve`:

1. **User namespace (rootless).** Runs as an unprivileged user; the payload is
   root *inside* the namespace, mapped to your ordinary uid outside.
2. **Mount / PID / UTS / IPC / net / cgroup namespaces.** Full process,
   filesystem, hostname, IPC and network isolation.
3. **`pivot_root` into the rootfs**, with the host mount tree detached so it is
   unreachable, a fresh `/proc`, and minimal `/dev`.
4. **All capabilities dropped** — bounding set emptied, ambient cleared,
   `capset` zeroed, `securebits` locked (`SECBIT_NOROOT`, so uid-0-in-ns confers
   nothing), and `PR_SET_NO_NEW_PRIVS` set so setuid binaries cannot escalate.
5. **seccomp-BPF allowlist** — default `ENOSYS`, with a `KILL_PROCESS` deny-set
   for `ptrace`, `mount`, `unshare`, `setns`, `bpf`, `keyctl`, module and kexec
   syscalls, etc. Non-native (incl. x32) ABIs are killed.
6. **cgroups v2 limits** (best-effort under rootless delegation) — `memory.max`,
   `pids.max`, `cpu.max`.

This is verified by the test-suite (see *Testing*): the payload cannot see host
PIDs, cannot reach the host filesystem, has an empty capability set, is killed
on a denied syscall, and sees only loopback networking.

### How this compares

| Property                    | Esquema            | Docker/Podman   | Jails / LXC     | `guix shell`        |
|-----------------------------|--------------------|-----------------|-----------------|---------------------|
| Language-native (Scheme)    | ✅                 | ❌              | ❌              | ✅                  |
| Daemon-free                 | ✅                 | ❌ (Docker)     | ✅              | ✅                  |
| Rootless by default         | ✅                 | partial         | ❌              | ✅                  |
| User namespace isolation    | ✅                 | ✅              | n/a (BSD)       | only `--container`  |
| seccomp syscall filtering   | ✅ (allowlist)     | ✅              | ✅ (coarse)     | ❌                  |
| Capability drop + no-new-privs | ✅              | ✅              | partial         | ❌                  |
| Declarative in one language | ✅ (Scheme)        | ❌ (YAML/OCI)   | ❌              | ✅ (Guix)           |

A plain `guix shell` gives a reproducible *environment* but **no kernel-level
isolation** (shared namespaces, no seccomp, full capabilities). Esquema adds the
isolation while keeping the Scheme-native, daemon-free ergonomics. Container
startup is ~**13 ms** (≈8 ms over a bare `execve`).

---

## Getting started

Build the shared library and run the smoke test inside the pinned environment:

```sh
guix shell -m manifest.scm -- make smoke
```

Build a self-contained demo rootfs and launch a container:

```sh
guix shell -m manifest.scm -- sh examples/build-rootfs.sh examples/rootfs-min
guix shell -m manifest.scm -- env ESQUEMA_LIBDIR=$PWD \
  guile -L scheme examples/hello.scm
```

Define and run a container from Scheme:

```scheme
(use-modules (esquema runtime) (esquema container))

(define box
  (make-container "web" "/path/to/rootfs"
                  (list "/bin/httpd" "-p" "8080")
                  #:hostname   "web"
                  #:rootfs-ro? #t                       ; seal the root
                  #:limits     (make-limits (* 256 1024 1024) ; memory.max bytes
                                            128              ; pids.max
                                            50000 100000))) ; cpu 50%
;; forks, isolates, execve()s the payload, waits, returns the exit status:
(run-container box)
```

`make-container` is **secure by default**: all namespaces, seccomp on, and every
capability dropped unless you opt out (`#:seccomp? #f`, `#:drop-caps? #f`,
`#:namespaces '(user mount pid ...)`).

---

## Testing

```sh
guix shell -m manifest.scm -- make check       # C tests + functional + security + cppcheck
guix shell -m manifest.scm -- make test-perf   # startup latency / overhead / leak guard
guix shell -m manifest.scm -- make static      # gcc -fanalyzer
guix shell -m manifest.scm -- make sanitize    # ASan + UBSan build and run
```

The suite covers functional behaviour (`scheme/esquema/tests/functional.scm`),
isolation and escape attempts with positive+negative controls
(`security.scm`), C-level enforcement including the seccomp `SIGSYS` kill
(`tests/c/test_primitives.c`), and performance/leak guards (`performance.scm`).
The C library builds warning-clean under `-Wall -Wextra -Werror` with FORTIFY,
stack-protector/clash protection, full RELRO, a non-executable stack and
CF-protection.

---

## Guix service

`(esquema esquema-service)` provides a Shepherd service type to supervise a
container as part of a Guix system configuration.

> Esquema empowers secure, reproducible, declarative containerization for GNU
> Guix — for development, CI/CD and lightweight server deployments.
