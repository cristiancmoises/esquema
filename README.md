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
5. **Versioned seccomp-BPF policy** — default `ENOSYS`, with a mandatory
   `KILL_PROCESS` deny-set for `ptrace`, `mount`, `unshare`, `setns`, `bpf`,
   `keyctl`, module and kexec syscalls, etc. Version 1 validates the runtime
   architecture, selects allowed socket families, makes `io_uring` an explicit
   allow-or-kill decision, and offers `none`, `restricted`, or legacy ioctl
   handling. `TIOCSTI` and `TIOCLINUX` remain fatal invariants. Non-native
   (including x32) ABIs are killed.
6. **Landlock filesystem scope** — when the running kernel supports Landlock,
   future path opens covered by the build-time Landlock headers are confined
   beneath the post-`pivot_root` filesystem.
   This base rule prevents new access outside the cell root; it is not yet a
   per-directory least-privilege policy and it cannot revoke an already-open
   descriptor.
7. **Descriptor capability closure** — every inherited descriptor above 2 is
   closed before `execve`, unless the trusted caller explicitly registered it
   with `#:preserve-fds` / `esquema_config_preserve_fd`. This is the mechanism
   intended for a pre-opened, capability-scoped agent channel.
8. **cgroups v2 limits** — legacy mode remains best-effort under rootless
   delegation. Opt-in `#:strict? #t` mode installs and reads back every
   requested `memory.max`, `pids.max`, and `cpu.max` value before releasing the
   payload, and aborts cleanly if delegation or verification fails.
9. **Race-resistant bind attachment** — destinations must be relative and may
   not contain empty, `.` or `..` components. They are resolved beneath a
   pinned root with `openat2` (`RESOLVE_BENEATH`, `NO_SYMLINKS`,
   `NO_MAGICLINKS`) or a component-by-component fd walk. On modern kernels,
   detached mounts are made read-only before fd-to-fd `move_mount` attachment.
   Strict mode fails closed when this fd-based mount API is unavailable;
   compatibility mode retains a validated pathname fallback for older kernels.
   A strict read-only root also requires a successful recursive
   `mount_setattr(AT_RECURSIVE)` operation and readback. It never treats the
   legacy single-mount remount as equivalent, because that fallback can leave
   nested mounts writable. Compatibility mode may use that documented,
   weaker fallback when the recursive API is unavailable.
10. **PID-1 supervision** — Fortress uses a minimal supervisor which forwards
    lifecycle signals to the payload process group, adopts and reaps orphaned
    descendants, and escalates from `TERM` to `KILL` after a bounded timeout.
    The launcher does not return a cell pid until its host-side signal relay is
    installed, so an immediate stop request is not lost during setup.
    Process-wide cleanup records are dynamically allocated, cross-thread safe,
    and capped at 4096 live cgroup-backed launches instead of a fixed 64-slot
    thread-local table.

This is verified by the test-suite (see *Testing*): the payload cannot see host
PIDs, cannot reach the host filesystem, has an empty capability set, is killed
on a denied syscall, and sees only loopback networking. Esquema cells still
share the host Linux kernel; these controls are not a hypervisor or VM boundary.

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

Select the typed version-1 policy explicitly for a non-Fortress cell when its
socket, `io_uring`, and ioctl requirements are known:

```scheme
(make-container "parser" "/path/to/rootfs" '("/bin/parser")
                #:seccomp-policy
                (make-seccomp-policy 'native '(unix) 'deny 'restricted)
                #:supervise? #t
                #:teardown-timeout-ms 1000)
```

The positional `(container name rootfs command)` constructor and configurations
without `#:seccomp-policy` retain the legacy seccomp behavior for API
compatibility. That compatibility policy is not accepted as a Fortress policy.

Landlock is defence in depth, not a complete filesystem monitor. It does not
mediate reads and writes on files opened before restriction, and Linux does
not currently mediate every metadata operation (for example all `chmod`,
`chown`, `stat`, or extended-attribute cases). Esquema handles only rights
known to the Linux UAPI headers used for the build; a higher runtime ABI does
not justify claiming coverage for rights unknown to those headers.

Fortress callers must additionally select `#:strict? #t`, provide at least one
cgroup limit, and leave all namespaces, seccomp, capability dropping, and
Landlock enabled. The Scheme constructor automatically supplies the typed
Fortress seccomp policy and enables PID-1 supervision for strict cells. Direct
C callers must set both explicitly. Strict mode deliberately fails when the
host has not delegated the requested cgroup controllers; it never silently
converts a
mandatory limit into best-effort operation. The legacy constructor and its
best-effort cgroup behavior remain available for compatibility, but are not a
Fortress boundary.

---

## Tutorial: host a website with Esquema

Serve a real, browser-reachable website from inside an isolated Esquema
container — rootless, seccomp-filtered, every capability dropped. Three steps.

### 1. Build a web rootfs

A rootfs is just a directory. The helper populates one with a full BusyBox
userland (its `httpd` applet is the web server) plus the standard mount points:

```sh
examples/build-web-rootfs.sh examples/rootfs-web
# drop your own files in examples/rootfs-web/www/ (index.html, assets, …)
```

BusyBox on Guix is dynamically linked, so the container bind-mounts
`/gnu/store` **read-only** at run time to resolve its loader and libraries — no
copying, and the store is world-readable already. (For a fully self-contained
image, put a statically-linked server in `bin/` instead and skip the bind.)

### 2. Describe the deployment

A container is a value. `examples/deploy-web.scm`:

```scheme
(use-modules (esquema runtime) (esquema container))

(define port (or (getenv "ESQ_PORT") "8081"))

(run-container
 (make-container "esquema-web" "/absolute/path/to/examples/rootfs-web"
                 (list "/bin/httpd" "-f" "-v" "-p" port "-h" "/www")
                 #:hostname   "esquema-web"
                 ;; Drop 'net to SHARE the host network so the port is reachable;
                 ;; keep it to isolate networking (then only loopback exists).
                 #:namespaces '(user mount pid uts ipc cgroup)
                 #:mounts     '(("/gnu/store" "gnu/store" #t))   ; ro: busybox libs
                 #:limits     (make-limits (* 128 1024 1024) 64 #f #f)))
```

Everything except networking stays isolated: the payload is PID 1 in its own
PID/mount/UTS/IPC namespace, `pivot_root`-ed into the rootfs, with an empty
capability set and the seccomp filter loaded.

### 3. Run it

```sh
# from a checkout (library on ESQUEMA_LIBDIR):
ESQ_PORT=8081 guix shell -m manifest.scm -- \
  env ESQUEMA_LIBDIR=$PWD guile -L scheme examples/deploy-web.scm

# or, once installed from the securityops channel (guix install esquema):
ESQ_PORT=8081 guile examples/deploy-web.scm
```

Verify and see the isolation the visitor's server runs under:

```sh
curl -s http://localhost:8081/ | head        # your page
# what the server process itself sees:
guile -c '(use-modules (esquema runtime)(esquema container))
 (run-container (make-container "x" "'$PWD'/examples/rootfs-web"
   (list "/bin/sh" "-c" "id -u; hostname; grep -E \"Cap|Seccomp\" /proc/self/status; ls /")
   #:mounts (quote (("/gnu/store" "gnu/store" #t)))))'
#  -> uid=0 (in-ns)  host=x  CapEff 0000000000000000  Seccomp: 2  / = just the rootfs
```

### Ports below 1024

A rootless container can only bind an **unprivileged** port (≥ 1024 by default),
so `8081` works out of the box but `80`/`81` do not. To serve on a privileged
port, lower the threshold once (reversible), then use it:

```sh
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=81   # revert with =1024
ESQ_PORT=81 guile examples/deploy-web.scm
```

To keep it running across reboots, wrap it in the Shepherd service (below) or a
`guix home` Shepherd service.

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
(`tests/c/test_primitives.c`), Landlock ABI/path enforcement, inherited-secret
descriptor closure plus explicit descriptor delegation, strict cgroup abort
and child reaping, typed seccomp architecture/socket/`io_uring`/ioctl policy,
symlink and magiclink bind attacks, supervisor signal/timeout behavior, orphan
reaping, 72 concurrent launches, and performance/leak guards
(`performance.scm`).
The C library builds warning-clean under `-Wall -Wextra -Werror` with FORTIFY,
stack-protector/clash protection, full RELRO, a non-executable stack and
CF-protection.

---

## Guix service

`(esquema esquema-service)` provides a Shepherd service type to supervise a
container as part of a Guix system configuration.

> Esquema empowers secure, reproducible, declarative containerization for GNU
> Guix — for development, CI/CD and lightweight server deployments.
