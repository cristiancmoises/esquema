# Esquema operating guide

[README](../README.md) · [Português brasileiro](guide.pt-BR.md)

Run checkout commands from the repository root. Esquema is a Linux runtime;
the C library and Scheme modules do not provide an OCI image puller or a
Docker-compatible command-line interface.

## Installation

Build dependencies are Guile 3.0, GNU Make, a GNU-compatible C toolchain,
`pkg-config`, libseccomp development files and Linux UAPI headers with Landlock.
Tests also use cppcheck and statically linked Bash. The Guix manifest provides
the build and analysis tools; build Bash separately:

```sh
guix shell -m manifest.scm -- make smoke
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
```

The manifest contains package names, not pinned Guix channel revisions.
Reproducing dependencies also requires selecting the same channels. On another
Linux distribution, install equivalent development packages and run `make smoke`.

Install into your own prefix without root:

```sh
make install PREFIX="$HOME/.local"
export GUILE_LOAD_PATH="$HOME/.local/share/guile/site/3.0${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"
guile -c '(use-modules (esquema runtime)) (display (esquema-runtime-version)) (newline)'
```

When building through Guix, run installation inside the same
`guix shell -m manifest.scm --` environment. Defaults place the library in
`PREFIX/lib`, the C header in `PREFIX/include` and Scheme modules in
`PREFIX/share/guile/site/3.0`. Installation records the final library directory
for the FFI; `ESQUEMA_LIBDIR` overrides it for a checkout or another library.

For package maintainers, stage files without writing into the host prefix:

```sh
make install PREFIX=/usr DESTDIR="$PWD/package-root"
```

`LIBDIR`, `INCLUDEDIR`, `GUILE_SITE_DIR` and `DOCDIR` override the corresponding
final directories; `DESTDIR` is prepended only while staging. Compiler and linker
flags can be supplied through `CPPFLAGS`, `CFLAGS` and `LDFLAGS`.

Remove an installation using the same directory settings:

```sh
make uninstall PREFIX="$HOME/.local"
```

Remove distribution packages through the package manager that installed them.

## Root filesystems and the API

A rootfs is an existing directory containing the executable, its dynamic loader
and libraries when needed, and mount points such as `/proc` and `/dev`. Esquema
does not download an image or resolve payload dependencies for you.

The self-contained demo copies static Bash into `/bin/sh`:

```sh
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
sh examples/build-rootfs.sh examples/rootfs-min
ESQUEMA_LIBDIR="$PWD" guile -L scheme examples/hello.scm
```

Without Guix, point `ESQUEMA_TEST_SHELL` at an existing static Bash. The demo uses
Bash features, so an arbitrary POSIX shell is not interchangeable.

```scheme
(use-modules (esquema runtime) (esquema container))

(define job
  (make-container "job" "/absolute/path/to/rootfs"
                  '("/bin/sh" "-c" "echo ready")
                  #:env '(("PATH" . "/bin") ("LANG" . "C"))
                  #:rootfs-ro? #t
                  #:supervise? #t))

(exit (run-container job))
```

`run-container` waits and returns the exit status, including `128 + signal` for
signal termination. `exit` propagates that status to the caller or service
manager. Configuration and spawn failures may instead raise a Guile exception.
`esquema-runtime-version` queries the loaded library version.

| Option | Meaning and default |
| --- | --- |
| `#:namespaces` | `(user mount pid uts ipc net cgroup)` by default. |
| `#:hostname` | Container name by default. |
| `#:env` | Explicit environment association list; an empty list uses minimal `PATH` and `HOME`, not the host environment. |
| `#:mounts` | `(source destination read-only?)` entries; destination is relative to the rootfs. Default: no binds. |
| `#:rootfs-ro?` | Read-only root request; default `#f`. |
| `#:seccomp?`, `#:drop-caps?`, `#:landlock?` | Default `#t`; Landlock failure is fatal only in strict mode. |
| `#:preserve-fds` | Explicitly delegated descriptors numbered 3 or higher; default empty. |
| `#:limits` | Resource limits record; default `#f`. |
| `#:strict?` | Require the complete strict configuration; default `#f`. |
| `#:supervise?` | PID-1 supervisor; default `#f`, automatically enabled in strict mode. |
| `#:teardown-timeout-ms` | Supervisor TERM-to-KILL timeout, 1–60000 ms; default 2000. |

The three-argument `(container name rootfs command)` constructor remains
compatible. The public C API is documented in [`c/esquema.h`](../c/esquema.h);
its usual lifecycle is configure, `esquema_spawn`, `esquema_wait`, then release
the configuration.

## Isolation and strict mode

Defaults create user, mount, PID, UTS, IPC, network and cgroup namespaces,
change root with `pivot_root`, detach the old mount tree and provide a new
`/proc` and minimal `/dev`. Namespace uid 0 maps to the invoking user's host uid.
Capabilities are dropped and `PR_SET_NO_NEW_PRIVS` is set. The payload shares
the host Linux kernel.

Compatibility mode keeps legacy seccomp behavior and best-effort cgroup and
Landlock setup. Strict mode, also called **Fortress**, requires all namespaces,
seccomp, capability dropping, Landlock, PID-1 supervision, a typed seccomp policy,
at least one cgroup limit and a version-1 open-file limit:

```scheme
(use-modules (esquema runtime) (esquema container))

(exit
 (run-container
  (make-container "worker" "/absolute/path/to/rootfs"
                  '("/bin/sh" "-c" "echo confined")
                  #:strict? #t
                  #:rootfs-ro? #t
                  #:limits (make-limits-v1 (* 256 1024 1024)
                                          128 50000 100000 1024))))
```

`make-limits-v1` takes memory bytes, process count, CPU quota in microseconds,
CPU period in microseconds and maximum open files. This requests 256 MiB,
128 processes, 50% of one CPU and 1024 open files. `#f` leaves an individual
cgroup limit unset; strict mode requires at least one. The four-argument
`make-limits` leaves the open-file limit unmanaged and is insufficient for strict
mode. The Scheme constructor supplies the Fortress seccomp policy and supervisor;
C callers must select them explicitly.

Strict startup aborts when cgroup delegation, requested limit readback, Landlock
or required mount operations fail. Delegate the requested controllers to the
invoking user's cgroup; mounting cgroups v2 alone is insufficient. A compatibility
launch does not demonstrate that strict mode works on that host.

Other policy boundaries:

- **Seccomp:** version 1 validates the native architecture, socket families,
  `io_uring` and ioctl handling. Unknown syscalls return `ENOSYS`; mandatory
  dangerous syscall denials kill the process. For example,
  `(make-seccomp-policy 'native '(unix) 'deny 'restricted)` selects Unix sockets
  and denies `io_uring`. `TIOCSTI` and `TIOCLINUX` remain fatal denials.
  Non-native ABIs, including x32, are rejected.
- **Landlock:** the base rule confines handled filesystem access beneath the
  post-pivot root. It is not a per-directory permission policy and cannot revoke
  already-open descriptors. Coverage depends on the build-time Linux headers
  and running kernel; it does not cover every metadata operation.
- **Descriptors:** inherited descriptors above 2 close unless listed in
  `#:preserve-fds`. Standard input, output and error remain available. Each
  preserved descriptor is an explicit capability granted to the payload.
- **Open files:** version-1 limits must be 16–1048576. Soft and hard
  `RLIMIT_NOFILE` are installed and read back before execution. Preserved
  descriptors at or above the limit are rejected. Strict seccomp also rejects
  resource-limit mutation. The direct limit syscall has x86-64 and AArch64
  implementations and fails closed on unsupported architectures.
- **Mounts:** bind destinations reject empty, `.` and `..` components and
  symlink traversal. Strict binds require the fd-based mount API. Strict
  read-only roots require recursive `mount_setattr` and readback; compatibility
  may use a weaker single-mount remount that can leave nested mounts writable.
- **Lifecycle:** the supervisor forwards lifecycle signals to the payload
  process group, reaps descendants and escalates TERM to KILL after the timeout.
  Cgroup launch tracking is shared across threads and capped at 4096 live records.

## Serve a website

This Guix-oriented example uses BusyBox `httpd` and mounts `/gnu/store`
read-only for its dynamic loader and libraries:

```sh
guix shell -m manifest.scm -- make smoke
BUSYBOX="$(guix build busybox)/bin/busybox" \
  sh examples/build-web-rootfs.sh examples/rootfs-web
ESQ_PORT=8081 guix shell -m manifest.scm -- \
  env ESQUEMA_LIBDIR="$PWD" guile -L scheme examples/deploy-web.scm
```

In another terminal, run `curl --fail http://127.0.0.1:8081/`. Put content in
`examples/rootfs-web/www/`. `ESQ_ROOTFS=/absolute/path/to/rootfs` overrides the
script-relative rootfs; `ESQ_PORT` defaults to 8081.

The example omits the network namespace so the server can use the host network.
It uses compatibility mode and cannot meet strict mode's all-namespaces
requirement. Cgroup limits are best-effort. The store bind exposes readable
store contents. A static server can avoid it if its rootfs is self-contained
and the deployment mount list is also adjusted.

Use a permitted unprivileged port; `net.ipv4.ip_unprivileged_port_start` controls
the host's threshold. An existing reverse proxy can forward public HTTPS to the
chosen local port. Configure its listening address, access rules and TLS as part
of deployment. The example itself serves HTTP and may bind on all host interfaces.

## Guix and Shepherd

When the `securityops` channel has been configured and updated, install its
package with `guix install esquema`. This is a third-party channel package;
it does not imply acceptance into upstream Guix or another distribution.

`(esquema esquema-service)` exports `esquema-service-type` and
`(esquema-configuration name rootfs command scheme-dir)`. It creates a Shepherd
service using the default container configuration. Its four fields do not expose
the full policy, host-network web settings or account selection. Arrange the
Scheme/library search paths and execution account in the surrounding service
environment; the module's description does not establish an unprivileged account.
For an explicit policy, supervise a Scheme launcher that constructs the desired
container and propagates its exit status.

## Testing

```sh
export ESQUEMA_TEST_SHELL="$(guix build bash-static:out)/bin/bash"
guix shell -m manifest.scm -- make check
guix shell -m manifest.scm -- make static
guix shell -m manifest.scm -- make sanitize
guix shell -m manifest.scm -- make test-perf
```

`check` includes C, functional and security tests, cppcheck, and installation
regressions using staged/custom prefixes and compiled Scheme modules. `static` runs
GCC's analyzer. `sanitize` executes C tests under ASan and UBSan. `test-perf`
measures startup overhead and resource leaks. See individual targets in
`make help`.

The suites exercise syscall denials, descriptor closure, mount traversal,
resource limits, supervision and strict-mode failure paths. Kernel-dependent
checks can skip or fail without host prerequisites; inspect the output. A smoke
test does not prove all isolation properties. Record kernel, architecture,
dependencies and actual test results when validating a Linux distribution.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Guile cannot find `(esquema runtime)` | Use `guile -L scheme` in a checkout or add the installed site directory to `GUILE_LOAD_PATH`. |
| `libesquema` cannot be loaded | Run `make smoke`; set `ESQUEMA_LIBDIR` to the directory containing the matching library. |
| No static Bash found | Set `ESQUEMA_TEST_SHELL` to executable static Bash; the manifest does not include it. |
| Namespace failure or status 91 | Check unprivileged user namespaces, kernel configuration and host/container restrictions. |
| Mount failure or status 94 | Check rootfs paths, mount targets, ownership and APIs required by the mode. |
| Strict cgroup setup fails | Delegate requested controllers in the caller's cgroups v2 subtree; inspect `/proc/self/cgroup` and `/sys/fs/cgroup`. |
| Landlock failure or status 99 | Check kernel support and whether the Landlock LSM is enabled. |
| Open-file limit failure or status 101 | Check the value, preserved descriptors and the caller's existing hard limit. |
| Executable exists but status is 127 | Check its interpreter/dynamic loader and libraries also exist inside the rootfs. |
| Web server is unreachable | Check `ESQ_PORT`, host networking, firewall and whether `httpd` is running. |

Setup statuses are implementation diagnostics; the payload can also return the
same codes. Use the surrounding error output and configuration to distinguish them.
