/* esquema.h — public C API for the Esquema rootless container runtime.
 *
 * Esquema isolates an untrusted payload behind, in order:
 *   user namespace (rootless)  -> mount/pid/uts/ipc/net/cgroup namespaces
 *   -> uid/gid mapping          -> private mount propagation
 *   -> pivot_root into rootfs   -> fresh /proc, minimal /dev
 *   -> cgroup v2 resource caps  -> capability drop -> seccomp -> execve.
 *
 * The whole sequence between clone() and execve() runs in C so that a
 * multi-threaded host runtime (Guile) never executes non-async-signal-safe
 * code in the child.  The caller builds an opaque config, calls
 * esquema_spawn(), then esquema_wait().
 */
#ifndef ESQUEMA_H
#define ESQUEMA_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- version / health ------------------------------------------------ */

#define ESQUEMA_VERSION_STRING "0.3.0"

/* Human-readable version string (never NULL). */
const char *esquema_version(void);

/* Legacy health probe: returns 42 when the library loaded successfully.
 * Kept stable because the README, service and smoke tests rely on it. */
int esquema_init(void);
int esquema_core_init(void);

/* ---- error introspection --------------------------------------------- */

/* errno captured by the most recent failing esquema_* call on this thread. */
int esquema_errno(void);
/* Human string "<stage>: <strerror>" for the most recent failure. */
const char *esquema_strerror(void);

/* ---- namespace selection --------------------------------------------- */

#define ESQUEMA_NS_USER   (1u << 0)
#define ESQUEMA_NS_MOUNT  (1u << 1)
#define ESQUEMA_NS_PID    (1u << 2)
#define ESQUEMA_NS_UTS    (1u << 3)
#define ESQUEMA_NS_IPC    (1u << 4)
#define ESQUEMA_NS_NET    (1u << 5)
#define ESQUEMA_NS_CGROUP (1u << 6)
#define ESQUEMA_NS_ALL    (ESQUEMA_NS_USER | ESQUEMA_NS_MOUNT | ESQUEMA_NS_PID | \
                           ESQUEMA_NS_UTS | ESQUEMA_NS_IPC | ESQUEMA_NS_NET | \
                           ESQUEMA_NS_CGROUP)

/* ---- opaque container configuration ---------------------------------- */

typedef struct esquema_config esquema_config;

/* Versioned, fixed-layout seccomp policy.  Unknown versions, sizes, enum
 * values, flags, and reserved fields are rejected instead of guessed. */
#define ESQUEMA_SECCOMP_POLICY_VERSION 1U

enum esquema_seccomp_arch {
    ESQUEMA_ARCH_NATIVE  = 0,
    ESQUEMA_ARCH_X86_64  = 1,
    ESQUEMA_ARCH_AARCH64 = 2
};

enum esquema_socket_family {
    ESQUEMA_SOCKET_UNIX    = 1ULL << 0,
    ESQUEMA_SOCKET_INET    = 1ULL << 1,
    ESQUEMA_SOCKET_INET6   = 1ULL << 2,
    ESQUEMA_SOCKET_NETLINK = 1ULL << 3,
    ESQUEMA_SOCKET_VSOCK   = 1ULL << 4,
    ESQUEMA_SOCKET_ALL     = (1ULL << 5) - 1
};

enum esquema_io_uring_policy {
    ESQUEMA_IO_URING_DENY  = 0,
    ESQUEMA_IO_URING_ALLOW = 1
};

enum esquema_ioctl_policy {
    ESQUEMA_IOCTL_NONE       = 0,
    ESQUEMA_IOCTL_RESTRICTED = 1,
    ESQUEMA_IOCTL_LEGACY     = 2
};

typedef struct esquema_seccomp_policy {
    uint32_t version;
    uint32_t size;
    uint32_t expected_arch;
    uint32_t io_uring;
    uint32_t ioctl_policy;
    uint32_t flags;
    uint64_t socket_families;
    uint64_t reserved[2];
} esquema_seccomp_policy;

/* Initialize POLICY to the Fortress v1 default: native architecture,
 * AF_UNIX/INET/INET6, io_uring denied, restricted ioctl requests. */
void esquema_seccomp_policy_init(esquema_seccomp_policy *policy);

/* Copy a validated v1 policy into CFG.  The legacy global allowlist remains
 * active when no versioned policy has been assigned. */
int esquema_config_set_seccomp_policy(esquema_config *cfg,
                                      const esquema_seccomp_policy *policy);
int esquema_config_set_seccomp_policy_v1(esquema_config *cfg,
                                         uint32_t expected_arch,
                                         uint64_t socket_families,
                                         uint32_t io_uring,
                                         uint32_t ioctl_policy);

esquema_config *esquema_config_new(void);
void            esquema_config_free(esquema_config *cfg);

/* All setters return 0 on success, -1 on error (esquema_errno set). */
int esquema_config_set_rootfs(esquema_config *cfg, const char *path);
int esquema_config_set_hostname(esquema_config *cfg, const char *name);
int esquema_config_add_arg(esquema_config *cfg, const char *arg);
int esquema_config_add_env(esquema_config *cfg, const char *keyval);
/* Extra bind mount: host <src> -> in-container <dst>, before pivot_root.
 * DST is a relative path with no empty, ".", or ".." components. Symlinks and
 * procfs magiclinks in the destination walk are rejected. read_only != 0
 * makes the detached bind tree read-only before it is attached where the
 * running kernel supports the fd-based mount API. */
int esquema_config_add_bind(esquema_config *cfg, const char *src,
                            const char *dst, int read_only);

/* Preserve one already-open descriptor across the payload exec.  Descriptors
 * 0, 1 and 2 are always preserved; every other inherited descriptor is
 * closed.  This explicit allowlist is intended for capability-scoped,
 * pre-opened channels such as an evcell-agent socket.  The descriptor must be
 * open when it is registered and remains owned by the caller. */
int esquema_config_preserve_fd(esquema_config *cfg, int fd);

void esquema_config_set_namespaces(esquema_config *cfg, unsigned int ns_mask);
void esquema_config_set_id_map(esquema_config *cfg, unsigned int uid,
                               unsigned int gid);
void esquema_config_set_seccomp(esquema_config *cfg, int enable);
void esquema_config_set_drop_caps(esquema_config *cfg, int enable);
void esquema_config_set_rootfs_ro(esquema_config *cfg, int read_only);

/* Fortress mode makes requested security controls fail closed. It requires
 * all namespaces, a non-legacy versioned seccomp policy, PID-1 supervision,
 * capability dropping, Landlock, at least one cgroup limit, and a configured
 * open-files limit. Requested limits must be installed and read back. Legacy
 * mode remains the default for API compatibility and treats unavailable
 * cgroup delegation or Landlock as best-effort. */
void esquema_config_set_strict(esquema_config *cfg, int enable);

/* Enable the Landlock "no new filesystem access outside the post-pivot root"
 * layer.  It is enabled by default.  Failure is fatal only in strict mode. */
void esquema_config_set_landlock(esquema_config *cfg, int enable);

/* Run a minimal PID-1 supervisor rather than execing the payload as PID 1.
 * It reaps orphaned descendants, forwards host lifecycle signals, and kills
 * remaining descendants after timeout_ms (1..60000). Strict mode requires it. */
int esquema_config_set_supervisor(esquema_config *cfg, int enable,
                                  unsigned int timeout_ms);

/* Resource limits.
 *
 * memory/pids/cpu are cgroup-v2 controls (best-effort under rootless
 * delegation unless strict mode is selected).  A value <= 0 leaves the
 * corresponding cgroup limit unset.
 *
 * open_files_max is a per-process RLIMIT_NOFILE value.  The setter accepts
 * only the bounded v1 range below.  Before payload exec Esquema sets both the
 * soft and hard limits to this value and reads them back.  Strict mode
 * requires the setter to have succeeded.  Preserved descriptors must be
 * numerically below the configured limit.  Strict seccomp permits resource
 * limit queries but kills subsequent mutations.  Omitting this setter in
 * legacy mode preserves the pre-v1 behavior (no Esquema-managed
 * RLIMIT_NOFILE). */
#define ESQUEMA_OPEN_FILES_MIN 16U
#define ESQUEMA_OPEN_FILES_MAX 1048576U

void esquema_config_set_memory_max(esquema_config *cfg, long bytes);
void esquema_config_set_pids_max(esquema_config *cfg, long count);
void esquema_config_set_cpu_max(esquema_config *cfg, long quota_us,
                                long period_us);
int  esquema_config_set_cgroup_name(esquema_config *cfg, const char *name);
int  esquema_config_set_open_files_max(esquema_config *cfg,
                                       uint32_t open_files_max);

/* ---- lifecycle ------------------------------------------------------- */

/* Spawn the payload in a fresh sandbox. Returns child pid (>0) or -1. */
pid_t esquema_spawn(esquema_config *cfg);
/* Wait for a spawned child. Returns its exit code (0-255), 128+signal if
 * killed by a signal, or -1 on error. */
int   esquema_wait(pid_t pid);

/* ---- standalone hardening primitives (also used by the test-suite) --- */

/* Apply the hardened seccomp allowlist to the *current* thread.
 * Denied syscalls trigger SCMP_ACT_KILL_PROCESS. Sets NO_NEW_PRIVS. */
int esquema_apply_seccomp(void);

/* Apply a validated versioned policy to the current thread.  The mandatory
 * invariant deny-set is always present and cannot be removed by the policy. */
int esquema_apply_seccomp_policy(const esquema_seccomp_policy *policy);

/* Drop every capability (bounding set + ambient set + inheritable/
 * permitted/effective via capset), lock securebits and set NO_NEW_PRIVS. */
int esquema_drop_caps(void);

/* prctl(PR_SET_NO_NEW_PRIVS). */
int esquema_no_new_privs(void);

/* Return the running kernel's Landlock ABI (>0), 0 when unsupported, or -1
 * for another query error.  This reports availability, not policy strength. */
int esquema_landlock_abi(void);

/* ---- legacy granular API (retained, hardened) ------------------------ */

int esquema_unshare(int flags);
int esquema_drop_privs(void);      /* == esquema_drop_caps() */

/* ---- cgroup helper (retained, hardened, non-crashing) ---------------- */

/* Best-effort: create <name> under the delegated cgroup v2 base and move
 * the current process into it. Returns 0 on success, -1 on error. */
int esquema_enter_cgroup(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* ESQUEMA_H */
