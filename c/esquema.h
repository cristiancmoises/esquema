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

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- version / health ------------------------------------------------ */

#define ESQUEMA_VERSION_STRING "0.2.0"

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

esquema_config *esquema_config_new(void);
void            esquema_config_free(esquema_config *cfg);

/* All setters return 0 on success, -1 on error (esquema_errno set). */
int esquema_config_set_rootfs(esquema_config *cfg, const char *path);
int esquema_config_set_hostname(esquema_config *cfg, const char *name);
int esquema_config_add_arg(esquema_config *cfg, const char *arg);
int esquema_config_add_env(esquema_config *cfg, const char *keyval);
/* Extra bind mount: host <src> -> in-container <dst>, before pivot_root.
 * read_only != 0 remounts the bind read-only. */
int esquema_config_add_bind(esquema_config *cfg, const char *src,
                            const char *dst, int read_only);

void esquema_config_set_namespaces(esquema_config *cfg, unsigned int ns_mask);
void esquema_config_set_id_map(esquema_config *cfg, unsigned int uid,
                               unsigned int gid);
void esquema_config_set_seccomp(esquema_config *cfg, int enable);
void esquema_config_set_drop_caps(esquema_config *cfg, int enable);
void esquema_config_set_rootfs_ro(esquema_config *cfg, int read_only);

/* Resource limits (cgroup v2, best-effort under rootless delegation).
 * A value <= 0 leaves the corresponding limit unset. */
void esquema_config_set_memory_max(esquema_config *cfg, long bytes);
void esquema_config_set_pids_max(esquema_config *cfg, long count);
void esquema_config_set_cpu_max(esquema_config *cfg, long quota_us,
                                long period_us);
int  esquema_config_set_cgroup_name(esquema_config *cfg, const char *name);

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

/* Drop every capability (bounding set + ambient set + inheritable/
 * permitted/effective via capset), lock securebits and set NO_NEW_PRIVS. */
int esquema_drop_caps(void);

/* prctl(PR_SET_NO_NEW_PRIVS). */
int esquema_no_new_privs(void);

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
