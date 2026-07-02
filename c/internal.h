/* internal.h — shared definitions private to the Esquema C implementation. */
#ifndef ESQUEMA_INTERNAL_H
#define ESQUEMA_INTERNAL_H

#define _GNU_SOURCE
#include <stddef.h>
#include <linux/filter.h> /* struct sock_fprog */

#include "esquema.h"

/* ---- child-side exit codes (surface setup failures via wait status) -- */
enum {
    ES_EXIT_UNSHARE = 91,
    ES_EXIT_IDMAP   = 92,
    ES_EXIT_FORKB   = 93,
    ES_EXIT_MOUNT   = 94,
    ES_EXIT_CAPS    = 95,
    ES_EXIT_SECCOMP = 96,
    ES_EXIT_REAP    = 97,
    ES_EXIT_EXEC    = 127
};

/* ---- last-error state (thread-local) --------------------------------- */

/* Record a failure: remember errno and a "<stage>: <strerror(errno)>"
 * message. Always returns -1 so callers can `return es_fail("stage");`. */
int         es_fail(const char *stage);
void        es_clear_error(void);
int         es_get_errno(void);
const char *es_get_message(void);

/* ---- opaque config (definition shared by config.c / spawn.c) --------- */

struct esquema_bind {
    char *src;
    char *dst;
    int   read_only;
};

struct esquema_config {
    char  *rootfs;
    char  *hostname;

    char **argv;              /* NULL-terminated */
    size_t argc;
    size_t argv_cap;

    char **envp;              /* NULL-terminated */
    size_t envc;
    size_t envp_cap;

    struct esquema_bind *binds;
    size_t binds_n;
    size_t binds_cap;

    unsigned int ns_mask;
    unsigned int map_uid;
    unsigned int map_gid;

    int seccomp;
    int drop_caps;
    int rootfs_ro;

    long memory_max;          /* bytes,   <=0 unset */
    long pids_max;            /* count,   <=0 unset */
    long cpu_quota_us;        /* <=0 unset */
    long cpu_period_us;       /* default 100000 */
    char *cgroup_name;
};

/* ---- seccomp (compile in parent, apply in child) --------------------- */

/* Build the hardened BPF program into *out (malloc'd filter buffer the
 * caller must free with es_seccomp_free_program). Returns 0 / -1. */
int  es_seccomp_compile(struct sock_fprog *out);
/* Build the small stacked TTY-injection (TIOCSTI/TIOCLINUX) kill filter.
 * Apply this BEFORE the main filter in the child. */
int  es_seccomp_compile_tty(struct sock_fprog *out);
void es_seccomp_free_program(struct sock_fprog *prog);
/* Apply a precompiled program with the raw seccomp() syscall. No malloc:
 * safe between clone() and execve(). Returns 0 / -1. */
int  es_seccomp_apply_program(const struct sock_fprog *prog);

/* ---- capability dropping (async-signal-safe) ------------------------- */
int es_drop_all_caps(void);

/* ---- namespace / mount helpers --------------------------------------- */

/* Parent side: write uid_map, "deny" to setgroups, then gid_map for pid. */
int es_write_id_maps(pid_t pid, unsigned int uid, unsigned int gid);

/* Child side (post-map): make mounts private, pivot into rootfs, mount a
 * fresh /proc and a minimal /dev, apply binds. Async-signal-safe. */
int es_setup_mounts(const struct esquema_config *cfg);

/* Child side: bring the loopback interface up (best-effort). */
int es_setup_loopback(void);

/* ---- cgroup v2 (parent side) ----------------------------------------- */

/* Create the cgroup, apply limits, and move `pid` into it. Best-effort:
 * on a permission failure under rootless delegation it logs and returns 0
 * unless `strict`. Fills `created_path` (size len) for later cleanup. */
int  es_cgroup_setup(const struct esquema_config *cfg, pid_t pid,
                     char *created_path, size_t len);
void es_cgroup_cleanup(const char *created_path);

/* ---- small async-signal-safe I/O helper ------------------------------ */
/* write the whole buffer to an already-open fd; returns 0/-1. */
int es_write_all(int fd, const void *buf, size_t n);
/* open+write+close a file with `content` (len bytes). Returns 0/-1. */
int es_write_file(const char *path, const char *content, size_t len);

#endif /* ESQUEMA_INTERNAL_H */
