/* spawn.c — top-level sandbox orchestrator.
 *
 * Sequence (P = host/Guile process, A = setup child, B = payload / PID 1):
 *   P  compiles the seccomp filter (safe: not post-fork), forks A.
 *   A  is single-threaded (fork copies only the calling thread), which is
 *      what lets it unshare a user namespace at all; it writes its own
 *      uid/gid maps, sets the hostname, then forks B.
 *   B  becomes PID 1 of the new PID namespace, sets up mounts + loopback,
 *      drops all capabilities, applies seccomp and execve()s the payload.
 *   P  optionally moves A into a cgroup, then returns A's pid; esquema_wait
 *      reaps A (whose status is B's status) and cleans the cgroup up.
 *
 * Everything between fork and execve uses only async-signal-safe calls. */
#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

/* Per-thread pid -> created-cgroup-path map, so esquema_wait cleans up the
 * cgroup belonging to the pid it actually reaped even when several containers
 * are live on one thread. */
#define ES_CG_SLOTS 64
static __thread pid_t  g_cg_pid[ES_CG_SLOTS];
static __thread char  *g_cg_path[ES_CG_SLOTS];

static void cg_store(pid_t pid, const char *path)
{
    if (!path || !path[0]) return;
    for (int i = 0; i < ES_CG_SLOTS; i++) {
        if (g_cg_pid[i] == 0) {
            char *p = strdup(path);
            if (!p) return;                 /* best-effort */
            g_cg_path[i] = p;
            g_cg_pid[i]  = pid;
            return;
        }
    }
    /* table full: leak this one rather than mis-associate (very rare) */
}

/* Detach and return the path for `pid` (caller frees), or NULL. */
static char *cg_take(pid_t pid)
{
    for (int i = 0; i < ES_CG_SLOTS; i++) {
        if (g_cg_pid[i] == pid) {
            char *p = g_cg_path[i];
            g_cg_pid[i]  = 0;
            g_cg_path[i] = NULL;
            return p;
        }
    }
    return NULL;
}

static unsigned int ns_to_clone(unsigned int m)
{
    unsigned int f = 0;
    if (m & ESQUEMA_NS_USER)   f |= CLONE_NEWUSER;
    if (m & ESQUEMA_NS_MOUNT)  f |= CLONE_NEWNS;
    if (m & ESQUEMA_NS_PID)    f |= CLONE_NEWPID;
    if (m & ESQUEMA_NS_UTS)    f |= CLONE_NEWUTS;
    if (m & ESQUEMA_NS_IPC)    f |= CLONE_NEWIPC;
    if (m & ESQUEMA_NS_NET)    f |= CLONE_NEWNET;
    if (m & ESQUEMA_NS_CGROUP) f |= CLONE_NEWCGROUP;
    return f;
}

static char *default_env[] = {
    (char *) "PATH=/bin:/usr/bin:/sbin",
    (char *) "HOME=/",
    NULL
};

pid_t esquema_spawn(esquema_config *cfg)
{
    es_clear_error();

    if (!cfg || !cfg->rootfs) { errno = EINVAL; return (pid_t) es_fail("spawn: no rootfs"); }
    if (cfg->argc == 0 || !cfg->argv || !cfg->argv[0]) {
        errno = EINVAL; return (pid_t) es_fail("spawn: no command");
    }

    /* Resolve rootfs to an absolute path (pivot_root needs one) and store it
     * back so both children inherit it after fork. */
    char abs[PATH_MAX];
    if (!realpath(cfg->rootfs, abs)) return (pid_t) es_fail("spawn: realpath rootfs");
    char *newroot = strdup(abs);
    if (!newroot) { errno = ENOMEM; return (pid_t) es_fail("spawn: strdup"); }
    free(cfg->rootfs);
    cfg->rootfs = newroot;

    char **envp = (cfg->envc > 0) ? cfg->envp : default_env;
    unsigned int flags = ns_to_clone(cfg->ns_mask);

    /* Compile seccomp before any fork (libseccomp allocates freely here).
     * Two filters: the small TTY-injection killer (applied first in the
     * child) and the main allowlist. */
    struct sock_fprog prog = { 0, NULL };
    struct sock_fprog prog_tty = { 0, NULL };
    int have_seccomp = 0;
    if (cfg->seccomp) {
        if (es_seccomp_compile_tty(&prog_tty) < 0) return -1;    /* es_fail set */
        if (es_seccomp_compile(&prog) < 0) {
            es_seccomp_free_program(&prog_tty);
            return -1;
        }
        have_seccomp = 1;
    }

    int sp[2];
    if (pipe(sp) < 0) {
        if (have_seccomp) { es_seccomp_free_program(&prog); es_seccomp_free_program(&prog_tty); }
        return (pid_t) es_fail("spawn: pipe");
    }

    pid_t a = fork();
    if (a < 0) {
        int e = errno;
        close(sp[0]); close(sp[1]);
        if (have_seccomp) { es_seccomp_free_program(&prog); es_seccomp_free_program(&prog_tty); }
        errno = e;
        return (pid_t) es_fail("spawn: fork");
    }

    if (a == 0) {
        /* ===================== setup child A ===================== */
        close(sp[1]);
        prctl(PR_SET_PDEATHSIG, SIGKILL);          /* die with P */
        /* Reset SIGCHLD to default: A inherited Guile's dispositions and may
         * have SIG_IGN/SA_NOCLDWAIT, which would auto-reap B and make the
         * waitpid below fail with ECHILD instead of returning B's status. */
        signal(SIGCHLD, SIG_DFL);

        char ch;
        while (read(sp[0], &ch, 1) < 0 && errno == EINTR) { }
        close(sp[0]);

        if (unshare((int) flags) < 0) _exit(ES_EXIT_UNSHARE);

        if ((cfg->ns_mask & ESQUEMA_NS_USER) &&
            es_write_id_maps(0, cfg->map_uid, cfg->map_gid) < 0)
            _exit(ES_EXIT_IDMAP);

        if ((cfg->ns_mask & ESQUEMA_NS_UTS) && cfg->hostname)
            if (sethostname(cfg->hostname, strlen(cfg->hostname)) < 0)
                { /* best-effort: hostname is cosmetic */ }

        pid_t b = fork();
        if (b < 0) _exit(ES_EXIT_FORKB);

        if (b == 0) {
            /* =================== payload child B =================== */
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            /* New session: detach from the host's controlling terminal so a
             * TIOCSTI/TIOCLINUX injection has no target tty (complements the
             * seccomp block). */
            setsid();
            if (es_setup_mounts(cfg) < 0) _exit(ES_EXIT_MOUNT);
            if (cfg->ns_mask & ESQUEMA_NS_NET)
                es_setup_loopback();                /* best-effort */

            if (cfg->drop_caps) {
                if (es_drop_all_caps() < 0) _exit(ES_EXIT_CAPS);
            } else {
                prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }

            if (have_seccomp) {
                /* TTY-injection killer first (default-allow), then the main
                 * allowlist; NNP was set by es_drop_all_caps above. */
                if (es_seccomp_apply_program(&prog_tty) < 0) _exit(ES_EXIT_SECCOMP);
                if (es_seccomp_apply_program(&prog) < 0)     _exit(ES_EXIT_SECCOMP);
            }

            execve(cfg->argv[0], cfg->argv, envp);
            _exit(ES_EXIT_EXEC);
        }

        /* A reaps B and mirrors its status. `st` is initialised so a
         * non-EINTR waitpid failure can never read indeterminate memory. */
        int st = 0;
        for (;;) {
            pid_t w = waitpid(b, &st, 0);
            if (w == b) break;
            if (w < 0 && errno == EINTR) continue;
            _exit(ES_EXIT_REAP);
        }
        if (WIFEXITED(st))  _exit(WEXITSTATUS(st));
        _exit(128 + WTERMSIG(st));
    }

    /* ========================= parent P ========================= */
    close(sp[0]);

    if (cfg->cgroup_name &&
        (cfg->memory_max > 0 || cfg->pids_max > 0 || cfg->cpu_quota_us > 0)) {
        /* Best-effort under rootless delegation; move A (B inherits it).
         * Remember any created path against A's pid so esquema_wait cleans up
         * exactly this container's cgroup. */
        char path[PATH_MAX];
        es_cgroup_setup(cfg, a, path, sizeof path);
        if (path[0]) cg_store(a, path);
    }

    /* Release A. */
    while (write(sp[1], "x", 1) < 0 && errno == EINTR) { }
    close(sp[1]);
    if (have_seccomp) { es_seccomp_free_program(&prog); es_seccomp_free_program(&prog_tty); }
    return a;
}

int esquema_wait(pid_t pid)
{
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno == EINTR) continue;
        /* Preserve the waitpid errno across cleanup's rmdir(). */
        int e = errno;
        { char *p = cg_take(pid); if (p) { es_cgroup_cleanup(p); free(p); } }
        errno = e;
        return es_fail("wait");
    }
    { char *p = cg_take(pid); if (p) { es_cgroup_cleanup(p); free(p); } }

    if (WIFEXITED(st))   return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 0;
}
