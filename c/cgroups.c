/* cgroups.c — rootless-friendly cgroup v2 resource limiting.
 *
 * The original scm_enter_cgroup() dereferenced an unchecked fopen() and set
 * no limits. This replacement discovers the *delegated* cgroup subtree,
 * validates the name against traversal, sets real limits and checks every
 * write. Under rootless delegation the control files are often not writable
 * (EACCES); callers treat that as best-effort unless they need hard limits. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* cgroup2 mount point on this host family. */
#define CG_ROOT "/sys/fs/cgroup"

/* Reject names that could escape the delegated subtree. */
static int name_ok(const char *name)
{
    if (!name || !name[0]) return 0;
    if (strchr(name, '/')) return 0;
    if (strchr(name, '\n')) return 0;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    if (name[0] == '.') return 0;
    if (strlen(name) > 200) return 0;
    return 1;
}

/* Discover the writable cgroup subtree from the "0::" line of
 * /proc/self/cgroup joined onto the cgroup2 mount point. */
static int cgroup_base(char *out, size_t outsz)
{
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) { errno = EIO; return -1; }
    buf[n] = '\0';

    const char *rel = NULL;
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        if (strncmp(line, "0::", 3) == 0) { rel = line + 3; break; }
    }
    if (!rel) { errno = ENOTSUP; return -1; }

    int w = snprintf(out, outsz, "%s%s", CG_ROOT,
                     strcmp(rel, "/") == 0 ? "" : rel);
    if (w < 0 || (size_t) w >= outsz) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static int write_limit(const char *dir, const char *file, const char *val)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", dir, file);
    if (n < 0 || n >= (int) sizeof path) { errno = ENAMETOOLONG; return -1; }
    /* A failure here (ENOENT = controller not delegated, EACCES = no
     * delegation) is reported honestly: a requested limit that cannot be
     * enforced must NOT look like success. Callers that treat cgroups as
     * best-effort ignore the return; those that need the limit see the error. */
    return es_write_file(path, val, strlen(val));
}

/* Create base/esquema-<name> (supervisor) + /leaf, enable controllers on the
 * supervisor, write limits to the leaf, and move `pid` into the leaf. */
int es_cgroup_setup(const struct esquema_config *cfg, pid_t pid,
                    char *created_path, size_t len)
{
    if (created_path && len) created_path[0] = '\0';
    if (!cfg->cgroup_name || !name_ok(cfg->cgroup_name)) {
        errno = EINVAL; return -1;
    }

    char base[PATH_MAX];
    if (cgroup_base(base, sizeof base) < 0) return -1;

    char super[PATH_MAX], leaf[PATH_MAX], buf[64];
    int n = snprintf(super, sizeof super, "%s/esquema-%s", base, cfg->cgroup_name);
    if (n < 0 || n >= (int) sizeof super) { errno = ENAMETOOLONG; return -1; }
    n = snprintf(leaf, sizeof leaf, "%s/leaf", super);
    if (n < 0 || n >= (int) sizeof leaf) { errno = ENAMETOOLONG; return -1; }

    if (mkdir(super, 0755) < 0 && errno != EEXIST) return -1;
    if (mkdir(leaf, 0755) < 0 && errno != EEXIST) return -1;
    if (created_path && len)
        snprintf(created_path, len, "%s", super);

    /* Enable controllers on the supervisor while it holds no processes. */
    (void) write_limit(super, "cgroup.subtree_control", "+memory +pids +cpu");

    if (cfg->memory_max > 0) {
        snprintf(buf, sizeof buf, "%ld", cfg->memory_max);
        if (write_limit(leaf, "memory.max", buf) < 0) return -1;
    }
    if (cfg->pids_max > 0) {
        snprintf(buf, sizeof buf, "%ld", cfg->pids_max);
        if (write_limit(leaf, "pids.max", buf) < 0) return -1;
    }
    if (cfg->cpu_quota_us > 0) {
        snprintf(buf, sizeof buf, "%ld %ld", cfg->cpu_quota_us, cfg->cpu_period_us);
        if (write_limit(leaf, "cpu.max", buf) < 0) return -1;
    }

    snprintf(buf, sizeof buf, "%ld", (long) pid);
    if (write_limit(leaf, "cgroup.procs", buf) < 0) return -1;
    return 0;
}

void es_cgroup_cleanup(const char *created_path)
{
    if (!created_path || !created_path[0]) return;
    char leaf[PATH_MAX];
    if (snprintf(leaf, sizeof leaf, "%s/leaf", created_path) < (int) sizeof leaf)
        rmdir(leaf);          /* best-effort; fails EBUSY while procs remain */
    rmdir(created_path);
}

/* ---- public standalone entry (hardened replacement) ------------------ */
int esquema_enter_cgroup(const char *name)
{
    if (!name_ok(name)) { errno = EINVAL; return es_fail("cgroup: bad name"); }

    char base[PATH_MAX], dir[PATH_MAX], buf[64];
    if (cgroup_base(base, sizeof base) < 0)
        return es_fail("cgroup: base");
    int n = snprintf(dir, sizeof dir, "%s/esquema-%s", base, name);
    if (n < 0 || n >= (int) sizeof dir) { errno = ENAMETOOLONG; return es_fail("cgroup: path"); }
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) return es_fail("cgroup: mkdir");

    n = snprintf(buf, sizeof buf, "%ld", (long) getpid());
    if (n < 0 || n >= (int) sizeof buf) { errno = ENAMETOOLONG; return es_fail("cgroup: pid"); }
    if (write_limit(dir, "cgroup.procs", buf) < 0) return es_fail("cgroup: enter");
    return 0;
}
