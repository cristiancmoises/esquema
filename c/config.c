/* config.c — opaque container configuration builder. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *dup_str(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* Push a copy of `s` onto a NULL-terminated string vector, growing it. */
static int push_str(char ***arr, size_t *n, size_t *cap, const char *s)
{
    if (*n + 2 > *cap) {
        size_t ncap = *cap ? *cap * 2 : 8;
        char **na = realloc(*arr, ncap * sizeof(char *));
        if (!na) { errno = ENOMEM; return -1; }
        *arr = na;
        *cap = ncap;
    }
    char *d = dup_str(s);
    if (!d) { errno = ENOMEM; return -1; }
    (*arr)[(*n)++] = d;
    (*arr)[*n] = NULL;
    return 0;
}

static int set_field(char **field, const char *value)
{
    char *d = dup_str(value);
    if (value && !d) { errno = ENOMEM; return es_fail("config: dup"); }
    free(*field);
    *field = d;
    return 0;
}

esquema_config *esquema_config_new(void)
{
    esquema_config *c = calloc(1, sizeof *c);
    if (!c) { errno = ENOMEM; es_fail("config_new"); return NULL; }
    c->ns_mask       = ESQUEMA_NS_ALL;
    c->map_uid       = (unsigned int) getuid();
    c->map_gid       = (unsigned int) getgid();
    c->seccomp       = 1;
    c->drop_caps     = 1;
    c->rootfs_ro     = 0;
    c->strict        = 0;
    c->landlock      = 1;
    c->memory_max    = -1;
    c->pids_max      = -1;
    c->cpu_quota_us  = -1;
    c->cpu_period_us = 100000;
    return c;
}

void esquema_config_free(esquema_config *cfg)
{
    if (!cfg) return;
    free(cfg->rootfs);
    free(cfg->hostname);
    free(cfg->cgroup_name);
    for (size_t i = 0; i < cfg->argc; i++) free(cfg->argv[i]);
    free(cfg->argv);
    for (size_t i = 0; i < cfg->envc; i++) free(cfg->envp[i]);
    free(cfg->envp);
    for (size_t i = 0; i < cfg->binds_n; i++) {
        free(cfg->binds[i].src);
        free(cfg->binds[i].dst);
    }
    free(cfg->binds);
    free(cfg->preserve_fds);
    free(cfg);
}

int esquema_config_set_rootfs(esquema_config *cfg, const char *path)
{
    if (!cfg || !path) { errno = EINVAL; return es_fail("set_rootfs"); }
    return set_field(&cfg->rootfs, path);
}

int esquema_config_set_hostname(esquema_config *cfg, const char *name)
{
    if (!cfg || !name) { errno = EINVAL; return es_fail("set_hostname"); }
    return set_field(&cfg->hostname, name);
}

int esquema_config_add_arg(esquema_config *cfg, const char *arg)
{
    if (!cfg || !arg) { errno = EINVAL; return es_fail("add_arg"); }
    if (push_str(&cfg->argv, &cfg->argc, &cfg->argv_cap, arg) < 0)
        return es_fail("add_arg");
    return 0;
}

int esquema_config_add_env(esquema_config *cfg, const char *keyval)
{
    if (!cfg || !keyval) { errno = EINVAL; return es_fail("add_env"); }
    if (push_str(&cfg->envp, &cfg->envc, &cfg->envp_cap, keyval) < 0)
        return es_fail("add_env");
    return 0;
}

int esquema_config_add_bind(esquema_config *cfg, const char *src,
                            const char *dst, int read_only)
{
    if (!cfg || !src || !dst) { errno = EINVAL; return es_fail("add_bind"); }
    if (cfg->binds_n + 1 > cfg->binds_cap) {
        size_t ncap = cfg->binds_cap ? cfg->binds_cap * 2 : 4;
        struct esquema_bind *nb = realloc(cfg->binds, ncap * sizeof *nb);
        if (!nb) { errno = ENOMEM; return es_fail("add_bind"); }
        cfg->binds = nb;
        cfg->binds_cap = ncap;
    }
    char *s = dup_str(src), *d = dup_str(dst);
    if (!s || !d) { free(s); free(d); errno = ENOMEM; return es_fail("add_bind"); }
    cfg->binds[cfg->binds_n].src = s;
    cfg->binds[cfg->binds_n].dst = d;
    cfg->binds[cfg->binds_n].read_only = read_only;
    cfg->binds_n++;
    return 0;
}

int esquema_config_preserve_fd(esquema_config *cfg, int fd)
{
    if (!cfg || fd < 3) { errno = EINVAL; return es_fail("preserve_fd"); }
    if (fcntl(fd, F_GETFD) < 0) return es_fail("preserve_fd: not open");

    size_t pos = 0;
    while (pos < cfg->preserve_fds_n && cfg->preserve_fds[pos] < fd) pos++;
    if (pos < cfg->preserve_fds_n && cfg->preserve_fds[pos] == fd) return 0;
    if (cfg->preserve_fds_n >= 64) {
        errno = E2BIG; return es_fail("preserve_fd: too many");
    }
    if (cfg->preserve_fds_n + 1 > cfg->preserve_fds_cap) {
        size_t ncap = cfg->preserve_fds_cap ? cfg->preserve_fds_cap * 2 : 4;
        int *nf = realloc(cfg->preserve_fds, ncap * sizeof *nf);
        if (!nf) { errno = ENOMEM; return es_fail("preserve_fd"); }
        cfg->preserve_fds = nf;
        cfg->preserve_fds_cap = ncap;
    }
    memmove(&cfg->preserve_fds[pos + 1], &cfg->preserve_fds[pos],
            (cfg->preserve_fds_n - pos) * sizeof *cfg->preserve_fds);
    cfg->preserve_fds[pos] = fd;
    cfg->preserve_fds_n++;
    return 0;
}

void esquema_config_set_namespaces(esquema_config *cfg, unsigned int ns_mask)
{
    if (cfg) cfg->ns_mask = ns_mask & ESQUEMA_NS_ALL;
}

void esquema_config_set_id_map(esquema_config *cfg, unsigned int uid,
                               unsigned int gid)
{
    if (cfg) { cfg->map_uid = uid; cfg->map_gid = gid; }
}

void esquema_config_set_seccomp(esquema_config *cfg, int enable)
{
    if (cfg) cfg->seccomp = enable ? 1 : 0;
}

void esquema_config_set_drop_caps(esquema_config *cfg, int enable)
{
    if (cfg) cfg->drop_caps = enable ? 1 : 0;
}

void esquema_config_set_rootfs_ro(esquema_config *cfg, int read_only)
{
    if (cfg) cfg->rootfs_ro = read_only ? 1 : 0;
}

void esquema_config_set_strict(esquema_config *cfg, int enable)
{
    if (cfg) cfg->strict = enable ? 1 : 0;
}

void esquema_config_set_landlock(esquema_config *cfg, int enable)
{
    if (cfg) cfg->landlock = enable ? 1 : 0;
}

void esquema_config_set_memory_max(esquema_config *cfg, long bytes)
{
    if (cfg) cfg->memory_max = bytes;
}

void esquema_config_set_pids_max(esquema_config *cfg, long count)
{
    if (cfg) cfg->pids_max = count;
}

void esquema_config_set_cpu_max(esquema_config *cfg, long quota_us,
                                long period_us)
{
    if (cfg) {
        cfg->cpu_quota_us  = quota_us;
        cfg->cpu_period_us = period_us > 0 ? period_us : 100000;
    }
}

int esquema_config_set_cgroup_name(esquema_config *cfg, const char *name)
{
    if (!cfg || !name) { errno = EINVAL; return es_fail("set_cgroup_name"); }
    return set_field(&cfg->cgroup_name, name);
}
