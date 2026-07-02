/* jail.c — namespace, uid/gid-map and capability/privilege primitives.
 *
 * The functions used on the post-fork child path (es_write_id_maps,
 * es_drop_all_caps) are written with raw syscalls / prctl only, so they are
 * async-signal-safe and never allocate. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/securebits.h>

/* Allowed unshare flags for the public granular primitive. */
#define ES_CLONE_ALLOWED \
    (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | \
     CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWCGROUP)

int es_write_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) { errno = EIO; return -1; }
        p += w;
        n -= (size_t) w;
    }
    return 0;
}

int es_write_file(const char *path, const char *content, size_t len)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = es_write_all(fd, content, len);
    int e = errno;
    close(fd);
    if (rc < 0) { errno = e; return -1; }
    return 0;
}

/* Read the running kernel's highest capability number (do not trust the
 * compile-time CAP_LAST_CAP macro against a newer/older kernel). */
static int read_cap_last_cap(void)
{
    int v = CAP_LAST_CAP;
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char b[16];
        ssize_t n = read(fd, b, sizeof b - 1);
        if (n > 0) { b[n] = '\0'; v = (int) strtol(b, NULL, 10); }
        close(fd);
    }
    return v;
}

/* ---- public granular API --------------------------------------------- */

int esquema_unshare(int flags)
{
    unsigned int uf = (unsigned int) flags;
    if (uf & ~((unsigned int) ES_CLONE_ALLOWED)) {
        errno = EINVAL;
        return es_fail("unshare: disallowed flag");
    }
    if (unshare((int) uf) < 0) return es_fail("unshare");
    return 0;
}

int esquema_no_new_privs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return es_fail("no_new_privs");
    return 0;
}

/* ---- id maps (parent- or self-side) ---------------------------------- */

int es_write_id_maps(pid_t pid, unsigned int uid, unsigned int gid)
{
    char sg[64], up[64], gp[64], buf[64];
    if (pid == 0) {
        snprintf(sg, sizeof sg, "/proc/self/setgroups");
        snprintf(up, sizeof up, "/proc/self/uid_map");
        snprintf(gp, sizeof gp, "/proc/self/gid_map");
    } else {
        snprintf(sg, sizeof sg, "/proc/%ld/setgroups", (long) pid);
        snprintf(up, sizeof up, "/proc/%ld/uid_map", (long) pid);
        snprintf(gp, sizeof gp, "/proc/%ld/gid_map", (long) pid);
    }

    /* setgroups=deny is mandatory before an unprivileged gid_map write
     * (CVE-2014-8989). Tolerate ENOENT on ancient kernels only. */
    if (es_write_file(sg, "deny", 4) < 0 && errno != ENOENT)
        return -1;

    int n = snprintf(buf, sizeof buf, "0 %u 1\n", uid);
    if (n < 0 || n >= (int) sizeof buf) { errno = ENAMETOOLONG; return -1; }
    if (es_write_file(up, buf, (size_t) n) < 0) return -1;

    n = snprintf(buf, sizeof buf, "0 %u 1\n", gid);
    if (n < 0 || n >= (int) sizeof buf) { errno = ENAMETOOLONG; return -1; }
    if (es_write_file(gp, buf, (size_t) n) < 0) return -1;

    return 0;
}

/* ---- capability / privilege drop ------------------------------------- */

/* Zero the effective, permitted and inheritable capability sets via the
 * raw capset syscall (no libcap allocation on the child path). */
static int capset_clear(void)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
    };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    return (int) syscall(SYS_capset, &hdr, data);
}

int es_drop_all_caps(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;

    /* SECBIT_NOROOT neutralises the "uid 0 gets all caps" magic so that
     * being root-in-userns confers nothing; lock the bits irreversibly. */
    unsigned long secure =
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
        SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |
        SECBIT_KEEP_CAPS_LOCKED;
    if (prctl(PR_SET_SECUREBITS, secure, 0, 0, 0) < 0) return -1;

    /* Ambient caps survive a plain execve; clear them (best-effort: the
     * securebits above already forbid raising them). */
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    int last = read_cap_last_cap();
    for (int c = 0; c <= last; c++)
        prctl(PR_CAPBSET_DROP, c, 0, 0, 0);   /* EINVAL for gaps is fine */

    if (capset_clear() < 0) return -1;
    return 0;
}

int esquema_drop_caps(void)
{
    if (es_drop_all_caps() < 0) return es_fail("drop_caps");
    return 0;
}
