/* fds.c — remove ambient descriptor capabilities before payload exec.
 *
 * File descriptors are capabilities.  A namespace boundary does not revoke
 * an already-open host file, directory, device, socket or agent connection,
 * so the payload gets only stdin/stdout/stderr and descriptors explicitly
 * registered with esquema_config_preserve_fd(). */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>

struct es_linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static int preserved(const struct esquema_config *cfg, int fd)
{
    if (!cfg) return 0;
    for (size_t i = 0; i < cfg->preserve_fds_n; i++) {
        if (cfg->preserve_fds[i] == fd) return 1;
        if (cfg->preserve_fds[i] > fd) break;
    }
    return 0;
}

/* Preserving a descriptor means preserving it through exec, even when the
 * broker opened it O_CLOEXEC.  Refuse a stale/reused closed fd. */
static int prepare_preserved(const struct esquema_config *cfg)
{
    if (!cfg) return 0;
    for (size_t i = 0; i < cfg->preserve_fds_n; i++) {
        int fd = cfg->preserve_fds[i];
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0) return -1;
        if ((flags & FD_CLOEXEC) && fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
            return -1;
    }
    return 0;
}

/* Return 0 when close_range completed, 1 when a fallback is needed. */
static int close_with_ranges(const struct esquema_config *cfg)
{
#ifdef __NR_close_range
    /* A harmless probe avoids partially closing the table before discovering
     * that the running kernel or outer seccomp policy lacks close_range. */
    if (syscall(__NR_close_range, UINT_MAX, UINT_MAX, 0U) < 0)
        return 1;

    unsigned int first = 3;
    if (cfg) {
        for (size_t i = 0; i < cfg->preserve_fds_n; i++) {
            unsigned int keep = (unsigned int) cfg->preserve_fds[i];
            if (keep > first &&
                syscall(__NR_close_range, first, keep - 1, 0U) < 0)
                return 1;
            if (keep >= first) first = keep + 1;
        }
    }
    if (syscall(__NR_close_range, first, UINT_MAX, 0U) < 0) return 1;
    return 0;
#else
    (void) cfg;
    return 1;
#endif
}

static int parse_fd(const char *s)
{
    unsigned int value = 0;
    if (!s || !s[0]) return -1;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        unsigned int digit = (unsigned int) (s[i] - '0');
        if (value > ((unsigned int) INT_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    return (int) value;
}

/* Raw getdents avoids allocation and stdio in the post-fork child. */
static int close_from_proc(const struct esquema_config *cfg)
{
#if defined(__NR_openat) && defined(__NR_getdents64)
    int dirfd = (int) syscall(__NR_openat, AT_FDCWD, "/proc/self/fd",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dirfd < 0) return -1;

    char buf[4096] __attribute__((aligned(8)));
    for (;;) {
        long nread = syscall(__NR_getdents64, dirfd, buf, sizeof buf);
        if (nread == 0) break;
        if (nread < 0) {
            if (errno == EINTR) continue;
            int e = errno; close(dirfd); errno = e; return -1;
        }
        long pos = 0;
        while (pos < nread) {
            struct es_linux_dirent64 *ent =
                (struct es_linux_dirent64 *) (void *) (buf + pos);
            size_t name_off = offsetof(struct es_linux_dirent64, d_name);
            if (ent->d_reclen <= name_off ||
                pos + ent->d_reclen > nread) {
                close(dirfd); errno = EIO; return -1;
            }
            if (!memchr(ent->d_name, '\0', ent->d_reclen - name_off)) {
                close(dirfd); errno = EIO; return -1;
            }
            int fd = parse_fd(ent->d_name);
            if (fd >= 3 && fd != dirfd && !preserved(cfg, fd)) close(fd);
            pos += ent->d_reclen;
        }
    }
    close(dirfd);
    return 0;
#else
    (void) cfg;
    errno = ENOSYS;
    return -1;
#endif
}

/* Last-resort fallback for a rootfs without procfs on an old kernel. */
static int close_by_limit(const struct esquema_config *cfg)
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_NOFILE, &lim) < 0) return -1;
    if (lim.rlim_cur == RLIM_INFINITY || lim.rlim_cur > (rlim_t) INT_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    for (int fd = 3; fd < (int) lim.rlim_cur; fd++)
        if (!preserved(cfg, fd)) close(fd);
    return 0;
}

int es_close_inherited_fds(const struct esquema_config *cfg)
{
    if (prepare_preserved(cfg) < 0) return -1;
    if (close_with_ranges(cfg) == 0) return 0;
    if (close_from_proc(cfg) == 0) return 0;
    return close_by_limit(cfg);
}
