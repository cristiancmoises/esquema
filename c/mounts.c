/* mounts.c — filesystem confinement for the payload child (PID 1).
 *
 * All functions here run post-fork in the payload child and use only
 * syscalls / async-signal-safe libc. The mount order is load-bearing:
 * make "/" private, bind the rootfs onto itself, mount a *fresh* /proc into
 * the new root BEFORE pivot_root (this avoids EPERM on hosts that mask parts
 * of the host /proc, e.g. Guix/systemd), apply binds, then pivot and detach
 * the old root so the host tree is unreachable. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/statvfs.h>
#include <net/if.h>
#include <linux/limits.h>

/* Bind minimal device nodes from the host into rootfs/dev before pivot,
 * while the host /dev is still reachable. Entirely best-effort. */
static void setup_dev(const char *root)
{
    char devdir[PATH_MAX];
    if (snprintf(devdir, sizeof devdir, "%s/dev", root) >= (int) sizeof devdir)
        return;
    mkdir(devdir, 0755);

    static const char *nodes[] = {
        "null", "zero", "full", "random", "urandom", "tty", NULL
    };
    for (int i = 0; nodes[i]; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        if (snprintf(src, sizeof src, "/dev/%s", nodes[i]) >= (int) sizeof src)
            continue;
        if (snprintf(dst, sizeof dst, "%s/dev/%s", root, nodes[i]) >= (int) sizeof dst)
            continue;
        int fd = open(dst, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) close(fd);
        mount(src, dst, NULL, MS_BIND, NULL);   /* best-effort */
    }
}

/* Legacy single-mount read-only remount. In a user namespace a bare
 * MS_REMOUNT|MS_RDONLY is rejected because it would clear the "locked"
 * nosuid/nodev/noexec flags the bind inherited; preserve them. statfs() is a
 * direct syscall (async-signal-safe), unlike statvfs()/getmntent(). Used only
 * as a fallback where mount_setattr() is unavailable. */
static int remount_ro_legacy(const char *dst)
{
    struct statfs sfs;
    unsigned long extra = 0;
    if (statfs(dst, &sfs) == 0) {
        if (sfs.f_flags & ST_NOSUID) extra |= MS_NOSUID;
        if (sfs.f_flags & ST_NODEV)  extra |= MS_NODEV;
        if (sfs.f_flags & ST_NOEXEC) extra |= MS_NOEXEC;
    }
    return mount(NULL, dst, NULL,
                 MS_BIND | MS_REMOUNT | MS_RDONLY | extra, NULL);
}

/* Make a subtree read-only *recursively*. A non-recursive remount would leave
 * nested submounts of a MS_REC bind (or of the rootfs) writable/executable —
 * the classic recursive-bind RO bypass. mount_setattr(AT_RECURSIVE) applies
 * read-only to the mount and every submount atomically, preserving locked
 * flags; fall back to the legacy per-mount remount only if unavailable. */
static int remount_ro(const char *dst)
{
#ifdef __NR_mount_setattr
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
    struct es_mount_attr {
        unsigned long long attr_set, attr_clr, propagation, userns_fd;
    } attr = { MOUNT_ATTR_RDONLY, 0, 0, 0 };
    if (syscall(__NR_mount_setattr, AT_FDCWD, dst, AT_RECURSIVE,
                &attr, sizeof attr) == 0)
        return 0;
    if (errno != ENOSYS && errno != EINVAL && errno != EPERM)
        return -1;
    /* else fall through to the legacy path */
#endif
    return remount_ro_legacy(dst);
}

static int apply_binds(const struct esquema_config *cfg)
{
    for (size_t i = 0; i < cfg->binds_n; i++) {
        char dst[PATH_MAX];
        int n = snprintf(dst, sizeof dst, "%s/%s",
                         cfg->rootfs, cfg->binds[i].dst);
        if (n < 0 || n >= (int) sizeof dst) { errno = ENAMETOOLONG; return -1; }
        if (mount(cfg->binds[i].src, dst, NULL, MS_BIND | MS_REC, NULL) < 0)
            return -1;
        if (cfg->binds[i].read_only && remount_ro(dst) < 0)
            return -1;
    }
    return 0;
}

int es_setup_mounts(const struct esquema_config *cfg)
{
    const char *root = cfg->rootfs;
    char path[PATH_MAX];

    /* 1. Stop mount events propagating back to the host mount namespace. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return -1;

    /* 2. Make the rootfs a mount point (required by pivot_root). */
    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) < 0) return -1;

    /* 3. Fresh /proc into the new root, before pivot (see file header). */
    if (cfg->ns_mask & ESQUEMA_NS_PID) {
        if (snprintf(path, sizeof path, "%s/proc", root) >= (int) sizeof path) {
            errno = ENAMETOOLONG; return -1;
        }
        mkdir(path, 0555);
        if (mount("proc", path, "proc",
                  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
            return -1;
    }

    /* 4. Minimal /dev and user binds (still with host visible). */
    setup_dev(root);
    if (apply_binds(cfg) < 0) return -1;

    /* 5. Pivot into the new root and detach the old one entirely. */
    if (chdir(root) < 0) return -1;
    if (syscall(SYS_pivot_root, ".", ".") < 0) return -1;
    if (umount2(".", MNT_DETACH) < 0) return -1;
    if (chdir("/") < 0) return -1;

    /* 6. Optionally seal the root read-only (preserving locked flags). */
    if (cfg->rootfs_ro && remount_ro("/") < 0)
        return -1;
    return 0;
}

int es_setup_loopback(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { int e = errno; close(fd); errno = e; return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    int e = errno;
    close(fd);
    if (rc < 0) { errno = e; return -1; }
    return 0;
}
