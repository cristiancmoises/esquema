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
#include <linux/openat2.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

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
 * flags.
 *
 * Strict/Fortress callers pass allow_legacy == 0.  For them, any
 * mount_setattr failure is returned unchanged: a successful single-mount
 * remount is not evidence that the subtree is sealed.  Compatibility callers
 * may explicitly retain the old single-mount fallback on kernels that cannot
 * perform the recursive operation. */
int es_mount_seal_read_only(const char *dst, int allow_legacy)
{
    if (!dst || dst[0] == '\0') { errno = EINVAL; return -1; }
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
                &attr, sizeof attr) == 0) {
        struct statfs sfs;
        if (statfs(dst, &sfs) < 0) return -1;
        if (!(sfs.f_flags & ST_RDONLY)) { errno = EIO; return -1; }
        return 0;
    }
    if (!allow_legacy)
        return -1;
    if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP &&
        errno != EPERM)
        return -1;
#else
    if (!allow_legacy) { errno = ENOSYS; return -1; }
#endif
    return remount_ro_legacy(dst);
}

/* Race-safe fallback for kernels without openat2: pin every component with
 * O_PATH|O_NOFOLLOW and reject a symlink final component explicitly. */
static int open_beneath_walk(int rootfd, const char *path)
{
    int current = fcntl(rootfd, F_DUPFD_CLOEXEC, 3);
    if (current < 0) return -1;
    const char *segment = path;
    for (;;) {
        const char *slash = strchr(segment, '/');
        size_t len = slash ? (size_t) (slash - segment) : strlen(segment);
        if (len == 0 || len > NAME_MAX) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, segment, len);
        name[len] = '\0';
        int flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
        if (slash) flags |= O_DIRECTORY;
        int next = openat(current, name, flags);
        int e = errno;
        close(current);
        if (next < 0) { errno = e; return -1; }
        if (!slash) {
            struct stat st;
            if (fstat(next, &st) < 0) {
                e = errno; close(next); errno = e; return -1;
            }
            if (S_ISLNK(st.st_mode)) {
                close(next); errno = ELOOP; return -1;
            }
            return next;
        }
        current = next;
        segment = slash + 1;
    }
}

static int open_beneath(int rootfd, const char *path)
{
#ifdef __NR_openat2
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS,
    };
    int fd = (int) syscall(__NR_openat2, rootfd, path, &how, sizeof how);
    if (fd >= 0) return fd;
    if (errno != ENOSYS && errno != EINVAL && errno != E2BIG) return -1;
#endif
    return open_beneath_walk(rootfd, path);
}

/* Clone a source mount and attach it to an already-open destination.  Empty
 * path semantics keep both endpoints fd-bound; no /proc magiclink or pathname
 * is resolved during the attach.  A read-only request is applied to the
 * detached tree before it becomes visible, avoiding a writable race window. */
static int attach_bind_fd(int srcfd, int dstfd, int source_is_dir,
                          int read_only)
{
#if defined(__NR_open_tree) && defined(__NR_move_mount)
    unsigned int open_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
                              AT_EMPTY_PATH;
    if (source_is_dir) open_flags |= AT_RECURSIVE;
    int treefd = (int) syscall(__NR_open_tree, srcfd, "", open_flags);
    if (treefd < 0) return -1;

    if (read_only) {
#ifdef __NR_mount_setattr
        struct es_mount_attr {
            unsigned long long attr_set, attr_clr, propagation, userns_fd;
        } attr = { MOUNT_ATTR_RDONLY, 0, 0, 0 };
        unsigned int attr_flags = AT_EMPTY_PATH;
        if (source_is_dir) attr_flags |= AT_RECURSIVE;
        if (syscall(__NR_mount_setattr, treefd, "", attr_flags,
                    &attr, sizeof attr) < 0) {
            int e = errno; close(treefd); errno = e; return -1;
        }
#else
        close(treefd); errno = ENOSYS; return -1;
#endif
    }

    /* The source is a detached O_PATH mount and therefore needs empty-path
     * semantics.  For a directory destination, resolving "." relative to its
     * pinned O_PATH descriptor is equally race-free and works on kernels that
     * expose but reject MOVE_MOUNT_T_EMPTY_PATH for attachment targets. */
    const char *target_path = source_is_dir ? "." : "";
    unsigned int move_flags = MOVE_MOUNT_F_EMPTY_PATH;
    if (!source_is_dir) move_flags |= MOVE_MOUNT_T_EMPTY_PATH;
    if (syscall(__NR_move_mount, treefd, "", dstfd, target_path,
                move_flags) < 0) {
        int e = errno; close(treefd); errno = e; return -1;
    }
    close(treefd);
    return 0;
#else
    (void) srcfd; (void) dstfd; (void) source_is_dir; (void) read_only;
    errno = ENOSYS;
    return -1;
#endif
}

/* Compatibility fallback for kernels lacking the fd-based mount API.  The
 * destination was already validated and pinned by open_beneath(), but mount(2)
 * itself still consumes a pathname.  Fortress therefore never uses this
 * fallback; legacy callers retain old-kernel functionality explicitly. */
static int attach_bind_legacy(const struct esquema_config *cfg, size_t index,
                              int dstfd)
{
    char dst[PATH_MAX];
    int n = snprintf(dst, sizeof dst, "%s/%s", cfg->rootfs,
                     cfg->binds[index].dst);
    if (n < 0 || n >= (int) sizeof dst) { errno = ENAMETOOLONG; return -1; }

    struct stat pinned, current;
    if (fstat(dstfd, &pinned) < 0 || lstat(dst, &current) < 0) return -1;
    if (S_ISLNK(current.st_mode) || pinned.st_dev != current.st_dev ||
        pinned.st_ino != current.st_ino) {
        errno = ESTALE; return -1;
    }
    if (mount(cfg->binds[index].src, dst, NULL, MS_BIND | MS_REC, NULL) < 0)
        return -1;
    if (cfg->binds[index].read_only &&
        es_mount_seal_read_only(dst, 1) < 0)
        return -1;
    return 0;
}

static int apply_binds(const struct esquema_config *cfg, int rootfd)
{
    for (size_t i = 0; i < cfg->binds_n; i++) {
        int srcfd = open(cfg->binds[i].src, O_PATH | O_CLOEXEC);
        if (srcfd < 0) return -1;
        struct stat source;
        if (fstat(srcfd, &source) < 0) {
            int e = errno; close(srcfd); errno = e; return -1;
        }
        int dstfd = open_beneath(rootfd, cfg->binds[i].dst);
        if (dstfd < 0) { int e = errno; close(srcfd); errno = e; return -1; }

        int rc = attach_bind_fd(srcfd, dstfd, S_ISDIR(source.st_mode),
                                cfg->binds[i].read_only);
        if (rc < 0 && !cfg->strict)
            rc = attach_bind_legacy(cfg, i, dstfd);
        if (rc < 0) {
            int e = errno; close(srcfd); close(dstfd); errno = e; return -1;
        }
        close(srcfd);
        close(dstfd);
    }
    return 0;
}

int es_setup_mounts(const struct esquema_config *cfg, int rootfs_fd)
{
    if (rootfs_fd < 0) { errno = EINVAL; return -1; }
    const char *root = cfg->rootfs;
    char path[PATH_MAX];

    /* Linux rejects a bind mount whose target is a procfs O_PATH magiclink.
     * Retain the canonical root pathname for pivot_root, but prove immediately
     * before mounting that it still resolves to the directory pinned by the
     * parent.  User bind destinations below never use this pathname: they are
     * resolved beneath rootfs_fd with openat2/fd walking. */
    struct stat pinned, current;
    if (fstat(rootfs_fd, &pinned) < 0 || stat(root, &current) < 0) return -1;
    if (pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino) {
        errno = ESTALE; return -1;
    }

    /* 1. Stop mount events propagating back to the host mount namespace. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return -1;

    /* 2. Make the rootfs a mount point (required by pivot_root). */
    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) < 0) return -1;

    /* The descriptor inherited from the parent pins the directory but refers
     * to its pre-bind mount.  Reopen it after the self-bind so fd-based
     * move_mount attaches user binds to the mount that will become `/`. */
    int mounted_rootfd = open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW |
                              O_CLOEXEC);
    if (mounted_rootfd < 0) return -1;
    struct stat mounted;
    if (fstat(mounted_rootfd, &mounted) < 0) {
        int e = errno; close(mounted_rootfd); errno = e; return -1;
    }
    if (mounted.st_dev != pinned.st_dev || mounted.st_ino != pinned.st_ino) {
        close(mounted_rootfd); errno = ESTALE; return -1;
    }

    /* 3. Fresh /proc into the new root, before pivot (see file header). */
    if (cfg->ns_mask & ESQUEMA_NS_PID) {
        if (snprintf(path, sizeof path, "%s/proc", root) >= (int) sizeof path) {
            close(mounted_rootfd); errno = ENAMETOOLONG; return -1;
        }
        mkdir(path, 0555);
        if (mount("proc", path, "proc",
                  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
            int e = errno; close(mounted_rootfd); errno = e;
            return -1;
        }
    }

    /* 4. Minimal /dev and user binds (still with host visible). */
    setup_dev(root);
    if (apply_binds(cfg, mounted_rootfd) < 0) {
        int e = errno; close(mounted_rootfd); errno = e; return -1;
    }
    close(mounted_rootfd);

    /* 5. Pivot into the new root and detach the old one entirely. */
    if (chdir(root) < 0) return -1;
    if (syscall(SYS_pivot_root, ".", ".") < 0) return -1;
    if (umount2(".", MNT_DETACH) < 0) return -1;
    if (chdir("/") < 0) return -1;

    /* 6. Optionally seal the root read-only (preserving locked flags). */
    if (cfg->rootfs_ro &&
        es_mount_seal_read_only("/", cfg->strict ? 0 : 1) < 0)
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
