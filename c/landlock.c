/* landlock.c — unprivileged filesystem confinement layered after pivot_root.
 *
 * The base policy grants the running application the kernel-supported
 * filesystem rights beneath the post-pivot root and handles those rights
 * everywhere else.  This is deliberately a "no new access outside this
 * root" invariant, not yet a per-path least-privilege policy. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

int esquema_landlock_abi(void)
{
#if defined(__NR_landlock_create_ruleset)
    int abi = (int) syscall(__NR_landlock_create_ruleset, NULL, 0,
                            LANDLOCK_CREATE_RULESET_VERSION);
    if (abi >= 0) return abi;
    if (errno == ENOSYS || errno == EOPNOTSUPP) return 0;
    return -1;
#else
    return 0;
#endif
}

static uint64_t handled_fs_access(int abi)
{
    uint64_t access =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
    return access;
}

int es_landlock_restrict_root(const char *path)
{
#if defined(__NR_landlock_create_ruleset) && \
    defined(__NR_landlock_add_rule) && defined(__NR_landlock_restrict_self)
    if (!path) { errno = EINVAL; return -1; }
    int abi = esquema_landlock_abi();
    if (abi <= 0) {
        if (abi == 0) errno = ENOSYS;
        return -1;
    }

    uint64_t access = handled_fs_access(abi);
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = access,
    };
    int ruleset_fd = (int) syscall(__NR_landlock_create_ruleset,
                                   &ruleset_attr, sizeof ruleset_attr, 0);
    if (ruleset_fd < 0) return -1;

    int root_fd = open(path, O_PATH | O_CLOEXEC);
    if (root_fd < 0) {
        int e = errno; close(ruleset_fd); errno = e; return -1;
    }
    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = access,
        .parent_fd = root_fd,
    };
    if (syscall(__NR_landlock_add_rule, ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0) {
        int e = errno; close(root_fd); close(ruleset_fd); errno = e; return -1;
    }
    close(root_fd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        int e = errno; close(ruleset_fd); errno = e; return -1;
    }
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
        int e = errno; close(ruleset_fd); errno = e; return -1;
    }
    close(ruleset_fd);
    return 0;
#else
    (void) path;
    errno = ENOSYS;
    return -1;
#endif
}
