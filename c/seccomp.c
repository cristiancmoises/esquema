/* seccomp.c — hardened seccomp-BPF allowlist.
 *
 * Model: default action SCMP_ACT_ERRNO(ENOSYS) so libc feature-probes fall
 * back gracefully; an explicit SCMP_ACT_KILL_PROCESS deny-set for the
 * dangerous syscalls (defence in depth, unit-tested); a broad-but-safe
 * allow-set that lets a real dynamically-linked program run. Non-native
 * architectures (incl. the x32 ABI) are killed via SCMP_FLTATR_ACT_BADARCH.
 *
 * The filter is compiled once in the (multi-threaded) parent and applied in
 * the child via a raw prctl(PR_SET_SECCOMP) so the child never allocates. */
#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <seccomp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

/* Syscalls upgraded to hard kill even if a future allow-set edit slips. */
static const char *const DENY[] = {
    "ptrace", "process_vm_readv", "process_vm_writev", "process_madvise",
    "keyctl", "add_key", "request_key",
    "mount", "umount2", "pivot_root", "chroot", "move_mount",
    "open_tree", "fsopen", "fsconfig", "fsmount", "fspick",
    "setns", "unshare", "bpf", "perf_event_open",
    "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load", "reboot",
    "swapon", "swapoff", "iopl", "ioperm",
    "userfaultfd", "open_by_handle_at", "name_to_handle_at",
    "quotactl", "acct", "settimeofday", "clock_settime",
    "clock_adjtime", "adjtimex", NULL
};

/* Runnable minimum for a static or dynamic binary plus in-namespace
 * networking (the network namespace already isolates all sockets). */
static const char *const ALLOW[] = {
    /* process / thread (clone handled separately with a flag mask) */
    "execve", "execveat", "exit", "exit_group", "wait4", "waitid",
    "vfork", "set_tid_address", "set_robust_list",
    "get_robust_list", "rseq", "gettid", "getpid", "getppid", "tgkill",
    "kill", "sched_yield", "sched_getaffinity", "sched_setaffinity",
    "getcpu", "getpgrp", "getpgid", "setpgid", "getsid", "setsid",
    "getpriority", "setpriority", "prctl",
    /* memory */
    "brk", "mmap", "munmap", "mremap", "mprotect", "madvise", "msync",
    "mlock", "munlock", "mincore",
    /* signals */
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
    "rt_sigtimedwait", "rt_sigpending", "rt_sigsuspend", "rt_sigqueueinfo",
    "signalfd4", "restart_syscall",
    /* file / io */
    "read", "write", "pread64", "pwrite64", "readv", "writev", "preadv",
    "pwritev", "preadv2", "pwritev2", "lseek", "open", "openat", "openat2",
    "close", "close_range", "creat", "dup", "dup2", "dup3", "fcntl",
    "flock", "fsync", "fdatasync", "ftruncate", "truncate", "fallocate",
    "stat", "fstat", "lstat", "newfstatat", "statx", "fstatfs", "statfs",
    "getdents", "getdents64", "getcwd", "chdir", "fchdir", "readlink",
    "readlinkat", "access", "faccessat", "faccessat2", "umask",
    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "link", "linkat", "symlink", "symlinkat",
    "chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat",
    "utime", "utimes", "futimesat", "utimensat",
    "poll", "ppoll", "select", "pselect6", "epoll_create", "epoll_create1",
    "epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
    "eventfd", "eventfd2", "pipe", "pipe2", "splice", "tee", "vmsplice",
    "sendfile", "copy_file_range", "ioctl", "fadvise64",
    "inotify_init1", "inotify_add_watch", "inotify_rm_watch", "memfd_create",
    /* network (confined to the container's own net namespace) */
    "socket", "socketpair", "bind", "listen", "accept", "accept4",
    "connect", "getsockname", "getpeername", "getsockopt", "setsockopt",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "shutdown",
    /* time / rng / info */
    "clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep",
    "gettimeofday", "getrandom", "uname", "sysinfo", "getrusage",
    "times", "getrlimit", "setrlimit", "prlimit64",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "timer_create", "timer_settime", "timer_gettime", "timer_delete",
    /* identity (in-namespace only) */
    "getuid", "geteuid", "getgid", "getegid", "getgroups", "setgroups",
    "getresuid", "getresgid", "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "setfsuid", "setfsgid",
    /* misc runtime */
    "arch_prctl", "futex", "futex_waitv", "membarrier", "sync",
    "syncfs", "sync_file_range", NULL
};

/* Populate ctx with the deny-set, allow-set and BADARCH policy. */
static int build_main_rules(scmp_filter_ctx ctx)
{
    int rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH,
                              SCMP_ACT_KILL_PROCESS);
    if (rc < 0) { errno = -rc; return -1; }

    for (int i = 0; DENY[i]; i++) {
        int s = seccomp_syscall_resolve_name(DENY[i]);
        if (s == __NR_SCMP_ERROR) continue;
        rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, s, 0);
        if (rc < 0) { errno = -rc; return -1; }
    }
    for (int i = 0; ALLOW[i]; i++) {
        int s = seccomp_syscall_resolve_name(ALLOW[i]);
        if (s == __NR_SCMP_ERROR) continue;
        rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, s, 0);
        /* EEXIST: name already covered by an alias — not fatal. */
        if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    }

    /* clone: permit fork()/pthread_create() but NOT namespace creation or
     * capability re-gain — allow only when no CLONE_NEW* flag is set (arg0).
     * clone3() takes a pointer seccomp cannot inspect, so it is left to the
     * ENOSYS default, which makes glibc fall back to clone(). */
    {
        int cl = seccomp_syscall_resolve_name("clone");
        if (cl != __NR_SCMP_ERROR) {
            unsigned long ns_flags =
                CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS |
                CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWCGROUP;
            rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, cl, 1,
                                  SCMP_A0(SCMP_CMP_MASKED_EQ, ns_flags, 0));
            if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
        }
    }

    return 0;
}

/* Second, stacked filter: default ALLOW, but KILL the terminal-injection
 * ioctls TIOCSTI/TIOCLINUX. A single filter cannot express "allow ioctl
 * except TIOCSTI" (an unconditional ALLOW shadows any conditional rule for
 * the same syscall), so this is loaded as a separate filter — seccomp takes
 * the most restrictive action across all loaded filters, so KILL wins for
 * those requests while everything else is decided by the main filter. Loaded
 * BEFORE the main filter so its own PR_SET_SECCOMP call is still permitted. */
static int build_tty_rules(scmp_filter_ctx ctx)
{
    int io = seccomp_syscall_resolve_name("ioctl");
    if (io == __NR_SCMP_ERROR) return 0;
    struct scmp_arg_cmp a_sti = {
        .arg = 1, .op = SCMP_CMP_EQ, .datum_a = (scmp_datum_t) TIOCSTI, .datum_b = 0
    };
    struct scmp_arg_cmp a_lin = {
        .arg = 1, .op = SCMP_CMP_EQ, .datum_a = (scmp_datum_t) TIOCLINUX, .datum_b = 0
    };
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, io, 1, a_sti);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, io, 1, a_lin);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    return 0;
}

/* Export a built context to a malloc'd sock_fprog (so the child can apply it
 * with a raw prctl, allocation-free). */
static int export_ctx(scmp_filter_ctx ctx, struct sock_fprog *out)
{
    int fd = (int) syscall(__NR_memfd_create, "es-bpf", (unsigned) MFD_CLOEXEC);
    if (fd < 0) return es_fail("seccomp: memfd");

    int rc = seccomp_export_bpf(ctx, fd);
    if (rc < 0) { close(fd); errno = -rc; return es_fail("seccomp: export"); }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0 || (size_t) sz % sizeof(struct sock_filter) != 0) {
        close(fd); errno = EIO; return es_fail("seccomp: size");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) { close(fd); return es_fail("seccomp: lseek"); }

    char *buf = malloc((size_t) sz);
    if (!buf) { close(fd); errno = ENOMEM; return es_fail("seccomp: malloc"); }

    ssize_t got = 0;
    while (got < sz) {
        ssize_t r = read(fd, buf + got, (size_t) (sz - got));
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return es_fail("seccomp: read"); }
        if (r == 0) break;
        got += r;
    }
    close(fd);
    if (got != sz) { free(buf); errno = EIO; return es_fail("seccomp: short read"); }

    out->len    = (unsigned short) ((size_t) sz / sizeof(struct sock_filter));
    out->filter = (struct sock_filter *) buf;
    return 0;
}

/* Load a context onto the current thread. */
static int load_ctx(scmp_filter_ctx ctx)
{
    int rc = seccomp_load(ctx);
    if (rc < 0) { errno = -rc; return -1; }
    return 0;
}

/* ---- apply directly to the current thread (standalone / tests) ------- */
int esquema_apply_seccomp(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return es_fail("seccomp: no_new_privs");

    /* TTY-injection filter first (default ALLOW), then the main allowlist. */
    scmp_filter_ctx tty = seccomp_init(SCMP_ACT_ALLOW);
    if (!tty) { errno = ENOMEM; return es_fail("seccomp: init tty"); }
    if (build_tty_rules(tty) < 0 || load_ctx(tty) < 0) {
        seccomp_release(tty); return es_fail("seccomp: tty");
    }
    seccomp_release(tty);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
    if (!ctx) { errno = ENOMEM; return es_fail("seccomp: init"); }
    if (build_main_rules(ctx) < 0 || load_ctx(ctx) < 0) {
        seccomp_release(ctx); return es_fail("seccomp: main");
    }
    seccomp_release(ctx);
    return 0;
}

/* ---- compile in parent, apply in child ------------------------------- */
int es_seccomp_compile(struct sock_fprog *out)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
    if (!ctx) { errno = ENOMEM; return es_fail("seccomp: init"); }
    if (build_main_rules(ctx) < 0) { seccomp_release(ctx); return es_fail("seccomp: rules"); }
    int rc = export_ctx(ctx, out);
    seccomp_release(ctx);
    return rc;
}

int es_seccomp_compile_tty(struct sock_fprog *out)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { errno = ENOMEM; return es_fail("seccomp: init tty"); }
    if (build_tty_rules(ctx) < 0) { seccomp_release(ctx); return es_fail("seccomp: tty rules"); }
    int rc = export_ctx(ctx, out);
    seccomp_release(ctx);
    return rc;
}

void es_seccomp_free_program(struct sock_fprog *prog)
{
    if (prog) { free(prog->filter); prog->filter = NULL; prog->len = 0; }
}

int es_seccomp_apply_program(const struct sock_fprog *prog)
{
    /* Caller must have already set PR_SET_NO_NEW_PRIVS. */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog, 0, 0) < 0)
        return -1;
    return 0;
}
