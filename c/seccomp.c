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
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <stdint.h>
#include <seccomp.h>
#include <sys/socket.h>
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
    "sendfile", "copy_file_range", "fadvise64",
    "inotify_init1", "inotify_add_watch", "inotify_rm_watch", "memfd_create",
    /* network (confined to the container's own net namespace) */
    "bind", "listen", "accept", "accept4", "connect", "getsockname",
    "getpeername", "getsockopt", "setsockopt",
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

void esquema_seccomp_policy_init(esquema_seccomp_policy *policy)
{
    if (!policy) return;
    memset(policy, 0, sizeof *policy);
    policy->version = ESQUEMA_SECCOMP_POLICY_VERSION;
    policy->size = sizeof *policy;
    policy->expected_arch = ESQUEMA_ARCH_NATIVE;
    policy->io_uring = ESQUEMA_IO_URING_DENY;
    policy->ioctl_policy = ESQUEMA_IOCTL_RESTRICTED;
    policy->socket_families =
        ESQUEMA_SOCKET_UNIX | ESQUEMA_SOCKET_INET | ESQUEMA_SOCKET_INET6;
}

static uint32_t native_policy_arch(void)
{
    uint32_t arch = seccomp_arch_native();
    if (arch == SCMP_ARCH_X86_64) return ESQUEMA_ARCH_X86_64;
    if (arch == SCMP_ARCH_AARCH64) return ESQUEMA_ARCH_AARCH64;
    return UINT32_MAX;
}

static int validate_policy_arch(const esquema_seccomp_policy *policy)
{
    if (!policy) return 0;                 /* compatibility policy */
    if (policy->version != ESQUEMA_SECCOMP_POLICY_VERSION ||
        policy->size != sizeof *policy) {
        errno = EINVAL; return -1;
    }
    uint32_t native = native_policy_arch();
    if (native == UINT32_MAX) { errno = EAFNOSUPPORT; return -1; }
    if (policy->expected_arch != ESQUEMA_ARCH_NATIVE &&
        policy->expected_arch != native) {
        errno = EPROTONOSUPPORT; return -1;
    }
    return 0;
}

static int add_allow_name(scmp_filter_ctx ctx, const char *name)
{
    int syscall_nr = seccomp_syscall_resolve_name(name);
    if (syscall_nr == __NR_SCMP_ERROR) return 0;
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    return 0;
}

static int add_kill_name(scmp_filter_ctx ctx, const char *name)
{
    int syscall_nr = seccomp_syscall_resolve_name(name);
    if (syscall_nr == __NR_SCMP_ERROR) return 0;
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, syscall_nr, 0);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    return 0;
}

static int add_socket_family(scmp_filter_ctx ctx, int syscall_nr, int family)
{
    if (syscall_nr == __NR_SCMP_ERROR) return 0;
    struct scmp_arg_cmp cmp = {
        .arg = 0,
        .op = SCMP_CMP_EQ,
        .datum_a = (scmp_datum_t) (unsigned int) family,
        .datum_b = 0
    };
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 1, cmp);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    return 0;
}

static int add_policy_sockets(scmp_filter_ctx ctx,
                              const esquema_seccomp_policy *policy)
{
    int socket_nr = seccomp_syscall_resolve_name("socket");
    int pair_nr = seccomp_syscall_resolve_name("socketpair");
    if (!policy) {
        if (add_allow_name(ctx, "socket") < 0 ||
            add_allow_name(ctx, "socketpair") < 0)
            return -1;
        return 0;
    }
    struct family_map { uint64_t bit; int family; } families[] = {
        { ESQUEMA_SOCKET_UNIX, AF_UNIX },
        { ESQUEMA_SOCKET_INET, AF_INET },
        { ESQUEMA_SOCKET_INET6, AF_INET6 },
        { ESQUEMA_SOCKET_NETLINK, AF_NETLINK },
#ifdef AF_VSOCK
        { ESQUEMA_SOCKET_VSOCK, AF_VSOCK },
#endif
    };
    for (size_t i = 0; i < sizeof families / sizeof families[0]; i++) {
        if (!(policy->socket_families & families[i].bit)) continue;
        if (add_socket_family(ctx, socket_nr, families[i].family) < 0)
            return -1;
        /* Linux only supports useful socketpair semantics for AF_UNIX among
         * the families exposed by this v1 policy. */
        if (families[i].family == AF_UNIX &&
            add_socket_family(ctx, pair_nr, AF_UNIX) < 0)
            return -1;
    }
    return 0;
}

static int add_policy_io_uring(scmp_filter_ctx ctx,
                               const esquema_seccomp_policy *policy)
{
    if (!policy) return 0;                  /* legacy ENOSYS default */
    static const char *const calls[] = {
        "io_uring_setup", "io_uring_enter", "io_uring_register", NULL
    };
    for (size_t i = 0; calls[i]; i++) {
        int rc = policy->io_uring == ESQUEMA_IO_URING_ALLOW
                 ? add_allow_name(ctx, calls[i])
                 : add_kill_name(ctx, calls[i]);
        if (rc < 0) return -1;
    }
    return 0;
}

static int add_ioctl_request(scmp_filter_ctx ctx, int syscall_nr,
                             unsigned long request)
{
    struct scmp_arg_cmp cmp = {
        .arg = 1,
        .op = SCMP_CMP_EQ,
        .datum_a = (scmp_datum_t) request,
        .datum_b = 0
    };
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 1, cmp);
    if (rc < 0 && rc != -EEXIST) { errno = -rc; return -1; }
    return 0;
}

static int add_policy_ioctls(scmp_filter_ctx ctx,
                             const esquema_seccomp_policy *policy)
{
    if (!policy || policy->ioctl_policy == ESQUEMA_IOCTL_LEGACY)
        return add_allow_name(ctx, "ioctl");
    if (policy->ioctl_policy == ESQUEMA_IOCTL_NONE) return 0;

    int ioctl_nr = seccomp_syscall_resolve_name("ioctl");
    if (ioctl_nr == __NR_SCMP_ERROR) return 0;
    static const unsigned long safe_requests[] = {
        FIOCLEX, FIONCLEX, FIONBIO, FIONREAD,
        TCGETS, TCSETS, TCSETSW, TCSETSF, TIOCGWINSZ, TIOCSWINSZ
    };
    for (size_t i = 0; i < sizeof safe_requests / sizeof safe_requests[0]; i++)
        if (add_ioctl_request(ctx, ioctl_nr, safe_requests[i]) < 0) return -1;
    return 0;
}

/* Populate ctx with the deny-set, allow-set and BADARCH policy. */
static int build_main_rules(scmp_filter_ctx ctx,
                            const esquema_seccomp_policy *policy)
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
    if (add_policy_sockets(ctx, policy) < 0 ||
        add_policy_io_uring(ctx, policy) < 0 ||
        add_policy_ioctls(ctx, policy) < 0)
        return -1;

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
    return esquema_apply_seccomp_policy(NULL);
}

int esquema_apply_seccomp_policy(const esquema_seccomp_policy *policy)
{
    if (validate_policy_arch(policy) < 0)
        return es_fail("seccomp: policy architecture");
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
    if (build_main_rules(ctx, policy) < 0 || load_ctx(ctx) < 0) {
        seccomp_release(ctx); return es_fail("seccomp: main");
    }
    seccomp_release(ctx);
    return 0;
}

/* ---- compile in parent, apply in child ------------------------------- */
int es_seccomp_compile(const esquema_seccomp_policy *policy,
                       struct sock_fprog *out)
{
    if (validate_policy_arch(policy) < 0)
        return es_fail("seccomp: policy architecture");
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
    if (!ctx) { errno = ENOMEM; return es_fail("seccomp: init"); }
    if (build_main_rules(ctx, policy) < 0) {
        seccomp_release(ctx); return es_fail("seccomp: rules");
    }
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
