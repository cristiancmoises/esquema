/* test_primitives.c — C-level unit tests for the Esquema hardening
 * primitives that are awkward to exercise from Scheme: seccomp actually
 * KILLing a denied syscall with SIGSYS, the capability drop emptying the
 * cap sets, and the input validation on the granular API.
 *
 * Build: gcc -I c test_primitives.c -L. -lesquema  (run with LD_LIBRARY_PATH=.)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "internal.h"

static int failures = 0;
static void check(const char *name, int ok)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

/* Run `child` in a fork; return the raw wait status. */
static int run_child(void (*child)(void))
{
    pid_t p = fork();
    if (p == 0) { child(); _exit(0); }
    int st = 0;
    while (waitpid(p, &st, 0) < 0 && errno == EINTR) { }
    return st;
}

/* Benign payload: applies seccomp, does allowed work, exits 0. */
static void child_allowed(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    const char msg[] = "x";
    if (write(2, msg, 0) < 0) { /* allowed */ }
    _exit(0);
}

/* Applies seccomp then invokes a DENIED syscall (unshare) — must SIGSYS. */
static void child_denied_unshare(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    syscall(SYS_unshare, 0);       /* deny-set -> SCMP_ACT_KILL_PROCESS */
    _exit(0);                      /* reached only if NOT killed */
}

/* Applies seccomp then attempts ptrace — must SIGSYS. */
static void child_denied_ptrace(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    syscall(SYS_ptrace, 0, 0, 0, 0);
    _exit(0);
}

/* clone() to create a nested user namespace must be refused (ENOSYS) by the
 * flag-masked allow rule, while ordinary fork()-style clone still works. */
static void child_clone_newuser_blocked(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    long rc = syscall(SYS_clone, (unsigned long)(CLONE_NEWUSER | SIGCHLD),
                      (void *) 0, (void *) 0, (void *) 0, (unsigned long) 0);
    if (rc == 0) _exit(0);                        /* unexpected child: bail */
    if (rc == -1 && errno == ENOSYS) _exit(0);    /* correctly blocked */
    _exit(80);                                    /* leaked through! */
}

/* ioctl(TIOCSTI) — terminal injection — must be killed by SIGSYS. */
static void child_tiocsti_blocked(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    char c = 'x';
    ioctl(0, TIOCSTI, &c);   /* killed before the syscall executes */
    _exit(0);
}

/* An ordinary fork must still succeed under the filter. */
static void child_fork_allowed(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    pid_t p = fork();
    if (p == 0) _exit(0);
    if (p < 0) _exit(81);
    int st; waitpid(p, &st, 0);
    _exit((WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : 82);
}

static void child_policy_socket_allowed(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    policy.socket_families = ESQUEMA_SOCKET_UNIX;
    if (esquema_apply_seccomp_policy(&policy) < 0) _exit(50);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) _exit(83);
    close(fd);
    _exit(0);
}

static void child_policy_socket_forbidden(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    policy.socket_families = ESQUEMA_SOCKET_UNIX;
    if (esquema_apply_seccomp_policy(&policy) < 0) _exit(50);
    errno = 0;
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (fd >= 0) { close(fd); _exit(84); }
    _exit(errno == ENOSYS ? 0 : 85);
}

static void child_policy_ioctl_restricted(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    if (esquema_apply_seccomp_policy(&policy) < 0) _exit(50);
    int fds[2];
    if (pipe(fds) < 0) _exit(86);
    int available = -1;
    if (ioctl(fds[0], FIONREAD, &available) < 0) _exit(87);
    errno = 0;
    if (ioctl(fds[0], 0xdeadbeefUL, 0) != -1 || errno != ENOSYS) _exit(88);
    close(fds[0]); close(fds[1]);
    _exit(0);
}

static void child_policy_denied_ptrace(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    if (esquema_apply_seccomp_policy(&policy) < 0) _exit(50);
    syscall(SYS_ptrace, 0, 0, 0, 0);
    _exit(0);
}

static int apply_strict_seccomp(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    struct sock_fprog program = { 0, NULL };
    if (es_seccomp_compile_strict(&policy, &program) < 0) return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        es_seccomp_free_program(&program);
        return -1;
    }
    if (es_seccomp_apply_program(&program) < 0) {
        es_seccomp_free_program(&program);
        return -1;
    }
    es_seccomp_free_program(&program);
    return 0;
}

#ifdef SYS_prlimit64
static void child_strict_prlimit_denied(void)
{
    if (apply_strict_seccomp() < 0) _exit(50);
    struct rlimit limit = { 17, 17 };
    syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limit, NULL);
    _exit(0);
}


static void child_strict_prlimit_query_allowed(void)
{
    if (apply_strict_seccomp() < 0) _exit(50);
    struct rlimit limit;
    if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &limit) < 0)
        _exit(87);
    _exit(0);
}
#endif

#ifdef SYS_setrlimit
static void child_strict_setrlimit_denied(void)
{
    if (apply_strict_seccomp() < 0) _exit(50);
    struct rlimit limit = { 16, 16 };
    syscall(SYS_setrlimit, RLIMIT_NOFILE, &limit);
    _exit(0);
}
#endif

static void child_compat_rlimit_available(void)
{
    if (esquema_apply_seccomp() < 0) _exit(50);
    struct rlimit limit;
#ifdef SYS_prlimit64
    if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &limit) < 0)
        _exit(86);
#else
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) _exit(86);
#endif
    _exit(0);
}

static void child_nofile_enforced(void)
{
    esquema_config *cfg = esquema_config_new();
    if (!cfg || esquema_config_set_open_files_max(cfg, 16) < 0)
        _exit(70);
    if (es_apply_nofile_limit(cfg) < 0) _exit(71);

    struct rlimit observed;
    if (getrlimit(RLIMIT_NOFILE, &observed) < 0 ||
        observed.rlim_cur != 16 || observed.rlim_max != 16)
        _exit(72);
    struct rlimit raised = { 17, 17 };
    errno = 0;
    if (setrlimit(RLIMIT_NOFILE, &raised) != -1 || errno != EPERM)
        _exit(73);
    esquema_config_free(cfg);
    _exit(0);
}

static void child_nofile_unenforceable(void)
{
    struct rlimit inherited = { 16, 16 };
    if (setrlimit(RLIMIT_NOFILE, &inherited) < 0) _exit(70);
    esquema_config *cfg = esquema_config_new();
    if (!cfg || esquema_config_set_open_files_max(cfg, 17) < 0)
        _exit(71);
    errno = 0;
    int rc = es_apply_nofile_limit(cfg);
    int saved = errno;
    esquema_config_free(cfg);
    _exit(rc == -1 && saved == EPERM ? 0 : 72);
}

#ifdef SYS_io_uring_setup
static void child_policy_io_uring_denied(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    if (esquema_apply_seccomp_policy(&policy) < 0) _exit(50);
    syscall(SYS_io_uring_setup, 1, NULL);
    _exit(0);
}
#endif

static int test_policy_arch_mismatch(void)
{
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
#if defined(__x86_64__)
    policy.expected_arch = ESQUEMA_ARCH_AARCH64;
#elif defined(__aarch64__)
    policy.expected_arch = ESQUEMA_ARCH_X86_64;
#else
    return 1; /* the runtime validator reports unsupported; no false match */
#endif
    struct sock_fprog program = { 0, NULL };
    errno = 0;
    int rc = es_seccomp_compile(&policy, &program);
    es_seccomp_free_program(&program);
    return rc == -1 && errno == EPROTONOSUPPORT;
}

static int test_dynamic_lifecycle_registry(void)
{
    enum { records = 96 };
    int tracked = 0;
    int ok = 1;
    for (int i = 0; i < records; i++) {
        char path[64];
        snprintf(path, sizeof path, "/tmp/esq-cgroup-%d", i);
        if (es_lifecycle_track((pid_t) (100000 + i), path) < 0) {
            ok = 0; break;
        }
        tracked++;
    }
    if (es_lifecycle_count() != (size_t) tracked || tracked != records) ok = 0;
    for (int i = 0; i < tracked; i++) {
        char expected[64];
        snprintf(expected, sizeof expected, "/tmp/esq-cgroup-%d", i);
        char *path = es_lifecycle_take((pid_t) (100000 + i));
        if (!path || strcmp(path, expected) != 0) ok = 0;
        free(path);
    }
    if (es_lifecycle_count() != 0) ok = 0;
    return ok;
}

enum { lifecycle_threads = 8, lifecycle_per_thread = 64 };

struct lifecycle_thread_args {
    int index;
    int ok;
};

static void *lifecycle_thread(void *opaque)
{
    struct lifecycle_thread_args *args = opaque;
    args->ok = 1;
    int tracked = 0;
    for (int i = 0; i < lifecycle_per_thread; i++) {
        char path[64];
        snprintf(path, sizeof path, "/tmp/esq-thread-%d-%d", args->index, i);
        pid_t pid = (pid_t) (200000 + args->index * 100 + i);
        if (es_lifecycle_track(pid, path) < 0) {
            args->ok = 0; break;
        }
        tracked++;
    }
    for (int i = 0; i < tracked; i++) {
        pid_t pid = (pid_t) (200000 + args->index * 100 + i);
        char *path = es_lifecycle_take(pid);
        if (!path) args->ok = 0;
        free(path);
    }
    return NULL;
}

static int test_cross_thread_lifecycle_registry(void)
{
    pthread_t threads[lifecycle_threads];
    struct lifecycle_thread_args args[lifecycle_threads];
    int created = 0;
    int ok = 1;
    for (int i = 0; i < lifecycle_threads; i++) {
        args[i].index = i;
        args[i].ok = 0;
        if (pthread_create(&threads[i], NULL, lifecycle_thread, &args[i]) != 0)
            break;
        created++;
    }
    if (created != lifecycle_threads) ok = 0;
    for (int i = 0; i < created; i++) {
        if (pthread_join(threads[i], NULL) != 0 || !args[i].ok) ok = 0;
    }
    if (es_lifecycle_count() != 0) ok = 0;
    return ok;
}

/* Drops all caps, then verifies the sets are empty and NNP is set.
 * Runs inside a fresh user namespace, which is the only context where the
 * drop is meaningful: there the process transiently holds a full cap set
 * (incl. CAP_SETPCAP) that securebits/bounding-set drops consume. */
static void child_dropcaps(void)
{
    if (unshare(CLONE_NEWUSER) < 0) _exit(70);   /* become root-in-userns */
    if (esquema_drop_caps() < 0) _exit(60);

    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct d[2];
    memset(d, 0, sizeof d);
    if (syscall(SYS_capget, &h, d) < 0) _exit(61);
    if (d[0].effective || d[1].effective) _exit(62);
    if (d[0].permitted || d[1].permitted) _exit(63);

    if (prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN) != 0) _exit(64);
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) _exit(65);
    _exit(0);
}

static char landlock_allowed[PATH_MAX];
static char landlock_allowed_file[PATH_MAX];
static char landlock_secret_file[PATH_MAX];

static void child_landlock_scope(void)
{
    if (es_landlock_restrict_root(landlock_allowed) < 0) _exit(70);
    int fd = open(landlock_allowed_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) _exit(71);
    close(fd);

    errno = 0;
    fd = open(landlock_secret_file, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { close(fd); _exit(72); }
    if (errno != EACCES && errno != EPERM) _exit(73);
    _exit(0);
}

static int make_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int rc = write(fd, "x", 1) == 1 ? 0 : -1;
    int e = errno;
    close(fd);
    errno = e;
    return rc;
}

/* Exercise recursive read-only sealing in a private user+mount namespace.
 * The nested tmpfs is a distinct mount, so a legacy remount of only the outer
 * tmpfs cannot make this test pass. */
static char ro_tree[PATH_MAX];
static char ro_nested[PATH_MAX];
static uid_t test_host_uid;
static gid_t test_host_gid;

static int setup_ro_mount_tree(void)
{
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) return -1;
    if (es_write_id_maps(0, (unsigned int) test_host_uid,
                        (unsigned int) test_host_gid) < 0)
        return -1;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return -1;
    if (mount("tmpfs", ro_tree, "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=0700,size=1m") < 0)
        return -1;
    if (mkdir(ro_nested, 0700) < 0) return -1;
    if (mount("tmpfs", ro_nested, "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=0700,size=1m") < 0)
        return -1;
    return 0;
}

/* Returns 1 for a successful write, 0 for a read-only rejection, and -1 for
 * an unexpected failure. */
static int probe_write(const char *path)
{
    errno = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return errno == EROFS ? 0 : -1;
    int ok = write(fd, "x", 1) == 1;
    int e = errno;
    close(fd);
    errno = e;
    return ok ? 1 : -1;
}

static int ro_path(char *out, size_t out_len, const char *dir,
                   const char *name)
{
    int n = snprintf(out, out_len, "%s/%s", dir, name);
    if (n < 0 || n >= (int) out_len) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

/* Exit 75 means this host cannot create the isolated mount fixture. Exit 76
 * means the fixture worked but recursive mount_setattr is unavailable. */
static void child_recursive_ro_seal(void)
{
    if (setup_ro_mount_tree() < 0) _exit(75);
    char outer_file[PATH_MAX], nested_file[PATH_MAX];
    if (ro_path(outer_file, sizeof outer_file, ro_tree, "write-probe") < 0 ||
        ro_path(nested_file, sizeof nested_file, ro_nested, "write-probe") < 0)
        _exit(80);

    errno = 0;
    if (es_mount_seal_read_only(ro_tree, 0) < 0) {
        if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP ||
            errno == EPERM)
            _exit(76);
        _exit(81);
    }

    struct statfs outer, nested;
    if (statfs(ro_tree, &outer) < 0 || statfs(ro_nested, &nested) < 0)
        _exit(82);
    if (!(outer.f_flags & ST_RDONLY) || !(nested.f_flags & ST_RDONLY))
        _exit(83);
    if (probe_write(outer_file) != 0 || probe_write(nested_file) != 0)
        _exit(84);
    _exit(0);
}

/* Force precisely the old-kernel condition without depending on the running
 * kernel: mount_setattr returns ENOSYS, while all other syscalls remain
 * available to the fixture. */
static int force_mount_setattr_enosys(void)
{
#ifdef __NR_mount_setattr
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int) offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount_setattr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short) (sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0) return -1;
#endif
    return 0;
}

static void child_strict_ro_no_fallback(void)
{
    if (setup_ro_mount_tree() < 0) _exit(75);
    if (force_mount_setattr_enosys() < 0) _exit(76);

    char outer_strict[PATH_MAX], nested_strict[PATH_MAX];
    char outer_compat[PATH_MAX], nested_compat[PATH_MAX];
    if (ro_path(outer_strict, sizeof outer_strict, ro_tree,
                "strict-probe") < 0 ||
        ro_path(nested_strict, sizeof nested_strict, ro_nested,
                "strict-probe") < 0 ||
        ro_path(outer_compat, sizeof outer_compat, ro_tree,
                "compat-probe") < 0 ||
        ro_path(nested_compat, sizeof nested_compat, ro_nested,
                "compat-probe") < 0)
        _exit(80);

    errno = 0;
    if (es_mount_seal_read_only(ro_tree, 0) != -1 || errno != ENOSYS)
        _exit(81);
    /* Strict failure must not quietly have applied the weaker operation. */
    if (probe_write(outer_strict) != 1 || probe_write(nested_strict) != 1)
        _exit(82);

    if (es_mount_seal_read_only(ro_tree, 1) < 0) _exit(83);
    struct statfs outer, nested;
    if (statfs(ro_tree, &outer) < 0 || statfs(ro_nested, &nested) < 0)
        _exit(84);
    /* This deliberately demonstrates why the compatibility fallback cannot
     * satisfy Fortress: only the outer mount is read-only. */
    if (!(outer.f_flags & ST_RDONLY) || (nested.f_flags & ST_RDONLY))
        _exit(85);
    if (probe_write(outer_compat) != 0 || probe_write(nested_compat) != 1)
        _exit(86);
    _exit(0);
}

static int run_ro_mount_test(void (*child)(void))
{
    char base[] = "/tmp/esq-recursive-ro-XXXXXX";
    if (!mkdtemp(base)) return -1;
    if (strlen(base) >= sizeof ro_tree ||
        snprintf(ro_nested, sizeof ro_nested, "%s/nested", base) >=
            (int) sizeof ro_nested) {
        rmdir(base); errno = ENAMETOOLONG; return -1;
    }
    strcpy(ro_tree, base);
    int st = run_child(child);
    rmdir(base);
    return st;
}

static int test_landlock_scope(void)
{
    char base[] = "/tmp/esq-landlock-XXXXXX";
    if (!mkdtemp(base)) return 0;
    int ok = 0;
    if (snprintf(landlock_allowed, sizeof landlock_allowed, "%s/allowed", base)
            >= (int) sizeof landlock_allowed ||
        snprintf(landlock_allowed_file, sizeof landlock_allowed_file,
                 "%s/inside", landlock_allowed) >=
            (int) sizeof landlock_allowed_file ||
        snprintf(landlock_secret_file, sizeof landlock_secret_file,
                 "%s/host-secret", base) >=
            (int) sizeof landlock_secret_file)
        goto out;
    if (mkdir(landlock_allowed, 0700) < 0) goto out;
    if (make_file(landlock_allowed_file) < 0 ||
        make_file(landlock_secret_file) < 0)
        goto out;

    int st = run_child(child_landlock_scope);
    ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
out:
    unlink(landlock_allowed_file);
    unlink(landlock_secret_file);
    rmdir(landlock_allowed);
    rmdir(base);
    return ok;
}

/* A bad cgroup name deterministically fails after the setup child has been
 * forked but while it is still blocked on the parent gate.  Strict mode must
 * return failure and synchronously reap that child. */
static int test_strict_cgroup_failure(int *clean_teardown)
{
    esquema_config *cfg = esquema_config_new();
    if (!cfg) return 0;
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    int configured =
        esquema_config_set_rootfs(cfg, "/") == 0 &&
        esquema_config_add_arg(cfg, "/bin/false") == 0 &&
        esquema_config_set_cgroup_name(cfg, "invalid/name") == 0 &&
        esquema_config_set_seccomp_policy(cfg, &policy) == 0 &&
        esquema_config_set_open_files_max(cfg, 64) == 0 &&
        esquema_config_set_supervisor(cfg, 1, 100) == 0;
    esquema_config_set_memory_max(cfg, 4096);
    esquema_config_set_strict(cfg, 1);
    pid_t pid = configured ? esquema_spawn(cfg) : -2;
    int saved = esquema_errno();
    esquema_config_free(cfg);

    errno = 0;
    int st = 0;
    pid_t leftover = waitpid(-1, &st, WNOHANG);
    *clean_teardown = leftover == -1 && errno == ECHILD;
    return pid == -1 && saved == EINVAL;
}

static int test_strict_missing_nofile(void)
{
    esquema_config *cfg = esquema_config_new();
    if (!cfg) return 0;
    esquema_seccomp_policy policy;
    esquema_seccomp_policy_init(&policy);
    int configured =
        esquema_config_set_rootfs(cfg, "/") == 0 &&
        esquema_config_add_arg(cfg, "/bin/false") == 0 &&
        esquema_config_set_cgroup_name(cfg, "strict-missing-nofile") == 0 &&
        esquema_config_set_seccomp_policy(cfg, &policy) == 0 &&
        esquema_config_set_supervisor(cfg, 1, 100) == 0;
    esquema_config_set_memory_max(cfg, 4096);
    esquema_config_set_strict(cfg, 1);
    pid_t pid = configured ? esquema_spawn(cfg) : -2;
    int saved = esquema_errno();
    esquema_config_free(cfg);
    return pid == -1 && saved == EINVAL;
}

int main(void)
{
    test_host_uid = getuid();
    test_host_gid = getgid();
    printf("Esquema C primitive tests (version %s)\n", esquema_version());

    /* ---- version / init ---- */
    check("esquema_init returns 42", esquema_init() == 42);
    check("esquema_version non-empty", esquema_version() && esquema_version()[0]);

    /* ---- seccomp: allow benign, kill denied ---- */
    {
        int st = run_child(child_allowed);
        check("seccomp: benign payload survives (exit 0)",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_denied_unshare);
        check("seccomp: denied unshare killed by SIGSYS",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
    {
        int st = run_child(child_denied_ptrace);
        check("seccomp: denied ptrace killed by SIGSYS",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
    {
        int st = run_child(child_clone_newuser_blocked);
        check("seccomp: clone(CLONE_NEWUSER) refused (no nested userns)",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_tiocsti_blocked);
        check("seccomp: ioctl(TIOCSTI) terminal injection killed by SIGSYS",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
    {
        int st = run_child(child_fork_allowed);
        check("seccomp: ordinary fork() still permitted",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }

    /* ---- versioned policy: architecture + syscall sub-policies ---- */
    check("seccomp v1: runtime architecture mismatch rejected",
          test_policy_arch_mismatch());
    {
        int st = run_child(child_policy_socket_allowed);
        check("seccomp v1: allowlisted AF_UNIX socket permitted",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_policy_socket_forbidden);
        check("seccomp v1: non-allowlisted AF_PACKET socket refused",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_policy_ioctl_restricted);
        check("seccomp v1: safe ioctl allowed, unknown request refused",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_policy_denied_ptrace);
        check("seccomp v1: invariant ptrace deny cannot be removed",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
#ifdef SYS_io_uring_setup
    {
        int st = run_child(child_policy_io_uring_denied);
        check("seccomp v1: io_uring deny policy kills setup",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
#else
    printf("BLOCKED seccomp v1 io_uring test: SYS_io_uring_setup unavailable\n");
#endif

    /* ---- RLIMIT_NOFILE contract + strict post-installation lock ---- */
    {
        int st = run_child(child_nofile_enforced);
        check("RLIMIT_NOFILE: soft+hard values are installed and cannot be raised",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_nofile_unenforceable);
        check("RLIMIT_NOFILE: unenforceable policy value fails closed",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    {
        int st = run_child(child_compat_rlimit_available);
        check("RLIMIT_NOFILE: compatibility seccomp retains resource-limit API",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
#ifdef SYS_prlimit64
    {
        int st = run_child(child_strict_prlimit_denied);
        check("strict seccomp: mutating prlimit64 is killed after policy installation",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
    {
        int st = run_child(child_strict_prlimit_query_allowed);
        check("strict seccomp: query-only prlimit64 remains available",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
#else
    printf("BLOCKED strict prlimit64 test: SYS_prlimit64 unavailable\n");
#endif
#ifdef SYS_setrlimit
    {
        int st = run_child(child_strict_setrlimit_denied);
        check("strict seccomp: setrlimit is killed after policy installation",
              WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    }
#else
    printf("BLOCKED strict setrlimit test: SYS_setrlimit unavailable\n");
#endif

    /* ---- capability drop ---- */
    {
        int st = run_child(child_dropcaps);
        check("drop_caps: caps emptied + NNP set (exit 0)",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }

    /* ---- Landlock ABI + path scope ---- */
    {
        int abi = esquema_landlock_abi();
        if (abi > 0) {
            char label[96];
            snprintf(label, sizeof label,
                     "landlock ABI %d: allowed root works, host secret denied", abi);
            check(label, test_landlock_scope());
        } else {
            printf("BLOCKED landlock: kernel reports ABI %d (%s)\n",
                   abi, abi < 0 ? strerror(errno) : "unsupported");
        }
    }

    /* ---- recursive read-only mount sealing ---- */
    {
        int st = run_ro_mount_test(child_recursive_ro_seal);
        if (WIFEXITED(st) &&
            (WEXITSTATUS(st) == 75 || WEXITSTATUS(st) == 76)) {
            printf("BLOCKED recursive read-only sealing: isolated mount or "
                   "mount_setattr capability unavailable (exit %d)\n",
                   WEXITSTATUS(st));
        } else {
            check("mount_setattr: outer and nested mounts read-only by readback",
                  WIFEXITED(st) && WEXITSTATUS(st) == 0);
        }
    }
    {
        int st = run_ro_mount_test(child_strict_ro_no_fallback);
        if (WIFEXITED(st) &&
            (WEXITSTATUS(st) == 75 || WEXITSTATUS(st) == 76)) {
            printf("BLOCKED strict read-only fallback test: isolated mount or "
                   "seccomp fixture unavailable (exit %d)\n",
                   WEXITSTATUS(st));
        } else {
            check("strict read-only: ENOSYS fails closed; compatibility remains weaker",
                  WIFEXITED(st) && WEXITSTATUS(st) == 0);
        }
    }

    /* ---- strict cgroup failure and abort cleanup ---- */
    {
        int clean = 0;
        check("strict mode: missing open-files limit fails before launch",
              test_strict_missing_nofile());
        check("strict mode: cgroup setup failure aborts launch",
              test_strict_cgroup_failure(&clean));
        check("strict mode: aborted setup child is synchronously reaped", clean);
    }

    /* ---- granular API input validation (safe in-process) ---- */
    check("unshare rejects CLONE_VM (EINVAL)",
          esquema_unshare(0x00000100) == -1);
    check("enter_cgroup rejects traversal name",
          esquema_enter_cgroup("../escape") == -1);
    check("enter_cgroup rejects slash name",
          esquema_enter_cgroup("a/b") == -1);
    check("enter_cgroup rejects empty name",
          esquema_enter_cgroup("") == -1);
    {
        esquema_config *cfg = esquema_config_new();
        check("bind destination rejects absolute paths",
              cfg && esquema_config_add_bind(cfg, "/tmp", "/escape", 1) == -1);
        check("bind destination rejects parent traversal",
              cfg && esquema_config_add_bind(cfg, "/tmp", "tmp/../escape", 1) == -1);
        check("bind destination rejects empty path segments",
              cfg && esquema_config_add_bind(cfg, "/tmp", "tmp//escape", 1) == -1);
        check("open-files limit rejects values below 16",
              cfg && esquema_config_set_open_files_max(cfg, 15) == -1 &&
              esquema_errno() == ERANGE);
        check("open-files limit rejects values above 1048576",
              cfg && esquema_config_set_open_files_max(cfg, 1048577) == -1 &&
              esquema_errno() == ERANGE);
        int source_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int high_fd = source_fd < 0 ? -1
                                    : fcntl(source_fd, F_DUPFD_CLOEXEC, 32);
        check("open-files limit rejects an already-preserved descriptor at its bound",
              cfg && high_fd >= 32 &&
              esquema_config_preserve_fd(cfg, high_fd) == 0 &&
              esquema_config_set_open_files_max(cfg,
                                                 (uint32_t) high_fd) == -1 &&
              esquema_errno() == ERANGE);
        if (high_fd >= 0) close(high_fd);
        if (source_fd >= 0) close(source_fd);
        esquema_seccomp_policy policy;
        esquema_seccomp_policy_init(&policy);
        policy.version++;
        check("seccomp policy rejects an unknown version",
              cfg && esquema_config_set_seccomp_policy(cfg, &policy) == -1);
        esquema_seccomp_policy_init(&policy);
        policy.size--;
        check("seccomp policy rejects a noncanonical structure size",
              cfg && esquema_config_set_seccomp_policy(cfg, &policy) == -1);
        esquema_seccomp_policy_init(&policy);
        policy.socket_families = ESQUEMA_SOCKET_ALL | (1ULL << 32);
        check("seccomp policy rejects unknown socket-family bits",
              cfg && esquema_config_set_seccomp_policy(cfg, &policy) == -1);
        esquema_seccomp_policy_init(&policy);
        policy.reserved[0] = 1;
        check("seccomp policy rejects nonzero reserved fields",
              cfg && esquema_config_set_seccomp_policy(cfg, &policy) == -1);
        esquema_config_free(cfg);
    }
    {
        esquema_config *cfg = esquema_config_new();
        int source_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int high_fd = source_fd < 0 ? -1
                                    : fcntl(source_fd, F_DUPFD_CLOEXEC, 16);
        check("preserve_fd rejects a descriptor at an existing open-files bound",
              cfg && high_fd >= 16 &&
              esquema_config_set_open_files_max(cfg, 16) == 0 &&
              esquema_config_preserve_fd(cfg, high_fd) == -1 &&
              esquema_errno() == ERANGE);
        if (high_fd >= 0) close(high_fd);
        if (source_fd >= 0) close(source_fd);
        esquema_config_free(cfg);
    }
    check("lifecycle registry tracks and removes more than 64 launches",
          test_dynamic_lifecycle_registry());
    check("lifecycle registry is safe across broker threads",
          test_cross_thread_lifecycle_registry());

    printf("\n%d C check(s) failed\n", failures);
    return failures ? 1 : 0;
}
