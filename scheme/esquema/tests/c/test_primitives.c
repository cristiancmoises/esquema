/* test_primitives.c — C-level unit tests for the Esquema hardening
 * primitives that are awkward to exercise from Scheme: seccomp actually
 * KILLing a denied syscall with SIGSYS, the capability drop emptying the
 * cap sets, and the input validation on the granular API.
 *
 * Build: gcc -I c test_primitives.c -L. -lesquema  (run with LD_LIBRARY_PATH=.)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/capability.h>

#include "esquema.h"

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

int main(void)
{
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

    /* ---- capability drop ---- */
    {
        int st = run_child(child_dropcaps);
        check("drop_caps: caps emptied + NNP set (exit 0)",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
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

    printf("\n%d C check(s) failed\n", failures);
    return failures ? 1 : 0;
}
