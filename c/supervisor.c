/* supervisor.c — minimal strict-mode PID-1 and signal relay.
 *
 * The supervisor parses no payload data.  It owns only process lifecycle:
 * reset inherited signal state for the payload, forward trusted host signals,
 * reap orphaned descendants, and enforce a bounded TERM->KILL teardown. */
#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t signal_target;
static volatile sig_atomic_t signal_target_group;
static volatile sig_atomic_t pending_signal;
static volatile sig_atomic_t pending_shutdown;
static volatile sig_atomic_t forwarding_prepared;

static const int forwarded_signals[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2,
    SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU, SIGWINCH
};

static void forward_handler(int signo)
{
    pending_signal = signo;
    if (signo == SIGHUP || signo == SIGINT || signo == SIGQUIT ||
        signo == SIGTERM)
        pending_shutdown = 1;
    pid_t target = (pid_t) signal_target;
    if (target > 0)
        kill(signal_target_group ? -target : target, signo);
}

static int install_forward_handlers(int group, int clear_pending)
{
    signal_target = 0;
    signal_target_group = group ? 1 : 0;
    if (clear_pending) {
        pending_signal = 0;
        pending_shutdown = 0;
    }
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = forward_handler;
    action.sa_flags = 0;
    for (size_t i = 0;
         i < sizeof forwarded_signals / sizeof forwarded_signals[0]; i++)
        if (sigaction(forwarded_signals[i], &action, NULL) < 0) return -1;
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0) return -1;
    forwarding_prepared = 1;
    return 0;
}

static int reset_payload_signals(void)
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    for (size_t i = 0;
         i < sizeof forwarded_signals / sizeof forwarded_signals[0]; i++)
        if (sigaction(forwarded_signals[i], &action, NULL) < 0) return -1;
    if (sigaction(SIGCHLD, &action, NULL) < 0 ||
        sigaction(SIGPIPE, &action, NULL) < 0)
        return -1;
    sigset_t empty;
    sigemptyset(&empty);
    return sigprocmask(SIG_SETMASK, &empty, NULL);
}

static int shell_status(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 255;
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return 0;
    return (uint64_t) now.tv_sec * 1000U + (uint64_t) now.tv_nsec / 1000000U;
}

int es_wait_forwarding(pid_t pid)
{
    if (pid <= 0 || !forwarding_prepared) { errno = EINVAL; return -1; }
    signal_target = (sig_atomic_t) pid;
    if (pending_signal) kill(pid, pending_signal);

    int status = 0;
    for (;;) {
        pid_t waited = waitpid(pid, &status, 0);
        if (waited == pid) return shell_status(status);
        if (waited < 0 && errno == EINTR) continue;
        return -1;
    }
}

int es_forwarding_prepare(void)
{
    forwarding_prepared = 0;
    return install_forward_handlers(0, 1);
}

int es_supervise_exec(char *const argv[], char *const envp[],
                      unsigned int timeout_ms)
{
    if (!argv || !argv[0] || timeout_ms == 0 || timeout_ms > 60000) {
        errno = EINVAL; return -1;
    }
    /* B inherits a signal that A received between esquema_spawn() returning
     * and B becoming PID 1. Preserve that pending state while changing the
     * relay target from B itself to the payload process group. */
    if (install_forward_handlers(1, 0) < 0) return -1;

    pid_t payload = fork();
    if (payload < 0) return -1;
    if (payload == 0) {
        if (reset_payload_signals() < 0) _exit(126);
        if (setpgid(0, 0) < 0) _exit(126);
        execve(argv[0], argv, envp);
        _exit(127);
    }
    /* Close the race where the child has not called setpgid yet. */
    if (setpgid(payload, payload) < 0 && errno != EACCES && errno != ESRCH) {
        kill(payload, SIGKILL);
        while (waitpid(payload, NULL, 0) < 0 && errno == EINTR) { }
        return -1;
    }
    signal_target = (sig_atomic_t) payload;
    if (pending_signal) kill(-payload, pending_signal);

    /* Only the payload owns explicitly delegated capability descriptors. */
    if (es_close_inherited_fds(NULL) < 0) {
        kill(-payload, SIGKILL);
        while (waitpid(payload, NULL, 0) < 0 && errno == EINTR) { }
        return -1;
    }

    int payload_seen = 0;
    int payload_status = 255;
    int shutting_down = 0;
    int killed = 0;
    uint64_t deadline = 0;
    uint64_t hard_deadline = 0;

    for (;;) {
        int status = 0;
        pid_t reaped;
        int have_children = 1;
        while ((reaped = waitpid(-1, &status, WNOHANG)) > 0) {
            if (reaped == payload) {
                payload_seen = 1;
                payload_status = shell_status(status);
            }
        }
        if (reaped < 0 && errno == ECHILD) have_children = 0;
        else if (reaped < 0 && errno != EINTR) return -1;
        if (!have_children) return payload_seen ? payload_status : 255;

        if (pending_signal) pending_signal = 0;
        int shutdown_requested = pending_shutdown ? 1 : 0;
        if (shutdown_requested) pending_shutdown = 0;
        if (!shutting_down && (payload_seen || shutdown_requested)) {
            shutting_down = 1;
            kill(-1, SIGTERM);
            uint64_t now = monotonic_ms();
            deadline = now + timeout_ms;
            hard_deadline = deadline + 1000;
        }

        uint64_t now = monotonic_ms();
        if (shutting_down && !killed && now >= deadline) {
            kill(-1, SIGKILL);
            killed = 1;
        }
        /* Exiting namespace PID 1 asks the kernel to destroy any task stuck
         * in uninterruptible teardown, keeping the caller's wait bounded. */
        if (shutting_down && killed && now >= hard_deadline)
            return payload_seen ? payload_status : 137;

        struct timespec pause = { 0, 10 * 1000 * 1000 };
        while (nanosleep(&pause, &pause) < 0 && errno == EINTR) { }
    }
}
