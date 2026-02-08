#include <seccomp.h>
#include <errno.h>

int esquema_apply_seccomp(void) {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx)
        return -ENOMEM;

    /* allow exit */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    /* allow write (stdout/stderr) */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);

    return rc;
}
