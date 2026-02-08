#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include "esquema.h"

int esquema_unshare(int flags) {
    return unshare(flags);
}

int esquema_drop_privs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return 0;
}
