/* api.c — thin public shims layered over the core primitives. */
#include "internal.h"

int esquema_init(void) { return esquema_core_init(); }

/* esquema_drop_privs historically meant "make this process safe". It now
 * performs the full capability + securebits + no-new-privs drop. */
int esquema_drop_privs(void) { return esquema_drop_caps(); }
