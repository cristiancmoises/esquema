/* esquema.c — version/health entry points. */
#include "internal.h"

/* Legacy health probe. Historically returns 42 ("the answer"): the README,
 * the Shepherd service and the smoke test all rely on this value, so it is
 * kept ABI-stable. A real ABI/version check should use esquema_version(). */
int esquema_core_init(void) { return 42; }

const char *esquema_version(void) { return ESQUEMA_VERSION_STRING; }
