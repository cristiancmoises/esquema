/* error.c — thread-local last-error state for the Esquema C API. */
#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static __thread int  es_errno_val = 0;
static __thread char es_msg[256];

int es_fail(const char *stage)
{
    es_errno_val = errno;
    snprintf(es_msg, sizeof es_msg, "%s: %s",
             stage ? stage : "esquema", strerror(es_errno_val));
    return -1;
}

void es_clear_error(void)
{
    es_errno_val = 0;
    es_msg[0] = '\0';
}

int es_get_errno(void)          { return es_errno_val; }
const char *es_get_message(void){ return es_msg[0] ? es_msg : "no error"; }

/* Public introspection ------------------------------------------------- */
int         esquema_errno(void)    { return es_get_errno(); }
const char *esquema_strerror(void) { return es_get_message(); }
