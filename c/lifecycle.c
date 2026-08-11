/* lifecycle.c — cross-thread cleanup ownership for launched containers.
 *
 * The original 64-slot thread-local table lost cgroup cleanup when a broker
 * waited on a different thread or launched more than 64 cells.  This bounded
 * dynamic registry is process-wide and keyed by the exact setup pid. */
#include "internal.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define ES_LIFECYCLE_MAX 4096U

struct lifecycle_record {
    pid_t pid;
    char *path;
    struct lifecycle_record *next;
};

static struct lifecycle_record *records;
static size_t record_count;
static atomic_flag records_lock = ATOMIC_FLAG_INIT;

static void lock_records(void)
{
    while (atomic_flag_test_and_set_explicit(&records_lock,
                                              memory_order_acquire))
        sched_yield();
}

static void unlock_records(void)
{
    atomic_flag_clear_explicit(&records_lock, memory_order_release);
}

int es_lifecycle_track(pid_t pid, const char *path)
{
    if (pid <= 0 || !path || !path[0]) { errno = EINVAL; return -1; }
    struct lifecycle_record *record = malloc(sizeof *record);
    if (!record) { errno = ENOMEM; return -1; }
    record->path = strdup(path);
    if (!record->path) { free(record); errno = ENOMEM; return -1; }
    record->pid = pid;

    lock_records();
    if (record_count >= ES_LIFECYCLE_MAX) {
        unlock_records();
        free(record->path); free(record);
        errno = ENOSPC; return -1;
    }
    for (struct lifecycle_record *it = records; it; it = it->next) {
        if (it->pid == pid) {
            unlock_records();
            free(record->path); free(record);
            errno = EEXIST; return -1;
        }
    }
    record->next = records;
    records = record;
    record_count++;
    unlock_records();
    return 0;
}

char *es_lifecycle_take(pid_t pid)
{
    lock_records();
    struct lifecycle_record **link = &records;
    while (*link && (*link)->pid != pid) link = &(*link)->next;
    if (!*link) { unlock_records(); return NULL; }
    struct lifecycle_record *record = *link;
    *link = record->next;
    record_count--;
    unlock_records();

    char *path = record->path;
    free(record);
    return path;
}

size_t es_lifecycle_count(void)
{
    lock_records();
    size_t count = record_count;
    unlock_records();
    return count;
}
