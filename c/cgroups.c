#include "esquema.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void scm_enter_cgroup(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name);
    mkdir(path, 0755);

    char procs[256];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", path);
    FILE *f = fopen(procs, "w");
    fprintf(f, "%d\n", getpid());
    fclose(f);
}
