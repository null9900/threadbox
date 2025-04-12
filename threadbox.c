#include <stdio.h>
#include <string.h>

void sandbox_ps() {
    FILE *fp = fopen("/sys/kernel/security/funcsandbox/sandbox_ps", "w");
    if (fp == NULL) {
        perror("Failed to open sandbox_ps");
        return;
    }
    fprintf(fp, " ");
    fclose(fp);
}

void permissions(const char *promises, const char *debug, int complain) {
    FILE *p = fopen("/sys/kernel/security/funcsandbox/promises", "w");
    FILE *d = fopen("/sys/kernel/security/funcsandbox/debug", "w");
    FILE *c = fopen("/sys/kernel/security/funcsandbox/learning_mode", "w");

    if (p == NULL || d == NULL || c == NULL) {
        perror("Failed to open one or more permission files");
        if (p) fclose(p);
        if (d) fclose(d);
        if (c) fclose(c);
        return;
    }

    fprintf(p, "%s", promises);
    
    if (strlen(debug) != 0) {
        fprintf(d, "%s", debug);
    }
    if (complain) {
        fprintf(c, " ");
    }
    
    fclose(p);
    fclose(d);
    fclose(c);
}

