#include <libipset/ipset.h>

#include <stdio.h>
#include <stdlib.h>

int func(struct ipset *ipset, void *p, int status, const char *msg, ...) {
    return 0;
}

int func2(struct ipset *ipset, void *p) {
    return 0;
}

int func3(struct ipset_session *session, void *p, const char *fmt, ...) {
    return 0;
}

int main() {
    char *cmd = "test nohttp 192.168.1.1,2232";
    char *cmd2[10] = {"add", "nohttp", "192.168.1.1,223"};
    struct ipset *ipset;
    int ret;

    printf("line\n");
    /* Load set types */
    ipset_load_types();

    /* Initialize ipset library */
    ipset = ipset_init();
    if (ipset == NULL) {
        fprintf(stderr, "Cannot initialize ipset, aborting.");
        exit(1);
    }

    ipset_custom_printf(ipset, func, func2, func3, NULL);

    ret = ipset_parse_argv(ipset, 3, cmd2);

    printf("line\n");
    printf("a = %d\n", ret);

    ipset_fini(ipset);

    // return ret;
}

