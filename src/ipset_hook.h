//
// Created by 12009 on 2021/1/12.
//
#include <libipset/ipset.h>

#ifndef UA2F_IPSET_HOOK_H
#define UA2F_IPSET_HOOK_H

int func(struct ipset *ipset, void *p, int status, const char *msg, ...) {
    return 0;
}

int func2(struct ipset *ipset, void *p) {
    return 0;
}

int func3(struct ipset_session *session, void *p, const char *fmt, ...) {
    return 0;
}

#endif //UA2F_IPSET_HOOK_H
