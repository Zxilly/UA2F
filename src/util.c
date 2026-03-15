#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool probe_http_method(const char *p, const int len, const char *opt) {
    if (len < strlen(opt)) {
        return false;
    }

    return !strncmp(p, opt, strlen(opt));
}

bool is_http_protocol(const char *p, const unsigned int len) {
    bool pass = false;

#define PROBE_HTTP_METHOD(opt)                                                                                         \
    if ((pass = probe_http_method(p, len, opt)) != false)                                                              \
    return pass

    PROBE_HTTP_METHOD("GET");
    PROBE_HTTP_METHOD("POST");
    PROBE_HTTP_METHOD("OPTIONS");
    PROBE_HTTP_METHOD("HEAD");
    PROBE_HTTP_METHOD("PUT");
    PROBE_HTTP_METHOD("DELETE");
    PROBE_HTTP_METHOD("TRACE");
    PROBE_HTTP_METHOD("CONNECT");
    PROBE_HTTP_METHOD("PATCH");

#undef PROBE_HTTP_METHOD
    return false;
}
