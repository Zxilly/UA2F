#ifdef UA2F_ENABLE_UCI
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <uci.h>

#include "config.h"

struct ua2f_config config = {
    .use_custom_ua = false,
    .custom_ua = NULL,
    .disable_connmark = false,
    .max_http_sessions = 0,
    .session_ttl = 300,
};

void load_config() {
    const __auto_type ctx = uci_alloc_context();
    if (ctx == NULL) {
        syslog(LOG_ERR, "Failed to allocate uci context");
        return;
    }

    struct uci_package *package;
    if (uci_load(ctx, "ua2f", &package) != UCI_OK) {
        goto cleanup;
    }

    // find ua2f.main.custom_ua
    const __auto_type section = uci_lookup_section(ctx, package, "main");
    if (section == NULL) {
        goto cleanup;
    }

    const __auto_type custom_ua = uci_lookup_option_string(ctx, section, "custom_ua");
    if (custom_ua != NULL && strlen(custom_ua) > 0) {
        config.use_custom_ua = true;
        config.custom_ua = strdup(custom_ua);
    }

    const __auto_type disable_connmark = uci_lookup_option_string(ctx, section, "disable_connmark");
    if (disable_connmark != NULL && strcmp(disable_connmark, "1") == 0) {
        config.disable_connmark = true;
    }

    const __auto_type max_sessions_str = uci_lookup_option_string(ctx, section, "max_http_sessions");
    if (max_sessions_str != NULL) {
        char *endptr;
        const long val = strtol(max_sessions_str, &endptr, 10);
        if (*endptr == '\0' && val >= 0) {
            config.max_http_sessions = (int)val;
        } else {
            syslog(LOG_WARNING, "Invalid max_http_sessions value: %s, using default %d", max_sessions_str, config.max_http_sessions);
        }
    }

    const __auto_type session_ttl_str = uci_lookup_option_string(ctx, section, "session_ttl");
    if (session_ttl_str != NULL) {
        char *endptr;
        const long val = strtol(session_ttl_str, &endptr, 10);
        if (*endptr == '\0' && val > 0) {
            config.session_ttl = (int)val;
        } else {
            syslog(LOG_WARNING, "Invalid session_ttl value: %s, using default %d", session_ttl_str, config.session_ttl);
        }
    }

cleanup:
    uci_free_context(ctx);
}
#endif
