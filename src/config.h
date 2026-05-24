#pragma once

#ifdef UA2F_ENABLE_UCI
#ifndef UA2F_CONFIG_H
#define UA2F_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "mode.h"

struct ua2f_config {
    bool use_custom_ua;
    char *custom_ua;
    bool disable_connmark;
    int max_http_sessions; // 0 = unlimited
    int session_ttl; // seconds, default 300
    enum ua2f_mode mode;
    uint16_t listen_port;
};

void load_config();

extern struct ua2f_config config;

#endif // UA2F_CONFIG_H
#endif
