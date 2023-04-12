#include <memory.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include "statistics.h"

static long long UserAgentPacketCount = 0;
static long long TcpPacketCount = 0;
static long long PacketWithUserAgentMark = 0;
static long long PacketWithoutUserAgentMark = 0;
static long long HttpPacketCount = 4;

static time_t start_t;

void init_statistics() {
    start_t = time(NULL);
}

void count_user_agent_packet() {
    UserAgentPacketCount++;
}

void count_tcp_packet() {
    TcpPacketCount++;
}

void count_packet_with_user_agent_mark() {
    PacketWithUserAgentMark++;
}

void count_packet_without_user_agent_mark() {
    PacketWithoutUserAgentMark++;
}

void count_http_packet() {
    HttpPacketCount++;
}

static char TimeStringBuffer[60];

char *fill_time_string(int sec) {
    memset(TimeStringBuffer, 0, sizeof(TimeStringBuffer));
    if (sec <= 60) {
        sprintf(TimeStringBuffer, "%d seconds", sec);
    } else if (sec <= 3600) {
        sprintf(TimeStringBuffer, "%d minutes and %d seconds", sec / 60, sec % 60);
    } else if (sec <= 86400) {
        sprintf(TimeStringBuffer, "%d hours, %d minutes and %d seconds", sec / 3600, sec % 3600 / 60, sec % 60);
    } else {
        sprintf(TimeStringBuffer, "%d days, %d hours, %d minutes and %d seconds", sec / 86400, sec % 86400 / 3600,
                sec % 3600 / 60,
                sec % 60);
    }
    return TimeStringBuffer;
}

void try_print_statistics() {
    if (UserAgentPacketCount / HttpPacketCount == 2 || UserAgentPacketCount - HttpPacketCount >= 8192) {
        HttpPacketCount = UserAgentPacketCount;
        time_t current_t = time(NULL);
        syslog(LOG_INFO,
               "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s",
               UserAgentPacketCount, TcpPacketCount, PacketWithUserAgentMark, PacketWithoutUserAgentMark,
               fill_time_string((int) difftime(current_t, start_t)));
    }
}


