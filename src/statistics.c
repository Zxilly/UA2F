#include <memory.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include "statistics.h"

static long long UserAgentPacketCount = 0;
static long long TcpPacketCount = 0;
static long long PacketWithUserAgentMark = 0;
static long long PacketWithoutUserAgentMark = 0;
static long long LastReportCount = 4;

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

static char TimeStringBuffer[60];

char *fill_time_string(double sec) {
    int s = (int) sec;
    memset(TimeStringBuffer, 0, sizeof(TimeStringBuffer));
    if (s <= 60) {
        sprintf(TimeStringBuffer, "%d seconds", s);
    } else if (s <= 3600) {
        sprintf(TimeStringBuffer, "%d minutes and %d seconds", s / 60, s % 60);
    } else if (s <= 86400) {
        sprintf(TimeStringBuffer, "%d hours, %d minutes and %d seconds", s / 3600, s % 3600 / 60, s % 60);
    } else {
        sprintf(TimeStringBuffer, "%d days, %d hours, %d minutes and %d seconds", s / 86400, s % 86400 / 3600,
                s % 3600 / 60,
                s % 60);
    }
    return TimeStringBuffer;
}

void try_print_statistics() {
    if (UserAgentPacketCount / LastReportCount == 2 || UserAgentPacketCount - LastReportCount >= 16384) {
        LastReportCount = UserAgentPacketCount;
        time_t current_t = time(NULL);
        syslog(LOG_INFO,
               "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s",
               UserAgentPacketCount, TcpPacketCount, PacketWithUserAgentMark, PacketWithoutUserAgentMark,
               fill_time_string(difftime(current_t, start_t)));
    }
}


