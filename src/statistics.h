#ifndef UA2F_STATISTICS_H
#define UA2F_STATISTICS_H

void count_user_agent_packet();

void count_tcp_packet();

void count_packet_with_user_agent_mark();

void count_packet_without_user_agent_mark();

void count_http_packet();

void init_statistics();

#endif //UA2F_STATISTICS_H
