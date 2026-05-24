#include "proxy.h"

#include "handler.h"
#include "http_parser_ua.h"
#include "http_session.h"
#include "statistics.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif

#ifndef SO_MARK
#define SO_MARK 36
#endif

#define PROXY_BUFFER_SIZE 16384
#define PROXY_MAX_CONNECTIONS 512

struct proxy_listener {
    int fd;
    int family;
};

struct connection_args {
    int client_fd;
    int family;
    enum ua2f_mode mode;
    uint16_t listen_port;
};

struct raw_pipe_args {
    int from_fd;
    int to_fd;
};

static atomic_int active_connections = 0;

static bool proxy_try_acquire_connection(void) {
    int current = atomic_load_explicit(&active_connections, memory_order_relaxed);
    while (current < PROXY_MAX_CONNECTIONS) {
        if (atomic_compare_exchange_weak_explicit(&active_connections, &current, current + 1, memory_order_relaxed,
                                                  memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

static void proxy_release_connection(void) {
    atomic_fetch_sub_explicit(&active_connections, 1, memory_order_relaxed);
}

static socklen_t sockaddr_size(const struct sockaddr_storage *addr) {
    switch (addr->ss_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return sizeof(*addr);
    }
}

static uint16_t sockaddr_port(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        return ntohs(in->sin_port);
    }
    if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        return ntohs(in6->sin6_port);
    }
    return 0;
}

static bool sockaddr_is_loopback(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        const uint32_t ip = ntohl(in->sin_addr.s_addr);
        return (ip >> 24) == 127;
    }
    if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr);
    }
    return false;
}

static bool sockaddr_addr_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) {
        return false;
    }
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *in_a = (const struct sockaddr_in *)a;
        const struct sockaddr_in *in_b = (const struct sockaddr_in *)b;
        return in_a->sin_addr.s_addr == in_b->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6_a = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *in6_b = (const struct sockaddr_in6 *)b;
        return memcmp(&in6_a->sin6_addr, &in6_b->sin6_addr, sizeof(in6_a->sin6_addr)) == 0;
    }
    return false;
}

static bool sockaddr_endpoint_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    return sockaddr_port(a) == sockaddr_port(b) && sockaddr_addr_equal(a, b);
}

static bool sockaddr_matches_local_socket(int fd, const struct sockaddr_storage *dst) {
    struct sockaddr_storage local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) {
        return false;
    }
    return sockaddr_endpoint_equal(&local, dst);
}

static bool should_drop_proxy_loop(int client_fd, enum ua2f_mode mode, const struct sockaddr_storage *dst,
                                   uint16_t listen_port) {
    if (sockaddr_port(dst) != listen_port) {
        return false;
    }
    if (sockaddr_is_loopback(dst)) {
        return true;
    }
    if (mode == UA2F_MODE_REDIRECT) {
        return sockaddr_matches_local_socket(client_fd, dst);
    }
    return true;
}

static void format_sockaddr(const struct sockaddr_storage *addr, char *buf, size_t buf_len) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};

    if (getnameinfo((const struct sockaddr *)addr, sockaddr_size(addr), host, sizeof(host), service, sizeof(service),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(buf, buf_len, "<unknown>");
        return;
    }

    if (addr->ss_family == AF_INET6) {
        snprintf(buf, buf_len, "[%s]:%s", host, service);
    } else {
        snprintf(buf, buf_len, "%s:%s", host, service);
    }
}

static bool send_all(int fd, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    while (len > 0) {
        const ssize_t sent = send(fd, p, len, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (sent == 0) {
            return false;
        }
        p += sent;
        len -= (size_t)sent;
    }
    return true;
}

static int copy_raw_loop(int from_fd, int to_fd) {
    uint8_t buf[PROXY_BUFFER_SIZE];

    for (;;) {
        const ssize_t n = recv(from_fd, buf, sizeof(buf), 0);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (!send_all(to_fd, buf, (size_t)n)) {
            return -1;
        }
    }
}

static void shutdown_pair(int fd1, int fd2) {
    shutdown(fd1, SHUT_RDWR);
    shutdown(fd2, SHUT_RDWR);
}

static void *raw_pipe_thread(void *arg) {
    struct raw_pipe_args *pipe_args = (struct raw_pipe_args *)arg;

    (void)copy_raw_loop(pipe_args->from_fd, pipe_args->to_fd);
    shutdown_pair(pipe_args->from_fd, pipe_args->to_fd);

    return NULL;
}

static void rewrite_user_agent_entries(uint8_t *buf, size_t len, const struct http_session *session) {
    const char *replacement = get_replacement_user_agent_string();
    if (replacement == NULL) {
        return;
    }
    const size_t replacement_len = get_replacement_user_agent_string_length();

    for (int i = 0; i < session->ua_entry_count; i++) {
        const size_t offset = session->ua_entries[i].offset;
        const size_t ua_len = session->ua_entries[i].len;
        const size_t replacement_offset = session->ua_entries[i].replacement_offset;
        if (offset > len || ua_len > len - offset) {
            continue;
        }

        memset(buf + offset, ' ', ua_len);
        if (replacement_offset < replacement_len) {
            size_t available = replacement_len - replacement_offset;
            if (available > ua_len) {
                available = ua_len;
            }
            memcpy(buf + offset, replacement + replacement_offset, available);
        }
    }
}

static int copy_rewrite_loop(int from_fd, int to_fd) {
    uint8_t buf[PROXY_BUFFER_SIZE];
    struct http_session session;
    memset(&session, 0, sizeof(session));
    http_parser_init_session(&session);

    for (;;) {
        const ssize_t n = recv(from_fd, buf, sizeof(buf), 0);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        count_tcp_packet();
        session_reset_per_packet(&session, buf);
        const int parse_ret = http_parser_feed(&session, (const char *)buf, (size_t)n);
        if (session.ua_entry_count > 0) {
            rewrite_user_agent_entries(buf, (size_t)n, &session);
            count_user_agent_packet();
        }

        if (!send_all(to_fd, buf, (size_t)n)) {
            return -1;
        }

        try_print_statistics();

        if (parse_ret != 0) {
            return copy_raw_loop(from_fd, to_fd);
        }
    }
}

static bool get_redirect_original_dst(int fd, int family, struct sockaddr_storage *dst, socklen_t *dst_len) {
    memset(dst, 0, sizeof(*dst));

    if (family == AF_INET) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST, &addr, &len) != 0) {
            syslog(LOG_WARNING, "getsockopt SO_ORIGINAL_DST failed: %s", strerror(errno));
            return false;
        }
        memcpy(dst, &addr, sizeof(addr));
        *dst_len = sizeof(addr);
        return true;
    }

    if (family == AF_INET6) {
        struct sockaddr_in6 addr6;
        socklen_t len = sizeof(addr6);
        if (getsockopt(fd, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, &addr6, &len) != 0) {
            syslog(LOG_WARNING, "getsockopt IP6T_SO_ORIGINAL_DST failed: %s", strerror(errno));
            return false;
        }
        memcpy(dst, &addr6, sizeof(addr6));
        *dst_len = sizeof(addr6);
        return true;
    }

    return false;
}

static bool get_tproxy_original_dst(int fd, struct sockaddr_storage *dst, socklen_t *dst_len) {
    memset(dst, 0, sizeof(*dst));
    *dst_len = sizeof(*dst);
    if (getsockname(fd, (struct sockaddr *)dst, dst_len) != 0) {
        syslog(LOG_WARNING, "getsockname original destination failed: %s", strerror(errno));
        return false;
    }
    return true;
}

static int connect_target(const struct sockaddr_storage *dst, socklen_t dst_len) {
    const int fd = socket(dst->ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        syslog(LOG_WARNING, "socket target failed: %s", strerror(errno));
        return -1;
    }

    const int mark = UA2F_PROXY_SO_MARK;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        syslog(LOG_WARNING, "setsockopt SO_MARK failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (connect(fd, (const struct sockaddr *)dst, dst_len) != 0) {
        char dst_buf[128];
        format_sockaddr(dst, dst_buf, sizeof(dst_buf));
        syslog(LOG_WARNING, "connect target %s failed: %s", dst_buf, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void *connection_thread(void *arg) {
    struct connection_args *conn = (struct connection_args *)arg;
    const int client_fd = conn->client_fd;
    const int family = conn->family;
    const enum ua2f_mode mode = conn->mode;
    const uint16_t listen_port = conn->listen_port;
    free(conn);
    int target_fd = -1;

    struct sockaddr_storage dst;
    socklen_t dst_len = sizeof(dst);
    bool got_dst = false;
    if (mode == UA2F_MODE_REDIRECT) {
        got_dst = get_redirect_original_dst(client_fd, family, &dst, &dst_len);
    } else {
        got_dst = get_tproxy_original_dst(client_fd, &dst, &dst_len);
    }

    if (!got_dst) {
        goto done;
    }

    if (should_drop_proxy_loop(client_fd, mode, &dst, listen_port)) {
        char dst_buf[128];
        format_sockaddr(&dst, dst_buf, sizeof(dst_buf));
        syslog(LOG_WARNING, "dropping transparent proxy loop to %s", dst_buf);
        goto done;
    }

    if (dst.ss_family == AF_INET) {
        count_ipv4_packet();
    } else if (dst.ss_family == AF_INET6) {
        count_ipv6_packet();
    }

    target_fd = connect_target(&dst, dst_len);
    if (target_fd < 0) {
        goto done;
    }

    struct raw_pipe_args pipe_args = {
        .from_fd = target_fd,
        .to_fd = client_fd,
    };
    pthread_t pipe_thread;
    bool pipe_started = pthread_create(&pipe_thread, NULL, raw_pipe_thread, &pipe_args) == 0;
    if (!pipe_started) {
        syslog(LOG_WARNING, "pthread_create pipe failed");
        goto done;
    }

    (void)copy_rewrite_loop(client_fd, target_fd);
    shutdown_pair(client_fd, target_fd);

    pthread_join(pipe_thread, NULL);

done:
    if (target_fd >= 0) {
        close(target_fd);
    }
    close(client_fd);
    proxy_release_connection();
    return NULL;
}

static int set_socket_int(int fd, int level, int option, int value, const char *name) {
    if (setsockopt(fd, level, option, &value, sizeof(value)) != 0) {
        syslog(LOG_WARNING, "setsockopt %s failed: %s", name, strerror(errno));
        return -1;
    }
    return 0;
}

static int create_listener(int family, enum ua2f_mode mode, uint16_t listen_port) {
    const int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        syslog(LOG_WARNING, "socket listener failed: %s", strerror(errno));
        return -1;
    }

    if (set_socket_int(fd, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR") != 0) {
        close(fd);
        return -1;
    }

    if (family == AF_INET6 && set_socket_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1, "IPV6_V6ONLY") != 0) {
        close(fd);
        return -1;
    }

    if (mode == UA2F_MODE_TPROXY) {
        if (family == AF_INET) {
            if (set_socket_int(fd, IPPROTO_IP, IP_TRANSPARENT, 1, "IP_TRANSPARENT") != 0) {
                close(fd);
                return -1;
            }
        } else if (set_socket_int(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, 1, "IPV6_TRANSPARENT") != 0) {
            close(fd);
            return -1;
        }
    }

    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(listen_port);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            syslog(LOG_WARNING, "bind IPv4 listener failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(listen_port);
        if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
            syslog(LOG_WARNING, "bind IPv6 listener failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (listen(fd, SOMAXCONN) != 0) {
        syslog(LOG_WARNING, "listen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void close_listeners(struct proxy_listener *listeners, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (listeners[i].fd >= 0) {
            close(listeners[i].fd);
        }
    }
}

int run_proxy(enum ua2f_mode mode, uint16_t listen_port, volatile sig_atomic_t *should_exit) {
    struct proxy_listener listeners[2] = {
        {.fd = -1, .family = AF_INET},
        {.fd = -1, .family = AF_INET6},
    };
    size_t listener_count = 0;

    const int v4 = create_listener(AF_INET, mode, listen_port);
    if (v4 >= 0) {
        listeners[listener_count++] = (struct proxy_listener){.fd = v4, .family = AF_INET};
    }

    const int v6 = create_listener(AF_INET6, mode, listen_port);
    if (v6 >= 0) {
        listeners[listener_count++] = (struct proxy_listener){.fd = v6, .family = AF_INET6};
    }

    if (listener_count == 0) {
        syslog(LOG_ERR, "Failed to start %s proxy listeners on port %u", ua2f_mode_name(mode), (unsigned)listen_port);
        return -1;
    }

    syslog(LOG_INFO, "UA2F %s mode listening on port %u", ua2f_mode_name(mode), (unsigned)listen_port);

    while (!*should_exit) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int max_fd = -1;
        for (size_t i = 0; i < listener_count; i++) {
            FD_SET(listeners[i].fd, &readfds);
            if (listeners[i].fd > max_fd) {
                max_fd = listeners[i].fd;
            }
        }

        struct timeval timeout = {
            .tv_sec = 1,
            .tv_usec = 0,
        };
        const int ready = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_ERR, "select listener failed: %s", strerror(errno));
            close_listeners(listeners, listener_count);
            return -1;
        }
        if (ready == 0) {
            continue;
        }

        for (size_t i = 0; i < listener_count; i++) {
            if (!FD_ISSET(listeners[i].fd, &readfds)) {
                continue;
            }

            const int client_fd = accept(listeners[i].fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                syslog(LOG_WARNING, "accept failed: %s", strerror(errno));
                continue;
            }

            if (!proxy_try_acquire_connection()) {
                syslog(LOG_WARNING, "Too many active proxy connections, rejecting client");
                close(client_fd);
                continue;
            }

            struct connection_args *args = malloc(sizeof(*args));
            if (args == NULL) {
                close(client_fd);
                proxy_release_connection();
                continue;
            }
            args->client_fd = client_fd;
            args->family = listeners[i].family;
            args->mode = mode;
            args->listen_port = listen_port;

            pthread_t tid;
            if (pthread_create(&tid, NULL, connection_thread, args) != 0) {
                syslog(LOG_WARNING, "pthread_create connection failed");
                close(client_fd);
                free(args);
                proxy_release_connection();
                continue;
            }
            pthread_detach(tid);
        }
    }

    close_listeners(listeners, listener_count);
    return 0;
}

#undef PROXY_BUFFER_SIZE
