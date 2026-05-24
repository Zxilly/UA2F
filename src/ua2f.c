#include "assert.h"
#include "backtrace.h"
#include "cli.h"
#include "handler.h"
#include "http_session.h"
#include "mode.h"
#include "proxy.h"
#include "session_cleaner.h"
#include "statistics.h"
#include "util.h"
#ifdef UA2F_HAS_CONNTRACK_LISTENER
#include "conntrack_listener.h"
#endif
#ifdef UA2F_ENABLE_UCI
#include "config.h"
#endif
#include "third/nfqueue-mnl/nfqueue-mnl.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

volatile sig_atomic_t should_exit = 0;

void signal_handler(int sig) {
    (void)sig;
    should_exit = 1;
}

int parse_packet(const struct nf_queue *queue, struct nf_buffer *buf) {
    struct nf_packet packet[1] = {0};

    while (!should_exit) {
        const __auto_type status = nfqueue_next(buf, packet);
        if (status == IO_READY) {
            handle_packet(&nfqueue_packet_io, (void *)queue, packet);
        } else {
            return status;
        }
    }

    return IO_ERROR;
}

int read_buffer(struct nf_queue *queue, struct nf_buffer *buf) {
    // Use timeout to allow periodic checking of should_exit flag during signal handling
    const __auto_type buf_status = nfqueue_receive(queue, buf, 1000);
    if (buf_status == IO_READY) {
        return parse_packet(queue, buf);
    }
    return buf_status;
}

bool retry_without_conntrack(struct nf_queue *queue) {
    nfqueue_close(queue);

    syslog(LOG_INFO, "Retry without conntrack");
    const __auto_type ret = nfqueue_open(queue, QUEUE_NUM, 0, true);
    if (!ret) {
        syslog(LOG_ERR, "Failed to open nfqueue with conntrack disabled");
        return false;
    }
    return true;
}

void main_loop(struct nf_queue *queue) {
    struct nf_buffer buf[1] = {0};
    bool retried = false;

    while (!should_exit) {
        if (read_buffer(queue, buf) == IO_ERROR) {
            if (!retried) {
                retried = true;
                if (!retry_without_conntrack(queue)) {
                    break;
                }
            } else {
                should_exit = true;
                break;
            }
        }
    }

    free(buf->data);
}

int main(const int argc, char *argv[]) {
    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    // Register signal handlers for graceful shutdown
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

#ifdef UA2F_ENABLE_UCI
    load_config();
#else
    syslog(LOG_INFO, "uci support is disabled");
#endif

    try_print_info(argc, argv);

    enum ua2f_mode mode = UA2F_MODE_NFQUEUE;
    uint16_t listen_port = UA2F_DEFAULT_PROXY_PORT;
#ifdef UA2F_ENABLE_UCI
    mode = config.mode;
    listen_port = config.listen_port;
#endif
    if (cli_mode_set) {
        mode = cli_mode;
    }
    if (cli_listen_port_set) {
        listen_port = cli_listen_port;
    }

    require_root();

    init_statistics();
    init_handler();

#ifdef UA2F_ENABLE_UCI
    init_http_sessions(config.max_http_sessions);
    init_session_cleaner(config.session_ttl, 60);
#else
    init_http_sessions(UA2F_DEFAULT_MAX_HTTP_SESSIONS);
    init_session_cleaner(300, 60);
#endif

    UA2F_INIT_BACKTRACE();

    if (mode == UA2F_MODE_REDIRECT || mode == UA2F_MODE_TPROXY) {
        syslog(LOG_INFO, "Starting in %s mode on listen port %u", ua2f_mode_name(mode), (unsigned)listen_port);
        if (run_proxy(mode, listen_port, &should_exit) != 0) {
            return EXIT_FAILURE;
        }
        syslog(LOG_INFO, "UA2F exiting gracefully");
        return EXIT_SUCCESS;
    }

    syslog(LOG_INFO, "Starting in NFQUEUE mode on queue %d", QUEUE_NUM);

    struct nf_queue queue[1] = {0};

    const __auto_type ret = nfqueue_open(queue, QUEUE_NUM, 0, false);
    if (!ret) {
        syslog(LOG_ERR, "Failed to open nfqueue");
        return EXIT_FAILURE;
    }
    assert(queue->queue_num == QUEUE_NUM);
    assert(queue->nl_socket != NULL);

#ifdef UA2F_HAS_CONNTRACK_LISTENER
    init_conntrack_listener();
#endif

    main_loop(queue);

    nfqueue_close(queue);

    syslog(LOG_INFO, "UA2F exiting gracefully");

    return EXIT_SUCCESS;
}

#pragma clang diagnostic pop
