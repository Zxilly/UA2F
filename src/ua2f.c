#include "cli.h"
#include "handler.h"
#include "statistics.h"
#include "third/nfqueue-mnl.h"
#include "util.h"

#ifdef UA2F_ENABLE_UCI
#include "config.h"
#endif

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

volatile int should_exit = false;

void signal_handler(const int signum) {
    syslog(LOG_ERR, "Signal %s received, exiting...", strsignal(signum));
    should_exit = true;
}

int main(const int argc, char *argv[]) {
    openlog("UA2F", LOG_PID, LOG_SYSLOG);

#ifdef UA2F_ENABLE_UCI
    load_config();
#else
    syslog(LOG_INFO, "uci support is disabled");
#endif

    try_print_info(argc, argv);

    init_statistics();
    init_handler();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);

    struct nf_queue queue[1] = {0};
    struct nf_buffer buf[1] = {0};

    const __auto_type ret = nfqueue_open(queue, QUEUE_NUM, 0);
    if (!ret) {
        syslog(LOG_ERR, "Failed to open nfqueue");
        return EXIT_FAILURE;
    }

    while (!should_exit) {
        if (nfqueue_receive(queue, buf, 0) == IO_READY) {
            struct nf_packet packet[1];
            int status;
            while (status = nfqueue_next(buf, packet)) {
                if (status == IO_READY) {
                    handle_packet(queue, packet);
                } else if (status == IO_ERROR && buf->nlh->nlmsg_type == NLMSG_ERROR) {
                    __auto_type err = (struct nlmsgerr *) NLMSG_DATA(buf->nlh);
                    if (-err->error == ENOTSUP) {
                        fprintf(stderr,"NETLINK error: %s\n",strerror(-err->error));
                        free(buf->data);
                        nfqueue_close(queue);
                        return EXIT_FAILURE;
                    }
                }
            }
        }
    }

    free(buf->data);
    nfqueue_close(queue);
}

#pragma clang diagnostic pop
