#include "conntrack_listener.h"
#include "http_session.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int destroy_cb(enum nf_conntrack_msg_type type __attribute__((unused)),
                      struct nf_conntrack *ct,
                      void *data __attribute__((unused))) {
    const uint32_t conn_id = nfct_get_attr_u32(ct, ATTR_ID);
    const struct session_key key = session_key_from_connid(conn_id);

    session_wrlock();
    struct http_session *s = session_find(&key);
    if (s != NULL) {
        session_delete(s);
    }
    session_wrunlock();

    return NFCT_CB_CONTINUE;
}

static struct nfct_handle *open_conntrack(void) {
    struct nfct_handle *h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY);
    if (h == NULL) {
        syslog(LOG_ERR, "Failed to open conntrack handle for destroy events");
        return NULL;
    }
    nfct_callback_register(h, NFCT_T_DESTROY, destroy_cb, NULL);
    return h;
}

static void *listener_thread(void *arg __attribute__((unused))) {
    struct nfct_handle *h = open_conntrack();
    if (h == NULL) {
        return NULL;
    }

    syslog(LOG_INFO, "Conntrack listener started");
    int consecutive_errors = 0;

    while (1) {
        const int ret = nfct_catch(h);
        if (ret == -1) {
            consecutive_errors++;
            syslog(LOG_ERR, "Conntrack catch error: %s (consecutive: %d)", strerror(errno), consecutive_errors);

            if (consecutive_errors >= 10) {
                syslog(LOG_WARNING, "Too many consecutive conntrack errors, reopening handle");
                nfct_close(h);
                h = open_conntrack();
                if (h == NULL) {
                    syslog(LOG_ERR, "Failed to reopen conntrack handle, listener exiting");
                    return NULL;
                }
                consecutive_errors = 0;
            }

            sleep(1);
        } else {
            consecutive_errors = 0;
        }
    }
}

void init_conntrack_listener(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, listener_thread, NULL) != 0) {
        syslog(LOG_ERR, "Failed to create conntrack listener thread");
        return;
    }
    pthread_detach(tid);
}
