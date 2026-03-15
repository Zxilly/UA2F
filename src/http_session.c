#include "http_session.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/syslog.h>

static struct http_session *sessions = NULL;
static pthread_rwlock_t session_lock;
static int max_session_count = 0;
static int current_session_count = 0;

void init_http_sessions(int max_sessions) {
    max_session_count = max_sessions;
    current_session_count = 0;
    sessions = NULL;

    if (pthread_rwlock_init(&session_lock, NULL) != 0) {
        syslog(LOG_ERR, "Failed to init http_session lock");
        exit(EXIT_FAILURE);
    }
}

struct session_key session_key_from_connid(uint32_t conn_id) {
    struct session_key key;
    memset(&key, 0, sizeof(key));
    key.use_conn_id = true;
    key.conn_id = conn_id;
    return key;
}

struct session_key session_key_from_tuple(const struct ip_tuple *tuple) {
    struct session_key key;
    memset(&key, 0, sizeof(key));
    key.use_conn_id = false;
    memcpy(&key.tuple, tuple, sizeof(struct ip_tuple));
    return key;
}

struct http_session *session_find(const struct session_key *key) {
    struct http_session *s = NULL;
    HASH_FIND(hh, sessions, key, sizeof(struct session_key), s);
    return s;
}

struct http_session *session_create(const struct session_key *key) {
    if (max_session_count > 0 && current_session_count >= max_session_count) {
        return NULL;
    }

    struct http_session *s = calloc(1, sizeof(struct http_session));
    if (s == NULL) {
        return NULL;
    }

    memcpy(&s->key, key, sizeof(struct session_key));
    s->last_active = time(NULL);

    HASH_ADD(hh, sessions, key, sizeof(struct session_key), s);
    current_session_count++;

    return s;
}

void session_delete(struct http_session *session) {
    if (session == NULL) {
        return;
    }
    HASH_DEL(sessions, session);
    current_session_count--;
    free(session);
}

void session_delete_by_key(const struct session_key *key) {
    struct http_session *s = session_find(key);
    if (s != NULL) {
        session_delete(s);
    }
}

int session_count(void) {
    return current_session_count;
}

int session_cleanup_expired(int ttl_seconds) {
    const time_t now = time(NULL);
    int deleted = 0;

    struct http_session *cur, *tmp;
    HASH_ITER(hh, sessions, cur, tmp) {
        if (ttl_seconds < 0 || difftime(now, cur->last_active) > ttl_seconds) {
            session_delete(cur);
            deleted++;
        }
    }

    return deleted;
}

void session_wrlock(void) {
    pthread_rwlock_wrlock(&session_lock);
}

void session_wrunlock(void) {
    pthread_rwlock_unlock(&session_lock);
}

void session_reset_per_packet(struct http_session *session, const void *tcp_payload_base) {
    session->ua_entry_count = 0;
    session->tcp_payload_base = tcp_payload_base;
    // last_active is updated in session_create and by the cleaner's TTL check.
    // Avoid time() syscall on every packet — the TTL is coarse (300s default).
}

void session_reset_per_message(struct http_session *session) {
    session->field_buf_len = 0;
    session->field_matched = false;
    session->field_too_long = false;
    session->last_was_value = false;
    session->in_ua_value = false;
}
