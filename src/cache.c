#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cache.h"

#include "third/uthash.h"

pthread_rwlock_t cacheLock;

struct cache *dst_cache = NULL;

typedef struct {
    int check_interval;
    pthread_rwlock_t* lock;
    struct cache** table;
} thread_args;

_Noreturn static void* check_cache(void* arg) {
    pthread_detach(pthread_self());

    const __auto_type args = (thread_args *)arg;
    const __auto_type lock = args->lock;
    const __auto_type check_interval = args->check_interval;
    const __auto_type cache_ptr = args->table;
    free(args);

    while (true) {
        pthread_rwlock_wrlock(lock);

        const time_t now = time(NULL);
        struct cache *cur, *tmp;

        HASH_ITER(hh, *cache_ptr, cur, tmp) {
            if (difftime(now, cur->last_time) > check_interval) {
                HASH_DEL(*cache_ptr, cur);
                free(cur);
            }
        }

        pthread_rwlock_unlock(lock);

        sleep(check_interval);
    }
}

void init_not_http_cache(const int interval) {
    if (pthread_rwlock_init(&cacheLock, NULL) != 0) {
        syslog(LOG_ERR, "Failed to init cache lock");
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "Cache lock initialized");

    pthread_t cleanup_thread;

    thread_args* arg = malloc(sizeof(thread_args));
    arg->check_interval = interval;
    arg->lock = &cacheLock;
    arg->table = &dst_cache;

    const __auto_type ret = pthread_create(&cleanup_thread, NULL, check_cache, arg);
    if (ret) {
        syslog(LOG_ERR, "Failed to create cleanup thread: %s", strerror(ret));
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "Cleanup thread created");
}

bool cache_contains(struct addr_port target) {
    pthread_rwlock_wrlock(&cacheLock);

    struct cache *s;
    HASH_FIND(hh, dst_cache, &target, sizeof(struct addr_port), s);
    if (s != NULL) {
        s->last_time = time(NULL);
    }

    pthread_rwlock_unlock(&cacheLock);

    return s != NULL;
}

void cache_add(struct addr_port addr_port) {
    pthread_rwlock_wrlock(&cacheLock);

    struct cache *s;

    HASH_FIND(hh, dst_cache, &addr_port, sizeof(struct addr_port), s);
    if (s == NULL) {
        s = malloc(sizeof(struct cache));
        memcpy(&s->target.addr, &addr_port, sizeof(struct addr_port));
        HASH_ADD(hh, dst_cache, target.addr, sizeof(struct addr_port), s);
    }
    s->last_time = time(NULL);

    pthread_rwlock_unlock(&cacheLock);
}
