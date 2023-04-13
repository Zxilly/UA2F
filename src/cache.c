#include "cache.h"
#include "hashmap.h"
#include "rwmutex.h"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/syslog.h>
#include <stdbool.h>

RWMutex lock;

const double CACHE_TIMEOUT = 600;

struct hashmap_s no_http_dst_cache;

static int iterate_pairs(void *const context, struct hashmap_element_s *const e) {
    __auto_type current_time = (time_t) context;

    __auto_type store_time = (time_t) e->data;

    if (difftime(current_time, store_time) > CACHE_TIMEOUT) {
        return -1;
    }

    return 0;
}

_Noreturn static void check_cache() {
    while (true) {
        rw_mutex_write_lock(&lock);

        __auto_type current_time = time(NULL);

        hashmap_iterate_pairs(&no_http_dst_cache, iterate_pairs, (void *) current_time);

        rw_mutex_read_unlock(&lock);

        // wait for 1 minute
        thrd_sleep(&(struct timespec) {60, 0}, NULL);
    }
}

void init_cache() {
    rw_mutex_init(&lock);
    hashmap_create(1024, &no_http_dst_cache);

    pthread_t cleanup_thread;
    __auto_type ret = pthread_create(&cleanup_thread, NULL, (void *(*)(void *)) check_cache, NULL);
    if (ret) {
        syslog(LOG_ERR, "Failed to create cleanup thread: %d", ret);
        exit(EXIT_FAILURE);
    }
}

bool check_addr_port(const char *addr_port, const int len) {
    rw_mutex_read_lock(&lock);
    __auto_type ret = hashmap_get(&no_http_dst_cache, addr_port, len) != NULL;
    rw_mutex_read_unlock(&lock);

    rw_mutex_write_lock(&lock);
    if (ret) {
        hashmap_put(&no_http_dst_cache, addr_port, len, (void *) time(NULL));
    }
    rw_mutex_write_unlock(&lock);

    return ret;
}