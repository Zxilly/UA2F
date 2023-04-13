#ifndef UA2F_RWMUTEX_H
#define UA2F_RWMUTEX_H

#include <stdio.h>
#include <threads.h>
#include <stdatomic.h>

typedef struct {
    mtx_t write_mtx;
    mtx_t read_mtx;
    atomic_int read_counter;
} RWMutex;

void rw_mutex_init(RWMutex *rw_mutex) {
    mtx_init(&rw_mutex->write_mtx, mtx_plain);
    mtx_init(&rw_mutex->read_mtx, mtx_plain);
    rw_mutex->read_counter = ATOMIC_VAR_INIT(0);
}

void rw_mutex_destroy(RWMutex *rw_mutex) {
    mtx_destroy(&rw_mutex->write_mtx);
    mtx_destroy(&rw_mutex->read_mtx);
}

void rw_mutex_read_lock(RWMutex *rw_mutex) {
    mtx_lock(&rw_mutex->read_mtx);
    __auto_type read_count = atomic_fetch_add(&rw_mutex->read_counter, 1);
    if (read_count == 0) {
        mtx_lock(&rw_mutex->write_mtx);
    }
    mtx_unlock(&rw_mutex->read_mtx);
}

void rw_mutex_read_unlock(RWMutex *rw_mutex) {
    mtx_lock(&rw_mutex->read_mtx);
    __auto_type read_count = atomic_fetch_sub(&rw_mutex->read_counter, 1);
    if (read_count == 1) {
        mtx_unlock(&rw_mutex->write_mtx);
    }
    mtx_unlock(&rw_mutex->read_mtx);
}

void rw_mutex_write_lock(RWMutex *rw_mutex) {
    mtx_lock(&rw_mutex->write_mtx);
}

void rw_mutex_write_unlock(RWMutex *rw_mutex) {
    mtx_unlock(&rw_mutex->write_mtx);
}

#endif //UA2F_RWMUTEX_H
