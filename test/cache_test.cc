#include <gtest/gtest.h>

extern "C" {
#include <cache.h>
#include <syslog.h>
}

class CacheTest : public ::testing::Test {
protected:
    addr_port test_addr{.addr = {.ip4 = 12345}};

    static void SetUpTestSuite() {
        init_not_http_cache(1);

        // redirect syslog to stderr
        openlog("ua2f", LOG_PID | LOG_PERROR, LOG_USER);
    }

    static void TearDownTestSuite() {
        closelog();
    }

    void TearDown() override {
        pthread_rwlock_wrlock(&cacheLock);
        cache *cur, *tmp;
        HASH_ITER(hh, dst_cache, cur, tmp) {
            HASH_DEL(dst_cache, cur);
            free(cur);
        }
        pthread_rwlock_unlock(&cacheLock);
    }
};

TEST_F(CacheTest, CacheInitiallyEmpty) { EXPECT_FALSE(cache_contains(test_addr)); }

TEST_F(CacheTest, AddToCache) {
    cache_add(test_addr);
    EXPECT_TRUE(cache_contains(test_addr));
}

TEST_F(CacheTest, AddAndRemoveFromCache) {
    cache_add(test_addr);
    EXPECT_TRUE(cache_contains(test_addr));
    sleep(3);
    EXPECT_FALSE(cache_contains(test_addr));
}

TEST_F(CacheTest, CacheDoesNotContainNonexistentEntry) {
    addr_port nonexistent_addr{};
    nonexistent_addr.addr.ip4 = 54321;
    EXPECT_FALSE(cache_contains(nonexistent_addr));
}
