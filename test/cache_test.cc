#include <gtest/gtest.h>

extern "C" {
#include <cache.h>
}

#define CACHE_TIMEOUT 2

class CacheTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        init_not_http_cache(CACHE_TIMEOUT);
    }
};


TEST_F(CacheTest, CacheAddAndContains)
{
    const char* addr_port = "127.0.0.1:2335";
    cache_add(addr_port);
    EXPECT_TRUE(cache_contains(addr_port));
}

TEST_F(CacheTest, CacheDoesNotContainAfterTimeout)
{
    const char* addr_port = "127.0.0.1:2334";
    cache_add(addr_port);
    sleep(CACHE_TIMEOUT * 2 + 2);
    EXPECT_FALSE(cache_contains(addr_port));
}

TEST_F(CacheTest, CacheContainsAfterRenewal)
{
    const char* addr_port = "127.0.0.1:2333";
    cache_add(addr_port);
    EXPECT_TRUE(cache_contains(addr_port));
    sleep(CACHE_TIMEOUT * 2 + 2);
    EXPECT_FALSE(cache_contains(addr_port));
    cache_add(addr_port);
    EXPECT_TRUE(cache_contains(addr_port));
}
