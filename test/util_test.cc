#include <gtest/gtest.h>

extern "C" {
#include <util.h>
}

TEST(HttpProtocolTest, RealWorldRequests) {
    const char* getPayload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const char* postPayload = "POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const char* optionsPayload = "OPTIONS /test HTTP/1.1\r\nHost: example.com\r\n\r\n";

    EXPECT_TRUE(is_http_protocol(getPayload, strlen(getPayload))) << "GET method failed";
    EXPECT_TRUE(is_http_protocol(postPayload, strlen(postPayload))) << "POST method failed";
    EXPECT_TRUE(is_http_protocol(optionsPayload, strlen(optionsPayload))) << "OPTIONS method failed";

    const char* invalidPayload = "INVALID string";

    // Check that these cases return false
    EXPECT_FALSE(is_http_protocol(invalidPayload, strlen(invalidPayload))) << "Invalid method passed";
}

TEST(HttpProtocolTest, AllHttpMethods) {
    // Test all supported HTTP methods
    EXPECT_TRUE(is_http_protocol("GET /", 5));
    EXPECT_TRUE(is_http_protocol("POST /", 6));
    EXPECT_TRUE(is_http_protocol("OPTIONS /", 9));
    EXPECT_TRUE(is_http_protocol("HEAD /", 6));
    EXPECT_TRUE(is_http_protocol("PUT /", 5));
    EXPECT_TRUE(is_http_protocol("DELETE /", 8));
    EXPECT_TRUE(is_http_protocol("TRACE /", 7));
    EXPECT_TRUE(is_http_protocol("CONNECT /", 9));
}

TEST(HttpProtocolTest, EdgeCases) {
    // Empty payload
    EXPECT_FALSE(is_http_protocol("", 0));
    
    // Too short for any method
    EXPECT_FALSE(is_http_protocol("G", 1));
    EXPECT_FALSE(is_http_protocol("GE", 2));
    
    // Incomplete methods
    EXPECT_FALSE(is_http_protocol("GE", 2));
    EXPECT_FALSE(is_http_protocol("POS", 3));
    
    // Case sensitivity
    EXPECT_FALSE(is_http_protocol("get /", 5));
    EXPECT_FALSE(is_http_protocol("Post /", 6));
    
    // Non-HTTP protocols
    EXPECT_FALSE(is_http_protocol("FTP /", 5));
    EXPECT_FALSE(is_http_protocol("SSH /", 5));
    EXPECT_FALSE(is_http_protocol("HTTPS /", 7));
}
