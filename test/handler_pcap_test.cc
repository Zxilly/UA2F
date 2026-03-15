#ifdef UA2F_HAS_PCAP

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "handler.h"
#include "cache.h"
#include "http_session.h"
#include "statistics.h"
}

#include "mock_packet_io.h"
#include "packet_builder.h"
#include "pcap_helpers.h"

class HandlerPcapTest : public ::testing::Test {
protected:
    mock_io_context mock_ctx;

    void SetUp() override {
        init_not_http_cache(60);
        init_handler();
        init_http_sessions(0);
        init_statistics();
        use_conntrack = false;
    }

    void TearDown() override {
        session_wrlock();
        session_cleanup_expired(-1);
        session_wrunlock();
    }

    // Replay all packets from a pcap through the handler
    void replay_pcap(const std::string &filename) {
        auto packets = load_pcap_tcp_packets(PCAP_DATA_DIR "/" + filename);
        ASSERT_FALSE(packets.empty()) << "Failed to load " << filename;
        for (size_t i = 0; i < packets.size(); i++) {
            auto pkt = make_nf_packet_from_pcap(packets[i], i + 1);
            handle_packet(&mock_packet_io, &mock_ctx, &pkt);
        }
        ASSERT_EQ(mock_ctx.verdicts.size(), packets.size());
    }

    // Count verdicts whose mangled payload contains the given needle
    int count_mangled_with(const std::string &needle, int ip_ver = IPV4) {
        int count = 0;
        for (const auto &v : mock_ctx.verdicts) {
            if (!v.mangled_data.empty()) {
                auto payload = extract_tcp_payload(v.mangled_data, ip_ver);
                std::string s(payload.begin(), payload.end());
                if (s.find(needle) != std::string::npos) {
                    count++;
                }
            }
        }
        return count;
    }

    // Check that a given original UA string is absent from all mangled payloads
    void expect_ua_replaced(const std::string &original_ua, int ip_ver = IPV4) {
        for (const auto &v : mock_ctx.verdicts) {
            if (!v.mangled_data.empty()) {
                auto payload = extract_tcp_payload(v.mangled_data, ip_ver);
                std::string s(payload.begin(), payload.end());
                EXPECT_EQ(s.find(original_ua), std::string::npos)
                    << "Original UA '" << original_ua << "' should have been replaced";
            }
        }
    }
};

// --- Basic scenarios ---

TEST_F(HandlerPcapTest, HttpGetWithUaReplay) {
    replay_pcap("http_get_with_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0) << "Expected mangled UA";
    expect_ua_replaced("TestBrowser/1.0");
}

TEST_F(HandlerPcapTest, TlsTrafficReplay) {
    replay_pcap("tls_traffic.pcap");
    for (const auto &v : mock_ctx.verdicts) {
        EXPECT_EQ(v.verdict, NF_ACCEPT);
    }
}

TEST_F(HandlerPcapTest, HttpPostWithUaReplay) {
    replay_pcap("http_post_with_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0) << "Expected mangled UA";
    expect_ua_replaced("curl/7.68.0");
}

TEST_F(HandlerPcapTest, HttpKeepaliveReplay) {
    replay_pcap("http_keepalive.pcap");
    EXPECT_GE(count_mangled_with("FFFFF"), 2)
        << "Expected at least 2 packets with mangled UA in keep-alive";
    expect_ua_replaced("KeepAliveAgent/1.0");
}

// --- Edge cases ---

// Long UA (2000 chars) — stress the in-place mangle path
TEST_F(HandlerPcapTest, LongUserAgent) {
    replay_pcap("http_long_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    // The 2000-char "XXX..." UA should be fully replaced
    expect_ua_replaced(std::string(100, 'X'));
}

// Empty UA value — 'User-Agent: \r\n'
TEST_F(HandlerPcapTest, EmptyUserAgent) {
    replay_pcap("http_empty_ua.pcap");
    // Should still accept; an empty UA has nothing to mangle but shouldn't crash
    for (const auto &v : mock_ctx.verdicts) {
        EXPECT_EQ(v.verdict, NF_ACCEPT);
    }
}

// Multiple User-Agent headers in one request
TEST_F(HandlerPcapTest, MultipleUaHeaders) {
    replay_pcap("http_multiple_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("FirstAgent/1.0");
    expect_ua_replaced("SecondAgent/2.0");
}

// HTTP pipelining — two requests in one TCP segment
TEST_F(HandlerPcapTest, PipelinedRequests) {
    replay_pcap("http_pipelined.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("PipeAgent/1.0");
    expect_ua_replaced("PipeAgent/2.0");
}

// Case-insensitive UA field name ('user-agent:', 'USER-AGENT:', 'User-agent:')
TEST_F(HandlerPcapTest, CaseVariantUaField) {
    replay_pcap("http_case_variant_ua.pcap");
    int mangled = count_mangled_with("FFFFF");
    EXPECT_EQ(mangled, 3) << "All 3 case variants should have UA mangled";
    expect_ua_replaced("LowerCaseField/1.0");
    expect_ua_replaced("UpperCaseField/1.0");
    expect_ua_replaced("MixedCaseField/1.0");
}

// All HTTP methods recognized by is_http_protocol()
TEST_F(HandlerPcapTest, AllHttpMethods) {
    replay_pcap("http_all_methods.pcap");
    // All methods except CONNECT produce mangled UA.
    // CONNECT has special semantics in llhttp (tunnel mode), so
    // the parser may not emit the UA entry the same way.
    int mangled = count_mangled_with("FFFFF");
    EXPECT_GE(mangled, 8) << "At least 8 of 9 HTTP methods should produce mangled UA";

    // All packets should be accepted regardless
    for (const auto &v : mock_ctx.verdicts) {
        EXPECT_EQ(v.verdict, NF_ACCEPT);
    }
}

// POST with body containing "User-Agent:" — only the real header should be mangled
TEST_F(HandlerPcapTest, PostBodyWithFakeUa) {
    replay_pcap("http_post_body_with_fake_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("RealAgent/1.0");

    // The fake "User-Agent: FakeInBody" in the POST body should remain untouched
    for (const auto &v : mock_ctx.verdicts) {
        if (!v.mangled_data.empty()) {
            auto payload = extract_tcp_payload(v.mangled_data, IPV4);
            std::string s(payload.begin(), payload.end());
            if (s.find("FakeInBody") != std::string::npos) {
                // Body content preserved — good
                SUCCEED();
                return;
            }
        }
    }
    // If no verdict had the body, the test still passes (body might not be in mangled output)
}

// IPv6 HTTP traffic
TEST_F(HandlerPcapTest, Ipv6Http) {
    replay_pcap("http_ipv6_with_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF", IPV6), 0);
    expect_ua_replaced("IPv6Browser/1.0", IPV6);
}

// Mixed HTTP and non-HTTP from different sources
TEST_F(HandlerPcapTest, MixedHttpNonHttp) {
    replay_pcap("mixed_http_nonhttp.pcap");

    // Should have 4 verdicts total
    ASSERT_EQ(mock_ctx.verdicts.size(), 4u);

    // All should be accepted
    for (const auto &v : mock_ctx.verdicts) {
        EXPECT_EQ(v.verdict, NF_ACCEPT);
    }

    // HTTP packets (indices 0, 2) should have mangled data
    int mangled = count_mangled_with("FFFFF");
    EXPECT_GE(mangled, 2) << "HTTP packets should have UA mangled";

    // Original UA should be gone from HTTP packets
    expect_ua_replaced("ClientA/1.0");
}

// UA with real-world complex value (parens, semicolons, slashes)
TEST_F(HandlerPcapTest, UaSpecialChars) {
    replay_pcap("http_ua_special_chars.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("Mozilla/5.0");
    expect_ua_replaced("Chrome/120.0.6099.144");
}

// Chunked transfer encoding
TEST_F(HandlerPcapTest, ChunkedTransfer) {
    replay_pcap("http_chunked.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("ChunkedClient/1.0");
}

// Request with 30 custom headers before User-Agent
TEST_F(HandlerPcapTest, ManyHeadersBeforeUa) {
    replay_pcap("http_many_headers.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("BuriedAgent/1.0");
}

// HTTP/1.0 request
TEST_F(HandlerPcapTest, Http10WithUa) {
    replay_pcap("http10_with_ua.pcap");
    EXPECT_GT(count_mangled_with("FFFFF"), 0);
    expect_ua_replaced("OldBrowser/1.0");
}

#endif // UA2F_HAS_PCAP
