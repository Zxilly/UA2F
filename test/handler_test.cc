#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "handler.h"
#include "cache.h"
#include "http_session.h"
#include "http_parser_ua.h"
#include "statistics.h"
}

#include "mock_packet_io.h"
#include "packet_builder.h"

namespace {

// Compute Internet checksums from bytes, independently of libnetfilter_queue.
uint16_t read_network_u16(const uint8_t *data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

void write_network_u16(uint8_t *data, uint16_t value) {
    data[0] = static_cast<uint8_t>(value >> 8);
    data[1] = static_cast<uint8_t>(value);
}

uint32_t checksum_sum(const uint8_t *data, size_t len, uint32_t sum = 0) {
    while (len >= 2) {
        sum += read_network_u16(data);
        data += 2;
        len -= 2;
    }
    if (len != 0) {
        sum += static_cast<uint32_t>(data[0]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return sum;
}

uint32_t tcp_checksum_sum(const std::vector<uint8_t> &packet, int ip_version, size_t tcp_offset) {
    const size_t tcp_len = packet.size() - tcp_offset;
    const size_t address_offset = ip_version == IPV4 ? 12 : 8;
    const size_t address_len = ip_version == IPV4 ? 8 : 32;
    uint32_t sum = checksum_sum(packet.data() + address_offset, address_len);
    sum += IPPROTO_TCP + static_cast<uint32_t>(tcp_len);
    return checksum_sum(packet.data() + tcp_offset, tcp_len, sum);
}

void set_packet_checksums(std::vector<uint8_t> &packet, int ip_version, size_t tcp_offset) {
    if (ip_version == IPV4) {
        write_network_u16(packet.data() + 2, static_cast<uint16_t>(packet.size()));
        write_network_u16(packet.data() + 10, 0);
        write_network_u16(packet.data() + 10,
                          static_cast<uint16_t>(~checksum_sum(packet.data(), tcp_offset)));
    } else {
        write_network_u16(packet.data() + 4, static_cast<uint16_t>(packet.size() - 40));
    }
    write_network_u16(packet.data() + tcp_offset + 16, 0);
    write_network_u16(packet.data() + tcp_offset + 16,
                      static_cast<uint16_t>(~tcp_checksum_sum(packet, ip_version, tcp_offset)));
}

void expect_valid_packet_checksums(const std::vector<uint8_t> &packet, int ip_version, size_t tcp_offset) {
    ASSERT_GE(packet.size(), tcp_offset + 20);
    if (ip_version == IPV4) {
        EXPECT_EQ(read_network_u16(packet.data() + 2), packet.size());
        EXPECT_EQ(checksum_sum(packet.data(), tcp_offset), 0xffffU);
    } else {
        EXPECT_EQ(read_network_u16(packet.data() + 4), packet.size() - 40);
    }
    EXPECT_EQ(tcp_checksum_sum(packet, ip_version, tcp_offset), 0xffffU);
}

} // namespace

class HandlerTest : public ::testing::Test {
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
        // Clean up sessions
        session_wrlock();
        session_cleanup_expired(-1);
        session_wrunlock();
    }

    // Helper: build an IPv4 HTTP packet with given payload
    struct nf_packet make_http_packet(const char *http_data, uint32_t pkt_id = 1) {
        auto raw = build_ipv4_tcp_packet(
            htonl(0x0a000001), htonl(0x0a000002),
            12345, 80,
            http_data, strlen(http_data));
        return make_nf_packet(raw, pkt_id, IPV4);
    }

    // Helper: build an IPv4 HTTP packet with conntrack
    struct nf_packet make_http_packet_ct(const char *http_data, uint32_t pkt_id = 1,
                                          uint32_t conn_id = 100) {
        auto raw = build_ipv4_tcp_packet(
            htonl(0x0a000001), htonl(0x0a000002),
            12345, 80,
            http_data, strlen(http_data));
        return make_nf_packet_with_conntrack(raw, pkt_id, IPV4, conn_id,
                                              htonl(0x0a000001), htonl(0x0a000002), 12345, 80);
    }
};

// 1. HTTP GET with User-Agent → NF_ACCEPT, UA replaced
TEST_F(HandlerTest, HttpGetWithUserAgent) {
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    auto pkt = make_http_packet(req);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mangled_data.empty());

    // Extract TCP payload from mangled data and verify UA was replaced
    auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV4);
    ASSERT_FALSE(payload.empty());
    std::string payload_str(payload.begin(), payload.end());

    // The original "Mozilla/5.0" (11 chars) should be replaced with "FFFFFFFFFFF"
    EXPECT_NE(payload_str.find("FFFFFFFFFFF"), std::string::npos);
    EXPECT_EQ(payload_str.find("Mozilla/5.0"), std::string::npos);
}

// 2. HTTP GET without User-Agent → NF_ACCEPT without redundant replacement data
TEST_F(HandlerTest, HttpGetWithoutUserAgent) {
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto pkt = make_http_packet(req);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[0].mangled_data.empty());
}

// 3. Non-HTTP traffic → NF_ACCEPT, no mangling
TEST_F(HandlerTest, NonHttpTraffic) {
    const char *data = "\x16\x03\x01\x02\x00\x01\x00"; // TLS ClientHello-like
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 443,
        data, 7);
    auto pkt = make_nf_packet(raw, 1, IPV4);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mark.should_set);
}

// 4. Empty TCP payload (ACK) → NF_ACCEPT
TEST_F(HandlerTest, EmptyTcpPayload) {
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 80,
        nullptr, 0);
    auto pkt = make_nf_packet(raw, 1, IPV4);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
}

// 5. IPv6 HTTP with User-Agent → NF_ACCEPT, mangled
TEST_F(HandlerTest, Ipv6HttpWithUserAgent) {
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBrowser\r\n\r\n";

    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr dst = IN6ADDR_LOOPBACK_INIT;
    // Make them different
    dst.s6_addr[15] = 2;

    auto raw = build_ipv6_tcp_packet(src, dst, 12345, 80, req, strlen(req));
    auto pkt = make_nf_packet(raw, 1, IPV6);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mangled_data.empty());

    auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV6);
    std::string payload_str(payload.begin(), payload.end());
    EXPECT_EQ(payload_str.find("TestBrowser"), std::string::npos);
}

// 6. UA replacement preserves payload length
TEST_F(HandlerTest, UaReplacementPreservesLength) {
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: MyCustomAgent/1.0\r\n\r\n";
    auto raw_original = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 80,
        req, strlen(req));
    auto pkt = make_nf_packet(raw_original, 1, IPV4);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].mangled_data.size(), raw_original.size());
}

// 7. Pipelined requests → both UAs mangled
TEST_F(HandlerTest, PipelinedRequests) {
    std::string req =
        "GET /page1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Agent1\r\n\r\n"
        "GET /page2 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Agent2\r\n\r\n";
    auto pkt = make_http_packet(req.c_str());

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mangled_data.empty());

    auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV4);
    std::string payload_str(payload.begin(), payload.end());
    EXPECT_EQ(payload_str.find("Agent1"), std::string::npos);
    EXPECT_EQ(payload_str.find("Agent2"), std::string::npos);
}

// 8. Conntrack: cached destination → CONNMARK_NOT_HTTP, skip processing
TEST_F(HandlerTest, ConntrackCachedDestination) {
    use_conntrack = true;

    // First, send a non-HTTP packet to cache the destination
    const char *data = "\x16\x03\x01\x02\x00\x01\x00";
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 443,
        data, 7);
    auto pkt1 = make_nf_packet_with_conntrack(raw, 1, IPV4, 100,
                                               htonl(0x0a000001), htonl(0x0a000002), 12345, 443);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.should_set, true);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_NOT_HTTP);

    // Second packet to same destination should hit cache
    mock_ctx.verdicts.clear();
    auto raw2 = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12346, 443,
        data, 7);
    auto pkt2 = make_nf_packet_with_conntrack(raw2, 2, IPV4, 101,
                                               htonl(0x0a000001), htonl(0x0a000002), 12346, 443);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_NOT_HTTP);

    use_conntrack = false;
}

// 9. Conntrack: new HTTP → CONNMARK_HTTP
TEST_F(HandlerTest, ConntrackNewHttp) {
    use_conntrack = true;

    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n";
    auto pkt = make_http_packet_ct(req, 1, 200);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_HTTP);

    use_conntrack = false;
}

// 10. Conntrack: non-HTTP → CONNMARK_NOT_HTTP, added to cache
TEST_F(HandlerTest, ConntrackNonHttp) {
    use_conntrack = true;

    const char *data = "\x16\x03\x01\x02\x00\x01\x00";
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000003),
        12345, 8443,
        data, 7);
    auto pkt = make_nf_packet_with_conntrack(raw, 1, IPV4, 300,
                                              htonl(0x0a000001), htonl(0x0a000003), 12345, 8443);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_NOT_HTTP);

    use_conntrack = false;
}

// 11. Session limit → NF_DROP
TEST_F(HandlerTest, SessionLimitDrop) {
    // Reinit with limit of 1 session
    init_http_sessions(1);

    const char *req1 = "GET /1 HTTP/1.1\r\nHost: a.com\r\nUser-Agent: A\r\n\r\n";
    auto raw1 = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        10001, 80,
        req1, strlen(req1));
    auto pkt1 = make_nf_packet(raw1, 1, IPV4);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);

    // Second session from different source should be dropped
    const char *req2 = "GET /2 HTTP/1.1\r\nHost: b.com\r\nUser-Agent: B\r\n\r\n";
    auto raw2 = build_ipv4_tcp_packet(
        htonl(0x0a000003), htonl(0x0a000004),
        10002, 80,
        req2, strlen(req2));
    auto pkt2 = make_nf_packet(raw2, 2, IPV4);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    EXPECT_EQ(mock_ctx.verdicts[1].verdict, NF_DROP);

    // Reset to unlimited
    init_http_sessions(0);
}

// 12. Parse error mid-session → session deleted, NF_ACCEPT
TEST_F(HandlerTest, ParseErrorMidSession) {
    // Send valid HTTP first to create a session
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
    auto pkt1 = make_http_packet(req, 1);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);

    // Send garbage on same connection to trigger parse error
    // Use same src/dst so it maps to the same session
    const char *garbage = "INVALID GARBAGE DATA\r\n\r\n";
    auto raw2 = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 80,
        garbage, strlen(garbage));
    auto pkt2 = make_nf_packet(raw2, 2, IPV4);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    EXPECT_EQ(mock_ctx.verdicts[1].verdict, NF_ACCEPT);
}

// 13. HTTP POST with User-Agent
TEST_F(HandlerTest, HttpPostWithUserAgent) {
    const char *req = "POST /api HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\nContent-Length: 0\r\n\r\n";
    auto pkt = make_http_packet(req);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mangled_data.empty());

    auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV4);
    std::string payload_str(payload.begin(), payload.end());
    EXPECT_EQ(payload_str.find("curl/7.68.0"), std::string::npos);
}

// 14. Unknown hw_protocol → NF_ACCEPT, no mark
TEST_F(HandlerTest, UnknownHwProtocol) {
    const char *data = "some payload data";
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 80,
        data, strlen(data));
    auto pkt = make_nf_packet(raw, 1, IPV4);
    // Set hw_protocol to something unknown (not ETH_P_IP or ETH_P_IPV6)
    pkt.hw_protocol = 0x9999;

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_FALSE(mock_ctx.verdicts[0].mark.should_set);
}

// 15. Conntrack parse error → cache + CONNMARK_NOT_HTTP
TEST_F(HandlerTest, ConntrackParseError) {
    use_conntrack = true;

    // First packet: valid HTTP to create a session
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
    auto pkt1 = make_http_packet_ct(req, 1, 500);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);

    // Second packet: garbage on same conntrack session → parse error
    const char *garbage = "INVALID GARBAGE DATA\r\n\r\n";
    auto raw2 = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000002),
        12345, 80,
        garbage, strlen(garbage));
    auto pkt2 = make_nf_packet_with_conntrack(raw2, 2, IPV4, 500,
                                               htonl(0x0a000001), htonl(0x0a000002), 12345, 80);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    EXPECT_EQ(mock_ctx.verdicts[1].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[1].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[1].mark.mark, (uint32_t)CONNMARK_NOT_HTTP);

    use_conntrack = false;
}

// 16. Conntrack non-HTTP first packet → cache + CONNMARK_NOT_HTTP
TEST_F(HandlerTest, ConntrackNonHttpFirstPacket) {
    use_conntrack = true;

    // Non-HTTP binary data on a new connection with conntrack
    const char *binary = "\x00\x01\x02\x03\x04\x05\x06\x07";
    auto raw = build_ipv4_tcp_packet(
        htonl(0x0a000001), htonl(0x0a000005),
        50000, 9999,
        binary, 8);
    auto pkt = make_nf_packet_with_conntrack(raw, 1, IPV4, 600,
                                              htonl(0x0a000001), htonl(0x0a000005), 50000, 9999);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_NOT_HTTP);

    use_conntrack = false;
}

// 17. Existing session second packet → no CONNMARK_HTTP (not new)
TEST_F(HandlerTest, ConntrackExistingSessionNoMark) {
    use_conntrack = true;

    // Use unique IPs/ports to avoid collisions with other tests
    uint32_t src = htonl(0x0a0a0001);
    uint32_t dst = htonl(0x0a0a0002);

    // First packet creates session → CONNMARK_HTTP
    const char *req1 = "GET /1 HTTP/1.1\r\nHost: x.com\r\nUser-Agent: A\r\n\r\n";
    auto raw1 = build_ipv4_tcp_packet(src, dst, 60001, 80, req1, strlen(req1));
    auto pkt1 = make_nf_packet_with_conntrack(raw1, 1, IPV4, 700, src, dst, 60001, 80);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, (uint32_t)CONNMARK_HTTP);

    // Second packet on same conntrack session → no mark (not new)
    const char *req2 = "GET /2 HTTP/1.1\r\nHost: x.com\r\nUser-Agent: B\r\n\r\n";
    auto raw2 = build_ipv4_tcp_packet(src, dst, 60001, 80, req2, strlen(req2));
    auto pkt2 = make_nf_packet_with_conntrack(raw2, 2, IPV4, 700, src, dst, 60001, 80);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    EXPECT_FALSE(mock_ctx.verdicts[1].mark.should_set);

    use_conntrack = false;
}

TEST_F(HandlerTest, CrossPacketUserAgentUsesReplacementOffset) {
    char *replacement = const_cast<char *>(get_replacement_user_agent_string());
    ASSERT_NE(replacement, nullptr);
    for (size_t i = 0; i < 64; i++) {
        replacement[i] = static_cast<char>('A' + (i % 26));
    }

    const char *pkt1_data = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.";
    auto pkt1 = make_http_packet(pkt1_data, 1);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt1);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    auto payload1 = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV4);
    std::string payload1_str(payload1.begin(), payload1.end());
    EXPECT_NE(payload1_str.find("ABCDEFGHIJ"), std::string::npos);
    EXPECT_EQ(payload1_str.find("Mozilla/5."), std::string::npos);

    const char *pkt2_data = "0 (Windows)\r\n\r\n";
    auto pkt2 = make_http_packet(pkt2_data, 2);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt2);

    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    auto payload2 = extract_tcp_payload(mock_ctx.verdicts[1].mangled_data, IPV4);
    std::string payload2_str(payload2.begin(), payload2.end());
    EXPECT_NE(payload2_str.find("KLMNOPQRSTU"), std::string::npos);
    EXPECT_EQ(payload2_str.find("0 (Windows)"), std::string::npos);
}

TEST_F(HandlerTest, MalformedIpv4StillSendsVerdict) {
    std::vector<uint8_t> raw = {0x45};
    auto pkt = make_nf_packet(raw, 99, IPV4);

    handle_packet(&mock_packet_io, &mock_ctx, &pkt);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[0].mangled_data.empty());
}

TEST_F(HandlerTest, RewritesAllPipelinedRequestsBeyondInlineCapacity) {
    std::string request;
    std::string expected;
    for (size_t i = 0; i < 33; ++i) {
        request += "GET / HTTP/1.1\r\nUser-Agent: Original\r\n\r\n";
        expected += "GET / HTTP/1.1\r\nUser-Agent: FFFFFFFF\r\n\r\n";
    }
    auto pkt = make_http_packet(request.c_str());
    handle_packet(&mock_packet_io, &mock_ctx, &pkt);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV4);
    EXPECT_EQ(std::string(payload.begin(), payload.end()), expected);
}

TEST_F(HandlerTest, RewritesAllDuplicateUaHeadersBeyondInlineCapacityIpv6) {
    std::string request = "GET / HTTP/1.1\r\n";
    std::string expected = request;
    for (size_t i = 0; i < 33; ++i) {
        request += "User-Agent: Original\r\n";
        expected += "User-Agent: FFFFFFFF\r\n";
    }
    request += "\r\n";
    expected += "\r\n";
    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr dst = IN6ADDR_LOOPBACK_INIT;
    dst.s6_addr[15] = 2;
    const auto raw = build_ipv6_tcp_packet(src, dst, 12345, 80, request.data(), request.size());
    auto pkt = make_nf_packet(raw, 1, IPV6);
    handle_packet(&mock_packet_io, &mock_ctx, &pkt);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto payload = extract_tcp_payload(mock_ctx.verdicts[0].mangled_data, IPV6);
    EXPECT_EQ(std::string(payload.begin(), payload.end()), expected);
}

TEST_F(HandlerTest, AllocationFailureKeepsSessionClosedForRetransmittedFragments) {
    use_conntrack = true;
    auto first = make_http_packet_ct("GET / HTTP/1.1\r\nUser-Agent: First");
    handle_packet(&mock_packet_io, &mock_ctx, &first);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);

    const auto key = session_key_from_connid(100);
    session_wrlock();
    auto *session = session_find(&key);
    session_wrunlock();
    ASSERT_NE(session, nullptr);
    session_state_lock(session);
    // Model the persistent state left by an entry/copy allocation failure.
    session->ua_allocation_failed = true;
    const auto stale_time = time(nullptr) - 301;
    session->last_active = stale_time;
    session_state_unlock(session);

    for (uint32_t packet_id = 2; packet_id <= 3; ++packet_id) {
        mock_ctx.verdicts.clear();
        auto continuation = make_http_packet_ct("Original\r\n\r\n", packet_id);
        handle_packet(&mock_packet_io, &mock_ctx, &continuation);
        ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
        EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_DROP);
        EXPECT_FALSE(mock_ctx.verdicts[0].mark.should_set);
        EXPECT_TRUE(mock_ctx.verdicts[0].mangled_data.empty());
        session_wrlock();
        EXPECT_EQ(session_find(&key), session);
        EXPECT_EQ(session_cleanup_expired(300), 0);
        session_wrunlock();
    }
}


TEST_F(HandlerTest, BodyOnlyVerdictOmitsPayloadAndPreservesSession) {
    use_conntrack = true;
    const char *header = "POST /upload HTTP/1.1\r\nUser-Agent: Original\r\nContent-Length: 12\r\n\r\n";
    auto first = make_http_packet_ct(header);
    handle_packet(&mock_packet_io, &mock_ctx, &first);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_FALSE(mock_ctx.verdicts[0].mangled_data.empty());
    const auto key = session_key_from_connid(100);
    session_wrlock();
    auto *session = session_find(&key);
    session_wrunlock();
    ASSERT_NE(session, nullptr);
    session_state_lock(session);
    session->last_active = time(nullptr) - 301;
    session_state_unlock(session);

    auto body = make_http_packet_ct("User-Agent: ", 2);
    handle_packet(&mock_packet_io, &mock_ctx, &body);
    ASSERT_EQ(mock_ctx.verdicts.size(), 2u);
    EXPECT_EQ(mock_ctx.verdicts[1].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[1].mangled_data.empty());
    EXPECT_FALSE(mock_ctx.verdicts[1].mark.should_set);
    session_wrlock();
    EXPECT_EQ(session_find(&key), session);
    EXPECT_EQ(session_cleanup_expired(300), 0);
    session_wrunlock();

    auto next = make_http_packet_ct("GET / HTTP/1.1\r\nUser-Agent: Next\r\n\r\n", 3);
    handle_packet(&mock_packet_io, &mock_ctx, &next);
    ASSERT_EQ(mock_ctx.verdicts.size(), 3u);
    const auto payload = extract_tcp_payload(mock_ctx.verdicts[2].mangled_data, IPV4);
    EXPECT_EQ(std::string(payload.begin(), payload.end()), "GET / HTTP/1.1\r\nUser-Agent: FFFF\r\n\r\n");
}

TEST_F(HandlerTest, NoUserAgentStillMarksNewHttpConnection) {
    use_conntrack = true;
    auto packet = make_http_packet_ct("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    handle_packet(&mock_packet_io, &mock_ctx, &packet);
    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    EXPECT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    EXPECT_TRUE(mock_ctx.verdicts[0].mangled_data.empty());
    EXPECT_TRUE(mock_ctx.verdicts[0].mark.should_set);
    EXPECT_EQ(mock_ctx.verdicts[0].mark.mark, static_cast<uint32_t>(CONNMARK_HTTP));
}

TEST_F(HandlerTest, PipelinedOddLengthUserAgentsHaveValidIpv4Checksums) {
    std::string request;
    std::string expected;
    for (size_t i = 0; i < 33; ++i) {
        request += "GET / HTTP/1.1\r\nUser-Agent: OddUA\r\n\r\n";
        expected += "GET / HTTP/1.1\r\nUser-Agent: FFFFF\r\n\r\n";
    }
    ASSERT_EQ(request.size() % 2, 1u);
    auto raw = build_ipv4_tcp_packet(htonl(0x0a000001), htonl(0x0a000002),
                                     12345, 80, request.data(), request.size());
    set_packet_checksums(raw, IPV4, 20);
    auto packet = make_nf_packet(raw, 1, IPV4);
    handle_packet(&mock_packet_io, &mock_ctx, &packet);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto &rewritten = mock_ctx.verdicts[0].mangled_data;
    ASSERT_EQ(rewritten.size(), raw.size());
    expect_valid_packet_checksums(rewritten, IPV4, 20);
    const auto payload = extract_tcp_payload(rewritten, IPV4);
    EXPECT_EQ(std::string(payload.begin(), payload.end()), expected);
}

TEST_F(HandlerTest, DuplicateOddLengthUserAgentsHaveValidIpv6Checksum) {
    std::string request = "GET / HTTP/1.1\r\n";
    std::string expected = request;
    for (size_t i = 0; i < 33; ++i) {
        request += "User-Agent: OddUA\r\n";
        expected += "User-Agent: FFFFF\r\n";
    }
    request += "\r\n";
    expected += "\r\n";
    ASSERT_EQ(request.size() % 2, 1u);
    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr dst = IN6ADDR_LOOPBACK_INIT;
    dst.s6_addr[15] = 2;
    auto raw = build_ipv6_tcp_packet(src, dst, 12345, 80, request.data(), request.size());
    set_packet_checksums(raw, IPV6, 40);
    auto packet = make_nf_packet(raw, 1, IPV6);
    handle_packet(&mock_packet_io, &mock_ctx, &packet);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto &rewritten = mock_ctx.verdicts[0].mangled_data;
    ASSERT_EQ(rewritten.size(), raw.size());
    expect_valid_packet_checksums(rewritten, IPV6, 40);
    const auto payload = extract_tcp_payload(rewritten, IPV6);
    EXPECT_EQ(std::string(payload.begin(), payload.end()), expected);
}

TEST_F(HandlerTest, Ipv4AndTcpOptionsSurviveUserAgentRewriteWithValidChecksums) {
    const std::string request = "GET / HTTP/1.1\r\nUser-Agent: OddUA\r\n\r\n";
    auto raw = build_ipv4_tcp_packet(htonl(0x0a000001), htonl(0x0a000002),
                                     12345, 80, request.data(), request.size());
    // Four IPv4 NOP options; TCP NOP, NOP, Timestamp options (12 bytes).
    raw.insert(raw.begin() + 20, {1, 1, 1, 1});
    raw[0] = 0x46;
    const std::vector<uint8_t> tcp_options = {1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2};
    raw.insert(raw.begin() + 44, tcp_options.begin(), tcp_options.end());
    raw[24 + 12] = static_cast<uint8_t>((8U << 4) | (raw[24 + 12] & 0x0fU));
    set_packet_checksums(raw, IPV4, 24);
    auto packet = make_nf_packet(raw, 1, IPV4);
    handle_packet(&mock_packet_io, &mock_ctx, &packet);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto &rewritten = mock_ctx.verdicts[0].mangled_data;
    ASSERT_EQ(rewritten.size(), raw.size());
    expect_valid_packet_checksums(rewritten, IPV4, 24);
    EXPECT_EQ(std::vector<uint8_t>(rewritten.begin() + 20, rewritten.begin() + 24),
              (std::vector<uint8_t>{1, 1, 1, 1}));
    EXPECT_EQ(std::vector<uint8_t>(rewritten.begin() + 44, rewritten.begin() + 56), tcp_options);
    const auto payload = extract_tcp_payload(rewritten, IPV4);
    EXPECT_EQ(std::string(payload.begin(), payload.end()),
              "GET / HTTP/1.1\r\nUser-Agent: FFFFF\r\n\r\n");
}

TEST_F(HandlerTest, Ipv6AtomicFragmentHeaderSurvivesRewriteWithValidTcpChecksum) {
    const std::string request = "GET / HTTP/1.1\r\nUser-Agent: OddUA\r\n\r\n";
    struct in6_addr src = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr dst = IN6ADDR_LOOPBACK_INIT;
    dst.s6_addr[15] = 2;
    auto raw = build_ipv6_tcp_packet(src, dst, 12345, 80, request.data(), request.size());
    // A complete atomic fragment: offset zero, M flag clear, identification zero.
    const std::vector<uint8_t> fragment_header = {IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0};
    raw.insert(raw.begin() + 40, fragment_header.begin(), fragment_header.end());
    raw[6] = IPPROTO_FRAGMENT;
    set_packet_checksums(raw, IPV6, 48);
    auto packet = make_nf_packet(raw, 1, IPV6);
    handle_packet(&mock_packet_io, &mock_ctx, &packet);

    ASSERT_EQ(mock_ctx.verdicts.size(), 1u);
    ASSERT_EQ(mock_ctx.verdicts[0].verdict, NF_ACCEPT);
    const auto &rewritten = mock_ctx.verdicts[0].mangled_data;
    ASSERT_EQ(rewritten.size(), raw.size());
    expect_valid_packet_checksums(rewritten, IPV6, 48);
    EXPECT_EQ(std::vector<uint8_t>(rewritten.begin() + 40, rewritten.begin() + 48), fragment_header);
    EXPECT_EQ(std::string(rewritten.begin() + 68, rewritten.end()),
              "GET / HTTP/1.1\r\nUser-Agent: FFFFF\r\n\r\n");
}

TEST_F(HandlerTest, SplitLongUserAgentPadsOnlyBeyondReplacementCapacity) {
    const size_t capacity = get_replacement_user_agent_string_length();
    const size_t first_value_len = 60000;
    ASSERT_GT(capacity, first_value_len);
    const std::string prefix = "GET / HTTP/1.1\r\nUser-Agent: ";
    const std::string first = prefix + std::string(first_value_len, 'A');
    const size_t replacement_remaining = capacity - first_value_len;
    const std::string second(replacement_remaining + 17, 'B');
    const std::string third = "Original-tail\r\n\r\n";
    const std::string expected[] = {
        prefix + std::string(get_replacement_user_agent_string(), first_value_len),
        std::string(get_replacement_user_agent_string() + first_value_len, replacement_remaining) +
            std::string(17, ' '),
        std::string(std::strlen("Original-tail"), ' ') + "\r\n\r\n",
    };
    const std::string fragments[] = {first, second, third};

    for (size_t i = 0; i < 3; ++i) {
        auto raw = build_ipv4_tcp_packet(htonl(0x0a000001), htonl(0x0a000002),
                                         12345, 80, fragments[i].data(), fragments[i].size());
        ASSERT_LE(raw.size(), 65535u);
        set_packet_checksums(raw, IPV4, 20);
        auto packet = make_nf_packet(raw, static_cast<uint32_t>(i + 1), IPV4);
        handle_packet(&mock_packet_io, &mock_ctx, &packet);
        ASSERT_EQ(mock_ctx.verdicts.size(), i + 1);
        ASSERT_EQ(mock_ctx.verdicts[i].verdict, NF_ACCEPT);
        const auto &rewritten = mock_ctx.verdicts[i].mangled_data;
        ASSERT_EQ(rewritten.size(), raw.size());
        expect_valid_packet_checksums(rewritten, IPV4, 20);
        const auto payload = extract_tcp_payload(rewritten, IPV4);
        EXPECT_EQ(std::string(payload.begin(), payload.end()), expected[i]);
    }
}
