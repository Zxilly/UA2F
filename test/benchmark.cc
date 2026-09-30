// In-process microbenchmarks, not NFQUEUE/end-to-end throughput measurements.
// Packet construction, expected-output construction, and full validation are
// outside timing. handle_packet owns/frees its input, so its timed adapter must
// malloc+copy each input. Session lookup/locks, statistics, pktb allocation,
// rewrite, checksum work, and the minimal verdict sink remain timed.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/syslog.h>
#include <unistd.h>

extern "C" {
#include "handler.h"
#include "http_parser_ua.h"
#include "http_session.h"
#include "statistics.h"
}
#include "packet_builder.h"

#ifndef UA2F_BENCH_BUILD_TYPE
#define UA2F_BENCH_BUILD_TYPE "unknown"
#endif
#ifndef UA2F_BENCH_C_FLAGS
#define UA2F_BENCH_C_FLAGS "unknown"
#endif

namespace {
using Clock = std::chrono::steady_clock;
volatile uint64_t final_sink = 0;
struct Span { size_t offset, len, replacement_offset; };
struct Segment {
    std::string input, expected;
    std::vector<Span> spans;
};
struct Workload {
    std::string name;
    std::vector<Segment> segments;
    bool parse_error = false;
    size_t requests = 1;
};

void require(bool good, const std::string &message) {
    if (!good) throw std::runtime_error(message);
}

Workload make_workload(const std::string &name, const std::string &input,
                       const std::vector<Span> &spans, std::vector<size_t> cuts = {},
                       bool parse_error = false, size_t requests = 1) {
    Workload w{name, {}, parse_error, requests};
    cuts.push_back(input.size());
    size_t begin = 0;
    for (size_t end : cuts) {
        require(end >= begin && end <= input.size(), "invalid segment boundary");
        Segment s{input.substr(begin, end - begin), input.substr(begin, end - begin), {}};
        for (const auto &span : spans) {
            size_t lo = std::max(begin, span.offset);
            size_t hi = std::min(end, span.offset + span.len);
            if (lo < hi) {
                Span part{lo - begin, hi - lo, span.replacement_offset + lo - span.offset};
                s.spans.push_back(part);
                const char *replacement = get_replacement_user_agent_string();
                size_t capacity = get_replacement_user_agent_string_length();
                for (size_t i = 0; i < part.len; ++i)
                    s.expected[part.offset + i] = part.replacement_offset + i < capacity
                        ? replacement[part.replacement_offset + i] : ' ';
            }
        }
        w.segments.push_back(std::move(s));
        begin = end;
    }
    return w;
}

std::vector<Workload> workloads() {
    std::vector<Workload> result;
    const std::string start = "GET /resource HTTP/1.1\r\nHost: example.test\r\n";
    const std::string ua = "Mozilla/5.0 benchmark-agent/1.0";
    auto add_ua = [&](std::string &s, std::vector<Span> &spans) {
        s += "User-Agent: ";
        spans.push_back({s.size(), ua.size(), 0});
        s += ua + "\r\n";
    };
    std::string single = start;
    std::vector<Span> single_spans;
    add_ua(single, single_spans);
    single += "\r\n";
    result.push_back(make_workload("get_single_ua", single, single_spans));
    result.push_back(make_workload("get_no_ua", start + "Accept: */*\r\n\r\n", {}));

    std::string many = start;
    std::vector<Span> many_spans;
    for (int i = 0; i < 32; ++i)
        many += "X-Benchmark-Header-" + std::to_string(i) + ": irrelevant-value-0123456789\r\n";
    // Names starting with U exercise the negative candidate path too.
    many += "Upgrade: h2c\r\nUser-Agent-Not: preserve-this\r\n";
    add_ua(many, many_spans);
    many += "\r\n";
    result.push_back(make_workload("get_34_irrelevant_headers", many, many_spans));

    std::string duplicate = start;
    std::vector<Span> duplicate_spans;
    for (int i = 0; i < 16; ++i) add_ua(duplicate, duplicate_spans);
    duplicate += "\r\n";
    result.push_back(make_workload("get_16_duplicate_ua", duplicate, duplicate_spans));

    for (int count : {32, 128}) {
        std::string duplicate_many = start;
        std::vector<Span> spans;
        for (int i = 0; i < count; ++i) add_ua(duplicate_many, spans);
        duplicate_many += "\r\n";
        result.push_back(make_workload("get_" + std::to_string(count) + "_duplicate_ua", duplicate_many, spans));
    }

    std::string pipeline;
    std::vector<Span> pipeline_spans;
    for (int i = 0; i < 16; ++i) {
        size_t base = pipeline.size();
        pipeline += single;
        pipeline_spans.push_back({base + single_spans[0].offset, ua.size(), 0});
    }
    result.push_back(make_workload("get_16_pipelined", pipeline, pipeline_spans, {}, false, 16));
    size_t ua_begin = single_spans[0].offset;
    result.push_back(make_workload("get_segmented_ua", single, single_spans,
                                  {ua_begin - 5, ua_begin + 9}));

    std::string body(16384, 'b');
    body.replace(100, 28, "User-Agent: leave-body-alone!");
    std::string upload = "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: " +
                         std::to_string(body.size()) + "\r\n";
    std::vector<Span> upload_spans;
    add_ua(upload, upload_spans);
    upload += "\r\n";
    size_t body_begin = upload.size();
    upload += body;
    result.push_back(make_workload("post_16k_body", upload, upload_spans));
    result.push_back(make_workload("post_segmented_body", upload, upload_spans,
                                  {body_begin, body_begin + 8192}));
    result.push_back(make_workload("malformed_http", "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n",
                                  {}, {}, true, 0));
    result.push_back(make_workload("non_http_tls", std::string("\x16\x03\x01\x02\x00\x01\x00", 7),
                                  {}, {}, true, 0));
    result.push_back(make_workload("empty_ack", "", {}, {}, false, 0));
    return result;
}

uint32_t checksum_sum(const uint8_t *p, size_t size, uint32_t sum = 0) {
    while (size >= 2) { sum += (uint32_t(p[0]) << 8) | p[1]; p += 2; size -= 2; }
    if (size) sum += uint32_t(*p) << 8;
    return sum;
}
uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return uint16_t(~sum);
}
size_t ip_size(int version) { return version == IPV4 ? 20 : 40; }
uint32_t tcp_pseudo_sum(const uint8_t *raw, size_t size, int version) {
    size_t ip_len = ip_size(version), tcp_len = size - ip_len;
    uint32_t sum = version == IPV4 ? checksum_sum(raw + 12, 8)
                                  : checksum_sum(raw + 8, 32);
    return sum + IPPROTO_TCP + uint32_t(tcp_len);
}
void complete_checksums(std::vector<uint8_t> &raw, int version) {
    size_t ip_len = ip_size(version);
    raw[ip_len + 16] = raw[ip_len + 17] = 0;
    uint16_t tcp = checksum_finish(checksum_sum(raw.data() + ip_len, raw.size() - ip_len,
                                               tcp_pseudo_sum(raw.data(), raw.size(), version)));
    raw[ip_len + 16] = uint8_t(tcp >> 8);
    raw[ip_len + 17] = uint8_t(tcp);
    if (version == IPV4) {
        raw[10] = raw[11] = 0;
        uint16_t ip = checksum_finish(checksum_sum(raw.data(), ip_len));
        raw[10] = uint8_t(ip >> 8); raw[11] = uint8_t(ip);
    }
}
void verify_checksums(const uint8_t *raw, size_t size, int version) {
    size_t ip_len = ip_size(version);
    require(size >= ip_len + 20, "packet is too short");
    if (version == IPV4)
        require(checksum_finish(checksum_sum(raw, ip_len)) == 0, "bad IPv4 checksum");
    require(checksum_finish(checksum_sum(raw + ip_len, size - ip_len,
                                        tcp_pseudo_sum(raw, size, version))) == 0, "bad TCP checksum");
}
struct Packet {
    std::vector<uint8_t> input, expected;
    int version;
};
std::vector<Packet> packets_for(const Workload &w, int version) {
    std::vector<Packet> packets;
    uint32_t sequence = 1000;
    for (const auto &segment : w.segments) {
        Packet p{{}, {}, version};
        if (version == IPV4) {
            p.input = build_ipv4_tcp_packet(htonl(0x0a000001), htonl(0x0a000002), 12345, 80,
                                            segment.input.data(), segment.input.size());
        } else {
            in6_addr src = IN6ADDR_LOOPBACK_INIT, dst = IN6ADDR_LOOPBACK_INIT;
            dst.s6_addr[15] = 2;
            p.input = build_ipv6_tcp_packet(src, dst, 12345, 80,
                                            segment.input.data(), segment.input.size());
        }
        auto *tcp = reinterpret_cast<tcphdr *>(p.input.data() + ip_size(version));
        tcp->seq = htonl(sequence);
        tcp->ack_seq = htonl(2000);
        tcp->psh = !segment.input.empty();
        sequence += segment.input.size();
        complete_checksums(p.input, version);
        verify_checksums(p.input.data(), p.input.size(), version);
        p.expected = p.input;
        std::copy(segment.expected.begin(), segment.expected.end(), p.expected.begin() + ip_size(version) + 20);
        complete_checksums(p.expected, version);
        packets.push_back(std::move(p));
    }
    return packets;
}

struct VerdictContext {
    const Packet *packet = nullptr;
    bool validate = false;
    uint64_t sink = 0, count = 0;
    std::vector<uint8_t> copy_buffer;
};
void verdict_sink(void *opaque, const nf_packet *pkt, int verdict, mark_op mark, pkt_buff *mangled) {
    auto &ctx = *static_cast<VerdictContext *>(opaque);
    const uint8_t *data = mangled ? pktb_data(mangled) : static_cast<const uint8_t *>(pkt->payload);
    size_t size = mangled ? pktb_len(mangled) : pkt->payload_len;
    if (ctx.validate) {
        require(verdict == NF_ACCEPT, "unexpected verdict");
        require(!mark.should_set, "unexpected connmark with conntrack disabled");
        require(size == ctx.packet->expected.size(), "packet length changed");
        require(std::memcmp(data, ctx.packet->expected.data(), size) == 0,
                "rewritten packet differs from independently generated expected bytes");
        verify_checksums(data, size, ctx.packet->version);
    }
    // Reflect handler_io's payload copy into a preallocated netlink-message
    // buffer when a replacement packet is submitted. Unchanged verdicts carry
    // no packet bytes. This excludes actual netlink/socket/kernel work.
    if (mangled) {
        std::memcpy(ctx.copy_buffer.data(), data, size);
        data = ctx.copy_buffer.data();
    }
    // Consume output without allocating or hashing the full packet in the hot loop.
    ctx.sink += size + uint64_t(verdict) + data[size - 1] +
                (uint64_t(data[ip_size(ctx.packet->version) + 16]) << 8) +
                data[ip_size(ctx.packet->version) + 17];
    ++ctx.count;
}
const packet_io benchmark_io{verdict_sink};

class ParserRun {
    const Workload &w;
    http_session session{};
public:
    uint64_t sink = 0;
    explicit ParserRun(const Workload &workload) : w(workload) {
        require(session_state_init(&session), "session state initialization failed");
        http_parser_init_session(&session);
    }
    ~ParserRun() { session_state_destroy(&session); }
    void cycle(bool validate) {
        // Error leaves llhttp terminal: initialize a fresh parser for each error
        // workload cycle. Successful workloads use a persistent keepalive parser.
        if (w.parse_error) http_parser_init_session(&session);
        for (const auto &segment : w.segments) {
            session_reset_per_packet(&session, segment.input.data());
            int result = http_parser_feed(&session, segment.input.data(), segment.input.size());
            if (validate) {
                require(w.parse_error ? result == -1 : result == 0, w.name + ": unexpected parse result");
                require(session.ua_entry_count == segment.spans.size(), w.name + ": unexpected UA entry count");
                for (size_t i = 0; i < segment.spans.size(); ++i) {
                    const auto *entry = session_ua_entry_const(&session, i);
                    const auto &expected = segment.spans[i];
                    require(entry->offset == expected.offset && entry->len == expected.len &&
                            entry->replacement_offset == expected.replacement_offset,
                            w.name + ": UA entry mismatch");
                }
            }
            sink += uint64_t(result + 3) + session.ua_entry_count;
            if (session.ua_entry_count) {
                const auto *entry = session_ua_entry_const(&session, session.ua_entry_count - 1);
                sink += entry->offset + entry->len + entry->replacement_offset;
            }
        }
    }
};
class HandlerRun {
    const std::vector<Packet> packets;
public:
    VerdictContext context;
    explicit HandlerRun(const Workload &w, int version) : packets(packets_for(w, version)) {
        init_http_sessions(0);
        size_t maximum_size = 0;
        for (const auto &packet : packets) maximum_size = std::max(maximum_size, packet.input.size());
        context.copy_buffer.resize(maximum_size);
    }
    ~HandlerRun() {
        session_wrlock(); session_cleanup_expired(-1); session_wrunlock();
    }
    void cycle(bool validate) {
        context.validate = validate;
        for (const auto &packet : packets) {
            context.packet = &packet;
            // The handler frees pkt.payload, matching its production ownership.
            nf_packet pkt = make_nf_packet(packet.input, 1, packet.version);
            require(pkt.payload != nullptr, "packet allocation failed");
            handle_packet(&benchmark_io, &context, &pkt);
        }
    }
    uint64_t consumed() const { return context.sink; }
};

struct Sample { uint64_t iterations; double elapsed_ns; uint64_t checksum; };
template<class Run> Sample time_run(Run &run, uint64_t iterations, double seconds) {
    uint64_t done = 0;
    const auto start = Clock::now();
    if (seconds > 0) {
        do {
            for (unsigned j = 0; j < 64; ++j) run.cycle(false);
            done += 64;
        } while (std::chrono::duration<double>(Clock::now() - start).count() < seconds);
    } else {
        for (; done < iterations; ++done) run.cycle(false);
    }
    return {done, std::chrono::duration<double, std::nano>(Clock::now() - start).count(), 0};
}

std::string json_escape(const std::string &s) {
    std::string out;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c >= 32) out += c;
    }
    return out;
}

struct Options {
    std::string mode = "all", workload = "all";
    uint64_t iterations = 100000, warmup = 200;
    double seconds = 0;
    int repetitions = 5;
    bool list = false;
};
Options options(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--list") { o.list = true; continue; }
        if (arg == "--help") {
            std::cout << "ua2f_benchmark [--mode all|parser|handler4|handler6] [--workload NAME|all]\n"
                         "  [--iterations N | --seconds S] [--repetitions N] [--warmup N] [--list]\n"
                         "One op is one complete workload cycle; segmented cycles contain multiple packets.\n"
                         "Full correctness validation precedes timing. Output is one JSON document.\n";
            std::exit(0);
        }
        require(i + 1 < argc, "missing value for " + arg);
        std::string value = argv[++i];
        if (arg == "--mode") o.mode = value;
        else if (arg == "--workload") o.workload = value;
        else if (arg == "--iterations") o.iterations = std::stoull(value);
        else if (arg == "--seconds") o.seconds = std::stod(value);
        else if (arg == "--repetitions") o.repetitions = std::stoi(value);
        else if (arg == "--warmup") o.warmup = std::stoull(value);
        else throw std::runtime_error("unknown option " + arg);
    }
    require(o.mode == "all" || o.mode == "parser" || o.mode == "handler4" || o.mode == "handler6", "invalid mode");
    require(o.iterations > 0 && o.repetitions > 0 && std::isfinite(o.seconds) && o.seconds >= 0, "invalid run length");
    return o;
}

void report(const Workload &w, const std::string &mode, const std::vector<Sample> &samples, bool &first) {
    std::vector<double> values;
    double mean = 0;
    for (const auto &s : samples) { values.push_back(s.elapsed_ns / s.iterations); mean += values.back(); }
    mean /= values.size();
    double variance = 0;
    for (double value : values) variance += (value - mean) * (value - mean);
    variance /= values.size(); // population CV of recorded repetitions
    std::sort(values.begin(), values.end());
    double median = (values[(values.size() - 1) / 2] + values[values.size() / 2]) / 2;
    size_t bytes = 0, entries = 0;
    for (const auto &s : w.segments) { bytes += s.input.size(); entries += s.spans.size(); }
    if (!first) std::cout << ',';
    first = false;
    std::cout << "{\"mode\":\"" << mode << "\",\"workload\":\"" << w.name
              << "\",\"packets_per_op\":" << w.segments.size() << ",\"requests_per_op\":" << w.requests
              << ",\"payload_bytes_per_op\":" << bytes << ",\"ua_entries_per_op\":" << entries
              << ",\"ns_per_op\":{\"mean\":" << mean << ",\"median\":" << median
              << ",\"cv\":" << std::sqrt(variance) / mean << ",\"min\":" << values.front()
              << ",\"max\":" << values.back() << "},\"median_ns_per_packet\":" << median / w.segments.size()
              << ",\"samples\":[";
    for (size_t i = 0; i < samples.size(); ++i) {
        if (i) std::cout << ',';
        const auto &s = samples[i];
        std::cout << "{\"iterations\":" << s.iterations << ",\"elapsed_ns\":" << s.elapsed_ns
                  << ",\"ns_per_op\":" << s.elapsed_ns / s.iterations << ",\"checksum\":" << s.checksum << '}';
    }
    std::cout << "]}";
}
} // namespace

int main(int argc, char **argv) {
    try {
        const Options o = options(argc, argv);
        setlogmask(LOG_MASK(LOG_EMERG)); // no syslog I/O; production calls and counters remain
        init_handler();
        init_statistics();
        use_conntrack = false;
        const auto all = workloads();
        if (o.list) { for (const auto &w : all) std::cout << w.name << '\n'; return 0; }
        bool selected = false;
        for (const auto &w : all) if (o.workload == "all" || o.workload == w.name) selected = true;
        require(selected, "unknown workload");
        std::cout << std::setprecision(12)
                  << "{\"schema_version\":1,\"kind\":\"in_process_microbenchmark\",\"metadata\":{"
                  << "\"git_commit\":\"" << UA2F_GIT_COMMIT << "\",\"git_dirty\":\"" << UA2F_GIT_DIRTY
                  << "\",\"compiler\":\"" << json_escape(__VERSION__) << "\",\"build_type\":\"" << UA2F_BENCH_BUILD_TYPE
                  << "\",\"c_flags\":\"" << json_escape(UA2F_BENCH_C_FLAGS)
                  << "\",\"cxx_flags\":\"" << json_escape(UA2F_BENCH_CXX_FLAGS)
                  << "\",\"link_flags\":\"" << json_escape(UA2F_BENCH_LINK_FLAGS)
                  << "\",\"build_options\":\"" << json_escape(UA2F_BENCH_OPTIONS)
                  << "\",\"benchmark_sha256\":\"" << UA2F_BENCH_HARNESS_SHA256
                  << "\",\"packet_builder_sha256\":\"" << UA2F_BENCH_PACKET_BUILDER_SHA256
                  << "\",\"common_compile_options\":\"-fno-omit-frame-pointer -fno-strict-aliasing\""
                  << ",\"pid\":" << getpid() << ",\"sizeof_session\":" << sizeof(http_session)
                  << ",\"conntrack\":false,\"handler_input_allocation_timed\":true,\"verdict_payload_copy_timed\":true,\"syslog_mask\":\"emergency_only\","
                  << "\"clock\":\"steady_clock\",\"unit\":\"workload_cycle\",\"warmup_cycles\":" << o.warmup
                  << "},\"results\":[";
        bool first = true;
        for (const auto &w : all) {
            if (o.workload != "all" && o.workload != w.name) continue;
            for (const std::string mode : {"parser", "handler4", "handler6"}) {
                if (o.mode != "all" && o.mode != mode) continue;
                std::vector<Sample> samples;
                for (int repetition = 0; repetition < o.repetitions; ++repetition) {
                    if (mode == "parser") {
                        ParserRun run(w);
                        for (int i = 0; i < 3; ++i) run.cycle(true);
                        for (uint64_t i = 0; i < o.warmup; ++i) run.cycle(false);
                        uint64_t before = run.sink;
                        auto sample = time_run(run, o.iterations, o.seconds);
                        sample.checksum = run.sink - before;
                        final_sink ^= sample.checksum;
                        samples.push_back(sample);
                    } else {
                        HandlerRun run(w, mode == "handler4" ? IPV4 : IPV6);
                        for (int i = 0; i < 3; ++i) run.cycle(true);
                        for (uint64_t i = 0; i < o.warmup; ++i) run.cycle(false);
                        uint64_t before = run.consumed(), before_count = run.context.count;
                        auto sample = time_run(run, o.iterations, o.seconds);
                        require(run.context.count - before_count == sample.iterations * w.segments.size(), "missing verdict");
                        sample.checksum = run.consumed() - before;
                        final_sink ^= sample.checksum;
                        samples.push_back(sample);
                    }
                }
                report(w, mode, samples, first);
            }
        }
        std::cout << "],\"sink\":" << final_sink << "}\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "benchmark error: " << e.what() << '\n';
        return 1;
    }
}
