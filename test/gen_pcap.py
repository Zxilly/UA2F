#!/usr/bin/env python3
"""Generate pcap test data for UA2F handler tests."""

import os
import struct
import socket

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

# pcap file format constants
PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_RAW = 101  # Raw IP


def pcap_global_header():
    return struct.pack("<IHHiIII",
                       PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
                       0, 0, 65535, LINKTYPE_RAW)


def pcap_packet_record(data):
    ts_sec = 0
    ts_usec = 0
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def ip_checksum(header_bytes):
    if len(header_bytes) % 2 != 0:
        header_bytes += b'\x00'
    s = 0
    for i in range(0, len(header_bytes), 2):
        s += (header_bytes[i] << 8) + header_bytes[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, payload):
    tcp_hdr_len = 20
    ip_hdr_len = 20
    total_len = ip_hdr_len + tcp_hdr_len + len(payload)

    # IP header (checksum placeholder = 0)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len,
                         0, 0x4000,
                         64, socket.IPPROTO_TCP, 0,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))
    chk = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", chk) + ip_hdr[12:]

    # TCP header (no checksum for simplicity - tests don't validate TCP checksum)
    tcp_hdr = struct.pack("!HHIIBBHHH",
                          src_port, dst_port,
                          1000, 0,
                          (tcp_hdr_len // 4) << 4, 0x10,  # ACK flag
                          65535, 0, 0)

    return ip_hdr + tcp_hdr + payload


def build_ipv6_tcp(src_ip, dst_ip, src_port, dst_port, payload):
    """Build an IPv6+TCP packet. src_ip/dst_ip are 16-byte packed addresses."""
    tcp_hdr_len = 20
    payload_len = tcp_hdr_len + len(payload)

    # IPv6 header: version=6, traffic class=0, flow label=0
    ip6_hdr = struct.pack("!IHBB16s16s",
                          0x60000000,  # version + traffic class + flow label
                          payload_len,
                          socket.IPPROTO_TCP,  # next header
                          64,  # hop limit
                          src_ip,
                          dst_ip)

    tcp_hdr = struct.pack("!HHIIBBHHH",
                          src_port, dst_port,
                          1000, 0,
                          (tcp_hdr_len // 4) << 4, 0x10,  # ACK flag
                          65535, 0, 0)

    return ip6_hdr + tcp_hdr + payload


def write_pcap(filename, packets):
    path = os.path.join(DATA_DIR, filename)
    with open(path, "wb") as f:
        f.write(pcap_global_header())
        for pkt in packets:
            f.write(pcap_packet_record(pkt))
    print(f"  Generated {path} ({len(packets)} packets)")


# --- Basic scenarios ---

def gen_http_get_with_ua():
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: TestBrowser/1.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, payload)
    write_pcap("http_get_with_ua.pcap", [pkt])


def gen_http_post_with_ua():
    body = b'{"key": "value"}'
    payload = (
        b"POST /api/data HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: curl/7.68.0\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 12346, 80, payload)
    write_pcap("http_post_with_ua.pcap", [pkt])


def gen_tls_traffic():
    # TLS ClientHello-like data (not valid TLS, but starts with 0x16 0x03)
    tls_data = bytes([
        0x16, 0x03, 0x01, 0x00, 0x20,  # TLS record header
    ]) + b'\x01' * 32  # dummy handshake data

    # SYN packet (no payload)
    syn = build_ipv4_tcp("10.0.0.1", "10.0.0.3", 54321, 443, b"")
    # Data packet with TLS-like content
    data = build_ipv4_tcp("10.0.0.1", "10.0.0.3", 54321, 443, tls_data)
    write_pcap("tls_traffic.pcap", [syn, data])


def gen_http_keepalive():
    req1 = (
        b"GET /page1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: KeepAliveAgent/1.0\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )
    req2 = (
        b"GET /page2 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: KeepAliveAgent/1.0\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )
    req3 = (
        b"GET /page3 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: KeepAliveAgent/1.0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    pkt1 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, req1)
    pkt2 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, req2)
    pkt3 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, req3)
    write_pcap("http_keepalive.pcap", [pkt1, pkt2, pkt3])


# --- Edge case scenarios ---

def gen_long_user_agent():
    """UA header with a very long value (2000 chars) — stress the mangle path."""
    long_ua = b"X" * 2000
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: " + long_ua + b"\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20001, 80, payload)
    write_pcap("http_long_ua.pcap", [pkt])


def gen_empty_user_agent():
    """UA header present but value is empty — 'User-Agent: \\r\\n'."""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: \r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20002, 80, payload)
    write_pcap("http_empty_ua.pcap", [pkt])


def gen_multiple_ua_headers():
    """Multiple User-Agent headers in one request (RFC violation, but seen in the wild)."""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: FirstAgent/1.0\r\n"
        b"Accept: */*\r\n"
        b"User-Agent: SecondAgent/2.0\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20003, 80, payload)
    write_pcap("http_multiple_ua.pcap", [pkt])


def gen_pipelined_requests():
    """Two complete HTTP requests in a single TCP segment (HTTP pipelining)."""
    req1 = (
        b"GET /first HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: PipeAgent/1.0\r\n"
        b"\r\n"
    )
    req2 = (
        b"GET /second HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: PipeAgent/2.0\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20004, 80, req1 + req2)
    write_pcap("http_pipelined.pcap", [pkt])


def gen_case_variant_ua():
    """UA header with unusual casing — 'user-agent:', 'USER-AGENT:', 'User-agent:'."""
    req1 = (
        b"GET /lower HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"user-agent: LowerCaseField/1.0\r\n"
        b"\r\n"
    )
    req2 = (
        b"GET /upper HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"USER-AGENT: UpperCaseField/1.0\r\n"
        b"\r\n"
    )
    req3 = (
        b"GET /mixed HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-agent: MixedCaseField/1.0\r\n"
        b"\r\n"
    )
    pkt1 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20005, 80, req1)
    pkt2 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20005, 80, req2)
    pkt3 = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20005, 80, req3)
    write_pcap("http_case_variant_ua.pcap", [pkt1, pkt2, pkt3])


def gen_http_methods():
    """All HTTP methods that is_http_protocol() recognizes, each with a UA.

    CONNECT uses host:port URI per RFC 7231 section 4.3.6.
    """
    methods = [b"GET", b"POST", b"OPTIONS", b"HEAD", b"PUT", b"DELETE",
               b"TRACE", b"CONNECT", b"PATCH"]
    pkts = []
    for i, method in enumerate(methods):
        if method == b"CONNECT":
            # CONNECT requires authority-form URI (host:port)
            request_line = method + b" example.com:443 HTTP/1.1\r\n"
        else:
            request_line = method + b" / HTTP/1.1\r\n"
        payload = (
            request_line
            + b"Host: example.com\r\n"
            b"User-Agent: MethodTest/" + method + b"\r\n"
            b"\r\n"
        )
        pkts.append(build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20010 + i, 80, payload))
    write_pcap("http_all_methods.pcap", pkts)


def gen_post_with_body():
    """POST with a non-trivial body — ensure body bytes don't confuse the parser."""
    body = b"username=admin&password=secret&User-Agent: FakeInBody"
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: RealAgent/1.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20020, 80, payload)
    write_pcap("http_post_body_with_fake_ua.pcap", [pkt])


def gen_ipv6_http():
    """HTTP GET over IPv6."""
    payload = (
        b"GET /ipv6 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: IPv6Browser/1.0\r\n"
        b"\r\n"
    )
    src = socket.inet_pton(socket.AF_INET6, "fd00::1")
    dst = socket.inet_pton(socket.AF_INET6, "fd00::2")
    pkt = build_ipv6_tcp(src, dst, 30000, 80, payload)
    write_pcap("http_ipv6_with_ua.pcap", [pkt])


def gen_mixed_http_nonhttp():
    """Interleaved HTTP and non-HTTP streams from different sources on the same pcap.

    Simulates a router seeing traffic from multiple clients:
    - Client A (10.0.1.1) sends HTTP to 10.0.0.2:80
    - Client B (10.0.1.2) sends TLS to 10.0.0.3:443
    - Client A sends another HTTP request
    """
    http1 = build_ipv4_tcp("10.0.1.1", "10.0.0.2", 40001, 80, (
        b"GET /page1 HTTP/1.1\r\n"
        b"Host: web.example.com\r\n"
        b"User-Agent: ClientA/1.0\r\n"
        b"\r\n"
    ))
    tls1 = build_ipv4_tcp("10.0.1.2", "10.0.0.3", 40002, 443,
                           bytes([0x16, 0x03, 0x03, 0x00, 0x30]) + b'\x00' * 48)
    http2 = build_ipv4_tcp("10.0.1.1", "10.0.0.2", 40001, 80, (
        b"GET /page2 HTTP/1.1\r\n"
        b"Host: web.example.com\r\n"
        b"User-Agent: ClientA/1.0\r\n"
        b"\r\n"
    ))
    tls2 = build_ipv4_tcp("10.0.1.2", "10.0.0.3", 40002, 443,
                           bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b'\x42' * 32)
    write_pcap("mixed_http_nonhttp.pcap", [http1, tls1, http2, tls2])


def gen_ua_with_special_chars():
    """UA containing characters that might trip up naive string handling:
    semicolons, parentheses, slashes, Unicode-like bytes, very long tokens."""
    ua = b"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: " + ua + b"\r\n"
        b"Accept-Encoding: gzip, deflate\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20030, 80, payload)
    write_pcap("http_ua_special_chars.pcap", [pkt])


def gen_chunked_transfer():
    """HTTP request followed by a chunked-encoded response-like body.
    Tests that the parser handles Content-Length: 0 correctly and doesn't
    get confused by subsequent data."""
    payload = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: ChunkedClient/1.0\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nHello\r\n"
        b"6\r\n World\r\n"
        b"0\r\n\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20040, 80, payload)
    write_pcap("http_chunked.pcap", [pkt])


def gen_many_headers():
    """Request with many headers before User-Agent — exercises header iteration."""
    headers = b""
    for i in range(30):
        headers += f"X-Custom-Header-{i}: value-{i}\r\n".encode()
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        + headers
        + b"User-Agent: BuriedAgent/1.0\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20050, 80, payload)
    write_pcap("http_many_headers.pcap", [pkt])


def gen_http10_request():
    """HTTP/1.0 request — no keep-alive by default."""
    payload = (
        b"GET / HTTP/1.0\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: OldBrowser/1.0\r\n"
        b"\r\n"
    )
    pkt = build_ipv4_tcp("10.0.0.1", "10.0.0.2", 20060, 80, payload)
    write_pcap("http10_with_ua.pcap", [pkt])


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    print("Generating pcap test data...")

    # Basic scenarios
    gen_http_get_with_ua()
    gen_http_post_with_ua()
    gen_tls_traffic()
    gen_http_keepalive()

    # Edge cases
    gen_long_user_agent()
    gen_empty_user_agent()
    gen_multiple_ua_headers()
    gen_pipelined_requests()
    gen_case_variant_ua()
    gen_http_methods()
    gen_post_with_body()
    gen_ipv6_http()
    gen_mixed_http_nonhttp()
    gen_ua_with_special_chars()
    gen_chunked_transfer()
    gen_many_headers()
    gen_http10_request()

    print("Done.")


if __name__ == "__main__":
    main()
