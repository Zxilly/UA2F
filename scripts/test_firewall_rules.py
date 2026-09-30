#!/usr/bin/env python3
"""Offline semantic tests. Never calls nft/iptables or creates a network namespace."""
import itertools
from pathlib import Path
import re
import struct
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "openwrt/files/ua2f.firewall"


def generate(function, *args):
    return subprocess.check_output(
        ["sh", "-c", '. "$1"; shift; "$@"', "sh", str(HELPER), function, *map(str, args)],
        text=True,
    ).splitlines()


def u32_matches(expression, packet):
    """Independent interpreter of the documented u32 operations used by the helper."""
    for test in expression.split("&&"):
        location, expected = test.strip().split("=")
        tokens = re.findall(r"0x[0-9a-fA-F]+|[0-9]+|>>|&", location)
        offset = int(tokens[0], 0)
        if offset + 4 > len(packet):
            return False
        value = int.from_bytes(packet[offset:offset + 4], "big")
        for op, raw in zip(tokens[1::2], tokens[2::2]):
            operand = int(raw, 0)
            value = value >> operand if op == ">>" else value & operand
        if value != int(expected.strip(), 0):
            return False
    return True


def packet(family, doff=5, payload=b"", flags=0x10, ihl=5, frag=0, nexthdr=6):
    tcp = bytearray(max(20, 4 * doff))
    tcp[12] = doff << 4
    tcp[13] = flags
    if family == 4:
        ip = bytearray(max(20, ihl * 4))
        ip[0] = 0x40 | ihl
        ip[9] = nexthdr
        struct.pack_into("!HH", ip, 2, len(ip) + len(tcp) + len(payload), 0)
        struct.pack_into("!H", ip, 6, frag)
    else:
        ip = bytearray(40)
        ip[0] = 0x60
        ip[6] = nexthdr
        struct.pack_into("!H", ip, 4, len(tcp) + len(payload))
    return bytes(ip + tcp + payload)


class EmptyAckRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {family: generate("ua2f_empty_ack_u32", family) for family in (4, 6)}
        cls.nft = generate("ua2f_empty_ack_nft")

    def bypass(self, family, data):
        return any(u32_matches(expr, data) for expr in self.rules[family])

    def test_exact_rule_shape(self):
        self.assertEqual(len(self.nft), 22)
        for family in (4, 6):
            self.assertEqual(len(self.rules[family]), 11)
        for line in self.nft:
            self.assertIn("ct direction original", line)
            self.assertIn("tcp flags & 0x17 == 0x10", line)
            self.assertIn('counter return comment "!ua2f: empty ACK";', line)
            self.assertNotIn("mark", line)
        for doff in range(5, 16):
            self.assertIn(f"tcp doff {doff} ip length {20+4*doff}", self.nft[2*(doff-5)])
            self.assertTrue(self.nft[2*(doff-5)].startswith(f"meta length {20+4*doff} "))
            self.assertIn("ip hdrlength 5 ip frag-off & 0x3fff == 0", self.nft[2*(doff-5)])
            self.assertIn(f"tcp doff {doff} ip6 length {4*doff}", self.nft[2*(doff-5)+1])
            self.assertTrue(self.nft[2*(doff-5)+1].startswith(f"meta length {40+4*doff} "))
            self.assertIn("ip6 nexthdr tcp", self.nft[2*(doff-5)+1])

    def test_all_flags_header_lengths_and_payloads(self):
        # Exhaust all eight TCP flag bits, valid/invalid doff and adjacent lengths.
        for family, doff, flags, size in itertools.product((4, 6), range(16), range(256), (0, 1, 2, 4, 100)):
            want = doff >= 5 and size == 0 and flags & 0x17 == 0x10
            self.assertEqual(self.bypass(family, packet(family, doff, b"x"*size, flags)), want,
                             (family, doff, flags, size))

    def test_ipv4_options_and_fragmentation_fall_back(self):
        for ihl, doff, frag in itertools.product(range(5, 16), range(5, 16), (0, 0x4000, 0x2000, 1, 0x3fff)):
            want = ihl == 5 and frag & 0x3fff == 0
            self.assertEqual(self.bypass(4, packet(4, doff, ihl=ihl, frag=frag)), want, (ihl, doff, frag))

    def test_ipv6_extensions_and_other_protocols_fall_back(self):
        for family, nh, doff in itertools.product((4, 6), (0, 17, 43, 44, 50, 51, 59, 60, 135), range(5, 16)):
            self.assertFalse(self.bypass(family, packet(family, doff, nexthdr=nh)))

    def test_truncation_invalid_lengths_and_jumbo_lengths_fall_back(self):
        for family, doff in itertools.product((4, 6), range(5, 16)):
            data = packet(family, doff)
            for size in range(len(data)):
                self.assertFalse(self.bypass(family, data[:size]), (family, doff, size))
            for length in (0, 1, 19, 65535):
                malformed = bytearray(data)
                struct.pack_into("!H", malformed, 2 if family == 4 else 4, length)
                self.assertFalse(self.bypass(family, malformed))

    def test_payload_ack_keepalive_pipeline_and_lifecycle(self):
        for family in (4, 6):
            request = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
            traffic = [packet(family, payload=request, flags=0x10), packet(family, doff=8),
                       packet(family, payload=request*2, flags=0x18), packet(family, payload=b"x"),
                       packet(family, flags=0x02), packet(family, flags=0x11), packet(family, flags=0x14)]
            self.assertEqual([self.bypass(family, x) for x in traffic], [False, True, False, False, False, False, False])

    def test_application_api_with_print_only_mock(self):
        # This shell function prints argv. No real firewall tool is invoked.
        code = '. "$1"; mock() { printf "%s\\n" "$*"; }; ua2f_add_empty_ack_iptables "$2" mock -t mangle -A test'
        for family in (4, 6):
            lines = subprocess.check_output(["sh", "-c", code, "sh", str(HELPER), str(family)], text=True).splitlines()
            self.assertEqual(len(lines), 11)
            self.assertTrue(all("--ctdir ORIGINAL -m u32 --u32" in line and line.endswith("-j RETURN") for line in lines))
        fail = '. "$1"; mock() { return 7; }; ua2f_add_empty_ack_iptables 4 mock'
        self.assertNotEqual(subprocess.run(["sh", "-c", fail, "sh", str(HELPER)], check=False).returncode, 0)

    def test_invalid_family_emits_nothing(self):
        result = subprocess.run(["sh", "-c", '. "$1"; ua2f_empty_ack_u32 7', "sh", str(HELPER)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_opt_in_only_and_queue_order(self):
        source = (ROOT / "openwrt/files/ua2f.init").read_text()
        self.assertIn('config_get_bool bypass_empty_ack "firewall" "bypass_empty_ack" "0"', source)
        self.assertEqual(source.count("|| ua2f_add_empty_ack_iptables 4 iptables"), 1)
        self.assertEqual(source.count("|| ua2f_add_empty_ack_iptables 6 ip6tables"), 1)
        self.assertLess(source.index("ct mark 43 counter return", source.index("setup_firewall()")), source.index("|| ua2f_empty_ack_nft"))
        self.assertLess(source.index("|| ua2f_empty_ack_nft"), source.index("ct direction original counter $nfqueue_expr"))
        self.assertIn("iptables-mod-u32", (ROOT / "openwrt/Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
