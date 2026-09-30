#!/usr/bin/env python3
"""Offline semantic tests. Never calls nft/iptables or creates a network namespace."""
from functools import lru_cache
import itertools
import os
import random
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


@lru_cache(maxsize=None)
def parse_u32(expression):
    """Compile only the u32 operations emitted by this helper, including ranges."""
    tests = []
    for test in expression.split("&&"):
        location, expected = test.strip().split("=")
        tokens = re.findall(r"0x[0-9a-fA-F]+|[0-9]+|>>|&", location)
        bounds = [int(value.strip(), 0) for value in expected.split(":")]
        tests.append((int(tokens[0], 0),
                      tuple((op, int(raw, 0)) for op, raw in zip(tokens[1::2], tokens[2::2])),
                      bounds[0], bounds[-1]))
    return tuple(tests)


def u32_matches(expression, packet):
    """Independent interpreter; a failed packet read is a non-match."""
    for offset, operations, low, high in parse_u32(expression):
        if offset + 4 > len(packet):
            return False
        value = int.from_bytes(packet[offset:offset + 4], "big")
        for op, operand in operations:
            value = value >> operand if op == ">>" else value & operand
        if not low <= value <= high:
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


def mocked_init(*, enabled=1, workers=1, marks=1, intranet=0, tls=0, mmtls=0,
                backend="iptables", fail_expr="", fail_queue=False):
    """Exercise actual init control flow with print-only shell command functions."""
    source = (ROOT / "openwrt/files/ua2f.init").read_text().replace(
        ". /usr/share/ua2f/firewall.sh", '. "$TEST_HELPER"')
    mocks = r'''
record() {
    printf '%s' "$1"
    shift
    printf '\t%s' "$@"
    printf '\n'
    case " $* " in *' -D '*) return 1 ;; esac
    for arg in "$@"; do
        [ -z "$TEST_FAIL_EXPR" ] || [ "$arg" != "$TEST_FAIL_EXPR" ] || return 1
        [ "$TEST_FAIL_QUEUE" != 1 ] || [ "$arg" != NFQUEUE ] || return 1
    done
    if [ "$TEST_FAIL_QUEUE" = 2 ] && [ "$1" = -t ] && [ "${5:-}" = -j ] && [ "${6:-}" = NFQUEUE ]; then
        return 1
    fi
    return 0
}
iptables() { record iptables "$@"; }
ip6tables() { record ip6tables "$@"; }
nft() { if [ "$1" = -f- ]; then cat; else record nft "$@"; fi; }
config_load() { :; }
config_get_bool() {
    case "$1" in
        handle_fw) export "$1=1" ;;
        bypass_empty_ack) export "$1=$TEST_ENABLED" ;;
        disable_connmark) export "$1=$TEST_DISABLE_MARKS" ;;
        handle_intranet) export "$1=$TEST_INTRANET" ;;
        handle_tls) export "$1=$TEST_TLS" ;;
        handle_mmtls) export "$1=$TEST_MMTLS" ;;
        *) return 1 ;;
    esac
}
config_get() {
    case "$1" in
        mode) export "$1=NFQUEUE" ;;
        listen_port) export "$1=10010" ;;
        nfqueue_workers) export "$1=$TEST_WORKERS" ;;
        *) return 1 ;;
    esac
}
'''
    env = dict(os.environ, TEST_HELPER=str(HELPER), TEST_ENABLED=str(enabled),
               TEST_WORKERS=str(workers), TEST_DISABLE_MARKS=str(1-marks),
               TEST_INTRANET=str(intranet), TEST_TLS=str(tls), TEST_MMTLS=str(mmtls),
               TEST_BACKEND=backend, TEST_FAIL_EXPR=fail_expr, TEST_FAIL_QUEUE=str(int(fail_queue)))
    run = subprocess.run(["sh", "-c", mocks + source + r'''
HAS_IPT6=mock
if [ "$TEST_BACKEND" = nft ]; then HAS_NFT=mock; else HAS_NFT=; fi
setup_firewall
'''], env=env, text=True, capture_output=True, check=True)
    return run.stdout.splitlines(), run.stderr


class EmptyAckRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {family: generate("ua2f_empty_ack_u32", family) for family in (4, 6)}
        cls.nft = generate("ua2f_empty_ack_nft")
        cls.lengths = {family: generate("ua2f_empty_ack_length_u32", family)[0] for family in (4, 6)}
        cls.tails = {family: [row.split("\t") for row in generate("ua2f_empty_ack_queue_iptables", family, 10010, 10010)]
                     for family in (4, 6)}

    def bypass(self, family, data):
        old = any(u32_matches(expr, data) for expr in self.rules[family])
        # New early queue is only a terminal queue on a coarse non-match.
        new = u32_matches(self.lengths[family], data) and old
        self.assertEqual(new, old, (family, data.hex()))
        return old

    def test_frozen_original_predicates(self):
        # Guard against accidentally proving equivalence to a modified baseline.
        for family in (4, 6):
            old = []
            for doff in range(5, 16):
                if family == 4:
                    old.append(f"0&0xFFFF={20 + 4*doff} && 0>>24&0xF=5 && 4&0x3FFF=0 && 6&0xFF=6 && 32>>28={doff} && 33>>24&0x17=0x10 && {16 + 4*doff}&0=0")
                else:
                    old.append(f"4>>16={4*doff} && 4>>8&0xFF=6 && 52>>28={doff} && 53>>24&0x17=0x10 && {36 + 4*doff}&0=0")
            self.assertEqual(self.rules[family], old)

    def test_all_byte_strings_equivalence_by_necessary_condition(self):
        # An exact rule begins with the SAME read and operations as the coarse
        # guard, then compares one value inside its interval. Hence old RETURN
        # implies coarse match for EVERY packet byte string, including malformed
        # versions, extra trailing bytes, options, fragments and truncated reads.
        # If the shared read fails, neither predicate matches. All other cases
        # preserve eleven original predicates and the exact original NFQUEUE.
        for family in (4, 6):
            coarse, = parse_u32(self.lengths[family])
            for expr in self.rules[family]:
                precise = parse_u32(expr)[0]
                self.assertEqual(precise[:2], coarse[:2])
                self.assertEqual(precise[2], precise[3])
                self.assertLessEqual(coarse[2], precise[2])
                self.assertLessEqual(precise[3], coarse[3])
            tail = self.tails[family]
            self.assertEqual(tail[0], ["-m", "u32", "!", "--u32", self.lengths[family], *tail[-1]])
            self.assertEqual(tail[-1], ["-j", "NFQUEUE", "--queue-num", "10010", "--queue-bypass"])
            self.assertEqual(tail[1:-1], [
                ["-p", "tcp", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "u32", "--u32", expr, "-j", "RETURN"]
                for expr in self.rules[family]])

    def test_exhaustive_declared_lengths_and_truncated_reads(self):
        # All 16-bit declared lengths, including invalid/jumbo/forged values,
        # with both minimal and maximal TCP headers and long trailing skb bytes.
        for family, doff in itertools.product((4, 6), (5, 15)):
            data = bytearray(packet(family, doff) + b"unexpected trailing bytes")
            for length in range(65536):
                struct.pack_into("!H", data, 2 if family == 4 else 4, length)
                self.bypass(family, data)
            for size in range(105):
                self.bypass(family, bytes(data[:size]))

    def test_exhaustive_ipv4_fragment_fields(self):
        for frag in range(65536):
            self.assertEqual(self.bypass(4, packet(4, frag=frag)), frag & 0x3fff == 0)

    def test_exhaustive_header_byte_mutations_and_random_malformed_packets(self):
        for family in (4, 6):
            # Every single-byte mutation across all bytes of a maximal header.
            original = packet(family, doff=15)
            for offset, value in itertools.product(range(len(original)), range(256)):
                data = bytearray(original)
                data[offset] = value
                self.bypass(family, data)
            rng = random.Random(0x2F)
            for _ in range(10000):
                self.bypass(family, rng.randbytes(rng.randrange(257)))

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
        for ihl, doff, frag in itertools.product(range(16), range(16), (0, 0x4000, 0x2000, 1, 0x3fff)):
            want = ihl == 5 and doff >= 5 and frag & 0x3fff == 0
            self.assertEqual(self.bypass(4, packet(4, doff, ihl=ihl, frag=frag)), want, (ihl, doff, frag))

    def test_ipv6_extensions_and_other_protocols_fall_back(self):
        for family, nh, doff in itertools.product((4, 6), range(256), range(5, 16)):
            self.assertEqual(self.bypass(family, packet(family, doff, nexthdr=nh)), nh == 6)

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

    def test_queue_tail_parameters_and_print_only_installer(self):
        # The installer must execute the TSV generator verbatim, including arg
        # boundaries, alternate queue IDs, balance ranges and queue-bypass flags.
        code = r'''. "$1"
mock() { printf '%s' "$1"; shift; printf '\t%s' "$@"; printf '\n'; }
ua2f_add_empty_ack_queue_iptables "$2" "$3" "$4" mock -t mangle -A 'space in chain'
'''
        for family, first, last in itertools.product((4, 6), (0, 10010, 65520), (0, 1, 15)):
            last += first
            rows = generate("ua2f_empty_ack_queue_iptables", family, first, last)
            self.assertEqual(len(rows), 13)
            self.assertEqual(rows[0].split("\t")[-5:], rows[-1].split("\t"))
            self.assertEqual(rows[-1].split("\t"), ["-j", "NFQUEUE", "--queue-num" if first == last else "--queue-balance",
                                                    str(first) if first == last else f"{first}:{last}", "--queue-bypass"])
            actual = subprocess.check_output(["sh", "-c", code, "sh", str(HELPER), str(family), str(first), str(last)], text=True).splitlines()
            self.assertEqual(actual, ["-t\tmangle\t-A\tspace in chain\t" + row for row in rows])

    def test_invalid_queue_configuration_is_rejected_before_emission(self):
        for family, first, last in ((7, 10010, 10010), (4, -1, 1), (6, 1, 65536), (4, 2, 1),
                                    (4, "", 1), (4, 1, ""), (6, "x", 1), (4, "1:2", 3),
                                    (4, "1;echo bad", 2), (6, "1\t2", 3)):
            args = ["sh", "-c", '. "$1"; ua2f_empty_ack_queue_iptables "$2" "$3" "$4"', "sh", str(HELPER), str(family), str(first), str(last)]
            run = subprocess.run(args, text=True, capture_output=True, check=False)
            self.assertNotEqual(run.returncode, 0, (family, first, last))
            self.assertEqual(run.stdout, "")

    def test_actual_init_preserves_mark_and_bypass_order(self):
        for workers, marks, intranet, tls, mmtls in itertools.product((1, 4, 16), (0, 1), (0, 1), (0, 1), (0, 1)):
            baseline, err = mocked_init(enabled=0, workers=workers, marks=marks, intranet=intranet, tls=tls, mmtls=mmtls)
            self.assertEqual(err, "")
            optimized, err = mocked_init(enabled=1, workers=workers, marks=marks, intranet=intranet, tls=tls, mmtls=mmtls)
            self.assertEqual(err, "")
            for family, command in ((4, "iptables"), (6, "ip6tables")):
                prefix = f"{command}\t-t\tmangle\t-A\tua2f\t"
                before = [line.removeprefix(prefix) for line in baseline if line.startswith(prefix)]
                after = [line.removeprefix(prefix) for line in optimized if line.startswith(prefix)]
                # All rules preceding the original queue stay byte-for-byte in
                # order; only its location is replaced by the generated tail.
                tail = generate("ua2f_empty_ack_queue_iptables", family, 10010, 10010+workers-1)
                self.assertEqual(after, before[:-1] + tail)
                self.assertEqual(before[-1], tail[-1])
                if marks:
                    set44 = next(i for i, line in enumerate(after) if "--set-mark\t44" in line)
                    ret43 = next(i for i, line in enumerate(after) if "--mark\t43" in line)
                    self.assertLess(set44, ret43)
                    self.assertLess(ret43, len(before)-1)
                else:
                    self.assertFalse(any("CONNMARK" in line or "connmark" in line for line in after))
            # Hook direction/family gates and all other chain operations unchanged.
            is_tail = lambda line: any(line.startswith(f"{cmd}\t-t\tmangle\t-A\tua2f\t") for cmd in ("iptables", "ip6tables"))
            self.assertEqual([line for line in baseline if not is_tail(line)], [line for line in optimized if not is_tail(line)])
            self.assertIn("iptables\t-t\tmangle\t-A\tPOSTROUTING\t-p\ttcp\t-m\tconntrack\t--ctdir\tORIGINAL\t-j\tua2f", optimized)
            self.assertIn("ip6tables\t-t\tmangle\t-A\tPOSTROUTING\t-p\ttcp\t-m\tconntrack\t--ctdir\tORIGINAL\t-j\tua2f", optimized)

    def test_partial_install_always_attempts_original_fallback(self):
        for family, workers in itertools.product((4, 6), (1, 16)):
            command = "iptables" if family == 4 else "ip6tables"
            prefix = f"{command}\t-t\tmangle\t-A\tua2f\t"
            tail = generate("ua2f_empty_ack_queue_iptables", family, 10010, 10010+workers-1)
            # Failure at every u32 rule, including the early guard, leaves a
            # prefix of safe rules followed by the identical original fallback.
            for failed_index in range(12):
                failed = tail[failed_index].split("\t")
                expr = failed[failed.index("--u32") + 1]
                lines, err = mocked_init(workers=workers, fail_expr=expr)
                actual = [line.removeprefix(prefix) for line in lines if line.startswith(prefix)]
                self.assertTrue(actual[-1] == tail[-1])
                self.assertEqual(actual[-failed_index-2:], tail[:failed_index+1] + [tail[-1]])
                self.assertIn(f"empty-ACK IPv{family} optimization unavailable; keeping NFQUEUE fallback", err)
        # A queue target failure also still attempts the old unconditional rule;
        # the test does not pretend an unavailable NFQUEUE target can be fixed.
        lines, err = mocked_init(fail_queue=True)
        self.assertIn("keeping NFQUEUE fallback", err)
        self.assertEqual(sum(line.endswith("-j\tNFQUEUE\t--queue-num\t10010\t--queue-bypass") for line in lines), 4)
        lines, err = mocked_init(fail_queue=2)
        self.assertIn("keeping NFQUEUE fallback", err)
        for command in ("iptables", "ip6tables"):
            prefix = f"{command}\t-t\tmangle\t-A\tua2f\t"
            actual = [line.removeprefix(prefix) for line in lines if line.startswith(prefix)]
            self.assertEqual(actual[-1], actual[-2])
            self.assertEqual(actual[-1], "-j\tNFQUEUE\t--queue-num\t10010\t--queue-bypass")

    def test_nft_path_is_unchanged(self):
        for workers, marks in itertools.product((1, 16), (0, 1)):
            disabled, err = mocked_init(enabled=0, workers=workers, marks=marks, backend="nft")
            self.assertEqual(err, "")
            enabled, err = mocked_init(enabled=1, workers=workers, marks=marks, backend="nft")
            self.assertEqual(err, "")
            # nft still inserts only the original 22 predicates, no new queue.
            self.assertEqual([line for line in enabled if "!ua2f: empty ACK" not in line and line.strip()],
                             [line for line in disabled if line.strip()])
            emitted = [line.strip() for line in enabled if "!ua2f: empty ACK" in line]
            self.assertEqual(emitted, self.nft)

    def test_invalid_family_emits_nothing(self):
        result = subprocess.run(["sh", "-c", '. "$1"; ua2f_empty_ack_u32 7', "sh", str(HELPER)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_opt_in_only_and_queue_order(self):
        source = (ROOT / "openwrt/files/ua2f.init").read_text()
        self.assertIn('config_get_bool bypass_empty_ack "firewall" "bypass_empty_ack" "0"', source)
        self.assertEqual(source.count('! ua2f_add_empty_ack_queue_iptables 4 10010 "$nfqueue_end" iptables'), 1)
        self.assertEqual(source.count('! ua2f_add_empty_ack_queue_iptables 6 10010 "$nfqueue_end" ip6tables'), 1)
        self.assertLess(source.index("ct mark 43 counter return", source.index("setup_firewall()")), source.index("|| ua2f_empty_ack_nft"))
        self.assertLess(source.index("|| ua2f_empty_ack_nft"), source.index("ct direction original counter $nfqueue_expr"))
        self.assertIn("iptables-mod-u32", (ROOT / "openwrt/Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
