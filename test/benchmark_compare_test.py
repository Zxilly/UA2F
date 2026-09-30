#!/usr/bin/env python3
"""Nonprivileged checks for experimental benchmark accounting and ordering."""
import argparse
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import benchmark_compare as compare
import test_empty_ack_netns as empty_ack
from benchmark import BenchmarkError


def counters(sequence=12, port=1234, number=10010, dropped=0, user_dropped=0):
    return compare.parse_queue_counters(
        f"{number} {port} 2 2 65531 {dropped} {user_dropped} {sequence} 1\n", number, 1)


class QueueCountersTest(unittest.TestCase):
    def test_kernel_proc_field_order(self):
        row = counters()[10010]
        self.assertEqual(row, {"queue_num": 10010, "peer_portid": 1234,
                              "queue_total": 2, "copy_mode": 2, "copy_range": 65531,
                              "queue_dropped": 0, "queue_user_dropped": 0, "id_sequence": 12})

    def test_uses_packet_sequence_not_backlog(self):
        old, new = counters(12), counters(1012)
        new[10010]["queue_total"] = 3
        result = compare.queue_delta(old, new)
        self.assertEqual(result["packets"], 1000)
        self.assertEqual(result["after"][10010]["queue_total"], 3)

    def test_one_uint32_wrap(self):
        self.assertEqual(compare.queue_delta(counters(0xfffffffd), counters(3))["packets"], 6)

    def test_missing_queue_rejected(self):
        with self.assertRaises(BenchmarkError):
            compare.parse_queue_counters("10011 99 0 2 65531 0 0 5 1", 10010, 1)

    def test_duplicate_queue_rejected(self):
        with self.assertRaises(BenchmarkError):
            compare.parse_queue_counters("10010 99 0 2 65531 0 0 5 1\n" * 2, 10010, 1)

    def test_malformed_line_rejected(self):
        for raw in ("10010 99", "10010 xx 0 2 65531 0 0 5 1", "10010 99 0 2 65531 0 0 -1 1"):
            with self.subTest(raw=raw), self.assertRaises(BenchmarkError):
                compare.parse_queue_counters(raw, 10010, 1)

    def test_recreated_queue_and_drops_rejected(self):
        for new in (counters(20, port=1235), counters(20, dropped=1),
                    counters(20, user_dropped=1), counters(5)):
            with self.subTest(new=new), self.assertRaises(BenchmarkError):
                compare.queue_delta(counters(12), new)

    def test_workers_sum_and_other_queues_ignored(self):
        raw = "10010 12 0 2 65531 0 0 10 1\n10011 13 0 2 65531 0 0 20 1\n8 9 0 2 65531 0 0 90 1\n"
        old = compare.parse_queue_counters(raw, 10010, 2)
        new = copy.deepcopy(old)
        new[10010]["id_sequence"] += 9
        new[10011]["id_sequence"] += 11
        self.assertEqual(compare.queue_delta(old, new)["packets"], 20)


class PlanTest(unittest.TestCase):
    def test_legacy_plan_still_72_cases(self):
        plan = compare.make_plan(6, [1024, 65536])
        self.assertEqual(len(plan), 72)
        self.assertNotIn("DIRECT", {r["mode"] for r in plan})

    def test_direct_never_separates_adjacent_pair(self):
        plan = compare.make_plan(6, [1024, 65536], ["NFQUEUE"], True)
        self.assertEqual(len(plan), 36)
        self.assertEqual(sum(r["mode"] == "DIRECT" for r in plan), 12)
        for pair in range(1, 7):
            for size in (1024, 65536):
                indices = [i for i, r in enumerate(plan) if r["pair"] == pair and
                           r["body_bytes"] == size and r["mode"] == "NFQUEUE"]
                self.assertEqual(indices[1], indices[0] + 1)
                expected = ["base", "candidate"] if pair % 2 else ["candidate", "base"]
                self.assertEqual([plan[i]["variant"] for i in indices], expected)

    def test_partial_direct_not_reported_complete(self):
        args = argparse.Namespace(include_direct=True, body_sizes=[1024], pairs=6)
        results = [{"body_bytes": 1024, "mode": "DIRECT", "ok": True, "summary": {"rps": 42}}]
        rows = compare.direct_aggregates(results, args)
        self.assertFalse(rows[0]["complete"])
        self.assertNotIn("rps", rows[0])


class ValidationTest(unittest.TestCase):
    def test_nft_wrapper_separates_declarations_and_closing_blocks(self):
        rules = 'ip protocol tcp counter return;\nip6 nexthdr tcp counter return;\n'
        generated = empty_ack.nft_ruleset("test0", rules)
        self.assertIn("  }\n  chain inspect {\n", generated)
        self.assertTrue(generated.endswith("  }\n}\n"))
        self.assertNotIn("} chain", generated)
        self.assertNotIn("} }", generated)
        self.assertEqual(generated.count(rules), 1)
        self.assertEqual(generated.count("counter queue num 10010;"), 1)

    def test_timed_rules_include_production_conntrack_matching(self):
        expressions = [f"32>>28={n}" for n in range(5, 16)]
        with patch("benchmark_compare.bench.run_cmd") as run:
            run.return_value = SimpleNamespace(stdout="\n".join(expressions))
            self.assertEqual(compare.install_empty_ack_candidate(Path("/source/helper"), "TEST"), expressions)
        self.assertEqual(run.call_count, 12)
        for index, call in enumerate(run.call_args_list[1:], 1):
            args = call.args[0]
            self.assertEqual(args[4:6], ["TEST", str(index)])
            self.assertIn("conntrack", args)
            self.assertEqual(args[args.index("--ctdir") + 1], "ORIGINAL")
            self.assertEqual(args[-2:], ["-j", "RETURN"])

    def test_direct_and_rewritten_ua_validation_are_distinct(self):
        client = {"requests": 1, "completed": 1, "errors": 0,
                  "status_counts": {"200": 1}, "latencies_sec": [.1], "duration_sec": .1}
        unchanged = {"requests": 1, "user_agents": {"UA-BENCH/0": 1}}
        rewritten = {"requests": 1, "user_agents": {"FFFFFFFFFF": 1}}
        compare.validate_client(client, unchanged, 1, direct=True)
        compare.validate_client(client, rewritten, 1)
        with self.assertRaises(BenchmarkError):
            compare.validate_client(client, unchanged, 1)
        with self.assertRaises(BenchmarkError):
            compare.validate_client(client, rewritten, 1, direct=True)


if __name__ == "__main__":
    unittest.main()
