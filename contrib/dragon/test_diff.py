#!/usr/bin/env python3
"""Unit tests for diff.py.

  cd contrib/dragon && python3 -m unittest -v test_diff
"""

import argparse
import json
import os
import shutil
import tempfile
import unittest

import diff


def rec(slot, kind, key, **payload):
    return {"seq": 0, "slot": slot, "kind": kind, "key": key, "payload": payload}


def account(slot, pubkey, lamports=1, rent_epoch=(1 << 64) - 1, startup=False):
    return rec(slot, "account", pubkey, pubkey=pubkey, lamports=lamports,
               owner="Owner", executable=False, rent_epoch=rent_epoch,
               data="00ff", data_len=2, txn_signature=None,
               is_startup=startup, filters=["all"])


def txn(slot, sig, index=0, fee=5000, logs=("a",)):
    return rec(slot, "transaction", sig, signature=sig, is_vote=False, index=index,
               transaction={"signatures": [sig], "message": {"account_keys": ["K1"]}},
               meta={"fee": fee, "log_messages": list(logs), "err": None,
                     "cost_units": 100},
               filters=["t"])


class DiffCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test-diff-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write(self, name, records):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        return path

    def run_diff(self, a, b, **kwargs):
        args = argparse.Namespace(
            label_a="a", label_b="b", ignore=[], kind=[], drop_startup_a=False,
            drop_startup_b=False, common_slots=False, slots=None, skip_first=0,
            skip_last=0, max_report=10, json=None)
        for k, v in kwargs.items():
            setattr(args, k, v)
        kinds = set(args.kind) or None
        window = (None, None)
        if args.slots:
            lo, _, hi = args.slots.partition(":")
            window = (int(lo) if lo else None, int(hi) if hi else None)
        a_slots, a_total, a_drop = diff.load(a, args.drop_startup_a, kinds, window)
        b_slots, b_total, b_drop = diff.load(b, args.drop_startup_b, kinds, window)
        a_slots = diff.apply_masks(a_slots, set(args.ignore))
        b_slots = diff.apply_masks(b_slots, set(args.ignore))
        report = {}
        bad = diff.compare(a_slots, b_slots, args, report)
        report["dropped"] = (a_drop, b_drop)
        report["totals"] = (a_total, b_total)
        return bad, report

    # -- the comparison itself

    def test_identical_captures_match(self):
        a = self.write("a.jsonl", [account(10, "P1"), txn(10, "S1")])
        b = self.write("b.jsonl", [account(10, "P1"), txn(10, "S1")])
        bad, report = self.run_diff(a, b)
        self.assertEqual(bad, 0)
        self.assertEqual(report["only_in_a"], {})
        self.assertEqual(report["only_in_b"], {})

    def test_order_within_a_slot_does_not_matter(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(10, "S2"), account(10, "P1")])
        b = self.write("b.jsonl", [account(10, "P1"), txn(10, "S2"), txn(10, "S1")])
        self.assertEqual(self.run_diff(a, b)[0], 0)

    def test_same_key_in_two_slots_is_not_confused(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(11, "S1")])
        b = self.write("b.jsonl", [txn(10, "S1"), txn(11, "S1", index=3)])
        bad, report = self.run_diff(a, b)
        self.assertEqual(bad, 1)
        self.assertEqual(report["first_slots_with_differences"], [11])

    def test_duplicate_of_one_update_is_a_difference(self):
        a = self.write("a.jsonl", [txn(10, "S1")])
        b = self.write("b.jsonl", [txn(10, "S1"), txn(10, "S1")])
        bad, report = self.run_diff(a, b)
        self.assertEqual(bad, 1)
        self.assertEqual(report["only_in_b"], {"transaction": 1})

    def test_missing_update_shows_only_in_a(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(10, "S2")])
        b = self.write("b.jsonl", [txn(10, "S1")])
        bad, report = self.run_diff(a, b)
        self.assertEqual(bad, 1)
        self.assertEqual(report["only_in_a"], {"transaction": 1})
        self.assertEqual(report["samples"][0]["only_in"], "a")

    def test_differing_payload_reports_the_field(self):
        a = self.write("a.jsonl", [txn(10, "S1", fee=5000)])
        b = self.write("b.jsonl", [txn(10, "S1", fee=7000)])
        bad, report = self.run_diff(a, b)
        self.assertEqual(bad, 1)
        self.assertEqual(report["differing"], {"transaction": 1})
        paths = [f["path"] for f in report["samples"][0]["fields"]]
        self.assertEqual(paths, ["meta.fee"])

    def test_list_length_difference_is_reported(self):
        a = self.write("a.jsonl", [txn(10, "S1", logs=("a", "b"))])
        b = self.write("b.jsonl", [txn(10, "S1", logs=("a",))])
        _, report = self.run_diff(a, b)
        paths = [f["path"] for f in report["samples"][0]["fields"]]
        self.assertIn("meta.log_messages[]", paths)

    # -- masks

    def test_ignored_field_is_not_a_difference(self):
        a = self.write("a.jsonl", [account(10, "P1", rent_epoch=0)])
        b = self.write("b.jsonl", [account(10, "P1", rent_epoch=(1 << 64) - 1)])
        self.assertEqual(self.run_diff(a, b)[0], 1)
        self.assertEqual(self.run_diff(a, b, ignore=["rent_epoch"])[0], 0)

    def test_ignored_field_is_dropped_at_any_depth(self):
        a = self.write("a.jsonl", [txn(10, "S1")])
        b_rec = txn(10, "S1")
        b_rec["payload"]["meta"]["cost_units"] = 999
        b = self.write("b.jsonl", [b_rec])
        self.assertEqual(self.run_diff(a, b)[0], 1)
        self.assertEqual(self.run_diff(a, b, ignore=["cost_units"])[0], 0)

    def test_startup_accounts_are_dropped_on_the_oracle_side(self):
        a = self.write("a.jsonl", [account(10, "P0", startup=True), account(10, "P1")])
        b = self.write("b.jsonl", [account(10, "P1")])
        self.assertEqual(self.run_diff(a, b)[0], 1)
        bad, report = self.run_diff(a, b, drop_startup_a=True)
        self.assertEqual(bad, 0)
        self.assertEqual(report["dropped"], (1, 0))

    def test_kind_filter_restricts_the_comparison(self):
        a = self.write("a.jsonl", [txn(10, "S1"), account(10, "P1")])
        b = self.write("b.jsonl", [txn(10, "S1"), account(10, "P1", lamports=2)])
        self.assertEqual(self.run_diff(a, b)[0], 1)
        self.assertEqual(self.run_diff(a, b, kind=["transaction"])[0], 0)

    # -- slot windows

    def test_slots_only_on_one_side_are_reported(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(11, "S2")])
        b = self.write("b.jsonl", [txn(11, "S2"), txn(12, "S3")])
        bad, report = self.run_diff(a, b)
        self.assertEqual(report["slots_only_in_a"], [10])
        self.assertEqual(report["slots_only_in_b"], [12])
        self.assertEqual(bad, 2)

    def test_common_slots_compares_the_overlap_only(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(11, "S2")])
        b = self.write("b.jsonl", [txn(11, "S2"), txn(12, "S3")])
        bad, report = self.run_diff(a, b, common_slots=True)
        self.assertEqual(bad, 0)
        self.assertEqual(report["slots_compared"], 1)

    def test_skip_first_and_last_bound_the_window(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(11, "S2"), txn(12, "S3")])
        b = self.write("b.jsonl", [txn(10, "SX"), txn(11, "S2"), txn(12, "SY")])
        self.assertEqual(self.run_diff(a, b)[0], 2)
        self.assertEqual(self.run_diff(a, b, skip_first=1, skip_last=1)[0], 0)

    def test_slot_range_bounds_the_window(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(20, "S2")])
        b = self.write("b.jsonl", [txn(10, "S1"), txn(20, "SX")])
        self.assertEqual(self.run_diff(a, b, slots="10:15")[0], 0)
        self.assertEqual(self.run_diff(a, b, slots="15:")[0], 1)

    def test_slot_range_is_applied_while_loading(self):
        a = self.write("a.jsonl", [txn(10, "S1"), txn(20, "S2")])
        self.assertEqual(diff.load(a)[1], 2)
        self.assertEqual(diff.load(a, window=(15, None))[1], 1)
        self.assertEqual(diff.load(a, window=(None, 15))[1], 1)
        self.assertEqual(diff.load(a, window=(11, 19))[1], 0)


class MaskCase(unittest.TestCase):

    def test_mask_removes_the_name_everywhere(self):
        value = {"a": 1, "b": {"a": 2, "c": [{"a": 3, "d": 4}]}}
        self.assertEqual(diff.mask(value, {"a"}), {"b": {"c": [{"d": 4}]}})

    def test_mask_of_an_unknown_name_changes_nothing(self):
        value = {"a": 1, "b": [1, 2]}
        self.assertEqual(diff.mask(value, {"zz"}), value)


if __name__ == "__main__":
    unittest.main()
