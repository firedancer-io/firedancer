#!/usr/bin/env python3
"""Unit tests for selfcheck.py.

  cd contrib/dragon && python3 -m unittest -v test_selfcheck
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import selfcheck

HERE = os.path.dirname(os.path.abspath(__file__))


def account(slot, pubkey, lamports=1, wv=1, data="00", seq=0):
    return {"seq": seq, "slot": slot, "kind": "account", "key": pubkey,
            "payload": {"pubkey": pubkey, "lamports": lamports, "owner": "Owner",
                        "executable": False, "rent_epoch": 0, "data": data,
                        "data_len": len(data) // 2, "txn_signature": None,
                        "is_startup": False, "filters": ["all"]},
            "nondet": {"write_version": wv, "bank_id": slot}}


def txn(slot, sig, index=0, fee=5000, seq=0):
    return {"seq": seq, "slot": slot, "kind": "transaction", "key": sig,
            "payload": {"signature": sig, "is_vote": False, "index": index,
                        "transaction": {"signatures": [sig], "message": {}},
                        "meta": {"fee": fee}, "filters": ["t"]},
            "nondet": {"bank_id": slot}}


def block_meta(slot, count, seq=0):
    return {"seq": seq, "slot": slot, "kind": "block_meta", "key": "BH%d" % slot,
            "payload": {"blockhash": "BH%d" % slot, "parent_slot": slot - 1,
                        "executed_transaction_count": count, "entries_count": 0,
                        "filters": ["bm"]},
            "nondet": {"bank_id": slot}}


def block(slot, sigs, pubkeys, seq=0):
    return {"seq": seq, "slot": slot, "kind": "block", "key": "BH%d" % slot,
            "payload": {"blockhash": "BH%d" % slot, "parent_slot": slot - 1,
                        "executed_transaction_count": len(sigs),
                        "updated_account_count": len(pubkeys),
                        "transactions": [{"signature": s, "index": i}
                                         for i, s in enumerate(sigs)],
                        "accounts": [{"pubkey": p} for p in pubkeys],
                        "entries": [], "entries_count": 0, "filters": ["blk"]},
            "nondet": {"bank_id": slot}}


def status(slot, name, seq):
    return {"seq": seq, "slot": slot, "kind": "slot", "key": name,
            "payload": {"status": name, "parent": slot - 1, "dead_error": None,
                        "filters": ["s"]},
            "nondet": {"bank_id": slot}}


class SelfcheckCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test-selfcheck-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write(self, prefix, records=(), statuses=()):
        path = os.path.join(self.dir, prefix)
        with open(path + ".jsonl", "w") as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        if statuses:
            with open(path + ".slots.jsonl", "w") as f:
                for r in statuses:
                    f.write(json.dumps(r, sort_keys=True) + "\n")
        return path

    def metrics(self, skipped=0, truncated=0):
        path = os.path.join(self.dir, "metrics.txt")
        with open(path, "w") as f:
            f.write('dragon_account_skipped_total{kind="dragon",kind_id="0"} %d\n'
                    % skipped)
            f.write('dragon_record_truncated_total{kind="dragon",kind_id="0"} %d\n'
                    % truncated)
        return path

    def truncated_log(self, *records):
        """A dragon log naming one truncated record per (slot, accounts)."""
        path = os.path.join(self.dir, "truncated.log")
        with open(path, "w") as f:
            for i, (slot, accounts) in enumerate(records):
                f.write("NOTICE  09-14 00:00:00.000000 0 fd_geyser_core.c(1285): "
                        "dragon truncated record: slot %d bank %d index %d "
                        "accounts %d\n" % (slot, slot, i, accounts))
        return path

    def run_check(self, *args):
        """Runs selfcheck as a program and returns (rc, verdicts)."""
        out = os.path.join(self.dir, "report.json")
        cmd = [sys.executable, os.path.join(HERE, "selfcheck.py"),
               "--json", out, "--skip-first", "0", "--skip-last", "0"] + list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        with open(out) as f:
            report = json.load(f)
        return proc.returncode, {r["check"]: r["verdict"] for r in report}, proc.stdout

    # -- transactions

    def test_equal_transactions_pass(self):
        p = self.write("p", [txn(10, "S1"), txn(10, "S2", index=1)])
        f = self.write("f", [txn(10, "S1"), txn(10, "S2", index=1)])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 0)
        self.assertEqual(v["transactions finalized"], "PASS")

    def test_missing_transaction_fails(self):
        p = self.write("p", [txn(10, "S1"), txn(10, "S2", index=1)])
        f = self.write("f", [txn(10, "S1")])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["transactions finalized"], "FAIL")

    def test_differing_meta_fails(self):
        p = self.write("p", [txn(10, "S1", fee=5000)])
        f = self.write("f", [txn(10, "S1", fee=9000)])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["transactions finalized"], "FAIL")

    def test_index_must_be_dense(self):
        p = self.write("p", [txn(10, "S1", index=0), txn(10, "S2", index=2)])
        rc, v, _ = self.run_check("--level", "processed=" + p)
        self.assertEqual(rc, 1)
        self.assertEqual(v["index dense processed"], "FAIL")

    # -- accounts

    def test_accounts_dedup_to_the_last_write(self):
        p = self.write("p", [account(10, "P1", lamports=1, wv=1),
                             account(10, "P1", lamports=2, wv=7),
                             account(10, "P2", lamports=5, wv=3)])
        f = self.write("f", [account(10, "P1", lamports=2, wv=7),
                             account(10, "P2", lamports=5, wv=3)])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "PASS")
        self.assertEqual(v["accounts deduped finalized"], "PASS")

    def test_wrong_write_wins_fails(self):
        p = self.write("p", [account(10, "P1", lamports=1, wv=1),
                             account(10, "P1", lamports=2, wv=7)])
        f = self.write("f", [account(10, "P1", lamports=1, wv=1)])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")

    def test_account_served_twice_at_finalized_fails(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P1")])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts deduped finalized"], "FAIL")

    def test_account_missing_at_finalized_fails(self):
        p = self.write("p", [account(10, "P1"), account(10, "P2")])
        f = self.write("f", [account(10, "P1")])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts missing finalized"], "FAIL")

    # -- the truncated record exception

    def test_finalized_only_account_fails_without_metrics(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        rc, v, out = self.run_check("--level", "processed=" + p,
                                    "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")
        self.assertIn("no --metrics", out)

    def test_finalized_only_account_warns_within_the_skipped_budget(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        rc, v, out = self.run_check("--level", "processed=" + p,
                                    "--level", "finalized=" + f,
                                    "--metrics", self.metrics(skipped=1, truncated=1))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "WARN")
        self.assertIn("truncated record", out)

    def test_more_unexplained_accounts_than_skipped_writes_fails(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2"), account(10, "P3")])
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--metrics", self.metrics(skipped=1, truncated=1))
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")

    def test_stale_processed_state_counts_against_the_same_budget(self):
        p = self.write("p", [account(10, "P1", lamports=1, wv=1)])
        f = self.write("f", [account(10, "P1", lamports=4, wv=9)])
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--metrics", self.metrics(skipped=1, truncated=1))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "WARN")

    # -- the truncated record log

    def test_truncated_log_accounts_for_a_finalized_only_account(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        rc, v, out = self.run_check("--level", "processed=" + p,
                                    "--level", "finalized=" + f,
                                    "--truncated-log", self.truncated_log((10, 1)))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "PASS")
        self.assertIn("every one of them accounted for", out)

    def test_a_slot_with_no_truncated_record_fails(self):
        p = self.write("p", [account(10, "P1"), account(11, "P1")])
        f = self.write("f", [account(10, "P1"), account(11, "P1"), account(11, "P2")])
        rc, v, out = self.run_check("--level", "processed=" + p,
                                    "--level", "finalized=" + f,
                                    "--truncated-log", self.truncated_log((10, 4)))
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")
        self.assertIn("no truncated record in that slot", out)

    def test_more_accounts_than_the_record_wrote_fails(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2"), account(10, "P3")])
        rc, v, out = self.run_check("--level", "processed=" + p,
                                    "--level", "finalized=" + f,
                                    "--truncated-log", self.truncated_log((10, 1)))
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")
        self.assertIn("2 accounts to explain, 1 written", out)

    def test_fewer_accounts_than_the_record_wrote_warns(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--truncated-log", self.truncated_log((10, 5)))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "WARN")

    def test_a_stale_state_is_reconciled_the_same_way(self):
        p = self.write("p", [account(10, "P1", lamports=1, wv=1)])
        f = self.write("f", [account(10, "P1", lamports=4, wv=9)])
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--truncated-log", self.truncated_log((10, 1)))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "PASS")
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--truncated-log", self.truncated_log((11, 1)))
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")

    def test_the_metric_only_warns_when_it_disagrees(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        args = ("--level", "processed=" + p, "--level", "finalized=" + f,
                "--truncated-log", self.truncated_log((10, 1)))
        rc, v, _ = self.run_check(*args, "--metrics", self.metrics(skipped=0))
        self.assertEqual(rc, 0)
        self.assertEqual(v["accounts equal finalized"], "PASS")
        self.assertEqual(v["truncated metric finalized"], "WARN")
        rc, v, _ = self.run_check(*args, "--metrics", self.metrics(skipped=1))
        self.assertEqual(v["truncated metric finalized"], "PASS")

    def test_an_empty_truncated_log_still_fails_a_real_difference(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [account(10, "P1"), account(10, "P2")])
        empty = self.truncated_log()
        rc, v, _ = self.run_check("--level", "processed=" + p,
                                  "--level", "finalized=" + f,
                                  "--truncated-log", empty,
                                  "--metrics", self.metrics(skipped=99))
        self.assertEqual(rc, 1)
        self.assertEqual(v["accounts equal finalized"], "FAIL")

    # -- block meta and blocks

    def test_block_meta_count_must_match(self):
        p = self.write("p", [txn(10, "S1"), block_meta(10, 1)])
        rc, v, _ = self.run_check("--level", "processed=" + p)
        self.assertEqual(v["block meta count processed"], "PASS")
        p2 = self.write("p2", [txn(10, "S1"), block_meta(10, 3)])
        rc, v, _ = self.run_check("--level", "processed=" + p2)
        self.assertEqual(rc, 1)
        self.assertEqual(v["block meta count processed"], "FAIL")

    def test_two_block_metas_for_one_slot_fail(self):
        p = self.write("p", [txn(10, "S1"), block_meta(10, 1), block_meta(10, 1)])
        rc, v, _ = self.run_check("--level", "processed=" + p)
        self.assertEqual(rc, 1)
        self.assertEqual(v["block meta once processed"], "FAIL")

    def test_block_carries_exactly_the_slots_content(self):
        p = self.write("p", [txn(10, "S1"), txn(10, "S2", index=1), account(10, "P1")])
        f = self.write("f", [block(10, ["S1", "S2"], ["P1"])])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 0)
        self.assertEqual(v["block transactions finalized"], "PASS")
        self.assertEqual(v["block accounts finalized"], "PASS")

    def test_block_missing_a_transaction_fails(self):
        p = self.write("p", [txn(10, "S1"), txn(10, "S2", index=1)])
        f = self.write("f", [block(10, ["S1"], [])])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["block transactions finalized"], "FAIL")

    def test_block_accounts_are_checked_against_their_own_level(self):
        # the finalized level carries both the accounts and the block,
        # so the two must agree exactly and the processed writes are
        # not what the block is measured against
        p = self.write("p", [account(10, "P1"), account(10, "P2")])
        f = self.write("f", [account(10, "P1"), block(10, [], ["P1"])])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f,
                                  "--metrics", self.metrics(skipped=9))
        self.assertEqual(v["block accounts finalized"], "PASS")

    def test_block_only_account_is_reconciled_when_the_level_has_none(self):
        p = self.write("p", [account(10, "P1")])
        f = self.write("f", [block(10, [], ["P1", "P2"])])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(v["block accounts finalized"], "FAIL")
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f,
                                  "--metrics", self.metrics(skipped=1, truncated=1))
        self.assertEqual(v["block accounts finalized"], "WARN")

    def test_block_count_must_match_what_it_carries(self):
        p = self.write("p", [txn(10, "S1")])
        blk = block(10, ["S1"], ["P1"])
        blk["payload"]["executed_transaction_count"] = 4
        f = self.write("f", [blk])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["block counts finalized"], "FAIL")

    # -- slot statuses

    def test_statuses_in_order_pass(self):
        s = self.write("s", [], [status(10, "created_bank", 0),
                                 status(10, "processed", 1),
                                 status(10, "confirmed", 2),
                                 status(10, "finalized", 3)])
        rc, v, _ = self.run_check("--level", "processed=" + s, "--slots", s)
        self.assertEqual(rc, 0)
        self.assertEqual(v["slot status order"], "PASS")
        self.assertEqual(v["rooted slot once"], "PASS")

    def test_a_status_out_of_order_fails(self):
        s = self.write("s", [], [status(10, "finalized", 0),
                                 status(10, "processed", 1)])
        rc, v, _ = self.run_check("--level", "processed=" + s, "--slots", s)
        self.assertEqual(rc, 1)
        self.assertEqual(v["slot status order"], "FAIL")

    def test_a_slot_finalized_twice_fails(self):
        s = self.write("s", [], [status(10, "finalized", 0),
                                 status(10, "finalized", 1)])
        rc, v, _ = self.run_check("--level", "processed=" + s, "--slots", s)
        self.assertEqual(rc, 1)
        self.assertEqual(v["rooted slot once"], "FAIL")

    def test_finalized_slots_must_ascend(self):
        s = self.write("s", [], [status(11, "finalized", 0),
                                 status(10, "finalized", 1)])
        rc, v, _ = self.run_check("--level", "processed=" + s, "--slots", s)
        self.assertEqual(rc, 1)
        self.assertEqual(v["finalized ascending"], "FAIL")

    def test_a_rooted_slot_with_no_content_fails(self):
        p = self.write("p", [txn(10, "S1"), txn(11, "S2"), txn(12, "S3")],
                       [status(s, "finalized", i) for i, s in enumerate((10, 11, 12))])
        f = self.write("f", [txn(10, "S1"), txn(12, "S3")])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f,
                                  "--slots", p)
        self.assertEqual(rc, 1)
        self.assertEqual(v["rooted slots served"], "FAIL")

    def test_skip_first_drops_the_bank_in_flight_at_connect(self):
        # the first bank was already executing when the subscription
        # opened, so its transactions are partial and its index is not
        # dense; --skip-first 1 is what takes it out
        recs = [txn(10, "S1", index=4), txn(11, "S2", index=0)]
        p = self.write("p", recs)
        rc, v, _ = self.run_check("--level", "processed=" + p)
        self.assertEqual(v["index dense processed"], "FAIL")
        rc, v, _ = self.run_check("--level", "processed=" + p, "--skip-first", "1")
        self.assertEqual(rc, 0)
        self.assertEqual(v["index dense processed"], "PASS")

    def test_skip_last_drops_the_bank_in_flight_when_the_capture_ended(self):
        # the highest slot of the processed capture was cut mid bank,
        # so its indices are not dense; --skip-last 1 is what takes it
        # out, and it does not touch the deferred comparison, whose
        # window never reaches that bank
        p = self.write("p", [txn(10, "S1", index=0), txn(11, "S2", index=0),
                             txn(11, "S3", index=2)])
        f = self.write("f", [txn(10, "S1", index=0)])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(v["index dense processed"], "FAIL")
        out = os.path.join(self.dir, "report.json")
        cmd = [sys.executable, os.path.join(HERE, "selfcheck.py"), "--json", out,
               "--skip-first", "0", "--skip-last", "1",
               "--level", "processed=" + p, "--level", "finalized=" + f]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        with open(out) as fh:
            verdicts = {r["check"]: r["verdict"] for r in json.load(fh)}
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(verdicts["index dense processed"], "PASS")
        self.assertEqual(verdicts["transactions finalized"], "PASS")

    def test_a_slot_only_at_finalized_fails(self):
        p = self.write("p", [txn(10, "S1")])
        f = self.write("f", [txn(10, "S1"), txn(11, "S2")])
        rc, v, _ = self.run_check("--level", "processed=" + p, "--level", "finalized=" + f)
        self.assertEqual(rc, 1)
        self.assertEqual(v["slots covered finalized"], "FAIL")


class MetricsCase(unittest.TestCase):

    def test_counters_are_read_and_summed(self):
        path = tempfile.mktemp()
        with open(path, "w") as f:
            f.write("# HELP dragon_account_skipped_total nope\n")
            f.write('dragon_account_skipped_total{kind="dragon",kind_id="0"} 7\n')
            f.write('other_total{kind="x"} 3\n')
        try:
            m = selfcheck.read_metrics(path)
            self.assertEqual(m["dragon_account_skipped_total"], 7)
            self.assertNotIn("other_total", m)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
