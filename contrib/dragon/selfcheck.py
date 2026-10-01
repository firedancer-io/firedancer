#!/usr/bin/env python3
"""Checks one dragon run against itself (plan WP7).

On a fork-free ledger the finalized content of a slot is by
construction its processed content deduped per account to the last
write, so a single run carries its own oracle.  This tool takes the
normalized captures of one run -- processed and finalized (and
optionally confirmed) -- and asserts what must hold between them:

  transactions     the transactions of a slot at a deferred level are
                   the same multiset, with the same meta, as at
                   processed
  index            the index values of a slot are dense from zero
  accounts         the accounts of a slot at a deferred level are the
                   processed writes of that slot deduped to the last
                   one per pubkey, with that write's state, and no
                   pubkey twice
  block meta       executed_transaction_count is the number of
                   transactions the slot delivered
  blocks           a block carries exactly its slot's transactions and
                   accounts, and its counts agree with what it carries
  slot statuses    the statuses of a slot arrive in order, every rooted
                   slot is finalized exactly once, and finalized slots
                   arrive ascending

Usage:

  ./selfcheck.py --level processed=/tmp/cap/txn_p \\
                 --level processed=/tmp/cap/acct_p \\
                 --level finalized=/tmp/cap/txn_f \\
                 --level finalized=/tmp/cap/acct_f \\
                 --slots /tmp/cap/slots --metrics /tmp/cap/metrics.txt

`--level NAME=PREFIX` names a capture written by capture.py; several
prefixes may carry the same level, and their records are merged.
`--slots PREFIX` is the capture whose slot statuses to check.

Truncated records.  A commit record that named the accounts a
transaction wrote but could not carry their data is not served at
processed at all (the tile counts it in `dragon_account_skipped_total`
and `dragon_record_truncated_total`); at a deferred level the same
account is read from the accounts database and served.  Those accounts
are therefore *expected* to be at finalized and not at processed, and
their last processed state can be stale.  This tool never tolerates
that silently: it counts the accounts it cannot explain any other way
and reconciles them against `dragon_account_skipped_total` from
`--metrics`.  Within that budget the check is a WARN naming the
accounts; over it, or with no metrics to check against, it is a FAIL.

Exit code 0 when every check passes (warnings included), 1 otherwise.
"""

import argparse
import collections
import json
import re
import sys

STATUS_RANK = {
    "first_shred_received": 0,
    "created_bank": 1,
    "completed": 2,
    "processed": 3,
    "confirmed": 4,
    "finalized": 5,
}


class Checks:
    """The verdicts of one run."""

    def __init__(self, max_report=8):
        self.results = []
        self.max_report = max_report

    def add(self, name, verdict, summary, details=()):
        self.results.append((name, verdict, summary, list(details)[:self.max_report]))

    def ok(self, name, summary, details=()):
        self.add(name, "PASS", summary, details)

    def warn(self, name, summary, details=()):
        self.add(name, "WARN", summary, details)

    def fail(self, name, summary, details=()):
        self.add(name, "FAIL", summary, details)

    def verdict(self, name, bad, summary, details=()):
        self.add(name, "FAIL" if bad else "PASS", summary, details)

    def report(self):
        failed = 0
        for name, verdict, summary, details in self.results:
            print("CHECK %-22s %-4s %s" % (name, verdict, summary))
            for d in details:
                print("    %s" % d)
            failed += verdict == "FAIL"
        print("RESULT: %s (%d checks, %d failed, %d warnings)"
              % ("FAIL" if failed else "PASS", len(self.results), failed,
                 sum(1 for r in self.results if r[1] == "WARN")))
        return failed


def blob(payload, drop=()):
    if drop:
        payload = {k: v for k, v in payload.items() if k not in drop}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class Level:
    """Everything one commitment level's captures carried."""

    def __init__(self, name):
        self.name = name
        self.txns = collections.defaultdict(collections.Counter)      # slot -> blob -> n
        self.txn_sigs = collections.defaultdict(collections.Counter)  # slot -> sig -> n
        self.txn_index = collections.defaultdict(list)                # slot -> [index]
        self.statuses = collections.defaultdict(collections.Counter)  # slot -> blob -> n
        self.accounts = collections.defaultdict(lambda: collections.defaultdict(list))
        self.meta = collections.defaultdict(list)                     # slot -> [payload]
        self.blocks = collections.defaultdict(list)                   # slot -> [payload]
        self.counts = collections.Counter()

    def add(self, rec):
        kind = rec["kind"]
        slot = rec["slot"]
        payload = rec["payload"]
        self.counts[kind] += 1
        if kind == "transaction":
            self.txns[slot][blob(payload, ("filters",))] += 1
            self.txn_sigs[slot][rec["key"]] += 1
            self.txn_index[slot].append(payload["index"])
        elif kind == "transaction_status":
            self.statuses[slot][blob(payload, ("filters",))] += 1
        elif kind == "account":
            wv = rec.get("nondet", {}).get("write_version")
            self.accounts[slot][rec["key"]].append((wv, payload))
        elif kind == "block_meta":
            self.meta[slot].append(payload)
        elif kind == "block":
            self.blocks[slot].append(payload)

    def all_slots(self):
        return (set(self.txns) | set(self.statuses) | set(self.accounts)
                | set(self.meta) | set(self.blocks))

    def dedup_accounts(self, slot):
        """pubkey -> the state of the highest write version."""
        out = {}
        for pubkey, writes in self.accounts[slot].items():
            best = writes[0]
            for w in writes[1:]:
                if w[0] is None or best[0] is None:
                    continue
                if w[0] > best[0]:
                    best = w
            out[pubkey] = best[1]
        return out


def load_level(level, prefix):
    for suffix in (".jsonl", ".slots.jsonl"):
        try:
            f = open(prefix + suffix)
        except FileNotFoundError:
            continue
        with f:
            for line in f:
                line = line.strip()
                if line:
                    level.add(json.loads(line))


def load_slots(prefix):
    """slot -> [(seq, status, payload)] and the arrival order."""
    per_slot = collections.defaultdict(list)
    order = []
    try:
        f = open(prefix + ".slots.jsonl")
    except FileNotFoundError:
        return per_slot, order
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            status = rec["payload"]["status"]
            per_slot[rec["slot"]].append((rec["seq"], status, rec["payload"]))
            order.append((rec["seq"], rec["slot"], status))
    for slot in per_slot:
        per_slot[slot].sort()
    order.sort()
    return per_slot, order


def read_truncated(path):
    """slot -> (records, accounts they named), from the dragon log.

    The tile logs one line per commit record whose account data did not
    fit, naming the slot and how many accounts the record wrote; those
    accounts are the ones processed cannot carry."""
    per_slot = {}
    if not path:
        return None
    with open(path) as f:
        for line in f:
            m = re.search(r"dragon truncated record: slot (\d+) bank \d+ "
                          r"index \d+ accounts (\d+)", line)
            if not m:
                continue
            slot = int(m.group(1))
            records, accounts = per_slot.get(slot, (0, 0))
            per_slot[slot] = (records+1, accounts+int(m.group(2)))
    return per_slot


def read_metrics(path):
    """The dragon counters of a prometheus scrape."""
    out = {}
    if not path:
        return out
    with open(path) as f:
        for line in f:
            m = re.match(r"^(dragon_[a-z0-9_]+)\{[^}]*\}\s+(\d+)", line)
            if m:
                out[m.group(1)] = out.get(m.group(1), 0) + int(m.group(2))
    return out


# ------------------------------------------------------------------ checks

def check_transactions(ck, base, deferred, slots, max_report):
    for attr, label in (("txns", "transactions"), ("statuses", "transaction_status")):
        a = getattr(base, attr)
        b = getattr(deferred, attr)
        if not b:
            continue
        bad = []
        n = 0
        for slot in slots:
            ca, cb = a[slot], b[slot]
            n += sum(cb.values())
            if ca != cb:
                bad.append("slot %d: %d at %s, %d at %s, %d only at %s, %d only at %s"
                           % (slot, sum(ca.values()), base.name, sum(cb.values()),
                              deferred.name, sum((ca - cb).values()), base.name,
                              sum((cb - ca).values()), deferred.name))
        ck.verdict("%s %s" % (label, deferred.name), bad,
                   "%d updates over %d slots, %d slots differ"
                   % (n, len(slots), len(bad)), bad[:max_report])


def check_index_dense(ck, level, slots, max_report):
    bad = []
    for slot in slots:
        idx = level.txn_index.get(slot)
        if not idx:
            continue
        if sorted(idx) != list(range(len(idx))):
            bad.append("slot %d: %d transactions, indices %s..%s"
                       % (slot, len(idx), sorted(idx)[:3], sorted(idx)[-3:]))
    ck.verdict("index dense %s" % level.name, bad,
               "%d slots with transactions, %d not dense from zero"
               % (sum(1 for s in slots if level.txn_index.get(s)), len(bad)),
               bad[:max_report])


def check_accounts(ck, base, deferred, slots, metrics, truncated, max_report):
    if not deferred.accounts:
        return
    dup = []
    only_deferred = []
    only_base = []
    mismatch = []
    per_slot_unexplained = collections.Counter()
    n_deferred = 0
    n_base = 0
    for slot in slots:
        for pubkey, writes in deferred.accounts[slot].items():
            if len(writes) > 1:
                dup.append("slot %d %s: %d updates at %s"
                           % (slot, pubkey, len(writes), deferred.name))
        want = base.dedup_accounts(slot)
        got = deferred.dedup_accounts(slot)
        n_deferred += len(got)
        n_base += len(want)
        for pubkey in sorted(set(got) - set(want)):
            only_deferred.append("slot %d %s" % (slot, pubkey))
            per_slot_unexplained[slot] += 1
        for pubkey in sorted(set(want) - set(got)):
            only_base.append("slot %d %s" % (slot, pubkey))
        for pubkey in sorted(set(want) & set(got)):
            if blob(want[pubkey], ("filters",)) != blob(got[pubkey], ("filters",)):
                mismatch.append("slot %d %s: lamports %d/%d, data %d/%d bytes"
                                % (slot, pubkey, want[pubkey]["lamports"],
                                   got[pubkey]["lamports"], want[pubkey]["data_len"],
                                   got[pubkey]["data_len"]))
                per_slot_unexplained[slot] += 1

    ck.verdict("accounts deduped %s" % deferred.name, dup,
               "%d accounts over %d slots, %d served more than once"
               % (n_deferred, len(slots), len(dup)), dup[:max_report])
    ck.verdict("accounts missing %s" % deferred.name, only_base,
               "%d accounts written at %s, %d of them not served at %s"
               % (n_base, base.name, len(only_base), deferred.name),
               only_base[:max_report])

    # the two ways a truncated record shows up: an account the
    # processed stream never carried, and an account whose last
    # processed state is older than the one the database holds
    unexplained = len(only_deferred) + len(mismatch)
    name = "accounts equal %s" % deferred.name
    summary = ("%d accounts, %d only at %s, %d with a different state"
               % (n_deferred, len(only_deferred), deferred.name, len(mismatch)))
    details = (only_deferred[:max_report] + mismatch[:max_report])
    skipped = metrics.get("dragon_account_skipped_total")

    if truncated is None:
        # no log to reconcile against: the counter is all there is, and
        # it is a scrape taken at some point during the run
        if not unexplained:
            ck.ok(name, summary)
        elif skipped is None:
            ck.fail(name, summary + "; no --truncated-log and no --metrics to "
                    "reconcile them against", details)
        elif unexplained <= skipped:
            ck.warn(name, summary + "; within the %d writes the tile reports "
                    "skipped for a truncated record (dragon_account_skipped_total)"
                    % skipped, details)
        else:
            ck.fail(name, summary + "; more than the %d writes the tile reports "
                    "skipped for a truncated record (dragon_account_skipped_total)"
                    % skipped, details)
        return

    # the log names every truncated record and the slot it was in, so
    # each unexplained account is either in one of those slots or a
    # real difference, and the count a slot may explain is bounded by
    # the accounts its truncated records wrote
    window = set(slots)
    expected = sum( truncated[s][1] for s in truncated if s in window )
    records  = sum( truncated[s][0] for s in truncated if s in window )
    bad = []
    for entry in only_deferred + mismatch:
        slot = int(entry.split()[1])
        if slot not in truncated:
            bad.append("%s: no truncated record in that slot" % entry)
    for slot in sorted(per_slot_unexplained):
        got = per_slot_unexplained[slot]
        cap = truncated.get(slot, (0, 0))[1]
        if got>cap:
            bad.append("slot %d: %d accounts to explain, %d written by its "
                       "truncated records" % (slot, got, cap))
    summary += ("; %d truncated record(s) over %d slot(s) wrote %d accounts"
                % (records, len([s for s in truncated if s in window]), expected))
    if bad:
        ck.fail(name, summary, bad[:max_report] + details[:max_report])
    elif unexplained==expected:
        ck.ok(name, summary + ", every one of them accounted for")
    else:
        ck.warn(name, summary + ", %d of them accounted for (the rest were "
                "written again in the same slot by a record that fit)" % unexplained,
                details)

    # the counter is a scrape of a running tile and can predate the
    # last truncated record, so it never fails a run on its own
    if skipped is not None:
        mname = "truncated metric %s" % deferred.name
        msummary = ("dragon_account_skipped_total %d, %d accounts to explain"
                    % (skipped, unexplained))
        if skipped==unexplained: ck.ok( mname, msummary )
        else:                    ck.warn( mname, msummary + "; the scrape is a "
                                          "snapshot of a running tile", () )


def check_block_meta(ck, level, slots, max_report):
    if not level.meta:
        return
    bad = []
    n = 0
    for slot in slots:
        for meta in level.meta[slot]:
            n += 1
            got = sum(level.txns[slot].values()) or sum(level.statuses[slot].values())
            if meta["executed_transaction_count"] != got:
                bad.append("slot %d: executed_transaction_count %d, delivered %d"
                           % (slot, meta["executed_transaction_count"], got))
    ck.verdict("block meta count %s" % level.name, bad,
               "%d block metas, %d disagree with the transactions delivered"
               % (n, len(bad)), bad[:max_report])
    once = [s for s in slots if len(level.meta[s]) > 1]
    ck.verdict("block meta once %s" % level.name, once,
               "%d slots with a block meta, %d with more than one"
               % (sum(1 for s in slots if level.meta[s]), len(once)),
               ["slot %d: %d metas" % (s, len(level.meta[s])) for s in once[:max_report]])


def check_blocks(ck, level, base, slots, metrics, max_report):
    if not level.blocks:
        return
    have_txns = any(b["transactions"] for bs in level.blocks.values() for b in bs)
    have_accts = any(b["accounts"] for bs in level.blocks.values() for b in bs)
    # a block is checked against the accounts of its own level where
    # that level was captured, which is an exact equality; against the
    # processed writes it inherits the truncated record exception
    src = level if level.accounts else base
    count_bad = []
    txn_bad = []
    acct_bad = []
    block_only = 0
    n = 0
    for slot in slots:
        for b in level.blocks[slot]:
            n += 1
            if have_txns and b["executed_transaction_count"] != len(b["transactions"]):
                count_bad.append("slot %d: count %d, carried %d"
                                 % (slot, b["executed_transaction_count"],
                                    len(b["transactions"])))
            if have_accts and b["updated_account_count"] != len(b["accounts"]):
                count_bad.append("slot %d: updated_account_count %d, carried %d"
                                 % (slot, b["updated_account_count"],
                                    len(b["accounts"])))
            if have_txns and base.txn_sigs[slot]:
                want = base.txn_sigs[slot]
                got = collections.Counter(t["signature"] for t in b["transactions"])
                if want != got:
                    txn_bad.append("slot %d: %d signatures in the block, %d at %s"
                                   % (slot, sum(got.values()), sum(want.values()),
                                      base.name))
            if have_accts and src.accounts[slot]:
                want = set(src.dedup_accounts(slot))
                got = set(a["pubkey"] for a in b["accounts"])
                if want != got:
                    block_only += len(got - want)
                    acct_bad.append("slot %d: %d accounts in the block, %d at %s, "
                                    "%d only in the block, %d only at %s"
                                    % (slot, len(got), len(want), src.name,
                                       len(got - want), len(want - got), src.name))
    ck.verdict("block counts %s" % level.name, count_bad,
               "%d blocks, %d whose counts disagree with what they carry"
               % (n, len(count_bad)), count_bad[:max_report])
    if have_txns:
        ck.verdict("block transactions %s" % level.name, txn_bad,
                   "%d blocks checked against the %s transactions, %d differ"
                   % (n, base.name, len(txn_bad)), txn_bad[:max_report])
    if have_accts:
        name = "block accounts %s" % level.name
        summary = ("%d blocks checked against the %s accounts, %d differ"
                   % (n, src.name, len(acct_bad)))
        skipped = metrics.get("dragon_account_skipped_total")
        if not acct_bad:
            ck.ok(name, summary)
        elif src is not level and skipped is not None and block_only <= skipped:
            ck.warn(name, summary + "; the %d accounts only in a block are within "
                    "the %d writes the tile reports skipped for a truncated record"
                    % (block_only, skipped), acct_bad[:max_report])
        else:
            ck.fail(name, summary, acct_bad[:max_report])


def check_slot_statuses(ck, per_slot, order, max_report):
    if not per_slot:
        return
    out_of_order = []
    for slot, entries in sorted(per_slot.items()):
        rank = -1
        for seq, status, _ in entries:
            if status == "dead":
                continue
            r = STATUS_RANK.get(status)
            if r is None:
                out_of_order.append("slot %d: unknown status %s" % (slot, status))
                continue
            if r < rank:
                out_of_order.append("slot %d: %s after a later status" % (slot, status))
            rank = max(rank, r)
    ck.verdict("slot status order", out_of_order,
               "%d slots, %d with a status out of order"
               % (len(per_slot), len(out_of_order)), out_of_order[:max_report])

    twice = []
    for slot, entries in sorted(per_slot.items()):
        counts = collections.Counter(s for _, s, _ in entries)
        for status in ("finalized", "confirmed", "processed", "created_bank"):
            if counts[status] > 1:
                twice.append("slot %d: %d %s statuses" % (slot, counts[status], status))
    rooted = [slot for slot, e in per_slot.items() if any(s == "finalized" for _, s, _ in e)]
    ck.verdict("rooted slot once", twice,
               "%d slots reached finalized, %d slots carry a duplicate status"
               % (len(rooted), len(twice)), twice[:max_report])

    ascending = []
    last = -1
    for seq, slot, status in order:
        if status != "finalized":
            continue
        if slot < last:
            ascending.append("slot %d finalized after slot %d" % (slot, last))
        last = max(last, slot)
    ck.verdict("finalized ascending", ascending,
               "%d finalized statuses, %d out of order" % (len(rooted), len(ascending)),
               ascending[:max_report])


def check_coverage(ck, base, deferred, per_slot, skip_first, max_report):
    """Every slot the deferred level served was served at processed too."""
    missing = sorted(set(deferred.all_slots()) - set(base.all_slots()))
    missing = missing[skip_first:] if skip_first else missing
    ck.verdict("slots covered %s" % deferred.name, missing,
               "%d slots at %s, %d of them never seen at %s"
               % (len(deferred.all_slots()), deferred.name, len(missing), base.name),
               ["slot %d" % s for s in missing[:max_report]])

    if per_slot:
        rooted = set(s for s, e in per_slot.items()
                     if any(st == "finalized" for _, st, _ in e))
        served = set(deferred.all_slots())
        lo = min(served) if served else 0
        hi = max(served) if served else 0
        gaps = sorted(s for s in rooted if lo <= s <= hi and s not in served)
        ck.verdict("rooted slots served", gaps,
                   "%d rooted slots between %d and %d, %d with no content at %s"
                   % (len([s for s in rooted if lo <= s <= hi]), lo, hi, len(gaps),
                      deferred.name),
                   ["slot %d" % s for s in gaps[:max_report]])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--level", action="append", default=[], metavar="NAME=PREFIX",
                    help="a capture and the commitment level it was taken at")
    ap.add_argument("--slots", default=None,
                    help="the capture prefix whose slot statuses to check")
    ap.add_argument("--truncated-log", default=None,
                    help="the dragon log, or the lines of it that name a "
                         "truncated record; what the finalized only accounts "
                         "are reconciled against")
    ap.add_argument("--metrics", default=None,
                    help="a prometheus scrape of the run, for the counters a "
                         "check needs to explain what it found")
    ap.add_argument("--base", default="processed",
                    help="the level the others are checked against")
    ap.add_argument("--skip-first", type=int, default=1,
                    help="ignore this many of the lowest slots, whose bank was "
                         "already in flight when the subscription opened")
    ap.add_argument("--skip-last", type=int, default=1,
                    help="ignore this many of the highest slots of the base "
                         "capture, whose bank was still executing when the "
                         "capture ended; the deferred levels lag behind it, so "
                         "their own window never reaches that bank")
    ap.add_argument("--max-report", type=int, default=8)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    levels = {}
    for spec in args.level:
        name, _, prefix = spec.partition("=")
        if not prefix:
            ap.error("--level wants NAME=PREFIX, got %r" % spec)
        levels.setdefault(name, Level(name))
        load_level(levels[name], prefix)
    if args.base not in levels:
        ap.error("no --level %s= given" % args.base)

    per_slot, order = load_slots(args.slots) if args.slots else ({}, [])
    metrics = read_metrics(args.metrics)
    truncated = read_truncated(args.truncated_log)
    base = levels[args.base]

    ck = Checks(args.max_report)
    for name in sorted(levels):
        print("%s: %s over %d slots"
              % (name, dict(levels[name].counts), len(levels[name].all_slots())))
    if metrics:
        print("metrics: skipped %s, truncated records %s"
              % (metrics.get("dragon_account_skipped_total"),
                 metrics.get("dragon_record_truncated_total")))
    if truncated is not None:
        print("truncated records: %d over %d slots, %d accounts"
              % (sum( v[0] for v in truncated.values() ), len(truncated),
                 sum( v[1] for v in truncated.values() )))

    base_slots = sorted(base.all_slots())[args.skip_first:]
    if args.skip_last:
        base_slots = base_slots[:max(0, len(base_slots) - args.skip_last)]
    check_index_dense(ck, base, base_slots, args.max_report)
    check_block_meta(ck, base, base_slots, args.max_report)
    for name in sorted(levels):
        if name == args.base:
            continue
        level = levels[name]
        slots = sorted(set(level.all_slots()) & set(base.all_slots()))
        if args.skip_first:
            slots = slots[args.skip_first:]
        check_coverage(ck, base, level, per_slot, args.skip_first, args.max_report)
        check_transactions(ck, base, level, slots, args.max_report)
        check_index_dense(ck, level, slots, args.max_report)
        check_accounts(ck, base, level, slots, metrics, truncated, args.max_report)
        check_block_meta(ck, level, slots, args.max_report)
        check_blocks(ck, level, base, slots, metrics, args.max_report)
    check_slot_statuses(ck, per_slot, order, args.max_report)

    failed = ck.report()
    if args.json:
        with open(args.json, "w") as f:
            json.dump([{"check": n, "verdict": v, "summary": s, "details": d}
                       for n, v, s, d in ck.results], f, indent=1)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
