#!/usr/bin/env python3
"""Compares two normalized Dragon's Mouth captures, slot by slot.

  ./diff.py oracle.jsonl subject.jsonl --drop-startup-a --ignore rent_epoch

Both files are what capture.py writes: one JSON record per line, with
`slot`, `kind`, `key` and `payload`.  The comparison is the one the
conformance harness calls for (plan section 8): within a slot the
updates of each side are a *multiset* -- their order is nondeterministic
on both sides and carries no meaning -- so a slot matches when the two
multisets of (kind, key, payload) are equal.

What a run reports per slot:
  - updates only in A and only in B, by kind,
  - updates whose (kind, key) is on both sides but whose payload
    differs, with the fields that differ.

Masks.  `--ignore NAME` drops the field NAME wherever it appears in a
payload, at any depth, on both sides; it is how a known and accepted
difference (`rent_epoch`, `cost_units`, ...) is taken out of the
comparison without hiding the rest of the record.  `--drop-startup-a`
drops the account updates an oracle emits during its startup dump,
which have no counterpart in a stream that begins at a live slot.
`--common-slots`, `--skip-first` and `--skip-last` bound the comparison
to the slots both captures could have seen: two streams never start and
never end on the same slot, and the first bank of a run is in flight
when the subscription opens.

Exit code 0 when the compared slots match, 1 when they do not, 2 on a
usage error.
"""

import argparse
import collections
import json
import sys


def load(path, drop_startup=False, kinds=None, window=(None, None)):
    """slot -> {(kind, key): Counter(payload json)}

    `window` is the (lo, hi) of --slots, applied here rather than after
    the load so that a capture too large to hold in memory can still be
    compared one window at a time."""
    lo, hi = window
    by_slot = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    total = 0
    dropped = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            slot = rec["slot"]
            if (lo is not None and slot < lo) or (hi is not None and slot > hi):
                continue
            kind = rec["kind"]
            if kinds and kind not in kinds:
                continue
            payload = rec["payload"]
            if drop_startup and kind == "account" and payload.get("is_startup"):
                dropped += 1
                continue
            total += 1
            key = (kind, rec["key"])
            blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            by_slot[slot][key][blob] += 1
    return by_slot, total, dropped


def mask(value, names):
    """The value with every field called one of `names` removed."""
    if isinstance(value, dict):
        return {k: mask(v, names) for k, v in value.items() if k not in names}
    if isinstance(value, list):
        return [mask(v, names) for v in value]
    return value


def apply_masks(by_slot, names):
    if not names:
        return by_slot
    out = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for slot, keys in by_slot.items():
        for key, blobs in keys.items():
            for blob, n in blobs.items():
                masked = json.dumps(mask(json.loads(blob), names),
                                    sort_keys=True, separators=(",", ":"))
                out[slot][key][masked] += n
    return out


def field_diff(a, b, path="", out=None, limit=20):
    """The leaf fields where two payloads differ."""
    if out is None:
        out = []
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            field_diff(a.get(k, "<absent>"), b.get(k, "<absent>"),
                       "%s.%s" % (path, k) if path else k, out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(("%s[]" % path, "%d items" % len(a), "%d items" % len(b)))
        for i in range(min(len(a), len(b))):
            field_diff(a[i], b[i], "%s[%d]" % (path, i), out, limit)
    elif a != b:
        out.append((path, a, b))
    return out


def summarize(value, width=72):
    s = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    return s if len(s) <= width else s[:width - 3] + "..."


def compare(a_slots, b_slots, args, report):
    """Fills `report` and returns the number of slots that differ."""
    slots_a = set(a_slots)
    slots_b = set(b_slots)
    slots = slots_a & slots_b if args.common_slots else slots_a | slots_b
    if args.slots:
        lo, _, hi = args.slots.partition(":")
        if lo:
            slots = {s for s in slots if s >= int(lo)}
        if hi:
            slots = {s for s in slots if s <= int(hi)}
    ordered = sorted(slots)
    if args.skip_first:
        ordered = ordered[args.skip_first:]
    if args.skip_last:
        ordered = ordered[:len(ordered) - args.skip_last] if args.skip_last < len(ordered) else []
    slots = set(ordered)

    report["slots_compared"] = len(ordered)
    report["slots_only_in_a"] = sorted(slots_a - slots_b)[:args.max_report]
    report["slots_only_in_b"] = sorted(slots_b - slots_a)[:args.max_report]
    report["slots_only_in_a_cnt"] = len(slots_a - slots_b)
    report["slots_only_in_b_cnt"] = len(slots_b - slots_a)

    only_a = collections.Counter()
    only_b = collections.Counter()
    differing = collections.Counter()
    bad_slots = []
    samples = []

    for slot in ordered:
        keys_a = a_slots.get(slot, {})
        keys_b = b_slots.get(slot, {})
        slot_bad = False
        for key in sorted(set(keys_a) | set(keys_b)):
            ca = keys_a.get(key, collections.Counter())
            cb = keys_b.get(key, collections.Counter())
            if ca == cb:
                continue
            slot_bad = True
            left_a = ca - cb
            left_b = cb - ca
            kind = key[0]
            if left_a and left_b:
                differing[kind] += sum(left_a.values())
                if len(samples) < args.max_report:
                    pa = json.loads(sorted(left_a)[0])
                    pb = json.loads(sorted(left_b)[0])
                    samples.append({
                        "slot": slot, "kind": kind, "key": key[1],
                        "fields": [{"path": p, args.label_a: summarize(x),
                                    args.label_b: summarize(y)}
                                   for p, x, y in field_diff(pa, pb)],
                    })
            elif left_a:
                only_a[kind] += sum(left_a.values())
                if len(samples) < args.max_report:
                    samples.append({"slot": slot, "kind": kind, "key": key[1],
                                    "only_in": args.label_a})
            else:
                only_b[kind] += sum(left_b.values())
                if len(samples) < args.max_report:
                    samples.append({"slot": slot, "kind": kind, "key": key[1],
                                    "only_in": args.label_b})
        if slot_bad:
            bad_slots.append(slot)

    report["only_in_a"] = dict(only_a)
    report["only_in_b"] = dict(only_b)
    report["differing"] = dict(differing)
    report["slots_with_differences"] = len(bad_slots)
    report["first_slots_with_differences"] = bad_slots[:args.max_report]
    report["samples"] = samples
    return len(bad_slots)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--label-a", default="a")
    ap.add_argument("--label-b", default="b")
    ap.add_argument("--ignore", action="append", default=[],
                    help="drop this field at any depth, on both sides")
    ap.add_argument("--kind", action="append", default=[],
                    help="compare only these kinds")
    ap.add_argument("--drop-startup-a", action="store_true")
    ap.add_argument("--drop-startup-b", action="store_true")
    ap.add_argument("--common-slots", action="store_true",
                    help="compare only the slots both captures have")
    ap.add_argument("--slots", default=None, help="restrict to lo:hi")
    ap.add_argument("--skip-first", type=int, default=0,
                    help="drop this many of the lowest compared slots")
    ap.add_argument("--skip-last", type=int, default=0,
                    help="drop this many of the highest compared slots")
    ap.add_argument("--max-report", type=int, default=10)
    ap.add_argument("--json", default=None, help="write the report here")
    args = ap.parse_args()

    kinds = set(args.kind) or None
    window = (None, None)
    if args.slots:
        lo, _, hi = args.slots.partition(":")
        window = (int(lo) if lo else None, int(hi) if hi else None)
    a_slots, a_total, a_startup = load(args.a, args.drop_startup_a, kinds, window)
    b_slots, b_total, b_startup = load(args.b, args.drop_startup_b, kinds, window)
    a_slots = apply_masks(a_slots, set(args.ignore))
    b_slots = apply_masks(b_slots, set(args.ignore))

    report = {
        args.label_a: {"path": args.a, "records": a_total,
                       "startup_dropped": a_startup, "slots": len(a_slots)},
        args.label_b: {"path": args.b, "records": b_total,
                       "startup_dropped": b_startup, "slots": len(b_slots)},
        "ignored_fields": sorted(args.ignore),
    }
    bad = compare(a_slots, b_slots, args, report)
    report["result"] = "FAIL" if bad else "PASS"

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=1, sort_keys=True)

    print("%s: %d records over %d slots" % (args.label_a, a_total, len(a_slots)))
    print("%s: %d records over %d slots" % (args.label_b, b_total, len(b_slots)))
    if a_startup or b_startup:
        print("startup accounts dropped: %s %d, %s %d"
              % (args.label_a, a_startup, args.label_b, b_startup))
    print("slots compared %d, only in %s %d %s, only in %s %d %s"
          % (report["slots_compared"], args.label_a, report["slots_only_in_a_cnt"],
             report["slots_only_in_a"], args.label_b, report["slots_only_in_b_cnt"],
             report["slots_only_in_b"]))
    print("updates only in %s: %s" % (args.label_a, report["only_in_a"] or "none"))
    print("updates only in %s: %s" % (args.label_b, report["only_in_b"] or "none"))
    print("updates with a differing payload: %s" % (report["differing"] or "none"))
    for s in report["samples"]:
        if "only_in" in s:
            print("  slot %d %s %s: only in %s" % (s["slot"], s["kind"],
                                                   s["key"][:24], s["only_in"]))
        else:
            print("  slot %d %s %s:" % (s["slot"], s["kind"], s["key"][:24]))
            for f in s["fields"]:
                print("    %s: %s %s | %s %s" % (f["path"], args.label_a,
                                                 f[args.label_a], args.label_b,
                                                 f[args.label_b]))
    print("slots with differences: %d of %d" % (report["slots_with_differences"],
                                                report["slots_compared"]))
    print("RESULT: %s" % report["result"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
