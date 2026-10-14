---
applyTo: "src/disco/metrics/metrics.xml"
---

# Reviewing metrics.xml changes

The NAMING RULES comment at the top of metrics.xml is the spec.
`lint_metrics.py` already enforces the mechanical rules in CI: name
shape and words, units, `<bool>`/`<time>`/`states=` usage, summary
form, the closed gauge vocabulary (Rule 3), counters ending in an
Action, a C writer for every metric, identical summaries for shared
Accdb*/Progcache* metrics, that metric names cited in a summary
exist, and that no tile metric reuses a <common> name (tile tables
carry the common columns).  Focus on what it cannot check.  For each added or changed
metric, comment on the line with the rule number and a suggestion
block.

- Type: a level or size is a gauge; a cumulative tally is a counter.  A
  0/1 value is `<bool>`, a wall-clock time `<time>`, one value from a
  fixed set a `*State` gauge with `states=`.
- Meaning: the name and summary alone tell a reader what is counted or
  measured, when it changes, and whether it is cumulative since boot, a
  current level, or per block/slot.
- Sentinels: absent values read 0 and the summary says ", 0 if none".
  Only Index, Id and Rank gauges, where 0 is legal, may use ULONG_MAX,
  and never inside an enum split that users will sum.
- Units: durations are nanoseconds.  If the tile stores
  `fd_tickcount()` deltas, the metric needs `source="ticks"`.
- Consistency: the same concept uses the same word as existing metrics
  in other tiles (Count, Open, InFlight, Used/Capacity, Rx/Tx, Slot
  last).  A gauge's head noun is the thing counted, not a process or
  container (TxnReassemblyPending, not TxnReassembly).
- Kind: a name that still reads as the other kind (a counter with no
  Action, a gauge ending in an -ed state word or Height) carries
  `ambiguous-kind="true"`; the lint flags the obvious cases, check the
  rest by reading the name cold.
- Enums: values are exhaustive and in the same unit; add a `<group>`
  when users will commonly sum a subset (every enum already has an
  implicit `All` group).  C code indexes enum arrays with the generated
  `FD_METRICS_ENUM_*_V_*_IDX` constants, never raw numbers.
- Writers: the C code writes what the summary says.  A metric written
  by a code path that can never run fails the lint only if nothing
  references it, so check the writer is live.
- `lint-allow="..."` exceptions need a stated reason in the PR;
  `lint-allow="writer"` (a metric written only by other code, such as
  a hand-built offset write) needs the writer named.

Renaming or removing an existing metric, or changing an enum value,
breaks Prometheus dashboards and frozen ClickHouse columns.  Flag it
and ask whether it is intended.  A removal must be deprecated="true"
(the generator refuses an outright delete) and a rename must carry
renamed_from listing every earlier name, oldest first ("A B"); both
apply to <int> enum values too.
