# Top Votes V2 Style Refactor

## Goal

Make `fd_top_votes_v2.c` read like `fd_top_votes.c` without changing its
public API, persistent layout, insertion semantics, lifecycle, or safety
checks.

## Private Naming and Structure

- Rename `vote_account_ele_t` to `vote_ele_t`.
- Name the account templates `heap`, `pool`, and `map`, matching v1.
  Keep `t_1_group_pool` distinct because it is a second pool.
- Use `get_heap`, `get_pool`, and `get_map` for the active heap and a
  group's durable storage.
- Keep public `fd_top_votes_v2_*` names and persistent field names
  unchanged.

## Simplification

- Format layout and scratch allocation as the compact aligned blocks
  used in v1.
- Align local declarations and avoid line wrapping where a v1-style
  expression remains readable.
- Make `fd_top_votes_v2_insert` follow the same ordering and shape as
  `fd_top_votes_insert`: resolve pool/heap/map, reject by watermark,
  evict the tied floor, then populate and insert the new element.
- Consolidate repeated offset bounds/alignment checks in a small private
  region-validation helper. Keep call-site warnings so failures remain
  diagnosable.
- Retain group-specific helpers only where v2's shared storage model
  requires them.

## Compatibility and Validation

The refactor must not change:

- `sizeof(fd_top_votes_v2_t)` or `sizeof(vote_ele_t)`;
- footprint ordering or offsets;
- magic value or alignment;
- bank/group ownership and sealing;
- join validation coverage;
- child and epoch-child behavior;
- insertion, query, or relocation behavior.

No runtime callers are added. Existing negative validation tests remain.

## Verification

Build and run `test_top_votes_v2` and `test_top_votes`, using normal pages
for the v1 executable. Run `git diff --check` and confirm the source diff
contains only behavior-preserving private refactoring.
