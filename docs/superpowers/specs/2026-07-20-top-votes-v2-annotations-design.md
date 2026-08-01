# Top Votes V2 Source Annotations

## Goal

Annotate `src/flamenco/stakes/fd_top_votes_v2.c` so a reader can follow
its storage model and lifecycle without changing code or behavior.

## Annotation Scope

Add concise comments that explain:

- the t-1 account sets and per-bank t-2 state snapshots;
- position-independent offsets and the contiguous memory layout;
- the heap, pool, map, and group-pool roles and shared invariants;
- mutable group ownership, sealing, inheritance, and epoch rotation;
- lazy initialization and insertion-session lifecycle requirements; and
- stake-watermark and tied-minimum eviction semantics.

Prefer comments above structs, helpers, public operations, and
non-obvious blocks. Avoid restating individual C expressions. Wrap
comments near 72 columns and follow existing Firedancer style.

## Compatibility

Only comments in `fd_top_votes_v2.c` will change. Preserve the existing
uncommitted `fd_top_votes_v2_new_child` edit and make no API, layout,
lifecycle, or runtime behavior changes.

## Verification

Run `git diff --check`, build `test_top_votes_v2`, and run the resulting
test executable. Confirm the source diff contains comment additions
only, apart from the user's pre-existing `fd_top_votes_v2_new_child`
change.
