# Top Votes V2 Minimal Join Validation

## Goal

Match `fd_top_votes.c` validation style instead of treating
`fd_top_votes_v2_join` as a corrupted-storage verifier.

## Validation Boundary

`fd_top_votes_v2_join` will:

- reject `NULL`;
- reject an incorrect top-level magic value; and
- otherwise return the joined object.

It will not validate alignment, footprint reconstruction, offsets,
nested pool/map dimensions, bank indices, or active insertion state.
As in v1, callers must only join memory previously formatted by `new`.

`fd_top_votes_v2_new` retains the checks needed to format valid memory:
NULL and alignment checks, valid nonzero footprint, successful nested
constructors, and final layout verification.

## Cleanup and Tests

Remove the now-unused `group_join` helper and malformed-storage join
tests. Keep construction, valid relocation, lifecycle rejection,
insertion, query, and v1-equivalence tests unchanged.

The persistent format and valid-object behavior do not change. Corrupt
or manually modified objects are no longer guaranteed to fail during
join.
