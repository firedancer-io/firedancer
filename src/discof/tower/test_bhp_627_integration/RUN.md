# BHP-627 integration test — run notes

This directory contains the integration test for the BHP-627 (= BP-627)
divergence: FD's `fd_fec_resolver_add_shred` (`src/disco/shred/
fd_fec_resolver.c`) returns `FD_FEC_RESOLVER_SHRED_EQUIVOC` when a
second shred in the same FEC set carries a byte-different but
individually-valid ed25519 signature over the same reconstructed
merkle root; Agave's `check_merkle_root_consistency`
(`ledger/src/blockstore.rs:3010`) short-circuits on equal merkle roots
at line 3020 and inserts both shreds cleanly. The consensus-visible
consequence of the buggy FD behavior is a *vote-abstain* divergence:
FD refuses to vote on the slot; Agave votes normally.

## What this test asserts

`test_bhp_627_integration.c` drives the divergence end-to-end and
asserts the vote path is preserved (i.e. the bug is not present):

1. Builds a valid 32-data/32-parity chained-merkle FEC set with a
   controlled leader keypair at slot=100, fec_set_idx=0.
2. Crafts a second valid ed25519 signature `Sig_B` over the same
   merkle root `M` via an RFC-8032-compatible signer with a distinct
   nonce seed. Both `Sig_A != Sig_B` byte-wise and both verify against
   the leader pubkey over `M`.
3. Builds a minimal ghost tree: root → eqvoc_blk (slot 100) → child_blk.
4. Feeds `shred_A` (with `Sig_A`) to `fd_fec_resolver_add_shred`.
   Asserts return is `SHRED_OKAY`.
5. Feeds `shred_B` (same shred body as `shred[1]`, signature rewritten
   to `Sig_B`) to the resolver.
6. Simulates the tower-tile propagation: if the resolver returns
   `SHRED_EQUIVOC`, invokes `fd_ghost_eqvoc` on `eqvoc_id`. This
   compresses the real tile chain (`fd_shred_tile.c:997` publishes
   `SHRED_SIG_RESULT_EQVOC` → `fd_tower_tile.c:1732` calls
   `fd_eqvoc_shred_insert` → `fd_eqvoc.c:717-728` inserts a proof →
   `fd_tower_tile.c:1268-1275` fires `fd_ghost_eqvoc` on
   `SLOT_COMPLETED`) into a single conditional.
7. Load-bearing assertion: `eqvoc_blk->valid == 1`. If the resolver
   returned `EQUIVOC`, the simulated propagation zeroed `valid` at
   `fd_ghost.c:638` and this assertion fails.

Behavior across the fix:

- **Before BP-627 fix:** resolver returns `EQUIVOC` on step 5;
  simulated propagation runs; `eqvoc_blk->valid` drops to 0; test
  **FAILS** at the `valid == 1` assertion.
- **After BP-627 fix:** resolver returns `IGNORED` on step 5; no
  propagation; `eqvoc_blk->valid` stays 1; test **PASSES**.

The test also asserts that `fd_ghost_best(root) == child_blk` and
`fd_ghost_invalid_ancestor(child_blk) == NULL` after the fix,
confirming that fork-choice can still select the eqvoc subtree and
FD's vote for the affected slot is not gated off.

## Building and running

```bash
make -j test_bhp_627_integration
./build/native/gcc/unit-test/test_bhp_627_integration --page-sz normal --page-cnt 512
```

Expected output (on fixed code):

```
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration test: resolver -> ghost vote-path preservation
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration: add_shred(shred_A, Sig_A) returned 0
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration: add_shred(shred_B, Sig_B) returned -2
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration: eqvoc_blk.valid=1 child_blk.valid=1 -- vote path preserved
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration: fd_ghost_best(root) == child (slot 101) -- fork-choice can still select the eqvoc subtree
NOTICE  test_bhp_627_integration.c(...): BHP-627 integration test pass
```

On buggy code (pre-fix), `add_shred(shred_B, Sig_B)` returns `-4`
(EQUIVOC) and the test fails at the `eqvoc_blk->valid == 1`
assertion.

## What is out of scope

This test compresses the tile-layer propagation into a single
conditional call to `fd_ghost_eqvoc`. It does not run the full FD
tile stack (shred tile → FEC resolver → tower tile → vote emit) end
to end, nor does it exercise the real vote-txn assembly path
(`fd_tower_choose_next` at `fd_tower.c:851`, which requires a
fully-provisioned tower + eqvoc + vote-account state).

Empirically observing the divergence in production shape requires a
two-validator co-run harness: both validators booted from the same
genesis, fed the same shred stream including the crafted
same-merkle-root two-signature pair, comparing per-slot vote
emissions and bank_hash lineage. That harness is not in-tree.

## References

- Report: `boundary-mappings/divergences/BP627-report.md`
- Unit reproducer: `src/disco/shred/test_fec_resolver_bp627.c`
- Fix: `src/disco/shred/fd_fec_resolver.c` (equivoc-branch merkle-
  root compare)
