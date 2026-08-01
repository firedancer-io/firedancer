# Top Votes V2 Shared Insertion Heap

## Goal

Give each t-1 vote-account group the same top-2000 insertion behavior as
`fd_top_votes_t`, while storing only one heap in `fd_top_votes_v2_t`.
Insertion into a child is a contiguous, non-concurrent session. Direct
insertion into t-2 groups and runtime integration are out of scope.

## Storage

`vote_account_ele_t` will store the vote pubkey, node-account pubkey,
stake, commission, map/pool link, and intrusive heap links. All account
indices will be `ushort`, which is sufficient for the fixed 2000-account
limit and keeps the complete element at 80 bytes.

Each acquired t-1 group records the bank index that owns its insertion
rights. The owner field shares storage with the group-pool free-list
link, which is unused while the group is acquired. Normal children copy
the group index but not ownership; only the root or epoch child that
acquired the group may initialize insertion.

The top-level object will contain one position-independent shared heap,
an active child index, and a scratch minimum-stake watermark. The heap
operates on the active t-1 group's pool. Heap links left in a completed
group are ignored after the session; the durable result is its pool and
map.

## API and Lifecycle

`fd_top_votes_v2_insert_init(top_votes, child_idx)` starts a session. It:

- verifies no other insertion session is active;
- initializes the child if necessary;
- requires the selected t-1 group to be fresh, empty, and unshared;
- resets the shared heap and watermark; and
- records the active child.

`fd_top_votes_v2_insert(top_votes, pubkey, node_account, stake,
commission)` inserts into the active group. It exactly preserves v1
behavior:

- zero stake and stakes at or below the watermark are ignored;
- while full, lower-stake candidates are ignored;
- all entries tied at the minimum are evicted together;
- a candidate tied at that minimum is not inserted;
- the evicted minimum becomes a persistent watermark for the session;
- stake ties in the heap use the vote pubkey as the deterministic
  tiebreaker.

As in v1, callers must not insert the same vote pubkey twice in one
session.

`fd_top_votes_v2_insert_fini(top_votes)` ends the session and marks the
heap available. It does not walk or clear the completed account group;
the next `insert_init` resets the scratch heap in O(1).

Fork lifecycle operations require no active insertion session.
`fd_top_votes_v2_new_epoch_child` continues to acquire and clear the
fresh t-1 group before insertion begins. Normal children share their
parent's completed t-1 group and cannot start insertion.

`fd_top_votes_v2_query_t_1(top_votes, child_idx, pubkey,
node_account_out_opt, stake_out_opt, commission_out_opt)` returns
membership and the requested account metadata. This makes the completed
group usable and allows behavioral testing without exposing private
layouts. Update, invalidate, refresh, t-2 state queries, and iteration
remain out of scope.

## Validation and Tests

Invariant violations use the existing `FD_TEST` style: invalid child
indices, nested sessions, insertion without a session, a nonempty or
shared target group, and lifecycle changes during a session.

The v2 unit test will cover the v1 insertion cases: basic insertion,
capacity rejection, single-minimum eviction, tied-minimum eviction,
watermark rejection and advancement, deterministic membership, and
node-account retention. A second child will then reuse the same heap in
a later session, verifying that its results are independent and that the
first completed group remains unchanged. Existing construction,
relocation, and alignment checks remain.
