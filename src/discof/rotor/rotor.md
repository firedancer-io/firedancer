# Chainer as events, repair requests, and deliverable FECs

This is a design sketch based on the current working copies of
[fd_chainer.c](src/discof/chainer/fd_chainer.c),
[fd_requestor.c](src/discof/rotor/fd_requestor.c), and their integration in
[fd_rotor_tile.c](src/discof/rotor/fd_rotor_tile.c). It proposes an event-driven
replacement for request selection and scheduling while keeping the current
block/FEC representation and admission rules as the starting point.

The interface is conceptually:

```text
(state, incoming tile fragment, now)
    -> frag_shred / frag_net / frag_votor / frag_replay / ...
    -> decode, validate, and select internal chainer transition
    -> updated state
    -> schedule repair work / cause cancellation of unneeded requests
    -> zero or more deliverable FECs

(local run loop: scheduled work, timer expiry, output credit)
    -> request, if still needed
    -> wait for response or retry
```

A fragment can schedule a request immediately or for a future deadline. Scheduling
does not mean sending a packet immediately. Chainer owns what is needed and when
to reconsider it. Rotor still selects peers, serializes and signs requests,
matches responses, verifies metadata proofs, and publishes FECs to replay.
The first-shred distinction is made inside the shred-fragment handler; other
tiles do not need to know chainer's state or emit a separate first-shred message.

The important change is that block discovery has explicit work of its own.
Parent discovery and highest-shred requests no longer need an incomplete FEC,
or a completed FEC 0 retained in a repair treap, to keep them alive.

**What the current code does**

The active path is `fd_requestor_fec_request`, called by `fec_sweep`. The older
`fd_requestor_block_start/advance` interface is no longer driven by the tile.
In particular, the older walk's orphan request and bounded blind fill are not
the active scheduling policy.

| Current mechanism                                               | Role in this proposal                                                          |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Per-version FEC entries in eager/notar treaps                   | Shred/FecRoot requests for absent entries; fill for existing FECs              |
| FEC 0 as the block's repair token                               | Separate header, parent/count, orphan, and highest-shred jobs                  |
| `fec_request` discovers the next request by inspecting an entry | Input events register the specific missing dependency; dispatch revalidates it |
| A position sweep with `next_req_ts` filtering                   | Two bounded request queues with independent capacity                           |
| Root-map owner holds the received bitmap                        | Keep this representation; all matching versions read the same bitmap           |
| `chainer_advance` cascades deliveries                           | Run advancement after every event that can satisfy a delivery dependency       |

Today, FEC insertion makes work due immediately, and the sweep rearms it for
100 ms after a pass. A 250 ms initial highest-shred delay is a proposed policy,
not the current timeout. The schedule below uses that delay, a proposed 100 ms
initial grace for turbine FEC fill, and the current 100 ms value as a starting
retry interval. These should be named policy constants.

**State to retain**

A block remains a particular version of a slot. Keep its slot, block ID,
`turbine` origin flag, consensus `final` bit, `cancel` bit, parent information,
FEC references, and independent delivery position. Computing a turbine block's
ID does not make it consensus-final and does not erase its turbine origin.

Create a block's private FEC entry only when an admitted shred or verified root
response establishes its root. Do not allocate rootless placeholders for earlier
positions or when a verified FEC count arrives. A missing table entry within a
known range is repair work, represented by a range and cursor on the block.

Once a root is known, exactly one matching entry owns the root-map record and
received bitmap. Shadows query that owner. Do not copy incoming shred bits into
every version. A queued Shred or FecRoot request refers to the block and position; it
does not require a FEC pool entry to exist there.

Root lookup currently compares the first 20 bytes. Metadata may introduce a
zero-padded prefix; a shred or completion upgrades it to the full root. Every
attachment must also agree on slot and FEC position. Position alone never
establishes that two versions share data.

Keep these facts distinct:

| Fact                    | Meaning                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| Received bitmap         | Data shreds available to the resolver for this root                   |
| FEC complete            | Resolver completion accepted; complete data is available for delivery |
| Block connected         | Its exact ancestry reaches the current root                           |
| Parent delivered        | The parent is ready before this block's delivery                      |
| Block delivery position | How far this particular version has been queued for replay            |

All 32 bits being present does not substitute for receiving FEC completion.
Likewise, one version delivering a shared FEC does not advance another version's
delivery position. `buffered_idx` can remain a cache, but repair selection must
read the authoritative bitmap. Attaching a shared root or evicting its data
must refresh or invalidate any cache used by delivery or metrics.

Requests carry slot, block ID, kind, shred/FEC index where applicable, and
scheduling information. On pop, query the target version and its current need.
For an all-zero block ID, use the turbine-version query so computing its block
ID does not strand queued requests. Named requests use exact version lookup.
Queued work must not dereference a recycled block/FEC pool element.

**The scheduled requests**

The notation `schedule(kind, target, due)` means enqueue the request in the
appropriate queue, subject to the capacity policy below. Repeating the same
need does not append duplicate requests or postpone an existing deadline.
For Shred/ShredForBlockId, scheduling can drop the request under pressure; the
fragment's state update still succeeds. If the target is a live, noncancelled
notar version, ensure it is in the per-block `deferred_requests` side queue.
Turbine versions are not enrolled there. A meaningful state transition can
accelerate work or cause cancellation of a request.

| Job                                        | Wire output when due and still needed                              | Conditions causing satisfaction/cancellation                                                    |
| ------------------------------------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Header for an unnamed turbine block        | `Shred(slot, 0)`                                                   | Usable parent marker; named metadata path takes over; cancellation/pruning                      |
| Orphan discovery for a turbine block       | `Orphan(slot)`                                                     | Exact parent is present or has been materialized with its own repair work; cancellation/pruning |
| Highest shred for an unnamed turbine block | `HighestShred(slot)`                                               | Slot end learned; named count path takes over; cancellation/pruning                             |
| Parent/count for a named block             | `ParentAndFecCount(slot, block_id)`                                | Verified parent and FEC count accepted; cancellation/pruning                                    |
| Missing FECs in an unnamed turbine block   | One `Shred(slot, idx)` from an absent FEC in the covered range     | A shred creates the entry and its fill job; retry other absent positions                        |
| Missing roots in a named block             | One `FecRoot(slot, block_id, fec_set_idx)` from the verified range | Root response creates/attaches the entry; retry other absent positions                          |
| Fill an unnamed turbine FEC                | One missing `Shred(slot, idx)` per dispatch                        | FEC completes or cancellation/pruning; park if all bits arrived but completion is pending       |
| Fill a named FEC                           | One missing `ShredForBlockId(slot, block_id, idx)` per dispatch    | Same, using the shared received bitmap                                                          |

For every absent FEC starting at k within the required range, schedule:

- Unnamed turbine block: `Shred(slot, k)`, requesting the FEC's first data shred.
- Named block: `FecRoot(slot, block_id, k)`, requesting its verified root.

Generate individual request entries for these positions without allocating
placeholder FECs. A cursor may bound generation per tile iteration, but queue
capacity follows the two-queue policy below. Once a shred or root response
creates an entry, it causes cancellation of requests whose only purpose was
to establish that entry; individual fill requests obtain the missing data.
Retained unanswered requests retry after their timeout. Dropping a notar
version's shred request enrolls the block once in `deferred_requests`. Recovery
regenerates individual requests when shred-queue capacity is available and the
delivered head has not advanced for X time.

Header discovery and requests to establish or fill FEC 0 can all request
`Shred(slot, 0)`. Send one pending request for that position, using the earliest
applicable deadline, rather than sending a copy for each reason.

A parent/count job is one combined dependency. Learning parent and count in
one verified response should not leave a redundant metadata timer behind.
A known parent that has not completed is repaired through the parent's jobs;
it does not justify repeatedly requesting the child's already-known metadata.

For a first implementation, Shred/FecRoot requests and individual fill requests
remain per version. Two versions sharing a root can issue redundant requests
before either response arrives, but every response satisfies both through the
shared bitmap. This duplication is bounded by the number of versions.
Cross-version suppression of outstanding requests can be added later;
correctness must not depend on one version being the sole requester or
continuing to exist.

The development `block_id_only` setting suppresses header, orphan, highest,
positional fill, and positional seed probes. A blocked unnamed version then
waits for named evidence; its suppressed jobs must not spin. Named metadata and
data repair remain enabled. If this setting changes at runtime, treat that as
an explicit event that reconsiders jobs suppressed by configuration.

**Incoming tile fragments and their transitions**

The top-level inputs are fragments received on rotor's existing tile links.
Each handler decodes its fragment, applies admission/verification, then calls
chainer's internal transitions. Names such as `received_first_shred_in_slot`,
`received_notar`, and `received_verified_fec_root` describe those internal
calls; they are not additional messages or new tile links.

Here, `k` denotes a FEC starting shred index: 0, 32, 64, etc. A "named block"
has a nonzero block ID. Repair class/origin still uses `turbine`. The `frag_*`
names below are proposed handler names corresponding to current incoming links.

**`frag_shred` — from shred tile, `shred_out`**

Decode the signature before interpreting the payload: an ordinary shred, a
completion, and an eviction have different payloads. Preserve the current root
initialization gate and discard obsolete arrivals at/below root; an obsolete
completion also releases its store entry.

For ordinary shreds, apply the known-root-first admission rule before choosing
first-shred versus existing-state handling. The first shred received for a
slot with an existing named version takes the existing-state path if its root
is admitted. It must not create turbine state or start turbine-only timers.

1. **Ordinary data shred: admission creates a new turbine block.**

   Internal call: `received_first_shred_in_slot(shred)`.

   **State:** Create the block and only the entry at k. Record first arrival,
   root, bitmap, and any parent/tip information. Record coverage through the end
   of that FEC; earlier positions remain absent from the table.

   **Requests / delivery:** If parent identity is unknown, schedule header and
   orphan now. If tip is unknown, schedule highest at first arrival + 250 ms.
   Schedule fill for this FEC and `Shred(slot, j)` for each earlier absent FEC
   starting at j after turbine grace. A known parent starts its own repair
   immediately if needed.

2. **Ordinary data shred: admission updates existing block/FEC state.**

   Internal call: `received_shred(shred)`.

   **State:** Update the root owner's bitmap once; update matching versions'
   metadata/caches/metrics. On the admitted turbine unknown-root path, create
   only this shred's FEC entry and extend coverage if needed.

   **Requests / delivery:** Causes cancellation of fill requests for the received
   position. Give a newly created entry its fill requests. When an unnamed turbine block
   extends its required range, schedule `Shred(slot, j)` for each newly exposed absent
   FEC starting at j; retain retry deadlines for earlier pending requests. Known-root
   reception by a named version leaves its other FecRoot requests pending. Do not revive
   explicitly cancelled work. A highest-shred response that reveals later FECs makes
   these requests and the new FEC's fill due now. Learning slot end causes cancellation
   of highest-shred requests and clamps coverage. Duplicates do not postpone timers.

3. **Either admitted data-shred branch carries a usable parent marker.**

   Internal call: `received_parent_marker(block, batch, parent_slot, parent_id)`,
   as part of processing that same shred fragment.

   **State:** Accept a newer permitted marker, replace the parent dependency,
   and find/create the exact parent version.

   **Requests / delivery:** Causes cancellation of obsolete child header/orphan requests
   once discovery is settled. Schedule the newly created parent's parent/count job now.
   Reevaluate connectivity, block-ID derivation, and delivery. Parse/apply the marker
   before deciding which first-shred timers are needed. A first shred 0 with an
   available parent does not need an orphan/header request.

   The current tile parses the marker on shred 0. Future UpdateParent support
   can take this same branch when a later permitted marker is decoded; it does
   not need a separate parent-marker fragment.

4. **`SHRED_SIG_FEC_COMPLETE` or `SHRED_SIG_FEC_COMPLETE_LEADER`.**

   Internal call: `received_fec_complete(slot, k, root, flags)`.

   **State:** Require an already-admitted root at that slot/position. Set the
   shared bitmap full; mark matching private entries complete and adopt the
   full root/flags. Reject an unknown root without allocating state; rotor
   removes the rejected store entry.

   **Requests / delivery:** Causes cancellation of matching FEC fill requests. Advance
   eligible versions. Completion of a later FEC leaves Shred/FecRoot requests for
   earlier absent entries pending. If it establishes slot end, clamp coverage; this
   causes cancellation of highest-shred requests. Keep other block discovery and parent
   dependencies alive.

5. **`SHRED_SIG_FEC_EVICTED` source.**

   Internal call: `fec_evicted(slot, k, root)`.

   **State:** For incomplete resolver data, clear the owner's bitmap and roll
   back affected cached prefixes. Preserve the entry and root attachments.

   **Requests / delivery:** Schedule missing-shred requests for each matching,
   noncancelled version, including positions whose previous requests were
   already discarded as satisfied. Apply the shred queue's pressure-drop policy.
   Do not revive cancelled versions or suppressed turbine work. These requests
   repair the reopened hole without a new root request. Completed store data
   has a separate lifetime.

6. **Ordinary shred reports `SHRED_SIG_RESULT_EQVOC`.**

   Proposed internal call: `shred_eqvoc(slot)`.

   **State:** Mark the existing unnamed turbine version as cancelled; this causes
   cancellation of its repair jobs.
   Keep block/FEC state and queued deliveries; do not admit the conflicting
   shred as ordinary data.

   **Requests / delivery:** No new requests. Repeated cancellation has no
   additional effect. Future admitted events follow the normal admission rules.
   This is the draft's proposed cancellation branch; the current tile simply
   skips ordinary shred handling for this result.

   A malformed block header is a separate guard in the ordinary-data path:
   reject the shred and call the existing internal `slot_inval(slot)` behavior.
   It is neither another incoming fragment nor successful first-shred admission.

7. **Coding shred.**

   Optional internal call: `received_code_shred(slot, k, root)`.

   **State:** At most update metrics for existing matching entries.

   **Requests / delivery:** None. The current rotor handler returns early on
   coding shreds; chainer's metrics API could be called here if desired.

The first turbine arrival also establishes the catch-up target inside
`frag_shred`, independently of whether it creates the first block in that
slot. Update the observed turbine slot and reconsider bounded seed work when
root/peer prerequisites are available. There is no separate `catchup_target`
fragment. Preserve the distinction between this first turbine observation and
first admitted data creating a block.

Repair responses containing shreds also arrive through `shred_out`, after shred
processing. They use the same data branches above. Match request accounting as
appropriate; do not create a separate `frag_net` data-repair path. Highest and
orphan responses may extend coverage, but a response alone does not settle tip
or ancestry discovery. A highest response without slot end keeps its timer;
an unrelated fork returned by orphan repair does not settle the exact parent.

**`frag_net` — repair packets from net tile, `net_repair`**

Rotor strips/validates packet framing. For metadata responses, match the nonce
and request kind, require a live target above root, and verify the proof before
calling chainer. Malformed, unsolicited, contradictory, or stale responses do
not satisfy a repair dependency.

1. **Verified parent/FEC-count response.**

   Internal call: `received_verified_parent_fec_count(block, parent, count)`.

   **State:** Record exact parent and count. Set coverage to `[0, count * 32)` without
   creating FEC entries. Find/create the exact parent above root, respecting finality
   and the root anchor. (is this a call to `received_notar(slot, block_id)`?)


   **Requests / delivery:** Causes cancellation of this block's parent/count request.
   Schedule `FecRoot(slot, block_id, k)` at every absent position in the verified range,
   including leading, interior, and trailing FECs. Keep FEC fill and parent repair
   independent. Adopt existing data and attempt delivery immediately.

2. **Verified FEC-root response.**

   Internal call: `received_verified_fec_root(block, k, prefix)`.

   **State:** Create the private entry at this verified position and attach it
   to the root owner, or become the owner if none exists. Reuse an existing
   matching entry; reject a contradictory root for this version.

   **Requests / delivery:** Satisfy this position's root request and keep range
   discovery for other missing roots. Schedule only missing shared shreds now. If the
   root already completed, adopt completion and advance immediately. An out-of-order
   response does not cause cancellation of an earlier unanswered FecRoot request.

3. **Repair ping.**

   No internal action, use rotor tile's existing ping/pong handling.

**`frag_votor` — from votor tile, `votor_out`**

1. **`FD_VOTOR_SIG_REPAIR` carrying a block ID.**

   Internal call: `received_notar(slot, block_id)`, for the named-block repair
   notification, including notar-fallback/SafeToNotar-driven repair.

   **State:** Find/create the named version above root, subject to finality and
   version limits. A duplicate notification reuses existing state.

   **Requests / delivery:** Schedule parent/count now if metadata is missing.
   The named-sibling policy suppresses the unfinished unnamed turbine version
   and causes cancellation of its repair requests. Other named siblings keep their work.

   A block ID learned from a child uses the same internal named-block admission
   logic while processing `frag_shred` or `frag_net`. It does not synthesize a
   votor fragment or claim a certificate was received for the parent.

2. **`FD_VOTOR_SIG_CERTED` with final or fast-final certificate.**

   Internal call: `blk_final(slot, block_id)`.

   **State:** Keep/create the selected version, set final, and prune same-slot
   siblings after cleaning their queued references. Preserve the redelivery
   lifetime barrier before applying the fragment.

   **Requests / delivery:** Causes cancellation of losing versions' jobs. Transfer
   shared root ownership before freeing the owner. Preserve winner repair or schedule
   metadata if it is new. Other certificate kinds have no finalization action in this
   handler.

**`frag_replay` — from replay tile, `replay_out`**

1. **`REPLAY_SIG_ROOT_ADVANCED`.**

   Internal call: `root_advanced(slot, block_id)`.

   **State:** After the delivery lifetime barrier, prune old state and retain
   the canonical delivered root anchor. If deliveries still hold references,
   retain the pending root notification and finish applying it when they drain.

   **Requests / delivery:** Causes cancellation of rooted work. Wake waiting children
   and extend bounded catch-up discovery as the live range moves forward. Resuming a
   deferred root is local continuation of this fragment, not a new input.

2. **`REPLAY_SIG_MISSING_FEC`.**

   Internal call: `replay_missing_fec()`.

   **State:** Record that the next delivery needs the existing lineage from root.

   **Requests / delivery:** Redeliver retained FECs in ancestry order, as rotor
   does today. Replay evicting a bank does not by itself require network repair.

**`frag_snapshot` — snapshot input, `snapin_manif`**

- **Branch:** Retain the manifest reference while receiving snapshot messages;
  apply initialization when `FD_SSMSG_DONE` arrives.
- **Internal call:** `initialize(root_slot, root_id)` from the manifest.
- **State:** Create the delivered root anchor.
- **Requests / delivery:** No repair for the root. Reconsider any deferred
  discovery once initialization prerequisites are satisfied.

**`frag_genesis` — genesis input, `genesi_out`**

- **Branch:** Bootstrap genesis metadata.
- **Internal call:** `initialize(0, zero_block_id)`, matching current bootstrap
  behavior. Non-bootstrap initialization comes from snapshot instead.
- **State:** Create the bootstrap root anchor.
- **Requests / delivery:** No repair for the root itself.

**`frag_gossip` — from gossip tile, `gossip_out`**

  No internal wor

**`frag_sign` — signatures from sign tiles, `sign_repair`**

- **State:** May choose to update req_sent directly in chainer.

**Local scheduling and internal continuations**

This is outside the incoming-fragment interface. The tile run loop still needs
local work for deadlines, output credits, and queued delivery. These conditions
are not fragments from another tile and require no new wire messages.

- **Timer becomes due:** Service both request queues. Revalidate target, current
  need, and cancellation state; discard unneeded requests when popped or send
  a bounded amount of due work. Retained unanswered requests remain retryable.
  Shred retries are subject to the same drop policy as new shred requests.
- **Signing submission succeeds:** Reserve the selected request/position while
  awaiting `frag_sign` so it is not submitted repeatedly. Submission itself is
  not network success. A failed handoff leaves the logical request retryable;
  only successful dispatch consumes it for this attempt and starts its timeout.
- **Peer/signing/output unavailable:** Preserve unsent work. Peer or signing
  availability can be restored by `frag_gossip` or `frag_sign`; network/replay
  link credits are observed by the local credit loop. Resume when the required
  resource becomes available, without requiring an unrelated input fragment.
- **Delivery queue drains:** Resume a pending root update or lifetime cleanup,
  wake children whose exact parent is now delivered, and retry deliverable FECs
  under replay credit. No synthetic `parent_delivered` fragment is needed.
- **Seed generation can resume:** Continue a bounded generation pass from its
  cursor as tile/transport budget becomes available. Seed Shred requests use
  the droppable shred queue; seed HighestShred requests use the other queue.
  The target originated in `frag_shred` and the live range in `frag_replay`.
  Seed probes and turbine versions do not enter `deferred_requests`; that side
  queue recovers dropped data requests for notar versions only.
- **Shred capacity is available and the delivered head is stalled:** If the
  delivered head has not advanced for X time, poll `deferred_requests` in
  bounded batches and regenerate individual ShredForBlockId requests from
  current block/FEC state. Preserve unfinished block scans if capacity runs
  out, and resume on a later eligible local turn. Incoming fragments continue
  to be processed; recovery does not require another fragment to trigger it.
- **Delivered head advances:** Update the last-progress timestamp. Keep deferred
  memberships and cursors, but pause their recovery until the stall condition
  holds again. Incoming shreds and request sends do not count as head progress.

**Requests for FECs that have not arrived**

Track the required shred range with an exclusive upper bound. A turbine shred
in the FEC starting at k establishes positions through `k + 32`, capped by the
runtime shred limit and accepted slot end. For each absent FEC in that range,
request its first data shred. For a named block, the verified count establishes
the range and each absent position needs a FecRoot request instead.

- **First shred is index 70:** Create only FEC 64 and record the required range
  `[0, 96)`. Schedule `Shred(slot, 0)` and `Shred(slot, 32)` to establish the
  earlier FECs. Separately request missing data in FEC 64, including 71–95.
- **A later shred establishes FEC 160:** Extend the range to `[0, 192)`. If
  FECs 96 and 128 are absent, schedule `Shred(slot, 96)` and `Shred(slot, 128)`.
  Retain unanswered requests for earlier positions. Restart this request
  generation if the previous range was already satisfied and it had stopped.
- **Highest returns shred 191 after we had only seen through 127:** Create
  FEC 160 and make requests for its missing shreds 160–190 due now. Also make
  `Shred(slot, 128)` due now if FEC 128 is absent. When any admitted shred
  creates FEC 128, request the remaining missing shreds within it. This all
  happens inside `frag_shred` → `received_shred`, without waiting for completion.
- **Highest/orphan returns no new positions:** Keep existing requests and their
  cursors. Retry highest if slot end remains unknown, or orphan if its ancestry
  dependency remains unresolved; a response alone does not satisfy either.
- **Slot end arrives before the prefix:** Causes cancellation of highest-shred
  requests. Keep Shred
  requests for every earlier absent FEC and fill for incomplete entries, and
  exclude all positions beyond the accepted end.
- **Verified parent/count arrives:** Set the range to `[0, count * 32)`. Schedule
  `FecRoot(slot, block_id, k)` for each absent entry at k = 0, 32, etc. The named
  version needs its own root proofs even if turbine has data at those positions.
- **A root arrives out of order:** Create/attach only that entry and request its
  missing data with ShredForBlockId, or adopt existing completion. Root 96
  arriving before root 32 leaves `FecRoot(slot, block_id, 32)` retryable.
- **Resolver eviction clears received bits:** Keep the entry and root. Request
  missing Shred or ShredForBlockId data for that existing FEC, according to its
  version; do not request its root again.

Bound scanning and request generation per turn; a per-block cursor can retain
a generation continuation separately from the required range. Generated Shred
requests go to `shred_or_shred_for_block_id_queue`; FecRoot requests go to
`all_other_requests_queue`. Advancing a cursor does not mean data arrived.
Retained requests retry if still needed. If a notar version's shred request
cannot be queued, `deferred_requests` retains the block for later regeneration.
A dropped turbine or seed Shred request does not enroll a block in this side
queue. Do not allocate a rootless FEC entry merely to remember an outstanding
request.

Delivery stops at an absent entry until its Shred/FecRoot response establishes
it and it completes. Having all entries causes cancellation of requests to
establish them; continue fill for their missing data. Parent dependencies can
still hold up delivery after all FECs complete. Missing slots between blocks
are discovered through ancestry/catch-up requests, not by assuming every slot
number must exist.

**Admission, sharing, and completion**

Preserve the current known-root-first rule. An admitted root updates existing
matching versions regardless of whether the packet came through turbine or
repair. It does not create an extra turbine version, attach unrelated missing
FECs to that version, or overwrite a different root at the same position. Shred/FecRoot
requests for absent entries remain per version, independent of who owns the
shared bitmap.

For an unknown root, turbine state may be created only when the slot has no
versions. An existing turbine version can extend only while its ID is unknown
and there is no non-turbine sibling. A conflicting root for a position already
chosen by turbine is dropped. Once only named versions exist, a root proof must
establish the relevant entry before its shreds/completion can be admitted.

A late named version must immediately see the root owner's bitmap. If that root
completed before the version learned it, attachment is itself a completion
transition for the new version. A blanket "root already complete, return" would
lose this transition and strand the new version forever. Duplicate completion
must avoid repeat delivery/recovery accounting for existing versions while still
allowing newly attached versions to adopt the same completion.

Keep block-specific facts separate from shared bytes. In particular, verified
FEC count belongs to a block version; sharing a FEC does not authorize changing
that count. The current code propagates slot-end flags and can overwrite
`complete_idx`. Resolving inconsistent slot-end/count evidence is an existing
policy gap, not something the timer refactor automatically solves. Before
implementation, specify rejection of contradictory bounds and whether such a
conflict affects a version or the underlying FEC. The scheduling requirement is
unambiguous: do not generate requests beyond the accepted end of that version.

**Ancestry must make progress without stopping fill**

Unknown parent identity, absent parent state, and an incomplete parent are three
different conditions:

| Condition                                                   | Action                                                                                                                 |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Unnamed turbine block has no usable parent marker           | Header request plus orphan discovery; continue filling known positions and keep highest discovery independent          |
| Named block has no verified parent/count                    | Parent/count request; do not speculate about FEC roots beyond an unknown count                                         |
| Exact parent ID is known but parent state is absent         | Materialize that named parent and immediately schedule its metadata repair                                             |
| Exact parent exists but is incomplete/disconnected          | Repair the parent through its own jobs; wait for its connection/delivery event while repairing the child independently |
| Parent identity is incompatible with the rooted/final chain | Do not recreate a pruned fork or retry an impossible dependency forever                                                |

"Some version of the parent slot exists" is not enough to attach a child.
Connections use the exact parent block ID. The root anchor also requires the
right identity; a different block at the root slot is not an available parent.

The current marker API supports a later batch superseding earlier parent
information, but the tile currently extracts the marker on shred 0. A future
UpdateParent event must move the waiting-child relationship to the new exact
parent, cause cancellation of obsolete discovery requests, and reevaluate
connectivity rather than
retaining a sticky `connected` result for the old parent. Do not prune the old
parent just because this child changed; other children may still need it.

These events also need to rerun block-ID derivation when all turbine FECs were
completed before usable parent metadata arrived. Requiring a second completion
event to finish that transition would introduce another missed wakeup.

**Abandonment and invalidation**

Keep the existing named-sibling suppression predicate as an explicit admission
and delivery policy:

```text
block.turbine && block.block_id == 0 && slot_has_nonturbine(block.slot)
```

When it becomes true, it causes cancellation of the turbine block's jobs. Existing
admitted roots remain usable: arrivals still update shared bytes, and named versions can
attach to them. The suppressed turbine version does not extend unknown roots, derive its
block ID, or advance delivery. A turbine version whose ID was already computed remains
eligible under the current policy. If two versions ultimately represent the same block,
replay can handle that; the queue design does not require abandonment to prevent
duplicate replay banks.

`slot_inval` marks the unnamed turbine version as cancelled, which causes
cancellation of its repair requests. It does not by itself change shred
admission or delivery eligibility. Later arrivals can still update admitted
data and completion can advance delivery, but they must not schedule new repair
for the cancelled version. The named-sibling policy additionally suppresses
extension and delivery as described above.

An absent job, an absent FEC 0, or an empty queue never means "invalid block."
Check the version's cancellation state explicitly. Keep that state set for the
version's lifetime; supporting reactivation would require distinguishing old
cancelled jobs from newly scheduled jobs, for example with a generation.

**Delivery and object lifetime**

After completion, root attachment, usable parent metadata, parent delivery, or
root advancement, try to advance the affected versions. Delivery starts at FEC
0 and stops at the first absent/incomplete position or an unmet parent dependency.
When a parent becomes fully delivered, wake its waiting children even if all
their FECs completed much earlier. The current child scan is sufficient to
start; a parent-to-children index is an optional performance change.

A shared prefix must be emitted again for each version that needs it. A global
"this root has been delivered" bit would break replay of a sibling that later
diverges. Keep the existing per-version delivery cursor. Root-based data sharing
and version-based ordered delivery are compatible.

Having no missing data in FEC 0 causes cancellation of its data requests. Its
block's metadata jobs and parent dependency continue independently. This does
not free FEC 0 from the pool/map/store: retain the data needed for normal
delivery, sibling adoption, and replay redelivery until finality/publish cleanup.

Freeing a block or FEC entry causes cancellation of jobs that no longer have
a live target or useful request. Before freeing it, remove or drain queued
deliveries and deal with transport references. If the departing entry owns a
root used by a survivor, transfer root ownership and the authoritative bitmap
first. Keep completed store data while surviving versions need it. A generation
check handles stale timers; it does not by itself pin store data for an already
queued replay delivery.

Preserve the current lifetime barriers: rotor holds finality processing while
its external redelivery queue contains references, and publish waits for queued
deliveries to drain. Finality filters the losing versions' chainer output before
pool release. Finality prunes versions of that slot, not every earlier slot or
its ancestry. If the selected final version is new and the slot is at its
version limit, prune losers before allocating it.

Late verified metadata for a pruned version is ignored rather than recreating
it. Late shreds are still subject to normal root admission: a stale request can
return bytes useful to a surviving version, but it cannot resurrect the loser.

**Two bounded request queues**

Use two separate priority queues with independent capacity:

**`shred_or_shred_for_block_id_queue`**

- Contains individual `Shred(slot, idx)` and
  `ShredForBlockId(slot, block_id, idx)` requests.
- This includes shred 0 requested for a header, the first shred requested for
  an unseen FEC, remaining missing shreds in a known FEC, and seed Shred probes.
  Routing is by request kind, not by why the request was generated.
- Size provisionally for 20,000 blocks with 2,048 data shreds per block:
  `20,000 * 2,048 = 40,960,000` request entries. This is a workload sizing
  assumption, not the protocol's maximum shred count or a guarantee that every
  possible missing shred can be queued. For this estimate, count block versions;
  sizing for 20,000 slots with multiple versions would require more entries.
- Queue memory is the entry capacity multiplied by the chosen request-node
  footprint, plus queue bookkeeping. The compact node layout is still to be
  chosen; capacity in requests is not a byte budget.
- When capacity runs low, dropping individual shred requests is allowed.
  This applies to initial scheduling and retries. If the dropped request is
  for a live, noncancelled notar version, enroll that version once in
  `deferred_requests`. Apply this both to a failed enqueue and to removing an
  already queued request to make space. Turbine versions are not enrolled.
  The pressure threshold and which requests to drop remain to be chosen.
- A dropped request does not change a received bit, complete a FEC, or cancel
  the block. Keep the accepted fragment's state changes and continue consuming
  inputs. Shred-queue exhaustion alone does not defer a fragment on its input
  link or force the tile to spin until request capacity is available.

**`all_other_requests_queue`**

- Contains `HighestShred`, `Orphan`, `ParentAndFecCount`, and `FecRoot` requests,
  including HighestShred seed probes.
- Size for the configured maximum admitted block versions and maximum FECs per
  version, rather than the 2,048-shred average-case assumption. Account for
  block-level requests, one FecRoot request per required FEC position, and
  bounded discovery requests for slots that do not yet have block state.
- Deduplicate each logical request; retries reuse its capacity rather than
  allocating another independent copy. The capacity calculation must also
  account for obsolete entries awaiting lazy cancellation and any requests
  retained while signing/in flight. Pruning must not permit an unbounded
  accumulation of old requests alongside newly admitted versions.
- These requests do not use the shred queue's pressure-drop policy. Missing
  metadata/discovery work must remain represented within its separate bound.
  Filling the shred queue cannot consume this queue's reserved capacity.

The two primary queues contain individual requests. The separate
`deferred_requests` side queue contains block versions, not individual shreds.
Request generation uses bounded loops/cursors to limit per-turn CPU work. The
block/FEC pools remain separately bounded; removing placeholder allocation
does not remove those state limits.

**`deferred_requests` — per-block recovery of dropped notar shred requests**

When a shred request cannot be added to `shred_or_shred_for_block_id_queue`
because of capacity, keep processing the fragment and enroll its target block
in `deferred_requests` if that version is non-turbine and not cancelled. This
also applies when a retry cannot be retained, or an existing notar request is
dropped to relieve pressure. The identity is `(slot, block_id)`, so sibling
versions are independent. Eligibility uses `!block->turbine`, not merely a
nonzero block ID: a turbine version that computes its ID is still turbine.

Store at most one deferred membership per live block version, with a bit or
index on the block preventing duplicate enrollment. Size this queue to the
configured maximum live block versions, including siblings. One dropped shred
or thousands of dropped shreds for the same version consume one side-queue
entry. Keep a cursor for a partially regenerated block so one large block does
not monopolize the tile.

This capacity bound requires membership storage to follow the block's lifetime.
Pruning causes cancellation of its deferred work, and its membership storage
must be reclaimed before that block's capacity is reused. An intrusive queue
using fields in the bounded block pool is one possible representation. Do not
accumulate detached stale entries while allocating memberships for replacement
blocks; lazy checks of primary request entries do not make that accumulation
bounded. Removing a block from this side queue is lifetime bookkeeping, not a
scan/removal of its individual requests from either primary queue.

The local run loop starts polling deferred blocks only when both conditions hold:

- `shred_or_shred_for_block_id_queue` has capacity to accept more requests.
- The delivered head has not advanced for X time.

Track the last time the delivered head actually advanced, using a consistent
clock. Neither incoming shreds, FEC reconstruction alone, nor request sends reset
that timer. Initialize the timer when the delivery head is initialized so a
validator that has never advanced it can still enter recovery. X remains a
policy parameter. The delivery path must identify the head being tracked;
unrelated out-of-order completions must not masquerade as advancement.

For each polled block:

1. Query the exact live version. Rooted, cancelled, turbine, or no-longer-needed
   work causes cancellation of that deferred entry; generate no data requests.
2. Examine its known FEC roots and authoritative shared received bitmaps within
   its verified count. Skip received positions and equivalent requests already
   queued, awaiting signing, or in flight under their retry policy.
3. For each remaining missing data position, enqueue
   `ShredForBlockId(slot, block_id, shred_idx)` in the shred queue, due now.
   No rootless FEC placeholders are needed.
4. Stop when capacity or the per-turn recovery budget is exhausted. Retain the
   block's membership and cursor, and give other deferred blocks bounded turns.
   Do not repeatedly pop and reinsert blocks while the shred queue is full.
5. Complete the deferred pass when every currently repairable missing position
   is either received or represented by a retained request. Clear that version's
   membership. If another enqueue/retry later fails, enroll it again.

If metadata or a FEC root is still missing, its ParentAndFecCount/FecRoot request
remains in `all_other_requests_queue`. Skip that dependency for this recovery
turn; do not issue unverified data requests or block other deferred versions.
The eventual verified response generates its normal data requests and enrolls
the block again if those cannot fit.

A scan cursor is not proof that earlier positions still have requests. A new
drop, eviction, or failed retry behind that cursor must rewind it to the affected
position or mark it for another pass before clearing deferred membership.
Repeated failures while a block is being serviced retain the same membership;
they must not create a second entry or be lost when the current pass ends.

When the delivered head advances, reset the stall timer and pause deferred
request generation. Retain memberships and cursors until recovery is eligible
again. Capacity becoming available by itself is insufficient to run recovery,
and a stall with no shred capacity is insufficient to enqueue more requests.
Cleanup of stale membership and normal fragment/request handling still proceed.

This recovery policy is intentionally limited to notar versions. Dropped turbine
requests and seed Shred probes do not populate `deferred_requests`. The two
primary queues continue operating normally alongside this local recovery path.

**Ordering, cancellation, and dispatch**

Each queue orders its requests by the chosen scheduling policy. A binary heap
is sufficient for insertion and priority pop with lazy cancellation. Deadline
and repair priority remain distinct policy choices: deadline-first ordering
and highest priority among due requests have different behavior. The queue
split does not settle that choice.

On pop, query the requested block version and check whether the request is still
needed. Missing/rooted/cancelled targets and satisfied requests are discarded.
Seed probes are an explicit exception to the missing-target check: they exist
to discover slots without block state and are validated against the bounded
seed range instead. State changes described as causing cancellation do not
require arbitrary removal from a heap while handling the fragment.

Service both queues with bounded work per tile iteration. Metadata and ancestry
requests must receive service even while the shred queue remains busy. Lazy
cancellation checks do not require signing or replay credit; check usefulness
before waiting for transport. Cancelled entries continue to occupy their queue
capacity until discarded.

For data requests, read the current authoritative shared bitmap and accepted
slot end before sending. Existing entries with all data present wait for FEC
completion; they need no further data requests. Resolver eviction clears the
bitmap and generates fresh missing-shred requests for noncancelled versions,
subject to shred-queue capacity. Completed store data has a separate lifetime.

Successful handoff of the signed packet to network output starts retry timing.
No peers or signing/output credit leaves retained work pending on transport
availability. A request that is retained and remains useful is retried after
its deadline; requeueing a shred request can drop it under the same pressure
policy and must enroll its notar version in `deferred_requests` if so. Failed
or malformed metadata does not satisfy its dependency. An old
attempt must not overwrite a newer request's state.

Replay output backpressure must not stop repair dispatch or fragment processing.
The current `after_credit` returns early without replay credits; this integration
needs to allow independent repair progress, within the separate request/state
bounds. Neither independent queue capacity nor an average-case shred capacity
is a network rate limit; transport admission and service budgets remain separate.

**Catch-up follows fragment inputs and local capacity**

Existing block jobs cannot repair a slot for which no state has ever been
created. Parent traversal eventually discovers actual ancestors, but waiting
one round trip per ancestor makes a large gap slow. Retain parallel discovery
as explicit seed work. Its target comes from `frag_shred`, peer eligibility
from `frag_gossip`, and root movement from `frag_replay`. Resuming work when
generation/transport budget returns belongs to the local run loop. Shred-queue
pressure may drop seed Shred requests; it does not block HighestShred requests
from entering `all_other_requests_queue`:

| Event                                                                 | State change                                            | Scheduled output                                                                     |
| --------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| First turbine slot establishes target, and enough peers are available | Set catch-up target and initial bounded discovery range | Shred 0 and highest-shred probes for unobserved slots in that range                  |
| Replay root advances                                                  | Move the maximum live range forward                     | Probe newly eligible slots up to the target                                          |
| Generation/transport budget returns                                   | Resume a partially registered range                     | Continue seed generation; dropped seed Shred requests do not enter deferred_requests |
| Probe returns an admitted shred                                       | Create normal block/FEC state                           | Normal event transitions now own its repair                                          |
| Probe returns nothing                                                 | No evidence the slot exists; it may have been skipped   | Do not allocate a block or retry every numeric slot forever                          |

Today seeding waits for 64 peers and probes through
`min(first_turbine_slot, replay_root + max_live_slots)`. Its watermark advances
as new slots are probed; "repeated seeding" mainly extends the range as replay
moves, rather than retrying the same range every timeout. Preserve that bound
and resume partially generated seed work on local budget availability. Dropping
a seed Shred request under the new pressure policy is distinct from pausing
generation. Seed Shred probes do not enroll a block in `deferred_requests`.

For a first version, keep seed probes best effort as today. Ancestor discovery
and later arrivals can discover slots missed by probes. The deferred recovery
mechanism applies once a notar version exists and its data requests are dropped;
it does not add recovery for seed probes or turbine versions. Periodic bounded reprobes are
a separate latency policy, not an excuse to make every skipped slot a permanent
repair obligation. The discovery bound is also not by itself a complete
admission bound: ordinary shreds/certificates can create state independently,
so block/FEC pools and downstream live-slot limits still need enforcement.

**Example event traces**

| Time/event                                                  | Mutation                                                         | Work/output                                                                                                                      |
| ----------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| t=0: first accepted shred is idx 70; parent and tip unknown | Create turbine version and only FEC 64; set bit 6; cover [0, 96) | Header + orphan now; Shred(slot, 0), Shred(slot, 32), FEC 64 fill at t+100 ms; highest at t+250 ms                               |
| t=20 ms: shred 0 names parent P                             | Create FEC 0; record exact P; create P if absent                 | Causes cancellation of child header/orphan requests once P has its own work; parent/count(P) due now; child fills/highest remain |
| t=40 ms: FEC 0 completes                                    | Mark it complete                                                 | Causes cancellation of its fill requests; Shred(slot, 32) remains pending; highest due at t=250 ms                               |
| t=100 ms: fill timer fires                                  | Re-read bitmap                                                   | Request Shred(slot, 32); FEC 64 fill requests its missing bits                                                                   |
| t=250 ms: highest timer fires; tip still unknown            | No data mutation                                                 | HighestShred(child); retry if response never establishes slot end                                                                |
| Later: tail and parent complete                             | Compute turbine ID when possible; satisfy parent dependency      | Deliver child's contiguous FECs from 0; wake its children at full delivery                                                       |

| Shared-root event                               | Mutation                                | Work/output                                                                          |
| ----------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------ |
| Turbine T has partial root R; notar names B     | Create B; suppress unnamed T            | Causes cancellation of T's jobs; parent/count(B) now                                 |
| Verified parent/count(B), then FEC root(B, 0)=R | Attach B to R's existing owner          | Request only missing R bits; do not copy reception into a separate bitmap            |
| R completes                                     | Complete matching T/B entries           | B can advance; suppressed T cannot. Causes cancellation of B's fill requests         |
| Another version C later proves root R           | Adopt existing full data and completion | Deliver R for C when its own parent/order permits; no extra completion packet needed |
| B becomes final; T owned R's root map entry     | Prune T and C; promote B's entry        | Preserve bitmap/full root/store data and B's delivery references                     |

**Cases the implementation should demonstrate**

These are future event-sequence tests, not code changes in this draft:

- Saturating `shred_or_shred_for_block_id_queue` drops shred requests without
  rolling back accepted state, setting received bits, cancelling a block, or
  blocking fragment consumption solely on that queue's capacity.
- Shred pressure cannot consume `all_other_requests_queue` capacity or prevent
  highest/orphan/parent/count/FEC-root request scheduling. Metadata capacity
  includes retained obsolete requests as well as live requests.
- Repeated shred enqueue failures for one notar version create one
  `deferred_requests` entry. Failures for distinct versions create distinct
  entries, bounded by the maximum live block-version count.
- Dropped turbine requests do not enroll even when the turbine block has
  computed a nonzero block ID. Failed notar retries also enroll.
- Deferred recovery runs only when shred capacity is available and the delivered
  head has been stationary for X time; it resumes without a new fragment.
- Recovery reads current shared bitmaps and avoids duplicate outstanding
  requests. Capacity exhaustion retains the unfinished cursor and membership.
- A new failure behind an in-progress scan cursor is revisited before the
  version is removed from `deferred_requests`.
- Delivery progress pauses recovery without forgetting deferred blocks. Pruned,
  cancelled, or already satisfied blocks cause no repair requests on recovery.
- Block-pool reuse and stale deferred membership never exceed the side queue's
  maximum-live-block bound or target the wrong version.
- Repeated first-shred/duplicate events neither duplicate jobs nor postpone
  highest indefinitely. Slot end before 250 ms causes cancellation of that request.
- First shred 70 creates only FEC 64; schedule `Shred(slot, 0)` and
  `Shred(slot, 32)` without placeholders. A later FEC schedules first-shred
  requests for newly exposed absent FECs while retaining unanswered requests.
- Verified count creates no FEC entries. FecRoot requests visit every absent
  position in the verified range; unanswered requests remain retryable when
  responses arrive out of order.
- A tail completing before its prefix does not cause cancellation of Shred/FecRoot
  requests for earlier absent entries. Delivery resumes in order as responses arrive; no
  requests extend beyond the accepted slot end.
- Header/orphan discovery and fill make independent progress. A response naming
  a new parent immediately starts that parent's requests.
- Completing FEC 0 does not remove highest or ancestor discovery. A completely
  buffered child wakes when its parent is delivered or becomes the root anchor.
- A verified root immediately exposes previously received shared bits and
  completion. Completion-before-attachment and attachment-before-completion
  both deliver once per version.
- Two named siblings at the same slot/FEC position both get timer service,
  including when one is cooling down or repeatedly loses responses.
- An all-received FEC waits for completion without busy looping; resolver
  eviction resets its bitmap and fill round so repair resumes.
- Named-sibling suppression preserves shared data. `slot_inval` causes cancellation of
  repair work without turning queue membership into admission/delivery policy.
- Finality during outstanding repair preserves surviving root ownership and
  rejects stale metadata. Reused pool indices do not inherit old callbacks.
- No-peer/signing/backpressure conditions preserve retained unsent work and
  resume it when transport is available. Dropped notar shred requests retain
  their block in `deferred_requests` for recovery under the stall/capacity gate.
- A large catch-up gap expands within the live bound. Shred-queue pressure
  does not block metadata scheduling or incoming state updates; skipped slots
  do not create immortal requests.
- All FEC ranges use the runtime `fec_blk_max`, including benchmark blocks larger
  than the normal production limit. Verified count gates root requests.

The first implementation can keep the current pools, maps, bitmap ownership,
and child scan. Allocate private FEC entries only for admitted roots. Move
request choice from `fd_requestor` into these fragment handlers and internal
transitions. Generate Shred requests for absent turbine FECs and FecRoot requests
for absent named FECs using per-block cursors. Replace the positional sweep with
explicit timed work and wire transport availability/acceptance into scheduling.
Dropped notar shred requests are recovered through `deferred_requests` when
shred capacity returns and delivery has stalled. Remaining choices include X
(the stall timeout), per-turn recovery budget, pressure threshold/drop selection,
exact timer/priority values, optional cross-version request deduplication, and
inconsistent slot-end evidence.
