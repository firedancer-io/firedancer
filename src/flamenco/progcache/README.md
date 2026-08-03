# Program cache

This document explains the internals of Firedancer's SVM program cache:
a fixed-size, fork-aware, thread-concurrent cache over programs in the
account database.  It uses CLOCK cache replacement.

## Motivation

The program cache is not strictly necessary — all data needed to execute
an SVM program is in the account database.  However, loading and
validating a program from its sBPF ELF can take up to a millisecond.

Firedancer therefore caches the results of program loading and
validation, including programs that failed to load.

## Users

There exist two kinds of users:
- transaction executor threads (execle, execrp tiles):
  - reads from the cache
  - fills cache on demand
  - evicts old records lazily (when out of space)
- replay thread (replay tile):
  - advances the root and cancels dead forks, deleting their records

## Terminology

### Concurrency terminology

This document uses several similar-looking terms whose differences
matter for concurrency:

- **concurrent**: multiple threads (on different CPU cores) accessing
  shared resources
- **lock**/**rwlock**: spinlock using atomic operations (Firedancer
  generally does not use OS locks because all threads are pinned and
  never sleep)
- **removal**: marks a resource as removed, making it invisible to
  future readers.  Safe even while there are active users
- **eviction**: removal due to cache pressure
- **reclamation**: frees resources of a removed record without active
  users
- **deletion**: removal and reclamation in one go
- **quiescent state**: a point in time when a given thread has no active
  uses/references to any resources (typical example: txn executor thread
  has finished one txn, but has not yet started executing the next)

A "resource" is a collection of objects sharing a life cycle (e.g. a
cache record and its value slot).
Reclamation ends a resource's lifetime.  The same underlying memory may
back a new resource, but it is logically distinct.

### Fork graph terminology

Some areas of Firedancer overload the term "transaction" (SVM txn and
database txn).  We use the term **fork** for the latter to avoid
confusion.

- **root**: the newest finalized block
- **fork**: "fork graph node" (a database revision corresponding to a
  block in the account database)
- **lineage**: a path from root to tip in the fork graph
- **slot** (number): given a lineage, uniquely identifies a block

## Design

### Fork graph

The program cache maintains its own fork graph and supports the standard
set of operations:
- attach_child: create a fork
- cancel: remove a fork and all its nodes/children
- advance_root: promote a fork graph node to root and cancel its siblings

The program cache uses a variation of the accounts database structure
design.  The fork graph is expressed as an n-ary tree:
- each node maintains a doubly-linked list of siblings
- each node maintains a doubly-linked list of cache records it owns

Fork graph nodes are allocated from a fixed-size pool.  A hash map
indexes all forks.

Fork creation and deletion are protected by a global rwlock (acceptable
because these operations are infrequent, O(100ms)).

### "Rooting"

The consensus layer asynchronously finalizes forks.  This is called
"rooting" in the SVM (synonym for "finalized").  All slot numbers up to
and including the root slot map to exactly zero or one blocks (zero if
the slot was skipped).

Once all threads in the system have acknowledged that a fork was rooted,
no query can reach record revisions older than the root.  Rooting also
cancels any fork graph paths that do not contain the rooted block,
potentially shadowing records that must then be reclaimed.

More precisely, there are three separate root slot numbers that advance
asynchronously: consensus, then system, then progcache.

- consensus root: advances when the consensus layer finalizes a fork
- system root: advances when all tiles have logically acknowledged the
  new root slot.  Logical ACK occurs when a tile understands that no
  more operations on conflicting forks are possible.  This is almost
  always instantaneous, except when a long fork is invalidated.
- progcache root: advances when all root-related reclamations are done

### Revisions

Program cache record revisions differ significantly from account
revisions.

Each program (identified by SVM address) has at least two account
revisions: before deployment and after first deployment.

Epoch boundaries may introduce breaking VM changes via feature
activations.  For example, a feature could alter the program loader,
producing a different read-only image for the same executable.

The cache therefore maintains distinct records before and after an
epoch boundary, even if they refer to the same program account
revision.

Future versions of Firedancer could relax this mechanism by only
reloading programs if the program content actually changed.

Selecting the correct revision on query is therefore non-trivial.
Each record access considers the following slot numbers:

- **load_slot**: the current slot number at the time the cache is being
  accessed
- **deploy_slot**: the most recent slot in which the program was
  deployed or retracted, as of load_slot
- **feature_slot**: slot in which the feature set last changed (some
  features invalidate programs or change their behavior)

### Record life cycle

Records have the following states:
- free: on its size class's free list, kept write-locked (a stale
  speculative reader can never lock a free record)
- in-flight: acquired and being loaded, invisible (not in the map)
- published: owned by a fork, visible to users
- rooted: finalized by consensus (not owned by a fork), visible

A program is fully loaded and validated before its record is published,
so the map only ever contains complete records.

### Record lookup

All revisions of a program are stored in the same hash map bucket.
Lookup walks the bucket chain and selects the best matching revision.

### Record deletion

Records to be deleted are immediately removed from the record map.  If
the record is still read-locked, it is pushed onto a deferred-reclaim
list shared across all threads; whichever thread next runs reclaim
(after eviction, rooting, cancellation) frees it once its readers have
released.  Reclamation returns the record to its class free list.

### Cache replacement policy

The program cache uses the CLOCK cache replacement policy, independently per
size class: each class has its own hand that walks only that class's
record range.  Any thread whose insert finds its class full runs cache
replacement.

If eviction cannot free a record (all victims still read-locked), the
insert falls back to a spill scratch: an exclusively-locked buffer sized
for one full CPI stack of top-class programs, guaranteeing every fill
completes without deadlock.  Spill records are never published to the
map.

## Details

### Concurrency

The program cache uses reader-writer spinlocks heavily (read operations require
atomic CAS) for sequencing concurrent accesses and ref-counting based
reclamation.  This is a deliberately conservative design, currently
preferred over approaches like QSBR.

The reason is that mainnet replay performance is heavily dependent on
tail events (like program cache OOM conditions).

Whether the happy path (read locks to existing records) takes 10 or
100 nanoseconds is immaterial to mainnet performance, but this is what
QSBR optimizes for, at the expense of tail event performance.

Reader-writer spinlocks are great in this case: all tiles spin pinned
to cores, so priority inversion and sleep deadlocks are not a concern.
And write lock latency is low.  The program cache further tries to
do fine grained locking in the happy path to distribute cache traffic.

QSBR, while having superior read lock latency, has massively higher
write lock (reclamation) latency.  Low latency reclamation is required
in the event of OOM, because it requires each exec tile to finish the
currently executing transaction, which could take multiple milliseconds.

### Allocator

Memory is divided into size classes, each with a fixed number of slots:

| class | slot size          |
|-------|--------------------|
| 0     | 128 KiB            |
| 1     | 512 KiB            |
| 2     | 1 MiB              |
| 3     | 2 MiB              |
| 4     | 4 MiB              |
| 5     | 11 MiB             |
| nx    | non-executable     |

A program occupies one slot of the smallest class that fits it.  The
spill region is shared by all exec tiles and stays write-locked to one
tile for its whole execution, so tiles that need it while it is held
spin.  Sizing the cache linearly in the number of exec tiles avoids
spilling entirely.

## Verification

The program cache is a complex component:
- Recycles fixed records and value slots (use-after-free risk)
- Thread-concurrent with complex locking rules (deadlock risk)
- Maintains a multi-versioned index (algorithmic complexity)
- Does cache eviction (use-after-free risk, correctness risk)

----------------

To address these risks, we use various dynamic analysis tooling:

### AddressSanitizer

Compiler tool for detecting invalid memory accesses
(compile-time instrumentation).

### Valgrind memcheck

External tool for detecting invalid memory accesses.

Uses a mix of automatic dynamic hooks inserted into libc and
custom instrumentation in our code.

### ThreadSanitizer

Compiler tool for detecting data races.  Integrates with
progcache's use of C11 stdatomic.

### fd_racesan

Framework for testing deterministic interleavings of
concurrent algorithms running on different threads.

### fd_progcache_verify

Algorithm for verifying data structure integrity issues
(leaked ref counts, index aliasing, linked list cycles, etc).

----------------

These are then run over the following test harnesses.

### test_progcache

Contains various unit and regression tests (ASan, MSan, Valgrind instrumented).

### test_progcache_racesan

Explores interleavings of progcache interactions on different simulated threads.
(ASan, Valgrind, fd_racesan instrumented)

----------------

### Quint models

`progcache_walk.qnt` and `progcache_txn_recycle.qnt` model two concurrent
interactions at instruction granularity, in the places where the reasoning is
easy to get wrong.  Each is parameterised so that the same machine can be
checked in a deliberately broken configuration as well as the real one: a
"no violation" verdict is only worth having if the model is able to produce a
violation at all.

    quint verify progcache_walk.qnt --main=buggy --invariant=walkSound
    quint verify progcache_walk.qnt --main=fixed --invariants walkSound walkComplete

`progcache_walk.qnt` covers publish_one's record walk against deferred reclaim
and slot reuse.  `buggy` reads the next link after clearing txn_idx and is
expected to fail; `fixed` snapshots the link first.

    quint verify progcache_txn_recycle.qnt --main=txnRecycle --invariant=noStaleUnlink
    quint verify progcache_txn_recycle.qnt --main=noCas      --invariant=noStaleUnlink
    quint verify progcache_txn_recycle.qnt --main=lockReinit --invariant=noForeignUnlock

`progcache_txn_recycle.qnt` covers a reclaimer that blocks on txn->lock while
the txn is published and its pool entry handed to another fork.  The real
configuration holds; `noCas` shows that the CAS on rec->txn_idx is what makes
it hold, and `lockReinit` shows that re-initialising txn->lock on pool reuse
would break lock ownership.

### Trace validation

Under racesan, `publish_one` logs each record walk; the deterministic
`publish_reclaim_reuse_walk` scenario pins the reclaim/reuse window that
randomised weaving does not reach, and the weaves cover breadth.
`contrib/quint/check_trace_conformance.sh` checks the logged walks against
`progcache_walk.qnt`; see that script's header for the trace format, the two
checking layers, and the exit codes.

    make -j BUILDDIR=clang-racesan CC=clang EXTRAS=racesan test_progcache_racesan
    contrib/quint/check_trace_conformance.sh

The abstraction maps a record on the list to its position and anything else to 0
(the model's record from another fork); relabelling by order of appearance would
erase exactly the distinction being checked.  The check runs in one direction
only: observed behaviour must be admitted by the model, not the converse.  The
model is configured for a two-record list, so longer walks are covered by the
structural layer alone.
