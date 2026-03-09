# Program cache

This document explains technical internals of Firedancer's SVM program
cache.  The program cache is a fork-aware thread-concurrent cache over
programs in the account database with fixed size.  It uses CLOCK cache
replacement.

The program cache is filled lazily on use, and does lazy and eager
cache invalidation (for feature activations and redeploys respectively).

## Motivation

Theoretically, the program cache is not necessary.  All data necessary
to execute an SVM program is contained in the account database.

Practically doing this is prohibitively expensive and slow.  Loading
and validating an SVM program from the sBPF ELF file format can take up
to a millisecond.

Firedancer therefore caches the results of program loading and
validation, including programs that failed to load.

## Terminology

### Concurrency terminology

This document uses similar-looking terms: eviction, reclamation,
removal, deletion, etc.  There are meaningful differences that are
important for concurrency:

- **concurrent**: multiple threads (on different CPU cores) accessing
  shared resources
- **lock**/**rwlock**: spinlock using atomic operations (Firedancer
  generally does not use OS locks because all threads are pinned and
  never sleep)
- **removal**: marks a resource as removed, making it "invisible" to
  future readers.  It is safe to mark a resource as removed while there
  are active users
- **eviction**: removal due to cache pressure
- **reclamation**: frees resources of a removed record without active
  users
- **deletion**: removal and reclamation in one go
- **quiescent state**: a point in time when a given thread has no active
  uses/references to any resources (typical example: txn executor thread
  has finished one txn, but has not yet started executing the next)

The term "resource" is loosely defined: a collection of objects with
the same life cycle (e.g. a fixed size descriptor from a pool allocator
and a variable-size heap allocation).  _Reclamation_ ends the lifetime
of a resource.  Another resource can be created with the exact same
underlying memory, but it is logically considered a different resource.

### Fork graph terminology

Some areas of Firedancer overload the term "transaction" (SVM txn and
database txn).  We use the term **fork** for the former to avoid
confusion.

- **root**: the newest finalized block
- **fork**: "fork graph node" (a database revision corresponding to a
  block in the account database)
- **lineage**: a path from root to tip in the fork graph node
- **slot** (number): given a lineage, uniquely identifies a block

## Users

There exist two kinds of users:
- transaction executor threads (execle, execrp tiles)
- replay thread (replay tile)

The executor threads fill the cache on demand and eagerly insert cache
invalidations.  The replay thread removes records in the background as
slots get rooted.

## Design

### Fork graph

The program cache maintains its own fork graph and supports the standard
set of operations:
- attach_child: create a fork
- cancel: remove a fork and it all its nodes/children
- attach_root: promote a fork graph node to root and evict its siblings

The program cache uses a variation of the funk data structure design.
The fork graph is expressed using a n-ary tree:
- each node maintains a doubly-linked list of siblings
- each node maintains a doubly-linked list of cache records it owns

Fork graph nodes are allocated from a fixed size pool.

There exists a hash map over all forks.

Creation and deletion of forks is protected by a global
rwlock (this is fine because it happens infrequently, O(100ms)).

### "Rooting"

The consensus layer asynchronously finalizes forks.  This is called
"rooting" in the SVM (synonym of "finalized").  All slot numbers up to
and including the "root slot" map to exactly zero or one blocks (zero in
the case that slot was skipped).

Once all threads in the system have acknowledged that a fork was rooted,
it is impossible for queries to reach revisions of records that are
present at the root or newer.  Rooting also cancels any paths in the
fork graph that do not contain the rooted block.  In other words, a root
operation may shadow some records, which must then be reclaimed.

To formalize this a bit more, there are 3 separate "root slot" numbers.
These advance asynchronously: first consensus, then system, then
progcache.

- consensus root: advances when the consensus layer finalizes a fork
- system root: advances when all tiles have logically acknowledged the
  new root slot.  Logical ACK occurs when a tile understands that no
  more operations on conflicting forks are possible.  This happens
  instantaneously implicitly almost always, except when a long fork is
  invalidated.
- progcache root: advances when all root-related reclamations are done

### Revisions

Program cache record revisions work quite differently from account
revisions.

Each program (identified by the SVM address) has multiple account
revisions.  Minimally, two: when the program did not exist, and when
the program was first deployed.

Epoch boundaries may introduce breaking virtual machine changes via
feature activations.  For example, a feature could do small changes to
the program loader, resulting in a different read-only image for the
same program executable.

Thus, the cache maintains distinct program cache records before and
after an epoch boundary, even if they refer to the same same program
account revision.

Future versions of Firedancer could relax this mechanism by only
reloading programs if the program content actually changed.

On query, selecting the wanted revision of a record is thus rather non-
trivial.  Each record access considers the following slot numbers:

- **load_slot**: the current slot number at the time the cache is being
  accessed
- **epoch_slot0**: the first slot of the epoch of load_slot
- **deploy_slot**: the most recent slot in which the program was
  deployed or retracted, as of load_slot
- **revision_slot**: derived from the above three (`>=deploy_slot`,
  `>=epoch_slot0`)

### Record life cycle

Records roughly have the following states:
- hidden: resources allocated, but invisible (cannot be referenced by
  any thread)
- published: owned by a fork, visible to users
- rooted: finalized by consensus (not owned by a fork), visible

### Record lookup

All revisions of a program are stored in the same hash map bucket.
Thus, looking up records is just a matter of walking all records in a
hash bucket (chain) and selecting the best one.

### Record deletion

Records to be deleted are immediately removed from the record map.
The thread doing the deletion spins on the rwlock to wait for all
readers to disappear.  Once all readers are gone, it also reclaims
(frees) the record's data allocation.

The record descriptor itself is reclaimed according to these rules:
- Records that are part of a transaction defer reclamation to rooting/
  cancellation (replay tile)
- Records that are already rooted are immediately reclaimed

### Cache replacement policy

Progcache uses the CLOCK cache replacement policy over hash map buckets.
Any thread that inserts records also runs cache replacement.

## Details

### Concurrency

Progcache uses reader-writer spinlocks heavily (read operations require
atomic CAS) for sequencing concurrent accesses and ref-counting based
reclamation.  This is a deliberately prude design and currently
preferable over designs like QSBR.

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

Progcache currently uses the general-purpose fd_wksp (large objects)
and fd_alloc (tiny objects) allocators.  On OOM (failure to allocate a
new object), the cache replacement algorithm does random evictions with
a heuristic.

It is a desirable future improvement to harmonize the allocator with
the cache replacement algorithm (e.g. by making the latter sizeclass
aware, or by supporting heap compaction).

## Verification

Progcache is a complex component:
- Uses a general-purpose heap allocator (use-after-free risk)
- Thread-concurrent with complex locking rules (deadlock risk)
- Maintains a multi-versioned index (algorithmic complexity)
- Does cache eviction (use-after-free risk, correctness risk)

----------------

To address these risks, we use various dynamic analysis tooling:

### AddressSanitizer

Compiler tool for detecting invalid memory accesses.

Uses compile-time instrumentation which is a mix of automatic
hooks inserted by the compiler and `asan_poison` calls in our
code.

### Valgrind memcheck

External tool for detecting invalid memory accesses.

Uses a mix of automatic dynamic hooks inserted into libc and
custom instrumentation in our code.

### ThreadSanitizer

Compiler tool for detecting data races.  Integrates with
progcache's use of C11 stdatomic.

### fd_progcache_verify

Algorithm for verifying data structure integrity issues
(leaked ref counts, index aliasing, linked list cycles, etc).

----------------

These are then run over the following test harnesses.

### test_progcache

Contains various unit and regression tests (ASan, MSan, Valgrind instrumented).

----------------
