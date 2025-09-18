# Firedancer Account Database

This document is an all-in-one overview of Firedancer's account database
**"fd_accdb"**.  fd_accdb is purpose-built from scratch to solve account
storage on SVM blockchain validators (mostly targeting Solana mainnet).

## Overview

### Requirements

**Data Set**

Each Firedancer validator keeps around a full copy of the Solana account
database.

As of September 2025, Solana mainnet has about 1 billion accounts
totalling ~300 GiB raw data size.  The vast majority of accounts is
small (less than 500 bytes).  Accounts are up to about 10 MiB large.
Accounts rarely change in size (either by delete/recreate pattern or by
size increments in the order of ~10 KiB).

**Indexing**

Accounts are keyed by a 32 byte address.  fd_accdb has a single primary
index that serves queries by account address.  There are no secondary
indices.

**Access Patterns**

On cold start (on a machine with no existing database), Firedancer loads
all accounts from a compressed snapshot.  Doing this initial database
load as fast as possible is important for individual validator uptime
(downtime is costly for operators) and global network robustness (mass
restart case).

During normal operation, access frequencies of accounts resembles a
power law distribution.  A very large amount of accounts are
written and read once, and then very rarely ever accessed again.

Worst case state size and access bandwidth requirements are
theoretically unbounded in the degraded case (e.g. consensus failure,
multiple transoceanic link outages).  fd_accdb should be able to exploit
all available I/O bandwidth in the worst case.

Record latency requirements are quite relaxed: Completing a record
read/write in 100 us is considered good enough for Solana mainnet.

**Multi-versioning**

Solana is an eventually-consistent blockchain system.  fd_accdb must
track multiple revisions of accounts, and switch between different
revisions quickly.

Changes to accounts are committed in batches.  I.e., each database
transaction introduces a subset of account revisions to the system.

There exists a directed graph/'family tree' of transactions, as
transactions inherit changes from another (the "fork graph").  Each path
in this graph expresses a particular lineage of history of accounts.

Solana's consensus algorithm attempts to converge all machines in the
system on one path in this graph, such that all machines eventually
agree on the exact historical developments of all accounts.  Once global
agreement is reached, that database transaction is declared "finalized"
or "rooted".

Under typical conditions, the fork graph is a single deep path (~33
database transactions deep).  There exist ephemeral branches in this
graph, typically only a few, but ~thousands in the event of a serious
global network degradation.

The fork graph has exactly one "root" (the latest finalized dataabase
transaction).  There is no point in keeping around older finalized
database transactions.

**Durability**

fd_accdb must be able to shutdown and startup fast with minimal data
loss (e.g. planned individual validator restart/outage).  fd_accdb
should further be able to recover from a crash (power loss).  Data
corruption is unacceptable.  Data loss is acceptable under specific
conditions (the database may revert to a prior point in time, but must
reproduce the state of an arbitrary previously rooted database
transaction exactly).

The amount of data that may be reverted should be limited to a few
minutes worth of real-time network progress.  This is because recent
account data can be recovered from the peer-to-peer network trivially
and safely.  Past ~30 minutes of downtime, a full database rebuilt might
be necessary.  (Recent Solana block data is replicated globally across
tens of thousands of machines and is cheap to fetch.  Account state is
then derived from that block data.)

**Concurrency**

Firedancer does account database accesses from various threads and
processes on the system.

At a high-level, scheduling logic in the replay and pack tiles avoids
most all forms of conflicting accesses to database records (concurrent
reads and writes to different account revisions are fine).  Therefore,
fd_accdb takes a **trust-but-verify** approach: fd_accdb interactions
assume non-conflicting accesses to keep logic simple.  But if such a
conflict does occur to a bug, the app is terminated.

## Components

The Firedancer account database is composed of two separate storage
layers: **fd_funk** and **fd_vinyl**.

In short:
- Vinyl (disk DB) stores rooted account revisions on disk and in a
  memory cache
- Funk (fork cache) manages non-rooted account revisions in memory
- Vinyl (disk DB) cannot concurrently track multiple versions of
  accounts, nor does it have database transactions
- Funk (fork cache) cannot persist to disk

New account revisions get born in funk, eventually migrate to vinyl as
they are rooted, and then eventually get garbage collected once
obsolete.

## Funk

### Funk data structures

Funk exists entirely in pinned memory (DRAM huge page backed workspace).

There exist the following data structures:

- `funk_val` generic heap allocator for storing account data (backed by
  `fd_alloc`)
- `funk_txn` object pool, one object per database transaction
- `funk_txn_map` hash map for identifying database transactions by "XID"
- `funk_rec` object pool, one object per account revision
- `funk_rec` linked lists joining together records owned by the same txn
- `funk_rec_map` giant separately chained hashmap indexing all account
  revisions by account address (hash chains ordered newest-to-oldest)

Further, there exist accdb-level data structures augmenting funk, mostly
to coordinate concurrent access:

- `accdb_users` session table for tracking active accdb users and
  reporting metrics

### Funk concurrency

Funk users cooperate via shared memory concurrency.

Code currently relies on the following primitives:
- TSO: messages sent by one thread should arrive in the same order
  on another thread
- 64-bit and 128-bit atomic read and compare-and-swap
- x86 MFENCE (rarely): broadcast a message to all CPUs and wait for it
  to propagate through the NOC.

There exist a non-trivial amount of rules that each user follows for
safe cooperation.  For example, two threads may not write records to the
same database transaction concurrently.

Bugs will eventually break these rules though.  Therefore, accdb aims to
reliably detect any unsafe/racy funk patterns, and terminate the app on
a rule violation.  If a rule is broken, the only permitted form of U.B.
is data corruption on read (which is inevitably followed by a hard
crash before effects of such an invalid read is written to disk/sent
out to memory).  Funk promises that race conditions do not result in
segfaults or undetected corruption.

A complete list of safe access patterns is documented further below.
An incomplete list of typical data race conditions and their defenses is
further mentioned.

### Funk transaction states

A funk transaction transitions between the following states:

**Prepare**

A transaction is in *preparation* briefly on creation.  A transaction
transitions from *prepare* to *writable* once inserted into the funk
transaction map / fork graph.

**Writable**

A transaction is *writable* if it is a leaf node (has no child nodes) in
the fork graph.

*Writable* transactions are semantically bound to one *accdb_client*
object.  This transaction permits record reads and writes from that
client.  Concurrent record read and writes to a writable transaction
from different threads are forbidden (crash the application).

A *writable* transaction transitions to *frozen* once all record writes
are done (e.g. done replaying a block).

**Frozen**

A *frozen* transaction permits record reads from any thread.  Unlike a
*writable* transaction, it is not bound to an *accdb_client*.

A *frozen* transaction transitions to *retiring* or *dead* if it is
merged into the database root (records copied to vinyl), or is
cancelled.

**Retiring**

A transaction is *retiring* while it is being merged into the database
root.  "Rooting" moves account records from funk to vinyl.  This is
problematic for database clients with in-progress reads from funk.

When a database client attempts to read from a retiring transaction, it
silently recovers from overruns, including a record being removed, or
the database transaction transitioning to *dead*.

**Dead**

Once a transaction is removed from the funk transaction map, it is
considered *dead*.  A *dead* transaction object is about to be freed and
returned to the transaction object pool.

## Vinyl

### Vinyl data structures

Take below with a grain of salt, vinyl was still in development while
this section was being written.

Vinyl consists of the following components:

- Vinyl log files: set of regular files on the file system.
  Accessed via sequential append (O_DIRECT), head truncate, and random
  read
- Vinyl in-memory database cache
- Vinyl in-memory record index

### Vinyl concurrency

Concurrent accesses to vinyl are coordinated via a central sequencer
(the `accdb` tile).

FIXME clarify how vinyl allows different consumers to declare data
dependencies between their requests.  Is there a "depends on sequence
number" metadata field, or should the dependent job just not be
enqueued until the dependency signals completion?

### Vinyl cache hierarchy

## Algorithms

All account database accesses are done through the `accdb_client` API,
no exceptions.  Each client is bound to a single thread.

There exists a specialized client object, called `accdb_manager`, who
does management-level operations, like managing funk transactions.
There may be only one such manager object.

### Account Lookup

Users look up accounts by key (account address, transaction XID).

The transaction XID identifies a particular node in the fork graph.
The lookup algorithm identifies the newest revision of the account with
that address, on the path from DB root to the selected DB transaction.

First, funk and vinyl hash maps are queried *by account address* to
narrow down candidate records.  Note that different revisions of the
same account will be part of the same hash chain.  Iterating over chains
in large hash maps incurs a lot of DRAM latency (~hundreds of cycles),
but memory bandwidth is plentiful.  Therefore, queries should be
pipelined/amortized aggressively for throughput. Possibilities include:

- batch lookups for multiple records
- parallel funk+vinyl lookups
- unrolling/inlining to expose more ILP opportunities to frontend
- optimistic queries in far upstream tiles

Candidate records include any record whose account address is matching.
The vinyl query yields none or one match.  The funk query yields
multiple matches, each match being a different database transaction.

To select the best candidate, we pick the record whose database
transaction has the highest priority.  Priority rules are as follows:

- A vinyl match has the lowest priority
- Funk txn XIDs that are not on the current fork/path (from root to
  XID provided with query) are ignored
- For funk txn XIDs that are on the current fork/path, the newest one
  wins

Identifying whether a funk txn XID is part of the selected fork
unfortunately requires pointer chasing, as the list of txn XIDs in the
current fork requires a tree path traversal.  The same fork is queried
~tens of thousand of times, therefore the fork's XID set is cached for
performance.

See [funk record index race](#funk-record-index-race) for how funk
recovers from data races when doing hash map accesses.  Note that the
vinyl index is not susceptible to data races because accesses are
sequenced and delegated to a single thread (accdb tile).

### Funk Record Read

This algorithms runs when the "account lookup" algorithm selected a funk
record, the funk transaction is *writable* or *frozen*, and the user
requested a read.

Each slot in the funk record pool has a sequence number.  This sequence
number increments any time a write is started or completed.  The number
increments even as the record is freed and recreated.  `seq%2 == 1`
implies that a write might currently be inflight.

It is generally assumed that any particular funk record is not written
to while there could be concurrent read accesses.  This assumption is
checked using the above sequence number mechanism.  To avoid noisy NOC
traffic, readers do not write to record memory (e.g. readlock acquire).

However, a funk record may get deleted while there are concurrent read
accesses.  This happens specifically for **retiring** transactions.  If
a transaction is retiring, the [funk record read (retiring)](#funk-record-read-retiring) algorithm is used instead.

A read operation occurs in 4 phases:

1. Sequence number read: Peek record sequence number, crash if a write
   is inflight or record is not valid
2. Read: Speculatively process, expecting there to not be a concurrent
   reader.
3. Overrun check: If the sequence number changed or the record got
   deleted after the read, crash the application
4. Commit: If the overrun check passed, commit results of speculative
   processing

### Funk Record Read (Retiring)

This algorithm is a fault-tolerant variant of the above.  It is used
when reading an account record owned by a transaction in *retiring*
state.

This algorithm may either produce a complete local copy of a funk record
or instruct the user to fetch the account from vinyl instead.

The fault-tolerant account read procedure is as follows:

1. Sequence number read: Peek record sequence number, crash if a write
   is inflight or record is not valid
2. Read/copy: Copy to local buffer
3. Overrun check:
   - If the record was removed due to evict, bail and instruct caller
     to query from vinyl
   - If the record was updated in any other way, crash the application

### Funk Record Read-Write

Updating funk records includes the following pieces of work:

- acquire a buffer suitable to store the write
- do the actual read/write
- ensure the record is part of the transaction's record linked list
- do all of the above such that data races are detected reliably and
  cheaply

The funk record process is similar:

1. Transaction prepare: Peek linked list tail of target DB transaction,
   remember for CAS in step 8
2. Sequence number read: Peek sequence number, crash if another write is
   inflight, remember for CAS in steps 3 and 7
3. Sequence number lock: Compare-and-swap `seq` with `seq+1`, crash if
   CAS fails
4. Allocate (optional): If a new funk record buffer is needed (e.g.
   existing buffer too small, or new record), allocate a new buf from
   the `funk_val` heap, and copy over existing data
5. Write: Do read or write in-place in buffer
6. Commit: If applicable, emplace new funk record buf, free old buf
7. Sequence number unlock: Compare-and-swap `seq+1` with `seq+2`, crash
   if CAS fails
8. Transaction commit: Compare-and-swap linked list tail of target DB
   transaction, crash if CAS fails

This sequence deliberately does not prevent forbidden concurrent access,
but just detects it.  For more information see
[funk record value race](#funk-record-value-race) below.

### Funk Transaction Create

To create a new funk transaction


### Funk Transaction Complete

### Funk Transaction Cancel

### Funk Transaction Rooting

## Concurrency

Various Firedancer threads may concurrently do fd_accdb read and write
accesses.

### Funk record index race



### Funk record value race

Note that the above procedure can result an unsafe concurrent reader to
encounter a `funk_val` heap/wksp use-after-free.  This is considered
acceptable, as the application is guaranteed to crash once the read is
complete, before any results are exposed to the rest of the system. The
`funk_val` workspace also does not contain any sensitive data.

### Funk record-transaction merge race



### Funk record-transaction cancel race


### Funk-to-vinyl race

### Funk transaction-transaction races

### Vinyl read-write race

### Vinyl write-write race
