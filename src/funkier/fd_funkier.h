#ifndef HEADER_fd_src_funk_fd_funkier_h
#define HEADER_fd_src_funk_fd_funkier_h

/* Funk is a hybrid of a database and version control system designed
   for ultra high performance blockchain applications.

   The data model is a flat table of records.  A record is a xid/key-val
   pair and records are fast O(1) indexable by their xid/key.  xid is
   short for "transaction id" and xids have a compile time fixed size
   (e.g. 16 bytes).  keys also have a compile time fixed size (e.g.
   40 bytes).  Record values can vary in length from zero to a compile
   time maximum size.  The xid of all zeros is reserved for the "root"
   transaction described below.  Outside this, there are no
   restrictions on what a record xid, key or val can be.  Individual
   records can be created, updated, and deleted arbitrarily.  They are
   just binary data as far as funk is concerned.

   The maximum number of records is practically only limited by the size
   of the workspace memory backing it.  At present, each record requires
   128 bytes of metadata (this includes records that are published and
   records that are in the process of being updated).  In other words,
   about 13 GiB record metadata per hundred million records.  The
   maximum number of records that can be held by a funk instance is set
   when that it was created (given the persistent and relocatable
   properties described below though, it is straightforward to resize
   this).

   The transaction model is richer than what is found in a regular
   database.  A transaction is a xid-"updates to parent transaction"
   pair and transactions are fast O(1) indexable by xid.  There is no
   limitation on the number of updates in a transaction.  Updates to the
   record value are represented as the complete value record to make it
   trivial to apply cryptographic operations like hashing to all updated
   values in a transaction with file I/O, operating system calls, memory
   data marshalling overhead, etc.

   Like records, the maximum number of transactions in preparation is
   practically only limited by the size of the workspace memory backing
   it.  At present, a transaction requires 96 bytes of memory.  As such,
   it is practical to track a large number of forks during an extended
   period of time of consensus failure in a block chain application
   without using much workspace memory at all.  The maximum number of
   transactions that can be in preparation at any given time by a funk
   instance is set when that it was created (as before, given the
   persistent and relocatable properties described below, it is
   straightforward to resize this).

   That is, a transaction is a compact representation of the entire
   history of _all_ the database records up to that transaction.  We can
   trace a transaction's ancestors back to the "root" give the complete
   history of all database records up to that transaction.  The “root”
   transaction is the ancestor of all transactions.  The transaction
   history is linear from the root transaction until the "last
   published" transaction and cannot be modified.

   To start "preparing" a new transaction, we pick the new transaction's
   xid (ideally unique among all transactions thus far) and fork off a
   "parent" transaction.  This operation virtually clones all database
   records in the parent transaction, even if the parent itself has not
   yet been "published".  Given the above, the parent transaction can be
   the last published transaction or another in-preparation transaction.

   Record inserts, reads, removes take place within the context
   of a transaction, effectively isolating them to a private view of the
   world.  If a transaction is "cancelled", the changes to a record are
   harmlessly discarded.  Records in a transaction that has children
   cannot be changed ("frozen").

   As such, it is not possible to modify the records in transactions
   strictly before the last published transaction.  However, it is
   possible to modify the records of the last published transaction if
   there is no transactions in preparation.  This is useful, for
   example, loading up a transaction from a checkpointed state on
   startup.  A common idiom at start of a block though is to fork the
   potential transaction of that block from its parent (freezing its
   parent) and then fork a child of the potential transaction that will
   hold updates to the block that are incrementally "merged" into the
   potential transaction as block processing progresses.

   Critically, in-preparation transactions form a tree of dependent and
   competing histories.  This model matches blockchains, where
   speculative work can proceed on several blocks at once long before
   the blocks are finalized.  When a transaction is published, all its
   ancestors are also published, any competing histories are
   cancelled, leaving only a linear history up to the published
   transaction.  There is no practical limitation on the complexity of
   this tree.

   Under the hood, the database state is stored in NUMA and TLB
   optimized shared memory (i.e. fd_wksp) such that various database
   operations can be used concurrently by multiple threads distributed
   arbitrarily over multiple processes zero copy.

   Database operations are at algorithmic minimums with reasonably high
   performance implementations.  Most are fast O(1) time and all are
   small O(1) space (e.g. in complex transaction tree operations, there
   is no use of dynamic allocation to hold temporaries and no use of
   recursion to bound stack utilization at trivial levels).  Further,
   there are no explicit operating system calls and, given a well
   optimized workspace (i.e. the wksp pages fit within a core's TLBs) no
   implicit operating system calls.  Critical operations (e.g. those
   that actually might impact transaction history) are fortified against
   memory corruption (e.g. robust against DoS attack by corrupting
   transaction metadata to create loops in transaction trees or going
   out of bounds in memory).  Outside of record values, all memory used
   is preallocated.  And record values are O(1) lockfree concurrent
   allocated via fd_alloc using the same wksp as funk (the
   implementation is structured in layers that are straightforward to
   retarget for particular applications as might be necessary).

   The shared memory used by a funk instance is within a workspace such
   that it is also persistent and remotely inspectable.  For example, a
   process attached to a funk instance can be terminated and a new
   process can resume exactly where the original process left off
   instantly (e.g. no file I/O).  Or a real-time monitor could be
   visualizing the ongoing activity in a database non-invasively (e.g.
   forks in flight, records updated by forks, etc).  Or an auxiliary
   process could be lazily and non-invasively writing all published
   records to permanent storage in the background in parallel with
   on-going operations.

   The records are further stored in the workspace memory relocatably.
   For example, workspace memory could just be committed to a persistent
   memory as is (or backed by NVMe or such directly), copied to a
   different host, and processes on the new host could resume (indeed,
   though it wouldn't be space efficient, the shared memory region is
   usable as is as an on-disk checkpoint file).  Or the workspace could
   be resized and what not to handle large needs than when the database
   was initially created and it all "just works".

   Limited concurrent (multithreaded) access is supported. As a
   general rule, transaction level operations
   (e.g. fd_funkier_txn_cancel and fd_funkier_txn_publish) have to be
   single-threaded. In this case, no other access is allowed at the
   same time. Purely record level operations are thread safe and can
   be arbitrarily interleaved across multiple cpus. Specifically,
   these are:
     fd_funkier_rec_query_try
     fd_funkier_rec_query_test
     fd_funkier_rec_query_try_global
     fd_funkier_rec_prepare
     fd_funkier_rec_publish
     fd_funkier_rec_cancel
     fd_funkier_rec_remove
*/

//#include "fd_funkier_base.h" /* Includes ../util/fd_util.h */
//#include "fd_funkier_txn.h"  /* Includes fd_funkier_base.h */
//#include "fd_funkier_rec.h"  /* Includes fd_funkier_txn.h */
#include "fd_funkier_val.h"    /* Includes fd_funkier_rec.h */

/* FD_FUNKIER_ALIGN describe the alignment needed
   for a funk.  ALIGN should be a positive integer power of 2.
   The footprint is dynamic depending on map sizes. */

#define FD_FUNKIER_ALIGN     (4096UL)

/* The details of a fd_funkier_private are exposed here to facilitate
   inlining various operations. */

#define FD_FUNKIER_MAGIC (0xf17eda2ce7fc2c02UL) /* firedancer funk version 2 */

struct __attribute__((aligned(FD_FUNKIER_ALIGN))) fd_funkier_private {

  /* Metadata */

  ulong magic;      /* ==FD_FUNKIER_MAGIC */
  ulong funk_gaddr; /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong wksp_tag;   /* Tag to use for wksp allocations, positive */
  ulong seed;       /* Seed for various hashing function used under the hood, arbitrary */
  ulong cycle_tag;  /* Next cycle_tag to use, used internally for various data integrity checks */

  /* The funk transaction map stores the details about transactions
     in preparation and their relationships to each other.  This is a
     fd_map_para/fd_pool_para and more details are given in fd_funkier_txn.h

     txn_max is the maximum number of transactions that can be in
     preparation.  Due to the use of compressed map indices to reduce
     workspace memory footprint required, txn_max is at most
     FD_FUNKIER_TXN_IDX_NULL (currently ~4B).  This should be more than
     ample for anticipated uses cases ... e.g. every single validator in
     a pool of tens of thousands Solana validator had its own fork and
     with no consensus ever being achieved, a funk with txn_max at the
     limits of a compressed index will be chug along for days to weeks
     before running out of indexing space.  But if ever needing to
     support more, it is straightforward to change the code to not use
     index compression.  Then, a funk (with a planet sized workspace
     backing it) would survive a similar scenario for millions of years.
     Presumably, if such a situation arose, in the weeks to eons while
     there was consensus, somebody would notice and care enough to
     intervene (if not it is probably irrelevant to the real world
     anyway).

     txn_map_gaddr is the wksp gaddr of the fd_funkier_txn_map_t used by
     this funk.

     child_{head,tail}_cidx are compressed txn map indices.  After
     decompression, they give the txn map index of the {oldest,youngest}
     child of funk (i.e. an in-preparation transaction whose parent
     transaction id is last_publish).  FD_FUNKIER_TXN_IDX_NULL indicates
     the funk is childless.  Thus, if head/tail is FD_FUNKIER_TXN_IDX_NULL,
     tail/head will be too. funk is "frozen" if it has children.

     last_publish is the ID of the last published transaction.  It will
     be the root transaction if no transactions have been published.
     Will be the root transaction immediately after construction. */

  ulong txn_max;         /* In [0,FD_FUNKIER_TXN_IDX_NULL] */
  ulong txn_map_gaddr;   /* Non-zero wksp gaddr with tag wksp_tag
                            seed   ==fd_funkier_txn_map_seed   (txn_map)
                            txn_max==fd_funkier_txn_map_key_max(txn_map) */
  ulong txn_pool_gaddr;
  ulong txn_ele_gaddr;

  uint  child_head_cidx; /* After decompression, in [0,txn_max) or FD_FUNKIER_TXN_IDX_NULL, FD_FUNKIER_TXN_IDX_NULL if txn_max 0 */
  uint  child_tail_cidx; /* " */

  /* Padding to FD_FUNKIER_TXN_XID_ALIGN here */

  fd_funkier_txn_xid_t root[1];         /* Always equal to the root transaction */
  fd_funkier_txn_xid_t last_publish[1]; /* Root transaction immediately after construction, not root thereafter */

  /* The funk record map stores the details about all the records in
     the funk, including all those in the last published transaction and
     all those getting updated in an in-preparation translation.  This
     is a fd_map_para/fd_pool_para and more details are given in fd_funkier_rec.h

     rec_max is the maximum number of records that can exist in this
     funk.

     rec_map_gaddr is the wksp gaddr of the fd_funkier_rec_map_t used by
     this funk. */

  ulong rec_max;
  ulong rec_map_gaddr; /* Non-zero wksp gaddr with tag wksp_tag
                          seed   ==fd_funkier_rec_map_seed   (rec_map)
                          rec_max==fd_funkier_rec_map_key_max(rec_map) */
  ulong rec_pool_gaddr;
  ulong rec_ele_gaddr;
  ulong rec_head_idx;  /* Record map index of the first record, FD_FUNKIER_REC_IDX_NULL if none (from oldest to youngest) */
  ulong rec_tail_idx;  /* "                       last          " */

  /* The funk alloc is used for allocating wksp resources for record
     values.  This is a fd_alloc and more details are given in
     fd_funkier_val.h.  Allocations from this allocator will be tagged with
     wksp_tag and operations on this allocator will use concurrency
     group 0.

     TODO: Consider letting user just pass a join of alloc (and maybe
     the cgroup_idx to give the funk), inferring the wksp, cgroup from
     that and allocating exclusively from that? */

  ulong alloc_gaddr; /* Non-zero wksp gaddr with tag wksp tag */

  /* Padding to FD_FUNKIER_ALIGN here */
};

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_funkier_align return FD_FUNKIER_ALIGN. */

FD_FN_CONST ulong
fd_funkier_align( void );

/* fd_funkier_footprint returns the size need for funk and all
   auxiliary data structures. Note that only record valus are
   allocated dynamically. */

FD_FN_CONST ulong
fd_funkier_footprint( ulong txn_max,
                      ulong rec_max );

/* fd_wksp_new formats an unused wksp allocation with the appropriate
   alignment and footprint as a funk.  Caller is not joined on return.
   Returns shmem on success and NULL on failure (shmem NULL, shmem
   misaligned, zero wksp_tag, shmem is not backed by a wksp ...  logs
   details).  A workspace can be used by multiple funks concurrently.
   They will dynamically share the underlying workspace (along with any
   other non-funk usage) but will otherwise act as completely separate
   non-conflicting funks.  To help with various diagnostics, garbage
   collection and what not, all allocations to the underlying wksp are
   tagged with the given tag (positive).  Ideally, the tag used here
   should be distinct from all other tags used by this workspace but
   this is not required. */

void *
fd_funkier_new( void * shmem,
                ulong  wksp_tag,
                ulong  seed,
                ulong  txn_max,
                ulong  rec_max );

/* fd_funkier_join joins the caller to a funk instance.  shfunk points to
   the first byte of the memory region backing the funk in the caller's
   address space.  Returns an opaque handle of the join on success
   (IMPORTANT! DO NOT ASSUME THIS IS A CAST OF SHFUNK) and NULL on
   failure (NULL shfunk, misaligned shfunk, shfunk is not backed by a
   wksp, bad magic, ... logs details).  Every successful join should
   have a matching leave.  The lifetime of the join is until the
   matching leave or the thread group is terminated (joins are local to
   a thread group). */

fd_funkier_t *
fd_funkier_join( void * shfunk );

/* fd_funkier_leave leaves an existing join.  Returns the underlying
   shfunk (IMPORTANT! DO NOT ASSUME THIS IS A CAST OF FUNK) on success
   and NULL on failure.  Reasons for failure include funk is NULL (logs
   details). */

void *
fd_funkier_leave( fd_funkier_t * funk );

/* fd_funkier_delete unformats a wksp allocation used as a funk
   (additionally frees all wksp allocations used by that funk).  Assumes
   nobody is or will be joined to the funk.  Returns shmem on success
   and NULL on failure (logs details).  Reasons for failure include
   shfunk is NULL, misaligned shfunk, shfunk is not backed by a
   workspace, etc. */

void *
fd_funkier_delete( void * shfunk );

/* Accessors */

/* fd_funkier_wksp returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

FD_FN_PURE static inline fd_wksp_t * fd_funkier_wksp( fd_funkier_t * funk ) { return (fd_wksp_t *)(((ulong)funk) - funk->funk_gaddr); }

/* fd_funkier_wksp_tag returns the workspace allocation tag used by the
   funk for its wksp allocations.  Will be positive.  Assumes funk is a
   current local join. */

FD_FN_PURE static inline ulong fd_funkier_wksp_tag( fd_funkier_t * funk ) { return funk->wksp_tag; }

/* fd_funkier_seed returns the hash seed used by the funk for various hash
   functions.  Arbitrary value.  Assumes funk is a current local join.
   TODO: consider renaming hash_seed? */

FD_FN_PURE static inline ulong fd_funkier_seed( fd_funkier_t * funk ) { return funk->seed; }

/* fd_funkier_txn_max returns maximum number of in-preparations the funk
   can support.  Assumes funk is a current local join.  Return in
   [0,FD_FUNKIER_TXN_IDX_NULL]. */

FD_FN_PURE static inline ulong fd_funkier_txn_max( fd_funkier_t * funk ) { return funk->txn_max; }

/* fd_funkier_txn_map returns the funk's transaction map join. This
   join can copied by value and is generally stored as a stack variable. */

static inline fd_funkier_txn_map_t
fd_funkier_txn_map( fd_funkier_t * funk,       /* Assumes current local join */
                    fd_wksp_t * wksp ) {       /* Assumes wksp == fd_funkier_wksp( funk ) */
  fd_funkier_txn_map_t join;
  fd_funkier_txn_map_join(
    &join,
    fd_wksp_laddr_fast( wksp, funk->txn_map_gaddr ),
    fd_wksp_laddr_fast( wksp, funk->txn_ele_gaddr ),
    funk->txn_max );
  return join;
}

/* fd_funkier_txn_pool returns the funk's transaction pool join. This
   join can copied by value and is generally stored as a stack variable. */

static inline fd_funkier_txn_pool_t
fd_funkier_txn_pool( fd_funkier_t * funk,    /* Assumes current local join */
                     fd_wksp_t * wksp ) {    /* Assumes wksp == fd_funkier_wksp( funk ) */
  fd_funkier_txn_pool_t join;
  fd_funkier_txn_pool_join(
    &join,
    fd_wksp_laddr_fast( wksp, funk->txn_pool_gaddr ),
    fd_wksp_laddr_fast( wksp, funk->txn_ele_gaddr ),
    funk->txn_max );
  return join;
}

/* fd_funkier_last_publish_child_{head,tail} returns a pointer in the
   caller's address space to {oldest,young} transaction child of root, NULL if
   funk is childless.  All pointers are in the caller's address space.
   These are all a fast O(1) but not fortified against memory data
   corruption. */

FD_FN_PURE static inline fd_funkier_txn_t *
fd_funkier_last_publish_child_head( fd_funkier_t *          funk,
                                    fd_funkier_txn_pool_t * pool ) {
  ulong idx = fd_funkier_txn_idx( funk->child_head_cidx );
  if( fd_funkier_txn_idx_is_null( idx ) ) return NULL; /* TODO: Consider branchless? */
  return pool->ele + idx;
}

FD_FN_PURE static inline fd_funkier_txn_t *
fd_funkier_last_publish_child_tail( fd_funkier_t *          funk,
                                    fd_funkier_txn_pool_t * pool ) {
  ulong idx = fd_funkier_txn_idx( funk->child_tail_cidx );
  if( fd_funkier_txn_idx_is_null( idx ) ) return NULL; /* TODO: Consider branchless? */
  return pool->ele + idx;
}

/* fd_funkier_root returns a pointer in the caller's address space to the
   transaction id of the root transaction.  Assumes funk is a current
   local join.  Lifetime of the returned pointer is the lifetime of the
   current local join.  The value at this pointer will always be the
   root transaction id. */

FD_FN_CONST static inline fd_funkier_txn_xid_t const * fd_funkier_root( fd_funkier_t * funk ) { return funk->root; }

/* fd_funkier_last_publish returns a pointer in the caller's address space
   to transaction id of the last published transaction.  Assumes funk is
   a current local join.  Lifetime of the returned pointer is the
   lifetime of the current local join.  The value at this pointer will
   be constant until the next transaction is published. */

FD_FN_CONST static inline fd_funkier_txn_xid_t const * fd_funkier_last_publish( fd_funkier_t * funk ) { return funk->last_publish; }

/* fd_funkier_is_frozen returns 1 if the records of the last published
   transaction are frozen (i.e. the funk has children) and 0 otherwise
   (i.e. the funk is childless).  Assumes funk is a current local join. */

FD_FN_PURE static inline int
fd_funkier_last_publish_is_frozen( fd_funkier_t const * funk ) {
  return fd_funkier_txn_idx( funk->child_head_cidx )!=FD_FUNKIER_TXN_IDX_NULL;
}

/* fd_funkier_rec_max returns maximum number of records that can be held
   in the funk.  This includes both records of the last published
   transaction and records for transactions that are in-flight. */

FD_FN_PURE static inline ulong fd_funkier_rec_max( fd_funkier_t * funk ) { return funk->rec_max; }

/* fd_funkier_rec_map returns the funk's record map join. This
   join can copied by value and is generally stored as a stack variable. */

static inline fd_funkier_rec_map_t
fd_funkier_rec_map( fd_funkier_t * funk,    /* Assumes current local join */
                    fd_wksp_t * wksp ) {    /* Assumes wksp == fd_funkier_wksp( funk ) */
  fd_funkier_rec_map_t join;
  fd_funkier_rec_map_join(
    &join,
    fd_wksp_laddr_fast( wksp, funk->rec_map_gaddr ),
    fd_wksp_laddr_fast( wksp, funk->rec_ele_gaddr ),
    funk->rec_max );
  return join;
}

/* fd_funkier_rec_pool returns the funk's record pool join. This
   join can copied by value and is generally stored as a stack variable. */

static inline fd_funkier_rec_pool_t
fd_funkier_rec_pool( fd_funkier_t * funk,    /* Assumes current local join */
                     fd_wksp_t * wksp ) {    /* Assumes wksp == fd_funkier_wksp( funk ) */
  fd_funkier_rec_pool_t join;
  fd_funkier_rec_pool_join(
    &join,
    fd_wksp_laddr_fast( wksp, funk->rec_pool_gaddr ),
    fd_wksp_laddr_fast( wksp, funk->rec_ele_gaddr ),
    funk->rec_max );
  return join;
}

/* fd_funkier_alloc returns a pointer in the caller's address space to
   the funk's allocator. */

FD_FN_PURE static inline fd_alloc_t *     /* Lifetime is that of the local join */
fd_funkier_alloc( fd_funkier_t * funk,    /* Assumes current local join */
                  fd_wksp_t * wksp ) {    /* Assumes wksp == fd_funkier_wksp( funk ) */
  return fd_alloc_join_cgroup_hint_set( (fd_alloc_t *)fd_wksp_laddr_fast( wksp, funk->alloc_gaddr ), fd_tile_idx() );
}

/* Misc */

#ifdef FD_FUNKIER_HANDHOLDING
/* fd_funkier_verify verifies the integrity of funk.  Returns
   FD_FUNKIER_SUCCESS if funk appears to be intact and FD_FUNKIER_ERR_INVAL
   otherwise (logs details).  Assumes funk is a current local join (NULL
   returns FD_FUNKIER_ERR_INVAL and logs details.) */

int
fd_funkier_verify( fd_funkier_t * funk );
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funkier_h */
