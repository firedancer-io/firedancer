#include "fd_txncache.h"
#include "../fd_rwlock.h"
#include "../../ballet/base58/fd_base58.h"

#define SORT_NAME        sort_slot_ascend
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"


/* The number of transactions in each page.  This needs to be high
   enough to amoritze the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (16384UL)

/* Status code for an empty/available entry in one of the probed hash
   tables.  The blockcache, nonce slotcache, nonce txn cache, and nonce
   blockcache tables are linearly probed.  We generally use the max_slot
   or the slot field to stash this status code. */

#define FD_TXNCACHE_ENTRY_FREE      (ULONG_MAX)
#define FD_TXNCACHE_ENTRY_FREE_UINT (UINT_MAX)

/* Status code for an exclusively busied entry.  This means that the
   entry is in the process of being created and concurrent competing
   interests should retry until the entry is no longer in this state. */

#define FD_TXNCACHE_ENTRY_XBUSY      (ULONG_MAX-1UL)
#define FD_TXNCACHE_ENTRY_XBUSY_UINT (UINT_MAX-1UL)

/* Placeholder max_slot value for a newly created blockcache or nonce
   blockcache entry.  Will be atomically overwritten with a real value
   shortly after. */

#define FD_TXNCACHE_ENTRY_NEW      (ULONG_MAX-2UL)
#define FD_TXNCACHE_ENTRY_NEW_UINT (UINT_MAX-2UL)

struct fd_txncache_private_txn {
  ulong slot;                            /* Slot that the transaction was executed.  A transaction might be in
                                            the cache multiple times if it was executed in a different slot on
                                            different forks.  The same slot will not appear multiple times
                                            however. */
  uint  blockcache_next;                 /* Pointer to the next element in the blockcache hash chain containing
                                            this entry from the pool. */
  uchar txnhash[ FD_TXNCACHE_KEY_SIZE ]; /* The transaction hash, truncated to 20 bytes.  The hash is not always
                                            the first 20 bytes, but is 20 bytes starting at the offset value
                                            given by the containing by_blockhash entry. */
};

typedef struct fd_txncache_private_txn fd_txncache_private_txn_t;
FD_STATIC_ASSERT( sizeof(fd_txncache_private_txn_t)==32UL, txn_size );

struct fd_txncache_private_txnpage {
  ushort                    free;                                   /* The number of free txn entries in this page. */
  ushort                    _pad[ 3 ];                              /* Alignment forced padding.  Could be repurposed. */
  fd_txncache_private_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE ][ 1 ]; /* The transactions in the page. */
};

typedef struct fd_txncache_private_txnpage fd_txncache_private_txnpage_t;

FD_STATIC_ASSERT( USHORT_MAX>=FD_TXNCACHE_TXNS_PER_PAGE, bump_size_of_free_cnt );

/* A NOTE ON TXNHASH OFFSET:

   To save memory, the Agave validator decided to truncate the hash of
   transactions stored in this memory to 20 bytes rather than 32 bytes
   or 64 bytes.  The bytes used are not the first 20 as you might
   expect, but instead the first 20 starting at some random offset into
   the transaction hash (starting between 0 and len(hash)-20, a/k/a 44
   for signatures, and 12 for transaction hashes).

   In an unfortunate turn, the offset is also propagated to peers via
   snapshot responses, which only communicate the offset and the
   respective 20 bytes.  To make sure we are deduplicating incoming
   transactions correctly, we must replicate this system even though it
   would be easier to just always take the first 20 bytes.  For
   transactions that we insert into the cache ourselves, we do just
   always use a key offset of zero, so the offset is only nonzero when
   constructed form a peer snapshot. */

struct fd_txncache_private_blockcache {
  uchar  blockhash[ 32 ]; /* The actual blockhash of these transactions. */
  ulong  max_slot;        /* The max slot we have seen that contains a transaction referencing
                             this blockhash.  The blockhash entry will not be purged until the
                             lowest rooted slot is greater than this. */
  ushort pages_cnt;       /* The number of txnpages currently in use to store the transactions in
                             this blockcache. */
  ushort _pad[ 1 ];       /* Alignment forced padding.  Could be repurposed. */
  uint   heads[ ];        /* The hash table for the blockhash.  Each entry is a pointer to the
                             head of a linked list of transactions that reference this blockhash.
                             As we add transactions to the bucket, the head pointer is updated to
                             the new item, and the new item is pointed to the previous head.
                             This is a hash table of size max_txn_per_slot. */
  // Logically, there's another field here:
  // uint   pages[ ];        /* An array of the txnpages containing the transactions for this
  //                            blockcache.  Size max_txnpages_per_blockhash. */
};

typedef struct fd_txncache_private_blockcache fd_txncache_private_blockcache_t;

/* When querying a transaction, including a nonce transaction, we have
   only the blockhash and the txnhash to work with.  The txnhash is what
   ultimately uniquely identifies a transaction.  However, as described
   above, txnhash values are truncated at a non-deterministic offset in
   Agave.  In Agave, the offsets are randomly generated on a
   per-blockhash basis.  In contrast, we always use an offset of 0.  So,
   when it's not a nonce transaction loaded from an Agave snapshot, we
   know for sure that the txnhash_offset is zero.  It is then pretty
   straightforward to query the nonce txn hash table using the truncated
   txnhash starting from offset 0.  Unfortunately, when loading from an
   Agave snapshot, every nonce transaction could in theory reference a
   unique blockhash, and every unique blockhash could have a different
   txnhash_offset.  The upshot of all of this is that when nonce
   transactions loaded from an Agave snapshot are present in the
   txncache, we have two options:

   (1) Query the nonce txn hash table multiple times, each time with a
       different txnhash_offset, until either a match, or we have
       checked all possible offsets.  This is similar to how TLBs that
       support multiple page sizes work, where given a virtual address,
       the TLB is first queried assuming a 4K mapping and its
       corresponding split of the virtual address into a page offset and
       a page index, and then a 2M mapping, and so on and so forth.

   (2) Maintain a mapping from blockhash to txnhash_offset.  Query this
       mapping to obtain the txnhash_offset, and then query the nonce
       txn hash table using the properly truncated txnhash.

   Here, we implement option (2), because we need queries to be fast.
   The downsides of option (2) are that it introduces an additional
   table that consumes memory, and the table potentially needs to be
   purged.  We implement a few optimizations here.  First, we only
   insert into this table the blockhashes that are loaded from an Agave
   snapshot.  New blockhashes with our default txnhash_offset of zero
   are not inserted.  If a query into this table misses, we can simply
   assume that the txnhash_offset is zero.  This also means that
   eventually, as replay goes on and higher slots get rooted and
   transactions loaded from Agave snapshots are purged, this table will
   be completely empty.  Second, we lazily and logically purge the
   table.  Rather than actively removing entries from the table at the
   end of each slot, like we do for the blockcache and the slotcache, we
   record the max slot that references any valid entry in this table.
   As described in the first optimization, we always use a default
   offset of zero for new blockhashes and hence we never insert new
   entries into this table after snapshot loading.  Therefore, we don't
   have to actively purge anything to make space.  Moreover, when the
   lowest rooted slot exceeds the recorded max slot, the entire table is
   logically purged.  Thereafter we should not have to query this table
   ever again.

   One more note regarding snapshot loading ...

   In yet another unfortunate turn, when loading the txncache from an
   Agave snapshot, there's no easy way to tell if a transaction is a
   nonce transaction or not.  The snapshot by itself doesn't contain the
   actual transactions, only the blockhashes and the truncated txn
   hashes.  So what we do is that we assume that all transactions from
   the snapshot are nonce transactions.  This is conservative and safe,
   because the nonce txn cache has enough capacity for max txns per
   slot.  This does make querying for and inserting regular transactions
   a little more complicated for as long as the nonce blockcache is
   active.

   The following describes the scheme for managing and querying nonce
   txnhash offsets:

   On insertion of a nonce transaction not loaded from an Agave
   snapshot:
   - If lowest rooted slot is greater than the table max slot, assume
     offset is zero
   - Query this table with blockhash
   - If hit
     - If the lowest rooted slot is no greater than the blockhash max
       slot, update the blockhash max slot, as well as the table max
       slot
     - Otherwise, assume offset is zero
   - If miss, assume offset is zero

   On insertion of a nonce transaction loaded from an Agave snapshot:
   - Query this table with blockhash
   - If hit, update the blockhash max slot, as well as the table max
     slot
   - If miss, create a new entry in the table with the blockhash and
     update the table max slot

   On query of a nonce transaction:
   - If lowest rooted slot is greater than the table max slot, assume
     offset is zero
   - Query this table with blockhash
   - If hit
     - If the lowest rooted slot is no greater than the blockhash max
       slot, truncate the txnhash with the offset given by the hit
     - Otherwise, truncate the txnhash with our default offset of zero
   - If miss, truncate the txnhash with our default offset of zero

   On query of a regular transaction:
   - If lowest rooted slot is no greater than the table max slot, this
     implies that this table has not been deactivated, which in turn
     implies that there could be regular transactions in the nonce txn
     cache.  So query for this transaction as if it were a nonce
     transaction, except that if the nonce blockhash entry is expired,
     then we don't bother with querying the nonce txn cache.
   - Query this transaction in the main txn cache

   On insertion of a regular transaction:
   - If lowest rooted slot is greater than the table max slot, insert
     into the main txn cache
   - Query this table with blockhash
   - If hit
     - If the lowest rooted slot is no greater than the blockhash max
       slot, insert as if it were a nonce transaction
     - Otherwise, insert into the main txn cache
   - If miss, insert into the main txn cache
 */
struct fd_txncache_private_nonce_blockcache {
  uchar blockhash[ 32 ]; /* The actual blockhash of these transactions. */
  uint  max_slot;        /* The max slot we have seen that contains a transaction referencing
                            this blockhash.  The blockhash entry will not be purged until the
                            lowest rooted slot is greater than this. */
  uint  txnhash_offset;  /* As described above. */
};

typedef struct fd_txncache_private_nonce_blockcache fd_txncache_private_nonce_blockcache_t;
FD_STATIC_ASSERT( sizeof(fd_txncache_private_nonce_blockcache_t)==40UL, nonce_blockcache_size );

struct fd_txncache_private_nonce_txn {
  uint  slot;                            /* Slot where the transaction was executed.  A transaction might be in
                                            the cache multiple times if it was executed in a different slot on
                                            different forks.  The same slot will not appear multiple times
                                            however. */
  uint  slotcache_next;                  /* Pointer to the next element in the per-slot doubly linked list
                                            containing this entry from the nonce txn pool. */
  union {
    struct {
      uint  slotcache_prev:31;           /* Pointer to the previous element in the per-slot doubly linked list
                                            containing this entry from the nonce txn pool.  Used for updating
                                            linked lists when we reprobe the nonce txn hash table.  If this
                                            field points to the head of the linked list, it is instead an index
                                            into the nonce_slotcache array. */
      uint  slotcache_prev_is_head:1;    /* Whether the slotcache_prev field points to the head of the linked
                                            list. */
    };
    uint    slotcache_prev_val;
  };
  uchar txnhash[ FD_TXNCACHE_KEY_SIZE ]; /* The transaction hash, truncated to 20 bytes.  The hash is not
                                            always the first 20 bytes, but is 20 bytes starting at the offset
                                            given by the txnhash_offset field. */
};

typedef struct fd_txncache_private_nonce_txn fd_txncache_private_nonce_txn_t;
FD_STATIC_ASSERT( sizeof(fd_txncache_private_nonce_txn_t)==32UL, nonce_txn_size );

/* Top bit unavailable due to slotcache_prev:31 */
#define FD_TXNCACHE_NONCE_TXN_IDX_MAX       ((1U<<31)-1U)
#define FD_TXNCACHE_NONCE_TXN_CNT_MAX       ((1U<<31))
#define FD_TXNCACHE_NONCE_TXN_IDX_MASK      ((1U<<31)-1U) /* Helps suppress -Wconversion warnings... */
/* Can't fully populate all bits because UINT_MAX means NULL. */
#define FD_TXNCACHE_NONCE_SLOTCACHE_IDX_MAX ((1U<<31)-2U)
#define FD_TXNCACHE_NONCE_SLOTCACHE_CNT_MAX ((1U<<31)-1U)

struct fd_txncache_private_nonce_slotcache {
  ulong slot;           /* The slot that this nonce slotcache is for. */
  uint  nonce_slot_pop; /* The number of transactions in this slot. */
  uint  head;           /* The head of the doubly linked list of nonce txns for this slot.  As
                           we add nonce transactions to the list, the head pointer is updated to
                           the new item, and the new item is pointed to the previous head. */
};

typedef struct fd_txncache_private_nonce_slotcache fd_txncache_private_nonce_slotcache_t;

struct __attribute__((aligned(FD_TXNCACHE_ALIGN))) fd_txncache_private {
  fd_rwlock_t lock[ 1 ]; /* The txncache is a concurrent structure and will be accessed by multiple threads
                            concurrently.  Insertion and querying only take a read lock as they can be done
                            lockless but all other operations will take a write lock internally. */

  ulong magic; /* ==FD_TXNCACHE_MAGIC */

  ushort block_pop;
  ushort slot_pop;
  ushort block_pop_max;
  ushort slot_pop_max;
  uint   nonce_slot_pop_max;
  ushort _metric_pad[ 6 ];

  ulong  root_slots_max;
  ulong  nonce_blockcache_max_slot; /* This is only accessed when the nonce blockcache is still active.
                                       So initially there will be a bit of false sharing, but eventually
                                       this should be a dead field. */
  ulong  lowest_observed_slot;      /* This is only accessed towards the end of an insertion.  Immediately
                                       afterwards we unlock. */

  /* Cache line aligned. */

  ulong  nonce_blockcache_deactivated_slot_delta; /* !=ULONG_MAX when the nonce blockcache is deactivated. */
  ulong  txn_per_slot_max;
  ulong  live_slots_max;       /* A note on live slots ...

                                  The maximum number of live slots is the sum of the rooted and
                                  unrooted slots.  The rooted slots are typically capped at 300
                                  (implying we keep around 2 minutes of history around for queries and
                                  snapshots).

                                  For the unrooted slots, we must root at least one slot in an epoch
                                  for an epoch transition to occur successfully to the next one, so
                                  assuming every slot is unconfirmed for some reason, and the prior
                                  epoch was rooted at the first slot in the epoch, and the next epoch
                                  is rooted at the last slot, there could be

                                      432,000 + 432,000 - 31 = 863,969

                                  Live slots on the validator.  This is clearly impractical as each
                                  bank consumes a lof of memory to store slot state, so the validator
                                  would crash long before this. */
  uint   nonce_txns_max;
  ulong  nonce_blockcache_entries_max;
  ushort txnpages_per_blockhash_max;
  uint   txnpages_max;

  ulong  root_slots_cnt;       /* The number of root slots being tracked in the below array. */
  ulong  root_slots_off;       /* The highest N slots that have been rooted.  These slots are
                                  used to determine which transactions should be kept around to
                                  be queried and served to snapshot requests.  The actual
                                  footprint for this data (and other data below) are declared
                                  immediately following the struct.  I.e. these pointers point to
                                  memory not far after the struct. */

  ulong  blockcache_t_sz;      /* The size of each blockcache table entry. */
  ulong  blockcache_off;       /* The cache of transactions by blockhash.  This is a linear probed hash
                                  table that maps blockhashes to the transactions that reference them.
                                  The depth of the hash table is live_slots_max, since this is the
                                  maximum number of blockhashes that can be alive.  The loading factor
                                  if they were all alive would be 1.0, but this is rare because we
                                  will almost never fork repeatedly to hit this limit.  These
                                  blockcaches are just pointers to pages from the txnpages below, so
                                  they don't take up much memory. */
  ulong  txnpages_off;         /* The actual storage for the transactions.  The blockcache points to
                                  these pages when storing transactions.  Transactions are grouped into
                                  pages of size 16384 to make certain allocation and deallocation
                                  operations faster (just the pages are acquired/released, rather than
                                  each txn).  Array size is txnpages_max. */
  ulong  txnpages_free_off;    /* Array of free txnpages.  Stores indices into the txnpages array. */
  uint   txnpages_free_cnt;    /* The number of txnpages that are free.  The first this many elements
                                  in the above array are the ones that are free.*/

  ulong  nonce_slotcache_off;  /* The cache of nonce transactions by slot, so we can quickly purge
                                  nonce transactions by slot number.  This is a linearly probed hash
                                  table that maps a slot number to a doubly linked list of nonce
                                  transactions for that slot. */
  ulong  nonce_txns_off;       /* The actual storage for nonce transactions.  The nonce slotcache
                                  linked lists point to these.  Storage capacity is
                                  live_slots_max*txn_per_slot_max.  This also doubles as a hash table
                                  of nonce transactions.  The hash table is indexed by transaction hash
                                  and linearly probed.  Ideally, storage capacity can be
                                  live_slots_max*nonce_txn_per_slot_max, since nonce transactions
                                  consume a higher amount of CU than the most barebones non-nonce
                                  transaction.  Unfortunately, this storage is abused to store
                                  non-nonce transactions as well on startup, so this is sized out for
                                  that usage. */
  ulong  nonce_blockcache_off; /* The mapping of blockhashes to nonce transaction hash offsets. */
};

FD_FN_PURE static ulong *
fd_txncache_get_root_slots( fd_txncache_t const * tc ) {
  return (ulong *)( (uchar *)tc + tc->root_slots_off );
}

FD_FN_PURE static fd_txncache_private_blockcache_t *
fd_txncache_get_blockcache_at_idx( fd_txncache_t const * tc, ulong idx ) {
  return (fd_txncache_private_blockcache_t *)( (uchar *)tc + tc->blockcache_off + idx*tc->blockcache_t_sz );
}

FD_FN_PURE static uint *
fd_txncache_get_blockcache_pages( fd_txncache_t const *                    tc,
                                  fd_txncache_private_blockcache_t const * blockcache ) {
  return (uint *)( blockcache->heads + tc->txn_per_slot_max );
}

FD_FN_PURE static fd_txncache_private_nonce_txn_t *
fd_txncache_get_nonce_txns( fd_txncache_t const * tc ) {
  return (fd_txncache_private_nonce_txn_t *)( (uchar *)tc + tc->nonce_txns_off );
}

FD_FN_PURE static fd_txncache_private_nonce_blockcache_t *
fd_txncache_get_nonce_blockcache( fd_txncache_t const * tc ) {
  return (fd_txncache_private_nonce_blockcache_t *)( (uchar *)tc + tc->nonce_blockcache_off );
}

FD_FN_PURE static fd_txncache_private_nonce_slotcache_t *
fd_txncache_get_nonce_slotcache( fd_txncache_t const * tc ) {
  return (fd_txncache_private_nonce_slotcache_t *)( (uchar *)tc + tc->nonce_slotcache_off );
}

FD_FN_PURE static uint *
fd_txncache_get_txnpages_free( fd_txncache_t const * tc ) {
  return (uint *)( (uchar *)tc + tc->txnpages_free_off );
}

FD_FN_PURE static fd_txncache_private_txnpage_t *
fd_txncache_get_txnpages( fd_txncache_t const * tc ) {
  return (fd_txncache_private_txnpage_t *)( (uchar *)tc + tc->txnpages_off );
}

FD_FN_CONST static ushort
fd_txncache_max_txnpages_per_blockhash( ulong max_txn_per_slot ) {
  /* The maximum number of transaction pages we might need to store all
     the transactions that could be seen in a blockhash.

     In the worst case, every transaction in every slot refers to
     the same blockhash for as long as it is possible (150 slots
     following the slot where the blockhash is produced).  So there
     could be up to

        524,288 * 150 = 78,643,200

     Note that the blockcaches store txns for forks, and the same txn
     might appear multiple times in one block, but if there's a fork,
     the fork has to have skipped slots (had 0 txns in them), so it
     cannot cause this limit to go higher.

     Transactions referenced by a particular blockhash.
     Transactions are stored in pages of 16,384, so we might need up
     to 4,800 of these pages to store all the transactions in a
     slot. */

  ulong result = 1UL+(max_txn_per_slot*150UL-1UL)/FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST static uint
fd_txncache_max_txnpages( ulong max_live_slots,
                          ulong max_txn_per_slot ) {
  /* We need to be able to store potentially every slot that is live
     being completely full of transactions.  This would be

       max_live_slots*max_txn_per_slot

     transactions, except that we are counting pages here, not
     transactions.  It's not enough to divide by the page size, because
     pages might be wasted.  The maximum page wastage occurs when all
     the blockhashes except one have one transaction in them, and the
     remaining blockhash has all other transactions.  In that case, the
     full blockhash needs

       (max_live_slots*max_txn_per_slot)/FD_TXNCACHE_TXNS_PER_PAGE

     pages, and the other blockhashes need 1 page each. */

  ulong result = max_live_slots-1UL+(1UL+(max_live_slots*max_txn_per_slot-1UL)/FD_TXNCACHE_TXNS_PER_PAGE);
  if( FD_UNLIKELY( result>UINT_MAX ) ) return 0;

  /* Transaction index into the pages is stored in a uint. */
  ulong txn_idx_max = result * FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( txn_idx_max>UINT_MAX ) ) return 0;

  return (uint)result;
}

FD_FN_CONST ulong
fd_txncache_align( void ) {
  return FD_TXNCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_rooted_slots,
                       ulong max_live_slots,
                       ulong max_txn_per_slot ) {
  if( FD_UNLIKELY( max_rooted_slots<1UL || max_live_slots<1UL ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots<max_rooted_slots ) ) return 0UL;
  if( FD_UNLIKELY( max_txn_per_slot<1UL ) ) return 0UL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_live_slots ) ) ) return 0UL;

  /* To save memory, txnpages are referenced as uint which is enough
     to support mainnet parameters without overflow. */
  uint max_txnpages = fd_txncache_max_txnpages( max_live_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages ) ) return 0UL;

  ulong max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return 0UL;

  ulong max_nonce_txns = max_live_slots*max_txn_per_slot;
  if( FD_UNLIKELY( max_nonce_txns>FD_TXNCACHE_NONCE_TXN_CNT_MAX ) ) return 0UL;

  ulong max_nonce_blockcache_entries = max_live_slots*max_txn_per_slot;

  ulong blockcache_t_sz = fd_ulong_align_up( sizeof(fd_txncache_private_blockcache_t) + (max_txn_per_slot+max_txnpages_per_blockhash)*sizeof(uint), alignof(fd_txncache_private_blockcache_t) );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_ALIGN,                               sizeof(fd_txncache_t)                                                       );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                                  max_rooted_slots*sizeof(ulong)                                              ); /* root_slots */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_blockcache_t),       max_live_slots*blockcache_t_sz                                              ); /* blockcache */
  l = FD_LAYOUT_APPEND( l, alignof(uint),                                   max_txnpages*sizeof(uint)                                                   ); /* txnpages_free */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_txnpage_t),          max_txnpages*sizeof(fd_txncache_private_txnpage_t)                          ); /* txnpages */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_nonce_slotcache_t),  max_live_slots*sizeof(fd_txncache_private_nonce_slotcache_t)                ); /* nonce_slotcache */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_nonce_txn_t),        max_nonce_txns*sizeof(fd_txncache_private_nonce_txn_t)                      ); /* nonce_txns */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_nonce_blockcache_t), max_nonce_blockcache_entries*sizeof(fd_txncache_private_nonce_blockcache_t) ); /* nonce_blockcache */
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_ALIGN );
}

void *
fd_txncache_new( void * shmem,
                 ulong  max_rooted_slots,
                 ulong  max_live_slots,
                 ulong  max_txn_per_slot ) {
  fd_txncache_t * tc = (fd_txncache_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_rooted_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_live_slots ) ) return NULL;
  if( FD_UNLIKELY( max_live_slots<max_rooted_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_txn_per_slot ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_live_slots ) ) ) return NULL;

  uint   max_txnpages                 = fd_txncache_max_txnpages( max_live_slots, max_txn_per_slot );
  ushort max_txnpages_per_blockhash   = fd_txncache_max_txnpages_per_blockhash( max_txn_per_slot );
  ulong  max_nonce_txns               = max_live_slots*max_txn_per_slot;
  ulong  max_nonce_blockcache_entries = max_live_slots*max_txn_per_slot;

  if( FD_UNLIKELY( !max_txnpages ) ) return NULL;
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return NULL;
  if( FD_UNLIKELY( max_nonce_txns>FD_TXNCACHE_NONCE_TXN_CNT_MAX ) ) return NULL;

  ulong blockcache_t_sz = fd_ulong_align_up( sizeof(fd_txncache_private_blockcache_t) + (max_txn_per_slot+max_txnpages_per_blockhash)*sizeof(uint), alignof(fd_txncache_private_blockcache_t) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_t * txncache = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_ALIGN,                               sizeof(fd_txncache_t)                                                       );
  void * _root_slots       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                                  max_rooted_slots*sizeof(ulong)                                              );
  void * _blockcache       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_blockcache_t),       max_live_slots*blockcache_t_sz                                              );
  void * _txnpages_free    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                                   max_txnpages*sizeof(uint)                                                   );
  void * _txnpages         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_txnpage_t),          max_txnpages*sizeof(fd_txncache_private_txnpage_t)                          );
  void * _nonce_slotcache  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_nonce_slotcache_t),  max_live_slots*sizeof(fd_txncache_private_nonce_slotcache_t)                );
  void * _nonce_txns       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_nonce_txn_t),        max_nonce_txns*sizeof(fd_txncache_private_nonce_txn_t)                      );
  void * _nonce_blockcache = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_nonce_blockcache_t), max_nonce_blockcache_entries*sizeof(fd_txncache_private_nonce_blockcache_t) );
  ulong  _end              = FD_SCRATCH_ALLOC_FINI( l, FD_TXNCACHE_ALIGN );

  txncache->blockcache_t_sz = blockcache_t_sz;

  /* We calculate and store the offsets for these allocations. */
  txncache->root_slots_off        = (ulong)_root_slots - (ulong)txncache;
  txncache->blockcache_off        = (ulong)_blockcache - (ulong)txncache;
  txncache->txnpages_free_off     = (ulong)_txnpages_free - (ulong)txncache;
  txncache->txnpages_off          = (ulong)_txnpages - (ulong)txncache;
  txncache->nonce_slotcache_off   = (ulong)_nonce_slotcache - (ulong)txncache;
  txncache->nonce_txns_off        = (ulong)_nonce_txns - (ulong)txncache;
  txncache->nonce_blockcache_off  = (ulong)_nonce_blockcache - (ulong)txncache;

  ulong root_slots_size = txncache->blockcache_off-txncache->root_slots_off;
  ulong blockcache_size = txncache->txnpages_free_off-txncache->blockcache_off;
  ulong txnpages_free_size = txncache->txnpages_off-txncache->txnpages_free_off;
  ulong txnpages_size = txncache->nonce_slotcache_off-txncache->txnpages_off;
  ulong nonce_slotcache_size = txncache->nonce_txns_off-txncache->nonce_slotcache_off;
  ulong nonce_txns_size = txncache->nonce_blockcache_off-txncache->nonce_txns_off;
  ulong nonce_blockcache_size = _end-(ulong)_nonce_blockcache;
  ulong total_size = _end-(ulong)txncache;
  FD_LOG_INFO(( "txncache footprint: root_slots %lu (%lu%%), blockcache %lu (%lu%%), txnpages_free %lu (%lu%%), txnpages %lu (%lu%%), nonce_slotcache %lu (%lu%%), nonce_txns %lu (%lu%%), nonce_blockcache %lu (%lu%%), total %lu",
                root_slots_size, root_slots_size*100UL/total_size,
                blockcache_size, blockcache_size*100UL/total_size,
                txnpages_free_size, txnpages_free_size*100UL/total_size,
                txnpages_size, txnpages_size*100UL/total_size,
                nonce_slotcache_size, nonce_slotcache_size*100UL/total_size,
                nonce_txns_size, nonce_txns_size*100UL/total_size,
                nonce_blockcache_size, nonce_blockcache_size*100UL/total_size,
                total_size ));

  tc->lock->value           = 0U;
  tc->block_pop             = 0U;
  tc->slot_pop              = 0U;
  tc->block_pop_max         = 0U;
  tc->slot_pop_max          = 0U;
  tc->nonce_slot_pop_max    = 0U;
  tc->root_slots_cnt        = 0UL;

  tc->root_slots_max               = max_rooted_slots;
  tc->txn_per_slot_max             = max_txn_per_slot;
  tc->live_slots_max               = max_live_slots;
  tc->nonce_txns_max               = (uint)max_nonce_txns;
  tc->nonce_blockcache_entries_max = max_nonce_blockcache_entries;
  tc->txnpages_per_blockhash_max   = max_txnpages_per_blockhash;
  tc->txnpages_max                 = max_txnpages;

  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache_at_idx( tc, i );
    blockcache->max_slot                          = FD_TXNCACHE_ENTRY_FREE;
  }
  fd_memset( _root_slots,       0xFF, max_rooted_slots*sizeof(ulong) );
  fd_memset( _nonce_txns,       0xFF, max_nonce_txns*sizeof(fd_txncache_private_nonce_txn_t)                      );
  fd_memset( _nonce_blockcache, 0xFF, max_nonce_blockcache_entries*sizeof(fd_txncache_private_nonce_blockcache_t) );
  fd_memset( _nonce_slotcache,  0xFF, max_live_slots*sizeof(fd_txncache_private_nonce_slotcache_t)                );

  tc->nonce_blockcache_max_slot               = 0UL;
  tc->lowest_observed_slot                    = ULONG_MAX;
  tc->nonce_blockcache_deactivated_slot_delta = ULONG_MAX;

  tc->txnpages_free_cnt = max_txnpages;
  uint * txnpages_free  = _txnpages_free;
  for( uint i=0; i<max_txnpages; i++ ) txnpages_free[ i ] = i;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tc->magic ) = FD_TXNCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)tc;
}

fd_txncache_t *
fd_txncache_join( void * shtc ) {
  if( FD_UNLIKELY( !shtc ) ) {
    FD_LOG_WARNING(( "NULL shtc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtc, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtc" ));
    return NULL;
  }

  fd_txncache_t * tc = (fd_txncache_t *)shtc;

  if( FD_UNLIKELY( tc->magic!=FD_TXNCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return tc;
}

void *
fd_txncache_leave( fd_txncache_t * tc ) {
  if( FD_UNLIKELY( !tc ) ) {
    FD_LOG_WARNING(( "NULL tc" ));
    return NULL;
  }

  return (void *)tc;
}

void *
fd_txncache_delete( void * shtc ) {
  if( FD_UNLIKELY( !shtc ) ) {
    FD_LOG_WARNING(( "NULL shtc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtc, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtc" ));
    return NULL;
  }

  fd_txncache_t * tc = (fd_txncache_t *)shtc;

  if( FD_UNLIKELY( tc->magic!=FD_TXNCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tc->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)tc;
}

static void
fd_txncache_print_state( fd_txncache_t const * tc,
                         char const *          prefix ) {
  FD_LOG_INFO(( "%s: rooted %lu/%lu slots, txnpages %u/%u free, blockcache pop curr %u peak %u/%lu, nonce slotcache pop curr %u peak %u/%lu, nonce slotcache per slot pop peak %u/%lu",
                prefix,
                tc->root_slots_cnt, tc->root_slots_max,
                tc->txnpages_free_cnt, tc->txnpages_max,
                tc->block_pop, tc->block_pop_max, tc->live_slots_max,
                tc->slot_pop, tc->slot_pop_max, tc->live_slots_max,
                tc->nonce_slot_pop_max, tc->txn_per_slot_max ));
}

static void
fd_txncache_print_insert( fd_txncache_insert_t const * txn,
                          char const *                 prefix ) {

  FD_BASE58_ENCODE_32_BYTES( txn->blockhash, blockhash );
  if( txn->key_sz==32UL ) {
    FD_BASE58_ENCODE_32_BYTES( txn->txnhash, key_str );
    FD_LOG_NOTICE(( "%s: blockhash %s, slot %lu, key %s, res %u",
                    prefix,
                    blockhash,
                    txn->slot,
                    key_str,
                    *(txn->result) ));
  } else if( txn->key_sz==64UL ) {
    FD_BASE58_ENCODE_64_BYTES( txn->txnhash, key_str );
    FD_LOG_NOTICE(( "%s: blockhash %s, slot %lu, key %s, res %u",
                    prefix,
                    blockhash,
                    txn->slot,
                    key_str,
                    *(txn->result) ));
  } else {
    FD_LOG_NOTICE(( "%s: blockhash %s, slot %lu, key %s, res %u",
                    prefix,
                    blockhash,
                    txn->slot,
                    "(unsupported key length)",
                    *(txn->result) ));
  }
}

/* Assumes key is at least sizeof(ulong) in size.  Inserted keys are
   either the blockhash or the message hash (blake3) or the signature of
   a landed transaction.  These are hard to forge, so even if we simply
   take the first 8 bytes without any additional maths, the likelihood
   of an attacker crafting payloads to cause excessive slowdowns in the
   txncache is low.  Could easily add per-validator randomized maths to
   make the life of an attacker even harder. */
static inline ulong
fd_txncache_key_hash( void const * key ) {
  return FD_LOAD( ulong, key );
}

static void
fd_txncache_remove_blockcache_idx( fd_txncache_t * tc,
                                   ulong           idx ) {
  fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache_at_idx( tc, idx );
  uint * txnpages_free = fd_txncache_get_txnpages_free( tc );

  /* Remove from blockcache and make a hole at idx. */
  blockcache->max_slot = FD_TXNCACHE_ENTRY_FREE;

  /* Free pages. */
  uint * pages = fd_txncache_get_blockcache_pages( tc, blockcache );
  fd_memcpy( txnpages_free+tc->txnpages_free_cnt, pages, blockcache->pages_cnt*sizeof(uint) );
  tc->txnpages_free_cnt += blockcache->pages_cnt;

  /* Reprobe the hash table. */
  for(;;) {
    ulong hole = idx;

    for(;;) {
      idx        = (idx+1UL) & (tc->live_slots_max-1UL); /* live_slots_max is power of 2. */
      blockcache = fd_txncache_get_blockcache_at_idx( tc, idx );

      if( blockcache->max_slot==FD_TXNCACHE_ENTRY_FREE ) return;

      ulong hash  = fd_txncache_key_hash( blockcache->blockhash );
      ulong start = hash & (tc->live_slots_max-1UL);
      if( !(((hole<start) & (start<=idx)) | ((hole>idx) & ((hole<start) | (start<=idx)))) ) break;
    }

    fd_txncache_private_blockcache_t * blockcache_hole = fd_txncache_get_blockcache_at_idx( tc, hole );

    /* Move. */
    fd_memcpy( blockcache_hole, blockcache, tc->blockcache_t_sz );

    /* Make a hole at src of move. */
    blockcache->max_slot = FD_TXNCACHE_ENTRY_FREE;
  }
}

static void
fd_txncache_remove_nonce_txn_idx( fd_txncache_t * tc,
                                  uint            idx,
                                  uint *          next_idx ) {
  fd_txncache_private_nonce_txn_t * nonce_txns = fd_txncache_get_nonce_txns( tc );

  /* Repair the linked list. */
  if( FD_UNLIKELY( !nonce_txns[ idx ].slotcache_prev_is_head ) ) {
    FD_LOG_CRIT(( "invariant violation: nonce txn %u has prev %u", idx, nonce_txns[ idx ].slotcache_prev_val ));
  }
  if( FD_LIKELY( nonce_txns[ idx ].slotcache_next!=UINT_MAX ) ) {
    nonce_txns[ nonce_txns[ idx ].slotcache_next ].slotcache_prev_val = UINT_MAX;
  }

  /* Remove: make a hole at idx. */
  nonce_txns[ idx ].slot               = FD_TXNCACHE_ENTRY_FREE_UINT;
  nonce_txns[ idx ].slotcache_next     = UINT_MAX;
  nonce_txns[ idx ].slotcache_prev_val = UINT_MAX;

  /* Reprobe the hash table. */
  for(;;) {
    uint hole = idx;

    for(;;) {
      idx = (idx+1U)%tc->nonce_txns_max;

      if( nonce_txns[ idx ].slot==FD_TXNCACHE_ENTRY_FREE_UINT ) return;

      ulong key_hash = fd_txncache_key_hash( nonce_txns[ idx ].txnhash );
      ulong start = key_hash%tc->nonce_txns_max;
      if( !(((hole<start) & (start<=idx)) | ((hole>idx) & ((hole<start) | (start<=idx)))) ) break;
    }

    /* Move. */
    nonce_txns[ hole ] = nonce_txns[ idx ];

    /* Repair the linked list. */
    if( FD_LIKELY( nonce_txns[ hole ].slotcache_prev_val!=UINT_MAX ) ) {
      if( FD_UNLIKELY( nonce_txns[ hole ].slotcache_prev_is_head ) ) {
        fd_txncache_private_nonce_slotcache_t * nonce_slotcache   = fd_txncache_get_nonce_slotcache( tc );
        nonce_slotcache[ nonce_txns[ hole ].slotcache_prev ].head = hole;
      }
      if( FD_LIKELY( !nonce_txns[ hole ].slotcache_prev_is_head ) ) {
        nonce_txns[ nonce_txns[ hole ].slotcache_prev ].slotcache_next = hole;
      }
    }
    if( FD_LIKELY( nonce_txns[ hole ].slotcache_next!=UINT_MAX ) ) {
      if( FD_UNLIKELY( nonce_txns[ nonce_txns[ hole ].slotcache_next ].slotcache_prev_is_head ) ) {
        FD_LOG_CRIT(( "invariant violation: nonce txn %u (moved from %u) has next %u with prev %u being head prev_val 0x%x", hole, idx, nonce_txns[ hole ].slotcache_next, (uint)nonce_txns[ nonce_txns[ hole ].slotcache_next ].slotcache_prev, nonce_txns[ nonce_txns[ hole ].slotcache_next ].slotcache_prev_val ));
      }
      nonce_txns[ nonce_txns[ hole ].slotcache_next ].slotcache_prev = hole&FD_TXNCACHE_NONCE_TXN_IDX_MASK;
    }
    if( FD_UNLIKELY( *next_idx==idx ) ) {
      *next_idx = hole;
    }

    /* Make a hole at src of move. */
    nonce_txns[ idx ].slot               = FD_TXNCACHE_ENTRY_FREE_UINT;
    nonce_txns[ idx ].slotcache_next     = UINT_MAX;
    nonce_txns[ idx ].slotcache_prev_val = UINT_MAX;
  }
}

static void
fd_txncache_remove_nonce_slotcache_idx( fd_txncache_t * tc,
                                        ulong           idx ) {
  fd_txncache_private_nonce_slotcache_t * nonce_slotcache = fd_txncache_get_nonce_slotcache( tc );
  fd_txncache_private_nonce_txn_t *       nonce_txns      = fd_txncache_get_nonce_txns( tc );

  /* Remove all nonce txns in the slot. */
  uint nonce_txn_idx = nonce_slotcache[ idx ].head;
  while( nonce_txn_idx!=UINT_MAX ) {
    uint next_nonce_txn_idx = nonce_txns[ nonce_txn_idx ].slotcache_next;
    fd_txncache_remove_nonce_txn_idx( tc, nonce_txn_idx, &next_nonce_txn_idx );
    nonce_slotcache[ idx ].nonce_slot_pop--;
    nonce_txn_idx = next_nonce_txn_idx;
  }
  if( FD_UNLIKELY( nonce_slotcache[ idx ].nonce_slot_pop!=0U ) ) {
    FD_LOG_CRIT(( "invariant violation: nonce slotcache %lu slot %lu has nonce_slot_pop %u after purging, tc->slot_pop %u", idx, nonce_slotcache[ idx ].slot, nonce_slotcache[ idx ].nonce_slot_pop, tc->slot_pop ));
  }

  /* Remove from slotcache and make a hole at idx. */
  nonce_slotcache[ idx ].slot = FD_TXNCACHE_ENTRY_FREE;

  /* Reprobe the hash table. */
  for(;;) {
    ulong hole = idx;

    for(;;) {
      idx = (idx+1UL) & (tc->live_slots_max-1UL); /* live_slots_max is power of 2. */

      if( nonce_slotcache[ idx ].slot==FD_TXNCACHE_ENTRY_FREE ) return;

      ulong start = nonce_slotcache[ idx ].slot & (tc->live_slots_max-1UL);
      if( !(((hole<start) & (start<=idx)) | ((hole>idx) & ((hole<start) | (start<=idx)))) ) break;
    }

    nonce_slotcache[ hole ] = nonce_slotcache[ idx ];
    /* Make a hole at src of move. */
    nonce_slotcache[ idx ].slot = FD_TXNCACHE_ENTRY_FREE;
  }
}

static void
fd_txncache_purge_slot( fd_txncache_t * tc,
                        ulong           slot ) {
  ulong not_purged_cnt = 0UL;
  ulong purged_cnt     = 0UL;
  ulong max_distance   = 0UL;
  ulong sum_distance   = 0UL;
  for( ulong i=0UL; i<tc->live_slots_max; /* manually advance i */ ) {
    fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache_at_idx( tc, i );
    if( FD_UNLIKELY( blockcache->max_slot==FD_TXNCACHE_ENTRY_NEW ) ) {
      FD_LOG_CRIT(( "invariant violation: blockcache %lu has max_slot set to ENTRY_NEW during purge", i ));
    }
    if( FD_LIKELY( blockcache->max_slot==FD_TXNCACHE_ENTRY_FREE || blockcache->max_slot>slot ) ) {
      if( blockcache->max_slot!=FD_TXNCACHE_ENTRY_FREE ) {
        not_purged_cnt++;
        ulong dist    = blockcache->max_slot-slot;
        max_distance  = fd_ulong_max( max_distance, dist );
        sum_distance += dist;
      }
      i++;
      continue;
    }
    fd_txncache_remove_blockcache_idx( tc, i );
    tc->block_pop--; /* No atomic fetch and add because global lock is held. */
    purged_cnt++;
  }
  ulong avg_distance = (not_purged_cnt==0) ? ULONG_MAX : (sum_distance/not_purged_cnt);
  FD_LOG_INFO(( "purge_slot: %lu, purged_cnt: %lu, not_purged_cnt: %lu, max_distance: %lu, avg_distance: %lu",
                slot, purged_cnt, not_purged_cnt, max_distance, avg_distance ));

  /* The whole txncache is write locked, so it is okay for the
     blockcache and the slotcache to be out of sync for a short while.
   */

  fd_txncache_private_nonce_slotcache_t * nonce_slotcache = fd_txncache_get_nonce_slotcache( tc );
  for( ulong i=0UL; i<tc->live_slots_max; /* manually advance i */ ) {
    if( FD_LIKELY( nonce_slotcache[ i ].slot==FD_TXNCACHE_ENTRY_FREE || nonce_slotcache[ i ].slot>slot ) ) {
      i++;
      continue;
    }
    if( FD_LIKELY( !( tc->root_slots_cnt==0UL || tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) ) {
      /* For slots loaded from an Agave snapshot, we insert all
         transactions as nonce transactions.  This makes the nonce slot
         population count inflated.  So we don't track these slots into
         the max count. */
      tc->nonce_slot_pop_max = fd_uint_max( tc->nonce_slot_pop_max, nonce_slotcache[ i ].nonce_slot_pop );
    }
    fd_txncache_remove_nonce_slotcache_idx( tc, i );
    tc->slot_pop--; /* No atomic fetch and add because global lock is held. */
  }
}

/* fd_txncache_register_root_slot_private is a helper function that
   actually registers the root. This function assumes that the
   caller has already obtained a lock to the status cache. */

static void
fd_txncache_register_root_slot_private( fd_txncache_t * tc,
                                        ulong           slot ) {

  FD_TEST( fd_rwlock_iswrite( tc->lock ) );

  ulong * root_slots = fd_txncache_get_root_slots( tc );
  ulong idx;
  for( idx=0UL; idx<tc->root_slots_cnt; idx++ ) {
    if( FD_UNLIKELY( root_slots[ idx ]==slot ) ) return; /* Slot already registered. */
    if( FD_UNLIKELY( root_slots[ idx ]>slot  ) ) break;  /* Would like to insert at idx if pushing right, and idx-1 if evicting left. */
  }

  if( FD_UNLIKELY( tc->root_slots_cnt>=tc->root_slots_max ) ) {
    if( FD_LIKELY( idx ) ) {
      if( FD_UNLIKELY( tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) {
        if( FD_UNLIKELY( root_slots[ 0 ]>=tc->nonce_blockcache_max_slot ) ) {
          tc->nonce_blockcache_deactivated_slot_delta = root_slots[ 0 ]-tc->lowest_observed_slot;
          FD_LOG_INFO(( "deactivated nonce blockcache at slot %lu, delta %lu", root_slots[ 0 ], tc->nonce_blockcache_deactivated_slot_delta ));
        }
      }
      fd_txncache_purge_slot( tc, root_slots[ 0 ] );
      memmove( root_slots, root_slots+1UL, (idx-1UL)*sizeof(ulong) );
      root_slots[ (idx-1UL) ] = slot;
    } else {
      /* Slot number too small to make its way into rooted slots.
         Purge transactions that have slipped into the txncache
         since the last purge. */
      fd_txncache_purge_slot( tc, slot );
    }
  } else {
    if( FD_UNLIKELY( idx<tc->root_slots_cnt ) ) {
      memmove( root_slots+idx+1UL, root_slots+idx, (tc->root_slots_cnt-idx)*sizeof(ulong) );
    }
    root_slots[ idx ] = slot;
    tc->root_slots_cnt++;
  }
}

void
fd_txncache_register_root_slot( fd_txncache_t * tc,
                                ulong           slot ) {

  fd_rwlock_write( tc->lock );

  /* Update metrics because we might purge and reduce hash table
     population. */
  tc->block_pop_max = fd_ushort_max( tc->block_pop_max, tc->block_pop );
  tc->slot_pop_max  = fd_ushort_max( tc->slot_pop_max,  tc->slot_pop );

  fd_txncache_register_root_slot_private( tc, slot );

  fd_rwlock_unwrite( tc->lock );
}

void
fd_txncache_root_slots( fd_txncache_t * tc,
                        ulong *         out_slots ) {
  fd_rwlock_read( tc->lock );
  ulong * root_slots = fd_txncache_get_root_slots( tc );
  memcpy( out_slots, root_slots, tc->root_slots_max*sizeof(ulong) );
  fd_rwlock_unread( tc->lock );
}

#define FD_TXNCACHE_FIND_FOUND      (0)
#define FD_TXNCACHE_FIND_FOUNDEMPTY (1)
#define FD_TXNCACHE_FIND_FULL       (2)

static int
fd_txncache_find_blockhash( fd_txncache_t *                     tc,
                            uchar const                         blockhash[ static 32 ],
                            fd_txncache_private_blockcache_t ** out_blockcache ) {

  ulong hash = fd_txncache_key_hash( blockhash );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    ulong blockcache_idx = (hash+i)%tc->live_slots_max;
    fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache_at_idx( tc, blockcache_idx );
    if( FD_UNLIKELY( blockcache->max_slot==FD_TXNCACHE_ENTRY_FREE ) ) {
      *out_blockcache = blockcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    }
    while( FD_UNLIKELY( FD_VOLATILE_CONST( blockcache->max_slot )==FD_TXNCACHE_ENTRY_XBUSY ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE(); /* Prevent reordering of the blockhash read to before the atomic lock
                             (highest_slot) has been fully released by the writer. */
    if( FD_LIKELY( !memcmp( blockcache->blockhash, blockhash, 32UL ) ) ) {
      *out_blockcache = blockcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_find_nonce_slot( fd_txncache_t const *                     tc,
                             ulong                                     slot,
                             fd_txncache_private_nonce_slotcache_t * * out_nonce_slotcache ) {

  fd_txncache_private_nonce_slotcache_t * tc_nonce_slotcache = fd_txncache_get_nonce_slotcache( tc );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    ulong nonce_slotcache_idx = (slot+i)%tc->live_slots_max;
    fd_txncache_private_nonce_slotcache_t * nonce_slotcache = &tc_nonce_slotcache[ nonce_slotcache_idx ];
    if( FD_UNLIKELY( nonce_slotcache->slot==FD_TXNCACHE_ENTRY_FREE ) ) {
      *out_nonce_slotcache = nonce_slotcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    }
    while( FD_UNLIKELY( FD_VOLATILE_CONST( nonce_slotcache->slot )==FD_TXNCACHE_ENTRY_XBUSY ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE(); /* Prevent reordering of the slot read to before the atomic lock
                             (slot) has been fully released by the writer. */
    if( FD_LIKELY( nonce_slotcache->slot==slot ) ) {
      *out_nonce_slotcache = nonce_slotcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_find_nonce_blockhash( fd_txncache_t *                            tc,
                                  uchar const                                blockhash[ static 32 ],
                                  fd_txncache_private_nonce_blockcache_t * * out_blockcache ) {

  ulong hash = fd_txncache_key_hash( blockhash );
  fd_txncache_private_nonce_blockcache_t * tc_nonce_blockcache = fd_txncache_get_nonce_blockcache( tc );
  for( ulong i=0UL; i<tc->nonce_blockcache_entries_max; i++ ) {
    ulong blockcache_idx = (hash+i)%tc->nonce_blockcache_entries_max;
    fd_txncache_private_nonce_blockcache_t * nonce_blockcache = &tc_nonce_blockcache[ blockcache_idx ];
    if( FD_UNLIKELY( nonce_blockcache->max_slot==FD_TXNCACHE_ENTRY_FREE_UINT ) ) {
      *out_blockcache = nonce_blockcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    }
    while( FD_UNLIKELY( FD_VOLATILE_CONST( nonce_blockcache->max_slot )==FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( !memcmp( nonce_blockcache->blockhash, blockhash, 32UL ) ) ) {
      *out_blockcache = nonce_blockcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_find_nonce_txn( fd_txncache_t const *               tc,
                            uchar const                         txnhash[ static FD_TXNCACHE_KEY_SIZE ],
                            void *                              query_func_ctx,
                            int ( * query_func )( ulong slot, void * ctx ),
                            fd_txncache_private_nonce_txn_t * * out_nonce_txn ) {
  ulong key_hash = fd_txncache_key_hash( txnhash );
  fd_txncache_private_nonce_txn_t * nonce_txns = fd_txncache_get_nonce_txns( tc );
  for( uint i=0U; i<tc->nonce_txns_max; i++ ) {
    ulong nonce_txn_idx = (key_hash+i)%tc->nonce_txns_max;
    fd_txncache_private_nonce_txn_t * nonce_txn = &nonce_txns[ nonce_txn_idx ];
    if( FD_LIKELY( nonce_txn->slot==FD_TXNCACHE_ENTRY_FREE_UINT ) ) {
      *out_nonce_txn = nonce_txn;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    }
    while( FD_UNLIKELY( FD_VOLATILE_CONST( nonce_txn->slot )==FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( !memcmp( nonce_txn->txnhash, txnhash, FD_TXNCACHE_KEY_SIZE ) && ( !query_func || query_func( nonce_txn->slot, query_func_ctx ) ) ) ) {
      *out_nonce_txn = nonce_txn;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_ensure_blockcache( fd_txncache_t *                     tc,
                               uchar const                         blockhash[ static 32 ],
                               fd_txncache_private_blockcache_t ** out_blockcache ) {
  for(;;) {
    int blockcache_find = fd_txncache_find_blockhash( tc, blockhash, out_blockcache );
    if( FD_LIKELY( blockcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( blockcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_TXNCACHE_ENTRY_FREE==FD_ATOMIC_CAS( &((*out_blockcache)->max_slot), FD_TXNCACHE_ENTRY_FREE, FD_TXNCACHE_ENTRY_XBUSY ) ) ) {
      memcpy( (*out_blockcache)->blockhash, blockhash, 32UL );
      memset( (*out_blockcache)->heads, 0xFF, tc->txn_per_slot_max*sizeof(uint) );
      (*out_blockcache)->pages_cnt = 0;
      uint * pages = fd_txncache_get_blockcache_pages( tc, *out_blockcache );
      memset( pages, 0xFF, tc->txnpages_per_blockhash_max*sizeof(uint) );
      FD_ATOMIC_FETCH_AND_ADD( &tc->block_pop, 1U );
      FD_COMPILER_MFENCE();
      (*out_blockcache)->max_slot       = FD_TXNCACHE_ENTRY_NEW;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static int
fd_txncache_ensure_nonce_slotcache( fd_txncache_t *                           tc,
                                    ulong                                     slot,
                                    fd_txncache_private_nonce_slotcache_t * * out_slotcache ) {
  for(;;) {
    int slotcache_find = fd_txncache_find_nonce_slot( tc, slot, out_slotcache );
    if( FD_LIKELY( slotcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( slotcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_TXNCACHE_ENTRY_FREE==FD_ATOMIC_CAS( &(*out_slotcache)->slot, FD_TXNCACHE_ENTRY_FREE, FD_TXNCACHE_ENTRY_XBUSY ) ) ) {
      (*out_slotcache)->nonce_slot_pop = 0U;
      FD_ATOMIC_FETCH_AND_ADD( &tc->slot_pop, 1U );
      (*out_slotcache)->head = UINT_MAX;
      FD_COMPILER_MFENCE();
      (*out_slotcache)->slot = slot;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static int
fd_txncache_ensure_nonce_blockcache( fd_txncache_t *                            tc,
                                     uchar const                                blockhash[ static 32 ],
                                     fd_txncache_private_nonce_blockcache_t * * out_blockcache ) {
  for(;;) {
    int blockcache_find = fd_txncache_find_nonce_blockhash( tc, blockhash, out_blockcache );
    if( FD_LIKELY( blockcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( blockcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_TXNCACHE_ENTRY_FREE_UINT==FD_ATOMIC_CAS( &((*out_blockcache)->max_slot), FD_TXNCACHE_ENTRY_FREE_UINT, FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) ) {
      memcpy( (*out_blockcache)->blockhash, blockhash, 32UL );
      (*out_blockcache)->txnhash_offset = 0UL;
      FD_COMPILER_MFENCE();
      (*out_blockcache)->max_slot       = FD_TXNCACHE_ENTRY_NEW_UINT;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static int
query_func_identical_slot( ulong slot, void * _ctx ) {
  ulong * target_slot = (ulong *)_ctx;
  if( FD_LIKELY( slot==*target_slot ) ) return 1;

  return 0;
}

static fd_txncache_private_nonce_txn_t *
fd_txncache_ensure_new_nonce_txn( fd_txncache_t *                          tc,
                                  fd_txncache_private_nonce_blockcache_t * blockcache,
                                  fd_txncache_insert_t const *             txn ) {

  ulong txnhash_offset = 0UL;
  if( FD_UNLIKELY( blockcache ) ) {
    txnhash_offset = blockcache->txnhash_offset;
  }
  if( FD_UNLIKELY( txnhash_offset ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.13/runtime/src/status_cache.rs#L185

       We get these non-zero offset values only for slots loaded from
       an Agave snapshot.  These slots will be gradually evicted over
       time, and eventually all of our offsets will be 0.  Optimize
       branch for the common case and accept a slow start.

       Also note that Agave doesn't actually propagate key offsets
       that exceed what's reasonable for a 32-byte transaction message
       hash.  In other words, key offsets in Agave snapshots don't
       actually exceed 11.  This is because Agave inserts the 32-byte
       transaction message hash first, and the 64-byte transaction
       signature second.  So any new blockcache entry will rng a key
       offset in [0, 11].  However, we still do the following offset
       capping, which Agave also does, in case things change.

       Why 11 and not 12, you might ask.  The max key offset
       calculation in Agave is off by one.  We replicate that here. */
    ulong max_key_idx = fd_ulong_sat_sub( txn->key_sz, FD_TXNCACHE_KEY_SIZE+1UL );
    txnhash_offset = fd_ulong_min( txnhash_offset, max_key_idx );
  }

  for(;;) {
    fd_txncache_private_nonce_txn_t * nonce_txn;
    ulong slot = txn->slot;
    /* The query function checks if the nonce txn is already in the
       table.  This is a cheap defensive check to catch duplicate
       insertions.  We could easily remove this check and always try to
       find an empty entry, but duplicate insertions really shouldn't be
       allowed. */
    int nonce_txn_find = fd_txncache_find_nonce_txn( tc, txn->txnhash+txnhash_offset, &slot, query_func_identical_slot, &nonce_txn );
    if( FD_UNLIKELY( nonce_txn_find==FD_TXNCACHE_FIND_FULL ) ) {
      FD_LOG_WARNING(( "nonce txn table full" ));
      return NULL;
    }
    if( FD_UNLIKELY( nonce_txn_find==FD_TXNCACHE_FIND_FOUND ) ) FD_LOG_CRIT(( "invariant violation: nonce txn table found existing nonce txn for slot %u and the duplicate is for slot %lu", nonce_txn->slot, slot ));

    if( FD_LIKELY( FD_TXNCACHE_ENTRY_FREE_UINT==FD_ATOMIC_CAS( &nonce_txn->slot, FD_TXNCACHE_ENTRY_FREE_UINT, FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) ) {
      memcpy( nonce_txn->txnhash, txn->txnhash+txnhash_offset, FD_TXNCACHE_KEY_SIZE );
      return nonce_txn;
    }
    FD_SPIN_PAUSE();
  }

}

static fd_txncache_private_txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t *                    tc,
                            fd_txncache_private_blockcache_t * blockcache ) {
  ushort page_cnt = blockcache->pages_cnt;
  if( FD_UNLIKELY( page_cnt>tc->txnpages_per_blockhash_max ) ) {
    FD_LOG_NOTICE(( "pagecnt %u > txnpages_per_blockhash_max %u", page_cnt, tc->txnpages_per_blockhash_max ));
    return NULL;
  }
  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );

  uint * pages = fd_txncache_get_blockcache_pages( tc, blockcache );
  if( FD_LIKELY( page_cnt ) ) {
    uint txnpage_idx = pages[ page_cnt-1 ];
    ushort txnpage_free = txnpages[ txnpage_idx ].free;
    if( FD_LIKELY( txnpage_free ) ) {
      return &txnpages[ txnpage_idx ];
    }
  }

  if( FD_UNLIKELY( page_cnt==tc->txnpages_per_blockhash_max ) ) {
    FD_LOG_NOTICE(( "pagecnt %u == txnpages_per_blockhash_max %u but we need more", page_cnt, tc->txnpages_per_blockhash_max ));
    return NULL;
  }
  if( FD_LIKELY( FD_ATOMIC_CAS( &pages[ page_cnt ], FD_TXNCACHE_ENTRY_FREE_UINT, FD_TXNCACHE_ENTRY_XBUSY_UINT )==FD_TXNCACHE_ENTRY_FREE_UINT ) ) {
    ulong txnpages_free_cnt = tc->txnpages_free_cnt;
    for(;;) {
      if( FD_UNLIKELY( !txnpages_free_cnt ) ) {
        FD_LOG_NOTICE(( "txnpages_free_cnt %lu == 0 but we need more", txnpages_free_cnt ));
        return NULL;
      }
      ulong old_txnpages_free_cnt = FD_ATOMIC_CAS( &tc->txnpages_free_cnt, (uint)txnpages_free_cnt, (uint)(txnpages_free_cnt-1UL) );
      if( FD_LIKELY( old_txnpages_free_cnt==txnpages_free_cnt ) ) break;
      txnpages_free_cnt = old_txnpages_free_cnt;
      FD_SPIN_PAUSE();
    }
    uint * txnpages_free = fd_txncache_get_txnpages_free( tc );

    uint txnpage_idx = txnpages_free[ txnpages_free_cnt-1UL ];
    fd_txncache_private_txnpage_t * txnpage = &txnpages[ txnpage_idx ];
    txnpage->free = FD_TXNCACHE_TXNS_PER_PAGE;
    FD_COMPILER_MFENCE();
    pages[ page_cnt ] = txnpage_idx;
    FD_COMPILER_MFENCE();
    blockcache->pages_cnt = (ushort)(page_cnt+1);
    return txnpage;
  } else {
    uint txnpage_idx = pages[ page_cnt ];
    while( FD_UNLIKELY( txnpage_idx>=FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) {
      txnpage_idx = FD_VOLATILE_CONST( pages[ page_cnt ] );
      FD_SPIN_PAUSE();
    }
    return &txnpages[ txnpage_idx ];
  }
}

/* Returns 0 on failure, 1 on success. */
static int
fd_txncache_insert_regular_txn_do( fd_txncache_t *                    tc,
                                   fd_txncache_private_blockcache_t * blockcache,
                                   fd_txncache_private_txnpage_t *    txnpage,
                                   fd_txncache_insert_t const *       txn ) {
  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );
  ulong txnpage_idx = (ulong)(txnpage - txnpages);

  for(;;) {
    ushort txnpage_free = txnpage->free;
    if( FD_UNLIKELY( !txnpage_free ) ) return 0;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &txnpage->free, txnpage_free, txnpage_free-1UL )!=txnpage_free ) ) continue;

    ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-txnpage_free;
    ulong txnhash = fd_txncache_key_hash( txn->txnhash ); /* The main txn cache always offsets the txnhash by 0. */
    memcpy( txnpage->txns[ txn_idx ]->txnhash, txn->txnhash, FD_TXNCACHE_KEY_SIZE );
    txnpage->txns[ txn_idx ]->slot = txn->slot;
    FD_COMPILER_MFENCE();

    for(;;) {
      ulong txn_bucket = txnhash%tc->txn_per_slot_max;
      uint head = blockcache->heads[ txn_bucket ];
      txnpage->txns[ txn_idx ]->blockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->heads[ txn_bucket ], head, (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx) )==head ) ) break;
      FD_SPIN_PAUSE();
    }

    for(;;) {
      ulong max_slot = blockcache->max_slot;
      if( FD_UNLIKELY( txn->slot<=max_slot && max_slot!=FD_TXNCACHE_ENTRY_NEW ) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->max_slot, max_slot, txn->slot )==max_slot ) ) break;
      FD_SPIN_PAUSE();
    }
    return 1;
  }
}

static void
fd_txncache_insert_nonce_txn_do( fd_txncache_t *                          tc,
                                 fd_txncache_private_nonce_slotcache_t *  nonce_slotcache,
                                 fd_txncache_private_nonce_blockcache_t * nonce_blockcache,
                                 fd_txncache_private_nonce_txn_t *        nonce_txn,
                                 fd_txncache_insert_t const *             txn ) {

  fd_txncache_private_nonce_txn_t * nonce_txns = fd_txncache_get_nonce_txns( tc );
  uint nonce_txn_idx = (uint)(nonce_txn-nonce_txns);
  nonce_txn->slotcache_prev_is_head = 1;
  nonce_txn->slotcache_prev         = ((uint)(nonce_slotcache-fd_txncache_get_nonce_slotcache( tc )))&FD_TXNCACHE_NONCE_TXN_IDX_MASK;
  for(;;) {
    uint head = FD_VOLATILE_CONST( nonce_slotcache->head );
    nonce_txn->slotcache_next = head;
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( FD_ATOMIC_CAS( &nonce_slotcache->head, head, nonce_txn_idx )==head ) ) {
      if( FD_LIKELY( head!=UINT_MAX ) ) {
        nonce_txns[ head ].slotcache_prev         = nonce_txn_idx&FD_TXNCACHE_NONCE_TXN_IDX_MASK;
        nonce_txns[ head ].slotcache_prev_is_head = 0;
      }
      FD_ATOMIC_FETCH_AND_ADD( &nonce_slotcache->nonce_slot_pop, 1U );
      break;
    }
    FD_SPIN_PAUSE();
  }

  ulong * root_slots = fd_txncache_get_root_slots( tc );
  if( FD_UNLIKELY( nonce_blockcache && ( txn->flags&FD_TXNCACHE_FLAG_SNAPSHOT || tc->root_slots_cnt==0UL || nonce_blockcache->max_slot>=root_slots[ 0UL ] ) ) ) {
    for(;;) {
      uint max_slot     = FD_VOLATILE_CONST( nonce_blockcache->max_slot );
      uint new_max_slot = (uint)txn->slot; /* Safe cast because we checked earlier. */
      if( FD_UNLIKELY( new_max_slot<=max_slot && max_slot!=FD_TXNCACHE_ENTRY_NEW_UINT ) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &nonce_blockcache->max_slot, max_slot, new_max_slot )==max_slot ) ) break;
      FD_SPIN_PAUSE();
    }
    for(;;) {
      ulong max_slot = FD_VOLATILE_CONST( tc->nonce_blockcache_max_slot );
      if( FD_UNLIKELY( txn->slot<=max_slot ) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &tc->nonce_blockcache_max_slot, max_slot, txn->slot )==max_slot ) ) break;
      FD_SPIN_PAUSE();
    }
  }

  if( FD_UNLIKELY( nonce_txn->slot!=FD_TXNCACHE_ENTRY_XBUSY_UINT ) ) {
    FD_LOG_CRIT(( "invariant violation: nonce txn slot already set to %u", nonce_txn->slot ));
  }
  FD_COMPILER_MFENCE();
  /* Safe cast because we checked for overflow at the very beginning of
     insert. */
  nonce_txn->slot = (uint)txn->slot;

}

/* Returns 0 on failure, 1 on success. */
static int
fd_txncache_insert_nonce_txn( fd_txncache_t *              tc,
                              fd_txncache_insert_t const * txn ) {

  fd_txncache_private_nonce_slotcache_t * nonce_slotcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_nonce_slotcache( tc, txn->slot, &nonce_slotcache ) ) ) {
    fd_txncache_print_insert( txn, "failed to ensure nonce slotcache entry" );
    fd_txncache_print_state( tc, "failed to ensure nonce slotcache entry" );
    return 0;
  }

  fd_txncache_private_nonce_blockcache_t * nonce_blockcache = NULL;
  if( FD_UNLIKELY( txn->flags&FD_TXNCACHE_FLAG_SNAPSHOT || tc->root_slots_cnt==0UL || tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) {
    if( FD_UNLIKELY( !fd_txncache_ensure_nonce_blockcache( tc, txn->blockhash, &nonce_blockcache ) ) ) {
      fd_txncache_print_insert( txn, "failed to ensure nonce blockcache entry" );
      fd_txncache_print_state( tc, "failed to ensure nonce blockcache entry" );
      return 0;
    }
  }

  fd_txncache_private_nonce_txn_t * nonce_txn = fd_txncache_ensure_new_nonce_txn( tc, nonce_blockcache, txn );
  if( FD_UNLIKELY( !nonce_txn ) ) {
    fd_txncache_print_insert( txn, "failed to ensure nonce txn" );
    fd_txncache_print_state( tc, "failed to ensure nonce txn" );
    return 0;
  }

  fd_txncache_insert_nonce_txn_do( tc, nonce_slotcache, nonce_blockcache, nonce_txn, txn );

  for(;;) {
    ulong lowest_observed_slot = tc->lowest_observed_slot;
    if( FD_UNLIKELY( txn->slot<lowest_observed_slot ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &tc->lowest_observed_slot, lowest_observed_slot, txn->slot )==lowest_observed_slot ) ) {
        break;
      } else {
        FD_SPIN_PAUSE();
        continue;
      }
    }
    break;
  }

  return 1;
}

/* Returns 0 on failure, 1 on success. */
static int
fd_txncache_insert_regular_txn( fd_txncache_t *              tc,
                                fd_txncache_insert_t const * txn ) {

  if( FD_UNLIKELY( tc->root_slots_cnt==0UL || tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) {
    ulong * root_slots = fd_txncache_get_root_slots( tc );
    fd_txncache_private_nonce_blockcache_t * nonce_blockcache;
    int result = fd_txncache_find_nonce_blockhash( tc, txn->blockhash, &nonce_blockcache );
    if( FD_LIKELY( result==FD_TXNCACHE_FIND_FOUND && ( tc->root_slots_cnt==0UL || nonce_blockcache->max_slot>=root_slots[ 0UL ] ) ) ) {
      return fd_txncache_insert_nonce_txn( tc, txn );
    }
  }

  /* Insert into the main txn cache.  This is the expected path after
     the nonce blockcache has been deactivated. */
  fd_txncache_private_blockcache_t * blockcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_blockcache( tc, txn->blockhash, &blockcache ) ) ) {
    fd_txncache_print_insert( txn, "failed to ensure blockcache entry" );
    fd_txncache_print_state( tc, "failed to ensure blockcache entry" );
    return 0;
  }

  for(;;) {
    fd_txncache_private_txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache );
    if( FD_UNLIKELY( !txnpage ) ) {
      fd_txncache_print_insert( txn, "failed to ensure txnpage" );
      fd_txncache_print_state( tc, "failed to ensure txnpage" );
      return 0;
    }

    int success = fd_txncache_insert_regular_txn_do( tc, blockcache, txnpage, txn );
    if( FD_LIKELY( success ) ) break;
    FD_SPIN_PAUSE();
  }

  for(;;) {
    ulong lowest_observed_slot = tc->lowest_observed_slot;
    if( FD_UNLIKELY( txn->slot<lowest_observed_slot ) ) {
      if( FD_LIKELY( FD_ATOMIC_CAS( &tc->lowest_observed_slot, lowest_observed_slot, txn->slot )==lowest_observed_slot ) ) {
        break;
      } else {
        FD_SPIN_PAUSE();
        continue;
      }
    }
    break;
  }

  return 1;
}

int
fd_txncache_insert_batch( fd_txncache_t *              tc,
                          fd_txncache_insert_t const * txns,
                          ulong                        txns_cnt ) {

  /* Validate input. */
  for( ulong i=0UL; i<txns_cnt; i++ ) {
    fd_txncache_insert_t const * txn = txns + i;
    if( FD_UNLIKELY( txn->flags&FD_TXNCACHE_FLAG_REGULAR_TXN && txn->flags&FD_TXNCACHE_FLAG_NONCE_TXN ) ) {
      FD_LOG_CRIT(( "invalid flags specified both REGULAR and NONCE: 0x%lx", txn->flags ));
    }
    if( FD_UNLIKELY( txn->slot>UINT_MAX ) ) {
      FD_LOG_CRIT(( "slot too large: %lu", txn->slot ));
    }
  }

  fd_rwlock_read( tc->lock );

  for( ulong i=0UL; i<txns_cnt; i++ ) {
    fd_txncache_insert_t const * txn = txns + i;
    if( FD_UNLIKELY( txn->key_sz!=FD_TXNCACHE_KEY_SIZE && txn->key_sz!=32UL && txn->key_sz!=64UL ) ) {
      FD_LOG_CRIT(( "unexpected key_sz %lu", txn->key_sz ));
    }

    if( FD_LIKELY( txn->flags&FD_TXNCACHE_FLAG_REGULAR_TXN ) ) {
      if( FD_UNLIKELY( !fd_txncache_insert_regular_txn( tc, txn ) ) ) {
        goto unlock_fail;
      }
    } else if( FD_LIKELY( txn->flags&FD_TXNCACHE_FLAG_NONCE_TXN ) ) {
      if( FD_UNLIKELY( !fd_txncache_insert_nonce_txn( tc, txn ) ) ) {
        goto unlock_fail;
      }
    } else {
      FD_LOG_CRIT(( "unexpected flags 0x%lx", txn->flags ));
    }
  }

  fd_rwlock_unread( tc->lock );
  return 1;

unlock_fail:
  fd_rwlock_unread( tc->lock );
  return 0;
}

static void
fd_txncache_query_nonce_txn( fd_txncache_t *             tc,
                             fd_txncache_query_t const * query,
                             void *                      query_func_ctx,
                             int ( * query_func )( ulong slot, void * ctx ),
                             int *                       out_result ) {

  *out_result = FD_TXNCACHE_QUERY_ABSENT;
  ulong * root_slots     = fd_txncache_get_root_slots( tc );
  ulong   txnhash_offset = 0UL;
  fd_txncache_private_nonce_blockcache_t * nonce_blockcache;
  if( FD_UNLIKELY( tc->root_slots_cnt==0UL || tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) {
    int result = fd_txncache_find_nonce_blockhash( tc, query->blockhash, &nonce_blockcache );
    if( FD_LIKELY( result==FD_TXNCACHE_FIND_FOUND && ( tc->root_slots_cnt==0UL || nonce_blockcache->max_slot>=root_slots[ 0UL ] ) ) ) {
      txnhash_offset = nonce_blockcache->txnhash_offset;
    }
  }

  if( FD_UNLIKELY( txnhash_offset ) ) {
    ulong max_key_idx = fd_ulong_sat_sub( query->key_sz, FD_TXNCACHE_KEY_SIZE+1UL );
    txnhash_offset = fd_ulong_min( txnhash_offset, max_key_idx );
  }
  fd_txncache_private_nonce_txn_t * nonce_txn;
  int nonce_txn_find = fd_txncache_find_nonce_txn( tc, query->txnhash+txnhash_offset, query_func_ctx, query_func, &nonce_txn );
  if( FD_UNLIKELY( nonce_txn_find==FD_TXNCACHE_FIND_FOUND ) ) {
    *out_result = FD_TXNCACHE_QUERY_PRESENT;
  }
}

static void
fd_txncache_query_regular_txn( fd_txncache_t *             tc,
                               fd_txncache_query_t const * query,
                               void *                      query_func_ctx,
                               int ( * query_func )( ulong slot, void * ctx ),
                               int *                       out_result ) {

  *out_result = FD_TXNCACHE_QUERY_ABSENT;
  if( FD_UNLIKELY( tc->root_slots_cnt==0UL || tc->nonce_blockcache_deactivated_slot_delta==ULONG_MAX ) ) {
    /* The nonce blockcache initialized from the snapshot hasn't been
       deactivated.  This implies that the regular transaction could be
       in the nonce txn cache.  So check there too, before we check the
       main txn cache. */
    ulong * root_slots     = fd_txncache_get_root_slots( tc );
    ulong   txnhash_offset = 0UL;
    fd_txncache_private_nonce_blockcache_t * nonce_blockcache;
    int result = fd_txncache_find_nonce_blockhash( tc, query->blockhash, &nonce_blockcache );
    if( FD_LIKELY( result==FD_TXNCACHE_FIND_FOUND && ( tc->root_slots_cnt==0UL || nonce_blockcache->max_slot>=root_slots[ 0UL ] ) ) ) {
      txnhash_offset = nonce_blockcache->txnhash_offset;
      if( FD_UNLIKELY( txnhash_offset ) ) {
        ulong max_key_idx = fd_ulong_sat_sub( query->key_sz, FD_TXNCACHE_KEY_SIZE+1UL );
        txnhash_offset = fd_ulong_min( txnhash_offset, max_key_idx );
      }
      /* The query into the nonce txn cache is gated behind the
         expiration check of the nonce blockcache entry, because if the
         nonce blockcache entry is expired, then the regular txn can't
         possibly be in the nonce txn cache.  In contrast, if it were an
         actual query for nonce transaction, then we have to query the
         nonce txn cache, regardless of whether the nonce blockcache
         entry is expired or not.  It's just that when the nonce
         blockcache entry is expired, we assume a txnhash offset of 0.
         */
      fd_txncache_private_nonce_txn_t * nonce_txn;
      int nonce_txn_find = fd_txncache_find_nonce_txn( tc, query->txnhash+txnhash_offset, query_func_ctx, query_func, &nonce_txn );
      if( FD_UNLIKELY( nonce_txn_find==FD_TXNCACHE_FIND_FOUND ) ) {
        *out_result = FD_TXNCACHE_QUERY_PRESENT;
        return;
      }
    }
  }

  /* Check the main txn cache.  This is the expected path after the
     nonce blockcache has been deactivated. */
  fd_txncache_private_blockcache_t * blockcache;
  int result = fd_txncache_find_blockhash( tc, query->blockhash, &blockcache );

  if( FD_UNLIKELY( result!=FD_TXNCACHE_FIND_FOUND ) ) {
    return;
  }

  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );

  ulong txnhash_offset = 0UL; /* The main txn cache always offsets the txnhash by 0. */
  ulong head_idx       = fd_txncache_key_hash( query->txnhash+txnhash_offset ) % tc->txn_per_slot_max;
  for( uint head=blockcache->heads[ head_idx ]; head!=UINT_MAX; head=txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next ) {
    fd_txncache_private_txn_t * txn = txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
    if( FD_UNLIKELY( !memcmp( query->txnhash+txnhash_offset, txn->txnhash, FD_TXNCACHE_KEY_SIZE ) ) ) {
      if( FD_UNLIKELY( !query_func || query_func( txn->slot, query_func_ctx ) ) ) {
        *out_result = FD_TXNCACHE_QUERY_PRESENT;
        return;
      }
    }
  }
}

void
fd_txncache_query_batch( fd_txncache_t *             tc,
                         fd_txncache_query_t const * queries,
                         ulong                       queries_cnt,
                         void *                      query_func_ctx,
                         int ( * query_func )( ulong slot, void * ctx ),
                         int *                       out_results ) {

  /* Validate input. */
  for( ulong i=0UL; i<queries_cnt; i++ ) {
    fd_txncache_query_t const * query = &queries[ i ];
    if( FD_UNLIKELY( query->flags&FD_TXNCACHE_FLAG_REGULAR_TXN && query->flags&FD_TXNCACHE_FLAG_NONCE_TXN ) ) {
      FD_LOG_CRIT(( "invalid flags specified both REGULAR and NONCE: 0x%lx", query->flags ));
    }
    if( FD_UNLIKELY( query->flags&FD_TXNCACHE_FLAG_SNAPSHOT ) ) {
      FD_LOG_CRIT(( "invalid flags specified SNAPSHOT on query: 0x%lx", query->flags ));
    }
    if( FD_UNLIKELY( query->key_sz!=32UL && query->key_sz!=64UL ) ) {
      FD_LOG_CRIT(( "unexpected key_sz %lu", query->key_sz ));
    }
  }

  fd_rwlock_read( tc->lock );

  for( ulong i=0UL; i<queries_cnt; i++ ) {
    fd_txncache_query_t const * query = &queries[ i ];

    if( FD_LIKELY( query->flags&FD_TXNCACHE_FLAG_REGULAR_TXN ) ) {
      fd_txncache_query_regular_txn( tc, query, query_func_ctx, query_func, out_results+i );
    } else if( FD_LIKELY( query->flags&FD_TXNCACHE_FLAG_NONCE_TXN ) ) {
      fd_txncache_query_nonce_txn( tc, query, query_func_ctx, query_func, out_results+i );
    } else {
      FD_LOG_CRIT(( "unexpected flags 0x%lx", query->flags ));
    }
  }

  fd_rwlock_unread( tc->lock );
}

int
fd_txncache_set_nonce_txnhash_offset( fd_txncache_t * tc,
                                      uchar           blockhash[ 32 ],
                                      ulong           txnhash_offset ) {
  if( FD_UNLIKELY( txnhash_offset>UINT_MAX ) ) {
    FD_LOG_CRIT(( "crazy large txnhash_offset %lu", txnhash_offset ));
  }

  fd_rwlock_read( tc->lock );

  fd_txncache_private_nonce_blockcache_t * blockcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_nonce_blockcache( tc, blockhash, &blockcache ) ) ) goto unlock_fail;
  if( FD_UNLIKELY( blockcache->txnhash_offset!=0U && blockcache->txnhash_offset!=txnhash_offset ) ) {
    FD_BASE58_ENCODE_32_BYTES( blockhash, blockhash_str );
    FD_LOG_CRIT(( "blockhash %s: non-zero txnhash_offset %u being reset to a different value %lu this indicates that the snapshot is busted or not being parsed correctly", blockhash_str, blockcache->txnhash_offset, txnhash_offset ));
  }
  blockcache->txnhash_offset = (uint)txnhash_offset;

  fd_rwlock_unread( tc->lock );
  return 1;

unlock_fail:
  fd_rwlock_unread( tc->lock );
  return 0;
}

int
fd_txncache_is_rooted_slot_locked( fd_txncache_t * tc,
                                   ulong           slot ) {

  ulong * root_slots = fd_txncache_get_root_slots( tc );
  /* TODO The root slots array is sorted; might be able to exploit that */
  for( ulong idx=0UL; idx<tc->root_slots_cnt; idx++ ) {
    if( FD_UNLIKELY( root_slots[ idx ]==slot ) ) {
      return 1;
    }
    if( FD_UNLIKELY( root_slots[ idx ]>slot ) ) break;
  }

  return 0;
}

int
fd_txncache_is_rooted_slot( fd_txncache_t * tc,
                            ulong           slot ) {
  fd_rwlock_read( tc->lock );

  int rv = fd_txncache_is_rooted_slot_locked( tc, slot );

  fd_rwlock_unread( tc->lock );
  return rv;
}
