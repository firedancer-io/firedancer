#include "fd_txncache_shmem.h"
#include "fd_txncache_private.h"

#define POOL_NAME       blockcache_pool
#define POOL_T          fd_txncache_blockcache_shmem_t
#define POOL_IDX_T      ulong
#define POOL_NEXT       pool.next
#define POOL_IMPL_STYLE 2
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blockhash_map
#define MAP_KEY                blockhash
#define MAP_ELE_T              fd_txncache_blockcache_shmem_t
#define MAP_KEY_T              fd_hash_t
#define MAP_PREV               blockhash_map.prev
#define MAP_NEXT               blockhash_map.next
#define MAP_KEY_EQ(k0,k1)      fd_hash_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (__extension__({ (void)(seed); fd_ulong_load_8_fast( (key)->uc ); }))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              1
#define MAP_IMPL_STYLE         2
#include "../../util/tmpl/fd_map_chain.c"

#define SLIST_NAME       root_slist
#define SLIST_ELE_T      fd_txncache_blockcache_shmem_t
#define SLIST_IDX_T      ulong
#define SLIST_NEXT       slist.next
#define SLIST_IMPL_STYLE 2
#include "../../util/tmpl/fd_slist.c"

FD_FN_CONST ushort
fd_txncache_max_txnpages_per_blockhash( ulong max_active_slots,
                                        ulong max_txn_per_slot ) {
  /* The maximum number of transaction pages we might need to store all
     the transactions that could be seen in a blockhash.

     In the worst case, every transaction in every live bank refers to
     the same blockhash. */

  ulong result = 1UL+(max_txn_per_slot*max_active_slots)/FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST ushort
fd_txncache_max_txnpages( ulong max_active_slots,
                          ulong max_txn_per_slot ) {
  /* We need to be able to store potentially every slot that is live
     being completely full of transactions.  This would be

       max_active_slots*max_txn_per_slot

     transactions, except that we are counting pages here, not
     transactions.  It's not enough to divide by the page size, because
     pages might be wasted.  The maximum page wastage occurs when all
     the blockhashes except one have one transaction in them, and the
     remaining blockhash has all other transactions.  In that case, the
     full blockhash needs

       (max_active_slots*max_txn_per_slot)/FD_TXNCACHE_TXNS_PER_PAGE

     pages, and the other blockhashes need 1 page each. */

  ulong result = max_active_slots-1UL+max_active_slots*(1UL+(max_txn_per_slot-1UL)/FD_TXNCACHE_TXNS_PER_PAGE);
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST ulong
fd_txncache_shmem_align( void ) {
  return FD_TXNCACHE_SHMEM_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_shmem_footprint( ulong max_live_slots,
                             ulong max_txn_per_slot ) {
  if( FD_UNLIKELY( max_live_slots<1UL ) ) return 0UL;
  if( FD_UNLIKELY( max_txn_per_slot<1UL ) ) return 0UL;

  ulong max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+max_live_slots;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*max_active_slots );

  /* To save memory, txnpages are referenced as ushort which is enough
     to support mainnet parameters without overflow. */
  ushort _max_txnpages = fd_txncache_max_txnpages( max_active_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !_max_txnpages ) ) return 0UL;

  ulong _max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !_max_txnpages_per_blockhash ) ) return 0UL;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN,        sizeof(fd_txncache_shmem_t)                               );
  l = FD_LAYOUT_APPEND( l, blockhash_map_align(),          blockhash_map_footprint( blockhash_map_chains )           );
  l = FD_LAYOUT_APPEND( l, blockcache_pool_align(),        blockcache_pool_footprint( max_active_slots )             );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                  max_active_slots*_max_txnpages_per_blockhash*sizeof(uint) ); /* blockcache->pages */
  l = FD_LAYOUT_APPEND( l, alignof(uint),                  max_active_slots*max_txn_per_slot*sizeof(uint)            ); /* blockcache->heads */
  l = FD_LAYOUT_APPEND( l, alignof(uchar),                 max_active_slots*max_active_slots*sizeof(uchar)           ); /* blockcache->descends */
  l = FD_LAYOUT_APPEND( l, alignof(ushort),                _max_txnpages*sizeof(ushort)                              ); /* txnpages_free */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_txnpage_t), _max_txnpages*sizeof(fd_txncache_txnpage_t)               ); /* txnpages */
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_SHMEM_ALIGN );
}

void *
fd_txncache_shmem_new( void * shmem,
                       ulong  max_live_slots,
                       ulong  max_txn_per_slot ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_txncache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_live_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_txn_per_slot ) ) return NULL;

  ulong max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+max_live_slots;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*max_active_slots );

  ushort _max_txnpages               = fd_txncache_max_txnpages( max_active_slots, max_txn_per_slot );
  ushort _max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot );

  if( FD_UNLIKELY( !_max_txnpages ) ) return NULL;
  if( FD_UNLIKELY( !_max_txnpages_per_blockhash ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_shmem_t * tc    = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN,         sizeof(fd_txncache_shmem_t)                               );
  void * _blockhash_map       = FD_SCRATCH_ALLOC_APPEND( l, blockhash_map_align(),           blockhash_map_footprint( blockhash_map_chains )           );
  void * _blockcache_pool     = FD_SCRATCH_ALLOC_APPEND( l, blockcache_pool_align(),         blockcache_pool_footprint( max_active_slots )             );
                                FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*_max_txnpages_per_blockhash*sizeof(uint) );
                                FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*max_txn_per_slot*sizeof(uint)            );
                                FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                  max_active_slots*max_active_slots*sizeof(uchar)           );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _max_txnpages*sizeof(ushort)                              );
                                FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  _max_txnpages*sizeof(fd_txncache_txnpage_t)               );

  fd_txncache_blockcache_shmem_t * blockcache_pool = blockcache_pool_join( blockcache_pool_new( _blockcache_pool, max_active_slots ) );
  FD_TEST( blockcache_pool );

  blockhash_map_t * blockhash_map = blockhash_map_join( blockhash_map_new( _blockhash_map, blockhash_map_chains, 0UL /* seed not used */ ) );
  FD_TEST( blockhash_map );

  tc->root_cnt = 0UL;
  FD_TEST( root_slist_join( root_slist_new( tc->root_ll ) ) );

  tc->lock->value = 0;

  tc->txn_per_slot_max           = max_txn_per_slot;
  tc->active_slots_max           = max_active_slots;
  tc->txnpages_per_blockhash_max = _max_txnpages_per_blockhash;
  tc->max_txnpages               = _max_txnpages;

  tc->txnpages_free_cnt = _max_txnpages;
  ushort * txnpages_free = (ushort *)_txnpages_free;
  for( ushort i=0; i<_max_txnpages; i++ ) txnpages_free[ i ] = i;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tc->magic ) = FD_TXNCACHE_SHMEM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)tc;
}

fd_txncache_shmem_t *
fd_txncache_shmem_join( void * shtc ) {
  if( FD_UNLIKELY( !shtc ) ) {
    FD_LOG_WARNING(( "NULL shtc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtc, fd_txncache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtc" ));
    return NULL;
  }

  fd_txncache_shmem_t * tc = (fd_txncache_shmem_t *)shtc;

  if( FD_UNLIKELY( tc->magic!=FD_TXNCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return tc;
}
