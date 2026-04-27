#include "fd_new_votes.h"

/* Shared pool backing both the root map and per-fork delta dlists. */

#define POOL_NAME  nv_pool
#define POOL_T     fd_new_vote_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               nv_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_new_vote_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  nv_dlist
#define DLIST_ELE_T fd_new_vote_ele_t
#define DLIST_PREV  prev
#define DLIST_NEXT  next
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

struct nv_fork_pool_ele { ushort next; };
typedef struct nv_fork_pool_ele nv_fork_pool_ele_t;

#define POOL_NAME  nv_fork_pool
#define POOL_T     nv_fork_pool_ele_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* Internal accessors */

static inline fd_new_vote_ele_t *
get_pool( fd_new_votes_t const * new_votes ) {
  return fd_type_pun( (uchar *)new_votes + new_votes->pool_offset );
}

static inline nv_map_t *
get_map( fd_new_votes_t const * new_votes ) {
  return fd_type_pun( (uchar *)new_votes + new_votes->map_offset );
}

static inline nv_fork_pool_ele_t *
get_fork_pool( fd_new_votes_t const * new_votes ) {
  return fd_type_pun( (uchar *)new_votes + new_votes->fork_pool_offset );
}

static inline nv_dlist_t *
get_dlist( fd_new_votes_t const * new_votes,
           ushort                 fork_idx ) {
  return fd_type_pun( (uchar *)new_votes + new_votes->dlist_offsets[ fork_idx ] );
}

ulong
fd_new_votes_align( void ) {
  return FD_NEW_VOTES_ALIGN;
}

ulong
fd_new_votes_footprint( ulong max_vote_accounts,
                        ulong expected_vote_accounts,
                        ulong max_live_forks ) {
  ulong map_chain_cnt = nv_map_chain_cnt_est( expected_vote_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_NEW_VOTES_ALIGN,    sizeof(fd_new_votes_t) );
  l = FD_LAYOUT_APPEND( l, nv_pool_align(),        nv_pool_footprint( max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, nv_map_align(),         nv_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, nv_fork_pool_align(),   nv_fork_pool_footprint( max_live_forks ) );
  for( ulong i=0UL; i<max_live_forks; i++ ) {
    l = FD_LAYOUT_APPEND( l, nv_dlist_align(), nv_dlist_footprint() );
  }
  return FD_LAYOUT_FINI( l, FD_NEW_VOTES_ALIGN );
}

void *
fd_new_votes_new( void * mem,
                  ulong  seed,
                  ulong  max_vote_accounts,
                  ulong  expected_vote_accounts,
                  ulong  max_live_forks ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_new_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_vote_accounts ) ) {
    FD_LOG_WARNING(( "max_vote_accounts is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_live_forks>FD_NEW_VOTES_FORK_MAX ) ) {
    FD_LOG_WARNING(( "max_live_forks is too large" ));
    return NULL;
  }

  ulong map_chain_cnt = nv_map_chain_cnt_est( expected_vote_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_new_votes_t * new_votes = FD_SCRATCH_ALLOC_APPEND( l, FD_NEW_VOTES_ALIGN,    sizeof(fd_new_votes_t) );
  void *           pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, nv_pool_align(),        nv_pool_footprint( max_vote_accounts ) );
  void *           map_mem   = FD_SCRATCH_ALLOC_APPEND( l, nv_map_align(),         nv_map_footprint( map_chain_cnt ) );
  void *           fpool_mem = FD_SCRATCH_ALLOC_APPEND( l, nv_fork_pool_align(),   nv_fork_pool_footprint( max_live_forks ) );
  for( ushort i=0; i<(ushort)max_live_forks; i++ ) {
    void *       dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, nv_dlist_align(), nv_dlist_footprint() );
    nv_dlist_t * dlist     = nv_dlist_join( nv_dlist_new( dlist_mem ) );
    if( FD_UNLIKELY( !dlist ) ) {
      FD_LOG_WARNING(( "Failed to create new votes fork dlist" ));
      return NULL;
    }
    new_votes->dlist_offsets[ i ] = (ulong)dlist - (ulong)mem;
  }

  fd_new_vote_ele_t * pool = nv_pool_join( nv_pool_new( pool_mem, max_vote_accounts ) );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create new votes pool" ));
    return NULL;
  }

  nv_map_t * map = nv_map_join( nv_map_new( map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "Failed to create new votes map" ));
    return NULL;
  }

  nv_fork_pool_ele_t * fork_pool = nv_fork_pool_join( nv_fork_pool_new( fpool_mem, max_live_forks ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create new votes fork pool" ));
    return NULL;
  }

  new_votes->max_vote_accounts = max_vote_accounts;
  new_votes->pool_offset       = (ulong)pool      - (ulong)mem;
  new_votes->map_offset        = (ulong)map       - (ulong)mem;
  new_votes->fork_pool_offset  = (ulong)fork_pool - (ulong)mem;

  fd_rwlock_new( &new_votes->lock );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( new_votes->magic ) = FD_NEW_VOTES_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_new_votes_t *
fd_new_votes_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_new_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_new_votes_t * new_votes = (fd_new_votes_t *)mem;

  if( FD_UNLIKELY( new_votes->magic!=FD_NEW_VOTES_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return new_votes;
}

void
fd_new_votes_reset( fd_new_votes_t * new_votes ) {
  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool = get_pool( new_votes );

  nv_fork_pool_ele_t * fork_pool = get_fork_pool( new_votes );
  ulong max_forks = nv_fork_pool_max( fork_pool );
  for( ulong i=0UL; i<max_forks; i++ ) {
    nv_dlist_remove_all( get_dlist( new_votes, (ushort)i ), pool );
  }
  nv_fork_pool_reset( fork_pool );
  nv_pool_reset( pool );
  nv_map_reset( get_map( new_votes ) );

  fd_rwlock_unwrite( &new_votes->lock );
}

void
fd_new_votes_reset_root( fd_new_votes_t * new_votes ) {
  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool = get_pool( new_votes );
  nv_map_t *          map  = get_map( new_votes );

  /* We cannot use nv_pool_reset here because the shared pool also
     contains elements that belong to fork dlists.  Instead we walk
     the map and release each element individually.  nv_map_iter_next
     is called before nv_pool_ele_release so the iterator has already
     read ele->next to advance; the subsequent clobber of ele->next
     by the pool free-list push is therefore harmless. */
  nv_map_iter_t iter = nv_map_iter_init( map, pool );
  while( !nv_map_iter_done( iter, map, pool ) ) {
    fd_new_vote_ele_t * ele = nv_map_iter_ele( iter, map, pool );
    iter = nv_map_iter_next( iter, map, pool );
    nv_pool_ele_release( pool, ele );
  }
  nv_map_reset( map );

  fd_rwlock_unwrite( &new_votes->lock );
}

ulong
fd_new_votes_cnt( fd_new_votes_t const * new_votes ) {
  fd_rwlock_t * lock = (fd_rwlock_t *)&new_votes->lock;
  fd_rwlock_read( lock );
  ulong cnt = nv_pool_used( get_pool( new_votes ) );
  fd_rwlock_unread( lock );
  return cnt;
}

ushort
fd_new_votes_new_fork( fd_new_votes_t * new_votes ) {
  fd_rwlock_write( &new_votes->lock );

  nv_fork_pool_ele_t * fork_pool = get_fork_pool( new_votes );
  FD_CRIT( nv_fork_pool_free( fork_pool ), "no free forks in new votes fork pool" );
  ushort fork_idx = (ushort)nv_fork_pool_idx_acquire( fork_pool );

  fd_rwlock_unwrite( &new_votes->lock );
  return fork_idx;
}

void
fd_new_votes_evict_fork( fd_new_votes_t * new_votes,
                         ushort           fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool  = get_pool( new_votes );
  nv_dlist_t *        dlist = get_dlist( new_votes, fork_idx );
  while( !nv_dlist_is_empty( dlist, pool ) ) {
    fd_new_vote_ele_t * ele = nv_dlist_ele_pop_head( dlist, pool );
    nv_pool_ele_release( pool, ele );
  }

  nv_fork_pool_idx_release( get_fork_pool( new_votes ), fork_idx );

  fd_rwlock_unwrite( &new_votes->lock );
}

void
fd_new_votes_insert( fd_new_votes_t *    new_votes,
                     ushort              fork_idx,
                     fd_pubkey_t const * pubkey ) {
  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool  = get_pool( new_votes );
  nv_dlist_t *        dlist = get_dlist( new_votes, fork_idx );

  FD_CRIT( nv_pool_free( pool ), "no free elements in new votes pool" );
  fd_new_vote_ele_t * ele = nv_pool_ele_acquire( pool );
  ele->pubkey       = *pubkey;
  ele->is_tombstone = 0;
  nv_dlist_ele_push_tail( dlist, ele, pool );

  FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_out );
  FD_LOG_DEBUG(( "insert: pubkey=%s", pubkey_out ));
  fd_rwlock_unwrite( &new_votes->lock );
}

void
fd_new_votes_remove( fd_new_votes_t *    new_votes,
                     ushort              fork_idx,
                     fd_pubkey_t const * pubkey ) {
  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool  = get_pool( new_votes );
  nv_dlist_t *        dlist = get_dlist( new_votes, fork_idx );

  FD_CRIT( nv_pool_free( pool ), "no free elements in new votes pool" );
  fd_new_vote_ele_t * ele = nv_pool_ele_acquire( pool );
  ele->pubkey       = *pubkey;
  ele->is_tombstone = 1;
  nv_dlist_ele_push_tail( dlist, ele, pool );

  FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_out );
  FD_LOG_DEBUG(( "remove: pubkey=%s", pubkey_out ));
  fd_rwlock_unwrite( &new_votes->lock );
}

void
fd_new_votes_apply_delta( fd_new_votes_t * new_votes,
                          ushort           fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &new_votes->lock );

  fd_new_vote_ele_t * pool  = get_pool( new_votes );
  nv_map_t *          map   = get_map( new_votes );
  nv_dlist_t *        dlist = get_dlist( new_votes, fork_idx );

  while( !nv_dlist_is_empty( dlist, pool ) ) {
    fd_new_vote_ele_t * ele = nv_dlist_ele_pop_head( dlist, pool );
    if( ele->is_tombstone ) {
      /* If the element is a tombstone, remove it from the root map if
         it exists and free both the root map element and the tombstone
         element.  If the element doesn't exist in the root, just free
         the tombstone. */
      if( FD_UNLIKELY( nv_map_ele_query( map, &ele->pubkey, NULL, pool ) ) ) {
        fd_new_vote_ele_t * root_ele = nv_map_ele_remove( map, &ele->pubkey, NULL, pool );
        nv_pool_ele_release( pool, root_ele );
        nv_pool_ele_release( pool, ele );
      } else {
        nv_pool_ele_release( pool, ele );
      }
    } else {
      /* If the element is not a tombstone, insert it into the root map
         if it doesn't exist in the root and just transfer pool element
         ownership: otherwise, just free the pool_element. */
      if( FD_UNLIKELY( nv_map_ele_query( map, &ele->pubkey, NULL, pool ) ) ) {
        nv_pool_ele_release( pool, ele );
      } else {
        nv_map_ele_insert( map, ele, pool );
      }
    }
  }
  fd_rwlock_unwrite( &new_votes->lock );
}

/* Iterator internals.  Phase 0 walks the root map; phase 1 walks
   each fork dlist in order, skipping pubkeys already in the root map. */

struct fd_new_votes_iter {
  fd_new_votes_t * new_votes;
  ushort const *   fork_idxs;
  ulong            fork_idx_cnt;
  ulong            fork_pos;       /* current position in fork_idxs (phase 1) */
  nv_map_iter_t    map_iter;       /* 16 bytes */
  nv_dlist_iter_t  dlist_iter;     /* 8 bytes */
  int              phase;          /* 0 = root map, 1 = fork dlists, 2 done */
};

FD_STATIC_ASSERT( sizeof(struct fd_new_votes_iter)<=FD_NEW_VOTES_ITER_FOOTPRINT, fd_new_votes_iter_footprint );
FD_STATIC_ASSERT( alignof(struct fd_new_votes_iter)<=FD_NEW_VOTES_ITER_ALIGN,    fd_new_votes_iter_align     );

static void
iter_advance_dlist( fd_new_votes_iter_t * it ) {
  fd_new_vote_ele_t * pool = get_pool( it->new_votes );
  nv_map_t *          map  = get_map( it->new_votes );

  for(;;) {
    nv_dlist_t * dlist = get_dlist( it->new_votes, it->fork_idxs[ it->fork_pos ] );

    while( !nv_dlist_iter_done( it->dlist_iter, dlist, pool ) ) {
      fd_new_vote_ele_t const * ele = nv_dlist_iter_ele_const( it->dlist_iter, dlist, pool );
      if( FD_LIKELY( !nv_map_ele_query( map, &ele->pubkey, NULL, pool ) ) ) return;
      it->dlist_iter = nv_dlist_iter_fwd_next( it->dlist_iter, dlist, pool );
    }

    it->fork_pos++;
    if( it->fork_pos>=it->fork_idx_cnt ) {
      it->phase = 2;
      return;
    }
    dlist = get_dlist( it->new_votes, it->fork_idxs[ it->fork_pos ] );
    it->dlist_iter = nv_dlist_iter_fwd_init( dlist, pool );
  }
}

fd_new_votes_iter_t *
fd_new_votes_iter_init( fd_new_votes_t * new_votes,
                        ushort const *   fork_idxs,
                        ulong            fork_idx_cnt,
                        uchar *          iter_mem ) {
  fd_new_votes_iter_t * it = (fd_new_votes_iter_t *)iter_mem;

  fd_rwlock_read( &new_votes->lock );

  it->new_votes    = new_votes;
  it->fork_idxs    = fork_idxs;
  it->fork_idx_cnt = fork_idx_cnt;

  fd_new_vote_ele_t * pool = get_pool( new_votes );
  nv_map_t *          map  = get_map( new_votes );

  it->map_iter = nv_map_iter_init( map, pool );

  if( !nv_map_iter_done( it->map_iter, map, pool ) ) {
    it->phase = 0;
    return it;
  }

  if( fork_idx_cnt>0UL ) {
    it->phase      = 1;
    it->fork_pos   = 0UL;
    nv_dlist_t * dlist = get_dlist( new_votes, fork_idxs[0] );
    it->dlist_iter = nv_dlist_iter_fwd_init( dlist, pool );
    iter_advance_dlist( it );
  } else {
    it->phase = 2;
  }

  return it;
}

int
fd_new_votes_iter_done( fd_new_votes_iter_t const * iter ) {
  return iter->phase==2;
}

void
fd_new_votes_iter_next( fd_new_votes_iter_t * it ) {
  fd_new_vote_ele_t * pool = get_pool( it->new_votes );
  nv_map_t *          map  = get_map( it->new_votes );

  if( it->phase==0 ) {
    it->map_iter = nv_map_iter_next( it->map_iter, map, pool );
    if( !nv_map_iter_done( it->map_iter, map, pool ) ) return;

    if( it->fork_idx_cnt>0UL ) {
      it->phase    = 1;
      it->fork_pos = 0UL;
      nv_dlist_t * dlist = get_dlist( it->new_votes, it->fork_idxs[0] );
      it->dlist_iter = nv_dlist_iter_fwd_init( dlist, pool );
      iter_advance_dlist( it );
    } else {
      it->phase = 2;
    }
    return;
  }

  if( it->phase==1 ) {
    nv_dlist_t * dlist = get_dlist( it->new_votes, it->fork_idxs[ it->fork_pos ] );
    it->dlist_iter = nv_dlist_iter_fwd_next( it->dlist_iter, dlist, pool );
    iter_advance_dlist( it );
  }
}

fd_pubkey_t const *
fd_new_votes_iter_ele( fd_new_votes_iter_t const * it,
                       int *                       is_tombstone ) {
  fd_new_vote_ele_t * pool = get_pool( it->new_votes );

  if( it->phase==0 ) {
    nv_map_t * map = get_map( it->new_votes );
    fd_new_vote_ele_t const * ele = nv_map_iter_ele_const( it->map_iter, map, pool );
    *is_tombstone = 0;
    return &ele->pubkey;
  }

  nv_dlist_t * dlist = get_dlist( it->new_votes, it->fork_idxs[ it->fork_pos ] );
  fd_new_vote_ele_t const * ele = nv_dlist_iter_ele_const( it->dlist_iter, dlist, pool );
  *is_tombstone = ele->is_tombstone;
  return &ele->pubkey;
}

void
fd_new_votes_iter_fini( fd_new_votes_iter_t * it ) {
  fd_rwlock_unread( &it->new_votes->lock );
}
