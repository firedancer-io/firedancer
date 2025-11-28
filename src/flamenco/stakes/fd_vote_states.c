#include "fd_vote_states.h"
#include "../types/fd_types.h"
#include "../runtime/program/fd_vote_program.h"

#define POOL_NAME fd_vote_state_pool
#define POOL_T    fd_vote_state_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_vote_state_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_state_ele_t
#define MAP_KEY                vote_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_
#include "../../util/tmpl/fd_map_chain.c"

static fd_vote_state_ele_t *
fd_vote_states_get_pool( fd_vote_states_t const * vote_states ) {
  return fd_vote_state_pool_join( (uchar *)vote_states + vote_states->pool_offset_ );
}

static fd_vote_state_map_t *
fd_vote_states_get_map( fd_vote_states_t const * vote_states ) {
  return fd_vote_state_map_join( (uchar *)vote_states + vote_states->map_offset_ );
}

ulong
fd_vote_states_align( void ) {
  /* The align of the struct should be the max of the align of the data
     structures that it contains.  In this case, this is the map, the
     pool, and the struct itself. */
  return fd_ulong_max( fd_ulong_max( fd_vote_state_map_align(),
                       fd_vote_state_pool_align() ), alignof(fd_vote_states_t) );
}

ulong
fd_vote_states_footprint( ulong max_vote_accounts ) {

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( max_vote_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  l = FD_LAYOUT_APPEND( l,  fd_vote_state_pool_align(), fd_vote_state_pool_footprint( max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l,  fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_vote_states_align() );
}

void *
fd_vote_states_new( void * mem,
                    ulong  max_vote_accounts,
                    ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_vote_accounts ) ) {
    FD_LOG_WARNING(( "max_vote_accounts is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( max_vote_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_states_t * vote_states = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  void *             pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( max_vote_accounts ) );
  void *             map_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_states_align() )!=(ulong)mem+fd_vote_states_footprint( max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_vote_states_new: bad layout" ));
    return NULL;
  }

  vote_states->max_vote_accounts_ = max_vote_accounts;
  vote_states->pool_offset_       = (ulong)pool_mem - (ulong)mem;
  vote_states->map_offset_        = (ulong)map_mem - (ulong)mem;

  fd_vote_state_ele_t * vote_states_pool = fd_vote_state_pool_join( fd_vote_state_pool_new( pool_mem, max_vote_accounts ) );
  if( FD_UNLIKELY( !vote_states_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote states pool" ));
    return NULL;
  }

  for( ulong i=0UL; i<max_vote_accounts; i++ ) {
    fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( vote_states_pool, i );
    vote_state->idx = i;
  }

  if( FD_UNLIKELY( !fd_vote_state_map_join( fd_vote_state_map_new( map_mem, map_chain_cnt, seed ) ) ) ) {
    FD_LOG_WARNING(( "Failed to create vote states map" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( vote_states->magic ) = FD_VOTE_STATES_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_vote_states_t *
fd_vote_states_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_vote_states_t * vote_states = (fd_vote_states_t *)mem;

  if( FD_UNLIKELY( vote_states->magic != FD_VOTE_STATES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote states magic" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( vote_states->max_vote_accounts_ );
  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  vote_states     = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( vote_states->max_vote_accounts_ ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_states_align() )!=(ulong)mem+fd_vote_states_footprint( vote_states->max_vote_accounts_ ) ) ) {
    FD_LOG_WARNING(( "fd_vote_states_join: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_state_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_state_map_join( map_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states map" ));
    return NULL;
  }

  return vote_states;
}

fd_vote_state_ele_t *
fd_vote_states_update( fd_vote_states_t *  vote_states,
                       fd_pubkey_t const * vote_account ) {

  fd_vote_state_ele_t * vote_state_pool = fd_vote_states_get_pool( vote_states );
  fd_vote_state_map_t * vote_state_map  = fd_vote_states_get_map( vote_states );

  if( FD_UNLIKELY( !vote_state_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state pool" ));
  }
  if( FD_UNLIKELY( !vote_state_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state map" ));
  }

  /* First, handle the case where the vote state already exists
     and we just need to update the entry.  The reason we do a const idx
     query is to allow fd_vote_states_update to be called while
     iterating over the map.  It is unsafe to call
     fd_vote_state_map_ele_query() during iteration, but we only
     need to change fields which are not used for pool/map management. */

  ulong idx = fd_vote_state_map_idx_query_const(
      vote_state_map,
      vote_account,
      ULONG_MAX,
      vote_state_pool );

  if( idx!=ULONG_MAX ) {
    fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( vote_state_pool, idx );
    if( FD_UNLIKELY( !vote_state ) ) {
      FD_LOG_CRIT(( "unable to retrieve vote state" ));
    }

    /* TODO: can do something smarter where we only update the
       comission and the credits coresponding to the new epoch. */
    return vote_state;
  }

  /* If the vote state does not exist, we need to create a new entry. */
  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !fd_vote_state_pool_free( vote_state_pool ) ) ) {
    FD_LOG_CRIT(( "no free vote states in pool" ));
  }

  fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele_acquire( vote_state_pool );

  vote_state->vote_account = *vote_account;
  vote_state->stake        = 0UL;
  vote_state->stake_t_1    = 0UL;
  vote_state->stake_t_2    = 0UL;

  if( FD_UNLIKELY( !fd_vote_state_map_ele_insert(
        vote_state_map,
        vote_state,
        vote_state_pool ) ) ) {
    FD_LOG_CRIT(( "unable to insert stake delegation into map" ));
  }
  return vote_state;
}

void
fd_vote_states_remove( fd_vote_states_t *  vote_states,
                       fd_pubkey_t const * vote_account ) {
  fd_vote_state_ele_t * vote_state_pool = fd_vote_states_get_pool( vote_states );
  fd_vote_state_map_t * vote_state_map  = fd_vote_states_get_map( vote_states );
  if( FD_UNLIKELY( !vote_state_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  if( FD_UNLIKELY( !vote_state_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  ulong vote_state_idx = fd_vote_state_map_idx_query_const(
      vote_state_map,
      vote_account,
      ULONG_MAX,
      vote_state_pool );
  if( FD_UNLIKELY( vote_state_idx == ULONG_MAX ) ) {
    /* The vote state was not found, nothing to do. */
    return;
  }

  fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( vote_state_pool, vote_state_idx );
  if( FD_UNLIKELY( !vote_state ) ) {
    FD_LOG_CRIT(( "unable to retrieve vote state" ));
  }

  ulong idx = fd_vote_state_map_idx_remove( vote_state_map, vote_account, ULONG_MAX, vote_state_pool );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "unable to remove vote state" ));
  }

  /* Set vote state's next_ pointer to the null idx. */
  vote_state->next_ = fd_vote_state_pool_idx_null( vote_state_pool );

  fd_vote_state_pool_idx_release( vote_state_pool, vote_state_idx );
}

fd_vote_state_ele_t *
fd_vote_states_update_from_account( fd_vote_states_t *  vote_states,
                                    fd_pubkey_t const * vote_account,
                                    uchar const *       account_data,
                                    ulong               account_data_len ) {

  /* TODO: Instead of doing this messy + unbounded decode, it should be
     replaced with a more efficient decode that just reads the fields
     we need directly. */

  fd_bincode_decode_ctx_t ctx = {
    .data    = account_data,
    .dataend = account_data + account_data_len,
  };

  uchar __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN))) vote_state_versioned[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ];

  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( vote_state_versioned, &ctx );
  if( FD_UNLIKELY( vsv==NULL ) ) {
    FD_LOG_CRIT(( "unable to decode vote state versioned" ));
  }

  fd_pubkey_t node_account;
  uchar       commission;
  long        last_vote_timestamp;
  ulong       last_vote_slot;

  switch( vsv->discriminant ) {
  case fd_vote_state_versioned_enum_v0_23_5:
    node_account        = vsv->inner.v0_23_5.node_pubkey;
    commission          = vsv->inner.v0_23_5.commission;
    last_vote_timestamp = vsv->inner.v0_23_5.last_timestamp.timestamp;
    last_vote_slot      = vsv->inner.v0_23_5.last_timestamp.slot;
    break;
  case fd_vote_state_versioned_enum_v1_14_11:
    node_account        = vsv->inner.v1_14_11.node_pubkey;
    commission          = vsv->inner.v1_14_11.commission;
    last_vote_timestamp = vsv->inner.v1_14_11.last_timestamp.timestamp;
    last_vote_slot      = vsv->inner.v1_14_11.last_timestamp.slot;
    break;
  case fd_vote_state_versioned_enum_current:
    node_account        = vsv->inner.current.node_pubkey;
    commission          = vsv->inner.current.commission;
    last_vote_timestamp = vsv->inner.current.last_timestamp.timestamp;
    last_vote_slot      = vsv->inner.current.last_timestamp.slot;
    break;
  default:
    __builtin_unreachable();
  }

  fd_vote_state_ele_t * vote_state = fd_vote_states_update( vote_states, vote_account );

  vote_state->node_account        = node_account;
  vote_state->commission          = commission;
  vote_state->last_vote_timestamp = last_vote_timestamp;
  vote_state->last_vote_slot      = last_vote_slot;

  return vote_state;
}

void
fd_vote_states_reset_stakes( fd_vote_states_t * vote_states ) {
  fd_vote_state_ele_t * vote_state_pool = fd_vote_states_get_pool( vote_states );
  fd_vote_state_map_t * vote_state_map  = fd_vote_states_get_map( vote_states );
  if( FD_UNLIKELY( !vote_state_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state pool" ));
  }
  if( FD_UNLIKELY( !vote_state_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state map" ));
  }

  for( fd_vote_state_map_iter_t iter = fd_vote_state_map_iter_init( vote_state_map, vote_state_pool );
       !fd_vote_state_map_iter_done( iter, vote_state_map, vote_state_pool );
       iter = fd_vote_state_map_iter_next( iter, vote_state_map, vote_state_pool ) ) {
    ulong idx = fd_vote_state_map_iter_idx( iter, vote_state_map, vote_state_pool );

    fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( vote_state_pool, idx );
    if( FD_UNLIKELY( !vote_state ) ) {
      FD_LOG_CRIT(( "unable to retrieve vote state" ));
    }

    vote_state->stake = 0UL;
  }
}

fd_vote_state_ele_t *
fd_vote_states_query( fd_vote_states_t const * vote_states,
                      fd_pubkey_t const *      vote_account ) {

  /* map_chain's _ele_query function isn't safe for concurrent access.
     The solution is to use the idx_query_const function, which is safe
     for concurrent access.  The caller is still responsible for
     synchronizing concurrent writers to the fd_vote_state_ele_t. */
  ulong idx = fd_vote_state_map_idx_query_const(
      fd_vote_states_get_map( vote_states ),
      vote_account,
      ULONG_MAX,
      fd_vote_states_get_pool( vote_states ) );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    return NULL;
  }

  fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( fd_vote_states_get_pool( vote_states ), idx );
  if( FD_UNLIKELY( !vote_state ) ) {
    FD_LOG_CRIT(( "unable to retrieve vote state" ));
  }

  return vote_state;
}

/* fd_vote_states_query_const is the same as fd_vote_states but instead
   returns a const pointer. */

fd_vote_state_ele_t const *
fd_vote_states_query_const( fd_vote_states_t const * vote_states,
                            fd_pubkey_t const *      vote_account ) {
  return fd_vote_state_map_ele_query_const(
      fd_vote_states_get_map( vote_states ),
      vote_account,
      NULL,
      fd_vote_states_get_pool( vote_states ) );
}

ulong
fd_vote_states_max( fd_vote_states_t const * vote_states ) {
  return vote_states->max_vote_accounts_;
}

ulong
fd_vote_states_cnt( fd_vote_states_t const * vote_states ) {
  return fd_vote_state_pool_used( fd_vote_states_get_pool( vote_states ) );
}

fd_vote_state_ele_t *
fd_vote_states_iter_ele( fd_vote_states_iter_t * iter ) {
  ulong idx = fd_vote_state_map_iter_idx( iter->iter, iter->map, iter->pool );
  return fd_vote_state_pool_ele( iter->pool, idx );
}

fd_vote_states_iter_t *
fd_vote_states_iter_init( fd_vote_states_iter_t *  iter,
                          fd_vote_states_t const * vote_states ) {
  if( FD_UNLIKELY( !iter ) ) {
    FD_LOG_CRIT(( "NULL iter_mem" ));
  }
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "NULL vote_states" ));
  }

  iter->map  = fd_vote_states_get_map( vote_states );
  iter->pool = fd_vote_states_get_pool( vote_states );
  iter->iter = fd_vote_state_map_iter_init( iter->map, iter->pool );

  return iter;
}

int
fd_vote_states_iter_done( fd_vote_states_iter_t * iter ) {
  return fd_vote_state_map_iter_done( iter->iter, iter->map, iter->pool );
}

void
fd_vote_states_iter_next( fd_vote_states_iter_t * iter ) {
  iter->iter = fd_vote_state_map_iter_next( iter->iter, iter->map, iter->pool );
}
