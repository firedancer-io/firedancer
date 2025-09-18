#include "fd_vote_tracker.h"

#define VOTE_TRACKER_MAX (512UL)

struct fd_vote_tracker_ele {
  fd_signature_t vote_sig;
  ulong          next_; /* Internal pool/map use */
};
typedef struct fd_vote_tracker_ele fd_vote_tracker_ele_t;

#define DEQUE_NAME fd_vote_tracker_deq
#define DEQUE_T    fd_vote_tracker_ele_t
#define DEQUE_MAX  512 /* must be a power of 2 */
#include "../../util/tmpl/fd_deque.c"

#define MAP_NAME          fd_vote_tracker_map
#define MAP_ELE_T         fd_vote_tracker_ele_t
#define MAP_KEY_T         fd_signature_t
#define MAP_KEY           vote_sig
#define MAP_NEXT          next_
#define MAP_KEY_EQ(k0,k1) fd_signature_eq( (k0), (k1) )
#define MAP_KEY_HASH(k,s) fd_hash( s, (k)->uc, sizeof(fd_signature_t) )
#include "../../util/tmpl/fd_map_chain.c"

struct fd_vote_tracker {
  ulong magic;
  ulong deq_offset;
  ulong map_offset;
};
typedef struct fd_vote_tracker fd_vote_tracker_t;

static inline fd_vote_tracker_ele_t *
fd_vote_tracker_deq_get( fd_vote_tracker_t * vote_tracker ) {
  return fd_vote_tracker_deq_join( (uchar *)vote_tracker + vote_tracker->deq_offset );
}

static inline fd_vote_tracker_map_t *
fd_vote_tracker_map_get( fd_vote_tracker_t * vote_tracker ) {
  return fd_vote_tracker_map_join( (uchar *)vote_tracker + vote_tracker->map_offset );
}

ulong
fd_vote_tracker_align( void ) {
  return fd_ulong_max( fd_ulong_max( fd_vote_tracker_map_align(), fd_vote_tracker_deq_align() ), alignof(fd_vote_tracker_t) );
}

ulong
fd_vote_tracker_footprint( void ) {
  ulong map_chain_cnt = fd_vote_tracker_map_chain_cnt_est( VOTE_TRACKER_MAX );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_vote_tracker_align(),     sizeof(fd_vote_tracker_t) );
  l = FD_LAYOUT_APPEND( l,  fd_vote_tracker_deq_align(), fd_vote_tracker_deq_footprint() );
  l = FD_LAYOUT_APPEND( l,  fd_vote_tracker_map_align(),  fd_vote_tracker_map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_vote_tracker_align() );
}

void *
fd_vote_tracker_new( void * mem, ulong seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_vote_tracker_map_chain_cnt_est( VOTE_TRACKER_MAX );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_tracker_t * vote_tracker = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_align(),     sizeof(fd_vote_tracker_t) );
  void *              deq_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_deq_align(), fd_vote_tracker_deq_footprint() );
  void *              map_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_map_align(), fd_vote_tracker_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_tracker_align() )!=(ulong)mem+fd_vote_tracker_footprint() ) ) {
    FD_LOG_WARNING(( "fd_vote_tracker_new: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_tracker_deq_new( deq_mem ) ) ) {
    FD_LOG_WARNING(( "fd_vote_tracker_new: bad deq" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_tracker_map_new( map_mem, map_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_vote_tracker_new: bad map" ));
    return NULL;
  }

  vote_tracker->deq_offset = (ulong)deq_mem - (ulong)mem;
  vote_tracker->map_offset = (ulong)map_mem - (ulong)mem;

  return vote_tracker;

}

fd_vote_tracker_t *
fd_vote_tracker_join( void * mem ) {
  return (fd_vote_tracker_t *)mem;
}

void
fd_vote_tracker_insert( fd_vote_tracker_t *    vote_tracker,
                        fd_signature_t const * vote_sig ) {
  fd_vote_tracker_ele_t * deq = fd_vote_tracker_deq_get( vote_tracker );
  fd_vote_tracker_map_t * map = fd_vote_tracker_map_get( vote_tracker );
  if( fd_vote_tracker_deq_full( deq ) ) {
    fd_vote_tracker_ele_t * ele = fd_vote_tracker_deq_pop_head_nocopy( deq );
    fd_vote_tracker_map_ele_remove( map, &ele->vote_sig, NULL, deq );
  }
  fd_vote_tracker_ele_t * ele = fd_vote_tracker_deq_push_tail_nocopy( deq );
  ele->vote_sig = *vote_sig;
  fd_vote_tracker_map_ele_insert( map, ele, deq );
}

int
fd_vote_tracker_query_sig( fd_vote_tracker_t *    vote_tracker,
                           fd_signature_t const * vote_sig ) {
  fd_vote_tracker_ele_t * deq = fd_vote_tracker_deq_get( vote_tracker );
  fd_vote_tracker_map_t * map = fd_vote_tracker_map_get( vote_tracker );
  return fd_vote_tracker_map_ele_query( map, vote_sig, NULL, deq )!=NULL;
}
