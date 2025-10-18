#include "fd_gossip_wpeer_sampler.h"
#include "crds/fd_crds.h"

/* This is a very rudimentary implementation of a weighted sampler. We
   will eventually want to use a modified fd_wsample. */
struct wpeer_sampler_private {
  /* Cumulative weight for each peer.
     Individual peer weight can be derived with
     cumul_weight[i]-cumul_weight[i-1]  */
  ulong * cumul_weight;
  ulong   max_idx;
};

#define PREV_PEER_WEIGHT( ps, idx ) \
  ( (idx) ? (ps)->cumul_weight[(idx)-1] : 0UL )


FD_FN_CONST ulong
wpeer_sampler_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, wpeer_sampler_align(), sizeof(wpeer_sampler_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong), sizeof(ulong)*max_peers );
  return FD_LAYOUT_FINI( l, wpeer_sampler_align() );
}

void *
wpeer_sampler_new( void * shmem, ulong  max_peers ) {
  if( FD_UNLIKELY( !shmem ) ){
      FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, wpeer_sampler_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  wpeer_sampler_t * ws = FD_SCRATCH_ALLOC_APPEND( l, wpeer_sampler_align(), sizeof(wpeer_sampler_t) );
  ws->cumul_weight     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), sizeof(ulong)*max_peers );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, wpeer_sampler_align() )==(ulong)shmem + wpeer_sampler_footprint( max_peers ) );

  fd_memset( ws->cumul_weight, 0, sizeof(ulong)*max_peers );
  ws->max_idx = ULONG_MAX;
  return (void *)ws;
}

wpeer_sampler_t *
wpeer_sampler_join( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ){
    FD_LOG_WARNING(( "null shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, wpeer_sampler_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  wpeer_sampler_t * ws = (wpeer_sampler_t *) shmem;

  return ws;

}

ulong
wpeer_sampler_sample( wpeer_sampler_t const * ps,
                      fd_rng_t *              rng ) {
  if( FD_UNLIKELY( ps->max_idx == ULONG_MAX || !ps->cumul_weight[ps->max_idx] ) ) {
    return SAMPLE_IDX_SENTINEL;
  }

  ulong sample = fd_rng_ulong_roll( rng, ps->cumul_weight[ps->max_idx] );
  /* avoid sampling 0 */
  sample = fd_ulong_min( sample+1UL, ps->cumul_weight[ps->max_idx] );

  /* Binary search for the smallest cumulative weight >= sample */
  ulong left = 0UL;
  ulong right = ps->max_idx+1;
  while( left < right ) {
    ulong mid = left + (right - left) / 2UL;
    if( ps->cumul_weight[mid]<sample ) {
      left = mid + 1UL;
    } else {
      right = mid;
    }
  }
  return left;
}

int
wpeer_sampler_upd( wpeer_sampler_t * ps,
                   ulong             weight,
                   ulong             idx ) {
  if( FD_UNLIKELY( !ps ) ) return -1;

  /* Special case weight = 0 and idx == max_idx */
  if( FD_UNLIKELY( weight==0UL && idx==ps->max_idx ) ) {
    ps->cumul_weight[idx] = 0UL;
    ps->max_idx = ( idx==0UL ) ? ULONG_MAX : idx-1;
    return 0;
  }
  /* Handle edge case where ps->max_idx is ULONG_MAX (sampler is empty) */
  if( FD_UNLIKELY( ps->max_idx == ULONG_MAX ) ) {
    ps->max_idx = idx;
  } else {
    ps->max_idx = fd_ulong_max( ps->max_idx, idx );
  }

  ulong old_weight = ps->cumul_weight[idx] - PREV_PEER_WEIGHT( ps, idx );
  if( FD_UNLIKELY( old_weight==weight ) ) return 0;

  if( weight>old_weight ) {
    for( ulong i=idx; i<ps->max_idx+1; i++ ) {
      ps->cumul_weight[i] += (weight - old_weight);
    }
  } else {
    for( ulong i=idx; i<ps->max_idx+1; i++ ) {
      ps->cumul_weight[i] -= (old_weight - weight);
    }
  }
  return 0;
}
