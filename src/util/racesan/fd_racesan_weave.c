#include "fd_racesan_weave.h"
#include "../../util/fd_util.h"

fd_racesan_weave_t *
fd_racesan_weave_new( fd_racesan_weave_t * weave ) {
  memset( weave, 0, sizeof(fd_racesan_weave_t) );
  return NULL;
}

void *
fd_racesan_weave_delete( fd_racesan_weave_t * weave ) {
  return weave;
}

void
fd_racesan_weave_add( fd_racesan_weave_t * weave,
                      fd_racesan_async_t * async ) {
  if( FD_UNLIKELY( weave->async_cnt>=FD_RACESAN_WEAVE_MAX ) ) {
    FD_LOG_ERR(( "exceeded max async count (%lu)", FD_RACESAN_WEAVE_MAX ));
  }
  weave->async[ weave->async_cnt++ ] = async;
}

void
fd_racesan_weave_exec_rand( fd_racesan_weave_t * weave,
                            ulong                seed,
                            ulong                step_max ) {
  uint async_cnt = weave->async_cnt;
  for( uint i=0U; i<async_cnt; i++ ) {
    weave->rem[ i ] = weave->async[ i ];
    fd_racesan_async_reset( weave->rem[ i ] );
  }
  weave->rem_cnt = async_cnt;

  uint  rng_seed = (uint)( seed>>32 );
  ulong rng_idx  = fd_ulong_hash( seed );
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, rng_idx ) );

  for( ulong step=0UL;
       step<step_max && weave->rem_cnt;
       step++ ) {
    if( step>=step_max ) {
      /* FIXME gracefully handle this condition */
      FD_LOG_ERR(( "step_max (%lu) reached", step_max ));
    }

    uint rem_idx = fd_rng_uint_roll( rng, weave->rem_cnt );
    int done = !fd_racesan_async_step( weave->rem[ rem_idx ] );
    if( done ) {
      weave->rem[ rem_idx ] = weave->rem[ --weave->rem_cnt ];
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );
}
