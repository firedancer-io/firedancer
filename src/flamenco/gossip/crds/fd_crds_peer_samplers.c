/* Owned by CRDS table, tightly coupled with contact info side table.

  The gossip table (currently) needs 25 (active set rotation)
  + 1 (tx pull req) stake-weighted peer samplers.

  Each sampler needs a different weight scoring implementation. This
  compile unit:
    - defines weight scoring implementations for each sampler.
    - defines functions to insert, remove, and update all samplers in
      one go

  The sample sets are designed to closely track modifications to the
  CRDS contact info table. */

#include "fd_crds.h"
#include "../fd_active_set_private.h"

#define SAMPLE_IDX_SENTINEL ULONG_MAX

#define SET_NAME peer_enabled
#define SET_MAX  CRDS_MAX_CONTACT_INFO
#include "../../../util/tmpl/fd_set.c"

/* This is a very rudimentary implementation of a weighted sampler. We will
   eventually want to use a modified fd_wsample. Using this until then. */
struct wpeer_sampler {
  /* Cumulative weight for each peer.
     Individual peer weight can be derived with cumul_weight[i]-cumul_weight[i-1]  */
  ulong          cumul_weight[ CRDS_MAX_CONTACT_INFO ];

  /* peer_enabled_test( peer_enabled, i ) determines if peer i is enabled. A
     disabled peer should not be scored (e.g., during an update) and should
     have a peer weight of 0 (i.e,. cumul_weight[i] - cumul_weight[i-1]==0).

     Why not just remove the peer?
      1. Removing is expensive (see wpeer_sampler_rem)
      2. Adding/removing should strictly track the CRDS Contact Info table.
         That is to say a peer must have an entry in the sampler if it has
         an entry in the table, and vice versa. We might want to "soft disable"
         a peer from being sampled.

     Why not just set the peer's weight to 0?
       A peer's weight might be updated/recalculated from various events
       (stake update, peer active status, etc,.). When this happens, a
       "disabled" peer may become inadvertently enabled.
       Note: the peer's weight is still set to zero, this just serves as an
       additional null check. */
  peer_enabled_t peer_enabled[ peer_enabled_word_cnt ];
};

typedef struct wpeer_sampler wpeer_sampler_t;

#define PREV_PEER_WEIGHT( ps, idx ) \
  ( (idx) ? (ps)->cumul_weight[(idx)-1] : 0UL )
int
wpeer_sampler_init( wpeer_sampler_t * ps ) {
  if( FD_UNLIKELY( !ps ) ) return -1;
  for( ulong i = 0UL; i < CRDS_MAX_CONTACT_INFO; i++ ) {
    ps->cumul_weight[i] = 0UL;
  }
  /* All peers are "enabled" by default as they get added. */
  peer_enabled_full( ps->peer_enabled );
  return 0;
}

ulong
wpeer_sampler_sample( wpeer_sampler_t const * ps,
                      fd_rng_t *              rng,
                      ulong                   ele_cnt ) {
  if( FD_UNLIKELY( !ele_cnt || !ps->cumul_weight[ele_cnt-1] ) ) {
    return SAMPLE_IDX_SENTINEL;
  }

  ulong sample = fd_rng_ulong_roll( rng, ps->cumul_weight[ele_cnt-1] );
  /* avoid sampling 0 */
  sample = fd_ulong_min( sample+1UL, ps->cumul_weight[ele_cnt-1] );

  /* Binary search for the smallest cumulative weight >= sample */
  ulong left = 0UL;
  ulong right = ele_cnt;
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
                   ulong             idx,
                   ulong             ele_cnt ) {
  if( FD_UNLIKELY( !ps ) ) return -1;

  /* Disabled peers should not be scored */
  weight *= (ulong)peer_enabled_test( ps->peer_enabled, idx );

  ulong old_weight = ps->cumul_weight[idx] - PREV_PEER_WEIGHT( ps, idx );
  if( FD_UNLIKELY( old_weight==weight ) ) return 0;
  long score_delta = (long)(weight - old_weight);

  if( score_delta>0 ){
    for( ulong i=idx; i<ele_cnt; i++ ) {
      ps->cumul_weight[i] += (ulong)score_delta;
    }
  } else {
    score_delta = -score_delta;
    for( ulong i=idx; i<ele_cnt; i++ ) {
      ps->cumul_weight[i] -= (ulong)score_delta;
    }
  }
  return 0;
}

int
wpeer_sampler_disable( wpeer_sampler_t * ps,
                       ulong             idx,
                       ulong             ele_cnt ) {
  if( FD_UNLIKELY( !ps || idx>=ele_cnt ) ) return -1;

  /* Set the peer weight to zero */
  if( FD_UNLIKELY( wpeer_sampler_upd( ps, 0UL, idx, ele_cnt )<0 ) ) return -1;

  /* Disable the peer in the enabled set */
  peer_enabled_remove( ps->peer_enabled, idx );
  return 0;
}

int
wpeer_sampler_enable( wpeer_sampler_t * ps,
                      ulong             idx,
                      ulong             ele_cnt ) {
  if( FD_UNLIKELY( !ps || idx>=ele_cnt ) ) return -1;
  peer_enabled_insert( ps->peer_enabled, idx );
  return 0;
}

/* NOTE: this should only be called if the peer is dropped from the Contact Info table,
         otherwise set weight to zero with peer_wsampler_upd instead */
int
wpeer_sampler_rem( wpeer_sampler_t * ps,
                   ulong             idx,
                   ulong             ele_cnt ) {
  ulong score = ps->cumul_weight[idx] - ps->cumul_weight[fd_ulong_sat_sub( idx, 1UL )];
  if( FD_UNLIKELY( !score ) ) return 0;

  for( ulong i = idx+1; i < ele_cnt; i++ ) {
    /* Shift the cumulative weights down */
    ps->cumul_weight[i] -= score;
    ps->cumul_weight[i-1] = ps->cumul_weight[i];
  }
  return 0;
}

#define BASE_WEIGHT 100UL /* TODO: figure this out!! */
ulong
wpeer_sampler_peer_score( fd_crds_entry_t * peer,
                          long              now ) {
  if( FD_UNLIKELY( !peer->contact_info.is_active ) ) return 0;
  ulong score = BASE_WEIGHT;
  score+= peer->stake;
  if( FD_UNLIKELY( peer->wallclock_nanos<now-60*1000L*1000L*1000L ) ) score/=100;

  return score;
}

ulong
wpeer_sampler_bucket_score( fd_crds_entry_t * peer,
                            ulong             bucket ) {
  ulong peer_bucket = fd_active_set_stake_bucket( peer->stake );
  ulong score = fd_ulong_sat_add( fd_ulong_min( bucket, peer_bucket ), 1UL );

  return score*score;
}

struct crds_samplers {
  wpeer_sampler_t   pr_sampler[1];
  wpeer_sampler_t   bucket_samplers[25];
  fd_crds_entry_t * ele[ CRDS_MAX_CONTACT_INFO ];
  ulong             ele_cnt;
};

typedef struct crds_samplers crds_samplers_t;


void
crds_samplers_new( crds_samplers_t * ps ) {
  if( FD_UNLIKELY( !ps ) ) return;

  wpeer_sampler_init( ps->pr_sampler );
  for( ulong i=0UL; i<25UL; i++ ) {
    wpeer_sampler_init( &ps->bucket_samplers[i] );
  }
  ps->ele_cnt = 0UL;
  for( ulong i=0UL; i<CRDS_MAX_CONTACT_INFO; i++ ) {
    ps->ele[i] = NULL;
  }
}

int
crds_samplers_upd_peer_at_idx( crds_samplers_t * ps,
                               fd_crds_entry_t * peer,
                               ulong             idx,
                               long              now ) {
  if( FD_UNLIKELY( idx>=ps->ele_cnt ) ) {
    FD_LOG_WARNING(( "Bad peer idx supplied in sample update" ));
    return -1;
  }
  ps->ele[idx] = peer;
  peer->contact_info.sampler_idx = idx;
  ulong peer_score = wpeer_sampler_peer_score( peer, now );
  if( FD_UNLIKELY( wpeer_sampler_upd( ps->pr_sampler, peer_score, idx, ps->ele_cnt )<0 ) ) return -1;

  for( ulong i=0UL; i<25UL; i++ ) {
    ulong bucket_score = wpeer_sampler_bucket_score( peer, i );
    if( FD_UNLIKELY( !bucket_score ) ) FD_LOG_ERR(( "0-weighted peer in bucket, should not be possible" ));
    if( FD_UNLIKELY( wpeer_sampler_upd( &ps->bucket_samplers[i], bucket_score, idx, ps->ele_cnt )<0 ) ) return -1;
  }

  return 0;
}

int
crds_samplers_swap_peer_at_idx( crds_samplers_t *  ps,
                                fd_crds_entry_t *  new_peer,
                                ulong              idx ) {
  if( FD_UNLIKELY( idx>=ps->ele_cnt ) ) {
    FD_LOG_WARNING(( "Bad peer idx supplied in sample update" ));
    return -1;
  }
  fd_crds_entry_t * old_peer = ps->ele[idx];
  if( FD_UNLIKELY( !old_peer ) ) {
    FD_LOG_ERR(( "No peer at index %lu in samplers" , idx ));
  }

  ps->ele[idx]                       = new_peer;
  new_peer->contact_info.sampler_idx = idx;
  old_peer->contact_info.sampler_idx = SAMPLE_IDX_SENTINEL;
  return 0;
}

int
crds_samplers_add_peer( crds_samplers_t * ps,
                        fd_crds_entry_t * peer,
                        long              now ) {
  ulong idx = fd_ulong_min( ps->ele_cnt, (CRDS_MAX_CONTACT_INFO)-1UL );
  ps->ele_cnt++;
  if( FD_UNLIKELY( !!crds_samplers_upd_peer_at_idx( ps, peer, idx, now ) ) ){
    FD_LOG_WARNING(( "Failed to update peer in samplers" ));
    ps->ele_cnt--;
    ps->ele[idx] = NULL;
    return -1;
  }
  return 0;
}

int
crds_samplers_rem_peer( crds_samplers_t * ps,
                        fd_crds_entry_t * peer ) {
  ulong idx = peer->contact_info.sampler_idx;
  if( FD_UNLIKELY( idx>=ps->ele_cnt ) ) return -1;
  if( FD_UNLIKELY( wpeer_sampler_rem( ps->pr_sampler, idx, ps->ele_cnt )<0 ) ) return -1;
  for( ulong i=0UL; i<25UL; i++ ) {
    if( FD_UNLIKELY( wpeer_sampler_rem( &ps->bucket_samplers[i], idx, ps->ele_cnt )<0 ) ) return -1;
  }

  // Shift the elements down in elems array
  for( ulong i = idx+1; i < ps->ele_cnt; i++ ) {
    ps->ele[i-1]                           = ps->ele[i];
    ps->ele[i-1]->contact_info.sampler_idx = i-1;
  }
  ps->ele_cnt--;
  return 0;
}
