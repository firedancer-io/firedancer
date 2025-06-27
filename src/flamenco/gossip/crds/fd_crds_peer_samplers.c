/* Owned by CRDS table, tightly coupled with contact info side table.

  The gossip table (currently) needs 25 (active set rotation) + 1 (tx pull req)
  stake-weighted peer samplers.

  Each sampler needs a different weight scoring implementation. This compile unit:
    - defines weight scoring implementations for each sampler.
    - defines macros to {insert, remove, update} all samplers in one go

  The sample sets are designed to closely track modifications to the CRDS
  contact info table. Any update/insert/remove to the CRDS table should result
  in a modification to the sample sets. */

#include "fd_crds.h"
#include "../fd_active_set_private.h"

/************************ Begin Weighted Peer Sampler API  ********************/

#define SAMPLE_IDX_SENTINEL ULONG_MAX

/* This is a very rudimentary implementation of a weighted sampler. We will
   eventually want to use a modified fd_wsample. Using this until then. */
struct wpeer_sampler {
  /* Cumulative weight for each peer.
     Individual peer weight can be derived with cum_weight[i]-cum_weight[i-1]  */
  ulong  cumul_weight[ CRDS_MAX_CONTACT_INFO ];
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
  return 0;
}

ulong
wpeer_sampler_sample( wpeer_sampler_t const * ps,
                      fd_rng_t *              rng,
                      ulong                   ele_cnt ) {
  if( FD_UNLIKELY( !ele_cnt || !ps->cumul_weight[ele_cnt-1] ) ) {
    return SAMPLE_IDX_SENTINEL; /* Return sentinel if no weights or empty sampler */
  }

  ulong sample = fd_rng_ulong_roll( rng, ps->cumul_weight[ele_cnt-1] );

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

  ulong old_weight = ps->cumul_weight[idx] - PREV_PEER_WEIGHT( ps, idx );
  if( FD_UNLIKELY( old_weight==weight ) ) return 0; /* No change */
  long score_delta = (long)(weight - old_weight);

  if( score_delta>0 ){
    for( ulong i = idx; i<ele_cnt; i++ ) {
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

/* NOTE: this should only be called if the peer is dropped from the Contact Info table,
         otherwise set weight to zero with peer_wsampler_upd instead */
int
wpeer_sampler_rem( wpeer_sampler_t * ps,
                   ulong             idx,
                   ulong             ele_cnt ) {
  ulong score = ps->cumul_weight[idx] - ps->cumul_weight[fd_ulong_sat_sub( idx, 1UL )];
  if( FD_UNLIKELY( !score ) ) return 0; /* No change */

  for( ulong i = idx+1; i < ele_cnt; i++ ) {
    /* Shift the cumulative weights down */
    ps->cumul_weight[i] -= score;
    ps->cumul_weight[i-1] = ps->cumul_weight[i];
  }
  return 0;
}

/***************************** Begin Scorers **********************************/

#define BASE_WEIGHT 100UL /* TODO: figure this out!! */
ulong
wpeer_sampler_peer_score( fd_crds_entry_t * peer,
                          long              now ) {
  if( FD_UNLIKELY( !peer->contact_info.is_active ) ) return 0; /* Inactive peers get 0 score (effectively dropped) */
  ulong score = BASE_WEIGHT;
  score+= peer->stake;
  if( FD_UNLIKELY( peer->wallclock_nanos<now-60*1000L*1000L*1000L ) ) score/=100; /* Downweight 100x if older than 1 min */

  return score;
}

ulong
wpeer_sampler_bucket_score( fd_crds_entry_t * peer,
                            ulong             bucket ) {
  ulong peer_bucket = fd_active_set_stake_bucket( peer->stake );
  ulong score = fd_ulong_sat_add( fd_ulong_min( bucket, peer_bucket ), 1UL );

  return score*score;
}

/**************************** Begin CRDS Samplers API *************************/
struct crds_samplers {
  wpeer_sampler_t   pr_sampler[1];
  wpeer_sampler_t   bucket_samplers[25];
  fd_crds_entry_t * ele[ CRDS_MAX_CONTACT_INFO ]; /* Array of pointers to active elements */
  ulong             ele_cnt; /* Number of active elements in the samplers */
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
crds_samplers_upd_peer( crds_samplers_t * ps,
                        fd_crds_entry_t * peer,
                        long              now ) {
  ulong idx = peer->contact_info.sampler_idx;
  if( FD_UNLIKELY( idx>=ps->ele_cnt ) ) {
    FD_LOG_WARNING(( "Bad peer idx supplied in sample update" )); /* Invalid index */
    return -1;
  }
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
crds_samplers_add_peer( crds_samplers_t * ps,
                        fd_crds_entry_t * peer,
                        long              now ) {
  ulong idx = fd_ulong_min( ps->ele_cnt, (CRDS_MAX_CONTACT_INFO)-1UL );
  peer->contact_info.sampler_idx = idx;
  ps->ele_cnt++;
  ps->ele[idx] = peer;
  if( FD_UNLIKELY( !!crds_samplers_upd_peer( ps, peer, now ) ) ){
    FD_LOG_ERR(( "Failed to update peer in samplers" ));
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
  if( FD_UNLIKELY( idx>=ps->ele_cnt ) ) return -1; /* Invalid index */
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
