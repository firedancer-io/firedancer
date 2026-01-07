#include "fd_gossip.h"
#include "fd_bloom.h"
#include "fd_gossip_private.h"
#include "fd_gossip_txbuild.h"
#include "fd_active_set.h"
#include "fd_ping_tracker.h"
#include "crds/fd_crds.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../ballet/sha256/fd_sha256.h"

FD_STATIC_ASSERT( FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT==FD_GOSSIP_MESSAGE_LAST+1UL,
                  "FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT must match FD_GOSSIP_MESSAGE_LAST+1" );

FD_STATIC_ASSERT( FD_METRICS_ENUM_CRDS_VALUE_CNT==FD_GOSSIP_VALUE_LAST+1UL,
                  "FD_METRICS_ENUM_CRDS_VALUE_CNT must match FD_GOSSIP_VALUE_LAST+1" );

#include <math.h>

#define BLOOM_FALSE_POSITIVE_RATE (0.1)
#define BLOOM_NUM_KEYS            (8.0)

struct stake {
  fd_pubkey_t pubkey;
  ulong       stake;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct stake stake_t;

/* NOTE: Since the staked count is known at the time we populate
   the map, we can treat the pool as an array instead. This means we
   can bypass the acquire/release model and quickly iterate through the
   pool when we repopulate the map on every fd_gossip_stakes_update
   iteration. */
#define POOL_NAME  stake_pool
#define POOL_T     stake_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stake_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              stake_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#include "fd_push_set_private.c"

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];
  ulong               identity_stake;

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  fd_sha256_t sha256[1];
  fd_sha512_t sha512[1];

  ulong         entrypoints_cnt;
  fd_ip4_port_t entrypoints[ 16UL ];

  fd_rng_t * rng;

  struct {
    ulong         count;
    stake_t *     pool;
    stake_map_t * map;
  } stake;

  struct {
    long next_pull_request;
    long next_active_set_refresh;
    long next_contact_info_refresh;
    long next_flush_push_state;
  } timers;

  /* Callbacks */
  fd_gossip_sign_fn   sign_fn;
  void *              sign_ctx;

  fd_gossip_send_fn   send_fn;
  void *              send_ctx;

  fd_ping_tracker_change_fn ping_tracker_change_fn;
  void *                    ping_tracker_change_fn_ctx;

  struct {
    uchar             crds_val[ FD_GOSSIP_CRDS_MAX_SZ ];
    ulong             crds_val_sz;
    fd_contact_info_t ci[1];
  } my_contact_info;

  /* Push state for each peer in the active set. Tracks the active set,
     and must be flushed prior to a call to fd_active_set_rotate or
     fd_active_set_prune. */
  push_set_t *          active_pset;
  fd_gossip_out_ctx_t * gossip_net_out;
};

FD_FN_CONST ulong
fd_gossip_align( void ) {
  return 128uL;
}

FD_FN_CONST ulong
fd_gossip_footprint( ulong max_values,
                     ulong entrypoints_len ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_t),    sizeof(fd_gossip_t)                                                     );
  l = FD_LAYOUT_APPEND( l, fd_crds_align(),         fd_crds_footprint( max_values, max_values )                             );
  l = FD_LAYOUT_APPEND( l, fd_active_set_align(),   fd_active_set_footprint()                                               );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len )                            );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(),      stake_pool_footprint( CRDS_MAX_CONTACT_INFO )                           );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),       stake_map_footprint( stake_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO ) ) );
  l = FD_LAYOUT_APPEND( l, push_set_align(),        push_set_footprint( FD_ACTIVE_SET_MAX_PEERS )                           );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
}

static void
ping_tracker_change( void *        _ctx,
                     uchar const * peer_pubkey,
                     fd_ip4_port_t peer_address,
                     long          now,
                     int           change_type ) {
  fd_gossip_t * ctx = (fd_gossip_t *)_ctx;

  if( FD_UNLIKELY( !memcmp( peer_pubkey, ctx->identity_pubkey, 32UL ) ) ) return;

  switch( change_type ) {
    case FD_PING_TRACKER_CHANGE_TYPE_ACTIVE:   fd_crds_peer_active( ctx->crds, peer_pubkey, now ); break;
    case FD_PING_TRACKER_CHANGE_TYPE_INACTIVE: fd_crds_peer_inactive( ctx->crds, peer_pubkey, now ); break;
    case FD_PING_TRACKER_CHANGE_TYPE_INACTIVE_ENTRYPOINT: break;
    default: FD_LOG_ERR(( "Unknown change type %d", change_type )); return;
  }

  ctx->ping_tracker_change_fn( ctx->ping_tracker_change_fn_ctx, peer_pubkey, peer_address, now, change_type );
}

void *
fd_gossip_new( void *                    shmem,
               fd_rng_t *                rng,
               ulong                     max_values,
               ulong                     entrypoints_len,
               fd_ip4_port_t const *     entrypoints,
               fd_contact_info_t const * my_contact_info,
               long                      now,
               fd_gossip_send_fn         send_fn,
               void *                    send_ctx,
               fd_gossip_sign_fn         sign_fn,
               void *                    sign_ctx,
               fd_ping_tracker_change_fn ping_tracker_change_fn,
               void *                    ping_tracker_change_fn_ctx,
               fd_gossip_out_ctx_t *     gossip_update_out,
               fd_gossip_out_ctx_t *     gossip_net_out ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( entrypoints_len>16UL ) ) {
    FD_LOG_WARNING(( "entrypoints_cnt must be in [0, 16]" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_values ) ) ) {
    FD_LOG_WARNING(( "max_values must be a power of 2" ));
    return NULL;
  }
  ulong stake_map_chain_cnt = stake_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_t * gossip  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t),    sizeof(fd_gossip_t)                           );
  void * crds           = FD_SCRATCH_ALLOC_APPEND( l, fd_crds_align(),         fd_crds_footprint( max_values, max_values )   );
  void * active_set     = FD_SCRATCH_ALLOC_APPEND( l, fd_active_set_align(),   fd_active_set_footprint()                     );
  void * ping_tracker   = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len )  );
  void * stake_pool     = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(),      stake_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  void * stake_weights  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),       stake_map_footprint( stake_map_chain_cnt )    );
  void * active_ps      = FD_SCRATCH_ALLOC_APPEND( l, push_set_align(),        push_set_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_gossip_align() ) == (ulong)shmem + fd_gossip_footprint( max_values, entrypoints_len  ) );

  gossip->gossip_net_out  = gossip_net_out;

  gossip->entrypoints_cnt = entrypoints_len;
  fd_memcpy( gossip->entrypoints, entrypoints, entrypoints_len*sizeof(fd_ip4_port_t) );

  gossip->crds = fd_crds_join( fd_crds_new( crds, rng, max_values, max_values, gossip_update_out ) );
  FD_TEST( gossip->crds );

  gossip->active_set = fd_active_set_join( fd_active_set_new( active_set, rng ) );
  FD_TEST( gossip->active_set );

  gossip->ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( ping_tracker, rng, gossip->entrypoints_cnt, gossip->entrypoints, ping_tracker_change, gossip ) );
  FD_TEST( gossip->ping_tracker );

  gossip->stake.count = 0UL;
  gossip->stake.pool = stake_pool_join( stake_pool_new( stake_pool, CRDS_MAX_CONTACT_INFO ) );
  FD_TEST( gossip->stake.pool );

  gossip->stake.map = stake_map_join( stake_map_new( stake_weights, stake_map_chain_cnt, fd_rng_ulong( rng ) ) );
  FD_TEST( gossip->stake.map );

  gossip->active_pset = push_set_join( push_set_new( active_ps, FD_ACTIVE_SET_MAX_PEERS ) );
  FD_TEST( gossip->active_pset );

  FD_TEST( fd_sha256_join( fd_sha256_new( gossip->sha256 ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( gossip->sha512 ) ) );

  gossip->rng = rng;

  gossip->timers.next_pull_request = 0L;
  gossip->timers.next_active_set_refresh = 0L;
  gossip->timers.next_contact_info_refresh = 0L;
  gossip->timers.next_flush_push_state = 0L;

  gossip->send_fn  = send_fn;
  gossip->send_ctx = send_ctx;
  gossip->sign_fn  = sign_fn;
  gossip->sign_ctx = sign_ctx;
  gossip->ping_tracker_change_fn     = ping_tracker_change_fn;
  gossip->ping_tracker_change_fn_ctx = ping_tracker_change_fn_ctx;

  fd_gossip_set_my_contact_info( gossip, my_contact_info, now );

  fd_memset( gossip->metrics, 0, sizeof(fd_gossip_metrics_t) );

  return gossip;
}

fd_gossip_t *
fd_gossip_join( void * shgossip ) {
  if( FD_UNLIKELY( !shgossip ) ) {
    FD_LOG_WARNING(( "NULL shgossip" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shgossip, fd_gossip_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shgossip" ));
    return NULL;
  }

  return (fd_gossip_t *)shgossip;
}

fd_gossip_metrics_t const *
fd_gossip_metrics( fd_gossip_t const * gossip ) {
  return gossip->metrics;
}

fd_crds_metrics_t const *
fd_gossip_crds_metrics( fd_gossip_t const * gossip ) {
  return fd_crds_metrics( gossip->crds );
}

fd_ping_tracker_metrics_t const *
fd_gossip_ping_tracker_metrics( fd_gossip_t const * gossip ) {
  return fd_ping_tracker_metrics( gossip->ping_tracker );
}

static fd_ip4_port_t
random_entrypoint( fd_gossip_t const * gossip ) {
  ulong idx = fd_rng_ulong_roll( gossip->rng, gossip->entrypoints_cnt );
  return gossip->entrypoints[ idx ];
}

static void
txbuild_flush( fd_gossip_t *         gossip,
               fd_gossip_txbuild_t * txbuild,
               fd_stem_context_t *   stem,
               fd_ip4_port_t         dest_addr,
               long                  now ) {
  if( FD_UNLIKELY( !txbuild->crds_len ) ) return;

  gossip->send_fn( gossip->send_ctx, stem, txbuild->bytes, txbuild->bytes_len, &dest_addr, (ulong)now );

  gossip->metrics->message_tx[ txbuild->tag ]++;
  gossip->metrics->message_tx_bytes[ txbuild->tag ] += txbuild->bytes_len+42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
  for( ulong i=0UL; i<txbuild->crds_len; i++ ) {
    if( FD_LIKELY( txbuild->tag==FD_GOSSIP_MESSAGE_PUSH ) ) {
      gossip->metrics->crds_tx_push[ txbuild->crds[ i ].tag ]++;
      gossip->metrics->crds_tx_push_bytes[ txbuild->crds[ i ].tag ] += txbuild->crds[ i ].sz;
    } else {
      gossip->metrics->crds_tx_pull_response[ txbuild->crds[ i ].tag ]++;
      gossip->metrics->crds_tx_pull_response_bytes[ txbuild->crds[ i ].tag ] += txbuild->crds[ i ].sz;
    }
  }

  fd_gossip_txbuild_init( txbuild, gossip->identity_pubkey, txbuild->tag );
}

/* Note: NOT a no-op in the case contact info does not exist. We
   reset and push it back to the last-hit queue instead.

   TODO: Is this desired behavior? */

static void
active_push_set_flush( fd_gossip_t *       gossip,
                       push_set_t *        pset,
                       ulong               idx,
                       fd_stem_context_t * stem,
                       long                now ) {
  fd_contact_info_t const * ci = fd_crds_contact_info_lookup( gossip->crds, fd_active_set_node_pubkey( gossip->active_set, idx ) );
  push_set_entry_t * state = pset_entry_pool_ele( pset->pool, idx );
  if( FD_LIKELY( ci ) ) {
    txbuild_flush( gossip, state->txbuild, stem, fd_contact_info_gossip_socket( ci ), now );
  } else {
    fd_gossip_txbuild_init( state->txbuild, gossip->identity_pubkey, state->txbuild->tag );
  }
  push_set_pop_append( pset, state, now );
}

static void
active_push_set_insert( fd_gossip_t *       gossip,
                        uchar const *       crds_val,
                        ulong               crds_sz,
                        uchar const *       origin_pubkey,
                        ulong               origin_stake,
                        fd_stem_context_t * stem,
                        long                now,
                        int                 flush_immediately ) {
  ulong out_nodes[ 12UL ];
  ulong out_nodes_cnt = fd_active_set_nodes( gossip->active_set,
                                             gossip->identity_pubkey,
                                             gossip->identity_stake,
                                             origin_pubkey,
                                             origin_stake,
                                             0UL, /* ignore_prunes_if_peer_is_origin TODO */
                                             out_nodes );
  for( ulong j=0UL; j<out_nodes_cnt; j++ ) {
    ulong idx = out_nodes[ j ];
    push_set_entry_t * entry = pset_entry_pool_ele( gossip->active_pset->pool, idx );
    if( FD_UNLIKELY( !fd_gossip_txbuild_can_fit( entry->txbuild, crds_sz ) ) ) {
      active_push_set_flush( gossip, gossip->active_pset, idx, stem, now );
    }

    fd_gossip_txbuild_append( entry->txbuild, crds_sz, crds_val );
    push_set_pop_append( gossip->active_pset, entry, now );
    if( FD_UNLIKELY( !!flush_immediately ) ) {
      active_push_set_flush( gossip, gossip->active_pset, idx, stem, now );
    }
  }
}

static void
push_my_contact_info( fd_gossip_t *       gossip,
                      fd_stem_context_t * stem,
                      long now ){
  active_push_set_insert( gossip,
                          gossip->my_contact_info.crds_val,
                          gossip->my_contact_info.crds_val_sz,
                          gossip->identity_pubkey,
                          gossip->identity_stake,
                          stem,
                          now,
                          0 /* flush_immediately */ );
}

static inline void
refresh_contact_info( fd_gossip_t * gossip,
                      long          now ) {
  gossip->my_contact_info.ci->wallclock_nanos = now;
  fd_gossip_contact_info_encode( gossip->my_contact_info.ci,
                                 gossip->my_contact_info.crds_val,
                                 FD_GOSSIP_CRDS_MAX_SZ,
                                 &gossip->my_contact_info.crds_val_sz );
  gossip->sign_fn( gossip->sign_ctx,
                   gossip->my_contact_info.crds_val+64UL,
                   gossip->my_contact_info.crds_val_sz-64UL,
                   FD_KEYGUARD_SIGN_TYPE_ED25519,
                   gossip->my_contact_info.crds_val );

  /* We don't have stem_ctx here so we pre-empt in next
     fd_gossip_advance iteration instead. */
  gossip->timers.next_contact_info_refresh = now;
}

void
fd_gossip_set_my_contact_info( fd_gossip_t *             gossip,
                               fd_contact_info_t const * contact_info,
                               long                      now ) {
  fd_memcpy( gossip->identity_pubkey, contact_info->pubkey.uc, 32UL );

  *gossip->my_contact_info.ci = *contact_info;
  refresh_contact_info( gossip, now );
}

ulong
get_stake( fd_gossip_t const * gossip,
           uchar const *       pubkey ) {
  stake_t const * entry = stake_map_ele_query_const( gossip->stake.map, (fd_pubkey_t const *)pubkey, NULL, gossip->stake.pool );
  if( FD_UNLIKELY( !entry ) ) return 0UL;
  return entry->stake;
}

void
fd_gossip_stakes_update( fd_gossip_t *             gossip,
                         fd_stake_weight_t const * stake_weights,
                         ulong                     stake_weights_cnt ) {
  if( FD_UNLIKELY( stake_weights_cnt>CRDS_MAX_CONTACT_INFO ) ) {
    FD_LOG_ERR(( "stake_weights_cnt %lu exceeds maximum of %d", stake_weights_cnt, CRDS_MAX_CONTACT_INFO ));
  }

  /* Clear the map, this requires us to iterate through all elements and
     individually call map remove. */
  for( ulong i=0UL; i<gossip->stake.count; i++ ) {
    stake_map_idx_remove_fast( gossip->stake.map, i, gossip->stake.pool );
  }

  for( ulong i=0UL; i<stake_weights_cnt; i++ ) {
    stake_t * entry = stake_pool_ele( gossip->stake.pool, i );
    fd_memcpy( entry->pubkey.uc, stake_weights[i].key.uc, 32UL );
    entry->stake = stake_weights[i].stake;

    stake_map_idx_insert( gossip->stake.map, i, gossip->stake.pool );
  }
  /* Update the identity stake */
  gossip->identity_stake = get_stake( gossip, gossip->identity_pubkey );
  gossip->stake.count    = stake_weights_cnt;
}

static void
rx_pull_request( fd_gossip_t *                         gossip,
                 fd_gossip_view_pull_request_t const * pr_view,
                 uchar const *                         payload,
                 fd_ip4_port_t                         peer_addr,
                 fd_stem_context_t *                   stem,
                 long                                  now ) {
  /* TODO: Implement data budget? Or at least limit iteration range */

  fd_bloom_t filter[1];
  filter->keys_len = pr_view->bloom_keys_len;
  filter->keys     = (ulong *)( payload + pr_view->bloom_keys_offset );

  filter->bits_len = pr_view->bloom_bits_cnt;
  filter->bits     = (ulong *)( payload + pr_view->bloom_bits_offset );

  fd_gossip_txbuild_t pull_resp[1];
  fd_gossip_txbuild_init( pull_resp, gossip->identity_pubkey, FD_GOSSIP_MESSAGE_PULL_RESPONSE );

  uchar iter_mem[ 16UL ];

  for( fd_crds_mask_iter_t * it=fd_crds_mask_iter_init( gossip->crds, pr_view->mask, pr_view->mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it=fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_crds_entry_t const * candidate = fd_crds_mask_iter_entry( it, gossip->crds );

    /* TODO: Add jitter here? */
    // if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock_nanos ) ) continue;

    if( FD_UNLIKELY( !fd_bloom_contains( filter, fd_crds_entry_hash( candidate ), 32UL ) ) ) continue;

    uchar const * crds_val;
    ulong         crds_size;
    fd_crds_entry_value( candidate, &crds_val, &crds_size );
    if( FD_UNLIKELY( !fd_gossip_txbuild_can_fit( pull_resp, crds_size ) ) ) {
      txbuild_flush( gossip, pull_resp, stem, peer_addr, now );
    }
    fd_gossip_txbuild_append( pull_resp, crds_size, crds_val );
  }

  txbuild_flush( gossip, pull_resp, stem, peer_addr, now );
}

static void
rx_pull_response( fd_gossip_t *                          gossip,
                  fd_gossip_view_pull_response_t const * pull_response,
                  uchar const *                          payload,
                  fd_stem_context_t *                    stem,
                  long                                   now ) {
  for( ulong i=0UL; i<pull_response->crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &pull_response->crds_values[ i ];

    int checks_res = fd_crds_checks_fast( gossip->crds, value, payload, 0 /* from_push_msg m*/ );
    if( FD_UNLIKELY( !!checks_res ) ) {
      checks_res < 0 ? gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_STALE_IDX ]++
                     : gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_DUPLICATE_IDX ]++;
      continue;
    }

    uchar const * origin_pubkey = payload+value->pubkey_off;
    ulong origin_stake          = get_stake( gossip, origin_pubkey );

    /* TODO: Is this jittered in Agave? */
    long accept_after_nanos;
    uchar is_me = !memcmp( origin_pubkey, gossip->identity_pubkey, 32UL );
    if( FD_UNLIKELY( is_me ) ) {
      accept_after_nanos = 0L;
    } else if( !origin_stake && fd_crds_has_staked_node( gossip->crds ) ) {
      accept_after_nanos = now-15L*1000L*1000L*1000L;
    } else {
      accept_after_nanos = now-432000L*400L*1000L*1000L;
    }

    /* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/crds_gossip_pull.rs#L340-L351 */
    if( FD_UNLIKELY( accept_after_nanos>value->wallclock_nanos &&
                     !fd_crds_contact_info_lookup( gossip->crds, origin_pubkey ) ) ) {
      gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_WALLCLOCK_IDX ]++;
      uchar candidate_hash[ 32UL ];
      fd_crds_generate_hash( gossip->sha256, payload+value->value_off, value->length, candidate_hash );
      fd_crds_insert_failed_insert( gossip->crds, candidate_hash, now );
      continue;
    }

    fd_crds_entry_t const * candidate = fd_crds_insert( gossip->crds,
                                                        value,
                                                        payload,
                                                        origin_stake,
                                                        is_me,
                                                        now,
                                                        stem );
    FD_TEST( candidate );
    gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_UPSERTED_PULL_RESPONSE_IDX ]++;
    if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ){
      fd_contact_info_t const * contact_info = fd_crds_entry_contact_info( candidate );

      fd_ip4_port_t origin_addr = fd_contact_info_gossip_socket( contact_info );
      if( FD_LIKELY( !is_me ) ) fd_ping_tracker_track( gossip->ping_tracker, origin_pubkey, origin_addr, now );
      gossip->metrics->ci_rx_unrecognized_socket_tag_cnt += value->ci_view->unrecognized_socket_tag_cnt;
      gossip->metrics->ci_rx_ipv6_address_cnt            += value->ci_view->ip6_cnt;
    }
    active_push_set_insert( gossip, payload+value->value_off, value->length, origin_pubkey, origin_stake, stem, now, 0 /* flush_immediately */ );
  }
}

/* process_push_crds() > 0 holds the duplicate count */
static int
process_push_crds( fd_gossip_t *                       gossip,
                   fd_gossip_view_crds_value_t const * value,
                   uchar const *                       payload,
                   long                                now,
                   fd_stem_context_t *                 stem ) {
  /* overrides_fast here, either count duplicates or purge if older (how!?) */

  /* return values in both fd_crds_checks_fast and fd_crds_inserted need
     to be propagated since they both work the same (error>0 holds duplicate
     count). This is quite fragile. */
  int checks_res = fd_crds_checks_fast( gossip->crds,
                                        value,
                                        payload,
                                        1 /* from_push_msg */ );
  if( FD_UNLIKELY( !!checks_res ) ) {
    checks_res < 0 ? gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PUSH_STALE_IDX ]++
                   : gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PUSH_DUPLICATE_IDX ]++;
    return checks_res;
  }

  gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_UPSERTED_PUSH_IDX ]++;

  uchar const * origin_pubkey = payload+value->pubkey_off;
  uchar is_me                 = !memcmp( origin_pubkey, gossip->identity_pubkey, 32UL );
  ulong origin_stake          = get_stake( gossip, origin_pubkey );


  fd_crds_entry_t const * candidate = fd_crds_insert( gossip->crds,
                                                      value,
                                                      payload,
                                                      origin_stake,
                                                      is_me,
                                                      now,
                                                      stem );
  FD_TEST( candidate );
  if( FD_UNLIKELY( fd_crds_entry_is_contact_info( candidate ) ) ) {
    fd_contact_info_t const * contact_info = fd_crds_entry_contact_info( candidate );

    fd_ip4_port_t origin_addr = contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
    if( FD_LIKELY( !is_me ) ) fd_ping_tracker_track( gossip->ping_tracker, origin_pubkey, origin_addr, now );
    gossip->metrics->ci_rx_unrecognized_socket_tag_cnt += value->ci_view->unrecognized_socket_tag_cnt;
    gossip->metrics->ci_rx_ipv6_address_cnt            += value->ci_view->ip6_cnt;
  }
  active_push_set_insert( gossip, payload+value->value_off, value->length, origin_pubkey, origin_stake, stem, now, 0 /* flush_immediately */ );
  return 0;
}

static void
rx_push( fd_gossip_t *                 gossip,
         fd_gossip_view_push_t const * push,
         uchar const *                 payload,
         long                          now,
         fd_stem_context_t *           stem ) {
  for( ulong i=0UL; i<push->crds_values_len; i++ ) {
    int err = process_push_crds( gossip, &push->crds_values[ i ], payload, now, stem );
    if( FD_UNLIKELY( err>0 ) ) {
      /* TODO: implement prune finder
      ulong num_duplicates         = (ulong)err;
      uchar const * relayer_pubkey = payload+push->from_off;
      fd_prune_finder_record( gossip->prune_finder,
                              origin_pubkey,
                              origin_stake,
                              relayer_pubkey,
                              get_stake( gossip, relayer_pubkey ),
                              num_duplicates ); */
    }
  }
}

static void
rx_prune( fd_gossip_t *                  gossip,
          uchar const *                  payload,
          fd_gossip_view_prune_t const * prune ) {
  uchar const * push_dest_pubkey = payload+prune->pubkey_off;
  uchar const * origins          = payload+prune->origins_off;
  for( ulong i=0UL; i<prune->origins_len; i++ ) {
    uchar const * origin_pubkey = &origins[ i*32UL ];
    ulong         origin_stake  = get_stake( gossip, origin_pubkey );
    fd_active_set_prune( gossip->active_set,
                         push_dest_pubkey,
                         origin_pubkey,
                         origin_stake,
                         gossip->identity_pubkey,
                         gossip->identity_stake );
  }
}


static void
rx_ping( fd_gossip_t *           gossip,
         fd_gossip_view_ping_t * ping,
         fd_ip4_port_t           peer_address,
         fd_stem_context_t *     stem,
         long                    now ) {
  /* TODO: have this point to dcache buffer directly instead */
  uchar out_payload[ sizeof(fd_gossip_view_pong_t) + 4UL];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PONG );

  fd_gossip_view_pong_t * out_pong = (fd_gossip_view_pong_t *)(out_payload + 4UL);
  fd_memcpy( out_pong->pubkey, gossip->identity_pubkey, 32UL );

  /* fd_keyguard checks payloads for certain patterns before performing the
     sign. Pattern-matching can't be done on hashed data, so we need
     to supply the pre-hashed image to the sign fn (fd_keyguard will hash when
     supplied with FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519) while also hashing
     the image ourselves onto pong->ping_hash */

  uchar pre_image[ 48UL ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, ping->ping_token, 32UL );

  fd_sha256_hash( pre_image, 48UL, out_pong->ping_hash );

  gossip->sign_fn( gossip->sign_ctx, pre_image, 48UL, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, out_pong->signature );
  gossip->send_fn( gossip->send_ctx, stem, (uchar *)out_payload, sizeof(out_payload), &peer_address, (ulong)now );

  gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PONG ]++;
  gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PONG ] += sizeof(out_payload) + 42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
}

static void
rx_pong( fd_gossip_t *           gossip,
         fd_gossip_view_pong_t * pong,
         fd_ip4_port_t           peer_address,
         long                    now ) {
  fd_ping_tracker_register( gossip->ping_tracker, pong->pubkey, peer_address, pong->ping_hash, now );
}

void
fd_gossip_rx( fd_gossip_t *       gossip,
              fd_ip4_port_t       peer,
              uchar const *       data,
              ulong               data_sz,
              long                now,
              fd_stem_context_t * stem ) {
  /* TODO: Implement traffic shaper / bandwidth limiter */
  FD_TEST( data_sz>=sizeof(fd_gossip_view_t) );
  fd_gossip_view_t const * view    = (fd_gossip_view_t const *)data;
  uchar const *            payload = data+sizeof(fd_gossip_view_t);

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      rx_pull_request( gossip, view->pull_request, payload, peer, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      rx_pull_response( gossip, view->pull_response, payload, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      rx_push( gossip, view->push, payload, now, stem );
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      rx_prune( gossip, payload, view->prune );
      break;
    case FD_GOSSIP_MESSAGE_PING:
      rx_ping( gossip, (fd_gossip_view_ping_t *)(payload+view->ping_pong_off), peer, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      rx_pong( gossip, (fd_gossip_view_pong_t *)(payload+view->ping_pong_off), peer, now );
      break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %d", view->tag ));
      break;
  }
}

int
fd_gossip_push_vote( fd_gossip_t *       gossip,
                     uchar const *       txn,
                     ulong               txn_sz,
                     fd_stem_context_t * stem,
                     long                now ) {
  /* TODO: we can avoid addt'l memcpy if we pass a propely laid out
     crds buffer instead */
  uchar                       crds_val[ FD_GOSSIP_CRDS_MAX_SZ ];
  fd_gossip_view_crds_value_t view[1];

  fd_gossip_crds_vote_encode( crds_val,
                              FD_GOSSIP_CRDS_MAX_SZ,
                              txn,
                              txn_sz,
                              gossip->identity_pubkey,
                              now,
                              0UL, /* vote_index TODO */
                              view );

  gossip->sign_fn( gossip->sign_ctx,
                   crds_val+64UL,
                   view->length-64UL,
                   FD_KEYGUARD_SIGN_TYPE_ED25519,
                   crds_val );

  int res = fd_crds_checks_fast( gossip->crds, view, crds_val, 0 );
  if( FD_UNLIKELY( res ) ) return -1;

  fd_crds_entry_t const * entry = fd_crds_insert( gossip->crds, view, crds_val, gossip->identity_stake, 1, /* is_me */ now, stem );
  if( FD_UNLIKELY( !entry ) ) return -1;

  active_push_set_insert( gossip,
                          crds_val,
                          view->length,
                          gossip->identity_pubkey,
                          gossip->identity_stake,
                          stem,
                          now,
                          1 /* flush_immediately */ );
  return 0;
}

static void
tx_ping( fd_gossip_t *       gossip,
         fd_stem_context_t * stem,
         long                now ) {
  /* TODO: have this point to dcache buffer directly instead. */
  uchar out_payload[ sizeof(fd_gossip_view_ping_t) + 4UL ];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PING );

  fd_gossip_view_ping_t * out_ping = (fd_gossip_view_ping_t *)( out_payload + 4UL );
  fd_memcpy( out_ping->pubkey, gossip->identity_pubkey, 32UL );

  uchar const *         peer_pubkey;
  uchar const *         ping_token;
  fd_ip4_port_t const * peer_address;
  while( fd_ping_tracker_pop_request( gossip->ping_tracker,
                                      now,
                                      &peer_pubkey,
                                      &peer_address,
                                      &ping_token ) ) {
    fd_memcpy( out_ping->ping_token, ping_token, 32UL );

    gossip->sign_fn( gossip->sign_ctx, out_ping->ping_token, 32UL, FD_KEYGUARD_SIGN_TYPE_ED25519, out_ping->signature );
    gossip->send_fn( gossip->send_ctx, stem, out_payload, sizeof(out_payload), peer_address, (ulong)now );

    gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PING ]++;
    gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PING ] += sizeof(out_payload) + 42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
  }
}

static void
tx_pull_request( fd_gossip_t *       gossip,
                 fd_stem_context_t * stem,
                 long                now ) {
  ulong total_crds_vals = fd_crds_len( gossip->crds ) + fd_crds_purged_len( gossip->crds );
  ulong num_items       = fd_ulong_max( 512UL, total_crds_vals );

  double max_bits       = (double)fd_gossip_pull_request_max_filter_bits( BLOOM_NUM_KEYS, gossip->my_contact_info.crds_val_sz, FD_GOSSIP_MTU );
  double max_items      = fd_bloom_max_items( max_bits, BLOOM_NUM_KEYS, BLOOM_FALSE_POSITIVE_RATE );
  ulong  num_bits       = fd_bloom_num_bits( max_items, BLOOM_FALSE_POSITIVE_RATE, max_bits );

  double _mask_bits     = ceil( log2( (double)num_items / max_items ) );
  uint   mask_bits      = _mask_bits >= 0.0 ? fd_uint_min( (uint)_mask_bits, 63U ) : 0UL;
  ulong  mask           = fd_rng_ulong( gossip->rng ) | (~0UL>>(mask_bits));

  uchar payload[ FD_GOSSIP_MTU ] = {0};

  ulong payload_sz;
  ulong * keys_ptr, * bits_ptr, * bits_set;

  int res = fd_gossip_pull_request_init( payload,
                                         FD_GOSSIP_MTU,
                                         BLOOM_NUM_KEYS,
                                         num_bits,
                                         mask,
                                         mask_bits,
                                         gossip->my_contact_info.crds_val,
                                         gossip->my_contact_info.crds_val_sz,
                                         &keys_ptr,
                                         &bits_ptr,
                                         &bits_set,
                                         &payload_sz );
  FD_TEST( !res && payload_sz<=FD_GOSSIP_MTU );

  fd_bloom_t filter[1];
  fd_bloom_init_inplace( keys_ptr, bits_ptr, BLOOM_NUM_KEYS, num_bits, 0, gossip->rng, BLOOM_FALSE_POSITIVE_RATE, filter );

  uchar iter_mem[ 16UL ];
  for( fd_crds_mask_iter_t * it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it = fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_bloom_insert( filter, fd_crds_entry_hash( fd_crds_mask_iter_entry( it, gossip->crds ) ), 32UL );
  }

  for( fd_crds_mask_iter_t * it = fd_crds_purged_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_purged_mask_iter_done( it, gossip->crds );
       it = fd_crds_purged_mask_iter_next( it, gossip->crds ) ){
    fd_bloom_insert( filter, fd_crds_purged_mask_iter_hash( it, gossip->crds ), 32UL );
  }

  int num_bits_set = 0;
  for( ulong i=0UL; i<(num_bits+63)/64UL; i++ ) num_bits_set += fd_ulong_popcnt( bits_ptr[ i ] );
  *bits_set = (ulong)num_bits_set;

  fd_contact_info_t const * peer = fd_crds_peer_sample( gossip->crds, gossip->rng );
  fd_ip4_port_t peer_addr;
  if( FD_UNLIKELY( !peer ) ) {
    if( FD_UNLIKELY( !gossip->entrypoints_cnt ) ) {
      /* We are the bootstrapping node, and nobody else is present in
         the cluster.  Nowhere to send the pull request. */
      return;
    }
    peer_addr = random_entrypoint( gossip );
  } else {
    peer_addr = fd_contact_info_gossip_socket( peer );
  }
  gossip->send_fn( gossip->send_ctx, stem, payload, payload_sz, &peer_addr, (ulong)now );

  gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PULL_REQUEST ]++;
  gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PULL_REQUEST ] += payload_sz + 42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
}

static inline long
next_pull_request( fd_gossip_t const * gossip,
                   long                now ) {
  (void)gossip;
  /* TODO: Dynamic, jitter, etc. */
  return now + 32L*1000L*1000L;
}

static inline void
rotate_active_set( fd_gossip_t *       gossip,
                   fd_stem_context_t * stem,
                   long                now ) {
  push_set_t * pset          = gossip->active_pset;
  ulong        replaced_idx  = fd_active_set_rotate( gossip->active_set, gossip->crds );
  if( FD_UNLIKELY( replaced_idx==ULONG_MAX ) ) {
    return;
  }
  push_set_entry_t * entry = pset_entry_pool_ele( pset->pool, replaced_idx );
  if( FD_LIKELY( !!entry->pool.in_use ) ) {
    active_push_set_flush( gossip, pset, replaced_idx, stem, now );
  } else {
    entry->pool.in_use              = 1U;
    entry->last_hit.wallclock_nanos = now;
    pset_last_hit_ele_push_tail( pset->last_hit, entry, pset->pool );
  }

  fd_gossip_txbuild_init( entry->txbuild, gossip->identity_pubkey, FD_GOSSIP_MESSAGE_PUSH );
}

static inline void
flush_stale_push_states( fd_gossip_t *       gossip,
                         fd_stem_context_t * stem,
                         long                now ) {
  long stale_if_before = now-1*1000L*1000L;
  push_set_t * push_set = gossip->active_pset;
  if( FD_UNLIKELY( pset_last_hit_is_empty( push_set->last_hit, push_set->pool ) ) ) return;

  for(;;) {
    push_set_entry_t * entry     = pset_last_hit_ele_peek_head( push_set->last_hit, push_set->pool );
    ulong              entry_idx = pset_entry_pool_idx( push_set->pool, entry );
    if( FD_UNLIKELY( entry->last_hit.wallclock_nanos>stale_if_before ) ) break;
    active_push_set_flush( gossip, push_set, entry_idx, stem, now );
  }
}

void
fd_gossip_advance( fd_gossip_t *       gossip,
                   long                now,
                   fd_stem_context_t * stem ) {
  fd_crds_advance( gossip->crds, now, stem );
  tx_ping( gossip, stem, now );
  flush_stale_push_states( gossip, stem, now );
  if( FD_UNLIKELY( now>=gossip->timers.next_pull_request ) ) {
    tx_pull_request( gossip, stem, now );
    gossip->timers.next_pull_request = next_pull_request( gossip, now );
  }
  if( FD_UNLIKELY( now>=gossip->timers.next_contact_info_refresh ) ) {
    /* TODO: Frequency of this? More often if observing? */
    refresh_contact_info( gossip, now );
    push_my_contact_info( gossip, stem, now);
    gossip->timers.next_contact_info_refresh = now+15L*500L*1000L*1000L; /* TODO: Jitter */
  }
  if( FD_UNLIKELY( now>=gossip->timers.next_active_set_refresh ) ) {
    rotate_active_set( gossip, stem, now );
    gossip->timers.next_active_set_refresh = now+300L*1000L*1000L; /* TODO: Jitter */
  }
}

void
fd_gossip_ping_tracker_track( fd_gossip_t * gossip,
                              uchar const * peer_pubkey,
                              fd_ip4_port_t peer_address,
                              long          now ) {
  fd_ping_tracker_track( gossip->ping_tracker, peer_pubkey, peer_address, now );
}
