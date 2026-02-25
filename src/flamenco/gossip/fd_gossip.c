#include "fd_gossip.h"
#include "fd_bloom.h"
#include "fd_gossip_message.h"
#include "fd_gossip_txbuild.h"
#include "fd_active_set.h"
#include "fd_ping_tracker.h"
#include "crds/fd_crds.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../ballet/sha256/fd_sha256.h"

FD_STATIC_ASSERT( FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT==FD_GOSSIP_MESSAGE_CNT,
                  "FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT must match FD_GOSSIP_MESSAGE_CNT" );

FD_STATIC_ASSERT( FD_METRICS_ENUM_CRDS_VALUE_CNT==FD_GOSSIP_VALUE_CNT,
                  "FD_METRICS_ENUM_CRDS_VALUE_CNT must match FD_GOSSIP_VALUE_CNT" );

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

  fd_crds_t *          crds;
  fd_gossip_purged_t * purged;
  fd_active_set_t *    active_set;
  fd_ping_tracker_t *  ping_tracker;

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
    uchar             crds_val[ FD_GOSSIP_VALUE_MAX_SZ ];
    ulong             crds_val_sz;
    fd_gossip_value_t ci[1];
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_t),     sizeof(fd_gossip_t)                                                     );
  l = FD_LAYOUT_APPEND( l, fd_gossip_purged_align(), fd_gossip_purged_footprint( max_values )                                );
  l = FD_LAYOUT_APPEND( l, fd_crds_align(),          fd_crds_footprint( max_values )                                         );
  l = FD_LAYOUT_APPEND( l, fd_active_set_align(),    fd_active_set_footprint()                                               );
  l = FD_LAYOUT_APPEND( l, fd_ping_tracker_align(),  fd_ping_tracker_footprint( entrypoints_len )                            );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(),       stake_pool_footprint( CRDS_MAX_CONTACT_INFO )                           );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),        stake_map_footprint( stake_map_chain_cnt_est( CRDS_MAX_CONTACT_INFO ) ) );
  l = FD_LAYOUT_APPEND( l, push_set_align(),         push_set_footprint( FD_ACTIVE_SET_MAX_PEERS )                           );
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
    case FD_PING_TRACKER_CHANGE_TYPE_ACTIVE:
      fd_crds_peer_active( ctx->crds, peer_pubkey, 1 );
      if( FD_LIKELY( fd_crds_contact_info_lookup( ctx->crds, peer_pubkey ) ) ) {
        fd_gossip_purged_drain_no_contact_info( ctx->purged, peer_pubkey );
      }
      break;
    case FD_PING_TRACKER_CHANGE_TYPE_INACTIVE:
      fd_crds_peer_active( ctx->crds, peer_pubkey, 0 );
      fd_active_set_remove_peer( ctx->active_set, peer_pubkey );
      break;
    case FD_PING_TRACKER_CHANGE_TYPE_INACTIVE_STAKED: break;
    default: FD_LOG_ERR(( "Unknown change type %d", change_type )); return;
  }

  ctx->ping_tracker_change_fn( ctx->ping_tracker_change_fn_ctx, peer_pubkey, peer_address, now, change_type );
}

void *
fd_gossip_new( void *                           shmem,
               fd_rng_t *                       rng,
               ulong                            max_values,
               ulong                            entrypoints_len,
               fd_ip4_port_t const *            entrypoints,
               uchar const *                    identity_pubkey,
               fd_gossip_contact_info_t const * my_contact_info,
               long                             now,
               fd_gossip_send_fn                send_fn,
               void *                           send_ctx,
               fd_gossip_sign_fn                sign_fn,
               void *                           sign_ctx,
               fd_ping_tracker_change_fn        ping_tracker_change_fn,
               void *                           ping_tracker_change_fn_ctx,
               fd_gossip_activity_update_fn     activity_update_fn,
               void *                           activity_update_fn_ctx,
               fd_gossip_out_ctx_t *            gossip_update_out,
               fd_gossip_out_ctx_t *            gossip_net_out ) {
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
  fd_gossip_t * gossip  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t),     sizeof(fd_gossip_t)                           );
  void * purged         = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_purged_align(), fd_gossip_purged_footprint( max_values )      );
  void * crds           = FD_SCRATCH_ALLOC_APPEND( l, fd_crds_align(),          fd_crds_footprint( max_values )               );
  void * active_set     = FD_SCRATCH_ALLOC_APPEND( l, fd_active_set_align(),    fd_active_set_footprint()                     );
  void * ping_tracker   = FD_SCRATCH_ALLOC_APPEND( l, fd_ping_tracker_align(),  fd_ping_tracker_footprint( entrypoints_len )  );
  void * stake_pool     = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(),       stake_pool_footprint( CRDS_MAX_CONTACT_INFO ) );
  void * stake_weights  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),        stake_map_footprint( stake_map_chain_cnt )    );
  void * active_ps      = FD_SCRATCH_ALLOC_APPEND( l, push_set_align(),         push_set_footprint( FD_ACTIVE_SET_MAX_PEERS ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_gossip_align() ) == (ulong)shmem + fd_gossip_footprint( max_values, entrypoints_len  ) );

  gossip->gossip_net_out  = gossip_net_out;

  gossip->entrypoints_cnt = entrypoints_len;
  fd_memcpy( gossip->entrypoints, entrypoints, entrypoints_len*sizeof(fd_ip4_port_t) );

  gossip->purged = fd_gossip_purged_join( fd_gossip_purged_new( purged, rng, max_values ) );
  FD_TEST( gossip->purged );

  gossip->crds = fd_crds_join( fd_crds_new( crds, rng, max_values, gossip->purged, activity_update_fn, activity_update_fn_ctx, gossip_update_out ) );
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

  gossip->my_contact_info.ci->tag = FD_GOSSIP_VALUE_CONTACT_INFO;
  fd_memcpy( gossip->identity_pubkey, identity_pubkey, 32UL );
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

fd_gossip_purged_metrics_t const *
fd_gossip_purged_metrics2( fd_gossip_t const * gossip ) {
  return fd_gossip_purged_metrics( gossip->purged );
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
  fd_gossip_contact_info_t const * ci = fd_crds_contact_info_lookup( gossip->crds, fd_active_set_node_pubkey( gossip->active_set, idx ) );
  push_set_entry_t * state = pset_entry_pool_ele( pset->pool, idx );
  if( FD_LIKELY( ci ) ) {
    fd_ip4_port_t dest_addr;
    // TODO: Support ipv6, or prevent ending up in set
    dest_addr.addr = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0 : ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
    dest_addr.port = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port;
    txbuild_flush( gossip, state->txbuild, stem, dest_addr, now );
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

static inline void
refresh_contact_info( fd_gossip_t * gossip,
                      long          now ) {
  fd_memcpy( gossip->my_contact_info.ci->origin, gossip->identity_pubkey, 32UL );
  gossip->my_contact_info.ci->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );
  long sz = fd_gossip_value_serialize( gossip->my_contact_info.ci, gossip->my_contact_info.crds_val, FD_GOSSIP_VALUE_MAX_SZ );
  FD_TEST( sz!=-1L );
  gossip->my_contact_info.crds_val_sz = (ulong)sz;

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
fd_gossip_set_my_contact_info( fd_gossip_t *                    gossip,
                               fd_gossip_contact_info_t const * contact_info,
                               long                             now ) {
  *gossip->my_contact_info.ci->contact_info = *contact_info;
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
fd_gossip_set_identity( fd_gossip_t * gossip,
                        uchar const * identity_pubkey,
                        long          now ) {
  uchar old_identity[ 32UL ];
  fd_memcpy( old_identity, gossip->identity_pubkey, 32UL );

  int identity_changed = !!memcmp( old_identity, identity_pubkey, 32UL );

  if( FD_UNLIKELY( identity_changed ) ) {
    /* The new identity may already exist in CRDS as a normal peer
       (active in the wsample and potentially present in the active
       set).  We must deactivate it before updating identity_pubkey to
       maintain the invariant that our own identity is never sampleable.

       Deactivate in wsample first (zeroes all 26 tree weights), then
       remove from active set.  fd_active_set_remove_peer assumes the
       peer's bucket weights are already zeroed. */
    fd_crds_peer_active( gossip->crds, identity_pubkey, 0 );
    fd_active_set_remove_peer( gossip->active_set, identity_pubkey );
  }

  fd_memcpy( gossip->identity_pubkey, identity_pubkey, 32UL );
  gossip->identity_stake = get_stake( gossip, identity_pubkey );
  fd_crds_self_stake( gossip->crds, gossip->identity_stake );
  refresh_contact_info( gossip, now );

  if( FD_UNLIKELY( identity_changed ) ) {
    /* The old identity is now a normal peer.  If the ping tracker
       considers it active (validated via pong), restore its weights
       in the wsample so it becomes sampleable.  If not, it stays
       inactive and will be activated naturally when/if the ping
       tracker fires an ACTIVE callback for it.

       Note: identity_pubkey has been updated, so the filter in
       ping_tracker_change now blocks the new identity (correct) and
       allows the old identity through (correct). */
    if( fd_ping_tracker_active( gossip->ping_tracker, old_identity ) ) {
      fd_crds_peer_active( gossip->crds, old_identity, 1 );
    }
  }
}

void
fd_gossip_stakes_update( fd_gossip_t *             gossip,
                         fd_stake_weight_t const * stake_weights,
                         ulong                     stake_weights_cnt ) {
  FD_TEST( stake_weights_cnt<=CRDS_MAX_CONTACT_INFO );

  stake_map_reset( gossip->stake.map );

  for( ulong i=0UL; i<stake_weights_cnt; i++ ) {
    stake_t * entry = stake_pool_ele( gossip->stake.pool, i );
    fd_memcpy( entry->pubkey.uc, stake_weights[ i ].key.uc, 32UL );
    entry->stake = stake_weights[ i ].stake;

    stake_map_idx_insert( gossip->stake.map, i, gossip->stake.pool );
  }

  gossip->identity_stake = get_stake( gossip, gossip->identity_pubkey );
  fd_crds_self_stake( gossip->crds, gossip->identity_stake );
  gossip->stake.count    = stake_weights_cnt;
}

static void
rx_pull_request( fd_gossip_t *                    gossip,
                 fd_gossip_pull_request_t const * pr_view,
                 fd_ip4_port_t                    peer_addr,
                 fd_stem_context_t *              stem,
                 long                             now ) {
  /* TODO: Implement data budget? Or at least limit iteration range */

  ulong keys[ sizeof(pr_view->crds_filter->filter->keys)/sizeof(ulong) ];
  ulong bits[ sizeof(pr_view->crds_filter->filter->bits)/sizeof(ulong) ];
  fd_memcpy( keys, pr_view->crds_filter->filter->keys, sizeof(pr_view->crds_filter->filter->keys) );
  fd_memcpy( bits, pr_view->crds_filter->filter->bits, sizeof(pr_view->crds_filter->filter->bits) );

  fd_bloom_t filter[1];
  filter->keys_len = pr_view->crds_filter->filter->keys_len;
  filter->keys = keys;

  filter->bits_len = pr_view->crds_filter->filter->bits_len;
  filter->bits     = bits;

  fd_gossip_txbuild_t pull_resp[1];
  fd_gossip_txbuild_init( pull_resp, gossip->identity_pubkey, FD_GOSSIP_MESSAGE_PULL_RESPONSE );

  uchar iter_mem[ 16UL ];

  for( fd_crds_mask_iter_t * it=fd_crds_mask_iter_init( gossip->crds, pr_view->crds_filter->mask, pr_view->crds_filter->mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it=fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_crds_entry_t const * candidate = fd_crds_mask_iter_entry( it, gossip->crds );

    /* TODO: Add jitter here? */
    // if( FD_UNLIKELY( fd_crds_value_wallclock( candidate )>contact_info->wallclock_nanos ) ) continue;

    if( FD_UNLIKELY( fd_bloom_contains( filter, fd_crds_entry_hash( candidate ), 32UL ) ) ) continue;

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
rx_values( fd_gossip_t *             gossip,
           ulong                     values_len,
           fd_gossip_value_t const * values,
           uchar const *             payload,
           uchar const *             failed,
           fd_stem_context_t *       stem,
           long                      now,
           long                      results[ static 17UL ] ) {
  for( ulong i=0UL; i<values_len; i++ ) {
    fd_gossip_value_t const * value = &values[ i ];

    if( FD_UNLIKELY( failed[ i ] ) ) {
      uchar candidate_hash[ 32UL ];
      fd_sha256_hash( payload+value->offset, value->length, candidate_hash );
      if( FD_LIKELY( failed[ i ]==FD_GOSSIP_FAILED_NO_CONTACT_INFO ) ) fd_gossip_purged_insert_no_contact_info( gossip->purged, value->origin, candidate_hash, now );
      else                                                             fd_gossip_purged_insert_failed_insert( gossip->purged, candidate_hash, now );
      continue;
    }

    ulong origin_stake = get_stake( gossip, value->origin );
    int origin_active = fd_ping_tracker_active( gossip->ping_tracker, value->origin );
    int is_me = !memcmp( value->origin, gossip->identity_pubkey, 32UL );

    results[ i ] = fd_crds_insert( gossip->crds, value, payload+value->offset, value->length, origin_stake, origin_active, is_me, now, stem );
    if( FD_UNLIKELY( results[ i ] ) ) continue;

    if( FD_UNLIKELY( value->tag==FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
      fd_ip4_port_t origin_addr = {
        .addr = value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0U : value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4,
        .port = value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port
      };
      if( FD_LIKELY( !is_me ) ) fd_ping_tracker_track( gossip->ping_tracker, value->origin, origin_stake, origin_addr, now );

      /* We just learned this peer's contact info.  Drain any
         no_contact_info hashes associated with this origin from the
         purged set so peers re-send those CRDS values. */
      if( FD_LIKELY( fd_ping_tracker_active( gossip->ping_tracker, value->origin ) ) ) fd_gossip_purged_drain_no_contact_info( gossip->purged, value->origin );
    }

    active_push_set_insert( gossip, payload+value->offset, value->length, value->origin, origin_stake, stem, now, 0 /* flush_immediately */ );
  }
}

static void
rx_pull_response( fd_gossip_t *                     gossip,
                  fd_gossip_pull_response_t const * pull_response,
                  uchar const *                     payload,
                  uchar const *                     failed,
                  fd_stem_context_t *               stem,
                  long                              now ) {
  long results[ 17UL ];
  rx_values( gossip, pull_response->values_len, pull_response->values, payload, failed, stem, now, results );
  for( ulong i=0UL; i<pull_response->values_len; i++ ) {
    if( FD_UNLIKELY( failed[ i ] ) ) continue;
    if( FD_LIKELY( !results[ i ] ) ) gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_UPSERTED_PULL_RESPONSE_IDX ]++;
    else if( results[ i ]<0L )       gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_STALE_IDX ]++;
    else                             gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_DUPLICATE_IDX ]++;
  }
}

static void
rx_push( fd_gossip_t *            gossip,
         fd_gossip_push_t const * push,
         uchar const *            payload,
         uchar const *            failed,
         long                     now,
         fd_stem_context_t *      stem ) {
  long results[ 17UL ];
  rx_values( gossip, push->values_len, push->values, payload, failed, stem, now, results );
  for( ulong i=0UL; i<push->values_len; i++ ) {
    if( FD_UNLIKELY( failed[ i ] ) ) continue;
    if( FD_LIKELY( !results[ i ] ) ) gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_UPSERTED_PUSH_IDX ]++;
    else if( results[ i ]<0L )       gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PUSH_STALE_IDX ]++;
    else                             gossip->metrics->crds_rx_count[ FD_METRICS_ENUM_GOSSIP_CRDS_OUTCOME_V_DROPPED_PUSH_DUPLICATE_IDX ]++;
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

static void
rx_prune( fd_gossip_t *             gossip,
          fd_gossip_prune_t const * prune ) {
  for( ulong i=0UL; i<prune->prunes_len; i++ ) {
    fd_active_set_prune( gossip->active_set,
                         prune->pubkey,
                         prune->prunes[ i ],
                         get_stake( gossip, prune->prunes[ i ] ),
                         gossip->identity_pubkey,
                         gossip->identity_stake );
  }
}


static void
rx_ping( fd_gossip_t *            gossip,
         fd_gossip_ping_t const * ping,
         fd_ip4_port_t            peer_address,
         fd_stem_context_t *      stem,
         long                     now ) {
  /* TODO: have this point to dcache buffer directly instead */
  uchar out_payload[ sizeof(fd_gossip_pong_t)+4UL];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PONG );

  fd_gossip_pong_t * out_pong = (fd_gossip_pong_t *)(out_payload + 4UL);
  fd_memcpy( out_pong->from, gossip->identity_pubkey, 32UL );

  /* fd_keyguard checks payloads for certain patterns before performing the
     sign. Pattern-matching can't be done on hashed data, so we need
     to supply the pre-hashed image to the sign fn (fd_keyguard will hash when
     supplied with FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519) while also hashing
     the image ourselves onto pong->ping_hash */

  uchar pre_image[ 48UL ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, ping->token, 32UL );

  fd_sha256_hash( pre_image, 48UL, out_pong->hash );

  gossip->sign_fn( gossip->sign_ctx, pre_image, 48UL, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, out_pong->signature );
  gossip->send_fn( gossip->send_ctx, stem, out_payload, sizeof(out_payload), &peer_address, (ulong)now );

  gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PONG ]++;
  gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PONG ] += sizeof(out_payload)+42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
}

static void
rx_pong( fd_gossip_t *            gossip,
         fd_gossip_pong_t const * pong,
         fd_ip4_port_t            peer_address,
         long                     now ) {
  ulong stake = get_stake( gossip, pong->from );
  fd_ping_tracker_register( gossip->ping_tracker, pong->from, stake, peer_address, pong->hash, now );
}

void
fd_gossip_rx( fd_gossip_t *       gossip,
              fd_ip4_port_t       peer,
              uchar const *       data,
              ulong               data_sz,
              long                now,
              fd_stem_context_t * stem ) {
  /* TODO: Implement traffic shaper / bandwidth limiter */
  FD_TEST( data_sz>=sizeof(fd_gossip_message_t)+FD_GOSSIP_MESSAGE_MAX_CRDS );
  fd_gossip_message_t const * message = (fd_gossip_message_t const *)data;
  uchar const *               failed  = data+sizeof(fd_gossip_message_t);
  uchar const *               payload = data+sizeof(fd_gossip_message_t)+FD_GOSSIP_MESSAGE_MAX_CRDS;

  switch( message->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:  rx_pull_request( gossip, message->pull_request, peer, stem, now );              break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: rx_pull_response( gossip, message->pull_response, payload, failed, stem, now ); break;
    case FD_GOSSIP_MESSAGE_PUSH:          rx_push( gossip, message->push, payload, failed, now, stem );                   break;
    case FD_GOSSIP_MESSAGE_PRUNE:         rx_prune( gossip, message->prune );                                             break;
    case FD_GOSSIP_MESSAGE_PING:          rx_ping( gossip, message->ping, peer, stem, now );                              break;
    case FD_GOSSIP_MESSAGE_PONG:          rx_pong( gossip, message->pong, peer, now );                                    break;
    default:
      FD_LOG_CRIT(( "Unknown gossip message type %u", message->tag ));
      break;
  }
}

static int
fd_gossip_push( fd_gossip_t *             gossip,
                fd_gossip_value_t const * value,
                fd_stem_context_t *       stem,
                long                      now ) {
  uchar serialized[ FD_GOSSIP_VALUE_MAX_SZ ];
  long serialized_sz = fd_gossip_value_serialize( value, serialized, sizeof(serialized) );
  FD_TEST( serialized_sz!=-1L );
  gossip->sign_fn( gossip->sign_ctx, serialized+64UL, (ulong)serialized_sz-64UL, FD_KEYGUARD_SIGN_TYPE_ED25519, serialized );

  int origin_active = fd_ping_tracker_active( gossip->ping_tracker, value->origin );
  if( FD_UNLIKELY( fd_crds_insert( gossip->crds, value, serialized, (ulong)serialized_sz, gossip->identity_stake, origin_active, 1, now, stem ) ) ) return -1;

  active_push_set_insert( gossip, serialized, (ulong)serialized_sz, gossip->identity_pubkey, gossip->identity_stake, stem, now, 1 );
  return 0;
}

int
fd_gossip_push_vote( fd_gossip_t *       gossip,
                     uchar const *       txn,
                     ulong               txn_sz,
                     fd_stem_context_t * stem,
                     long                now ) {
  fd_gossip_value_t value = {
    .tag = FD_GOSSIP_VALUE_VOTE,
    .wallclock = (ulong)FD_NANOSEC_TO_MILLI( now ),
    .vote = {{
      .index = 0UL, /* TODO */
      .transaction_len = txn_sz,
    }}
  };
  fd_memcpy( value.origin, gossip->identity_pubkey, 32UL );
  fd_memcpy( value.vote->transaction, txn, txn_sz );

  return fd_gossip_push( gossip, &value, stem, now );
}

int
fd_gossip_push_duplicate_shred( fd_gossip_t *                       gossip,
                                fd_gossip_duplicate_shred_t const * duplicate_shred,
                                fd_stem_context_t *                 stem,
                                long                                now ) {
  fd_gossip_value_t value = {
    .tag = FD_GOSSIP_VALUE_DUPLICATE_SHRED,
    .wallclock = (ulong)FD_NANOSEC_TO_MILLI( now ),
  };
  fd_memcpy( value.origin, gossip->identity_pubkey, 32UL );
  *value.duplicate_shred = *duplicate_shred;

  return fd_gossip_push( gossip, &value, stem, now );
}

static void
tx_ping( fd_gossip_t *       gossip,
         fd_stem_context_t * stem,
         long                now ) {
  /* TODO: have this point to dcache buffer directly instead. */
  uchar out_payload[ sizeof(fd_gossip_ping_t) + 4UL ];
  FD_STORE( uint, out_payload, FD_GOSSIP_MESSAGE_PING );

  fd_gossip_ping_t * out_ping = (fd_gossip_ping_t *)( out_payload+4UL );
  fd_memcpy( out_ping->from, gossip->identity_pubkey, 32UL );

  uchar const *         peer_pubkey;
  uchar const *         ping_token;
  fd_ip4_port_t const * peer_address;
  while( fd_ping_tracker_pop_request( gossip->ping_tracker,
                                      now,
                                      &peer_pubkey,
                                      &peer_address,
                                      &ping_token ) ) {
    fd_memcpy( out_ping->token, ping_token, 32UL );

    gossip->sign_fn( gossip->sign_ctx, out_ping->token, 32UL, FD_KEYGUARD_SIGN_TYPE_ED25519, out_ping->signature );
    gossip->send_fn( gossip->send_ctx, stem, out_payload, sizeof(out_payload), peer_address, (ulong)now );

    gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PING ]++;
    gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PING ] += sizeof(out_payload) + 42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
  }
}

FD_FN_CONST static inline ulong
fd_gossip_pull_request_max_filter_bits( ulong num_keys,
                                        ulong contact_info_crds_sz,
                                        ulong payload_sz ) {
  return 8UL*( payload_sz
             - 4UL          /* discriminant */
             - 8UL          /* keys len */
             - 8UL*num_keys /* keys */
             - 1UL          /* has_bits */
             - 8UL          /* bloom vec len */
             - 8UL          /* bloom bits count */
             - 8UL          /* bloom num bits set */
             - 8UL          /* mask */
             - 4UL          /* mask bits */
             - contact_info_crds_sz ); /* contact info CRDS val */
}

static void
tx_pull_request( fd_gossip_t *       gossip,
                 fd_stem_context_t * stem,
                 long                now ) {
  ulong total_crds_vals = fd_crds_len( gossip->crds ) + fd_gossip_purged_len( gossip->purged );
  ulong num_items       = fd_ulong_max( 512UL, total_crds_vals );

  double max_bits       = (double)fd_gossip_pull_request_max_filter_bits( BLOOM_NUM_KEYS, gossip->my_contact_info.crds_val_sz, FD_GOSSIP_MTU );
  double max_items      = fd_bloom_max_items( max_bits, BLOOM_NUM_KEYS, BLOOM_FALSE_POSITIVE_RATE );
  ulong  num_bits       = fd_bloom_num_bits( max_items, BLOOM_FALSE_POSITIVE_RATE, max_bits );

  double _mask_bits     = ceil( log2( (double)num_items / max_items ) );
  uint   mask_bits      = _mask_bits >= 0.0 ? fd_uint_min( (uint)_mask_bits, 63U ) : 0UL;
  ulong  mask           = fd_rng_ulong( gossip->rng ) | (~0UL>>(mask_bits));

  uchar payload[ FD_GOSSIP_MTU ] = {0};

  ulong * keys_ptr, * bits_ptr, * bits_set;
  long payload_sz = fd_gossip_pull_request_init( payload,
                                                 FD_GOSSIP_MTU,
                                                 BLOOM_NUM_KEYS,
                                                 num_bits,
                                                 mask,
                                                 mask_bits,
                                                 gossip->my_contact_info.crds_val,
                                                 gossip->my_contact_info.crds_val_sz,
                                                 &keys_ptr,
                                                 &bits_ptr,
                                                 &bits_set );
  FD_TEST( -1L!=payload_sz );

  fd_bloom_t filter[1];
  fd_bloom_init_inplace( keys_ptr, bits_ptr, BLOOM_NUM_KEYS, num_bits, 0, gossip->rng, BLOOM_FALSE_POSITIVE_RATE, filter );

  uchar iter_mem[ 16UL ];
  for( fd_crds_mask_iter_t * it = fd_crds_mask_iter_init( gossip->crds, mask, mask_bits, iter_mem );
       !fd_crds_mask_iter_done( it, gossip->crds );
       it = fd_crds_mask_iter_next( it, gossip->crds ) ) {
    fd_bloom_insert( filter, fd_crds_entry_hash( fd_crds_mask_iter_entry( it, gossip->crds ) ), 32UL );
  }

  for( fd_gossip_purged_mask_iter_t * it = fd_gossip_purged_mask_iter_init( gossip->purged, mask, mask_bits, iter_mem );
       !fd_gossip_purged_mask_iter_done( it, gossip->purged );
       it = fd_gossip_purged_mask_iter_next( it, gossip->purged ) ){
    fd_bloom_insert( filter, fd_gossip_purged_mask_iter_hash( it, gossip->purged ), 32UL );
  }

  int num_bits_set = 0;
  for( ulong i=0UL; i<(num_bits+63)/64UL; i++ ) num_bits_set += fd_ulong_popcnt( bits_ptr[ i ] );
  *bits_set = (ulong)num_bits_set;

  fd_gossip_contact_info_t const * peer = fd_crds_peer_sample( gossip->crds );
  fd_ip4_port_t peer_addr;
  if( FD_UNLIKELY( !peer ) ) {
    if( FD_UNLIKELY( !gossip->entrypoints_cnt ) ) {
      /* We are the bootstrapping node, and nobody else is present in
         the cluster.  Nowhere to send the pull request. */
      return;
    }
    peer_addr = random_entrypoint( gossip );
  } else {
    peer_addr.addr = peer->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0 : peer->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
    peer_addr.port = peer->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port;
  }
  gossip->send_fn( gossip->send_ctx, stem, payload, (ulong)payload_sz, &peer_addr, (ulong)now );

  gossip->metrics->message_tx[ FD_GOSSIP_MESSAGE_PULL_REQUEST ]++;
  gossip->metrics->message_tx_bytes[ FD_GOSSIP_MESSAGE_PULL_REQUEST ] += (ulong)payload_sz + 42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
}

static inline long
next_pull_request( fd_gossip_t const * gossip,
                   long                now ) {
  (void)gossip;
  /* TODO: Dynamic, jitter, etc. */
  return now+1600L*1000L;
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
  fd_gossip_purged_expire( gossip->purged, now );
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
    active_push_set_insert( gossip, gossip->my_contact_info.crds_val, gossip->my_contact_info.crds_val_sz, gossip->identity_pubkey, gossip->identity_stake, stem, now, 0 );
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
  ulong origin_stake = get_stake( gossip, peer_pubkey );
  fd_ping_tracker_track( gossip->ping_tracker, peer_pubkey, origin_stake, peer_address, now );
}
