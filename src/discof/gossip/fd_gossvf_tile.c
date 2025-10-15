#include "fd_gossip_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../flamenco/gossip/fd_gossip_private.h"
#include "../../flamenco/gossip/fd_ping_tracker.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../util/net/fd_net_headers.h"
#include "generated/fd_gossvf_tile_seccomp.h"

#define DEBUG_PEERS (0)

#define IN_KIND_SHRED_VERSION (0)
#define IN_KIND_NET           (1)
#define IN_KIND_REPLAY        (2)
#define IN_KIND_PINGS         (3)
#define IN_KIND_GOSSIP        (4)

struct peer {
  fd_pubkey_t pubkey;

  fd_ip4_port_t gossip_addr;
  ushort shred_version;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct peer peer_t;

struct ping {
  fd_pubkey_t pubkey;
  fd_ip4_port_t addr;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct ping ping_t;

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

#define POOL_NAME  peer_pool
#define POOL_T     peer_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               peer_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              peer_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME  ping_pool
#define POOL_T     ping_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               ping_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              ping_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#include "../../util/tmpl/fd_map_chain.c"

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

struct fd_gossvf_tile_ctx {
  long instance_creation_wallclock_nanos;
  ushort shred_version;

  int allow_private_address;

  fd_keyswitch_t * keyswitch;
  fd_pubkey_t identity_pubkey[1];

  fd_ip4_port_t entrypoints[ 16UL ];
  ulong         entrypoints_cnt;

#if DEBUG_PEERS
  ulong peer_cnt;
  ulong ping_cnt;
#endif

  peer_t * peers;
  peer_map_t * peer_map;

  ping_t * pings;
  ping_map_t * ping_map;

  struct {
    ulong         count;
    stake_t *     pool;
    stake_map_t * map;
    uchar         msg_buf[ FD_STAKE_CI_STAKE_MSG_SZ ];
  } stake;

  uchar payload[ FD_NET_MTU ];
  fd_ip4_port_t peer;

  fd_gossip_ping_update_t _ping_update[1];
  fd_gossip_update_message_t _gossip_update[1];

  double ticks_per_ns;
  long   last_wallclock;
  long   last_tickcount;

  ulong seed;

  ulong round_robin_idx;
  ulong round_robin_cnt;

  fd_sha256_t sha256[1];
  fd_sha512_t sha[ 1 ];

  struct {
    ulong   depth;
    ulong   map_cnt;
    ulong * sync;
    ulong * ring;
    ulong * map;
  } tcache;

  struct {
    int         kind;
    ulong       chunk0;
    ulong       wmark;
    fd_wksp_t * mem;
    ulong       mtu;
  } in[ 64UL ];

  struct {
    ulong       chunk0;
    ulong       chunk;
    ulong       wmark;
    fd_wksp_t * mem;
  } out[ 1 ];

  struct {
    ulong message_rx[ FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_CNT ];
    ulong message_rx_bytes[ FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_CNT ];
    ulong crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_CNT ];
    ulong crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_CNT ];
  } metrics;
};

typedef struct fd_gossvf_tile_ctx fd_gossvf_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_gossvf_tile_ctx_t ), sizeof( fd_gossvf_tile_ctx_t )                                );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),               peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE )             );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),                peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE )          );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),               ping_pool_footprint( FD_PING_TRACKER_MAX )                    );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),                ping_map_footprint( 2UL*FD_PING_TRACKER_MAX )                 );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(),              stake_pool_footprint( MAX_STAKED_LEADERS )                    );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),               stake_map_footprint( fd_ulong_pow2_up( MAX_STAKED_LEADERS ) ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(),               fd_tcache_footprint( tile->gossvf.tcache_depth, 0UL )         );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_gossvf_tile_ctx_t * ctx ) {
  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    memcpy( ctx->identity_pubkey->uc, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_gossvf_tile_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( GOSSVF, MESSAGE_RX_COUNT, ctx->metrics.message_rx );
  FD_MCNT_ENUM_COPY( GOSSVF, MESSAGE_RX_BYTES, ctx->metrics.message_rx_bytes );
  FD_MCNT_ENUM_COPY( GOSSVF, CRDS_RX_COUNT, ctx->metrics.crds_rx );
  FD_MCNT_ENUM_COPY( GOSSVF, CRDS_RX_BYTES, ctx->metrics.crds_rx_bytes );
}

static int
before_frag( fd_gossvf_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig ) {
  if( FD_UNLIKELY( !ctx->shred_version && ctx->in[ in_idx ].kind!=IN_KIND_SHRED_VERSION ) ) return -1;

  switch( ctx->in[ in_idx ].kind ) {
    case IN_KIND_SHRED_VERSION: return 0;
    case IN_KIND_NET: return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
    case IN_KIND_REPLAY: return 0;
    case IN_KIND_PINGS: return 0;
    case IN_KIND_GOSSIP: return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
                                sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
    default: FD_LOG_ERR(( "unexpected in_kind %d", ctx->in[ in_idx ].kind )); return -1;
  }
}

static inline void
during_frag( fd_gossvf_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, ctx->in[ in_idx ].mtu ));

  switch( ctx->in[ in_idx ].kind ) {
    case IN_KIND_SHRED_VERSION: {
      ctx->shred_version = (ushort)sig;
      FD_TEST( ctx->shred_version );
      break;
    }
    case IN_KIND_NET: {
      uchar * src = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      fd_memcpy( ctx->payload, src, sz );
      break;
    }
    case IN_KIND_REPLAY: {
      fd_stake_weight_msg_t const * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( msg->staked_cnt>MAX_STAKED_LEADERS ) )
        FD_LOG_ERR(( "Malformed stake update with %lu stakes in it, but the maximum allowed is %lu", msg->staked_cnt, MAX_SHRED_DESTS ));
      ulong msg_sz = FD_STAKE_CI_STAKE_MSG_RECORD_SZ*msg->staked_cnt+FD_STAKE_CI_STAKE_MSG_HEADER_SZ;
      fd_memcpy( ctx->stake.msg_buf, msg, msg_sz );
      break;
    }
    case IN_KIND_PINGS: {
      fd_memcpy( ctx->_ping_update, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sz );
      break;
    }
    case IN_KIND_GOSSIP:
      FD_TEST( sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO || sz==FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE );
      fd_memcpy( ctx->_gossip_update, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sz );
      break;
    default:
      FD_LOG_ERR(( "unexpected in_kind %d", ctx->in[ in_idx ].kind ));
  }
}

static inline void
handle_stakes( fd_gossvf_tile_ctx_t *        ctx,
               fd_stake_weight_msg_t const * msg ) {
  fd_stake_weight_t stake_weights[ MAX_STAKED_LEADERS ];
  ulong new_stakes_cnt = compute_id_weights_from_vote_weights( stake_weights, msg->weights, msg->staked_cnt );

  for( ulong i=0UL; i<ctx->stake.count; i++ ) {
    stake_map_idx_remove_fast( ctx->stake.map, i, ctx->stake.pool );
  }

  for( ulong i=0UL; i<new_stakes_cnt; i++ ) {
    stake_t * entry = stake_pool_ele( ctx->stake.pool, i );
    fd_memcpy( entry->pubkey.uc, stake_weights[i].key.uc, 32UL );
    entry->stake = stake_weights[i].stake;

    stake_map_idx_insert( ctx->stake.map, i, ctx->stake.pool );
  }
  ctx->stake.count = new_stakes_cnt;
}

static int
verify_prune( fd_gossip_view_prune_t const * view,
              uchar const *                  payload,
              fd_sha512_t *                  sha ) {
  uchar sign_data[ FD_NET_MTU ];
  fd_memcpy(       sign_data,                             "\xffSOLANA_PRUNE_DATA",       18UL );
  fd_memcpy(       sign_data+18UL,                        payload+view->pubkey_off,      32UL );
  FD_STORE( ulong, sign_data+50UL,                        view->origins_len );
  fd_memcpy(       sign_data+58UL,                        payload+view->origins_off,     view->origins_len*32UL );
  fd_memcpy(       sign_data+58UL+view->origins_len*32UL, payload+view->destination_off, 32UL );
  FD_STORE( ulong, sign_data+90UL+view->origins_len*32UL, view->wallclock );

  ulong sign_data_len = 98UL+view->origins_len*32UL;
  int err_prefix    = fd_ed25519_verify( sign_data,      sign_data_len,      payload+view->signature_off, payload+view->pubkey_off, sha );
  int err_no_prefix = fd_ed25519_verify( sign_data+18UL, sign_data_len-18UL, payload+view->signature_off, payload+view->pubkey_off, sha );

  if( FD_LIKELY( err_prefix==FD_ED25519_SUCCESS || err_no_prefix==FD_ED25519_SUCCESS ) ) return 0;
  else                                                                                   return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PRUNE_SIGNATURE_IDX;
}

static int
verify_crds_value( fd_gossip_view_crds_value_t const * value,
                   uchar const *                       payload,
                   fd_sha512_t *                       sha ) {
  return fd_ed25519_verify( payload+value->signature_off+64UL, /* signable data begins after signature */
                            value->length-64UL,                /* signable data length */
                            payload+value->signature_off,
                            payload+value->pubkey_off,
                            sha );
}

static int
verify_signatures( fd_gossvf_tile_ctx_t * ctx,
                   fd_gossip_view_t *     view,
                   uchar const *          payload,
                   fd_sha512_t *          sha ) {
  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST: {
      if( FD_UNLIKELY( FD_ED25519_SUCCESS!=verify_crds_value( view->pull_request->pr_ci, payload, sha ) ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_SIGNATURE_IDX;
      } else {
        return 0;
      }
    }
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: {
      ulong i = 0UL;
      while( i<view->pull_response->crds_values_len ) {
        ulong dedup_tag = ctx->seed ^ fd_ulong_load_8_fast( payload+view->pull_response->crds_values[ i ].signature_off );
        int ha_dup = 0;
        FD_FN_UNUSED ulong tcache_map_idx = 0; /* ignored */
        FD_TCACHE_QUERY( ha_dup, tcache_map_idx, ctx->tcache.map, ctx->tcache.map_cnt, dedup_tag );
        if( FD_UNLIKELY( ha_dup ) ) {
          ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_DUPLICATE_IDX ]++;
          ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_DUPLICATE_IDX ] += view->pull_response->crds_values[ i ].length;
          view->pull_response->crds_values[ i ] = view->pull_response->crds_values[ view->pull_response->crds_values_len-1UL ];
          view->pull_response->crds_values_len--;
          continue;
        }

        int err = verify_crds_value( &view->pull_response->crds_values[ i ], payload, sha );
        if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) {
          ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_SIGNATURE_IDX ]++;
          ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_SIGNATURE_IDX ] += view->pull_response->crds_values[ i ].length;
          view->pull_response->crds_values[ i ] = view->pull_response->crds_values[ view->pull_response->crds_values_len-1UL ];
          view->pull_response->crds_values_len--;
          continue;
        }

        i++;
      }

      if( FD_UNLIKELY( !view->pull_response->crds_values_len ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_RESPONSE_NO_VALID_CRDS_IDX;
      return 0;
    }
    case FD_GOSSIP_MESSAGE_PUSH: {
      ulong i = 0UL;
      while( i<view->push->crds_values_len ) {
        int err = verify_crds_value( &view->push->crds_values[ i ], payload, sha );
        if( FD_UNLIKELY( err!=FD_ED25519_SUCCESS ) ) {
          ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_SIGNATURE_IDX ]++;
          ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_SIGNATURE_IDX ] += view->push->crds_values[ i ].length;
          view->push->crds_values[ i ] = view->push->crds_values[ view->push->crds_values_len-1UL ];
          view->push->crds_values_len--;
          continue;
        }

        i++;
      }

      if( FD_UNLIKELY( !view->push->crds_values_len ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PUSH_NO_VALID_CRDS_IDX;
      return 0;
    }
    case FD_GOSSIP_MESSAGE_PRUNE: return verify_prune( view->prune, payload, sha );
    case FD_GOSSIP_MESSAGE_PING: {
      fd_gossip_view_ping_t const * ping = (fd_gossip_view_ping_t const *)(payload+view->ping_pong_off);
      if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( ping->ping_token, 32UL, ping->signature, ping->pubkey, sha ) ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PING_SIGNATURE_IDX;
      } else {
        return 0;
      }
    }
    case FD_GOSSIP_MESSAGE_PONG: {
      fd_gossip_view_pong_t const * pong = (fd_gossip_view_pong_t const *)(payload+view->ping_pong_off);
      if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( pong->ping_hash, 32UL, pong->signature, pong->pubkey, sha ) ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PONG_SIGNATURE_IDX;
      } else {
        return 0;
      }
    }
    default: __builtin_unreachable();
  };
}

static inline int
is_entrypoint( fd_gossvf_tile_ctx_t * ctx,
               fd_ip4_port_t          addr ) {
  for( ulong i=0UL; i<ctx->entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( addr.addr==ctx->entrypoints[ i ].addr && addr.port==ctx->entrypoints[ i ].port ) ) return 1;
  }
  return 0;
}

static void
publish_no_origin_reject( fd_gossvf_tile_ctx_t *              ctx,
                          fd_gossip_view_crds_value_t const * value,
                          uchar const *                       payload,
                          fd_stem_context_t *                 stem ) {
  uchar * _dst = fd_chunk_to_laddr( ctx->out->mem, ctx->out->chunk );
  fd_gossip_no_origin_reject_t * reject = (fd_gossip_no_origin_reject_t *)_dst;
  fd_memcpy( reject->pubkey.uc, payload+value->pubkey_off, 32UL );
  fd_gossip_generate_crds_value_hash( ctx->sha256, payload+value->value_off, value->length, reject->sha256_hash );

  fd_stem_publish( stem, 0UL, fd_gossvf_sig( 0U, 0U, 2U ), ctx->out->chunk, sizeof(fd_gossip_no_origin_reject_t), 0UL, 0UL, 0UL );
  ctx->out->chunk = fd_dcache_compact_next( ctx->out->chunk, sizeof(fd_gossip_no_origin_reject_t), ctx->out->chunk0, ctx->out->wmark );
}

static void
filter_shred_version_crds( fd_gossvf_tile_ctx_t *            ctx,
                           int                               tag,
                           fd_gossip_view_crds_container_t * container,
                           uchar const *                     payload,
                           fd_stem_context_t *               stem ) {
  peer_t const * relayer = peer_map_ele_query_const( ctx->peer_map, (fd_pubkey_t*)(payload+container->from_off), NULL, ctx->peers );
  int keep_non_ci = (relayer && relayer->shred_version==ctx->shred_version) || (!relayer && is_entrypoint( ctx, ctx->peer ) );

  ulong i = 0UL;
  while( i<container->crds_values_len ) {
    int keep = container->crds_values[ i ].tag==FD_GOSSIP_VALUE_CONTACT_INFO;
    int no_origin = 0;
    if( FD_LIKELY( !keep && keep_non_ci ) ) {
      peer_t const * origin = peer_map_ele_query_const( ctx->peer_map, (fd_pubkey_t*)(payload+container->crds_values[ i ].pubkey_off), NULL, ctx->peers );
      no_origin = !origin;
      keep = origin && origin->shred_version==ctx->shred_version;
    }

    if( FD_UNLIKELY( !keep ) ) {
      if( FD_UNLIKELY( tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) ) {
        if( FD_LIKELY( keep_non_ci ) ) {
          if( FD_LIKELY( no_origin ) ) {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO_IDX ] += container->crds_values[ i ].length;
            publish_no_origin_reject( ctx, &container->crds_values[ i ], payload, stem );
          } else {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION_IDX ] += container->crds_values[ i ].length;
          }
        } else {
          if( FD_LIKELY( !relayer ) ) {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_RELAYER_NO_CONTACT_INFO_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_RELAYER_NO_CONTACT_INFO_IDX ] += container->crds_values[ i ].length;
          } else {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION_IDX ] += container->crds_values[ i ].length;
          }
        }
      } else {
        if( FD_LIKELY( keep_non_ci ) ) {
          if( FD_LIKELY( no_origin ) ) {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_ORIGIN_NO_CONTACT_INFO_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_ORIGIN_NO_CONTACT_INFO_IDX ] += container->crds_values[ i ].length;
            /* Should we ignore for push messages? */
            publish_no_origin_reject( ctx, &container->crds_values[ i ], payload, stem );
          } else {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_ORIGIN_SHRED_VERSION_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_ORIGIN_SHRED_VERSION_IDX ] += container->crds_values[ i ].length;
          }
        } else {
          if( FD_LIKELY( !relayer ) ) {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_RELAYER_NO_CONTACT_INFO_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_RELAYER_NO_CONTACT_INFO_IDX ] += container->crds_values[ i ].length;
          } else {
            ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_RELAYER_SHRED_VERSION_IDX ]++;
            ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_RELAYER_SHRED_VERSION_IDX ] += container->crds_values[ i ].length;
          }
        }
      }
      container->crds_values[ i ] = container->crds_values[ container->crds_values_len-1UL ];
      container->crds_values_len--;
      continue;
    }

    i++;
  }
}

static int
filter_shred_version( fd_gossvf_tile_ctx_t * ctx,
                      fd_gossip_view_t *     view,
                      uchar const *          payload,
                      fd_stem_context_t *    stem ) {
  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
    case FD_GOSSIP_MESSAGE_PRUNE:
      return 0;
    case FD_GOSSIP_MESSAGE_PUSH: {
      filter_shred_version_crds( ctx, view->tag, view->push, payload, stem );
      if( FD_UNLIKELY( !view->push->crds_values_len ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PUSH_NO_VALID_CRDS_IDX;
      } else {
        return 0;
      }
    }
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: {
      filter_shred_version_crds( ctx, view->tag, view->pull_response, payload, stem );
      if( FD_UNLIKELY( !view->pull_response->crds_values_len ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_RESPONSE_NO_VALID_CRDS_IDX;
      } else {
        return 0;
      }
    }
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      FD_TEST( view->pull_request->pr_ci->tag==FD_GOSSIP_VALUE_CONTACT_INFO );
      if( FD_UNLIKELY( view->pull_request->pr_ci->ci_view->contact_info->shred_version!=ctx->shred_version ) ) {
        return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_SHRED_VERSION_IDX;
      } else {
        return 0;
      }
    default:
      __builtin_unreachable();
  }
}

static void
check_duplicate_instance( fd_gossvf_tile_ctx_t *   ctx,
                          fd_gossip_view_t const * view,
                          uchar const *            payload ) {
  fd_gossip_view_crds_container_t const * container;
  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
    case FD_GOSSIP_MESSAGE_PRUNE:
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      return;
    case FD_GOSSIP_MESSAGE_PUSH:
      container = view->push;
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      container = view->pull_response;
      break;
    default:
      __builtin_unreachable();
  }

  for( ulong i=0UL; i<container->crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t const * value = &container->crds_values[ i ];
    if( FD_UNLIKELY( value->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) continue;

    fd_contact_info_t const * contact_info = value->ci_view->contact_info;

    if( FD_LIKELY( ctx->instance_creation_wallclock_nanos>=contact_info->instance_creation_wallclock_nanos ) ) continue;
    if( FD_LIKELY( memcmp( ctx->identity_pubkey->uc, payload+value->pubkey_off, 32UL ) ) ) continue;

    FD_LOG_ERR(( "duplicate running instances of the same validator node, our timestamp: %ldns their timestamp: %ldns", ctx->instance_creation_wallclock_nanos, contact_info->instance_creation_wallclock_nanos ));
  }
}

static inline int
is_ping_active( fd_gossvf_tile_ctx_t *    ctx,
                fd_contact_info_t const * contact_info ) {
  fd_ip4_port_t const * gossip_addr = &contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];

  /* 1. If the node is an entrypoint, it is active */
  if( FD_UNLIKELY( is_entrypoint( ctx, *gossip_addr ) ) ) return 1;

  /* 2. If the node has more than 1 sol staked, it is active */
  stake_t const * stake = stake_map_ele_query_const( ctx->stake.map, &contact_info->pubkey, NULL, ctx->stake.pool );
  if( FD_LIKELY( stake && stake->stake>=1000000000UL ) ) return 1;

  /* 3. If the node has actively ponged a ping, it is active */
  ping_t * ping = ping_map_ele_query( ctx->ping_map, &contact_info->pubkey, NULL, ctx->pings );
  return ping!=NULL;
}

static int
ping_if_unponged_contact_info( fd_gossvf_tile_ctx_t *    ctx,
                               fd_contact_info_t const * contact_info,
                               fd_stem_context_t *       stem ) {
  fd_ip4_port_t const *     gossip_addr  = &contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];

  if( FD_UNLIKELY( gossip_addr->l==0U ) ) return 1; /* implies ipv6 address */
  int is_ip4_nonpublic = !ctx->allow_private_address && !fd_ip4_addr_is_public( gossip_addr->addr );
  if( FD_UNLIKELY( is_ip4_nonpublic ) ) return 1;

  if( FD_UNLIKELY( !is_ping_active( ctx, contact_info ) ) ) {
    fd_gossip_pingreq_t * pingreq = (fd_gossip_pingreq_t*)fd_chunk_to_laddr( ctx->out->mem, ctx->out->chunk );
    fd_memcpy( pingreq->pubkey.uc, contact_info->pubkey.uc, 32UL );
    fd_stem_publish( stem, 0UL, fd_gossvf_sig( gossip_addr->addr, gossip_addr->port, 1 ), ctx->out->chunk, sizeof(fd_gossip_pingreq_t), 0UL, 0UL, 0UL );
    ctx->out->chunk = fd_dcache_compact_next( ctx->out->chunk, sizeof(fd_gossip_pingreq_t), ctx->out->chunk0, ctx->out->wmark );

#if DEBUG_PEERS
    char base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( contact_info->pubkey.uc, NULL, base58 );
    FD_LOG_NOTICE(( "pinging %s (" FD_IP4_ADDR_FMT ":%hu) (%lu)", base58, FD_IP4_ADDR_FMT_ARGS( gossip_addr->addr ), gossip_addr->port, ctx->ping_cnt ));
    ctx->ping_cnt++;
#endif
    return 1;
  }
  return 0;
}

static int
verify_addresses( fd_gossvf_tile_ctx_t * ctx,
                  fd_gossip_view_t *     view,
                  fd_stem_context_t *    stem ) {
  fd_gossip_view_crds_container_t * container;
  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
    case FD_GOSSIP_MESSAGE_PRUNE:
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      return 0;
    case FD_GOSSIP_MESSAGE_PUSH:
      container = view->push;
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      container = view->pull_response;
      break;
    default:
      FD_LOG_ERR(( "unexpected view tag %u", view->tag ));
  }

  ulong i = 0UL;
  while( i<container->crds_values_len ) {
    fd_gossip_view_crds_value_t const * value = &container->crds_values[ i ];
    if( FD_UNLIKELY( value->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) {
      i++;
      continue;
    }

    if( FD_UNLIKELY( ping_if_unponged_contact_info( ctx, value->ci_view->contact_info, stem ) ) ) {
      if( FD_LIKELY( view->tag==FD_GOSSIP_MESSAGE_PUSH ) ) {
        ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_INACTIVE_IDX ]++;
        ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_INACTIVE_IDX ] += value->length;
      } else {
        ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_INACTIVE_IDX ]++;
        ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_INACTIVE_IDX ] += value->length;
      }
      container->crds_values[ i ] = container->crds_values[ container->crds_values_len-1UL ];
      container->crds_values_len--;
      continue;
    }

    i++;
  }

  if( FD_UNLIKELY( !container->crds_values_len ) ) {
    if( view->tag==FD_GOSSIP_MESSAGE_PUSH ) {
      return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PUSH_NO_VALID_CRDS_IDX;
    } else if( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) {
      return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_RESPONSE_NO_VALID_CRDS_IDX;
    } else {
      __builtin_unreachable();
    }
  } else {
    return 0;
  }
}

static void
handle_ping_update( fd_gossvf_tile_ctx_t *    ctx,
                    fd_gossip_ping_update_t * ping_update ) {
#if DEBUG_PEERS
    char base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( ping_update->pubkey.uc, NULL, base58 );
#endif

  if( FD_UNLIKELY( ping_update->remove ) ) {
#if DEBUG_PEERS
    ctx->ping_cnt--;
    FD_LOG_NOTICE(( "removing ping for %s (" FD_IP4_ADDR_FMT ":%hu) (%lu)", base58, FD_IP4_ADDR_FMT_ARGS( ping_update->gossip_addr.addr ), fd_ushort_bswap( ping_update->gossip_addr.port ), ctx->ping_cnt ));
#endif

    ping_t * ping = ping_map_ele_remove( ctx->ping_map, &ping_update->pubkey, NULL, ctx->pings );
    FD_TEST( ping );
    ping_pool_ele_release( ctx->pings, ping );
  } else {
#if DEBUG_PEERS
    ctx->ping_cnt++;
    FD_LOG_NOTICE(( "adding ping for %s (" FD_IP4_ADDR_FMT ":%hu) (%lu)", base58, FD_IP4_ADDR_FMT_ARGS( ping_update->gossip_addr.addr ), fd_ushort_bswap( ping_update->gossip_addr.port ), ctx->ping_cnt ));
#endif

    FD_TEST( ping_pool_free( ctx->pings ) );
    FD_TEST( !ping_map_ele_query( ctx->ping_map, &ping_update->pubkey, NULL, ctx->pings ) );
    ping_t * ping = ping_pool_ele_acquire( ctx->pings );
    ping->addr.l = ping_update->gossip_addr.l;
    fd_memcpy( ping->pubkey.uc, ping_update->pubkey.uc, 32UL );
    ping_map_ele_insert( ctx->ping_map, ping, ctx->pings );
  }
}

static void
handle_peer_update( fd_gossvf_tile_ctx_t *       ctx,
                    fd_gossip_update_message_t * gossip_update ) {
#if DEBUG_PEERS
    char base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( gossip_update->origin_pubkey, NULL, base58 );
#endif

  switch( gossip_update->tag ) {
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
      peer_t * peer = peer_map_ele_query( ctx->peer_map, (fd_pubkey_t*)gossip_update->origin_pubkey, NULL, ctx->peers );
      if( FD_LIKELY( peer ) ) {
#if DEBUG_PEERS
        FD_LOG_NOTICE(( "updating peer %s (" FD_IP4_ADDR_FMT ":%hu) (%lu)", base58, FD_IP4_ADDR_FMT_ARGS( gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].addr ), fd_ushort_bswap( gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].port ), ctx->peer_cnt ));
#endif

        peer->shred_version = gossip_update->contact_info.contact_info->shred_version;
        peer->gossip_addr = gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
      } else {
#if DEBUG_PEERS
        ctx->peer_cnt++;
        FD_LOG_NOTICE(( "adding peer %s (" FD_IP4_ADDR_FMT ":%hu) (%lu)", base58, FD_IP4_ADDR_FMT_ARGS( gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].addr ), fd_ushort_bswap( gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].port ), ctx->peer_cnt ));
#endif

        FD_TEST( peer_pool_free( ctx->peers ) );
        peer = peer_pool_ele_acquire( ctx->peers );
        peer->shred_version = gossip_update->contact_info.contact_info->shred_version;
        peer->gossip_addr = gossip_update->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
        fd_memcpy( peer->pubkey.uc, gossip_update->contact_info.contact_info->pubkey.uc, 32UL );
        peer_map_ele_insert( ctx->peer_map, peer, ctx->peers );
      }
      break;
    }
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
#if DEBUG_PEERS
      ctx->peer_cnt--;
      FD_LOG_NOTICE(( "removing peer %s (%lu)", base58, ctx->peer_cnt ));
#endif

      peer_t * peer = peer_map_ele_remove( ctx->peer_map, (fd_pubkey_t*)gossip_update->origin_pubkey, NULL, ctx->peers );
      FD_TEST( peer );
      peer_pool_ele_release( ctx->peers, peer );
      break;
    }
    default: FD_LOG_ERR(( "unexpected gossip_update tag %u", gossip_update->tag ));
  }
}

static int
handle_net( fd_gossvf_tile_ctx_t * ctx,
            ulong                  sz,
            ulong                  tsorig,
            fd_stem_context_t *    stem ) {
  uchar * payload;
  ulong payload_sz;
  fd_ip4_hdr_t * ip4_hdr;
  fd_udp_hdr_t * udp_hdr;
  FD_TEST( fd_ip4_udp_hdr_strip( ctx->payload, sz, &payload, &payload_sz, NULL, &ip4_hdr, &udp_hdr ) );
  ctx->peer.addr = ip4_hdr->saddr;
  ctx->peer.port = udp_hdr->net_sport;

  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);

  fd_gossip_view_t view[ 1 ];
  ulong decode_sz = fd_gossip_msg_parse( view, payload, payload_sz );
  if( FD_UNLIKELY( !decode_sz ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_UNPARSEABLE_IDX;

  if( FD_UNLIKELY( view->tag==FD_GOSSIP_MESSAGE_PUSH ) ) FD_TEST( view->push->crds_values_len<=FD_GOSSIP_MSG_MAX_CRDS );
  if( FD_UNLIKELY( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) ) FD_TEST( view->pull_response->crds_values_len<=FD_GOSSIP_MSG_MAX_CRDS );

  if( FD_UNLIKELY( view->tag==FD_GOSSIP_MESSAGE_PULL_REQUEST ) ) {
    if( FD_UNLIKELY( view->pull_request->pr_ci->tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO_IDX;
    if( FD_UNLIKELY( !memcmp( payload+view->pull_request->pr_ci->pubkey_off, ctx->identity_pubkey, 32UL ) ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_LOOPBACK_IDX;
    if( FD_UNLIKELY( ping_if_unponged_contact_info( ctx, view->pull_request->pr_ci->ci_view->contact_info, stem ) ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_INACTIVE_IDX;

    /* TODO: Jitter? */
    long clamp_wallclock_lower_nanos = now-15L*1000L*1000L*1000L;
    long clamp_wallclock_upper_nanos = now+15L*1000L*1000L*1000L;
    if( FD_UNLIKELY( view->pull_request->pr_ci->wallclock_nanos<clamp_wallclock_lower_nanos ||
                     view->pull_request->pr_ci->wallclock_nanos>clamp_wallclock_upper_nanos ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_REQUEST_WALLCLOCK_IDX;
  }

  if( FD_UNLIKELY( view->tag==FD_GOSSIP_MESSAGE_PRUNE ) ) {
    if( FD_UNLIKELY( !!memcmp( payload+view->prune->destination_off, ctx->identity_pubkey, 32UL ) ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PRUNE_DESTINATION_IDX;
    if( FD_UNLIKELY( now-1000L*1000L*1000L>view->prune->wallclock_nanos ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PRUNE_WALLCLOCK_IDX;
  }

  if( FD_LIKELY( view->tag==FD_GOSSIP_MESSAGE_PUSH ) ) {
    ulong i = 0UL;
    while( i<view->push->crds_values_len ) {
      fd_gossip_view_crds_value_t const * value = &view->push->crds_values[ i ];
      if( FD_UNLIKELY( value->wallclock_nanos<now-15L*1000L*1000L*1000L ||
                       value->wallclock_nanos>now+15L*1000L*1000L*1000L ) ) {
        ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_WALLCLOCK_IDX ]++;
        ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_WALLCLOCK_IDX ] += value->length;
        view->push->crds_values[ i ] = view->push->crds_values[ view->push->crds_values_len-1UL ];
        view->push->crds_values_len--;
        continue;
      }
      i++;
    }

    if( FD_UNLIKELY( !view->push->crds_values_len ) ) return FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PUSH_NO_VALID_CRDS_IDX;
  }

  int result = filter_shred_version( ctx, view, payload, stem );
  if( FD_UNLIKELY( result ) ) return result;

  result = verify_addresses( ctx, view, stem );
  if( FD_UNLIKELY( result ) ) return result;

  result = verify_signatures( ctx, view, payload, ctx->sha );
  if( FD_UNLIKELY( result ) ) return result;

  check_duplicate_instance( ctx, view, payload );

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: {
      for( ulong i=0UL; i<view->pull_response->crds_values_len; i++ ) {
        ulong dedup_tag = ctx->seed ^ fd_ulong_load_8_fast( payload+view->pull_response->crds_values[ i ].signature_off );
        int ha_dup = 0;
        FD_TCACHE_INSERT( ha_dup, *ctx->tcache.sync, ctx->tcache.ring, ctx->tcache.depth, ctx->tcache.map, ctx->tcache.map_cnt, dedup_tag );
        (void)ha_dup; /* unused */
      }
      break;
    }
    case FD_GOSSIP_MESSAGE_PUSH: {
      for( ulong i=0UL; i<view->push->crds_values_len; i++ ) {
        ulong dedup_tag = ctx->seed ^ fd_ulong_load_8_fast( payload+view->push->crds_values[ i ].signature_off );
        int ha_dup = 0;
        FD_TCACHE_INSERT( ha_dup, *ctx->tcache.sync, ctx->tcache.ring, ctx->tcache.depth, ctx->tcache.map, ctx->tcache.map_cnt, dedup_tag );
        (void)ha_dup; /* unused */
      }
      break;
    }
    default:
      break;
  }

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:  result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PULL_REQUEST_IDX; break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PULL_RESPONSE_IDX; break;
    case FD_GOSSIP_MESSAGE_PUSH:          result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PUSH_IDX; break;
    case FD_GOSSIP_MESSAGE_PRUNE:         result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PRUNE_IDX; break;
    case FD_GOSSIP_MESSAGE_PING:          result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PING_IDX; break;
    case FD_GOSSIP_MESSAGE_PONG:          result = FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PONG_IDX; break;
    default: FD_LOG_ERR(( "unexpected view tag %d", view->tag ));
  }

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_SUCCESS_PULL_RESPONSE_IDX ] += view->pull_response->crds_values_len;
      for( ulong i=0UL; i<view->pull_response->crds_values_len; i++ ) {
        ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_SUCCESS_PULL_RESPONSE_IDX ] += view->pull_response->crds_values[ i ].length;
      }
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_SUCCESS_PUSH_IDX ] += view->push->crds_values_len;
      for( ulong i=0UL; i<view->push->crds_values_len; i++ ) {
        ctx->metrics.crds_rx_bytes[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_SUCCESS_PUSH_IDX ] += view->push->crds_values[ i ].length;
      }
      break;
    default:
      break;
  }

  uchar * dst = fd_chunk_to_laddr( ctx->out->mem, ctx->out->chunk );
  fd_memcpy( dst, view, sizeof(fd_gossip_view_t) );
  fd_memcpy( dst+sizeof(fd_gossip_view_t), payload, payload_sz );

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, fd_gossvf_sig( ctx->peer.addr, ctx->peer.port, 0 ), ctx->out->chunk, sizeof(fd_gossip_view_t)+payload_sz, 0UL, tsorig, tspub );
  ctx->out->chunk = fd_dcache_compact_next( ctx->out->chunk, sizeof(fd_gossip_view_t)+payload_sz, ctx->out->chunk0, ctx->out->wmark );

  return result;
}

static inline void
after_frag( fd_gossvf_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            ulong                  _tspub,
            fd_stem_context_t *    stem ) {
  (void)seq;
  (void)sig;
  (void)_tspub;

  switch( ctx->in[ in_idx ].kind ) {
    case IN_KIND_SHRED_VERSION: break;
    case IN_KIND_PINGS:  handle_ping_update( ctx, ctx->_ping_update ); break;
    case IN_KIND_GOSSIP: handle_peer_update( ctx, ctx->_gossip_update ); break;
    case IN_KIND_REPLAY: handle_stakes( ctx, (fd_stake_weight_msg_t const *) ctx->stake.msg_buf ); break;
    case IN_KIND_NET: {
      int result = handle_net( ctx, sz, tsorig, stem );
      ctx->metrics.message_rx[ result ]++;
      ctx->metrics.message_rx_bytes[ result ] += sz;
      break;
    }
    default: FD_LOG_ERR(( "unexpected in_kind %d", ctx->in[ in_idx ].kind ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossvf_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gossvf_tile_ctx_t ), sizeof( fd_gossvf_tile_ctx_t ) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8U ) );

  if( FD_UNLIKELY( !strcmp( tile->gossvf.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->gossvf.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossvf_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gossvf_tile_ctx_t ), sizeof( fd_gossvf_tile_ctx_t ) );
  void * _peer_pool          = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),               peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE )             );
  void * _peer_map           = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),                peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE )          );
  void * _ping_pool          = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),               ping_pool_footprint( FD_PING_TRACKER_MAX )                    );
  void * _ping_map           = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),                ping_map_footprint( 2UL*FD_PING_TRACKER_MAX )                 );
  void * _stake_pool         = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(),              stake_pool_footprint( MAX_STAKED_LEADERS )                    );
  void * _stake_map          = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),               stake_map_footprint( fd_ulong_pow2_up( MAX_STAKED_LEADERS ) ) );
  void * _tcache             = FD_SCRATCH_ALLOC_APPEND( l, fd_tcache_align(),               fd_tcache_footprint( tile->gossvf.tcache_depth, 0UL )         );

  ctx->peers = peer_pool_join( peer_pool_new( _peer_pool, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( ctx->peers );

  ctx->peer_map = peer_map_join( peer_map_new( _peer_map, 2UL*FD_CONTACT_INFO_TABLE_SIZE, ctx->seed ) );
  FD_TEST( ctx->peer_map );

  ctx->pings = ping_pool_join( ping_pool_new( _ping_pool, FD_PING_TRACKER_MAX ) );
  FD_TEST( ctx->pings );

  ctx->ping_map = ping_map_join( ping_map_new( _ping_map, 2UL*FD_PING_TRACKER_MAX, ctx->seed ) );
  FD_TEST( ctx->ping_map );

  ctx->stake.count = 0UL;
  ctx->stake.pool  = stake_pool_join( stake_pool_new( _stake_pool, MAX_STAKED_LEADERS ) );
  FD_TEST( ctx->stake.pool );

  ctx->stake.map = stake_map_join( stake_map_new( _stake_map, fd_ulong_pow2_up( MAX_STAKED_LEADERS ), ctx->seed ) );
  FD_TEST( ctx->stake.map );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->allow_private_address = tile->gossvf.allow_private_address;

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->shred_version = tile->gossvf.shred_version;

  ctx->ticks_per_ns   = fd_tempo_tick_per_ns( NULL );
  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();

  FD_TEST( fd_sha256_join( fd_sha256_new( ctx->sha ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( _tcache, tile->gossvf.tcache_depth, 0UL ) );
  FD_TEST( tcache );

  ctx->tcache.depth   = fd_tcache_depth       ( tcache );
  ctx->tcache.map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache.sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache.ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache.map     = fd_tcache_map_laddr   ( tcache );

  ctx->entrypoints_cnt = tile->gossvf.entrypoints_cnt;
  for( ulong i=0UL; i<tile->gossvf.entrypoints_cnt; i++ ) {
    ctx->entrypoints[ i ].l = tile->gossvf.entrypoints[ i ].l;
#if DEBUG_PEERS
    FD_LOG_NOTICE(( "entrypoint " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( ctx->entrypoints[ i ].addr ), fd_ushort_bswap( ctx->entrypoints[ i ].port ) ));
#endif
  }

  ctx->instance_creation_wallclock_nanos = tile->gossvf.boot_timestamp_nanos;

#if DEBUG_PEERS
  ctx->peer_cnt = 0UL;
  ctx->ping_cnt = 0UL;
#endif

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    } else {
      ctx->in[ i ].chunk0 = 0UL;
      ctx->in[ i ].wmark  = 0UL;
    }
    ctx->in[ i ].mtu    = link->mtu;

    if(      !strcmp( link->name, "gossip_gossv" ) ) ctx->in[ i ].kind = IN_KIND_PINGS;
    else if( !strcmp( link->name, "ipecho_out"   ) ) ctx->in[ i ].kind = IN_KIND_SHRED_VERSION;
    else if( !strcmp( link->name, "gossip_out"   ) ) ctx->in[ i ].kind = IN_KIND_GOSSIP;
    else if( !strcmp( link->name, "net_gossvf"   ) ) ctx->in[ i ].kind = IN_KIND_NET;
    else if( !strcmp( link->name, "replay_stake" ) ) ctx->in[ i ].kind = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  FD_TEST( tile->out_cnt==1UL );
  fd_topo_link_t * gossvf_out = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out->mem    = topo->workspaces[ topo->objs[ gossvf_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->out->chunk0 = fd_dcache_compact_chunk0( ctx->out->mem, gossvf_out->dcache );
  ctx->out->wmark  = fd_dcache_compact_wmark ( ctx->out->mem, gossvf_out->dcache, gossvf_out->mtu );
  ctx->out->chunk  = ctx->out->chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_gossvf_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_gossvf_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (FD_GOSSIP_MSG_MAX_CRDS+1UL)

#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gossvf_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gossvf_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gossvf = {
  .name                     = "gossvf",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
