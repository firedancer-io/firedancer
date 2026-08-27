#include "fd_votor_tile.h"
#include "generated/fd_votor_tile_seccomp.h"

#include "../../choreo/votor/ag_cert_serde.h"
#include "../../choreo/votor/ag_pool.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../choreo/votor/ag_votor.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/tls/fd_quic_tls.h"
#include "../replay/fd_replay_tile.h"

#define IN_KIND_EPOCH  (0)
#define IN_KIND_IPECHO (1)
#define IN_KIND_NET    (2)
#define IN_KIND_REPLAY (3)

#define OUT_IDX_VOTOR (0UL)
#define OUT_IDX_NET   (1UL)

#define QUIC_CONN_MAX (AG_VAT_MAX * 2)

#define DATAGRAM_KIND_NOTAR_VOTE          ( 1)
#define DATAGRAM_KIND_FINALIZE_VOTE       ( 2)
#define DATAGRAM_KIND_SKIP_VOTE           ( 3)
#define DATAGRAM_KIND_NOTAR_FALLBACK_VOTE ( 4)
#define DATAGRAM_KIND_SKIP_FALLBACK_VOTE  ( 5)
#define DATAGRAM_KIND_GENESIS_VOTE        ( 6)
#define DATAGRAM_KIND_FINALIZE_CERT       ( 7)
#define DATAGRAM_KIND_FAST_FINALIZE_CERT  ( 8)
#define DATAGRAM_KIND_NOTAR_CERT          ( 9)
#define DATAGRAM_KIND_NOTAR_FALLBACK_CERT (10)
#define DATAGRAM_KIND_SKIP_CERT           (11)
#define DATAGRAM_KIND_GENESIS_CERT        (12)

static fd_quic_limits_t quic_limits = {
  .conn_cnt                    = QUIC_CONN_MAX,
  .handshake_cnt               = 1024UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 64UL * QUIC_CONN_MAX,
  .min_inflight_frame_cnt_conn = 32UL,
};

struct replayed {
  ag_block_id_t block_id;
  ag_block_id_t parent_block_id;
};
typedef struct replayed replayed_t;

#define MAP_NAME               replayed
#define MAP_T                  replayed_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_NULL           ((ag_block_id_t){ .slot = ULONG_MAX })
#define MAP_KEY_INVAL(k)       ((k).slot==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1)   (!memcmp( &(k0), &(k1), sizeof(ag_block_id_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key,seed) ((uint)fd_hash( (seed), &(key), sizeof(ag_block_id_t) ))
#define MAP_MEMOIZE            0
#include "../../util/tmpl/fd_map_dynamic.c"

#define STACK_NAME rooted
#define STACK_T    ag_block_id_t
#include "../../util/tmpl/fd_stack.c"

struct publish {
  ulong          sig;
  fd_votor_msg_t msg;
};

typedef struct publish publish_t;

#define QUEUE_NAME publishes
#define QUEUE_T    publish_t
#include "../../util/tmpl/fd_queue_dynamic.c"

/* id_to_rank maps a validator identity key to its rank in the current
   and next epochs.  This map is refreshed on every epoch boundary.  The
   number of keys is bounded by the VAT (AG_VAT_MAX). */

#define ID_TO_RANK_LG_SLOT_CNT (13) /* 2*AG_VAT_MAX keys, fill ratio 0.25 */
FD_STATIC_ASSERT( (1UL<<ID_TO_RANK_LG_SLOT_CNT)>=4UL*AG_VAT_MAX, id_to_rank );

struct id_to_rank {
  fd_pubkey_t id_key;
  ushort      curr_rank; /* USHORT_MAX when the identity is unranked in that epoch */
  ushort      next_rank;
};
typedef struct id_to_rank id_to_rank_t;

#define MAP_NAME              id_to_rank
#define MAP_T                 id_to_rank_t
#define MAP_LG_SLOT_CNT       ID_TO_RANK_LG_SLOT_CNT
#define MAP_KEY               id_key
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          ((fd_pubkey_t){ .ul = {0} }) /* no validator identity is the zero pubkey */
#define MAP_KEY_INVAL(k)      (!((k).ul[0]|(k).ul[1]|(k).ul[2]|(k).ul[3]))
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( &(k0), &(k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash( 0UL, &(key), sizeof(fd_pubkey_t) ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map.c"
/* Staged notifications, drained one per after_credit.  Distinct from
   publishes because the notification link is unreliable and purely
   informational: when this queue fills we drop the oldest entry rather
   than stall votor, which is the whole point of keeping the two
   separate.  Every notification carries a complete state, so the
   consumer recovers from a drop on the next one for that slot. */

struct notif_publish {
  ulong            sig;
  fd_votor_notif_t msg;
};

typedef struct notif_publish notif_publish_t;

#define QUEUE_NAME notifs
#define QUEUE_T    notif_publish_t
#include "../../util/tmpl/fd_queue_dynamic.c"

struct fd_votor_tile {

  /* Metadata */

  uchar const * identity_keypair; /* FIXME */
  fd_pubkey_t   identity;         /* identity_keypair's public half, as the id_to_rank key type */
  ag_bls_sec_t  bls_key;
  uchar         sha512[ FD_SHA512_FOOTPRINT ] __attribute__((aligned(FD_SHA512_ALIGN)));
  ushort        shred_version;

  /* Data */

  ag_block_id_t     rooted_block_id;
  ag_epoch_info_t * curr_epoch_info;
  ulong             curr_epoch_slot;
  ushort            curr_epoch_rank; /* USHORT_MAX when we hold no stake this epoch */
  ag_epoch_info_t * next_epoch_info;
  ulong             next_epoch_slot;
  ushort            next_epoch_rank;
  id_to_rank_t *    id_to_rank;      /* identity -> its rank in each of the above */
  ag_pool_t *       pool;
  ag_votor_t *      votor;
  replayed_t *      replayed;
  ag_block_id_t *   rooted;
  publish_t *       publishes;

  /* Networking */

  fd_pubkey_t        conn_ctxs[ QUIC_CONN_MAX ];
  fd_net_rx_bounds_t net_in_bounds[ 32 ];
  uchar              net_buf[ FD_NET_MTU ];
  fd_quic_t *        quic;
  uchar              quic_tx_aio[ 128 ] __attribute__((aligned(alignof(fd_aio_t))));

  /* Links */

  int in_kind[ 32 ];
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];

  void * net_out_mem;
  ulong  net_out_chunk0;
  ulong  net_out_wmark;
  ulong  net_out_chunk;

  void * votor_out_mem;
  ulong  votor_out_chunk0;
  ulong  votor_out_wmark;
  ulong  votor_out_chunk;

  ulong  votor_notif_out_idx; /* ULONG_MAX when the GUI is disabled */
  void * votor_notif_out_mem;
  ulong  votor_notif_out_chunk0;
  ulong  votor_notif_out_wmark;
  ulong  votor_notif_out_chunk;

  notif_publish_t * notifs;         /* NULL when the notification link is absent */
  ulong             finalized_slot; /* last finalized slot we notified, ULONG_MAX if none */

  fd_stem_context_t * stem;

  /* Scratch */

  struct {
    union {
      ag_vote_t           vote;
      ag_cert_t           cert;
      ag_event_pool_t     pool_event;
      ag_event_repair_t   repair_event;
      ag_event_timeout_t  timeout_event;
      ag_event_vote_t     vote_event;
      ag_event_cert_t     cert_event;
    };
    ag_epoch_info_t curr_epoch_info;
    ag_epoch_info_t next_epoch_info;
  } scratch;
};
typedef struct fd_votor_tile fd_votor_tile_t;

/* stage_notif enqueues a notification for the informational link.  We
   discard the oldest entry when the queue is full rather than block:
   the link is unreliable by construction, a stale notification is worth
   less than a fresh one, and consensus must never wait on a consumer
   that is only watching. */

static inline void
stage_notif( fd_votor_tile_t *        ctx,
             ulong                    sig,
             fd_votor_notif_t const * msg ) {
  if( FD_UNLIKELY( !ctx->notifs ) ) return;
  if( FD_UNLIKELY( notifs_full( ctx->notifs ) ) ) notifs_pop( ctx->notifs );
  notif_publish_t pub = { .sig = sig, .msg = *msg };
  notifs_push( ctx->notifs, pub );
}

/* The whole union goes on the wire, so it is zeroed before a member is
   filled in.  Initializing one member of a union leaves the bytes past
   it unspecified, which would put stack contents on a link and make the
   payload non-reproducible. */

static inline void
notif_init( fd_votor_notif_t * notif ) {
  memset( notif, 0, sizeof(fd_votor_notif_t) );
}

static inline void
stage_finalized_slot( fd_votor_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->notifs || ctx->rooted_block_id.slot==ULONG_MAX ) ) return;

  ulong finalized_slot = ag_pool_finalized_slot( ctx->pool );
  if( FD_LIKELY( ctx->finalized_slot!=ULONG_MAX && finalized_slot<=ctx->finalized_slot ) ) return;

  ctx->finalized_slot = finalized_slot;

  fd_votor_notif_t notif; notif_init( &notif );
  notif.finalized_slot = finalized_slot;
  stage_notif( ctx, FD_VOTOR_NOTIF_FINALIZED_SLOT, &notif );
}

/* stage_cert reports a certificate the pool accepted.  Skip and slow
   finalization certificates name only a slot on the wire.  For a slow
   finalization the block is still recoverable from the finality
   tracker, which add_valid_cert updates before it pushes the event we
   are reacting to - unless the matching notarization certificate has
   not landed yet, in which case the block is not knowable and we say
   so.  A later certificate for the slot carries it. */

static inline void
stage_cert( fd_votor_tile_t * ctx,
            ag_cert_t const * cert ) {
  if( FD_UNLIKELY( !ctx->notifs ) ) return;

  uchar kind;
  switch( cert->kind ) {
  case AG_CERT_KIND_NOTAR:          kind = FD_VOTOR_NOTIF_CERT_NOTAR;          break;
  case AG_CERT_KIND_NOTAR_FALLBACK: kind = FD_VOTOR_NOTIF_CERT_NOTAR_FALLBACK; break;
  case AG_CERT_KIND_SKIP:           kind = FD_VOTOR_NOTIF_CERT_SKIP;           break;
  case AG_CERT_KIND_FAST_FINAL:     kind = FD_VOTOR_NOTIF_CERT_FAST_FINAL;     break;
  case AG_CERT_KIND_FINAL:          kind = FD_VOTOR_NOTIF_CERT_FINAL;          break;
  default:                          return; /* genesis; ag_cert_slot does not accept it either */
  }

  ulong slot = ag_cert_slot( cert );

  fd_votor_notif_t notif; notif_init( &notif );
  notif.cert.slot = slot;
  notif.cert.kind = kind;

  uchar const * block_hash = ag_cert_block_hash( cert );
  if( FD_LIKELY( block_hash ) ) {
    memcpy( notif.cert.block_id.uc, block_hash, sizeof(ag_block_hash_t) );
    notif.cert.has_block_id = 1;
  } else if( FD_UNLIKELY( cert->kind==AG_CERT_KIND_FINAL ) ) {
    ag_block_hash_t hash;
    if( FD_LIKELY( ag_pool_finalized_block_hash( ctx->pool, slot, hash ) ) ) {
      memcpy( notif.cert.block_id.uc, hash, sizeof(ag_block_hash_t) );
      notif.cert.has_block_id = 1;
    }
  }

  stage_notif( ctx, FD_VOTOR_NOTIF_CERT, &notif );

  /* A slow finalization certificate carries no block, so if it arrived
     before the notarization certificate for the same slot we reported
     it without one.  This is the moment the block becomes knowable, so
     report the finalization again now that we can name it.  A fast
     finalization never needs this - it carries its own block. */

  if( FD_UNLIKELY( cert->kind==AG_CERT_KIND_NOTAR ) ) {
    ag_block_hash_t hash;
    if( FD_UNLIKELY( ag_pool_finalized_block_hash( ctx->pool, slot, hash ) ) ) {
      fd_votor_notif_t final; notif_init( &final );
      final.cert.slot         = slot;
      final.cert.kind         = FD_VOTOR_NOTIF_CERT_FINAL;
      final.cert.has_block_id = 1;
      memcpy( final.cert.block_id.uc, hash, sizeof(ag_block_hash_t) );
      stage_notif( ctx, FD_VOTOR_NOTIF_CERT, &final );
    }
  }
}

static inline void
stage_parent_ready( fd_votor_tile_t *         ctx,
                    ag_parent_ready_t const * ready ) {
  if( FD_UNLIKELY( !ctx->notifs ) ) return;

  fd_votor_notif_t notif; notif_init( &notif );
  notif.parent_ready.slot        = ready->slot;
  notif.parent_ready.parent_slot = ready->parent.slot;
  memcpy( notif.parent_ready.parent_block_id.uc, ready->parent.hash, sizeof(ag_block_hash_t) );
  stage_notif( ctx, FD_VOTOR_NOTIF_PARENT_READY, &notif );
}

static void
index_id_to_rank( id_to_rank_t *          id_to_rank,
                  ag_epoch_info_t const * curr,
                  ag_epoch_info_t const * next ) {
  id_to_rank_clear( id_to_rank );

  for( ulong rank=0UL; rank<curr->validator_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, curr->validators[ rank ].id_key, sizeof(ag_id_key_t) );
    id_to_rank_t * ele = id_to_rank_insert( id_to_rank, id_key );
    FD_TEST( ele );
    ele->curr_rank = (ushort)rank;
    ele->next_rank = USHORT_MAX;
  }

  if( FD_UNLIKELY( !next ) ) return; /* second epoch not installed yet */

  for( ulong rank=0UL; rank<next->validator_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, next->validators[ rank ].id_key, sizeof(ag_id_key_t) );
    id_to_rank_t * ele = id_to_rank_query( id_to_rank, id_key, NULL );
    if( FD_UNLIKELY( !ele ) ) { /* ranked next epoch but not this one */
      ele = id_to_rank_insert( id_to_rank, id_key );
      FD_TEST( ele );
      ele->curr_rank = USHORT_MAX;
    }
    ele->next_rank = (ushort)rank;
  }
}

static void
handle_epoch( fd_votor_tile_t *           ctx,
               fd_epoch_info_msg_t const * msg ) {

  ag_epoch_info_t * epoch_info;
  if     ( FD_UNLIKELY( !ctx->curr_epoch_info ) ) epoch_info = &ctx->scratch.curr_epoch_info;
  else if( FD_UNLIKELY( !ctx->next_epoch_info ) ) epoch_info = &ctx->scratch.next_epoch_info;
  else                                            epoch_info = ctx->curr_epoch_info;

  ag_epoch_info_rank( epoch_info, fd_epoch_info_msg_stake_weights( msg ), msg->staked_vote_cnt );

  ushort epoch_rank = USHORT_MAX;
  for( ulong rank=0UL; rank<epoch_info->validator_cnt; rank++ ) {
    if( FD_LIKELY( memcmp( epoch_info->validators[ rank ].id_key, ctx->identity.uc, sizeof(ag_id_key_t) ) ) ) continue;
    epoch_rank = (ushort)rank;
    break;
  }

  if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) {
    ctx->curr_epoch_info = epoch_info;
    ctx->curr_epoch_slot = msg->start_slot;
    ctx->curr_epoch_rank = epoch_rank;
  } else {
    if( FD_LIKELY( ctx->next_epoch_info ) ) {
      ctx->curr_epoch_info = ctx->next_epoch_info;
      ctx->curr_epoch_slot = ctx->next_epoch_slot;
      ctx->curr_epoch_rank = ctx->next_epoch_rank;
    }
    ctx->next_epoch_info = epoch_info;
    ctx->next_epoch_slot = msg->start_slot;
    ctx->next_epoch_rank = epoch_rank;
  }

  index_id_to_rank( ctx->id_to_rank, ctx->curr_epoch_info, ctx->next_epoch_info );
  ag_pool_advance_epoch( ctx->pool, epoch_info, epoch_rank, msg->start_slot );
  ag_votor_advance_epoch( ctx->votor, epoch_rank, msg->start_slot );
}

static void
handle_replay( fd_votor_tile_t *           ctx,
               ulong                       sig,
               fd_replay_message_t const * replay ) {
  switch( sig ) {
  case REPLAY_SIG_SLOT_COMPLETED: {
    fd_replay_slot_completed_t const * slot_completed  = &replay->slot_completed;
    ag_block_id_t                      block_id        = ag_block_id( slot_completed->slot,        slot_completed->block_id.uc        );
    ag_block_id_t                      parent_block_id = ag_block_id( slot_completed->parent_slot, slot_completed->parent_block_id.uc );
    if( FD_LIKELY( !replayed_query( ctx->replayed, block_id, NULL ) ) ) replayed_insert( ctx->replayed, block_id )->parent_block_id = parent_block_id;

    /* the first block replay completes is the one it booted on */

    if( FD_UNLIKELY( ctx->rooted_block_id.slot==ULONG_MAX ) ) {
      ctx->rooted_block_id = block_id;
      ag_pool_init ( ctx->pool,  block_id.slot );
      ag_votor_init( ctx->votor, block_id.slot, fd_log_wallclock() );
    }
    ag_pool_add_block( ctx->pool, &block_id, &parent_block_id );
    ag_event_replay_t completed = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = block_id.slot, .block_info = { .parent = parent_block_id } };
    memcpy( completed.block_info.hash, block_id.hash, sizeof(ag_block_hash_t) );
    ag_votor_handle_replay_event( ctx->votor, &completed );
    break;
  }
  case REPLAY_SIG_SLOT_DEAD: {
    fd_replay_slot_dead_t const * slot_dead = &replay->slot_dead;
    ag_event_replay_t             dead      = { .kind = AG_EVENT_REPLAY_DEAD, .slot = slot_dead->slot };
    ag_votor_handle_replay_event( ctx->votor, &dead );
    break;
  }
  default:
    FD_LOG_ERR(( "unexpected replay sig %lu", sig ));
  }
}

static int
quic_aio_tx( void *                    _ctx,
             fd_aio_pkt_info_t const * batch,
             ulong                     batch_cnt,
             ulong *                   opt_batch_idx,
             int                       flush ) {
  (void)flush;

  fd_votor_tile_t * ctx = _ctx;

  for( ulong i=0UL; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;

    ulong sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
    ulong chunk = ctx->net_out_chunk;
    ulong ctl   = fd_frag_meta_ctl( 0UL, 1, 1, 0 );
    fd_stem_publish( ctx->stem, OUT_IDX_NET, sig, chunk, sz_l2, ctl, 0L, 0L );

    ctx->net_out_chunk = fd_dcache_compact_next( chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = batch_cnt;

  return FD_AIO_SUCCESS;
}

static void
quic_sign( void *      signer_ctx,
           uchar       signature[ static 64 ],
           uchar const payload[ static 130 ] ) {
  fd_votor_tile_t * ctx = signer_ctx;

  fd_sha512_t * sha = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->identity_keypair+32UL, ctx->identity_keypair, sha );
  fd_sha512_leave( sha );
}

static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {
  if( FD_UNLIKELY( !conn->tls_hs ) ) return; /* no authenticated identity, so no votes will be attributed */
  fd_pubkey_t const * id_key = (fd_pubkey_t const *)fd_type_pun_const( conn->tls_hs->hs.srv.client_pubkey );

  fd_votor_tile_t * ctx = _ctx;
  if( FD_LIKELY( ctx->curr_epoch_info ) && FD_UNLIKELY( !id_to_rank_query( ctx->id_to_rank, *id_key, NULL ) ) ) {
    fd_quic_conn_close( conn, 0U );
    return;
  }
  ctx->conn_ctxs[ conn->conn_idx ] = *id_key;
  fd_quic_conn_set_context( conn, &ctx->conn_ctxs[ conn->conn_idx ] );
}

static void
quic_datagram_rx( fd_quic_conn_t * conn,
                  uchar const *    data,
                  ulong            data_sz,
                  void *           _ctx ) {
  fd_votor_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( data_sz<2UL ) ) return;

  uchar kind = data[ 1 ];
  switch( kind ) {
  case DATAGRAM_KIND_NOTAR_VOTE:
  case DATAGRAM_KIND_FINALIZE_VOTE:
  case DATAGRAM_KIND_SKIP_VOTE:
  case DATAGRAM_KIND_NOTAR_FALLBACK_VOTE:
  case DATAGRAM_KIND_SKIP_FALLBACK_VOTE:
  case DATAGRAM_KIND_GENESIS_VOTE: {
    if( FD_UNLIKELY( ag_vote_de( &ctx->scratch.vote, ctx->shred_version, data, data_sz, NULL ) ) ) return;
    int                     next       = ag_vote_slot( &ctx->scratch.vote )>=ctx->next_epoch_slot;
    ag_epoch_info_t const * epoch_info = fd_ptr_if( next, ctx->next_epoch_info, ctx->curr_epoch_info );
    if( FD_UNLIKELY( !epoch_info ) ) return;
    fd_pubkey_t const * peer = fd_quic_conn_get_context( conn );
    if( FD_UNLIKELY( !peer ) ) return; /* bound in quic_conn_new, and fd_quic zeroes it when the slot is reused */
    id_to_rank_t const * ele = id_to_rank_query( ctx->id_to_rank, *peer, NULL );
    if( FD_UNLIKELY( !ele ) ) return;
    ushort rank = fd_ushort_if( next, ele->next_rank, ele->curr_rank );
    if( FD_UNLIKELY( rank==USHORT_MAX ) ) return; /* not an authenticated validator this epoch */
    ag_vote_set_rank( &ctx->scratch.vote, rank );
    // if( FD_UNLIKELY( !ag_vote_verify( &ctx->scratch.vote, epoch_info->validators[ rank ].bls_key, ctx->shred_version ) ) ) return; /* FIXME BLS is too expensive */
    ag_pool_add_vote( ctx->pool, &ctx->scratch.vote );
    return;
  }
  case DATAGRAM_KIND_FINALIZE_CERT:
  case DATAGRAM_KIND_FAST_FINALIZE_CERT:
  case DATAGRAM_KIND_NOTAR_CERT:
  case DATAGRAM_KIND_NOTAR_FALLBACK_CERT:
  case DATAGRAM_KIND_SKIP_CERT:
  case DATAGRAM_KIND_GENESIS_CERT: {
    if( FD_UNLIKELY( ag_cert_de( &ctx->scratch.cert, ctx->shred_version, data, data_sz, NULL ) ) ) return;
    ag_epoch_info_t const * epoch_info = fd_ptr_if( ag_cert_slot( &ctx->scratch.cert )>=ctx->next_epoch_slot, ctx->next_epoch_info, ctx->curr_epoch_info );
    if( FD_UNLIKELY( !epoch_info ) ) return;
    // if( FD_UNLIKELY( !ag_cert_verify( &ctx->scratch.cert, epoch_info, ctx->shred_version ) ) ) return; /* FIXME BLS is too expensive, 35x duplicate certs each cost a pairing */
    ag_pool_add_cert( ctx->pool, &ctx->scratch.cert );
    return;
  }
  default:
    return;
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_votor_tile_t), fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( AG_EQVOC_BLOCK_HASH_MAX*tile->votor.max_live_slots ) ) + 1;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &quic_limits )                 );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),          ag_pool_footprint( tile->votor.max_live_slots )   );
  l = FD_LAYOUT_APPEND( l, ag_votor_align(),         ag_votor_footprint( tile->votor.max_live_slots )  );
  l = FD_LAYOUT_APPEND( l, replayed_align(),         replayed_footprint( lg_blk_max )                          );
  l = FD_LAYOUT_APPEND( l, rooted_align(),           rooted_footprint( tile->votor.max_live_slots )    );
  l = FD_LAYOUT_APPEND( l, publishes_align(),        publishes_footprint( tile->votor.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, id_to_rank_align(),       id_to_rank_footprint()                            );
  l = FD_LAYOUT_APPEND( l, notifs_align(),           notifs_footprint( tile->votor.max_live_slots )    );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_LIKELY( !publishes_empty( ctx->publishes ) ) ) {
    publish_t pub = publishes_pop( ctx->publishes );
    memcpy( fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk ), &pub.msg, sizeof(fd_votor_msg_t) );
    fd_stem_publish( stem, OUT_IDX_VOTOR, pub.sig, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
    *opt_poll_in         = 0; /* drain the publishes */
    *charge_busy         = 1;
    return;
  }

  if( FD_UNLIKELY( ctx->notifs && !notifs_empty( ctx->notifs ) ) ) {
    notif_publish_t pub = notifs_pop( ctx->notifs );
    memcpy( fd_chunk_to_laddr( ctx->votor_notif_out_mem, ctx->votor_notif_out_chunk ), &pub.msg, sizeof(fd_votor_notif_t) );
    fd_stem_publish( stem, ctx->votor_notif_out_idx, pub.sig, ctx->votor_notif_out_chunk, sizeof(fd_votor_notif_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->votor_notif_out_chunk = fd_dcache_compact_next( ctx->votor_notif_out_chunk, sizeof(fd_votor_notif_t), ctx->votor_notif_out_chunk0, ctx->votor_notif_out_wmark );
    *opt_poll_in               = 0; /* drain the notifs */
    *charge_busy               = 1;
    return;
  }

  ctx->stem = stem;

  long now     = fd_log_wallclock();
  *charge_busy = fd_quic_service( ctx->quic, now );

  if( FD_UNLIKELY( ag_pool_poll_pool_event( ctx->pool, &ctx->scratch.pool_event ) ) ) {
    /* Mirror the two events a monitoring consumer cares about before
       handing the event on.  Deliberately not safe-to-notar or
       safe-to-skip: those are Votor's own vote triggers, not cluster
       state, and reporting them would say nothing about a block. */

    switch( ctx->scratch.pool_event.kind ) {
    case AG_EVENT_POOL_CERT_CREATED: stage_cert        ( ctx, &ctx->scratch.pool_event.cert_created ); break;
    case AG_EVENT_POOL_PARENT_READY: stage_parent_ready( ctx, &ctx->scratch.pool_event.parent_ready ); break;
    default:                                                                                          break;
    }

    ag_votor_handle_pool_event( ctx->votor, &ctx->scratch.pool_event, now );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_pool_poll_repair_event( ctx->pool, &ctx->scratch.repair_event ) ) ) {
    publish_t pub = { .sig = FD_VOTOR_SIG_REPAIR_BLOCK_ID };
    pub.msg.repair_block.slot = ctx->scratch.repair_event.block.slot;
    memcpy( &pub.msg.repair_block.block_id, ctx->scratch.repair_event.block.hash, sizeof(fd_hash_t) );
    publishes_push( ctx->publishes, pub );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_timeout_event( ctx->votor, now, &ctx->scratch.timeout_event ) ) ) { /* a timeout we set on ParentReady */
    ag_votor_handle_timeout_event( ctx->votor, &ctx->scratch.timeout_event );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_vote_event( ctx->votor, &ctx->scratch.vote_event ) ) ) { /* our own vote */
    ulong vote_slot = ag_vote_slot( &ctx->scratch.vote_event.vote );
    ulong rank      = fd_ulong_if( vote_slot<ctx->next_epoch_slot, ctx->curr_epoch_rank, ctx->next_epoch_rank );
    if( FD_LIKELY( vote_slot>=ctx->curr_epoch_slot && rank!=USHORT_MAX ) ) {
      ag_pool_add_vote( ctx->pool, &ctx->scratch.vote_event.vote );
      /* TODO broadcast out vote */
      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ag_votor_poll_cert_event( ctx->votor, &ctx->scratch.cert_event ) ) ) { /* a cert we built */
    ag_pool_add_cert( ctx->pool, &ctx->scratch.cert_event.cert );
    uint            kind           = ctx->scratch.cert_event.cert.kind;
    ulong           finalized_slot = ag_pool_finalized_slot( ctx->pool );
    ag_block_hash_t finalized_hash;
    if( FD_LIKELY( ( kind==AG_CERT_KIND_FINAL || kind==AG_CERT_KIND_FAST_FINAL ) && ag_pool_finalized_block_hash( ctx->pool, finalized_slot, finalized_hash ) ) ) {
      ag_block_id_t ancestor_block_id = ag_block_id( finalized_slot, finalized_hash );
      replayed_t *  replayed          = NULL;

      while( FD_LIKELY( ancestor_block_id.slot>ctx->rooted_block_id.slot && ( replayed = replayed_query( ctx->replayed, ancestor_block_id, NULL ) ) ) ) {
        FD_TEST( !rooted_full( ctx->rooted ) );
        rooted_push( ctx->rooted, ancestor_block_id );
        ancestor_block_id = replayed->parent_block_id;
      }

      if( FD_UNLIKELY( !ag_block_id_eq( &ancestor_block_id, &ctx->rooted_block_id ) ) ) rooted_remove_all( ctx->rooted );

      while( FD_UNLIKELY( !rooted_empty( ctx->rooted ) ) ) {
        ag_block_id_t rooted_block_id = rooted_pop( ctx->rooted );

        publish_t pub = { .sig = FD_VOTOR_SIG_ROOTED };
        pub.msg.rooted.slot = rooted_block_id.slot;
        memcpy( pub.msg.rooted.block_id.uc, rooted_block_id.hash, sizeof(fd_hash_t) );
        publishes_push( ctx->publishes, pub );

        replayed = replayed_query( ctx->replayed, rooted_block_id, NULL );
        if( FD_LIKELY( replayed ) ) replayed_remove( ctx->replayed, replayed );

        ctx->rooted_block_id = rooted_block_id;
      }
    }
    *charge_busy = 1;
  }

  stage_finalized_slot( ctx );
}

static int
before_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    return 0;
  case IN_KIND_IPECHO:
    return 0;
  case IN_KIND_NET:
    if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) return 1;
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_VOTOR;
  case IN_KIND_REPLAY:
    if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) return 1;
    return sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_SLOT_DEAD;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
during_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  (void)seq;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    handle_epoch( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    break;
  case IN_KIND_IPECHO:
    /* unreliable link, handled in after_frag */
    break;
  case IN_KIND_NET:
    fd_memcpy( ctx->net_buf, fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz ), sz );
    break;
  case IN_KIND_REPLAY: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>sizeof(fd_replay_message_t) ) ) {
      FD_LOG_ERR(( "chunk %lu sz %lu from replay out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    handle_replay( ctx, sig, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    break;
  }
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
after_frag( fd_votor_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)tsorig; (void)tspub;

  ctx->stem = stem;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    /* reliable link, handled in during_frag */
    break;
  case IN_KIND_IPECHO:
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    ag_votor_set_shred_version( ctx->votor, ctx->shred_version );
    break;
  case IN_KIND_NET:
    if( FD_UNLIKELY( sz<sizeof(fd_eth_hdr_t) ) ) break;
    fd_quic_process_packet( ctx->quic, ctx->net_buf+sizeof(fd_eth_hdr_t), sz-sizeof(fd_eth_hdr_t), fd_log_wallclock() );
    break;
  case IN_KIND_REPLAY:
    /* reliable link, handled in during_frag */
    break;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->votor.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_keypair = fd_keyload_load( tile->votor.identity_key_path, 0 );
  memcpy( ctx->identity.uc, ctx->identity_keypair+32UL, sizeof(fd_pubkey_t) );

  static char const derive_msg[] = "bls-key-derive-alpenglow";
  uchar         ikm[ 64 ];
  fd_sha512_t   _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, ctx->identity_keypair+32UL, ctx->identity_keypair, sha );
  fd_sha512_leave( sha );
  ag_bls_sec_derive( ctx->bls_key, ikm, sizeof(ikm) );
  fd_memzero_explicit( ikm, sizeof(ikm) );

  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {

  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( AG_EQVOC_BLOCK_HASH_MAX*tile->votor.max_live_slots ) ) + 1;
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                           );
  void *            quic       = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),          fd_quic_footprint( &quic_limits )                 );
  void *            pool       = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),          ag_pool_footprint( tile->votor.max_live_slots )   );
  void *            votor      = FD_SCRATCH_ALLOC_APPEND( l, ag_votor_align(),         ag_votor_footprint( tile->votor.max_live_slots )  );
  void *            replayed   = FD_SCRATCH_ALLOC_APPEND( l, replayed_align(),         replayed_footprint( lg_blk_max )                  );
  void *            rooted     = FD_SCRATCH_ALLOC_APPEND( l, rooted_align(),           rooted_footprint( tile->votor.max_live_slots )    );
  void *            publishes  = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( tile->votor.max_live_slots ) );
  void *            id_to_rank = FD_SCRATCH_ALLOC_APPEND( l, id_to_rank_align(),       id_to_rank_footprint()                            );
  void *            notifs     = FD_SCRATCH_ALLOC_APPEND( l, notifs_align(),           notifs_footprint( tile->votor.max_live_slots ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->shred_version = (ushort)0;

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  ulong seed;
  FD_TEST( fd_rng_secure( &seed, sizeof(seed) ) );

  ctx->pool = ag_pool_join( ag_pool_new( pool, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->pool );

  ctx->votor     = ag_votor_join( ag_votor_new( votor, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->votor );
  ag_votor_set_bls_key ( ctx->votor, ctx->bls_key );

  ctx->curr_epoch_info = NULL;
  ctx->curr_epoch_slot = ULONG_MAX;
  ctx->curr_epoch_rank = USHORT_MAX;
  ctx->next_epoch_info = NULL;
  ctx->next_epoch_slot = ULONG_MAX;
  ctx->next_epoch_rank = USHORT_MAX;
  fd_memset( ctx->conn_ctxs, 0, sizeof(ctx->conn_ctxs) );

  ctx->rooted_block_id = (ag_block_id_t){ .slot = ULONG_MAX };

  ctx->replayed = replayed_join( replayed_new( replayed, lg_blk_max, seed ) );
  FD_TEST( ctx->replayed );

  ctx->rooted = rooted_join( rooted_new( rooted, tile->votor.max_live_slots ) );
  FD_TEST( ctx->rooted );

  ctx->publishes = publishes_join( publishes_new( publishes, tile->votor.max_live_slots ) );
  FD_TEST( ctx->publishes );

  ctx->id_to_rank = id_to_rank_join( id_to_rank_new( id_to_rank ) );
  FD_TEST( ctx->id_to_rank );

  ctx->notifs                 = NULL; /* joined below, only if the link exists */
  ctx->finalized_slot         = ULONG_MAX;
  ctx->finalized_slot_pending = 0;

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "net_votor"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
      ctx->in[ i ].mtu    = link->mtu;
    }
  }

  FD_TEST( tile->out_cnt>OUT_IDX_NET );
  fd_topo_link_t const * votor_out = &topo->links[ tile->out_link_id[ OUT_IDX_VOTOR ] ];
  FD_TEST( !strcmp( votor_out->name, "votor_out" ) );
  ctx->votor_out_mem    = topo->workspaces[ topo->objs[ votor_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->votor_out_chunk0 = fd_dcache_compact_chunk0( ctx->votor_out_mem, votor_out->dcache );
  ctx->votor_out_wmark  = fd_dcache_compact_wmark ( ctx->votor_out_mem, votor_out->dcache, votor_out->mtu );
  ctx->votor_out_chunk  = ctx->votor_out_chunk0;

  fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ OUT_IDX_NET ] ];
  FD_TEST( !strcmp( net_out->name, "votor_net" ) );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ctx->votor_notif_out_idx = fd_topo_find_tile_out_link( topo, tile, "votor_notif", 0UL );
  if( FD_LIKELY( ctx->votor_notif_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * votor_notif_out = &topo->links[ tile->out_link_id[ ctx->votor_notif_out_idx ] ];
    ctx->votor_notif_out_mem    = topo->workspaces[ topo->objs[ votor_notif_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->votor_notif_out_chunk0 = fd_dcache_compact_chunk0( ctx->votor_notif_out_mem, votor_notif_out->dcache );
    ctx->votor_notif_out_wmark  = fd_dcache_compact_wmark ( ctx->votor_notif_out_mem, votor_notif_out->dcache, votor_notif_out->mtu );
    ctx->votor_notif_out_chunk  = ctx->votor_notif_out_chunk0;

    ctx->notifs = notifs_join( notifs_new( notifs, tile->votor.max_live_slots ) );
    FD_TEST( ctx->notifs );
  }

  ctx->quic = fd_quic_join( fd_quic_new( quic, &quic_limits ) );
  FD_TEST( ctx->quic );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_aio_tx ) );
  FD_TEST( quic_tx_aio );
  fd_quic_set_aio_net_tx( ctx->quic, quic_tx_aio );

  ctx->quic->config.role         = FD_QUIC_ROLE_SERVER;
  ctx->quic->config.retry        = 0;
  ctx->quic->config.idle_timeout = 5L*1000L*1000L*1000L;
  ctx->quic->config.ack_delay    = 2L*1000L*1000L;
  fd_memcpy( ctx->quic->config.identity_public_key, ctx->identity_keypair+32UL, 32UL );
  ctx->quic->config.sign         = quic_sign;
  ctx->quic->config.sign_ctx     = ctx;
  ctx->quic->config.alpn[ 0 ]    = 0x0c;
  fd_memcpy( ctx->quic->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic->config.alpn_sz      = 13UL;
  ctx->quic->config.initial_rx_max_stream_data = 0UL;
  ctx->quic->config.max_datagram_frame_size    = 1280UL;

  ctx->quic->cb.quic_ctx    = ctx;
  ctx->quic->cb.conn_new    = quic_conn_new;
  ctx->quic->cb.datagram_rx = quic_datagram_rx;

  FD_TEST( fd_quic_init( ctx->quic ) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_votor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_votor_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  return out_cnt;
}

#define STEM_BURST (2UL)
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_votor_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_votor = {
  .name                     = "votor",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
