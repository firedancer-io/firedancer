#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"

/* Pull the verifier tile into the fuzz target so the paired harness can
   route packets through the real static gossvf validation path. */
#define fd_tile_gossvf fd_tile_gossvf_pair_fuzz_unused
#include "fd_gossvf_tile.c"
#undef fd_tile_gossvf

#define PAIR_NODE_CNT       (2UL)
#define PAIR_MAX_VALUES     (256UL)
#define PAIR_OUT_DEPTH      (256UL)
#define PAIR_OUT_DBUF_SZ    (1UL<<17UL)
#define PAIR_TCACHE_DEPTH   (1UL<<10UL)
#define PAIR_QUEUE_DEPTH    (128UL)
#define PAIR_SHRED_VERSION  (42U)
#define PAIR_MAX_ACTIONS    (96UL)
#define PAIR_MAX_SLOT       (1000000000000000UL)

/* The production gossvf tile sizes its peer/ping/stake tables for a full
   mainnet cluster (FD_CONTACT_INFO_TABLE_SIZE, FD_PING_TRACKER_MAX,
   MAX_SHRED_DESTS).  This harness only ever exercises PAIR_NODE_CNT nodes,
   so we size the tables for the actual workload.  This shrinks the per-input
   backing memory (and the memset that zeroes it) by orders of magnitude
   without losing any reachable behavior. */
#define PAIR_PEER_CAP       (256UL)
#define PAIR_PING_CAP       (256UL)
#define PAIR_STAKE_CAP      (16UL)
#define PAIR_GOSSVF_OUT_MTU \
  (sizeof(fd_gossip_message_t) + FD_GOSSIP_MESSAGE_MAX_CRDS + FD_NET_MTU)

typedef struct pair_env pair_env_t;

typedef struct {
  uchar       priv[ 32UL ];
  fd_pubkey_t pub[ 1 ];
} pair_identity_t;

typedef struct {
  uchar const * cur;
  ulong         rem;
} pair_cursor_t;

typedef struct {
  pair_env_t * env;
  ulong        idx;

  fd_gossip_t * gossip;
  fd_rng_t      rng[ 1 ];
  fd_gossip_out_ctx_t gossip_out[ 1 ];
  fd_gossip_out_ctx_t net_out[ 1 ];
  fd_frag_meta_t *    gossip_mcache;
  fd_stem_context_t   gossip_stem[ 1 ];
  fd_frag_meta_t *    gossip_stem_mcache[ 1 ];
  ulong               gossip_stem_seq[ 1 ];
  ulong               gossip_stem_depth[ 1 ];
  ulong               gossip_stem_cr_avail[ 1 ];
  ulong               gossip_stem_min_cr_avail[ 1 ];
  int                 gossip_stem_out_reliable[ 1 ];
  ulong               gossip_drain_seq;

  fd_gossvf_tile_ctx_t vf[ 1 ];
  fd_frag_meta_t *     vf_mcache;
  fd_stem_context_t    vf_stem[ 1 ];
  fd_frag_meta_t *     vf_stem_mcache[ 1 ];
  ulong                vf_stem_seq[ 1 ];
  ulong                vf_stem_depth[ 1 ];
  ulong                vf_stem_cr_avail[ 1 ];
  ulong                vf_stem_min_cr_avail[ 1 ];
  int                  vf_stem_out_reliable[ 1 ];
  ulong                vf_drain_seq;

  fd_ip4_port_t addr;
  ushort        port_host;
} pair_node_t;

typedef struct {
  ulong        src_idx;
  ulong        dst_idx;
  fd_ip4_port_t src;
  fd_ip4_port_t dst;
  uchar        payload[ FD_NET_MTU ];
  ulong        payload_sz;
} pair_packet_t;

struct pair_env {
  pair_node_t nodes[ PAIR_NODE_CNT ];

  pair_packet_t queue[ PAIR_QUEUE_DEPTH ];
  ulong         queue_head;
  ulong         queue_cnt;

  long  now;
  ulong mutator_idx;

  uchar value_buf[ FD_GOSSIP_VALUE_MAX_SZ ];
  uchar wire_buf [ FD_NET_MTU ];
};

static pair_identity_t identities[ PAIR_NODE_CNT ];
static fd_sha512_t sha512[ 1 ];
static pair_env_t * pair_env;
static uchar *      pair_mem;
static ulong        pair_mem_sz;

static ulong
pair_mem_align( void ) {
  ulong a = 128UL;
  a = fd_ulong_max( a, fd_gossip_align() );
  a = fd_ulong_max( a, peer_pool_align () );
  a = fd_ulong_max( a, peer_map_align  () );
  a = fd_ulong_max( a, ping_pool_align () );
  a = fd_ulong_max( a, ping_map_align  () );
  a = fd_ulong_max( a, stake_pool_align() );
  a = fd_ulong_max( a, stake_map_align () );
  a = fd_ulong_max( a, fd_tcache_align () );
  a = fd_ulong_max( a, FD_CHUNK_ALIGN    );
  a = fd_ulong_max( a, fd_mcache_align() );
  return a;
}

static ulong
pair_node_layout_append( ulong l ) {
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(), fd_gossip_footprint( PAIR_MAX_VALUES, 1UL ) );
  l = FD_LAYOUT_APPEND( l, FD_CHUNK_ALIGN,    PAIR_OUT_DBUF_SZ );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(), fd_mcache_footprint( PAIR_OUT_DEPTH, 0UL ) );

  l = FD_LAYOUT_APPEND( l, peer_pool_align(),  peer_pool_footprint( PAIR_PEER_CAP ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*PAIR_PEER_CAP ) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),  ping_pool_footprint( PAIR_PING_CAP ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*PAIR_PING_CAP ) );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(), stake_pool_footprint( PAIR_STAKE_CAP ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( PAIR_STAKE_CAP ) ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( PAIR_TCACHE_DEPTH, 0UL ) );
  l = FD_LAYOUT_APPEND( l, FD_CHUNK_ALIGN,     PAIR_OUT_DBUF_SZ );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(),  fd_mcache_footprint( PAIR_OUT_DEPTH, 0UL ) );
  return l;
}

static ulong
pair_mem_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) l = pair_node_layout_append( l );
  return FD_LAYOUT_FINI( l, pair_mem_align() );
}

static ulong
pair_wmark( ulong dbuf_sz,
            ulong mtu ) {
  ulong chunk_cnt = dbuf_sz >> FD_CHUNK_LG_SZ;
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ - 1UL) >>
                     (1UL+FD_CHUNK_LG_SZ)) << 1UL;
  FD_TEST( chunk_cnt>chunk_mtu );
  return chunk_cnt - chunk_mtu;
}

static uchar
pair_u8( pair_cursor_t * cur ) {
  if( FD_UNLIKELY( !cur->rem ) ) return 0U;
  uchar v = cur->cur[ 0 ];
  cur->cur++;
  cur->rem--;
  return v;
}

static ulong
pair_u64( pair_cursor_t * cur ) {
  ulong x = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) x |= (ulong)pair_u8( cur ) << (8UL*i);
  return x;
}

static ulong
pair_bounded( pair_cursor_t * cur,
              ulong           bound ) {
  return bound ? pair_u64( cur ) % bound : 0UL;
}

static int
pair_txn_write_u8( uchar ** p,
                   ulong *   rem,
                   uchar     x ) {
  if( FD_UNLIKELY( !*rem ) ) return 0;
  FD_STORE( uchar, *p, x );
  (*p)++;
  (*rem)--;
  return 1;
}

static int
pair_txn_write_u16_varint( uchar ** p,
                           ulong *   rem,
                           ushort    x ) {
  if( FD_LIKELY( x<128U ) ) return pair_txn_write_u8( p, rem, (uchar)x );
  if( FD_LIKELY( x<16384U ) ) {
    if( FD_UNLIKELY( *rem<2UL ) ) return 0;
    FD_STORE( uchar, *p,     (uchar)((x & 0x7FU) | 0x80U) );
    FD_STORE( uchar, (*p)+1, (uchar)(x >> 7U) );
    (*p) += 2UL;
    (*rem) -= 2UL;
    return 1;
  }
  if( FD_UNLIKELY( *rem<3UL ) ) return 0;
  FD_STORE( uchar, *p,     (uchar)((x & 0x7FU) | 0x80U) );
  FD_STORE( uchar, (*p)+1, (uchar)(((x >> 7U) & 0x7FU) | 0x80U) );
  FD_STORE( uchar, (*p)+2, (uchar)(x >> 14U) );
  (*p) += 3UL;
  (*rem) -= 3UL;
  return 1;
}

static int
pair_txn_write_u32( uchar ** p,
                    ulong *   rem,
                    uint      x ) {
  if( FD_UNLIKELY( *rem<4UL ) ) return 0;
  FD_STORE( uint, *p, x );
  (*p) += 4UL;
  (*rem) -= 4UL;
  return 1;
}

static int
pair_txn_write_u64( uchar ** p,
                    ulong *   rem,
                    ulong     x ) {
  if( FD_UNLIKELY( *rem<8UL ) ) return 0;
  FD_STORE( ulong, *p, x );
  (*p) += 8UL;
  (*rem) -= 8UL;
  return 1;
}

static int
pair_txn_write_bytes( uchar **     p,
                      ulong *       rem,
                      uchar const * src,
                      ulong         sz ) {
  if( FD_UNLIKELY( *rem<sz ) ) return 0;
  fd_memcpy( *p, src, sz );
  (*p) += sz;
  (*rem) -= sz;
  return 1;
}

static ulong
pair_build_vote_txn( uchar *         out,
                     ulong           out_sz,
                     ulong           src_idx,
                     pair_cursor_t * cur ) {
  uchar instr[ 128UL ];
  uchar * q = instr;
  ulong instr_rem = sizeof(instr);

  ulong slot_cnt = 1UL + pair_bounded( cur, 4UL );
  ulong base_slot = 1000UL + pair_bounded( cur, 1000000UL );
  if( FD_UNLIKELY( !pair_txn_write_u32( &q, &instr_rem, fd_vote_instruction_enum_vote ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u64( &q, &instr_rem, slot_cnt ) ) ) return 0UL;
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    ulong slot = base_slot + i + pair_bounded( cur, 8UL );
    if( FD_UNLIKELY( !pair_txn_write_u64( &q, &instr_rem, slot ) ) ) return 0UL;
  }
  for( ulong i=0UL; i<32UL; i++ )
    if( FD_UNLIKELY( !pair_txn_write_u8( &q, &instr_rem, pair_u8( cur ) ) ) ) return 0UL;
  int has_timestamp = !!( pair_u8( cur ) & 1U );
  if( FD_UNLIKELY( !pair_txn_write_u8( &q, &instr_rem, (uchar)has_timestamp ) ) ) return 0UL;
  if( has_timestamp ) {
    ulong ts = (ulong)( 1000000000L + (long)pair_bounded( cur, 1000000000UL ) );
    if( FD_UNLIKELY( !pair_txn_write_u64( &q, &instr_rem, ts ) ) ) return 0UL;
  }
  ulong trailing = pair_bounded( cur, 8UL );
  for( ulong i=0UL; i<trailing; i++ )
    if( FD_UNLIKELY( !pair_txn_write_u8( &q, &instr_rem, pair_u8( cur ) ) ) ) return 0UL;
  ulong instr_sz = (ulong)( q - instr );

  uchar * p = out;
  ulong rem = out_sz;
  if( FD_UNLIKELY( !pair_txn_write_u16_varint( &p, &rem, 1U ) ) ) return 0UL;
  for( ulong i=0UL; i<64UL; i++ )
    if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, pair_u8( cur ) ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 0U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL;

  if( FD_UNLIKELY( !pair_txn_write_u16_varint( &p, &rem, 3U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_bytes( &p, &rem, identities[ src_idx ].pub->uc, 32UL ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_bytes( &p, &rem, identities[ src_idx ^ 1UL ].pub->uc, 32UL ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_bytes( &p, &rem, fd_solana_vote_program_id.uc, 32UL ) ) ) return 0UL;
  for( ulong i=0UL; i<32UL; i++ )
    if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, pair_u8( cur ) ) ) ) return 0UL;

  if( FD_UNLIKELY( !pair_txn_write_u16_varint( &p, &rem, 1U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 2U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u16_varint( &p, &rem, 2U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 0U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_u16_varint( &p, &rem, (ushort)instr_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( !pair_txn_write_bytes( &p, &rem, instr, instr_sz ) ) ) return 0UL;

  return (ulong)( p - out );
}

static void
init_identities( void ) {
  static int initialized = 0;
  if( FD_LIKELY( initialized ) ) return;

  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) {
    for( ulong j=0UL; j<32UL; j++ )
      identities[ i ].priv[ j ] = (uchar)( 7U + 19U*(uint)i + (uint)j );
    fd_ed25519_public_from_private( identities[ i ].pub->uc,
                                    identities[ i ].priv,
                                    sha512 );
  }
  initialized = 1;
}

static int
pair_queue_push( pair_env_t const * env_const,
                 pair_packet_t const * pkt ) {
  pair_env_t * env = (pair_env_t *)env_const;
  if( FD_UNLIKELY( env->queue_cnt>=PAIR_QUEUE_DEPTH ) ) return 0;

  ulong tail = (env->queue_head + env->queue_cnt) % PAIR_QUEUE_DEPTH;
  env->queue[ tail ] = *pkt;
  env->queue_cnt++;
  return 1;
}

static int
pair_queue_pop( pair_env_t *    env,
                pair_packet_t * pkt ) {
  if( FD_UNLIKELY( !env->queue_cnt ) ) return 0;
  *pkt = env->queue[ env->queue_head ];
  env->queue_head = (env->queue_head + 1UL) % PAIR_QUEUE_DEPTH;
  env->queue_cnt--;
  return 1;
}

static long
pair_find_node_by_addr( pair_env_t const * env,
                        fd_ip4_port_t      addr ) {
  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) {
    if( FD_LIKELY( env->nodes[ i ].addr.addr==addr.addr &&
                   env->nodes[ i ].addr.port==addr.port ) ) return (long)i;
  }
  return -1L;
}

static void
pair_send_fn( void *                _node,
              fd_stem_context_t *   stem FD_PARAM_UNUSED,
              uchar const *         data,
              ulong                 sz,
              fd_ip4_port_t const * peer_address,
              ulong                 now FD_PARAM_UNUSED ) {
  pair_node_t * node = (pair_node_t *)_node;
  if( FD_UNLIKELY( sz>FD_NET_MTU ) ) return;

  long dst_idx = pair_find_node_by_addr( node->env, *peer_address );
  if( FD_UNLIKELY( dst_idx<0L ) ) return;

  /* No memset: every header field is assigned below and only the first
     payload_sz payload bytes are ever read back (pair_deliver_payload and
     pair_mutate_packet both bound their access by payload_sz). */
  pair_packet_t pkt[1];
  pkt->src_idx    = node->idx;
  pkt->dst_idx    = (ulong)dst_idx;
  pkt->src        = node->addr;
  pkt->dst        = *peer_address;
  pkt->payload_sz = sz;
  fd_memcpy( pkt->payload, data, sz );
  pair_queue_push( node->env, pkt );
}

static void
pair_sign_fn( void *       _node,
              uchar const * data,
              ulong        sz,
              int          sign_type,
              uchar *      out_signature ) {
  pair_node_t * node = (pair_node_t *)_node;
  pair_identity_t * id = &identities[ node->idx ];

  if( sign_type==FD_KEYGUARD_SIGN_TYPE_ED25519 ) {
    fd_ed25519_sign( out_signature, data, sz, id->pub->uc, id->priv, sha512 );
  } else if( sign_type==FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) {
    uchar hash[ 32UL ];
    fd_sha256_hash( data, sz, hash );
    fd_ed25519_sign( out_signature, hash, 32UL, id->pub->uc, id->priv, sha512 );
  } else {
    FD_LOG_ERR(( "unexpected sign type %d", sign_type ));
  }
}

static void
pair_ping_change_fn( void *        _node,
                     uchar const * peer_pubkey,
                     fd_ip4_port_t peer_address,
                     long          now FD_PARAM_UNUSED,
                     int           change_type ) {
  pair_node_t * node = (pair_node_t *)_node;
  fd_gossip_ping_update_t update[1];
  memset( update, 0, sizeof(update) );
  fd_memcpy( update->pubkey.uc, peer_pubkey, 32UL );
  update->gossip_addr.l = peer_address.l;
  update->remove = change_type!=FD_PING_TRACKER_CHANGE_TYPE_ACTIVE;

  ping_t * existing = ping_map_ele_query( node->vf->ping_map,
                                          &update->pubkey,
                                          NULL,
                                          node->vf->pings );
  if( FD_UNLIKELY( update->remove ) ) {
    if( FD_LIKELY( existing ) ) handle_ping_update( node->vf, update );
  } else {
    if( FD_LIKELY( existing ) ) existing->addr.l = update->gossip_addr.l;
    else                        handle_ping_update( node->vf, update );
  }
}

static void
pair_activity_update_fn( void *                           _node FD_PARAM_UNUSED,
                         fd_pubkey_t const *              identity FD_PARAM_UNUSED,
                         fd_gossip_contact_info_t const * ci FD_PARAM_UNUSED,
                         int                              change_type FD_PARAM_UNUSED ) {
}

static void
pair_init_stem( fd_stem_context_t * stem,
                fd_frag_meta_t **   mcache,
                ulong *             seq,
                ulong *             depth,
                ulong *             cr_avail,
                ulong *             min_cr_avail,
                int *               out_reliable ) {
  seq[0]          = 0UL;
  depth[0]        = PAIR_OUT_DEPTH;
  cr_avail[0]     = ULONG_MAX/4UL;
  min_cr_avail[0] = ULONG_MAX/4UL;
  out_reliable[0] = 0;

  stem->mcaches             = mcache;
  stem->seqs                = seq;
  stem->depths              = depth;
  stem->cr_avail            = cr_avail;
  stem->min_cr_avail        = min_cr_avail;
  stem->cr_decrement_amount = 1UL;
  stem->out_reliable        = out_reliable;
}

static ulong
pair_setup_vf( pair_node_t * node,
               ulong         _mem,
               ulong         seed ) {
  fd_gossvf_tile_ctx_t * ctx = node->vf;
  /* ctx embeds stake.msg_buf[ FD_EPOCH_INFO_MAX_MSG_SZ ] (~10 MiB, sized for
     MAX_STAKED_LEADERS).  Zeroing it every input dominates the per-exec cost
     and is unnecessary: pair_apply_stakes() zeroes the used prefix before
     writing it, and handle_epoch() only reads staked_id_cnt entries.  Zero
     everything except that buffer. */
  ulong const msgbuf_off = offsetof( fd_gossvf_tile_ctx_t, stake.msg_buf );
  ulong const msgbuf_end = msgbuf_off + sizeof( ctx->stake.msg_buf );
  memset( (uchar *)ctx,              0, msgbuf_off                 );
  memset( (uchar *)ctx + msgbuf_end, 0, sizeof(*ctx) - msgbuf_end  );

  ctx->seed                  = seed;
  ctx->shred_version         = PAIR_SHRED_VERSION;
  ctx->allow_private_address = 0;
  ctx->gossip_addr           = node->addr;
  ctx->src_addr              = node->addr;
  ctx->round_robin_cnt       = 1UL;
  ctx->round_robin_idx       = 0UL;
  fd_clock_tile_init( ctx->clock );
  ctx->instance_creation_wallclock_nanos = node->env->now;
  *ctx->identity_pubkey      = *identities[ node->idx ].pub;

  void * peer_pool_mem  = FD_SCRATCH_ALLOC_APPEND( mem, peer_pool_align(),  peer_pool_footprint( PAIR_PEER_CAP ) );
  void * peer_map_mem   = FD_SCRATCH_ALLOC_APPEND( mem, peer_map_align(),   peer_map_footprint( 2UL*PAIR_PEER_CAP ) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( mem, ping_pool_align(),  ping_pool_footprint( PAIR_PING_CAP ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( mem, ping_map_align(),   ping_map_footprint( 2UL*PAIR_PING_CAP ) );
  void * stake_pool_mem = FD_SCRATCH_ALLOC_APPEND( mem, stake_pool_align(), stake_pool_footprint( PAIR_STAKE_CAP ) );
  void * stake_map_mem  = FD_SCRATCH_ALLOC_APPEND( mem, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( PAIR_STAKE_CAP ) ) );
  void * tcache_mem     = FD_SCRATCH_ALLOC_APPEND( mem, fd_tcache_align(),  fd_tcache_footprint( PAIR_TCACHE_DEPTH, 0UL ) );

  ctx->peers      = peer_pool_join( peer_pool_new( peer_pool_mem, PAIR_PEER_CAP ) );
  ctx->peer_map   = peer_map_join ( peer_map_new ( peer_map_mem, 2UL*PAIR_PEER_CAP, ctx->seed ) );
  ctx->pings      = ping_pool_join( ping_pool_new( ping_pool_mem, PAIR_PING_CAP ) );
  ctx->ping_map   = ping_map_join ( ping_map_new ( ping_map_mem,  2UL*PAIR_PING_CAP, ctx->seed ) );
  ctx->stake.pool = stake_pool_join( stake_pool_new( stake_pool_mem, PAIR_STAKE_CAP ) );
  ctx->stake.map  = stake_map_join ( stake_map_new ( stake_map_mem, stake_map_chain_cnt_est( PAIR_STAKE_CAP ), ctx->seed ) );
  FD_TEST( ctx->peers && ctx->peer_map && ctx->pings &&
           ctx->ping_map && ctx->stake.pool && ctx->stake.map );

  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( tcache_mem, PAIR_TCACHE_DEPTH, 0UL ) );
  FD_TEST( tcache );
  ctx->tcache.depth   = fd_tcache_depth       ( tcache );
  ctx->tcache.map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache.sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache.ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache.map     = fd_tcache_map_laddr   ( tcache );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  void * out_dcache = FD_SCRATCH_ALLOC_APPEND( mem, FD_CHUNK_ALIGN, PAIR_OUT_DBUF_SZ );
  ctx->out->mem     = out_dcache;
  ctx->out->chunk0  = fd_laddr_to_chunk( out_dcache, out_dcache );
  ctx->out->wmark   = ctx->out->chunk0 + pair_wmark( PAIR_OUT_DBUF_SZ,
                                                      PAIR_GOSSVF_OUT_MTU );
  ctx->out->chunk   = ctx->out->chunk0;

  void * mcache_mem = FD_SCRATCH_ALLOC_APPEND( mem, fd_mcache_align(),
                                               fd_mcache_footprint( PAIR_OUT_DEPTH, 0UL ) );
  node->vf_mcache = fd_mcache_join( fd_mcache_new( mcache_mem, PAIR_OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( node->vf_mcache );
  node->vf_stem_mcache[0] = node->vf_mcache;
  pair_init_stem( node->vf_stem,
                  node->vf_stem_mcache,
                  node->vf_stem_seq,
                  node->vf_stem_depth,
                  node->vf_stem_cr_avail,
                  node->vf_stem_min_cr_avail,
                  node->vf_stem_out_reliable );
  node->vf_drain_seq = 0UL;

  return _mem;
}

static ulong
pair_setup_gossip( pair_node_t * node,
                   ulong         _mem,
                   ulong         seed ) {
  void * gossip_mem = FD_SCRATCH_ALLOC_APPEND( mem,
                                               fd_gossip_align(),
                                               fd_gossip_footprint( PAIR_MAX_VALUES, 1UL ) );
  FD_TEST( fd_rng_join( fd_rng_new( node->rng, (uint)seed, seed>>32 ) ) );

  void * gossip_dcache = FD_SCRATCH_ALLOC_APPEND( mem, FD_CHUNK_ALIGN, PAIR_OUT_DBUF_SZ );
  node->gossip_out->mem    = gossip_dcache;
  node->gossip_out->chunk0 = fd_laddr_to_chunk( gossip_dcache, gossip_dcache );
  node->gossip_out->chunk  = node->gossip_out->chunk0;
  node->gossip_out->wmark  = node->gossip_out->chunk0 + pair_wmark( PAIR_OUT_DBUF_SZ,
                                                                     FD_NET_MTU );
  node->gossip_out->idx    = 0UL;
  node->net_out[0] = node->gossip_out[0];

  void * mcache_mem = FD_SCRATCH_ALLOC_APPEND( mem, fd_mcache_align(), fd_mcache_footprint( PAIR_OUT_DEPTH, 0UL ) );
  node->gossip_mcache = fd_mcache_join( fd_mcache_new( mcache_mem, PAIR_OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( node->gossip_mcache );
  node->gossip_stem_mcache[0] = node->gossip_mcache;
  pair_init_stem( node->gossip_stem,
                  node->gossip_stem_mcache,
                  node->gossip_stem_seq,
                  node->gossip_stem_depth,
                  node->gossip_stem_cr_avail,
                  node->gossip_stem_min_cr_avail,
                  node->gossip_stem_out_reliable );
  node->gossip_drain_seq = 0UL;

  fd_gossip_contact_info_t contact[1];
  memset( contact, 0, sizeof(contact) );
  contact->outset        = (ulong)FD_NANOSEC_TO_MICRO( node->env->now - 1000000L );
  contact->shred_version = PAIR_SHRED_VERSION;
  contact->version.major = 2U;
  contact->version.client = FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER;
  contact->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] = (fd_gossip_socket_t){
    .port    = node->addr.port,
    .is_ipv6 = 0U,
    .ip4     = node->addr.addr
  };
  contact->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ] = (fd_gossip_socket_t){
    .port    = fd_ushort_bswap( (ushort)( node->port_host + 1000U ) ),
    .is_ipv6 = 0U,
    .ip4     = node->addr.addr
  };

  fd_ip4_port_t entrypoint = node->env->nodes[ node->idx ^ 1UL ].addr;
  void * gossip = fd_gossip_new( gossip_mem,
                                 node->rng,
                                 PAIR_MAX_VALUES,
                                 1UL,
                                 &entrypoint,
                                 identities[ node->idx ].pub->uc,
                                 contact,
                                 node->env->now,
                                 pair_send_fn,
                                 node,
                                 pair_sign_fn,
                                 node,
                                 pair_ping_change_fn,
                                 node,
                                 pair_activity_update_fn,
                                 node,
                                 node->gossip_out,
                                 node->net_out );
  node->gossip = fd_gossip_join( gossip );
  FD_TEST( node->gossip );
  fd_gossip_set_shred_version( node->gossip, PAIR_SHRED_VERSION, node->env->now );

  return _mem;
}

static void
pair_apply_stakes( pair_env_t * env,
                   ulong        stake0,
                   ulong        stake1 ) {
  fd_stake_weight_t weights[ PAIR_NODE_CNT ];
  weights[0].key = *identities[0].pub;
  weights[0].stake = stake0;
  weights[1].key = *identities[1].pub;
  weights[1].stake = stake1;

  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) {
    fd_gossip_stakes_update( env->nodes[ i ].gossip, weights, PAIR_NODE_CNT );

    fd_gossvf_tile_ctx_t * vf = env->nodes[ i ].vf;
    memset( vf->stake.msg_buf,
            0,
            sizeof(fd_epoch_info_msg_t) + PAIR_NODE_CNT*sizeof(fd_stake_weight_t) );
    fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)vf->stake.msg_buf;
    msg->staked_id_cnt = PAIR_NODE_CNT;
    fd_memcpy( fd_epoch_info_msg_id_weights( msg ), weights, sizeof(weights) );
    handle_epoch( vf, msg );
  }
}

static void pair_drain_gossip_updates( pair_node_t * node );
static void pair_advance_node( pair_node_t * node, long now );

static void
pair_drain_vf_output( pair_node_t * node,
                      long          now ) {
  while( node->vf_drain_seq < node->vf_stem_seq[0] ) {
    ulong seq = node->vf_drain_seq++;
    fd_frag_meta_t const * meta = node->vf_mcache + fd_mcache_line_idx( seq, PAIR_OUT_DEPTH );
    if( FD_UNLIKELY( meta->seq!=seq ) ) continue;

    uchar const * payload = fd_chunk_to_laddr_const( node->vf->out->mem, meta->chunk );
    fd_ip4_port_t peer = {
      .addr = fd_gossvf_sig_addr( meta->sig ),
      .port = fd_gossvf_sig_port( meta->sig )
    };

    switch( fd_gossvf_sig_kind( meta->sig ) ) {
      case 0U:
        fd_gossip_rx( node->gossip, peer, payload, meta->sz, now, node->gossip_stem );
        fd_gossip_advance( node->gossip, now, node->gossip_stem, NULL );
        pair_drain_gossip_updates( node );
        break;
      case 1U: {
        if( FD_UNLIKELY( meta->sz!=sizeof(fd_gossip_pingreq_t) ) ) break;
        fd_gossip_pingreq_t const * pingreq = (fd_gossip_pingreq_t const *)payload;
        fd_gossip_ping_tracker_track( node->gossip, pingreq->pubkey.uc, peer, now );
        pair_drain_gossip_updates( node );
        break;
      }
      default:
        break;
    }
  }
}

static void
pair_drain_gossip_updates( pair_node_t * node ) {
  while( node->gossip_drain_seq < node->gossip_stem_seq[0] ) {
    ulong seq = node->gossip_drain_seq++;
    fd_frag_meta_t const * meta = node->gossip_mcache + fd_mcache_line_idx( seq, PAIR_OUT_DEPTH );
    if( FD_UNLIKELY( meta->seq!=seq ) ) continue;
    if( FD_UNLIKELY( meta->sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
                     meta->sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) ) continue;

    fd_gossip_update_message_t * update =
      (fd_gossip_update_message_t *)fd_chunk_to_laddr( node->gossip_out->mem, meta->chunk );

    peer_t * existing = peer_map_ele_query( node->vf->peer_map,
                                            fd_type_pun_const( update->origin ),
                                            NULL,
                                            node->vf->peers );
    if( FD_UNLIKELY( meta->sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) ) {
      if( FD_LIKELY( existing ) ) handle_peer_update( node->vf, update );
    } else {
      handle_peer_update( node->vf, update );
    }
  }
}

static void
pair_advance_node( pair_node_t * node,
                   long          now ) {
  fd_gossip_advance( node->gossip, now, node->gossip_stem, NULL );
  pair_drain_gossip_updates( node );
}

static void
pair_deliver_payload( pair_node_t *  dst,
                      fd_ip4_port_t  src,
                      fd_ip4_port_t  daddr,
                      uchar const *  payload,
                      ulong          payload_sz,
                      long           now ) {
  if( FD_UNLIKELY( payload_sz + sizeof(fd_ip4_udp_hdrs_t) > FD_NET_MTU ) ) return;

  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, src.addr, fd_ushort_bswap( src.port ) );
  hdrs->ip4->daddr      = daddr.addr;
  hdrs->udp->net_dport  = daddr.port;
  hdrs->ip4->check      = fd_ip4_hdr_check_fast( hdrs->ip4 );

  ulong packet_sz = sizeof(fd_ip4_udp_hdrs_t) + payload_sz;
  fd_memcpy( dst->vf->payload, hdrs, sizeof(fd_ip4_udp_hdrs_t) );
  fd_memcpy( dst->vf->payload + sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  int result = handle_net( dst->vf, packet_sz, (ulong)now, dst->vf_stem );
  dst->vf->metrics.message_rx[ result ]++;
  dst->vf->metrics.message_rx_bytes[ result ] += packet_sz;
  pair_drain_vf_output( dst, now );
}

static void
pair_mutate_packet( pair_packet_t * pkt,
                    pair_cursor_t * cur,
                    uchar           op ) {
  switch( op ) {
    case 8U:
    case 15U: {
      if( FD_UNLIKELY( !pkt->payload_sz ) ) break;
      ulong flip_cnt = 1UL + pair_bounded( cur, op==15U ? 8UL : 2UL );
      for( ulong i=0UL; i<flip_cnt; i++ ) {
        ulong off = pair_bounded( cur, pkt->payload_sz );
        pkt->payload[ off ] ^= (uchar)( pair_u8( cur ) | 1U );
      }
      break;
    }
    case 9U: {
      if( FD_LIKELY( pkt->payload_sz ) ) pkt->payload_sz = pair_bounded( cur, pkt->payload_sz );
      break;
    }
    case 10U:
      pkt->src.addr = FD_IP4_ADDR( 1, 1, 1, (uint)( 32UL + pair_bounded( cur, 64UL ) ) );
      pkt->src.port = fd_ushort_bswap( (ushort)( 7000UL + pair_bounded( cur, 1000UL ) ) );
      break;
    case 14U: {
      ulong room = FD_NET_MTU - sizeof(fd_ip4_udp_hdrs_t) - pkt->payload_sz;
      ulong add  = pair_bounded( cur, fd_ulong_min( room, 16UL ) + 1UL );
      for( ulong i=0UL; i<add; i++ ) pkt->payload[ pkt->payload_sz++ ] = pair_u8( cur );
      break;
    }
    default:
      break;
  }
}

static void
pair_pump_network( pair_env_t *    env,
                   pair_cursor_t * cur,
                   ulong           max_steps ) {
  for( ulong step=0UL; step<max_steps; step++ ) {
    pair_packet_t pkt[1];
    if( FD_UNLIKELY( !pair_queue_pop( env, pkt ) ) ) return;

    uchar op = 0U;
    if( FD_UNLIKELY( pkt->src_idx==env->mutator_idx ) ) op = (uchar)( pair_u8( cur ) & 15U );

    if( FD_UNLIKELY( op==12U ) ) continue;
    if( FD_UNLIKELY( op==13U ) ) {
      pair_queue_push( env, pkt );
      continue;
    }

    int duplicate = op==11U;
    pair_mutate_packet( pkt, cur, op );

    pair_deliver_payload( &env->nodes[ pkt->dst_idx ], pkt->src, pkt->dst, pkt->payload, pkt->payload_sz, env->now );
    if( FD_UNLIKELY( duplicate ) ) {
      pair_deliver_payload( &env->nodes[ pkt->dst_idx ], pkt->src, pkt->dst, pkt->payload, pkt->payload_sz, env->now );
    }
  }
}

static void
pair_set_shred_version( pair_node_t * node,
                        ushort        shred_version,
                        long          now ) {
  node->vf->shred_version = shred_version;
  fd_gossip_set_shred_version( node->gossip, shred_version, now );
  pair_advance_node( node, now );
}

static long
pair_serialize_signed_value( fd_gossip_value_t * value,
                             ulong               src_idx,
                             uchar *             out,
                             ulong               out_sz,
                             int                 corrupt_sig ) {
  memset( value->signature, 0, sizeof(value->signature) );
  long value_sz = fd_gossip_value_serialize( value, out, out_sz );
  if( FD_UNLIKELY( value_sz<=64L ) ) return -1L;

  pair_identity_t * id = &identities[ src_idx ];
  fd_ed25519_sign( value->signature,
                   out+64UL,
                   (ulong)value_sz-64UL,
                   id->pub->uc,
                   id->priv,
                   sha512 );
  if( FD_UNLIKELY( corrupt_sig ) ) value->signature[ 0 ] ^= 0x20U;

  return fd_gossip_value_serialize( value, out, out_sz );
}

static ulong
pair_build_crds_msg( pair_env_t *  env,
                     uint          tag,
                     ulong         src_idx,
                     uchar const * value_bytes,
                     ulong         value_sz ) {
  if( FD_UNLIKELY( 4UL+32UL+8UL+value_sz>sizeof(env->wire_buf) ) ) return 0UL;

  uchar * p = env->wire_buf;
  FD_STORE( uint,  p, tag ); p += 4UL;
  fd_memcpy( p, identities[ src_idx ].pub->uc, 32UL ); p += 32UL;
  FD_STORE( ulong, p, 1UL ); p += 8UL;
  fd_memcpy( p, value_bytes, value_sz ); p += value_sz;

  return (ulong)( p - env->wire_buf );
}

static void
pair_make_snapshot_hashes_value( pair_node_t *       node,
                                 pair_cursor_t *     cur,
                                 fd_gossip_value_t * value,
                                 long                now ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_SNAPSHOT_HASHES;
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );
  fd_memcpy( value->origin, identities[ node->idx ].pub->uc, 32UL );

  value->snapshot_hashes->full_slot = pair_bounded( cur, PAIR_MAX_SLOT-64UL );
  for( ulong i=0UL; i<sizeof(value->snapshot_hashes->full_hash); i++ )
    value->snapshot_hashes->full_hash[ i ] = pair_u8( cur );

  value->snapshot_hashes->incremental_len = pair_bounded( cur, 4UL );
  ulong slot = value->snapshot_hashes->full_slot;
  for( ulong i=0UL; i<value->snapshot_hashes->incremental_len; i++ ) {
    slot += 1UL + pair_bounded( cur, 4UL );
    value->snapshot_hashes->incremental[ i ].slot = slot;
    for( ulong j=0UL; j<sizeof(value->snapshot_hashes->incremental[ i ].hash); j++ )
      value->snapshot_hashes->incremental[ i ].hash[ j ] = pair_u8( cur );
  }
}

static void
pair_send_crds_value( pair_env_t *        env,
                      ulong               src_idx,
                      ulong               dst_idx,
                      fd_gossip_value_t * value,
                      uint                message_tag,
                      int                 corrupt_sig,
                      long                now ) {
  long value_sz = pair_serialize_signed_value( value,
                                               src_idx,
                                               env->value_buf,
                                               sizeof(env->value_buf),
                                               corrupt_sig );
  if( FD_UNLIKELY( value_sz<=0L ) ) return;

  ulong payload_sz = pair_build_crds_msg( env,
                                          message_tag,
                                          src_idx,
                                          env->value_buf,
                                          (ulong)value_sz );
  if( FD_UNLIKELY( !payload_sz ) ) return;

  pair_deliver_payload( &env->nodes[ dst_idx ],
                        env->nodes[ src_idx ].addr,
                        env->nodes[ dst_idx ].addr,
                        env->wire_buf,
                        payload_sz,
                        now );
}

static void
pair_send_snapshot_hashes( pair_node_t *   node,
                           pair_cursor_t * cur,
                           long            now ) {
  pair_env_t * env     = node->env;
  ulong        src_idx = node->idx;
  ulong        dst_idx = src_idx ^ 1UL;

  fd_gossip_value_t value[1];
  pair_make_snapshot_hashes_value( node, cur, value, now );

  uint message_tag = (pair_u8( cur ) & 1U) ?
                     FD_GOSSIP_MESSAGE_PULL_RESPONSE :
                     FD_GOSSIP_MESSAGE_PUSH;
  int corrupt_sig = !!( pair_u8( cur ) & 1U );

  pair_send_crds_value( env, src_idx, dst_idx, value, message_tag, corrupt_sig, now );
}

static void
pair_track_peer_for_ping( pair_node_t * node,
                          int           force_unstaked,
                          long          now ) {
  pair_env_t * env      = node->env;
  ulong        peer_idx = node->idx ^ 1UL;

  if( FD_UNLIKELY( force_unstaked ) ) {
    ulong stake0 = peer_idx==0UL ? 1UL : FD_GOSSIP_STAKED_THRESHOLD;
    ulong stake1 = peer_idx==1UL ? 1UL : FD_GOSSIP_STAKED_THRESHOLD;
    pair_apply_stakes( env, stake0, stake1 );
  }

  fd_gossip_ping_tracker_track( node->gossip, identities[ peer_idx ].pub->uc, env->nodes[ peer_idx ].addr, now );
  pair_advance_node( node, now );
}

static void
pair_send_ping( pair_node_t *   node,
                pair_cursor_t * cur,
                long            now ) {
  pair_env_t * env     = node->env;
  ulong        src_idx = node->idx;
  ulong        dst_idx = src_idx ^ 1UL;

  if( FD_UNLIKELY( sizeof(uint)+sizeof(fd_gossip_ping_t)>sizeof(env->wire_buf) ) ) return;

  uchar * p = env->wire_buf;
  FD_STORE( uint, p, FD_GOSSIP_MESSAGE_PING ); p += sizeof(uint);

  fd_gossip_ping_t * ping = (fd_gossip_ping_t *)p;
  fd_memcpy( ping->from, identities[ src_idx ].pub->uc, 32UL );
  for( ulong i=0UL; i<sizeof(ping->token); i++ ) ping->token[ i ] = pair_u8( cur );

  pair_identity_t * id = &identities[ src_idx ];
  fd_ed25519_sign( ping->signature, ping->token, sizeof(ping->token), id->pub->uc, id->priv, sha512 );
  if( FD_UNLIKELY( pair_u8( cur ) & 1U ) ) ping->signature[ 0 ] ^= 0x40U;

  pair_deliver_payload( &env->nodes[ dst_idx ],
                        env->nodes[ src_idx ].addr,
                        env->nodes[ dst_idx ].addr,
                        env->wire_buf,
                        sizeof(uint)+sizeof(fd_gossip_ping_t),
                        now );
}

static void
pair_push_duplicate_shred( pair_node_t * node,
                           pair_cursor_t * cur,
                           long          now ) {
  fd_gossip_duplicate_shred_t shred[1];
  memset( shred, 0, sizeof(shred) );
  shred->index       = (ushort)pair_bounded( cur, 65536UL );
  shred->slot        = pair_u64( cur );
  shred->num_chunks  = 3U;
  shred->chunk_index = (uchar)pair_bounded( cur, 3UL );
  shred->chunk_len   = pair_bounded( cur, sizeof(shred->chunk)+1UL );
  for( ulong i=0UL; i<shred->chunk_len; i++ ) shred->chunk[ i ] = pair_u8( cur );
  fd_gossip_push_duplicate_shred( node->gossip, shred, node->gossip_stem, now );
  if( FD_UNLIKELY( pair_u8( cur ) & 1U ) ) {
    fd_gossip_push_duplicate_shred( node->gossip, shred, node->gossip_stem, now );
  }
  pair_drain_gossip_updates( node );
}

static void
pair_push_vote( pair_node_t * node,
                pair_cursor_t * cur,
                long          now ) {
  uchar txn[ 256UL ];
  ulong txn_sz;
  if( FD_LIKELY( pair_u8( cur ) & 7U ) ) {
    txn_sz = pair_build_vote_txn( txn, sizeof(txn), node->idx, cur );
  } else {
    txn_sz = 1UL + pair_bounded( cur, sizeof(txn) );
    for( ulong i=0UL; i<txn_sz; i++ ) txn[ i ] = pair_u8( cur );
  }
  if( FD_UNLIKELY( !txn_sz ) ) return;
  fd_gossip_push_vote( node->gossip, txn, txn_sz, node->gossip_stem, now );
  pair_drain_gossip_updates( node );
}

static void
pair_round_trip( pair_env_t *    env,
                 pair_cursor_t * cur,
                 ulong           rounds ) {
  for( ulong i=0UL; i<rounds; i++ ) {
    pair_advance_node( &env->nodes[0], env->now );
    pair_advance_node( &env->nodes[1], env->now );
    pair_pump_network( env, cur, 16UL );
    env->now += 200000000L + (long)( 1000000UL*pair_bounded( cur, 100UL ) );
  }
}

static void
pair_setup_env( pair_env_t * env,
                ulong        seed ) {
  /* Avoid memset-ing the whole env: it embeds two fd_gossvf_tile_ctx_t, each
     carrying a ~10 MiB stake.msg_buf.  Every node field is re-initialized
     below by pair_setup_gossip()/pair_setup_vf(), and value_buf/wire_buf are
     always written before they are read.  Only the queue bookkeeping needs
     to be reset here.  pair_mem is still zeroed, but is now tiny (the tables
     are sized for PAIR_NODE_CNT, see PAIR_*_CAP). */
  env->queue_head = 0UL;
  env->queue_cnt  = 0UL;
  memset( pair_mem, 0, pair_mem_sz );
  env->now = 1000000000000L;

  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) {
    pair_node_t * node = &env->nodes[ i ];
    node->env       = env;
    node->idx       = i;
    node->port_host = (ushort)( 9000UL + i );
    node->addr.addr = FD_IP4_ADDR( 8, 8, 4, (uint)( 4UL + i ) );
    node->addr.port = fd_ushort_bswap( node->port_host );
  }

  FD_SCRATCH_ALLOC_INIT( mem, pair_mem );
  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) {
    _mem = pair_setup_gossip( &env->nodes[ i ], _mem, seed ^ (0x9e3779b9U + (uint)i) );
    _mem = pair_setup_vf    ( &env->nodes[ i ], _mem, seed ^ (0xd1b54a32d192ed03UL + i) );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( mem, pair_mem_align() ) <= (ulong)pair_mem + pair_mem_sz );

  pair_apply_stakes( env, FD_GOSSIP_STAKED_THRESHOLD, FD_GOSSIP_STAKED_THRESHOLD );

  for( ulong i=0UL; i<PAIR_NODE_CNT; i++ ) pair_advance_node( &env->nodes[ i ], env->now );
}

static void
pair_cleanup( void ) {
  free( pair_mem );
  free( pair_env );
}

int
LLVMFuzzerInitialize( int *    argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  init_identities();

  pair_env = aligned_alloc( alignof(pair_env_t), FD_ULONG_ALIGN_UP( sizeof(pair_env_t), alignof(pair_env_t) ) );
  FD_TEST( pair_env );

  pair_mem_sz = pair_mem_footprint();
  ulong mem_align = pair_mem_align();
  pair_mem = aligned_alloc( mem_align, FD_ULONG_ALIGN_UP( pair_mem_sz, mem_align ) );
  FD_TEST( pair_mem );
  atexit( pair_cleanup );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<2UL ) ) return 0;

  pair_cursor_t cur = { .cur = data, .rem = size };
  pair_env_t * env = pair_env;
  ulong seed = pair_u64( &cur );
  pair_setup_env( env, seed );
  env->mutator_idx = pair_u8( &cur ) & 1U;

  pair_pump_network( env, &cur, 64UL );

  ulong action_cnt = 1UL + (ulong)( pair_u8( &cur ) % PAIR_MAX_ACTIONS );
  for( ulong action_idx=0UL; action_idx<action_cnt && cur.rem; action_idx++ ) {
    env->now += (long)( 1000000UL * ( 1UL + pair_bounded( &cur, 250UL ) ) );
    uchar action = (uchar)( pair_u8( &cur ) % 13U );
    ulong node_idx = pair_u8( &cur ) & 1U;
    pair_node_t * node = &env->nodes[ node_idx ];

    switch( action ) {
      case 0U:
        pair_advance_node( &env->nodes[0], env->now );
        break;
      case 1U:
        pair_advance_node( &env->nodes[1], env->now );
        break;
      case 2U:
        pair_advance_node( &env->nodes[0], env->now );
        pair_advance_node( &env->nodes[1], env->now );
        break;
      case 3U: {
        ulong stake0 = (pair_u8( &cur ) & 1U) ? FD_GOSSIP_STAKED_THRESHOLD : 1UL;
        ulong stake1 = (pair_u8( &cur ) & 1U) ? FD_GOSSIP_STAKED_THRESHOLD : 1UL;
        pair_apply_stakes( env, stake0, stake1 );
        break;
      }
      case 4U: {
        ushort shred_version = (ushort)( (pair_u8( &cur ) & 3U) ?
                                         PAIR_SHRED_VERSION :
                                         PAIR_SHRED_VERSION+1U );
        pair_set_shred_version( node, shred_version, env->now );
        break;
      }
      case 5U:
        pair_push_duplicate_shred( node, &cur, env->now );
        break;
      case 6U:
        pair_push_vote( node, &cur, env->now );
        break;
      case 7U:
        env->now += 1700000000L;
        pair_round_trip( env, &cur, 1UL + pair_bounded( &cur, 4UL ) );
        break;
      case 8U:
        pair_push_duplicate_shred( &env->nodes[0], &cur, env->now );
        pair_push_duplicate_shred( &env->nodes[1], &cur, env->now );
        pair_push_vote( &env->nodes[ node_idx ], &cur, env->now );
        pair_round_trip( env, &cur, 1UL + pair_bounded( &cur, 2UL ) );
        break;
      case 9U:
        pair_track_peer_for_ping( node, !!( pair_u8( &cur ) & 1U ), env->now );
        break;
      case 10U:
        pair_send_snapshot_hashes( node, &cur, env->now );
        break;
      case 11U:
        pair_send_ping( node, &cur, env->now );
        break;
      default:
        pair_pump_network( env, &cur, 1UL + pair_bounded( &cur, 16UL ) );
        break;
    }

    pair_drain_gossip_updates( &env->nodes[0] );
    pair_drain_gossip_updates( &env->nodes[1] );
    pair_pump_network( env, &cur, 8UL );
  }

  pair_pump_network( env, &cur, 64UL );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
