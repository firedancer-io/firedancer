#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../disco/topo/fd_topob.h"
#include "../../util/tmpl/fd_unit_test.c"

#define FD_TILE_TEST
#include "fd_gossvf_tile.c"

#define TEST_PEER_CAP       (64UL)
#define TEST_PING_CAP       (64UL)
#define TEST_STAKE_CAP      (8UL)
#define TEST_TCACHE_DEPTH   (1024UL)
#define TEST_OUT_DEPTH      (64UL)
#define TEST_OUT_DBUF_SZ    (1UL<<16UL)
#define TEST_SHRED_VERSION  (42U)
#define TEST_PEER_CNT       (4UL)
#define TEST_GOSSVF_OUT_MTU \
  (sizeof(fd_gossip_message_t) + FD_GOSSIP_MESSAGE_MAX_CRDS + FD_NET_MTU)

typedef struct {
  uchar       priv[ 32UL ];
  fd_pubkey_t pub[ 1 ];
} test_peer_t;

typedef struct {
  fd_gossvf_tile_ctx_t ctx[ 1 ];

  fd_frag_meta_t *   out_mcache;
  fd_stem_context_t  stem[ 1 ];
  fd_frag_meta_t *   stem_mcache[ 1 ];
  ulong              stem_seq[ 1 ];
  ulong              stem_depth[ 1 ];
  ulong              stem_cr_avail[ 1 ];
  ulong              stem_min_cr_avail[ 1 ];
  int                stem_out_reliable[ 1 ];

  uchar udp_payload[ FD_NET_MTU ];
  uchar value_buf[ FD_NET_MTU ];
} test_env_t;

static test_peer_t peers[ TEST_PEER_CNT ];
static fd_sha512_t sha[ 1 ];
static test_env_t   test_env_g[ 1 ];
static uchar *      test_mem;
static ulong        test_mem_fp;

static ulong
test_mem_align( void ) {
  ulong a = 128UL;
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
test_mem_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),  peer_pool_footprint( TEST_PEER_CAP ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*TEST_PEER_CAP ) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),  ping_pool_footprint( TEST_PING_CAP ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*TEST_PING_CAP ) );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(), stake_pool_footprint( TEST_STAKE_CAP ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( TEST_STAKE_CAP ) ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( TEST_TCACHE_DEPTH, 0UL ) );
  l = FD_LAYOUT_APPEND( l, FD_CHUNK_ALIGN,     TEST_OUT_DBUF_SZ );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(),  fd_mcache_footprint( TEST_OUT_DEPTH, 0UL ) );
  return FD_LAYOUT_FINI( l, test_mem_align() );
}

static ulong
test_wmark( ulong dbuf_sz,
            ulong mtu ) {
  ulong chunk_cnt = dbuf_sz >> FD_CHUNK_LG_SZ;
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ - 1UL) >>
                     (1UL+FD_CHUNK_LG_SZ)) << 1UL;
  FD_TEST( chunk_cnt>chunk_mtu );
  return chunk_cnt - chunk_mtu;
}

static void
init_peers( void ) {
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<TEST_PEER_CNT; i++ ) {
    /* Private key content is arbitrary; only uniqueness across peers
       matters so each gets a distinct, deterministic public key. */
    for( ulong j=0UL; j<32UL; j++ ) peers[ i ].priv[ j ] = (uchar)( 3U + 29U*(uint)i + (uint)j );
    fd_ed25519_public_from_private( peers[ i ].pub->uc, peers[ i ].priv, sha );
  }
}

static void
setup_env( test_env_t * env ) {
  memset( env, 0, sizeof(*env) );
  memset( test_mem, 0, test_mem_fp );
  FD_SCRATCH_ALLOC_INIT( l, test_mem );

  fd_gossvf_tile_ctx_t * ctx = env->ctx;
  ctx->seed                  = 0x9e6c63d0aa1d3f61UL;
  ctx->shred_version         = TEST_SHRED_VERSION;
  ctx->allow_private_address = 0;
  ctx->gossip_addr.addr      = FD_IP4_ADDR( 8, 8, 4, 4 );
  ctx->gossip_addr.port      = fd_ushort_bswap( 9000U );
  ctx->src_addr              = ctx->gossip_addr;
  ctx->round_robin_cnt       = 1UL;
  ctx->round_robin_idx       = 0UL;
  ctx->ticks_per_ns          = fd_tempo_tick_per_ns( NULL );
  ctx->last_wallclock        = fd_log_wallclock();
  ctx->last_tickcount        = fd_tickcount();
  ctx->instance_creation_wallclock_nanos = ctx->last_wallclock;
  *ctx->identity_pubkey      = *peers[ 0 ].pub;

  void * peer_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),  peer_pool_footprint( TEST_PEER_CAP ) );
  void * peer_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*TEST_PEER_CAP ) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),  ping_pool_footprint( TEST_PING_CAP ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*TEST_PING_CAP ) );
  void * stake_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(), stake_pool_footprint( TEST_STAKE_CAP ) );
  void * stake_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( TEST_STAKE_CAP ) ) );
  void * tcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( TEST_TCACHE_DEPTH, 0UL ) );
  void * out_dcache     = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN, TEST_OUT_DBUF_SZ );
  void * mcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(), fd_mcache_footprint( TEST_OUT_DEPTH, 0UL ) );

  ctx->peers      = peer_pool_join( peer_pool_new( peer_pool_mem, TEST_PEER_CAP ) );
  ctx->peer_map   = peer_map_join ( peer_map_new ( peer_map_mem, 2UL*TEST_PEER_CAP, ctx->seed ) );
  ctx->pings      = ping_pool_join( ping_pool_new( ping_pool_mem, TEST_PING_CAP ) );
  ctx->ping_map   = ping_map_join ( ping_map_new ( ping_map_mem,  2UL*TEST_PING_CAP, ctx->seed ) );
  ctx->stake.pool = stake_pool_join( stake_pool_new( stake_pool_mem, TEST_STAKE_CAP ) );
  ctx->stake.map  = stake_map_join ( stake_map_new ( stake_map_mem, stake_map_chain_cnt_est( TEST_STAKE_CAP ), ctx->seed ) );
  FD_TEST( ctx->peers && ctx->peer_map && ctx->pings && ctx->ping_map && ctx->stake.pool && ctx->stake.map );

  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( tcache_mem, TEST_TCACHE_DEPTH, 0UL ) );
  FD_TEST( tcache );
  ctx->tcache.depth   = fd_tcache_depth       ( tcache );
  ctx->tcache.map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache.sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache.ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache.map     = fd_tcache_map_laddr   ( tcache );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ctx->out->mem     = out_dcache;
  ctx->out->chunk0  = fd_laddr_to_chunk( out_dcache, out_dcache );
  ctx->out->wmark   = ctx->out->chunk0 + test_wmark( TEST_OUT_DBUF_SZ, TEST_GOSSVF_OUT_MTU );
  ctx->out->chunk   = ctx->out->chunk0;

  env->out_mcache   = fd_mcache_join( fd_mcache_new( mcache_mem, TEST_OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( env->out_mcache );

  env->stem_mcache[0]       = env->out_mcache;
  env->stem_seq[0]          = 0UL;
  env->stem_depth[0]        = TEST_OUT_DEPTH;
  env->stem_cr_avail[0]     = ULONG_MAX/4UL;
  env->stem_min_cr_avail[0] = ULONG_MAX/4UL;
  env->stem_out_reliable[0] = 0;

  env->stem->mcaches             = env->stem_mcache;
  env->stem->seqs                = env->stem_seq;
  env->stem->depths              = env->stem_depth;
  env->stem->cr_avail            = env->stem_cr_avail;
  env->stem->min_cr_avail        = env->stem_min_cr_avail;
  env->stem->cr_decrement_amount = 1UL;
  env->stem->out_reliable        = env->stem_out_reliable;

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, test_mem_align() )<=(ulong)test_mem+test_mem_fp );
}

static void
make_contact_value( fd_gossip_value_t * value,
                    ulong               peer_idx,
                    uint                addr,
                    ushort              port,
                    ushort              shred_version,
                    long                now ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_CONTACT_INFO;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );

  value->contact_info->outset              = (ulong)FD_NANOSEC_TO_MICRO( now - 1000000L );
  value->contact_info->shred_version       = shred_version;
  value->contact_info->version.major       = 2U;
  value->contact_info->version.client      = FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER;
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] = (fd_gossip_socket_t){
    .port    = fd_ushort_bswap( port ),
    .is_ipv6 = 0U,
    .ip4     = addr
  };
}

/* serialize_signed_value serializes and ed25519-signs value in place,
   using peer_idx's keypair, then re-serializes so the encoded bytes
   include the real signature.  corrupt_sig flips a signature bit
   after signing to produce a payload with a well-formed but invalid
   signature. */
static long
serialize_signed_value( fd_gossip_value_t * value,
                        ulong               peer_idx,
                        uchar *             out,
                        ulong               out_sz,
                        int                 corrupt_sig ) {
  memset( value->signature, 0, sizeof(value->signature) );
  long value_sz = fd_gossip_value_serialize( value, out, out_sz );
  if( FD_UNLIKELY( value_sz<=64L ) ) return -1L;

  fd_ed25519_sign( value->signature, out+64UL, (ulong)value_sz-64UL, peers[ peer_idx ].pub->uc, peers[ peer_idx ].priv, sha );
  if( FD_UNLIKELY( corrupt_sig ) ) value->signature[ 0 ] ^= 0x80U;

  return fd_gossip_value_serialize( value, out, out_sz );
}

static ulong
build_single_value_msg( uchar *       payload,
                        ulong         payload_sz,
                        uint          tag,
                        uchar const * from,
                        uchar const * value_bytes,
                        ulong         value_sz ) {
  ulong total_sz = 4UL+32UL+8UL+value_sz;
  if( FD_UNLIKELY( total_sz>payload_sz ) ) return 0UL;

  uchar * p = payload;
  FD_STORE( uint,  p, tag ); p += 4UL;
  memcpy( p, from, 32UL ); p += 32UL;
  FD_STORE( ulong, p, 1UL ); p += 8UL;
  memcpy( p, value_bytes, value_sz ); p += value_sz;

  return (ulong)( p - payload );
}

static ulong
build_ping_or_pong( uchar * payload,
                    ulong   payload_sz,
                    uint    tag,
                    ulong   peer_idx,
                    int     corrupt_sig ) {
  FD_TEST( payload_sz>=4UL+32UL+32UL+64UL );
  uchar * p = payload;
  FD_STORE( uint, p, tag ); p += 4UL;
  memcpy( p, peers[ peer_idx ].pub->uc, 32UL ); p += 32UL;
  for( ulong i=0UL; i<32UL; i++ ) p[ i ] = (uchar)( 0xa0U + (uint)i );
  uchar * sign_data = p;
  p += 32UL;
  fd_ed25519_sign( p, sign_data, 32UL, peers[ peer_idx ].pub->uc, peers[ peer_idx ].priv, sha );
  if( FD_UNLIKELY( corrupt_sig ) ) p[ 0 ] ^= 0x40U;
  p += 64UL;
  return (ulong)( p - payload );
}

static void
inject_stake( test_env_t * env,
             ulong        peer_idx,
             ulong        stake ) {
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)env->ctx->stake.msg_buf;
  memset( msg, 0, sizeof(fd_epoch_info_msg_t) + sizeof(fd_stake_weight_t) );
  msg->staked_id_cnt = 1UL;
  fd_epoch_info_msg_id_weights( msg )[0].key   = *peers[ peer_idx ].pub;
  fd_epoch_info_msg_id_weights( msg )[0].stake = stake;
  handle_epoch( env->ctx, msg );
}

static int
send_packet( test_env_t *  env,
            uint          src_addr,
            ushort        src_port_host,
            uchar const * payload,
            ulong         payload_sz ) {
  FD_TEST( payload_sz+sizeof(fd_ip4_udp_hdrs_t)<=FD_NET_MTU );

  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, src_addr, src_port_host );
  ulong packet_sz = sizeof(fd_ip4_udp_hdrs_t)+payload_sz;
  memcpy( env->ctx->payload, hdrs, sizeof(fd_ip4_udp_hdrs_t) );
  memcpy( env->ctx->payload+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  int result = handle_net( env->ctx, packet_sz, 0UL, env->stem );
  env->ctx->metrics.message_rx[ result ]++;
  env->ctx->metrics.message_rx_bytes[ result ] += packet_sz;
  return result;
}

static fd_gossip_message_t const *
published_message( test_env_t *    env,
                   ulong            seq,
                   ulong            chunk,
                   uchar const **   opt_failed ) {
  fd_frag_meta_t const * meta = env->out_mcache + fd_mcache_line_idx( seq, TEST_OUT_DEPTH );
  FD_TEST( meta->seq==seq );
  FD_TEST( fd_gossvf_sig_kind( meta->sig )==0U ); /* 0 => forwarded message, 1 => pingreq */

  uchar const * out = fd_chunk_to_laddr_const( env->ctx->out->mem, chunk );
  if( opt_failed ) *opt_failed = out + sizeof(fd_gossip_message_t);
  return (fd_gossip_message_t const *)out;
}

FD_UNIT_TEST( test_ping_valid_signature_accepted ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  ulong payload_sz = build_ping_or_pong( env->udp_payload, sizeof(env->udp_payload), FD_GOSSIP_MESSAGE_PING, 1UL, 0 );
  FD_TEST( payload_sz );

  ulong old_seq   = env->stem_seq[0];
  ulong old_chunk = env->ctx->out->chunk;
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9001U, env->udp_payload, payload_sz );

  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PING_IDX );
  FD_TEST( env->stem_seq[0]==old_seq+1UL );

  fd_gossip_message_t const * msg = published_message( env, old_seq, old_chunk, NULL );
  FD_TEST( msg->tag==FD_GOSSIP_MESSAGE_PING );
  FD_TEST( !memcmp( msg->ping->from, peers[1].pub->uc, 32UL ) );
}

FD_UNIT_TEST( test_ping_invalid_signature_rejected ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  ulong payload_sz = build_ping_or_pong( env->udp_payload, sizeof(env->udp_payload), FD_GOSSIP_MESSAGE_PING, 1UL, 1 );
  FD_TEST( payload_sz );

  ulong old_seq = env->stem_seq[0];
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9001U, env->udp_payload, payload_sz );

  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PING_SIGNATURE_IDX );
  FD_TEST( env->stem_seq[0]==old_seq ); /* nothing forwarded */
}

FD_UNIT_TEST( test_malformed_payload_rejected ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  /* Message tag is outside [0, FD_GOSSIP_MESSAGE_CNT), so the very
     first enum read must fail cleanly. */
  uchar bad_tag[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44 };
  ulong old_seq = env->stem_seq[0];
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9001U, bad_tag, sizeof(bad_tag) );
  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_UNPARSEABLE_IDX );
  FD_TEST( env->stem_seq[0]==old_seq );

  /* Tag is valid (PING) but the message is truncated well before the
     from/token/signature fields are present. */
  uchar truncated_ping[ 4UL+10UL ];
  memset( truncated_ping, 0, sizeof(truncated_ping) );
  FD_STORE( uint, truncated_ping, FD_GOSSIP_MESSAGE_PING );
  result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9001U, truncated_ping, sizeof(truncated_ping) );
  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_UNPARSEABLE_IDX );
  FD_TEST( env->stem_seq[0]==old_seq );
}

FD_UNIT_TEST( test_push_valid_contact_info_accepted ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  /* Stake above FD_GOSSIP_STAKED_THRESHOLD makes peer 1 count as an
     "active" gossip participant (see is_ping_active), so
     verify_addresses doesn't reroute this into a ping-first flow. */
  inject_stake( env, 1UL, FD_GOSSIP_STAKED_THRESHOLD );

  fd_gossip_value_t value[1];
  make_contact_value( value, 1UL, FD_IP4_ADDR( 8, 8, 8, 9 ), 9100U, (ushort)TEST_SHRED_VERSION, env->ctx->last_wallclock );
  long value_sz = serialize_signed_value( value, 1UL, env->value_buf, sizeof(env->value_buf), 0 );
  FD_TEST( value_sz>0L );

  ulong payload_sz = build_single_value_msg( env->udp_payload, sizeof(env->udp_payload), FD_GOSSIP_MESSAGE_PUSH,
                                             peers[1].pub->uc, env->value_buf, (ulong)value_sz );
  FD_TEST( payload_sz );

  ulong old_seq   = env->stem_seq[0];
  ulong old_chunk = env->ctx->out->chunk;
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9100U, env->udp_payload, payload_sz );

  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PUSH_IDX );
  FD_TEST( env->stem_seq[0]==old_seq+1UL );

  uchar const * failed;
  fd_gossip_message_t const * msg = published_message( env, old_seq, old_chunk, &failed );
  FD_TEST( msg->tag==FD_GOSSIP_MESSAGE_PUSH );
  FD_TEST( msg->push->values_len==1UL );
  FD_TEST( !failed[0] );
  FD_TEST( !memcmp( msg->push->values[0].origin, peers[1].pub->uc, 32UL ) );
}

FD_UNIT_TEST( test_push_shred_version_mismatch_dropped ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  fd_gossip_value_t value[1];
  make_contact_value( value, 1UL, FD_IP4_ADDR( 8, 8, 8, 9 ), 9100U, (ushort)(TEST_SHRED_VERSION+1U), env->ctx->last_wallclock );
  long value_sz = serialize_signed_value( value, 1UL, env->value_buf, sizeof(env->value_buf), 0 );
  FD_TEST( value_sz>0L );

  ulong payload_sz = build_single_value_msg( env->udp_payload, sizeof(env->udp_payload), FD_GOSSIP_MESSAGE_PUSH,
                                             peers[1].pub->uc, env->value_buf, (ulong)value_sz );
  FD_TEST( payload_sz );

  /* filter_shred_version_crds only tags the offending crds value as
     failed; it does not shrink values_len (that only happens when a
     signature check swap-removes an entry).  So the containing PUSH
     message is still forwarded (for any other, valid values it might
     carry) as SUCCESS_PUSH, with this value's failed[] slot set so
     downstream consumers know to skip it. */
  ulong old_seq   = env->stem_seq[0];
  ulong old_chunk = env->ctx->out->chunk;
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 9 ), (ushort)9100U, env->udp_payload, payload_sz );

  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PUSH_IDX );
  FD_TEST( env->stem_seq[0]==old_seq+1UL );
  FD_TEST( env->ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PUSH_ORIGIN_SHRED_VERSION_IDX ]==1UL );

  uchar const * failed;
  fd_gossip_message_t const * msg = published_message( env, old_seq, old_chunk, &failed );
  FD_TEST( msg->tag==FD_GOSSIP_MESSAGE_PUSH );
  FD_TEST( msg->push->values_len==1UL );
  FD_TEST( failed[0]==FD_GOSSIP_FAILED_NO_CONTACT_INFO );
}

FD_UNIT_TEST( test_pull_response_duplicate_dropped ) {
  test_env_t * env = test_env_g;
  setup_env( env );

  inject_stake( env, 1UL, FD_GOSSIP_STAKED_THRESHOLD );

  fd_gossip_value_t value[1];
  make_contact_value( value, 1UL, FD_IP4_ADDR( 8, 8, 8, 10 ), 9200U, (ushort)TEST_SHRED_VERSION, env->ctx->last_wallclock );
  long value_sz = serialize_signed_value( value, 1UL, env->value_buf, sizeof(env->value_buf), 0 );
  FD_TEST( value_sz>0L );

  ulong payload_sz = build_single_value_msg( env->udp_payload, sizeof(env->udp_payload), FD_GOSSIP_MESSAGE_PULL_RESPONSE,
                                             peers[1].pub->uc, env->value_buf, (ulong)value_sz );
  FD_TEST( payload_sz );

  ulong seq_after_first = env->stem_seq[0];
  int result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 10 ), (ushort)9200U, env->udp_payload, payload_sz );
  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PULL_RESPONSE_IDX );
  FD_TEST( env->stem_seq[0]==seq_after_first+1UL );

  /* Redeliver the identical payload: the dedup tcache should catch
     the repeated signature and drop it before it is forwarded again. */
  ulong seq_after_second = env->stem_seq[0];
  result = send_packet( env, FD_IP4_ADDR( 8, 8, 8, 10 ), (ushort)9200U, env->udp_payload, payload_sz );
  FD_TEST( result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_DROPPED_PULL_RESPONSE_NO_VALID_CRDS_IDX );
  FD_TEST( env->stem_seq[0]==seq_after_second ); /* nothing forwarded on the duplicate */
  FD_TEST( env->ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_V_DROPPED_PULL_RESPONSE_DUPLICATE_IDX ]==1UL );
}

FD_UNIT_TEST( test_seccomp ) {
  int   out_fds[2];
  ulong nfds = populate_allowed_fds( NULL, NULL, 2UL, out_fds );
  FD_TEST( nfds>=1UL && nfds<=2UL );
  FD_TEST( out_fds[0]==STDERR_FILENO );

  struct sock_filter filter[ 32 ];
  populate_allowed_seccomp( NULL, NULL, 32UL, filter );
}

/* write_test_keypair writes a Solana JSON keypair file (64-element
   byte array: 32-byte seed followed by the 32-byte public key) to a
   fresh temp path and returns it; the caller must unlink() it. */
static void
write_test_keypair( char * path_inout, ulong path_sz, fd_pubkey_t const * pub ) {
  FD_TEST( path_sz>sizeof("/tmp/test_gossvf_identity_XXXXXX") );
  strcpy( path_inout, "/tmp/test_gossvf_identity_XXXXXX" );
  int fd = mkstemp( path_inout );
  FD_TEST( fd>=0 );

  uchar keypair[ 64UL ];
  for( ulong i=0UL; i<32UL; i++ ) keypair[ i ] = (uchar)(0x55U+(uint)i); /* seed half is unused when loading pubkey-only */
  memcpy( keypair+32UL, pub->uc, 32UL );

  char buf[ 512UL ];
  ulong len = 0UL;
  buf[ len++ ] = '[';
  for( ulong i=0UL; i<64UL; i++ ) {
    int n = snprintf( buf+len, sizeof(buf)-len, "%s%u", i? "," : "", (uint)keypair[ i ] );
    FD_TEST( n>0 );
    len += (ulong)n;
  }
  buf[ len++ ] = ']';

  FD_TEST( write( fd, buf, len )==(long)len );
  FD_TEST( !close( fd ) );
}

FD_UNIT_TEST( test_init ) {
  char key_path[ 64UL ];
  write_test_keypair( key_path, sizeof(key_path), peers[0].pub );

  void * topo_mem = aligned_alloc( alignof(fd_topo_t), sizeof(fd_topo_t) );
  FD_TEST( topo_mem );
  fd_topo_t * topo = fd_topob_new( topo_mem, "gossvf-test" );

  fd_topo_wksp_t * wksp = fd_topob_wksp( topo, "wksp" );
  wksp->wksp = NULL;

  fd_topo_tile_t * tile = fd_topob_tile( topo, "gossvf", "wksp", "wksp", 0UL, 0, 1, 0 );
  tile->gossvf.tcache_depth          = TEST_TCACHE_DEPTH;
  tile->gossvf.shred_version         = TEST_SHRED_VERSION;
  tile->gossvf.allow_private_address = 0;
  tile->gossvf.gossip_addr.addr      = FD_IP4_ADDR( 8, 8, 4, 4 );
  tile->gossvf.gossip_addr.port      = fd_ushort_bswap( 9000U );
  tile->gossvf.src_addr              = tile->gossvf.gossip_addr;
  tile->gossvf.entrypoints_cnt       = 0UL;
  tile->gossvf.boot_timestamp_nanos  = fd_log_wallclock();
  strncpy( tile->gossvf.identity_key_path, key_path, sizeof(tile->gossvf.identity_key_path)-1UL );

  /* No in links are wired up: unprivileged_init only validates in
     links that are actually present, so an empty set exercises the
     init path without needing a realistic net/gossip/epoch dcache
     layout, which init doesn't otherwise need to function correctly. */
  ulong out_mtu   = 4096UL;
  ulong out_depth = 8UL;
  fd_topo_link_t * out_link = fd_topob_link( topo, "gossvf_out", "wksp", out_depth, out_mtu, 1UL );
  fd_topob_tile_out( topo, "gossvf", 0UL, "gossvf_out", 0UL );

  ulong out_dcache_data_sz = fd_dcache_req_data_sz( out_mtu, out_depth, 1UL, 1 );
  void * out_mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( out_depth, 0UL ) );
  void * out_dcache_mem = aligned_alloc( fd_dcache_align(), fd_dcache_footprint( out_dcache_data_sz, 0UL ) );
  FD_TEST( out_mcache_mem && out_dcache_mem );
  out_link->mcache = fd_mcache_join( fd_mcache_new( out_mcache_mem, out_depth, 0UL, 0UL ) );
  out_link->dcache = fd_dcache_join( fd_dcache_new( out_dcache_mem, out_dcache_data_sz, 0UL ) );
  FD_TEST( out_link->mcache && out_link->dcache );

  ulong  scratch_align_v = scratch_align();
  ulong  scratch_fp      = scratch_footprint( tile );
  void * scratch          = aligned_alloc( scratch_align_v, FD_ULONG_ALIGN_UP( scratch_fp, scratch_align_v ) );
  FD_TEST( scratch );
  topo->objs[ tile->tile_obj_id ].offset = (ulong)scratch;

  void * keyswitch_mem = aligned_alloc( fd_keyswitch_align(), fd_keyswitch_footprint() );
  FD_TEST( keyswitch_mem );
  FD_TEST( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_LOCKED ) );
  topo->objs[ tile->id_keyswitch_obj_id ].offset = (ulong)keyswitch_mem;

  privileged_init( topo, tile );
  unprivileged_init( topo, tile );

  fd_gossvf_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( ctx->shred_version==TEST_SHRED_VERSION );
  FD_TEST( !memcmp( ctx->identity_pubkey->uc, peers[0].pub->uc, 32UL ) );
  FD_TEST( ctx->round_robin_cnt==1UL );
  FD_TEST( ctx->round_robin_idx==0UL );
  FD_TEST( ctx->peers && ctx->peer_map && ctx->pings && ctx->ping_map && ctx->stake.pool && ctx->stake.map );
  FD_TEST( ctx->out->mem==NULL ); /* wksp->wksp above was NULL */

  unlink( key_path );
  free( scratch );
  free( keyswitch_mem );
  free( out_mcache_mem );
  free( out_dcache_mem );
  free( topo_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  init_peers();

  test_mem_fp = test_mem_footprint();
  ulong align = test_mem_align();
  test_mem = aligned_alloc( align, FD_ULONG_ALIGN_UP( test_mem_fp, align ) );
  FD_TEST( test_mem );

  fd_unit_tests( argc, argv );

  free( test_mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
