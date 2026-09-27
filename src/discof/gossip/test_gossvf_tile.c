/* Unit tests for the gossvf tile's prune signing format memo and the
   sigok tcache.  The tile source is included so the static helpers
   can be driven directly, as the fuzzers do. */

#define fd_tile_gossvf fd_tile_gossvf_test_unused
#include "fd_gossvf_tile.c"
#undef fd_tile_gossvf

#include <stdlib.h>

#define TEST_PEER_CNT     (4UL)
#define TEST_TCACHE_DEPTH (1UL<<10UL)
#define TEST_SIGOK_DEPTH  (1UL<<6UL)
#define TEST_OUT_DEPTH    (128UL)
#define TEST_OUT_DBUF_SZ  (1UL<<20UL)
#define TEST_SHRED_VER    (42U)
#define TEST_OUT_MTU      (sizeof(fd_gossip_message_t)+FD_GOSSIP_MESSAGE_MAX_CRDS+FD_NET_MTU)

struct test_peer {
  uchar       priv[ 32UL ];
  fd_pubkey_t pub[ 1 ];
};
typedef struct test_peer test_peer_t;

static test_peer_t peers[ TEST_PEER_CNT ];
static fd_sha512_t sha[ 1 ];

static fd_gossvf_tile_ctx_t ctx[ 1 ];
static fd_frag_meta_t *     out_mcache;
static fd_stem_context_t    stem[ 1 ];
static fd_frag_meta_t *     stem_mcache[ 1 ];
static ulong                stem_seq[ 1 ];
static ulong                stem_depth[ 1 ];
static ulong                stem_cr_avail[ 1 ];
static ulong                stem_min_cr_avail[ 1 ];
static int                  stem_out_reliable[ 1 ];

/* The prune signable data builder as it was before prune_sign_data,
   kept here as the reference for bit identity. */

static ulong
old_prune_sign_data( fd_gossip_prune_t const * view,
                     uchar *                   sign_data ) {
  FD_STORE( ulong, sign_data,                             18UL );
  fd_memcpy(       sign_data+8UL,                         "\xffSOLANA_PRUNE_DATA",       18UL );
  fd_memcpy(       sign_data+26UL,                        view->pubkey,                  32UL );
  FD_STORE( ulong, sign_data+58UL,                        view->prunes_len );
  fd_memcpy(       sign_data+66UL,                        view->prunes,                  view->prunes_len*32UL );
  fd_memcpy(       sign_data+66UL+view->prunes_len*32UL,  view->destination, 32UL );
  FD_STORE( ulong, sign_data+98UL+view->prunes_len*32UL,  view->wallclock );
  return 106UL+view->prunes_len*32UL;
}

static ulong
wmark_of( ulong dbuf_sz,
          ulong mtu ) {
  ulong chunk_cnt = dbuf_sz >> FD_CHUNK_LG_SZ;
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ - 1UL) >> (1UL+FD_CHUNK_LG_SZ)) << 1UL;
  FD_TEST( chunk_cnt>chunk_mtu );
  return chunk_cnt - chunk_mtu;
}

/* Everything setup_ctx allocates is freed by free_ctx. */

static void * allocs[ 16UL ];
static ulong  alloc_cnt;

static void *
alloc_aligned( ulong align,
               ulong footprint ) {
  void * mem = aligned_alloc( align, FD_ULONG_ALIGN_UP( footprint, align ) );
  FD_TEST( mem );
  memset( mem, 0, FD_ULONG_ALIGN_UP( footprint, align ) );
  FD_TEST( alloc_cnt<sizeof(allocs)/sizeof(allocs[0]) );
  allocs[ alloc_cnt++ ] = mem;
  return mem;
}

static void
free_ctx( void ) {
  while( alloc_cnt ) free( allocs[ --alloc_cnt ] );
}

static void
join_tcache( void *  mem,
             ulong   depth,
             ulong * out_depth,
             ulong * out_map_cnt,
             ulong ** out_sync,
             ulong ** out_ring,
             ulong ** out_map ) {
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( mem, depth, 0UL ) );
  FD_TEST( tcache );
  *out_depth   = fd_tcache_depth       ( tcache );
  *out_map_cnt = fd_tcache_map_cnt     ( tcache );
  *out_sync    = fd_tcache_oldest_laddr( tcache );
  *out_ring    = fd_tcache_ring_laddr  ( tcache );
  *out_map     = fd_tcache_map_laddr   ( tcache );
}

static void
setup_ctx( void ) {
  memset( ctx, 0, sizeof(*ctx) );
  ctx->seed                  = 0x2b7e151628aed2a6UL;
  ctx->dedup_key[ 0 ]        = 0x0123456789abcdefUL;
  ctx->dedup_key[ 1 ]        = 0xfedcba9876543210UL;
  ctx->shred_version         = TEST_SHRED_VER;
  ctx->allow_private_address = 0;
  ctx->gossip_addr.addr      = FD_IP4_ADDR( 8, 8, 4, 4 );
  ctx->gossip_addr.port      = fd_ushort_bswap( 9000U );
  ctx->src_addr              = ctx->gossip_addr;
  ctx->round_robin_cnt       = 1UL;
  ctx->round_robin_idx       = 0UL;
  fd_clock_tile_init( ctx->clock );
  ctx->instance_creation_wallclock_nanos = fd_clock_tile_now( ctx->clock );
  *ctx->identity_pubkey      = *peers[ 0 ].pub;

  ctx->peers      = peer_pool_join ( peer_pool_new ( alloc_aligned( peer_pool_align(),  peer_pool_footprint( 64UL ) ), 64UL ) );
  ctx->peer_map   = peer_map_join  ( peer_map_new  ( alloc_aligned( peer_map_align(),   peer_map_footprint( 128UL ) ), 128UL, ctx->seed ) );
  ctx->pings      = ping_pool_join ( ping_pool_new ( alloc_aligned( ping_pool_align(),  ping_pool_footprint( 64UL ) ), 64UL ) );
  ctx->ping_map   = ping_map_join  ( ping_map_new  ( alloc_aligned( ping_map_align(),   ping_map_footprint( 128UL ) ), 128UL, ctx->seed ) );
  ctx->stake.pool = stake_pool_join( stake_pool_new( alloc_aligned( stake_pool_align(), stake_pool_footprint( 64UL ) ), 64UL ) );
  ctx->stake.map  = stake_map_join ( stake_map_new ( alloc_aligned( stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( 64UL ) ) ), stake_map_chain_cnt_est( 64UL ), ctx->seed ) );
  FD_TEST( ctx->peers && ctx->peer_map && ctx->pings && ctx->ping_map && ctx->stake.pool && ctx->stake.map );

  join_tcache( alloc_aligned( fd_tcache_align(), fd_tcache_footprint( TEST_TCACHE_DEPTH, 0UL ) ), TEST_TCACHE_DEPTH,
               &ctx->tcache.depth, &ctx->tcache.map_cnt, &ctx->tcache.sync, &ctx->tcache.ring, &ctx->tcache.map );
  join_tcache( alloc_aligned( fd_tcache_align(), fd_tcache_footprint( TEST_SIGOK_DEPTH, 0UL ) ), TEST_SIGOK_DEPTH,
               &ctx->sigok.depth, &ctx->sigok.map_cnt, &ctx->sigok.sync, &ctx->sigok.ring, &ctx->sigok.map );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );
  for( ulong i=0UL; i<FD_GOSSVF_BATCH_SIG_MAX+FD_GOSSIP_MESSAGE_MAX_CRDS; i++ ) FD_TEST( (ctx->batch_sha[ i ] = fd_sha512_join( fd_sha512_new( ctx->_batch_sha+i ) )) );
  ctx->ed25519_cache = fd_ed25519_cache_join( fd_ed25519_cache_new( alloc_aligned( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( 8UL ) ), 8UL, ctx->seed ) );
  FD_TEST( ctx->ed25519_cache );

  void * out_dcache = alloc_aligned( FD_CHUNK_ALIGN, TEST_OUT_DBUF_SZ );
  ctx->out->mem    = out_dcache;
  ctx->out->chunk0 = fd_laddr_to_chunk( out_dcache, out_dcache );
  ctx->out->wmark  = ctx->out->chunk0 + wmark_of( TEST_OUT_DBUF_SZ, TEST_OUT_MTU );
  ctx->out->chunk  = ctx->out->chunk0;

  out_mcache = fd_mcache_join( fd_mcache_new( alloc_aligned( fd_mcache_align(), fd_mcache_footprint( TEST_OUT_DEPTH, 0UL ) ), TEST_OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( out_mcache );
  stem_mcache[0]       = out_mcache;
  stem_seq[0]          = 0UL;
  stem_depth[0]        = TEST_OUT_DEPTH;
  stem_cr_avail[0]     = ULONG_MAX/4UL;
  stem_min_cr_avail[0] = ULONG_MAX/4UL;
  stem_out_reliable[0] = 0;
  stem->mcaches             = stem_mcache;
  stem->seqs                = stem_seq;
  stem->depths              = stem_depth;
  stem->cr_avail            = stem_cr_avail;
  stem->min_cr_avail        = stem_min_cr_avail;
  stem->cr_decrement_amount = 1UL;
  stem->out_reliable        = stem_out_reliable;
}

/* Prune tests */

static void
make_prune( fd_gossip_prune_t * prune,
            ulong               signer,
            ulong               prunes_len,
            ulong               wallclock,
            int                 unprefixed,
            int                 corrupt ) {
  memset( prune, 0, sizeof(*prune) );
  fd_memcpy( prune->sender, peers[ signer ].pub->uc, 32UL );
  fd_memcpy( prune->pubkey, peers[ signer ].pub->uc, 32UL );
  prune->prunes_len = prunes_len;
  for( ulong i=0UL; i<prunes_len; i++ ) for( ulong j=0UL; j<32UL; j++ ) prune->prunes[ i ][ j ] = (uchar)(i*7UL+j+signer);
  fd_memcpy( prune->destination, peers[ 0 ].pub->uc, 32UL );
  prune->wallclock = wallclock;

  uchar sign_data[ FD_GOSSVF_PRUNE_SIGN_DATA_MAX ];
  ulong sign_data_len = old_prune_sign_data( prune, sign_data );
  ulong off = unprefixed ? 26UL : 0UL;
  fd_ed25519_sign( prune->signature, sign_data+off, sign_data_len-off, peers[ signer ].pub->uc, peers[ signer ].priv, sha );
  if( corrupt ) prune->signature[ 5 ] ^= 0x10U;
}

static void
test_prune_sign_data_identity( void ) {
  fd_gossip_prune_t prune[1];
  for( ulong prunes_len=0UL; prunes_len<=36UL; prunes_len++ ) {
    for( ulong signer=0UL; signer<TEST_PEER_CNT; signer++ ) {
      make_prune( prune, signer, prunes_len, 1234567890123UL+prunes_len, 0, 0 );
      uchar a[ FD_GOSSVF_PRUNE_SIGN_DATA_MAX ]; memset( a, 0xa5, sizeof(a) );
      uchar b[ FD_GOSSVF_PRUNE_SIGN_DATA_MAX ]; memset( b, 0xa5, sizeof(b) );
      ulong la = old_prune_sign_data( prune, a );
      ulong lb = prune_sign_data( prune, b );
      FD_TEST( la==lb );
      FD_TEST( la==106UL+prunes_len*32UL );
      FD_TEST( !memcmp( a, b, sizeof(a) ) );
    }
  }
  FD_LOG_NOTICE(( "prune sign data identity: pass" ));
}

static void
test_prune_memo( void ) {
  setup_ctx();
  fd_gossip_prune_t prune[1];

  /* Both formats verify, from a cold memo and again once memoized. */
  for( int unprefixed=0; unprefixed<2; unprefixed++ ) {
    for( ulong signer=1UL; signer<TEST_PEER_CNT; signer++ ) {
      for( ulong rep=0UL; rep<3UL; rep++ ) {
        make_prune( prune, signer, 1UL+rep, 1000UL+rep, unprefixed, 0 );
        FD_TEST( verify_prune( ctx, prune )==0 );
        ulong memo_idx = fd_hash32( prune->pubkey, ctx->seed ) & (FD_GOSSVF_PRUNE_MEMO_CNT-1UL);
        FD_TEST( ctx->prune_unprefixed[ memo_idx ]==(uchar)unprefixed );
      }
    }
  }

  /* A signer that switches format keeps verifying; the memo follows. */
  for( ulong rep=0UL; rep<6UL; rep++ ) {
    int unprefixed = (int)(rep&1UL);
    make_prune( prune, 1UL, 2UL, 2000UL+rep, unprefixed, 0 );
    FD_TEST( verify_prune( ctx, prune )==0 );
    ulong memo_idx = fd_hash32( prune->pubkey, ctx->seed ) & (FD_GOSSVF_PRUNE_MEMO_CNT-1UL);
    FD_TEST( ctx->prune_unprefixed[ memo_idx ]==(uchar)unprefixed );
  }

  /* A bad signature is rejected whatever the memo says, and does not
     change the memo. */
  for( int memo=0; memo<2; memo++ ) {
    ulong memo_idx = fd_hash32( peers[ 2 ].pub->uc, ctx->seed ) & (FD_GOSSVF_PRUNE_MEMO_CNT-1UL);
    ctx->prune_unprefixed[ memo_idx ] = (uchar)memo;
    for( int unprefixed=0; unprefixed<2; unprefixed++ ) {
      make_prune( prune, 2UL, 3UL, 3000UL, unprefixed, 1 );
      FD_TEST( verify_prune( ctx, prune )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_DROPPED_PRUNE_SIGNATURE_IDX );
      FD_TEST( ctx->prune_unprefixed[ memo_idx ]==(uchar)memo );
    }
  }

  /* A prune signed by someone other than pubkey is rejected. */
  make_prune( prune, 3UL, 1UL, 4000UL, 0, 0 );
  fd_memcpy( prune->pubkey, peers[ 1 ].pub->uc, 32UL );
  fd_memcpy( prune->sender, peers[ 1 ].pub->uc, 32UL );
  FD_TEST( verify_prune( ctx, prune )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_DROPPED_PRUNE_SIGNATURE_IDX );

  free_ctx();
  FD_LOG_NOTICE(( "prune memo: pass" ));
}

/* sigok tests: a push carrying one contact info whose origin is
   unponged is dropped as inactive after its signature verifies; the
   second copy must give the same outcome, the same ping request and
   the same metrics without a second verify; a pong then admits the
   third copy. */

static void
make_contact_value( fd_gossip_value_t * value,
                    ulong               peer_idx,
                    uint                addr,
                    ushort              port,
                    long                now ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_CONTACT_INFO;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );
  value->contact_info->outset              = (ulong)FD_NANOSEC_TO_MICRO( now - 1000000L );
  value->contact_info->shred_version       = TEST_SHRED_VER;
  value->contact_info->version.major       = 2U;
  value->contact_info->version.client      = FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER;
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] = (fd_gossip_socket_t){ .port = fd_ushort_bswap( port ), .is_ipv6 = 0U, .ip4 = addr };
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU    ] = (fd_gossip_socket_t){ .port = fd_ushort_bswap( (ushort)(port+1000U) ), .is_ipv6 = 0U, .ip4 = addr };
}

static ulong
build_push( uchar *             payload,
            ulong               payload_sz,
            fd_gossip_value_t * value,
            ulong               signer,
            int                 corrupt ) {
  memset( value->signature, 0, 64UL );
  uchar value_bytes[ FD_NET_MTU ];
  long value_sz = fd_gossip_value_serialize( value, value_bytes, sizeof(value_bytes) );
  FD_TEST( value_sz>64L );
  fd_ed25519_sign( value->signature, value_bytes+64UL, (ulong)value_sz-64UL, peers[ signer ].pub->uc, peers[ signer ].priv, sha );
  if( corrupt ) value->signature[ 0 ] ^= 0x80U;
  value_sz = fd_gossip_value_serialize( value, value_bytes, sizeof(value_bytes) );
  FD_TEST( value_sz>64L );

  FD_TEST( payload_sz>=4UL+32UL+8UL+(ulong)value_sz );
  uchar * p = payload;
  FD_STORE( uint,  p, FD_GOSSIP_MESSAGE_PUSH ); p += 4UL;
  memcpy( p, peers[ signer ].pub->uc, 32UL );  p += 32UL;
  FD_STORE( ulong, p, 1UL );                   p += 8UL;
  memcpy( p, value_bytes, (ulong)value_sz );   p += (ulong)value_sz;
  return (ulong)(p-payload);
}

/* Feed a udp payload from src to the tile the way after_frag does;
   returns the message outcome. */

static int
send_payload( uint          src_addr,
              ushort        src_port,
              uchar const * payload,
              ulong         payload_sz ) {
  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, src_addr, src_port );
  ulong packet_sz = sizeof(fd_ip4_udp_hdrs_t)+payload_sz;
  memcpy( ctx->payload, hdrs, sizeof(fd_ip4_udp_hdrs_t) );
  memcpy( ctx->payload+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  ulong before[ FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_CNT ];
  memcpy( before, ctx->metrics.message_rx, sizeof(before) );
  int result = handle_net( ctx, packet_sz, 0UL, stem );
  if( result>=0 ) return result;
  batch_flush( ctx, stem );
  for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_CNT; i++ ) if( ctx->metrics.message_rx[ i ]!=before[ i ] ) return (int)i;
  FD_LOG_ERR(( "no outcome counted" ));
}

static void
test_sigok( void ) {
  setup_ctx();
  long  now  = fd_clock_tile_now( ctx->clock );
  uint  addr = FD_IP4_ADDR( 8, 8, 8, 9 );
  ushort port = 8001U;
  ulong peer_idx = 1UL;

  fd_gossip_value_t value[1];
  uchar payload[ FD_NET_MTU ];
  make_contact_value( value, peer_idx, addr, port, now );
  ulong payload_sz = build_push( payload, sizeof(payload), value, peer_idx, 0 );

  ulong misses0 = fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache );

  /* First copy: verified, dropped inactive (unponged), a ping request
     goes out. */
  ulong seq0 = stem_seq[0];
  FD_TEST( send_payload( addr, port, payload, payload_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_SUCCESS_PUSH_IDX );
  ulong misses1 = fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache );
  FD_TEST( misses1==misses0+1UL );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DROPPED_PUSH_INACTIVE_IDX ]==1UL );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_VERIFIED_PUSH_IDX ]==0UL );
  FD_TEST( stem_seq[0]==seq0+2UL ); /* ping request + message */
  FD_TEST( fd_gossvf_sig_kind( out_mcache[ fd_mcache_line_idx( seq0, TEST_OUT_DEPTH ) ].sig )==1U );

  /* Second copy: same outcome, same metrics, another ping request, no
     signature verification. */
  seq0 = stem_seq[0];
  FD_TEST( send_payload( addr, port, payload, payload_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_SUCCESS_PUSH_IDX );
  ulong misses2 = fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache );
  FD_TEST( misses2==misses1 );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DROPPED_PUSH_INACTIVE_IDX ]==2UL );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DUPLICATE_PUSH_IDX ]==0UL );
  FD_TEST( stem_seq[0]==seq0+2UL );
  FD_TEST( fd_gossvf_sig_kind( out_mcache[ fd_mcache_line_idx( seq0, TEST_OUT_DEPTH ) ].sig )==1U );
  {
    /* The published copy carries the value marked failed, as before. */
    fd_frag_meta_t const * meta = out_mcache + fd_mcache_line_idx( seq0+1UL, TEST_OUT_DEPTH );
    FD_TEST( fd_gossvf_sig_kind( meta->sig )==0U );
    uchar const * out = fd_chunk_to_laddr_const( ctx->out->mem, meta->chunk );
    fd_gossip_message_t const * msg = (fd_gossip_message_t const *)out;
    FD_TEST( msg->tag==FD_GOSSIP_MESSAGE_PUSH && msg->push->values_len==1UL );
    FD_TEST( out[ fd_gossip_message_used_sz( msg ) ]==FD_GOSSIP_FAILED_NO_CONTACT_INFO );
  }

  /* A forged copy of the same value (signature altered) is not the
     same bytes, so it misses sigok and is verified and dropped. */
  {
    fd_gossip_value_t forged[1];
    uchar forged_payload[ FD_NET_MTU ];
    make_contact_value( forged, peer_idx, addr, port, now );
    ulong forged_sz = build_push( forged_payload, sizeof(forged_payload), forged, peer_idx, 1 );
    FD_TEST( send_payload( addr, port, forged_payload, forged_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_DROPPED_PUSH_NO_VALID_CRDS_IDX );
    FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DROPPED_PUSH_SIGNATURE_IDX ]==1UL );
    FD_TEST( fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache )==misses2+1UL );
  }
  ulong misses3 = fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache );

  /* The origin pongs: the third copy is admitted without a new verify
     and enters the dedup tcache; the fourth is a duplicate. */
  fd_gossip_ping_update_t ping_update[1];
  memset( ping_update, 0, sizeof(ping_update) );
  ping_update->pubkey           = *peers[ peer_idx ].pub;
  ping_update->gossip_addr.addr = addr;
  ping_update->gossip_addr.port = fd_ushort_bswap( port );
  handle_ping_update( ctx, ping_update );

  seq0 = stem_seq[0];
  FD_TEST( send_payload( addr, port, payload, payload_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_SUCCESS_PUSH_IDX );
  FD_TEST( fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache )==misses3 );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_VERIFIED_PUSH_IDX ]==1UL );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DROPPED_PUSH_INACTIVE_IDX ]==2UL );
  FD_TEST( stem_seq[0]==seq0+1UL ); /* no ping request */
  {
    fd_frag_meta_t const * meta = out_mcache + fd_mcache_line_idx( seq0, TEST_OUT_DEPTH );
    uchar const * out = fd_chunk_to_laddr_const( ctx->out->mem, meta->chunk );
    fd_gossip_message_t const * msg = (fd_gossip_message_t const *)out;
    FD_TEST( out[ fd_gossip_message_used_sz( msg ) ]==0 );
  }

  FD_TEST( send_payload( addr, port, payload, payload_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_SUCCESS_PUSH_IDX );
  FD_TEST( fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache )==misses3 );
  FD_TEST( ctx->metrics.crds_rx[ FD_METRICS_ENUM_GOSSVF_CRDS_RESULT_V_DUPLICATE_PUSH_IDX ]==1UL );

  /* A value whose signature fails is never remembered: the next copy
     is verified (and fails) again. */
  {
    fd_gossip_value_t bad[1];
    uchar bad_payload[ FD_NET_MTU ];
    make_contact_value( bad, 2UL, FD_IP4_ADDR( 8, 8, 8, 10 ), 8002U, now );
    ulong bad_sz = build_push( bad_payload, sizeof(bad_payload), bad, 2UL, 1 );
    ulong m = fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache );
    FD_TEST( send_payload( FD_IP4_ADDR( 8, 8, 8, 10 ), 8002U, bad_payload, bad_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_DROPPED_PUSH_NO_VALID_CRDS_IDX );
    FD_TEST( send_payload( FD_IP4_ADDR( 8, 8, 8, 10 ), 8002U, bad_payload, bad_sz )==FD_METRICS_ENUM_GOSSVF_MESSAGE_RESULT_V_DROPPED_PUSH_NO_VALID_CRDS_IDX );
    FD_TEST( fd_ed25519_cache_miss_cnt( ctx->ed25519_cache )+fd_ed25519_cache_hit_cnt( ctx->ed25519_cache )==m+2UL );
  }

  free_ctx();
  FD_LOG_NOTICE(( "sigok: pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<TEST_PEER_CNT; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) peers[ i ].priv[ j ] = (uchar)( 3U + 29U*(uint)i + (uint)j );
    fd_ed25519_public_from_private( peers[ i ].pub->uc, peers[ i ].priv, sha );
  }

  test_prune_sign_data_identity();
  test_prune_memo();
  test_sigok();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
