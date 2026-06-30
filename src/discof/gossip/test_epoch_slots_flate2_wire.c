#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* BP707 — flate2: Integration test enforcing that a malformed
   Flate2-compressed EpochSlots payload arriving from the network is
   rejected at the wire boundary by the real firedancer gossvf tile.

   This test FAILS while the bug is present and PASSES once the fix
   lands.  Today's behaviour (the bug):

     - deser_epoch_slots (fd_gossip_message.c:244-272) skips the
       compressed bytes without validating them.
     - handle_net (fd_gossvf_tile.c:773) therefore returns SUCCESS_PUSH
       and the gossvf tile publishes the payload to the gossip tile,
       which forwards `payload + value->offset` for `value->length`
       bytes verbatim via fd_active_set_push (fd_gossip.c:659).

   Expected behaviour after the fix (audit §6.1, "validate but don't
   consume"): the malformed DEFLATE stream is detected and rejected
   before the payload is forwarded — handle_net returns a DROPPED_*
   outcome and no relay-eligible frag is published.

   What this exercises:
     1. Build an Ethernet+IPv4+UDP packet with a Push containing one
        EpochSlots CRDS value whose single slot range is a Flate2 entry
        with 8 bytes of pure-garbage `compressed` payload (not a valid
        DEFLATE stream — Agave's `Flate2::inflate` would reject these
        bytes).
     2. Sign the CRDS value with a peer's ed25519 key and pre-populate
        the gossvf peer table with the peer's contact info (matching
        shred version) so shred-version + signature checks pass.  This
        isolates the assertion to the DEFLATE-validation step: every
        other gossvf gate accepts the message.
     3. Feed the packet into handle_net() — the *real* path used at
        runtime when a network frame arrives.
     4. Assert the message was rejected: handle_net returned a
        non-SUCCESS outcome AND no frag was published to the gossip
        tile's input.  Both assertions fail today; both pass once the
        deser path validates the DEFLATE stream. */

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"

/* Pull the tile implementation into this integration test target so we
   can drive the real handle_net() function and its static validation
   helpers without exporting a production test API.  Same trick as
   fuzz_gossvf_tile.c. */
#define fd_tile_gossvf fd_tile_gossvf_integration_test_unused
#include "fd_gossvf_tile.c"
#undef fd_tile_gossvf

#define TEST_OUT_DEPTH     (128UL)
#define TEST_OUT_DBUF_SZ   (1UL<<20UL)
#define TEST_TCACHE_DEPTH  (1UL<<14UL)
#define TEST_SHRED_VERSION (42U)
#define TEST_GOSSVF_OUT_MTU \
  (sizeof(fd_gossip_message_t) + FD_GOSSIP_MESSAGE_MAX_CRDS + FD_NET_MTU)

#define GARBAGE_LEN (8UL)
static uchar const GARBAGE[ GARBAGE_LEN ] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};

typedef struct {
  uchar       priv[ 32UL ];
  fd_pubkey_t pub[ 1 ];
} test_identity_t;

typedef struct {
  fd_gossvf_tile_ctx_t ctx[ 1 ];

  fd_frag_meta_t *  out_mcache;
  fd_stem_context_t stem[ 1 ];
  fd_frag_meta_t *  stem_mcache[ 1 ];
  ulong             stem_seq[ 1 ];
  ulong             stem_depth[ 1 ];
  ulong             stem_cr_avail[ 1 ];
  ulong             stem_min_cr_avail[ 1 ];
  int               stem_out_reliable[ 1 ];
} test_env_t;

static test_identity_t identity_self;
static test_identity_t identity_peer;
static fd_sha512_t     sha[ 1 ];
static test_env_t      test_env[ 1 ];
static uchar *         test_mem;
static ulong           test_mem_fp;

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
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),  peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),  ping_pool_footprint( FD_PING_TRACKER_MAX ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*FD_PING_TRACKER_MAX ) );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(), stake_pool_footprint( MAX_SHRED_DESTS ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( MAX_SHRED_DESTS ) ) );
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
init_identities( void ) {
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong j=0UL; j<32UL; j++ ) identity_self.priv[ j ] = (uchar)( 0x10U + (uint)j );
  for( ulong j=0UL; j<32UL; j++ ) identity_peer.priv[ j ] = (uchar)( 0xA0U + (uint)j );
  fd_ed25519_public_from_private( identity_self.pub->uc, identity_self.priv, sha );
  fd_ed25519_public_from_private( identity_peer.pub->uc, identity_peer.priv, sha );
}

static void
setup_env( test_env_t * env ) {
  memset( env, 0, sizeof(*env) );
  memset( test_mem, 0, test_mem_fp );
  FD_SCRATCH_ALLOC_INIT( l, test_mem );

  fd_gossvf_tile_ctx_t * ctx = env->ctx;
  ctx->seed                  = 0x114320a17f4a7c15UL;
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
  *ctx->identity_pubkey      = *identity_self.pub;

  void * peer_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),  peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * peer_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),  ping_pool_footprint( FD_PING_TRACKER_MAX ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*FD_PING_TRACKER_MAX ) );
  void * stake_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(), stake_pool_footprint( MAX_SHRED_DESTS ) );
  void * stake_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( MAX_SHRED_DESTS ) ) );
  void * tcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( TEST_TCACHE_DEPTH, 0UL ) );
  void * out_dcache     = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN,     TEST_OUT_DBUF_SZ );
  void * mcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(),  fd_mcache_footprint( TEST_OUT_DEPTH, 0UL ) );

  ctx->peers      = peer_pool_join( peer_pool_new( peer_pool_mem, FD_CONTACT_INFO_TABLE_SIZE ) );
  ctx->peer_map   = peer_map_join ( peer_map_new ( peer_map_mem, 2UL*FD_CONTACT_INFO_TABLE_SIZE, ctx->seed ) );
  ctx->pings      = ping_pool_join( ping_pool_new( ping_pool_mem, FD_PING_TRACKER_MAX ) );
  ctx->ping_map   = ping_map_join ( ping_map_new ( ping_map_mem,  2UL*FD_PING_TRACKER_MAX, ctx->seed ) );
  ctx->stake.pool = stake_pool_join( stake_pool_new( stake_pool_mem, MAX_SHRED_DESTS ) );
  ctx->stake.map  = stake_map_join ( stake_map_new ( stake_map_mem, stake_map_chain_cnt_est( MAX_SHRED_DESTS ), ctx->seed ) );
  FD_TEST( ctx->peers && ctx->peer_map && ctx->pings && ctx->ping_map && ctx->stake.pool && ctx->stake.map );

  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( tcache_mem, TEST_TCACHE_DEPTH, 0UL ) );
  FD_TEST( tcache );
  ctx->tcache.depth   = fd_tcache_depth       ( tcache );
  ctx->tcache.map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache.sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache.ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache.map     = fd_tcache_map_laddr   ( tcache );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ctx->out->mem    = out_dcache;
  ctx->out->chunk0 = fd_laddr_to_chunk( out_dcache, out_dcache );
  ctx->out->wmark  = ctx->out->chunk0 + test_wmark( TEST_OUT_DBUF_SZ, TEST_GOSSVF_OUT_MTU );
  ctx->out->chunk  = ctx->out->chunk0;
  env->out_mcache  = fd_mcache_join( fd_mcache_new( mcache_mem, TEST_OUT_DEPTH, 0UL, 0UL ) );
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
inject_peer( test_env_t * env,
             uint         peer_addr,
             ushort       peer_port ) {
  fd_gossip_update_message_t update[1];
  memset( update, 0, sizeof(update) );
  update->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  fd_memcpy( update->origin, identity_peer.pub->uc, 32UL );
  update->wallclock = (ulong)FD_NANOSEC_TO_MILLI( env->ctx->last_wallclock );
  update->contact_info->idx = 1UL;
  update->contact_info->value->shred_version = TEST_SHRED_VERSION;
  update->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] =
    (fd_gossip_socket_t){
      .port    = fd_ushort_bswap( peer_port ),
      .is_ipv6 = 0U,
      .ip4     = peer_addr
    };
  handle_peer_update( env->ctx, update );
}

/* Build an EpochSlots CRDS value containing one Flate2 slot range with
   GARBAGE as the compressed payload.  Layout follows
   firedancer/src/flamenco/gossip/fd_gossip_message.c:244-272 (the
   deserializer this test is exercising).  Returns total signed length.

   `out_garbage_offset` reports the offset of GARBAGE within `out`, so
   the test can assert the bytes survive at the same on-wire location. */
static long
build_signed_epoch_slots_flate2_value( uchar * out,
                                       ulong   out_sz,
                                       ulong * out_garbage_offset ) {
  if( FD_UNLIKELY( out_sz<256UL ) ) return -1L;
  uchar * p   = out;
  uchar * end = out + out_sz;

  /* signature placeholder — filled in after we know what to sign */
  fd_memset( p, 0, 64UL ); p += 64UL;

  uchar * signable_begin = p;

  /* CRDS enum tag */
  FD_STORE( uint, p, FD_GOSSIP_VALUE_EPOCH_SLOTS ); p += 4UL;

  /* EpochSlots header */
  *p++ = (uchar)0;                                              /* index */
  fd_memcpy( p, identity_peer.pub->uc, 32UL ); p += 32UL;       /* origin */
  FD_STORE( ulong, p, 1UL ); p += 8UL;                          /* slots_len */

  /* One Flate2 slot range */
  FD_STORE( uint,  p, 0U   ); p += 4UL;                         /* is_uncompressed = 0 → Flate2 */
  FD_STORE( ulong, p, 0UL  ); p += 8UL;                         /* first_slot */
  FD_STORE( ulong, p, 1UL  ); p += 8UL;                         /* num */
  FD_STORE( ulong, p, GARBAGE_LEN ); p += 8UL;                  /* compressed_len */
  *out_garbage_offset = (ulong)( p - out );
  fd_memcpy( p, GARBAGE, GARBAGE_LEN ); p += GARBAGE_LEN;       /* malformed DEFLATE bytes */

  /* Wallclock — must lie within the gossvf ±15s window. */
  long now = fd_log_wallclock();
  FD_STORE( ulong, p, (ulong)FD_NANOSEC_TO_MILLI( now ) ); p += 8UL;

  FD_TEST( p<=end );

  /* Sign the bytes after the 64-byte signature with the origin's key. */
  fd_ed25519_sign( out,                       /* signature destination */
                   signable_begin,
                   (ulong)( p - signable_begin ),
                   identity_peer.pub->uc,
                   identity_peer.priv,
                   sha );

  return (long)( p - out );
}

/* Build a Push message wrapping a single CRDS value.  Layout per
   fd_gossip_message.c:584-596 (deser_push).  */
static ulong
build_push_message( uchar *       out,
                    ulong         out_sz,
                    uchar const * value_bytes,
                    ulong         value_sz,
                    ulong *       out_value_offset ) {
  ulong total = 4UL + 32UL + 8UL + value_sz;
  if( FD_UNLIKELY( total>out_sz ) ) return 0UL;
  uchar * p = out;
  FD_STORE( uint,  p, FD_GOSSIP_MESSAGE_PUSH ); p += 4UL;
  fd_memcpy( p, identity_peer.pub->uc, 32UL );  p += 32UL;     /* from */
  FD_STORE( ulong, p, 1UL );                    p += 8UL;      /* values_len */
  *out_value_offset = (ulong)( p - out );
  fd_memcpy( p, value_bytes, value_sz );        p += value_sz;
  return (ulong)( p - out );
}

static void
test_epoch_slots_flate2_wire( void ) {
  test_env_t * env = test_env;
  setup_env( env );

  /* Peer pre-registered with matching shred version so the gossvf's
     shred-version filter and signature check accept the message.
     (No stake or ping setup needed — EpochSlots is not a ContactInfo,
     so verify_addresses doesn't ping-check it.) */
  uint   const peer_addr = FD_IP4_ADDR( 1, 1, 1, 1 );
  ushort const peer_port = 8001U;
  inject_peer( env, peer_addr, peer_port );

  /* Build the signed CRDS value with malformed DEFLATE bytes. */
  uchar value_buf[ FD_NET_MTU ];
  ulong garbage_offset_in_value;
  long  value_sz = build_signed_epoch_slots_flate2_value( value_buf,
                                                          sizeof(value_buf),
                                                          &garbage_offset_in_value );
  FD_TEST( value_sz>0L );

  /* Wrap in a Push message. */
  uchar udp_payload[ FD_NET_MTU ];
  ulong value_offset_in_push;
  ulong payload_sz = build_push_message( udp_payload,
                                         sizeof(udp_payload),
                                         value_buf,
                                         (ulong)value_sz,
                                         &value_offset_in_push );
  FD_TEST( payload_sz );

  /* Snapshot the on-wire garbage bytes before they enter handle_net()
     so we can assert byte-for-byte equality after. */
  uchar garbage_snapshot[ GARBAGE_LEN ];
  fd_memcpy( garbage_snapshot,
             udp_payload + value_offset_in_push + garbage_offset_in_value,
             GARBAGE_LEN );
  FD_TEST( !memcmp( garbage_snapshot, GARBAGE, GARBAGE_LEN ) );

  /* Wrap in IPv4+UDP headers and deliver to the gossvf tile's wire
     entry point, exactly as the net tile would on a live datagram. */
  FD_TEST( payload_sz + sizeof(fd_ip4_udp_hdrs_t) <= FD_NET_MTU );
  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, peer_addr, fd_ushort_bswap( peer_port ) );
  ulong packet_sz = sizeof(fd_ip4_udp_hdrs_t) + payload_sz;
  fd_memcpy( env->ctx->payload, hdrs, sizeof(fd_ip4_udp_hdrs_t) );
  fd_memcpy( env->ctx->payload + sizeof(fd_ip4_udp_hdrs_t), udp_payload, payload_sz );

  ulong const old_seq = env->stem_seq[0];

  int result = handle_net( env->ctx, packet_sz, 0UL, env->stem );

  /* Once the fix lands, the malformed DEFLATE stream is rejected at
     the wire boundary.  This test expresses that requirement directly:

       (a) handle_net returns a non-SUCCESS outcome, AND
       (b) no relay-eligible frag is published to the gossip tile.

     Until the fix lands, both assertions fail — handle_net returns
     SUCCESS_PUSH and a frag carrying the unchanged malformed bytes is
     published.  The error messages point at the audit doc and the
     specific functions that need updating. */
  int accepted  = result==FD_METRICS_ENUM_GOSSVF_MESSAGE_OUTCOME_V_SUCCESS_PUSH_IDX;
  int published = env->stem_seq[0]!=old_seq;

  if( FD_UNLIKELY( accepted ) ) {
    FD_LOG_ERR(( "BP707: gossvf accepted a malformed Flate2 EpochSlots payload at "
                 "the wire boundary (handle_net returned SUCCESS_PUSH=%d).  "
                 "deser_epoch_slots (fd_gossip_message.c:244-272) must validate "
                 "the DEFLATE stream instead of SKIP_BYTES-ing it.",
                 result ));
  }
  if( FD_UNLIKELY( published ) ) {
    FD_LOG_ERR(( "BP707: gossvf published the malformed Flate2 EpochSlots payload "
                 "to the gossip tile (stem_seq advanced by %lu).  "
                 "fd_active_set_push (fd_gossip.c:659) would then forward the "
                 "unchanged compressed bytes to peers.",
                 env->stem_seq[0]-old_seq ));
  }

  FD_LOG_NOTICE(( "wire path rejected %lu malformed DEFLATE byte(s) (result=%d)",
                  GARBAGE_LEN, result ));
}

static void
test_cleanup( void ) {
  free( test_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  init_identities();

  test_mem_fp = test_mem_footprint();
  ulong align = test_mem_align();
  test_mem = aligned_alloc( align, FD_ULONG_ALIGN_UP( test_mem_fp, align ) );
  FD_TEST( test_mem );
  atexit( test_cleanup );

  test_epoch_slots_flate2_wire();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
