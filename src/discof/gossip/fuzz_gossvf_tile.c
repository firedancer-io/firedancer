#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"

/* Pull the tile implementation into this fuzz target so we can drive the
   real static validation helpers without exporting a production test API. */
#define fd_tile_gossvf fd_tile_gossvf_fuzz_unused
#include "fd_gossvf_tile.c"
#undef fd_tile_gossvf

#define FUZZ_PEER_CNT      (8UL)
#define FUZZ_OUT_DEPTH     (128UL)
#define FUZZ_OUT_DBUF_SZ   (1UL<<20UL)
#define FUZZ_TCACHE_DEPTH  (1UL<<14UL)
#define FUZZ_SHRED_VERSION (42U)
#define FUZZ_MAX_ACTIONS   (96UL)
#define FUZZ_GOSSVF_OUT_MTU \
  (sizeof(fd_gossip_message_t) + FD_GOSSIP_MESSAGE_MAX_CRDS + FD_NET_MTU)

typedef struct {
  uchar       priv[ 32UL ]; /* Private key for this peer. */
  fd_pubkey_t pub[ 1 ];
} fuzz_peer_t;

typedef struct {
  uchar const * cur; /* Current position in the raw fuzz input passed to LLVMFuzzerTestOneInput */
  ulong         rem; /* Remaining bytes in the raw fuzz input. */
} fuzz_cursor_t;

typedef struct {
  fd_gossvf_tile_ctx_t ctx[ 1 ];

  fd_frag_meta_t * out_mcache;
  fd_stem_context_t stem[ 1 ];
  fd_frag_meta_t *  stem_mcache[ 1 ];
  ulong             stem_seq[ 1 ];
  ulong             stem_depth[ 1 ];
  ulong             stem_cr_avail[ 1 ];
  ulong             stem_min_cr_avail[ 1 ];
  int               stem_out_reliable[ 1 ];

  uchar udp_payload[ FD_NET_MTU ];
  uchar value_buf[ 3UL ][ FD_NET_MTU ];
} fuzz_env_t;

static fuzz_peer_t peers[ FUZZ_PEER_CNT ];
static fd_sha512_t sha[ 1 ];
static fuzz_env_t  fuzz_env[ 1 ];
static uchar *     fuzz_mem;
static ulong       fuzz_mem_fp;

static ulong
fuzz_mem_align( void ) {
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
fuzz_mem_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),  peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),  ping_pool_footprint( FD_PING_TRACKER_MAX ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*FD_PING_TRACKER_MAX ) );
  l = FD_LAYOUT_APPEND( l, stake_pool_align(), stake_pool_footprint( MAX_SHRED_DESTS ) );
  l = FD_LAYOUT_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( MAX_SHRED_DESTS ) ) );
  l = FD_LAYOUT_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( FUZZ_TCACHE_DEPTH, 0UL ) );
  l = FD_LAYOUT_APPEND( l, FD_CHUNK_ALIGN,     FUZZ_OUT_DBUF_SZ );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(),  fd_mcache_footprint( FUZZ_OUT_DEPTH, 0UL ) );
  return FD_LAYOUT_FINI( l, fuzz_mem_align() );
}

static ulong
fuzz_wmark( ulong dbuf_sz,
            ulong mtu ) {
  ulong chunk_cnt = dbuf_sz >> FD_CHUNK_LG_SZ;
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ - 1UL) >>
                     (1UL+FD_CHUNK_LG_SZ)) << 1UL;
  FD_TEST( chunk_cnt>chunk_mtu );
  return chunk_cnt - chunk_mtu;
}

static void
fuzz_cleanup( void ) {
  free( fuzz_mem );
}

static uchar
fuzz_u8( fuzz_cursor_t * cur ) {
  if( FD_UNLIKELY( !cur->rem ) ) return 0U;
  uchar v = cur->cur[ 0 ];
  cur->cur++;
  cur->rem--;
  return v;
}

/* bound is exclusive */
static ulong
fuzz_bounded( fuzz_cursor_t * cur,
              ulong           bound ) {
  if( FD_UNLIKELY( bound<=1UL ) ) return 0UL;

  ulong x = 0UL;
  for( ulong shift=0UL, max=bound-1UL; max; shift+=8UL, max>>=8UL )
    x |= (ulong)fuzz_u8( cur ) << shift;
  return x % bound;
}

static int
fuzz_txn_write_u8( uchar ** p,
                   ulong *   rem,
                   uchar     x ) {
  if( FD_UNLIKELY( !*rem ) ) return 0;
  FD_STORE( uchar, *p, x );
  (*p)++;
  (*rem)--;
  return 1;
}

static int
fuzz_txn_write_u16_varint( uchar ** p,
                           ulong *   rem,
                           ushort    x ) {
  if( FD_LIKELY( x<128U ) ) return fuzz_txn_write_u8( p, rem, (uchar)x );
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
fuzz_txn_write_u32( uchar ** p,
                    ulong *   rem,
                    uint      x ) {
  if( FD_UNLIKELY( *rem<4UL ) ) return 0;
  FD_STORE( uint, *p, x );
  (*p) += 4UL;
  (*rem) -= 4UL;
  return 1;
}

static int
fuzz_txn_write_u64( uchar ** p,
                    ulong *   rem,
                    ulong     x ) {
  if( FD_UNLIKELY( *rem<8UL ) ) return 0;
  FD_STORE( ulong, *p, x );
  (*p) += 8UL;
  (*rem) -= 8UL;
  return 1;
}

static int
fuzz_txn_write_bytes( uchar **     p,
                      ulong *       rem,
                      uchar const * src,
                      ulong         sz ) {
  if( FD_UNLIKELY( *rem<sz ) ) return 0;
  memcpy( *p, src, sz );
  (*p) += sz;
  (*rem) -= sz;
  return 1;
}

static ulong
build_vote_txn( uchar *         out,
                ulong           out_sz,
                ulong           peer_idx,
                fuzz_cursor_t * cur ) {
  uchar instr[ 128UL ];
  uchar * q = instr;
  ulong instr_rem = sizeof(instr);

  ulong slot_cnt = 1UL + fuzz_bounded( cur, 4UL );
  ulong base_slot = 1000UL + fuzz_bounded( cur, 1000000UL );
  if( FD_UNLIKELY( !fuzz_txn_write_u32( &q, &instr_rem, fd_vote_instruction_enum_vote ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u64( &q, &instr_rem, slot_cnt ) ) ) return 0UL;
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    ulong slot = base_slot + i + fuzz_bounded( cur, 8UL );
    if( FD_UNLIKELY( !fuzz_txn_write_u64( &q, &instr_rem, slot ) ) ) return 0UL;
  }
  for( ulong i=0UL; i<32UL; i++ )
    if( FD_UNLIKELY( !fuzz_txn_write_u8( &q, &instr_rem, fuzz_u8( cur ) ) ) ) return 0UL;
  int has_timestamp = !!( fuzz_u8( cur ) & 1U );
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &q, &instr_rem, (uchar)has_timestamp ) ) ) return 0UL;
  if( has_timestamp ) {
    ulong ts = (ulong)( 1000000000L + (long)fuzz_bounded( cur, 1000000000UL ) );
    if( FD_UNLIKELY( !fuzz_txn_write_u64( &q, &instr_rem, ts ) ) ) return 0UL;
  }
  ulong trailing = fuzz_bounded( cur, 8UL );
  for( ulong i=0UL; i<trailing; i++ )
    if( FD_UNLIKELY( !fuzz_txn_write_u8( &q, &instr_rem, fuzz_u8( cur ) ) ) ) return 0UL;
  ulong instr_sz = (ulong)( q - instr );

  uchar * p = out;
  ulong rem = out_sz;
  if( FD_UNLIKELY( !fuzz_txn_write_u16_varint( &p, &rem, 1U ) ) ) return 0UL;
  for( ulong i=0UL; i<64UL; i++ )
    if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, fuzz_u8( cur ) ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL; /* required signatures */
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 0U ) ) ) return 0UL; /* readonly signed */
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL; /* readonly unsigned */

  if( FD_UNLIKELY( !fuzz_txn_write_u16_varint( &p, &rem, 3U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_bytes( &p, &rem, peers[ peer_idx ].pub->uc, 32UL ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_bytes( &p, &rem, peers[ 0 ].pub->uc, 32UL ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_bytes( &p, &rem, fd_solana_vote_program_id.uc, 32UL ) ) ) return 0UL;
  for( ulong i=0UL; i<32UL; i++ )
    if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, fuzz_u8( cur ) ) ) ) return 0UL;

  if( FD_UNLIKELY( !fuzz_txn_write_u16_varint( &p, &rem, 1U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 2U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u16_varint( &p, &rem, 2U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 0U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u8( &p, &rem, 1U ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_u16_varint( &p, &rem, (ushort)instr_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( !fuzz_txn_write_bytes( &p, &rem, instr, instr_sz ) ) ) return 0UL;

  return (ulong)( p - out );
}

static ushort
fuzz_port( ulong peer_idx ) {
  return (ushort)( 8000UL + peer_idx );
}

static uint
fuzz_addr_for_class( uchar cls,
                     ulong peer_idx ) {
  switch( cls % 6U ) {
    case 0U: return FD_IP4_ADDR( 8,   8,   8,   (uint)( 8UL + peer_idx ) );
    case 1U: return FD_IP4_ADDR( 1,   1,   1,   (uint)( 1UL + peer_idx ) );
    case 2U: return FD_IP4_ADDR( 10,  0,   0,   (uint)( 1UL + peer_idx ) );
    case 3U: return FD_IP4_ADDR( 127, 0,   0,   (uint)( 1UL + peer_idx ) );
    case 4U: return FD_IP4_ADDR( 224, 0,   0,   (uint)( 1UL + peer_idx ) );
    default: return 0U;
  }
}

static void
init_peers( void ) {
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<FUZZ_PEER_CNT; i++ ) {
    /* Private key is a seed sequence of bytes (no on-curve requirement) the only
       thing that matters here is that it is unique per peer so we get unique
       public keys. */
    for( ulong j=0UL; j<32UL; j++ ) peers[ i ].priv[ j ] = (uchar)( 1U + 17U*(uint)i + (uint)j );
    fd_ed25519_public_from_private( peers[ i ].pub->uc, peers[ i ].priv, sha );
  }
}

static void
setup_env( fuzz_env_t * env ) {
  memset( env, 0, sizeof(*env) );
  memset( fuzz_mem, 0, fuzz_mem_fp );
  FD_SCRATCH_ALLOC_INIT( l, fuzz_mem );

  fd_gossvf_tile_ctx_t * ctx = env->ctx;
  ctx->seed                  = 0x114320a17f4a7c15UL;
  ctx->shred_version         = FUZZ_SHRED_VERSION;
  ctx->allow_private_address = 0;
  ctx->gossip_addr.addr      = FD_IP4_ADDR( 8, 8, 4, 4 );
  ctx->gossip_addr.port      = fd_ushort_bswap( 9000U );
  ctx->src_addr              = ctx->gossip_addr;
  ctx->round_robin_cnt       = 1UL;
  ctx->round_robin_idx       = 0UL;
  fd_clock_tile_init( ctx->clock );
  ctx->instance_creation_wallclock_nanos = fd_clock_tile_now( ctx->clock );
  *ctx->identity_pubkey      = *peers[ 0 ].pub;

  void * peer_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),  peer_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * peer_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),   peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),  ping_pool_footprint( FD_PING_TRACKER_MAX ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),   ping_map_footprint( 2UL*FD_PING_TRACKER_MAX ) );
  void * stake_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stake_pool_align(), stake_pool_footprint( MAX_SHRED_DESTS ) );
  void * stake_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, stake_map_align(),  stake_map_footprint( stake_map_chain_cnt_est( MAX_SHRED_DESTS ) ) );
  void * tcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_tcache_align(),  fd_tcache_footprint( FUZZ_TCACHE_DEPTH, 0UL ) );
  void * out_dcache     = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN, FUZZ_OUT_DBUF_SZ );
  void * mcache_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(), fd_mcache_footprint( FUZZ_OUT_DEPTH, 0UL ) );

  ctx->peers      = peer_pool_join( peer_pool_new( peer_pool_mem, FD_CONTACT_INFO_TABLE_SIZE ) );
  ctx->peer_map   = peer_map_join ( peer_map_new ( peer_map_mem, 2UL*FD_CONTACT_INFO_TABLE_SIZE, ctx->seed ) );
  ctx->pings      = ping_pool_join( ping_pool_new( ping_pool_mem, FD_PING_TRACKER_MAX ) );
  ctx->ping_map   = ping_map_join ( ping_map_new ( ping_map_mem,  2UL*FD_PING_TRACKER_MAX, ctx->seed ) );
  ctx->stake.pool = stake_pool_join( stake_pool_new( stake_pool_mem, MAX_SHRED_DESTS ) );
  ctx->stake.map  = stake_map_join ( stake_map_new ( stake_map_mem, stake_map_chain_cnt_est( MAX_SHRED_DESTS ), ctx->seed ) );
  FD_TEST( !!(ctx->peers) & !!(ctx->peer_map) & !!(ctx->pings) & !!(ctx->ping_map) & !!(ctx->stake.pool) & !!(ctx->stake.map) );

  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( tcache_mem, FUZZ_TCACHE_DEPTH, 0UL ) );
  FD_TEST( tcache );
  ctx->tcache.depth   = fd_tcache_depth       ( tcache );
  ctx->tcache.map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache.sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache.ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache.map     = fd_tcache_map_laddr   ( tcache );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ctx->out->mem     = out_dcache;
  ctx->out->chunk0  = fd_laddr_to_chunk( out_dcache, out_dcache );
  ctx->out->wmark   = ctx->out->chunk0 + fuzz_wmark( FUZZ_OUT_DBUF_SZ, FUZZ_GOSSVF_OUT_MTU );
  ctx->out->chunk   = ctx->out->chunk0;
  env->out_mcache   = fd_mcache_join( fd_mcache_new( mcache_mem, FUZZ_OUT_DEPTH, 0UL, 0UL ) );
  FD_TEST( env->out_mcache );

  env->stem_mcache[0]       = env->out_mcache;
  env->stem_seq[0]          = 0UL;
  env->stem_depth[0]        = FUZZ_OUT_DEPTH;
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

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fuzz_mem_align() )<=(ulong)fuzz_mem+fuzz_mem_fp );
}

static void
make_contact_value( fd_gossip_value_t * value,
                    ulong               peer_idx,
                    uint                addr,
                    ushort              port,
                    ushort              shred_version,
                    long                now,
                    long                skew_ms ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_CONTACT_INFO;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)( FD_NANOSEC_TO_MILLI( now ) + skew_ms );

  value->contact_info->outset                    = (ulong)FD_NANOSEC_TO_MICRO( now - 1000000L );
  value->contact_info->shred_version             = shred_version;
  value->contact_info->version.major             = 2U;
  value->contact_info->version.minor             = 0U;
  value->contact_info->version.patch             = 0U;
  value->contact_info->version.commit            = 1U;
  value->contact_info->version.feature_set       = 1U;
  value->contact_info->version.client            = FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER;
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] = (fd_gossip_socket_t){
    .port    = fd_ushort_bswap( port ),
    .is_ipv6 = 0U,
    .ip4     = addr
  };
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ] = (fd_gossip_socket_t){
    .port    = fd_ushort_bswap( (ushort)( port + 1000U ) ),
    .is_ipv6 = 0U,
    .ip4     = addr
  };
}

static void
make_duplicate_shred_value( fd_gossip_value_t * value,
                            ulong               peer_idx,
                            long                now,
                            fuzz_cursor_t *     cur,
                            ulong               max_chunk_len ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_DUPLICATE_SHRED;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );

  value->duplicate_shred->index      = (ushort)fuzz_bounded( cur, 512UL );
  value->duplicate_shred->slot       = 1000UL + fuzz_bounded( cur, 1000000UL );
  value->duplicate_shred->num_chunks = (uchar)( 1UL + fuzz_bounded( cur, 4UL ) );
  value->duplicate_shred->chunk_index =
    (uchar)fuzz_bounded( cur, value->duplicate_shred->num_chunks );
  value->duplicate_shred->chunk_len =
    1UL + fuzz_bounded( cur, fd_ulong_min( max_chunk_len,
                                           sizeof(value->duplicate_shred->chunk) ) );
  for( ulong i=0UL; i<value->duplicate_shred->chunk_len; i++ )
    value->duplicate_shred->chunk[ i ] = fuzz_u8( cur );
}

static void
make_snapshot_hashes_value( fd_gossip_value_t * value,
                            ulong               peer_idx,
                            long                now,
                            fuzz_cursor_t *     cur,
                            ulong               max_incremental ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_SNAPSHOT_HASHES;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );

  value->snapshot_hashes->full_slot =
    1000UL + fuzz_bounded( cur, 1000000UL );
  for( ulong i=0UL; i<32UL; i++ )
    value->snapshot_hashes->full_hash[ i ] = fuzz_u8( cur );

  ulong inc_max = fd_ulong_min( max_incremental,
                                sizeof(value->snapshot_hashes->incremental)/
                                sizeof(value->snapshot_hashes->incremental[0]) );
  value->snapshot_hashes->incremental_len = fuzz_bounded( cur, inc_max+1UL );
  for( ulong i=0UL; i<value->snapshot_hashes->incremental_len; i++ ) {
    value->snapshot_hashes->incremental[ i ].slot =
      value->snapshot_hashes->full_slot + 1UL + i +
      fuzz_bounded( cur, 16UL );
    for( ulong j=0UL; j<32UL; j++ )
      value->snapshot_hashes->incremental[ i ].hash[ j ] = fuzz_u8( cur );
  }
}

static int
make_vote_value( fd_gossip_value_t * value,
                 ulong               peer_idx,
                 long                now,
                 fuzz_cursor_t *     cur ) {
  memset( value, 0, sizeof(*value) );
  value->tag       = FD_GOSSIP_VALUE_VOTE;
  memcpy( value->origin, peers[ peer_idx ].pub->uc, 32UL );
  value->wallclock = (ulong)FD_NANOSEC_TO_MILLI( now );
  value->vote->index = (uchar)fuzz_bounded( cur, 32UL );
  value->vote->transaction_len =
    build_vote_txn( value->vote->transaction,
                    sizeof(value->vote->transaction),
                    peer_idx,
                    cur );
  return !!value->vote->transaction_len;
}

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
build_push_or_pull_response( uchar *             payload,
                             ulong               payload_sz,
                             uint                tag,
                             uchar const * const value_bytes[ 3UL ],
                             ulong const *       value_sz,
                             ulong               value_cnt ) {
  if( FD_UNLIKELY( value_cnt>3UL ) ) return 0UL;
  ulong total_sz = 4UL+32UL+8UL;
  for( ulong i=0UL; i<value_cnt; i++ ) {
    if( FD_UNLIKELY( value_sz[ i ]>payload_sz ||
                     total_sz>payload_sz-value_sz[ i ] ) ) return 0UL;
    total_sz += value_sz[ i ];
  }

  uchar * p = payload;
  FD_STORE( uint,  p, tag ); p += 4UL;
  memcpy( p, peers[ 0 ].pub->uc, 32UL ); p += 32UL;
  FD_STORE( ulong, p, value_cnt ); p += 8UL;
  for( ulong i=0UL; i<value_cnt; i++ ) {
    memcpy( p, value_bytes[ i ], value_sz[ i ] );
    p += value_sz[ i ];
  }

  return (ulong)( p - payload );
}

static ulong
build_pull_request( uchar *       payload,
                    ulong         payload_sz,
                    uchar const * value_bytes,
                    ulong         value_sz,
                    ulong         num_bits,
                    uint          mask_bits ) {
  ulong * keys;
  ulong * bits;
  ulong * bits_set;
  long sz = fd_gossip_pull_request_init( payload, payload_sz, 1UL, num_bits, 0UL, mask_bits, value_bytes, value_sz, &keys, &bits, &bits_set );
  if( FD_UNLIKELY( sz<0L ) ) return 0UL;
  keys[0]   = 0x12345678UL;
  if( FD_LIKELY( bits ) ) bits[0] = 1UL;
  *bits_set = !!num_bits;
  return (ulong)sz;
}

static ulong
build_ping_or_pong( uchar * payload,
                    ulong   payload_sz,
                    uint    tag,
                    ulong   peer_idx,
                    int     corrupt_sig ) {
  if( FD_UNLIKELY( payload_sz < 4UL+32UL+32UL+64UL ) ) return 0UL;
  uchar * p = payload;
  FD_STORE( uint, p, tag ); p += 4UL;
  memcpy( p, peers[ peer_idx ].pub->uc, 32UL ); p += 32UL;
  for( ulong i=0UL; i<32UL; i++ ) p[ i ] = (uchar)( 0xa0U + (uint)i + (uint)peer_idx );
  uchar * sign_data = p;
  p += 32UL;
  fd_ed25519_sign( p, sign_data, 32UL, peers[ peer_idx ].pub->uc, peers[ peer_idx ].priv, sha );
  if( FD_UNLIKELY( corrupt_sig ) ) p[ 0 ] ^= 0x40U;
  p += 64UL;
  return (ulong)( p - payload );
}

static void
send_udp_payload( fuzz_env_t * env,
                  uint         src_addr,
                  ushort       src_port,
                  uchar const * payload,
                  ulong        payload_sz ) {
  if( FD_UNLIKELY( payload_sz + sizeof(fd_ip4_udp_hdrs_t) > FD_NET_MTU ) ) return;

  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, src_addr, src_port );
  ulong packet_sz = sizeof(fd_ip4_udp_hdrs_t) + payload_sz;
  memcpy( env->ctx->payload, hdrs, sizeof(fd_ip4_udp_hdrs_t) );
  memcpy( env->ctx->payload + sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  ulong old_chunk = env->ctx->out->chunk;
  ulong old_seq   = env->stem_seq[0];
  int result = handle_net( env->ctx, packet_sz, 0UL, env->stem );
  env->ctx->metrics.message_rx[ result ]++;
  env->ctx->metrics.message_rx_bytes[ result ] += packet_sz;

  if( FD_UNLIKELY( env->ctx->out->chunk==old_chunk ) ) return;

  fd_frag_meta_t const * meta = env->out_mcache + fd_mcache_line_idx( old_seq, FUZZ_OUT_DEPTH );
  if( FD_UNLIKELY( meta->seq!=old_seq || fd_gossvf_sig_kind( meta->sig )!=0U ) ) return;

  uchar const * out = fd_chunk_to_laddr_const( env->ctx->out->mem, old_chunk );
  fd_gossip_message_t const * msg = (fd_gossip_message_t const *)out;
  uchar const * failed = out + sizeof(fd_gossip_message_t);

  fd_gossip_value_t const * values = NULL;
  ulong values_len = 0UL;
  if( msg->tag==FD_GOSSIP_MESSAGE_PUSH ) {
    values = msg->push->values;
    values_len = msg->push->values_len;
  } else if( msg->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) {
    values = msg->pull_response->values;
    values_len = msg->pull_response->values_len;
  }

  for( ulong i=0UL; i<values_len; i++ ) {
    if( FD_UNLIKELY( failed[ i ] || values[ i ].tag!=FD_GOSSIP_VALUE_CONTACT_INFO ) ) continue;

    fd_gossip_update_message_t update[1];
    memset( update, 0, sizeof(update) );
    update->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
    memcpy( update->origin, values[ i ].origin, 32UL );
    update->wallclock = values[ i ].wallclock;
    update->contact_info->idx = i;
    *update->contact_info->value = *values[ i ].contact_info;
    handle_peer_update( env->ctx, update );
  }
}

static void
inject_ping_update( fuzz_env_t * env,
                    ulong        peer_idx,
                    uint         addr,
                    ushort       port ) {
  if( FD_UNLIKELY( !addr || !port ) ) return;
  fd_gossip_ping_update_t update[1];
  memset( update, 0, sizeof(update) );
  update->pubkey = *peers[ peer_idx ].pub;
  update->gossip_addr.addr = addr;
  update->gossip_addr.port = fd_ushort_bswap( port );
  update->remove = 0;
  if( FD_LIKELY( !ping_map_ele_query( env->ctx->ping_map,
                                      &update->pubkey,
                                      NULL,
                                      env->ctx->pings ) ) )
    handle_ping_update( env->ctx, update );
}

static void
inject_stakes( fuzz_env_t * env,
               ulong        first_peer,
               ulong        cnt,
               ulong        stake ) {
  memset( env->ctx->stake.msg_buf, 0, sizeof(fd_epoch_info_msg_t) + FUZZ_PEER_CNT*sizeof(fd_stake_weight_t) );
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)env->ctx->stake.msg_buf;
  msg->staked_id_cnt = fd_ulong_min( cnt, FUZZ_PEER_CNT );

  fd_stake_weight_t * weights = fd_epoch_info_msg_id_weights( msg );
  for( ulong i=0UL; i<msg->staked_id_cnt; i++ ) {
    ulong peer_idx = ( first_peer + i ) % FUZZ_PEER_CNT;
    weights[ i ].key = *peers[ peer_idx ].pub;
    weights[ i ].stake = stake;
  }
  handle_epoch( env->ctx, msg );
}

static void
inject_peer_update( fuzz_env_t * env,
                    ulong        peer_idx,
                    uint         addr,
                    ushort       port,
                    ushort       shred_version ) {
  fd_gossip_update_message_t update[1];
  memset( update, 0, sizeof(update) );
  update->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  memcpy( update->origin, peers[ peer_idx ].pub->uc, 32UL );
  update->wallclock = (ulong)FD_NANOSEC_TO_MILLI( fd_clock_tile_now( env->ctx->clock ) );
  update->contact_info->idx = peer_idx;
  update->contact_info->value->shred_version = shred_version;
  update->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ] =
      (fd_gossip_socket_t){
    .port    = fd_ushort_bswap( port ),
    .is_ipv6 = 0U,
    .ip4     = addr
  };
  handle_peer_update( env->ctx, update );
}


int
LLVMFuzzerInitialize( int *    argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  init_peers();

  fuzz_mem_fp = fuzz_mem_footprint();
  ulong align = fuzz_mem_align();
  fuzz_mem = aligned_alloc( align, FD_ULONG_ALIGN_UP( fuzz_mem_fp, align ) );
  FD_TEST( fuzz_mem );
  atexit( fuzz_cleanup );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<2UL ) ) return 0;

  fuzz_cursor_t cur = { .cur = data, .rem = size };
  fuzz_env_t * env = fuzz_env;
  setup_env( env );

  ulong action_cnt = 1UL + (ulong)( fuzz_u8( &cur ) % FUZZ_MAX_ACTIONS );
  for( ulong action_idx=0UL; (action_idx<action_cnt) & !!cur.rem; action_idx++ ) {
    /* Actions model the sources that feed gossvf in production:
       gossip-side peer/ping updates, epoch stakes, and net packets. */
    uchar action     = (uchar)( fuzz_u8( &cur ) % 11U );
    ulong peer_idx   = 1UL + fuzz_bounded( &cur, FUZZ_PEER_CNT-1UL );
    uchar addr_class = fuzz_u8( &cur );
    uint addr        = fuzz_addr_for_class( addr_class, peer_idx );
    ushort port      = fuzz_port( peer_idx );

    switch( action ) {
      case 0U: {
        inject_ping_update( env, peer_idx, addr, port );
        break;
      }
      case 1U: {
        ushort shred_version = (ushort)( (fuzz_u8( &cur ) & 1U) ? FUZZ_SHRED_VERSION : FUZZ_SHRED_VERSION+1U );
        inject_peer_update( env, peer_idx, addr, port, shred_version );
        break;
      }
      case 2U: {
        ulong cnt = 1UL + fuzz_bounded( &cur, FUZZ_PEER_CNT );
        ulong stake = (fuzz_u8( &cur ) & 1U) ? FD_GOSSIP_STAKED_THRESHOLD : 1UL;
        inject_stakes( env, peer_idx, cnt, stake );
        break;
      }
      case 3U:
      case 4U:
      case 5U: {
        fd_gossip_value_t value[1];
        ushort shred_version = (ushort)( (fuzz_u8( &cur ) & 3U) ? FUZZ_SHRED_VERSION : FUZZ_SHRED_VERSION+1U );
        long skew_ms = (long)( (int)( fuzz_u8( &cur ) % 41U ) - 20 ) * 1000L;
        int corrupt_sig = !!( fuzz_u8( &cur ) & 1U );
        make_contact_value( value, peer_idx, addr, port, shred_version, fd_clock_tile_now( env->ctx->clock ), skew_ms );

        long value_sz = serialize_signed_value( value,
                                                peer_idx,
                                                env->value_buf[0],
                                                sizeof(env->value_buf[0]),
                                                corrupt_sig );
        if( FD_UNLIKELY( value_sz<=0L ) ) break;

        ulong payload_sz;
        if( action==3U ) {
          uchar const * value_bytes[ 3UL ] = { env->value_buf[0], NULL, NULL };
          ulong value_szs[ 3UL ] = { (ulong)value_sz, 0UL, 0UL };
          payload_sz = build_push_or_pull_response( env->udp_payload,
                                                    sizeof(env->udp_payload),
                                                    FD_GOSSIP_MESSAGE_PUSH,
                                                    value_bytes,
                                                    value_szs,
                                                    1UL );
        } else if( action==4U ) {
          uchar const * value_bytes[ 3UL ] = { env->value_buf[0], NULL, NULL };
          ulong value_szs[ 3UL ] = { (ulong)value_sz, 0UL, 0UL };
          payload_sz = build_push_or_pull_response( env->udp_payload,
                                                    sizeof(env->udp_payload),
                                                    FD_GOSSIP_MESSAGE_PULL_RESPONSE,
                                                    value_bytes,
                                                    value_szs,
                                                    1UL );
        } else {
          ulong num_bits = (fuzz_u8( &cur ) & 1U) ? 64UL : 0UL;
          uint mask_bits = (uint)( fuzz_u8( &cur ) % 70U );
          payload_sz = build_pull_request( env->udp_payload,
                                           sizeof(env->udp_payload),
                                           env->value_buf[0],
                                           (ulong)value_sz,
                                           num_bits,
                                           mask_bits );
        }
        if( FD_LIKELY( payload_sz ) ) send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
        break;
      }
      case 6U: {
        int corrupt_sig = !!( fuzz_u8( &cur ) & 1U );
        uint tag = (fuzz_u8( &cur ) & 1U) ? FD_GOSSIP_MESSAGE_PING : FD_GOSSIP_MESSAGE_PONG;
        ulong payload_sz = build_ping_or_pong( env->udp_payload, sizeof(env->udp_payload), tag, peer_idx, corrupt_sig );
        if( FD_LIKELY( payload_sz ) ) send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
        break;
      }
      case 7U: {
        fd_gossip_value_t value[1];
        ushort origin_shred_version = (ushort)( (fuzz_u8( &cur ) & 7U) ? FUZZ_SHRED_VERSION : FUZZ_SHRED_VERSION+1U );
        inject_peer_update( env, peer_idx, addr, port, origin_shred_version );

        ulong value_kind = fuzz_bounded( &cur, 3UL );
        if( value_kind==0UL ) {
          make_duplicate_shred_value( value, peer_idx, fd_clock_tile_now( env->ctx->clock ), &cur, 256UL );
        } else if( value_kind==1UL ) {
          make_snapshot_hashes_value( value, peer_idx, fd_clock_tile_now( env->ctx->clock ), &cur, 8UL );
        } else if( FD_UNLIKELY( !make_vote_value( value, peer_idx, fd_clock_tile_now( env->ctx->clock ), &cur ) ) ) {
          break;
        }

        int corrupt_sig = !( fuzz_u8( &cur ) & 7U );
        long value_sz = serialize_signed_value( value,
                                                peer_idx,
                                                env->value_buf[0],
                                                sizeof(env->value_buf[0]),
                                                corrupt_sig );
        if( FD_UNLIKELY( value_sz<=0L ) ) break;

        uchar const * value_bytes[ 3UL ] = { env->value_buf[0], NULL, NULL };
        ulong value_szs[ 3UL ] = { (ulong)value_sz, 0UL, 0UL };
        uint tag = (fuzz_u8( &cur ) & 1U) ? FD_GOSSIP_MESSAGE_PUSH :
                                           FD_GOSSIP_MESSAGE_PULL_RESPONSE;
        ulong payload_sz = build_push_or_pull_response( env->udp_payload,
                                                        sizeof(env->udp_payload),
                                                        tag,
                                                        value_bytes,
                                                        value_szs,
                                                        1UL );
        if( FD_LIKELY( payload_sz ) ) {
          send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
          if( tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE && (fuzz_u8( &cur ) & 1U) )
            send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
        }
        break;
      }
      case 8U: {
        ulong peer1 = peer_idx;
        ulong peer2 = 1UL + fuzz_bounded( &cur, FUZZ_PEER_CNT-1UL );
        ulong peer3 = 1UL + fuzz_bounded( &cur, FUZZ_PEER_CNT-1UL );
        uint peer2_addr = fuzz_addr_for_class( 0U, peer2 );
        uint peer3_addr = fuzz_addr_for_class( 0U, peer3 );
        ushort peer2_port = fuzz_port( peer2 );
        ushort peer3_port = fuzz_port( peer3 );
        fd_gossip_value_t value[1];
        long value_sz[ 3UL ];

        inject_ping_update( env, peer1, addr, port );
        inject_stakes( env, peer1, FUZZ_PEER_CNT-1UL, FD_GOSSIP_STAKED_THRESHOLD );
        inject_peer_update( env, peer2, peer2_addr, peer2_port, FUZZ_SHRED_VERSION );
        inject_peer_update( env, peer3, peer3_addr, peer3_port, FUZZ_SHRED_VERSION );

        make_contact_value( value,
                            peer1,
                            addr,
                            port,
                            FUZZ_SHRED_VERSION,
                            fd_clock_tile_now( env->ctx->clock ),
                            0L );
        value_sz[0] = serialize_signed_value( value,
                                              peer1,
                                              env->value_buf[0],
                                              sizeof(env->value_buf[0]),
                                              0 );
        make_duplicate_shred_value( value, peer2, fd_clock_tile_now( env->ctx->clock ), &cur, 96UL );
        value_sz[1] = serialize_signed_value( value,
                                              peer2,
                                              env->value_buf[1],
                                              sizeof(env->value_buf[1]),
                                              !( fuzz_u8( &cur ) & 15U ) );
        make_snapshot_hashes_value( value, peer3, fd_clock_tile_now( env->ctx->clock ), &cur, 2UL );
        value_sz[2] = serialize_signed_value( value,
                                              peer3,
                                              env->value_buf[2],
                                              sizeof(env->value_buf[2]),
                                              !( fuzz_u8( &cur ) & 15U ) );
        if( FD_UNLIKELY( value_sz[0]<=0L || value_sz[1]<=0L || value_sz[2]<=0L ) ) break;

        uchar const * value_bytes[ 3UL ] = {
          env->value_buf[0],
          env->value_buf[1],
          env->value_buf[2]
        };
        ulong value_szs[ 3UL ] = {
          (ulong)value_sz[0],
          (ulong)value_sz[1],
          (ulong)value_sz[2]
        };
        uint tag = (fuzz_u8( &cur ) & 1U) ? FD_GOSSIP_MESSAGE_PUSH :
                                           FD_GOSSIP_MESSAGE_PULL_RESPONSE;
        ulong payload_sz = build_push_or_pull_response( env->udp_payload,
                                                        sizeof(env->udp_payload),
                                                        tag,
                                                        value_bytes,
                                                        value_szs,
                                                        3UL );
        if( FD_LIKELY( payload_sz ) ) {
          send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
          if( tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE && (fuzz_u8( &cur ) & 1U) )
            send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
        }
        break;
      }
      case 9U: {
        fd_gossip_value_t value[1];
        inject_stakes( env, peer_idx, 1UL, FD_GOSSIP_STAKED_THRESHOLD );
        if( FD_UNLIKELY( !make_vote_value( value, peer_idx, fd_clock_tile_now( env->ctx->clock ), &cur ) ) ) break;

        long value_sz = serialize_signed_value( value,
                                                peer_idx,
                                                env->value_buf[0],
                                                sizeof(env->value_buf[0]),
                                                !( fuzz_u8( &cur ) & 15U ) );
        if( FD_UNLIKELY( value_sz<=0L ) ) break;

        uchar const * value_bytes[ 3UL ] = { env->value_buf[0], NULL, NULL };
        ulong value_szs[ 3UL ] = { (ulong)value_sz, 0UL, 0UL };
        uint tag = (fuzz_u8( &cur ) & 1U) ? FD_GOSSIP_MESSAGE_PUSH :
                                           FD_GOSSIP_MESSAGE_PULL_RESPONSE;
        ulong payload_sz = build_push_or_pull_response( env->udp_payload,
                                                        sizeof(env->udp_payload),
                                                        tag,
                                                        value_bytes,
                                                        value_szs,
                                                        1UL );
        if( FD_LIKELY( payload_sz ) ) send_udp_payload( env, addr, port, env->udp_payload, payload_sz );
        break;
      }
      default: {
        ulong raw_sz = fuzz_bounded( &cur, fd_ulong_min( cur.rem, 1232UL ) + 1UL );
        raw_sz = fd_ulong_min( raw_sz, cur.rem );
        memcpy( env->udp_payload, cur.cur, raw_sz );
        cur.cur += raw_sz;
        cur.rem -= raw_sz;
        send_udp_payload( env, addr, port, env->udp_payload, raw_sz );
        break;
      }
    }
  }

  return 0;
}
