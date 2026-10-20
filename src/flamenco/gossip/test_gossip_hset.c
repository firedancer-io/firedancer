#include "../../util/fd_util.h"
#include "fd_gossip_hset.h"
#include "fd_gossip_purged.h"
#include "fd_crds.h"
#include "fd_gossip_wsample.h"
#include "fd_active_set.h"
#include "fd_bloom.h"

#include <stdlib.h>
#include <string.h>

/* Reference: brute force set of (idx, hash). */

static uchar (* ref_hash)[ 32 ];
static int *    ref_live;

static int
cmp_hash( void const * a, void const * b ) {
  return memcmp( a, b, 32UL );
}

/* collect_hset gathers the hashes visited by an hset mask iteration
   into out (sorted), returns the count. */

static ulong
collect_hset( fd_gossip_hset_t const * hset,
              ulong                    start,
              ulong                    end,
              uchar                 (* out)[ 32 ] ) {
  ulong cnt = 0UL;
  fd_gossip_hset_iter_t it[1];
  for( fd_gossip_hset_iter_init( it, hset, start, end ); !fd_gossip_hset_iter_done( it ); fd_gossip_hset_iter_next( it, hset ) ) {
    uchar const * h     = fd_gossip_hset_iter_hashes( it, hset );
    uint          lanes = fd_gossip_hset_iter_lanes( it, hset );
    for( ulong i=0UL; i<8UL; i++ ) if( lanes & (1U<<i) ) memcpy( out[ cnt++ ], h+32UL*i, 32UL );
  }
  qsort( out, cnt, 32UL, cmp_hash );
  return cnt;
}

static void
random_mask( fd_rng_t * rng,
             ulong *    start,
             ulong *    end ) {
  uint  mask_bits = fd_rng_uint_roll( rng, 20U );
  ulong mask      = fd_rng_ulong( rng ) | (~0UL>>mask_bits);
  fd_gossip_purged_generate_masks( mask, mask_bits, start, end );
}

static void
test_hset_ref( fd_rng_t * rng,
               ulong      ele_max ) {
  void * mem = aligned_alloc( fd_gossip_hset_align(), fd_gossip_hset_footprint( ele_max ) );
  fd_gossip_hset_t * hset = fd_gossip_hset_join( fd_gossip_hset_new( mem, ele_max ) );
  FD_TEST( hset );

  ref_hash = malloc( 32UL*ele_max );
  ref_live = calloc( ele_max, sizeof(int) );
  uchar (* got)[ 32 ] = malloc( 32UL*ele_max );
  uchar (* exp)[ 32 ] = malloc( 32UL*ele_max );

  for( ulong round=0UL; round<64UL; round++ ) {
    /* Random churn, with some rounds skewed so buckets fill unevenly */
    ulong ops = fd_rng_ulong_roll( rng, 4UL*ele_max );
    uchar skew = (round&3UL)==1UL;
    for( ulong op=0UL; op<ops; op++ ) {
      ulong i = fd_rng_ulong_roll( rng, ele_max );
      if( ref_live[ i ] ) {
        fd_gossip_hset_remove( hset, i );
        ref_live[ i ] = 0;
      } else {
        for( ulong j=0UL; j<32UL; j++ ) ref_hash[ i ][ j ] = fd_rng_uchar( rng );
        if( skew ) ref_hash[ i ][ 7 ] = 0x5a; /* first byte of the LE prefix is the MSB */
        fd_gossip_hset_insert( hset, i, ref_hash[ i ] );
        ref_live[ i ] = 1;
      }
    }

    for( ulong q=0UL; q<16UL; q++ ) {
      ulong start, end;
      if( q==0UL ) { start = 0UL; end = ULONG_MAX; }
      else random_mask( rng, &start, &end );
      ulong exp_cnt = 0UL;
      for( ulong i=0UL; i<ele_max; i++ ) {
        ulong p = fd_ulong_load_8( ref_hash[ i ] );
        if( ref_live[ i ] && p>=start && p<=end ) memcpy( exp[ exp_cnt++ ], ref_hash[ i ], 32UL );
      }
      qsort( exp, exp_cnt, 32UL, cmp_hash );
      ulong got_cnt = collect_hset( hset, start, end, got );
      FD_TEST( got_cnt==exp_cnt );
      FD_TEST( !memcmp( got, exp, 32UL*exp_cnt ) );
    }
  }

  free( exp ); free( got ); free( ref_live ); free( ref_hash );
  free( mem );
}

/* Table sized like mainnet: crds (epoch slots) and purged filled and
   churned through their real insert/replace/expire paths.  Filters built
   from a full scan of the hsets filtered by prefix in the test (the
   reference) and from the ranged iteration must be identical, and the
   ranged iteration must report the owning entries. */

static void
dummy_activity( void * ctx, fd_pubkey_t const * id, fd_gossip_contact_info_t const * ci, int t ) {
  (void)ctx; (void)id; (void)ci; (void)t;
}

static void
crds_upsert( fd_crds_t * crds, fd_rng_t * rng, fd_stem_context_t * stem, ulong origin, uchar index, ulong wallclock, long now ) {
  fd_gossip_value_t value[1];
  memset( value, 0, sizeof(value) );
  value->tag = FD_GOSSIP_VALUE_EPOCH_SLOTS;
  FD_STORE( ulong, value->origin, origin );
  value->epoch_slots->index = index;
  value->wallclock = wallclock;
  for( ulong i=0UL; i<64UL; i++ ) value->signature[ i ] = fd_rng_uchar( rng );
  uchar bytes[ 128 ];
  memcpy( bytes, value->signature, 64UL );
  for( ulong i=64UL; i<128UL; i++ ) bytes[ i ] = fd_rng_uchar( rng );
  fd_crds_insert( crds, value, bytes, 128UL, 1UL, 0, 0, 0, now, stem, NULL );
}

/* Push duplicate counts follow the route: a push insert counts as the
   first push, a pull insert and pull duplicates do not count. */

static void
test_push_dups( fd_rng_t * rng ) {
  ulong                ele_max    = 64UL;
  void *               purged_mem = aligned_alloc( fd_gossip_purged_align(), fd_gossip_purged_footprint( ele_max ) );
  void *               crds_mem   = aligned_alloc( fd_crds_align(),          fd_crds_footprint( ele_max )          );
  fd_gossip_purged_t * purged     = fd_gossip_purged_join( fd_gossip_purged_new( purged_mem, rng, ele_max ) );
  fd_gossip_out_ctx_t  out[ FD_GOSSIP_UPDATE_LINK_CNT ] = {{0}};
  fd_stem_context_t    stem[1];
  memset( stem, 0, sizeof(stem) );
  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, NULL, 0UL, NULL, NULL, rng, ele_max, purged, dummy_activity, NULL, out ) );
  FD_TEST( crds );

  /* route per insert (1 push, 0 pull) and expected return, which is 1
     plus the earlier pushes for a duplicate */
  static int  const route[ 3 ][ 3 ] = { { 0, 1, 1 }, { 1, 1, 1 }, { 0, 0, 1 } };
  static long const want [ 3 ][ 3 ] = { { 0, 1, 2 }, { 0, 2, 3 }, { 0, 1, 1 } };
  for( ulong t=0UL; t<3UL; t++ ) {
    fd_gossip_value_t value[1];
    memset( value, 0, sizeof(value) );
    value->tag       = FD_GOSSIP_VALUE_EPOCH_SLOTS;
    value->wallclock = 1UL;
    FD_STORE( ulong, value->origin, t+1UL );
    for( ulong i=0UL; i<64UL; i++ ) value->signature[ i ] = fd_rng_uchar( rng );
    uchar bytes[ 128 ];
    memcpy( bytes, value->signature, 64UL );
    for( ulong i=64UL; i<128UL; i++ ) bytes[ i ] = fd_rng_uchar( rng );
    for( ulong k=0UL; k<3UL; k++ ) FD_TEST( fd_crds_insert( crds, value, bytes, 128UL, 1UL, 0, 0, route[ t ][ k ], 1L<<40, stem, NULL )==want[ t ][ k ] );
  }

  free( crds_mem );
  free( purged_mem );
}

/* An entrypoint's contact info counts while it is fresh: it stops
   counting when it goes unfresh, moves to another address, or expires,
   and counts again when re-received. */

static void
ci_upsert( fd_crds_t * crds, fd_rng_t * rng, fd_stem_context_t * stem, ulong origin, uint ip4, ushort port, ulong stake, ulong wallclock, long now, int is_me ) {
  fd_gossip_value_t value[1];
  memset( value, 0, sizeof(value) );
  value->tag = FD_GOSSIP_VALUE_CONTACT_INFO;
  FD_STORE( ulong, value->origin, origin );
  value->wallclock = wallclock;
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4  = ip4;
  value->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port = port;
  for( ulong i=0UL; i<64UL; i++ ) value->signature[ i ] = fd_rng_uchar( rng );
  uchar bytes[ 128 ];
  memcpy( bytes, value->signature, 64UL );
  for( ulong i=64UL; i<128UL; i++ ) bytes[ i ] = fd_rng_uchar( rng );
  FD_TEST( !fd_crds_insert( crds, value, bytes, 128UL, stake, 1, is_me, 0, now, stem, NULL ) );
}

static void
test_entrypoint_fresh( fd_rng_t * rng ) {
  ulong ele_max = 64UL;
  void * purged_mem  = aligned_alloc( fd_gossip_purged_align(),  fd_gossip_purged_footprint( ele_max )                  );
  void * crds_mem    = aligned_alloc( fd_crds_align(),           fd_crds_footprint( ele_max )                           );
  void * wsample_mem = aligned_alloc( fd_gossip_wsample_align(), fd_gossip_wsample_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * as_mem      = aligned_alloc( fd_active_set_align(),     fd_active_set_footprint()                              );
  fd_gossip_purged_t *  purged  = fd_gossip_purged_join( fd_gossip_purged_new( purged_mem, rng, ele_max ) );
  fd_gossip_wsample_t * wsample = fd_gossip_wsample_join( fd_gossip_wsample_new( wsample_mem, rng, FD_CONTACT_INFO_TABLE_SIZE ) );
  /* Expiry publishes a removal on the contact info link, so give it one. */
  static uchar mcache_mem[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar dcache_mem[ FD_DCACHE_FOOTPRINT( 1UL<<20, 0UL ) ] __attribute__((aligned(FD_DCACHE_ALIGN)));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, 128UL, 0UL, 0UL ) );
  uchar *          dcache = fd_dcache_join( fd_dcache_new( dcache_mem, 1UL<<20, 0UL ) );
  FD_TEST( mcache && dcache );
  fd_gossip_out_ctx_t out[ FD_GOSSIP_UPDATE_LINK_CNT ];
  for( ulong i=0UL; i<FD_GOSSIP_UPDATE_LINK_CNT; i++ ) out[ i ] = (fd_gossip_out_ctx_t){ .idx = ULONG_MAX };
  ulong chunk0 = fd_dcache_compact_chunk0( dcache_mem, dcache );
  out[ FD_GOSSIP_UPDATE_LINK_CI_ADDR ] = (fd_gossip_out_ctx_t){ .mem = (fd_wksp_t *)dcache_mem, .chunk0 = chunk0, .chunk = chunk0, .wmark = fd_dcache_compact_wmark( dcache_mem, dcache, FD_NET_MTU ), .idx = 0UL };
  fd_frag_meta_t * mcaches[1]      = { mcache };
  ulong            seqs[1]         = { 0UL };
  ulong            depths[1]       = { 128UL };
  ulong            cr_avail[1]     = { ULONG_MAX };
  ulong            min_cr_avail[1] = { ULONG_MAX };
  int              reliable[1]     = { 0 };
  fd_stem_context_t stem[1] = {{ .mcaches = mcaches, .seqs = seqs, .depths = depths, .cr_avail = cr_avail, .min_cr_avail = min_cr_avail, .out_reliable = reliable }};

  fd_ip4_port_t entrypoints[ 2 ] = { { .addr = FD_IP4_ADDR( 10, 0, 0, 1 ), .port = fd_ushort_bswap( 8001 ) },
                                     { .addr = FD_IP4_ADDR( 10, 0, 0, 2 ), .port = fd_ushort_bswap( 8001 ) } };
  uchar identity[ 32 ] = {0};
  fd_crds_t *       crds = fd_crds_join( fd_crds_new( crds_mem, entrypoints, 2UL, wsample, as_mem, rng, ele_max, purged, dummy_activity, NULL, out ) );
  fd_active_set_t * as   = fd_active_set_join( fd_active_set_new( as_mem, wsample, crds, rng, identity, 0UL, NULL, NULL ) );
  FD_TEST( crds && wsample && as );

  /* Unstaked contact infos expire (15 s) before they go unfresh (60 s)
     once a staked node is known, so the unfresh steps use staked ones. */
  long s = 1000L*1000L*1000L;
  long now = 1L<<40;
  ci_upsert( crds, rng, stem, 1UL, FD_IP4_ADDR( 10, 0, 0, 9 ), fd_ushort_bswap( 8001 ), 1UL, 1UL, now, 0 ); /* not an entrypoint */
  ci_upsert( crds, rng, stem, 2UL, FD_IP4_ADDR( 10, 0, 0, 1 ), fd_ushort_bswap( 8002 ), 1UL, 1UL, now, 0 ); /* entrypoint address, other port */
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==0UL );
  ci_upsert( crds, rng, stem, 3UL, FD_IP4_ADDR( 10, 0, 0, 1 ), fd_ushort_bswap( 8001 ), 1UL, 1UL, now, 0 );
  ci_upsert( crds, rng, stem, 4UL, FD_IP4_ADDR( 10, 0, 0, 2 ), fd_ushort_bswap( 8001 ), 1UL, 1UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==2UL );

  /* Re-received: still counted once.  The other goes unfresh at 60 s. */
  now += 30L*s;
  ci_upsert( crds, rng, stem, 3UL, FD_IP4_ADDR( 10, 0, 0, 1 ), fd_ushort_bswap( 8001 ), 1UL, 2UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==2UL );
  now += 31L*s;
  fd_crds_advance( crds, now, stem, NULL );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==1UL );

  /* Re-received after going unfresh: counted again.  One that moves
     to another address stops counting. */
  ci_upsert( crds, rng, stem, 4UL, FD_IP4_ADDR( 10, 0, 0, 2 ), fd_ushort_bswap( 8001 ), 1UL, 3UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==2UL );
  ci_upsert( crds, rng, stem, 3UL, FD_IP4_ADDR( 10, 0, 0, 7 ), fd_ushort_bswap( 8001 ), 1UL, 4UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==1UL );

  /* Our own contact info never counts, even at an entrypoint address. */
  ci_upsert( crds, rng, stem, 6UL, FD_IP4_ADDR( 10, 0, 0, 2 ), fd_ushort_bswap( 8001 ), 1UL, 5UL, now, 1 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==1UL );
  ci_upsert( crds, rng, stem, 4UL, FD_IP4_ADDR( 10, 0, 0, 3 ), fd_ushort_bswap( 8001 ), 1UL, 6UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==0UL );
  ci_upsert( crds, rng, stem, 4UL, FD_IP4_ADDR( 10, 0, 0, 2 ), fd_ushort_bswap( 8001 ), 1UL, 7UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==1UL );

  /* An unstaked one counts until it expires. */
  ci_upsert( crds, rng, stem, 5UL, FD_IP4_ADDR( 10, 0, 0, 1 ), fd_ushort_bswap( 8001 ), 0UL, 1UL, now, 0 );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==2UL );
  now += 20L*s;
  fd_crds_advance( crds, now, stem, NULL );
  FD_TEST( fd_crds_peer_count( crds )==5UL );
  FD_TEST( fd_crds_entrypoint_fresh_cnt( crds )==1UL );

  free( as_mem );
  free( wsample_mem );
  free( crds_mem );
  free( purged_mem );
}

/* Relays of one key go out at most once per 100 ms after the last one:
   the first now, later versions held until 100 ms after it, and only
   the latest held version is pushed, once.  A held entry that expires
   is never pushed. */

static ulong relay_sent_cnt;
static uint  relay_sent_tag;
static ulong relay_sent_wallclock;

static void
relay_send( void * ctx, fd_stem_context_t * stem, uchar const * data, ulong sz, fd_ip4_port_t const * peer, ulong now ) {
  (void)ctx; (void)stem; (void)peer; (void)now;
  /* push message: tag(4) identity(32) crds_len(8), then each value */
  FD_TEST( sz>=44UL+64UL+4UL );
  ulong crds_len = FD_LOAD( ulong, data+36UL );
  relay_sent_cnt += crds_len;
  relay_sent_tag       = FD_LOAD( uint,  data+44UL+64UL );
  relay_sent_wallclock = FD_LOAD( ulong, data+44UL+68UL );
}

static void
relay_insert( fd_crds_t * crds, fd_rng_t * rng, fd_stem_context_t * stem, ulong origin, ulong stake, ulong wallclock, long now, int * relay ) {
  fd_gossip_value_t value[1];
  memset( value, 0, sizeof(value) );
  value->tag = FD_GOSSIP_VALUE_EPOCH_SLOTS;
  FD_STORE( ulong, value->origin, origin );
  value->wallclock = wallclock;
  for( ulong i=0UL; i<64UL; i++ ) value->signature[ i ] = fd_rng_uchar( rng );
  uchar bytes[ 128 ];
  memcpy( bytes, value->signature, 64UL );
  FD_STORE( uint,  bytes+64UL, FD_GOSSIP_VALUE_EPOCH_SLOTS );
  FD_STORE( ulong, bytes+68UL, wallclock ); /* stands in for the value body */
  for( ulong i=76UL; i<128UL; i++ ) bytes[ i ] = fd_rng_uchar( rng );
  FD_TEST( !fd_crds_insert( crds, value, bytes, 128UL, stake, 1, 0, 1, now, stem, relay ) );
}

static void
test_relay_coalesce( fd_rng_t * rng ) {
  ulong ele_max = 64UL;
  void * purged_mem  = aligned_alloc( fd_gossip_purged_align(),  fd_gossip_purged_footprint( ele_max )                    );
  void * crds_mem    = aligned_alloc( fd_crds_align(),           fd_crds_footprint( ele_max )                             );
  void * wsample_mem = aligned_alloc( fd_gossip_wsample_align(), fd_gossip_wsample_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * as_mem      = aligned_alloc( fd_active_set_align(),     fd_active_set_footprint()                                );
  fd_gossip_purged_t *  purged  = fd_gossip_purged_join( fd_gossip_purged_new( purged_mem, rng, ele_max ) );
  fd_gossip_wsample_t * wsample = fd_gossip_wsample_join( fd_gossip_wsample_new( wsample_mem, rng, FD_CONTACT_INFO_TABLE_SIZE ) );
  fd_gossip_out_ctx_t   out[ FD_GOSSIP_UPDATE_LINK_CNT ];
  for( ulong i=0UL; i<FD_GOSSIP_UPDATE_LINK_CNT; i++ ) out[ i ] = (fd_gossip_out_ctx_t){ .idx = ULONG_MAX };
  fd_stem_context_t stem[1];
  memset( stem, 0, sizeof(stem) );
  uchar identity[ 32 ] = { 0xFF };
  fd_crds_t *       crds = fd_crds_join( fd_crds_new( crds_mem, NULL, 0UL, wsample, as_mem, rng, ele_max, purged, dummy_activity, NULL, out ) );
  fd_active_set_t * as   = fd_active_set_join( fd_active_set_new( as_mem, wsample, crds, rng, identity, 0UL, relay_send, NULL ) );
  FD_TEST( crds && wsample && as );

  /* One staked peer in the active set to push to */
  long ms  = 1000L*1000L;
  long now = 1L<<40;
  ulong now_ms = (ulong)FD_NANOSEC_TO_MILLI( now );
  fd_gossip_value_t ci[1];
  memset( ci, 0, sizeof(ci) );
  ci->tag = FD_GOSSIP_VALUE_CONTACT_INFO;
  FD_STORE( ulong, ci->origin, 1UL );
  ci->wallclock = now_ms;
  ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4  = FD_IP4_ADDR( 10, 0, 0, 1 );
  ci->contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port = fd_ushort_bswap( 8001 );
  uchar ci_bytes[ 128 ] = { 0x01 };
  FD_TEST( !fd_crds_insert( crds, ci, ci_bytes, 128UL, FD_GOSSIP_STAKED_THRESHOLD, 1, 0, 0, now, stem, NULL ) );
  fd_active_set_advance( as, stem, now, NULL );

  /* First version relays now, the next two inside the window are held
     and the second replaces the first */
  int relay;
  relay_insert( crds, rng, stem, 2UL, FD_GOSSIP_STAKED_THRESHOLD, now_ms+1UL, now,        &relay ); FD_TEST( relay );
  relay_insert( crds, rng, stem, 2UL, FD_GOSSIP_STAKED_THRESHOLD, now_ms+2UL, now+90L*ms, &relay ); FD_TEST( !relay );
  relay_insert( crds, rng, stem, 2UL, FD_GOSSIP_STAKED_THRESHOLD, now_ms+3UL, now+95L*ms, &relay ); FD_TEST( !relay );
  FD_TEST( fd_crds_metrics( crds )->relay_coalesced_cnt==1UL );

  /* Due 100 ms after the last relay, not 100 ms after it was held */
  relay_sent_cnt = 0UL;
  fd_crds_advance( crds, now+99L*ms, stem, NULL );
  fd_active_set_advance( as, stem, now+99L*ms, NULL );
  FD_TEST( !relay_sent_cnt );
  fd_crds_advance( crds, now+100L*ms, stem, NULL );
  fd_active_set_advance( as, stem, now+102L*ms, NULL );
  FD_TEST( relay_sent_cnt==1UL );
  FD_TEST( relay_sent_tag==FD_GOSSIP_VALUE_EPOCH_SLOTS && relay_sent_wallclock==now_ms+3UL );
  fd_crds_advance( crds, now+300L*ms, stem, NULL );
  fd_active_set_advance( as, stem, now+302L*ms, NULL );
  FD_TEST( relay_sent_cnt==1UL );

  /* A held entry released (expired here) before it is due is never
     pushed; unstaked values expire after 15 s once a staked node is
     known */
  long t = now+1000L*ms;
  ulong t_ms = (ulong)FD_NANOSEC_TO_MILLI( t );
  relay_insert( crds, rng, stem, 3UL, 0UL, t_ms, t,         &relay ); FD_TEST( relay );
  relay_insert( crds, rng, stem, 3UL, 0UL, t_ms+1UL, t+10L*ms, &relay ); FD_TEST( !relay );
  relay_sent_cnt = 0UL;
  fd_crds_advance( crds, t+16000L*ms, stem, NULL );
  fd_active_set_advance( as, stem, t+16002L*ms, NULL );
  FD_TEST( !relay_sent_cnt );

  /* A held version that leaves the 15 s wallclock window by its due
     time is dropped, not relayed: a fresh version after it is timed
     from the last relay that went out */
  long  u    = t+20000L*ms;
  ulong u_ms = (ulong)FD_NANOSEC_TO_MILLI( u );
  relay_insert( crds, rng, stem, 4UL, FD_GOSSIP_STAKED_THRESHOLD, u_ms-14960UL,     u,         &relay ); FD_TEST( relay );
  relay_insert( crds, rng, stem, 4UL, FD_GOSSIP_STAKED_THRESHOLD, u_ms-14950UL,     u+10L*ms,  &relay ); FD_TEST( !relay );
  relay_sent_cnt = 0UL;
  fd_crds_advance( crds, u+100L*ms, stem, NULL );
  fd_active_set_advance( as, stem, u+102L*ms, NULL );
  FD_TEST( !relay_sent_cnt );
  relay_insert( crds, rng, stem, 4UL, FD_GOSSIP_STAKED_THRESHOLD, u_ms+110UL,       u+110L*ms, &relay ); FD_TEST( relay );

  free( as_mem );
  free( wsample_mem );
  free( crds_mem );
  free( purged_mem );
}

static void
build_old( fd_crds_t * crds, fd_gossip_purged_t * purged, fd_bloom_t * filter, ulong mask, uint mask_bits, ulong * cnt ) {
  ulong start, end;
  fd_gossip_purged_generate_masks( mask, mask_bits, &start, &end );
  fd_gossip_hset_t const * hsets[ 2 ] = { fd_crds_hset( crds ), fd_gossip_purged_hset( purged ) };
  ulong n = 0UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gossip_hset_iter_t it[1];
    for( fd_gossip_hset_iter_init( it, hsets[ i ], 0UL, ULONG_MAX ); !fd_gossip_hset_iter_done( it ); fd_gossip_hset_iter_next( it, hsets[ i ] ) ) {
      uchar const * h     = fd_gossip_hset_iter_hashes( it, hsets[ i ] );
      uint          lanes = fd_gossip_hset_iter_lanes( it, hsets[ i ] );
      for( ulong l=0UL; l<8UL; l++ ) {
        if( !(lanes & (1U<<l)) ) continue;
        ulong p = fd_ulong_load_8( h+32UL*l );
        if( p<start || p>end ) continue;
        fd_bloom_insert( filter, h+32UL*l, 32UL ); n++;
        /* the crds hset points back at the entry holding that hash */
        if( !i ) FD_TEST( !memcmp( fd_crds_entry_hash( fd_crds_entry_at( crds, fd_gossip_hset_iter_owner( it, hsets[ i ], l ) ) ), h+32UL*l, 32UL ) );
      }
    }
  }
  *cnt = n;
}

static void
build_new( fd_crds_t * crds, fd_gossip_purged_t * purged, fd_bloom_t * filter, ulong mask, uint mask_bits, ulong * cnt ) {
  ulong start, end;
  fd_gossip_purged_generate_masks( mask, mask_bits, &start, &end );
  fd_gossip_hset_t const * hsets[ 2 ] = { fd_crds_hset( crds ), fd_gossip_purged_hset( purged ) };
  ulong n = 0UL;
  /* Same pairing as fd_gossip.c tx_pull_request */
  uchar const * pend_hashes = NULL;
  uint          pend_lanes  = 0U;
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gossip_hset_iter_t it[1];
    for( fd_gossip_hset_iter_init( it, hsets[ i ], start, end ); !fd_gossip_hset_iter_done( it ); fd_gossip_hset_iter_next( it, hsets[ i ] ) ) {
      uint lanes = fd_gossip_hset_iter_lanes( it, hsets[ i ] );
      n += (ulong)fd_uint_popcnt( lanes );
      if( !lanes ) continue;
      uchar const * hashes = fd_gossip_hset_iter_hashes( it, hsets[ i ] );
      if( !pend_lanes ) { pend_hashes = hashes; pend_lanes = lanes; continue; }
      fd_bloom_insert16( filter, pend_hashes, pend_lanes, hashes, lanes );
      pend_lanes = 0U;
    }
  }
  if( pend_lanes ) fd_bloom_insert8( filter, pend_hashes, pend_lanes );
  *cnt = n;
}

static void
test_tables( fd_rng_t * rng,
             ulong      ele_max,
             ulong      crds_cnt,
             ulong      purged_cnt,
             int        bench ) {
  void * purged_mem = aligned_alloc( fd_gossip_purged_align(), fd_gossip_purged_footprint( ele_max ) );
  void * crds_mem   = aligned_alloc( fd_crds_align(),          fd_crds_footprint( ele_max )          );
  fd_gossip_purged_t * purged = fd_gossip_purged_join( fd_gossip_purged_new( purged_mem, rng, ele_max ) );
  FD_TEST( purged );

  fd_gossip_out_ctx_t out[ FD_GOSSIP_UPDATE_LINK_CNT ] = {{0}};
  fd_stem_context_t   stem[1];
  memset( stem, 0, sizeof(stem) );
  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, NULL, 0UL, NULL, NULL, rng, ele_max, purged, dummy_activity, NULL, out ) );
  FD_TEST( crds );

  long  now = 1L<<40;
  ulong origin_cnt = fd_ulong_max( crds_cnt/64UL, 1UL );
  ulong wallclock = 1UL;
  /* Fill: distinct keys, then replace some (moves hashes into purged) */
  for( ulong i=0UL; i<crds_cnt; i++ ) crds_upsert( crds, rng, stem, i%origin_cnt, (uchar)(i/origin_cnt), wallclock, now );
  while( fd_gossip_purged_len( purged )<purged_cnt/2UL ) {
    ulong i = fd_rng_ulong_roll( rng, crds_cnt );
    crds_upsert( crds, rng, stem, i%origin_cnt, (uchar)(i/origin_cnt), ++wallclock, now );
  }
  uchar h[ 32 ];
  while( fd_gossip_purged_len( purged )<purged_cnt ) {
    for( ulong j=0UL; j<32UL; j++ ) h[ j ] = fd_rng_uchar( rng );
    ulong kind = fd_rng_ulong_roll( rng, 3UL );
    if(      kind==0UL ) fd_gossip_purged_insert_failed_insert( purged, h, now );
    else if( kind==1UL ) fd_gossip_purged_insert_replaced( purged, h, now );
    else                 fd_gossip_purged_insert_no_contact_info( purged, h /* origin */, h, now );
  }
  FD_LOG_NOTICE(( "crds %lu purged %lu", fd_crds_len( crds ), fd_gossip_purged_len( purged ) ));

  ulong keys0[ 3 ], keys1[ 3 ];
  ulong bits0[ 151 ], bits1[ 151 ];
  ulong total = fd_crds_len( crds ) + fd_gossip_purged_len( purged );
  uint  mask_bits_real = (uint)fd_ulong_find_msb( fd_ulong_max( total, 65536UL )/2010UL ) + 1U;

  for( ulong round=0UL; round<(bench ? 1UL : 32UL); round++ ) {
    /* Churn: replacements, fresh purged entries, expiry of some */
    now += 1000000000L;
    for( ulong k=0UL; k<(ele_max/64UL); k++ ) {
      ulong i = fd_rng_ulong_roll( rng, crds_cnt );
      crds_upsert( crds, rng, stem, i%origin_cnt, (uchar)(i/origin_cnt), ++wallclock, now );
      for( ulong j=0UL; j<32UL; j++ ) h[ j ] = fd_rng_uchar( rng );
      fd_gossip_purged_insert_failed_insert( purged, h, now );
    }
    if( round==8UL ) {
      fd_gossip_purged_expire( purged, now+50L*1000000000L ); /* expires the older replaced/failed entries */
      fd_gossip_purged_drain_no_contact_info( purged, h );
    }

    for( ulong q=0UL; q<64UL; q++ ) {
      uint  mask_bits = q<32UL ? mask_bits_real : fd_rng_uint_roll( rng, 20U );
      ulong mask      = fd_rng_ulong( rng ) | (~0UL>>mask_bits);
      ulong num_bits  = 1UL + fd_rng_ulong_roll( rng, 151UL*64UL );
      memset( bits0, 0, sizeof(bits0) ); memset( bits1, 0, sizeof(bits1) );
      fd_rng_t r0[1], r1[1];
      ulong seed = fd_rng_ulong( rng );
      fd_bloom_t f0[1], f1[1];
      fd_bloom_init_inplace( keys0, bits0, 3UL, num_bits, 0UL, fd_rng_join( fd_rng_new( r0, (uint)seed, 0UL ) ), 0.1, f0 );
      fd_bloom_init_inplace( keys1, bits1, 3UL, num_bits, 0UL, fd_rng_join( fd_rng_new( r1, (uint)seed, 0UL ) ), 0.1, f1 );
      ulong c0, c1;
      build_old( crds, purged, f0, mask, mask_bits, &c0 );
      build_new( crds, purged, f1, mask, mask_bits, &c1 );
      FD_TEST( c0==c1 );
      FD_TEST( !memcmp( keys0, keys1, sizeof(keys0) ) );
      FD_TEST( !memcmp( bits0, bits1, sizeof(bits0) ) );
    }
  }

  if( bench ) {
    ulong iter = 4096UL;
    ulong * masks = malloc( iter*sizeof(ulong) );
    for( ulong i=0UL; i<iter; i++ ) masks[ i ] = fd_rng_ulong( rng ) | (~0UL>>mask_bits_real);
    ulong num_bits = 7696UL;
    fd_bloom_t f[1];
    for( ulong v=0UL; v<2UL; v++ ) {
      ulong n = 0UL;
      long dt = -fd_log_wallclock();
      for( ulong i=0UL; i<iter; i++ ) {
        memset( bits0, 0, sizeof(bits0) );
        fd_bloom_init_inplace( keys0, bits0, 3UL, num_bits, 0UL, rng, 0.1, f );
        ulong c;
        if( v ) build_new( crds, purged, f, masks[ i ], mask_bits_real, &c );
        else    build_old( crds, purged, f, masks[ i ], mask_bits_real, &c );
        n += c;
      }
      dt += fd_log_wallclock();
      FD_LOG_NOTICE(( "%s: mask_bits %u, %.0f hashes/filter, %.1f us/filter, %.2f ns/hash",
                      v ? "ranged" : "full scan", mask_bits_real, (double)n/(double)iter,
                      (double)dt/(double)iter/1e3, (double)dt/(double)n ));
    }
    free( masks );
  }

  free( crds_mem );
  free( purged_mem );
}

/* Cost of keeping the hset up to date: remove+insert pairs on a
   mainnet sized, 80% full hset with random element indices. */

static void
bench_update( fd_rng_t * rng ) {
  ulong ele_max = 524288UL;
  void * mem = aligned_alloc( fd_gossip_hset_align(), fd_gossip_hset_footprint( ele_max ) );
  fd_gossip_hset_t * hset = fd_gossip_hset_join( fd_gossip_hset_new( mem, ele_max ) );
  uchar h[ 32 ];
  ulong live = 4UL*ele_max/5UL;
  for( ulong i=0UL; i<live; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) h[ j ] = fd_rng_uchar( rng );
    fd_gossip_hset_insert( hset, i, h );
  }
  ulong iter = 1UL<<20;
  ulong * idx = malloc( iter*sizeof(ulong) );
  for( ulong i=0UL; i<iter; i++ ) idx[ i ] = fd_rng_ulong_roll( rng, live );
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_gossip_hset_remove( hset, idx[ i ] );
    FD_STORE( ulong, h, fd_rng_ulong( rng ) );
    fd_gossip_hset_insert( hset, idx[ i ], h );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "hset remove+insert: %.1f ns", (double)dt/(double)iter ));
  free( idx );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );

  test_hset_ref( rng, 1UL );
  test_hset_ref( rng, 8UL );
  test_hset_ref( rng, 1024UL );
  test_hset_ref( rng, 16384UL );
  test_push_dups( rng );
  test_entrypoint_fresh( rng );
  test_relay_coalesce( rng );
  if( bench ) { bench_update( rng ); test_tables( rng, 524288UL, 230000UL, 423000UL, 1 ); }
  else        test_tables( rng, 16384UL, 7000UL, 12000UL, 0 );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
