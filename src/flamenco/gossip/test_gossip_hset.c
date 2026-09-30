#include "../../util/fd_util.h"
#include "fd_gossip_hset.h"
#include "fd_gossip_purged.h"
#include "fd_crds.h"
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
  fd_crds_insert( crds, value, bytes, 128UL, 1UL, 0, 0, now, stem );
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

  fd_gossip_out_ctx_t out[1] = {{0}};
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
  if( bench ) { bench_update( rng ); test_tables( rng, 524288UL, 230000UL, 423000UL, 1 ); }
  else        test_tables( rng, 16384UL, 7000UL, 12000UL, 0 );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
