#include "fd_collector_overrides.h"

static fd_pubkey_t
key( uchar b ) {
  fd_pubkey_t k;
  fd_memset( k.uc, b, sizeof(fd_pubkey_t) );
  return k;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar mem[ 1UL<<20 ] __attribute__((aligned(FD_COLLECTOR_OVERRIDES_ALIGN)));
  ulong max_overrides = 1024UL;
  FD_TEST( fd_collector_overrides_footprint( max_overrides )<=sizeof(mem) );

  fd_collector_overrides_t * co = fd_collector_overrides_join( fd_collector_overrides_new( mem, max_overrides, 42UL ) );
  FD_TEST( co );

  ushort root = fd_collector_overrides_get_root_idx( co );

  fd_pubkey_t vote_a  = key( 0xaa );
  fd_pubkey_t vote_b  = key( 0xbb );
  fd_pubkey_t coll_1  = key( 0x11 );
  fd_pubkey_t coll_2  = key( 0x22 );
  fd_pubkey_t out_infl;
  fd_pubkey_t out_block;

  /* Empty: everything is default. */
  FD_TEST( !fd_collector_overrides_query( co, root, 100UL, &vote_a, &out_infl, &out_block ) );

  /* Upsert both collectors for vote_a at epoch 100 on the root. */
  fd_collector_overrides_upsert( co, root, 100UL, &vote_a, 1, &coll_1, 1, &coll_2 );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==1UL );

  int flags = fd_collector_overrides_query( co, root, 100UL, &vote_a, &out_infl, &out_block );
  FD_TEST( flags==(FD_COLLECTOR_OVERRIDE_INFLATION|FD_COLLECTOR_OVERRIDE_BLOCK) );
  FD_TEST( !memcmp( &out_infl, &coll_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &out_block, &coll_2, sizeof(fd_pubkey_t) ) );

  /* Wrong epoch or unknown pubkey: default. */
  FD_TEST( !fd_collector_overrides_query( co, root, 99UL, &vote_a, NULL, NULL ) );
  FD_TEST( !fd_collector_overrides_query( co, root, 100UL, &vote_b, NULL, NULL ) );

  /* Inflation-only override. */
  fd_collector_overrides_upsert( co, root, 100UL, &vote_b, 1, &coll_1, 0, NULL );
  flags = fd_collector_overrides_query( co, root, 100UL, &vote_b, &out_infl, NULL );
  FD_TEST( flags==FD_COLLECTOR_OVERRIDE_INFLATION );
  FD_TEST( !memcmp( &out_infl, &coll_1, sizeof(fd_pubkey_t) ) );

  /* Two boundary forks capture: identical state dedups, divergent
     state gets separate entries. */
  ushort f1 = fd_collector_overrides_new_child( co );
  ushort f2 = fd_collector_overrides_new_child( co );
  FD_TEST( f1!=root && f2!=root && f1!=f2 );

  /* Both forks inherit the epoch-100 entries as their "t_2". */
  fd_collector_overrides_inherit( co, root, f1, 100UL );
  fd_collector_overrides_inherit( co, root, f2, 100UL );
  FD_TEST( fd_collector_overrides_query( co, f1, 100UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, f2, 100UL, &vote_a, NULL, NULL ) );

  /* Fresh captures at epoch 101: same content on both forks shares an
     entry... */
  fd_collector_overrides_upsert( co, f1, 101UL, &vote_a, 1, &coll_1, 0, NULL );
  fd_collector_overrides_upsert( co, f2, 101UL, &vote_a, 1, &coll_1, 0, NULL );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==3UL );

  /* ...while divergent content does not. */
  fd_collector_overrides_upsert( co, f1, 101UL, &vote_b, 1, &coll_1, 0, NULL );
  fd_collector_overrides_upsert( co, f2, 101UL, &vote_b, 1, &coll_2, 0, NULL );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==5UL );

  flags = fd_collector_overrides_query( co, f1, 101UL, &vote_b, &out_infl, NULL );
  FD_TEST( flags==FD_COLLECTOR_OVERRIDE_INFLATION && !memcmp( &out_infl, &coll_1, sizeof(fd_pubkey_t) ) );
  flags = fd_collector_overrides_query( co, f2, 101UL, &vote_b, &out_infl, NULL );
  FD_TEST( flags==FD_COLLECTOR_OVERRIDE_INFLATION && !memcmp( &out_infl, &coll_2, sizeof(fd_pubkey_t) ) );

  /* Purging f2 keeps shared entries alive for f1 and frees
     f2-only entries. */
  fd_collector_overrides_purge_child( co, f2 );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==4UL );
  FD_TEST( fd_collector_overrides_query( co, f1, 101UL, &vote_a, NULL, NULL ) );

  /* Advancing the root to f1 drops everything only the old root saw
     ... but the inherited epoch-100 entries survive via f1's bit. */
  fd_collector_overrides_advance_root( co, f1 );
  FD_TEST( fd_collector_overrides_get_root_idx( co )==f1 );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==4UL );
  FD_TEST( fd_collector_overrides_query( co, f1, 100UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, f1, 101UL, &vote_a, NULL, NULL ) );

  /* Next boundary: child of f1 at epoch 102 with min_epoch 101 sheds
     the epoch-100 entries. */
  ushort f3 = fd_collector_overrides_new_child( co );
  fd_collector_overrides_inherit( co, f1, f3, 101UL );
  FD_TEST( !fd_collector_overrides_query( co, f3, 100UL, &vote_a, NULL, NULL ) );
  FD_TEST(  fd_collector_overrides_query( co, f3, 101UL, &vote_a, NULL, NULL ) );

  fd_collector_overrides_advance_root( co, f3 );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==2UL ); /* 101: vote_a shared, vote_b(f1 content) */

  /* Fork id reuse must not resurrect stale visibility. */
  ushort f4 = fd_collector_overrides_new_child( co );
  FD_TEST( !fd_collector_overrides_query( co, f4, 101UL, &vote_a, NULL, NULL ) );

  /* Reset drops everything. */
  fd_collector_overrides_reset( co );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==0UL );
  root = fd_collector_overrides_get_root_idx( co );
  FD_TEST( !fd_collector_overrides_query( co, root, 100UL, &vote_a, NULL, NULL ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
