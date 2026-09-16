#define _GNU_SOURCE
#include "fd_collector_overrides.h"
#include "../runtime/fd_bank.h"

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

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

  int spill_fd = memfd_create( "collector_overrides_spill", 0 );
  FD_TEST( spill_fd>=0 );
  FD_TEST( dup2( spill_fd, FD_COLLECTOR_OVERRIDES_FD )==FD_COLLECTOR_OVERRIDES_FD );
  FD_TEST( !close( spill_fd ) );

  static uchar mem[ 1UL<<20 ] __attribute__((aligned(FD_COLLECTOR_OVERRIDES_ALIGN)));
  ulong max_overrides = 1024UL;
  FD_TEST( fd_collector_overrides_footprint( 6000UL )<2UL*1024UL*1024UL );
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

  /* Two boundary forks capture: identical state is retained in each fork; divergent
     state stays isolated. */
  ushort f1 = fd_collector_overrides_new_child( co );
  ushort f2 = fd_collector_overrides_new_child( co );
  FD_TEST( f1!=root && f2!=root && f1!=f2 );

  /* Both forks inherit the epoch-100 entries as their "t_2". */
  fd_collector_overrides_inherit( co, root, f1, 100UL );
  fd_collector_overrides_inherit( co, root, f2, 100UL );
  FD_TEST( fd_collector_overrides_query( co, f1, 100UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, f2, 100UL, &vote_a, NULL, NULL ) );

  /* Fresh captures at epoch 101: same content is stored in each fork set... */
  fd_collector_overrides_upsert( co, f1, 101UL, &vote_a, 1, &coll_1, 0, NULL );
  fd_collector_overrides_upsert( co, f2, 101UL, &vote_a, 1, &coll_1, 0, NULL );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==8UL );

  /* A third populated fork must spill beyond the two resident sets. */
  struct stat spill_stat;
  FD_TEST( !fstat( FD_COLLECTOR_OVERRIDES_FD, &spill_stat ) );
  FD_TEST( spill_stat.st_size>0 );

  /* ...while divergent content does not. */
  fd_collector_overrides_upsert( co, f1, 101UL, &vote_b, 1, &coll_1, 0, NULL );
  fd_collector_overrides_upsert( co, f2, 101UL, &vote_b, 1, &coll_2, 0, NULL );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==10UL );

  flags = fd_collector_overrides_query( co, f1, 101UL, &vote_b, &out_infl, NULL );
  FD_TEST( flags==FD_COLLECTOR_OVERRIDE_INFLATION && !memcmp( &out_infl, &coll_1, sizeof(fd_pubkey_t) ) );
  flags = fd_collector_overrides_query( co, f2, 101UL, &vote_b, &out_infl, NULL );
  FD_TEST( flags==FD_COLLECTOR_OVERRIDE_INFLATION && !memcmp( &out_infl, &coll_2, sizeof(fd_pubkey_t) ) );

  /* Purging a spilled fork preserves the other fork's entries. */
  fd_collector_overrides_purge_child( co, f2 );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==6UL );
  FD_TEST( fd_collector_overrides_query( co, f1, 101UL, &vote_a, NULL, NULL ) );

  /* Advancing the root to f1 drops everything only the old root saw
     ... but the inherited epoch-100 entries survive in f1's set. */
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
  FD_TEST( fd_collector_overrides_ele_cnt( co )==2UL ); /* 101: vote_a and vote_b from f1 */

  /* Fork id reuse must not resurrect stale visibility. */
  ushort f4 = fd_collector_overrides_new_child( co );
  FD_TEST( !fd_collector_overrides_query( co, f4, 101UL, &vote_a, NULL, NULL ) );

  /* Repeatedly reload eight divergent sets, including dirty updates
     after a reload, then inherit from a spilled parent. */
  fd_collector_overrides_reset( co );
  FD_TEST( !ftruncate( FD_COLLECTOR_OVERRIDES_FD, 0L ) );
  root = fd_collector_overrides_get_root_idx( co );
  ushort forks[8];
  for( ulong i=0UL; i<8UL; i++ ) {
    forks[i] = fd_collector_overrides_new_child( co );
    fd_pubkey_t collector = key( (uchar)(i+1UL) );
    fd_collector_overrides_upsert( co, forks[i], 200UL, &vote_a, 1, &collector, 1, &coll_2 );
    if( i==1UL ) {
      FD_TEST( !fstat( FD_COLLECTOR_OVERRIDES_FD, &spill_stat ) );
      FD_TEST( !spill_stat.st_size ); /* Two sets need no disk. */
    }
  }
  for( ulong pass=0UL; pass<3UL; pass++ ) {
    for( ulong i=0UL; i<8UL; i++ ) {
      fd_pubkey_t collector = key( (uchar)(i+1UL) );
      flags = fd_collector_overrides_query( co, forks[i], 200UL, &vote_a, &out_infl, &out_block );
      FD_TEST( flags==(FD_COLLECTOR_OVERRIDE_INFLATION|FD_COLLECTOR_OVERRIDE_BLOCK) );
      FD_TEST( fd_pubkey_eq( &out_infl, &collector ) && fd_pubkey_eq( &out_block, &coll_2 ) );
      fd_collector_overrides_upsert( co, forks[i], 201UL, &vote_b, 0, NULL, 1, &collector );
      out_infl = coll_2;
      FD_TEST( fd_collector_overrides_query( co, forks[i], 201UL, &vote_b, &out_infl, &out_block )==FD_COLLECTOR_OVERRIDE_BLOCK );
      FD_TEST( fd_pubkey_eq( &out_block, &collector ) && fd_pubkey_eq( &out_infl, &coll_2 ) );
    }
  }
  FD_TEST( fd_collector_overrides_ele_cnt( co )==16UL );
  ushort inherited = fd_collector_overrides_new_child( co );
  fd_collector_overrides_inherit( co, forks[0], inherited, 201UL );
  FD_TEST( !fd_collector_overrides_query( co, inherited, 200UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, inherited, 201UL, &vote_b, NULL, &out_block )==FD_COLLECTOR_OVERRIDE_BLOCK );
  fd_pubkey_t expected = key( 1U );
  FD_TEST( fd_pubkey_eq( &out_block, &expected ) );

  /* Purge a spilled set, reuse its id, then force the replacement to
     spill too. Old file contents must never become visible again. */
  fd_collector_overrides_purge_child( co, forks[3] );
  ushort reused = fd_collector_overrides_new_child( co );
  FD_TEST( reused==forks[3] );
  FD_TEST( !fd_collector_overrides_query( co, reused, 200UL, &vote_a, NULL, NULL ) );
  fd_collector_overrides_upsert( co, reused, 202UL, &vote_b, 1, &coll_2, 0, NULL );
  FD_TEST( fd_collector_overrides_query( co, forks[6], 200UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, forks[7], 200UL, &vote_a, NULL, NULL ) );
  FD_TEST( fd_collector_overrides_query( co, reused, 202UL, &vote_b, &out_infl, NULL )==FD_COLLECTOR_OVERRIDE_INFLATION );
  FD_TEST( fd_pubkey_eq( &out_infl, &coll_2 ) );
  FD_TEST( !fd_collector_overrides_query( co, reused, 200UL, &vote_a, NULL, NULL ) );
  fd_collector_overrides_advance_root( co, forks[0] );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==2UL );
  FD_TEST( fd_collector_overrides_query( co, forks[0], 200UL, &vote_a, &out_infl, NULL ) );
  FD_TEST( fd_pubkey_eq( &out_infl, &expected ) );

  /* Reset invalidates spilled images as well as resident ones. */
  fd_collector_overrides_reset( co );
  for( ulong i=0UL; i<8UL; i++ ) {
    ushort fresh = fd_collector_overrides_new_child( co );
    FD_TEST( !fd_collector_overrides_query( co, fresh, 200UL, &vote_a, NULL, NULL ) );
    FD_TEST( !fd_collector_overrides_query( co, fresh, 201UL, &vote_b, NULL, NULL ) );
  }

  /* The collector override store must support the full bank fork
     width, including the root plus FD_BANKS_MAX_BANKS children. */
  fd_collector_overrides_reset( co );
  ushort max_fork = 0U;
  for( ulong i=0UL; i<FD_BANKS_MAX_BANKS; i++ ) {
    max_fork = fd_collector_overrides_new_child( co );
  }
  FD_TEST( max_fork==(ushort)FD_BANKS_MAX_BANKS );

  fd_collector_overrides_upsert( co, max_fork, 102UL, &vote_a, 1, &coll_1, 0, NULL );
  FD_TEST(  fd_collector_overrides_query( co, max_fork, 102UL, &vote_a, &out_infl, NULL )==FD_COLLECTOR_OVERRIDE_INFLATION );
  FD_TEST( !fd_collector_overrides_query( co, root,     102UL, &vote_a, NULL,      NULL ) );

  fd_collector_overrides_purge_child( co, max_fork );
  FD_TEST( fd_collector_overrides_new_child( co )==max_fork );
  FD_TEST( !fd_collector_overrides_query( co, max_fork, 102UL, &vote_a, NULL, NULL ) );

  /* Reset drops everything. */
  fd_collector_overrides_reset( co );
  FD_TEST( fd_collector_overrides_ele_cnt( co )==0UL );
  root = fd_collector_overrides_get_root_idx( co );
  FD_TEST( !fd_collector_overrides_query( co, root, 100UL, &vote_a, NULL, NULL ) );

  FD_TEST( !close( FD_COLLECTOR_OVERRIDES_FD ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
