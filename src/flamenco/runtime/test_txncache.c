#include "fd_txncache.h"

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/fd_util.h"
#include "fd_txncache_shmem.h"

FD_STATIC_ASSERT( FD_TXNCACHE_ALIGN==128UL, unit_test );

#define BLOCKHASH( x ) __extension__({         \
  uchar * _out = fd_alloca_check( 1UL, 32UL ); \
  fd_memset( _out, 0, 32UL );                  \
  (void)FD_STORE( ulong, _out, (x) );          \
  _out;                                        \
})

#define TXNHASH( x ) __extension__({           \
  uchar * _out = fd_alloca_check( 1UL, 32UL ); \
  fd_memset( _out, 0, 32UL );                  \
  (void)FD_STORE( ulong, _out, (x) );          \
  _out;                                        \
})

#define NULL_FORK ((fd_txncache_fork_id_t){ .val = USHORT_MAX })

void
test0( uchar * scratch0,
       uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST 0" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t root = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, root, 0UL, BLOCKHASH(1UL) );

  fd_txncache_fork_id_t slot1 = fd_txncache_attach_child( tc, root );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(1UL) );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(5UL) );
  fd_txncache_insert( tc, slot1, BLOCKHASH(1UL), TXNHASH(9UL) );
  fd_txncache_finalize_fork( tc, slot1, 0UL, BLOCKHASH(3UL) );

  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(1UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(2UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(3UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(4UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(5UL) ) );
  FD_TEST( !fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(6UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot1, BLOCKHASH(1UL), TXNHASH(9UL) ) );
}

void
test_new_join( uchar * scratch0 ) {
  FD_LOG_NOTICE(( "TEST NEW" ));

  FD_TEST( fd_txncache_shmem_new( NULL, 1UL, 1UL )==NULL );          /* null shmem         */
  FD_TEST( fd_txncache_shmem_new( (void *)0x1UL, 1UL, 1UL )==NULL ); /* misaligned shmem   */
  FD_TEST( fd_txncache_shmem_new( scratch0, 0UL, 1UL )==NULL );  /* 0 max_live_slots */
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 0UL )==NULL );  /* 0 max_txn_per_slot */

  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 2UL, 2UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 4096UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ) ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, fd_ulong_pow2_up( FD_MAX_TXN_PER_SLOT ) ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 512UL, 1UL ) );
  FD_TEST( fd_txncache_shmem_new( scratch0, 1UL, 1UL ) );

  FD_LOG_NOTICE(( "TEST JOIN" ));

  FD_TEST( fd_txncache_join( NULL )==NULL );          /* null shtc       */
  FD_TEST( fd_txncache_join( (void *)0x1UL )==NULL ); /* misaligned shtc */
  FD_TEST( fd_txncache_join( scratch0 ) );
}

void
test_advance_root( uchar * scratch0,
                   uchar * scratch1 ) {
  FD_LOG_NOTICE(( "TEST ADVANCE ROOT" ));

  fd_txncache_shmem_t * shtc = fd_txncache_shmem_join( fd_txncache_shmem_new( scratch0, 4UL, 4UL ) );
  FD_TEST( shtc );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( scratch1, shtc ) );
  FD_TEST( tc );

  fd_txncache_fork_id_t slot = fd_txncache_attach_child( tc, NULL_FORK );
  fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(0UL) );

  for( ulong i=0UL; i<8192UL; i++ ) {
    slot = fd_txncache_attach_child( tc, slot );
    fd_txncache_insert( tc, slot, BLOCKHASH(i), TXNHASH(i) );
    fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(i+1UL) );
    fd_txncache_advance_root( tc, slot );
  }

  FD_TEST( !fd_txncache_query( tc, slot, BLOCKHASH(8191UL), TXNHASH(8190UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8191UL), TXNHASH(8191UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8190UL), TXNHASH(8190UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8160UL), TXNHASH(8160UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8150UL), TXNHASH(8150UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8042UL), TXNHASH(8042UL) ) );
  FD_TEST(  fd_txncache_query( tc, slot, BLOCKHASH(8041UL), TXNHASH(8041UL) ) );

  slot = fd_txncache_attach_child( tc, slot );
  fd_txncache_finalize_fork( tc, slot, 0UL, BLOCKHASH(8193UL) );
  fd_txncache_advance_root( tc, slot );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max_footprint_shmem = fd_txncache_shmem_footprint( 4096UL, FD_MAX_TXN_PER_SLOT );
  ulong max_footprint_local = fd_txncache_footprint( FD_MAX_TXN_PER_SLOT );

  ulong max_footprint = fd_ulong_align_up( max_footprint_shmem, 4096UL ) + max_footprint_local;
  uchar * scratch0 = fd_shmem_acquire( 4096UL, 1UL+(max_footprint/4096UL), 0UL );
  FD_TEST( scratch0 );

  uchar * scratch1 = scratch0+fd_ulong_align_up( max_footprint_shmem, 4096UL );

  test0( scratch0, scratch1 );
  test_new_join( scratch0 );
  test_advance_root( scratch0, scratch1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
