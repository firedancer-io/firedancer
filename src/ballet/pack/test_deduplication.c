#define FD_UNALIGNED_ACCESS_STYLE 0
#include "../fd_ballet.h"
#include "fd_pack.h"
#include "fd_compute_budget_program.h"
#include "../txn/fd_txn.h"
#include "../../util/simd/fd_avx.h"

FD_IMPORT_BINARY( sample_vote,  "src/ballet/pack/sample_vote.bin"          );
FD_IMPORT_BINARY( transaction1, "src/ballet/txn/fixtures/transaction1.bin" );
FD_IMPORT_BINARY( transaction2, "src/ballet/txn/fixtures/transaction2.bin" );
FD_IMPORT_BINARY( transaction3, "src/ballet/txn/fixtures/transaction3.bin" );

#define SORT_NAME   sort_pubkeys
#define SORT_KEY_T  fd_acct_addr_t
#define SORT_BEFORE(_a,_b) (memcmp( (_a).b, (_b).b, FD_TXN_ACCT_ADDR_SZ )>0)
#include "../../util/tmpl/fd_sort.c"

uchar _txn[ FD_TXN_MAX_SZ ];

fd_acct_addr_t scratch1[ FD_TXN_ACCT_ADDR_MAX ] __attribute__((aligned(32)));
fd_acct_addr_t scratch2[ FD_TXN_ACCT_ADDR_MAX ] __attribute__((aligned(32)));

int
check_sort( uchar const * payload,
            ulong sz ) {
  FD_TEST( fd_txn_parse( payload, sz, _txn, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)_txn;
  ulong acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  memcpy( scratch1, fd_txn_get_acct_addrs( txn, payload ), acct_cnt*FD_TXN_ACCT_ADDR_SZ );

  fd_acct_addr_t * sorted = sort_pubkeys_stable_fast( scratch1, acct_cnt, scratch2 );
  for( ulong i=1UL; i<acct_cnt; i++ ) {
    if( !memcmp( sorted[i-1UL].b, sorted[i].b, FD_TXN_ACCT_ADDR_SZ ) ) return 0;
  }
  return 1;
}

static const fd_acct_addr_t null_addr = {{ 1, 0 }};

struct fd_pack_private_addr_use_record {
  fd_acct_addr_t key; /* account address */
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;

#define MAP_NAME              hash_pubkeys
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, null_addr)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#define MAP_LG_SLOT_CNT       8
#include "../../util/tmpl/fd_map.c"

struct wrap_ul {
  ulong key;
};
typedef struct wrap_ul wrap_ul_t;

#define MAP_NAME              hash_ul
#define MAP_T                 wrap_ul_t
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_MEMOIZE           0
#define MAP_LG_SLOT_CNT       8
#include "../../util/tmpl/fd_map.c"

uchar _map[ sizeof(fd_pack_addr_use_t)*(1UL<<9) ] __attribute__((aligned(32)));

int
check_hash( uchar const * payload,
            ulong sz ) {
  FD_TEST( fd_txn_parse( payload, sz, _txn, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)_txn;
  ulong acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( txn, payload );
  fd_pack_addr_use_t * map = hash_pubkeys_join( _map );

  int retval = 1;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    if( FD_UNLIKELY( hash_pubkeys_query( map, addrs[i], NULL ) ) ) { retval = 0; break; }
    hash_pubkeys_insert( map, addrs[i] );
  }
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    hash_pubkeys_remove( map, hash_pubkeys_query( map, addrs[i], NULL ) );
  }
  return retval;
}

int
dummy( uchar const * payload,
            ulong sz ) {
  FD_TEST( fd_txn_parse( payload, sz, _txn, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)_txn;
  ulong acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( txn, payload );

  uchar d;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    FD_VOLATILE( d ) = addrs[i].b[0];
  }
  return 1;
}

int
check_hash64( uchar const * payload,
              ulong sz ) {
  FD_TEST( fd_txn_parse( payload, sz, _txn, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)_txn;
  ulong acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( txn, payload );

  wrap_ul_t * map = hash_ul_join( _map );

  int retval = 1;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    ulong key = fd_ulong_load_8( addrs[i].b+7 )+1UL;
    if( FD_UNLIKELY( hash_ul_query( map, key, NULL ) ) ) { retval = 0; break; }
    hash_ul_insert( map, key );
  }
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    ulong key = fd_ulong_load_8( addrs[i].b+7 )+1UL;
    hash_ul_remove( map, hash_ul_query( map, key, NULL ) );
  }
  return retval;
}

int
check_avx( uchar const * payload,
           ulong sz ) {
  FD_TEST( fd_txn_parse( payload, sz, _txn, NULL ) );
  fd_txn_t * txn = (fd_txn_t*)_txn;
  ulong acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );

  fd_acct_addr_t const * addrs = fd_txn_get_acct_addrs( txn, payload );

  wu_t bv8  = wu_zero();
  wu_t bv9  = wu_zero();
  wu_t bv14 = wu_zero();
  wu_t bv17 = wu_zero();
  wu_t bv21 = wu_zero();
  wu_t bv26 = wu_zero();
  wu_t bv28 = wu_zero();
  wu_t bv31 = wu_zero();

  wu_t shift_mask = wu( 0, 32U, 64U, 96U, 128U, 160U, 192U, 224U );

#define CHECK_AND_UPDATE( n ) (__extension__({ wu_t byte = wu_bcast( addr[ n ] ); \
                                               wu_t subtr = wu_sub( byte, shift_mask ); \
                                               wu_t bitmask = wu_shl_vector( wu_one(), subtr ); \
                                               wu_t intersection = wu_and( bitmask, bv##n ); \
                                               bv##n = wu_or( bv##n, bitmask ); \
                                               wu_eq( intersection, wu_zero() ); }));

  for( ulong i=0UL; i<acct_cnt; i++ ) {
    uchar const * addr = addrs[i].b;
    wu_t sum;
    wu_t c8  = CHECK_AND_UPDATE( 8  );
    wu_t c9  = CHECK_AND_UPDATE( 9  ); sum = wu_add(  c8,  c9 );
    wu_t c14 = CHECK_AND_UPDATE( 14 ); sum = wu_add( sum, c14 );
    wu_t c17 = CHECK_AND_UPDATE( 17 ); sum = wu_add( sum, c17 );
    wu_t c21 = CHECK_AND_UPDATE( 21 ); sum = wu_add( sum, c21 );
    wu_t c26 = CHECK_AND_UPDATE( 26 ); sum = wu_add( sum, c26 );
    wu_t c28 = CHECK_AND_UPDATE( 28 ); sum = wu_add( sum, c28 );
    wu_t c31 = CHECK_AND_UPDATE( 31 ); sum = wu_add( sum, c31 );

    sum = wu_sum_all( sum );
    if( FD_UNLIKELY( wu_extract( sum, 0 ) == (uint)(-24) ) ) return 0;
  }
  return 1;
}


int
main( int argc,
    char ** argv ) {
  fd_boot( &argc, &argv );


  int sum = 0;
  long dummyt = -fd_log_wallclock( );
  for( ulong i=0UL; i<1000000UL; i++ ) {
    int r0 = dummy( sample_vote,  sample_vote_sz  );
    int r1 = dummy( transaction1, transaction1_sz );
    int r2 = dummy( transaction2, transaction2_sz );
    int r3 = dummy( transaction3, transaction3_sz );

    FD_COMPILER_FORGET( r0 );
    FD_COMPILER_FORGET( r1 );
    FD_COMPILER_FORGET( r2 );
    FD_COMPILER_FORGET( r3 );
    FD_VOLATILE( sum ) = r0+r1+r2+r3;
  }
  dummyt += fd_log_wallclock( );
  FD_LOG_NOTICE(( "%f ns mean per validation empty", (double)(dummyt)/4000000.0 ));

  long start = fd_log_wallclock( );
  for( ulong i=0UL; i<1000000UL; i++ ) {
    int r0 = check_sort( sample_vote, sample_vote_sz );
    int r1 = check_sort( transaction1, transaction1_sz );
    int r2 = check_sort( transaction2, transaction2_sz );
    int r3 = check_sort( transaction3, transaction3_sz );

    FD_COMPILER_FORGET( r0 );
    FD_COMPILER_FORGET( r1 );
    FD_COMPILER_FORGET( r2 );
    FD_COMPILER_FORGET( r3 );
    FD_VOLATILE( sum ) = r0+r1+r2+r3;
  }
  long end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "%f ns mean per validation sort (overhead excluded)", (double)(end-start-dummyt)/4000000.0 ));


  hash_pubkeys_new( _map );

  sum = 0;
  start = fd_log_wallclock( );
  for( ulong i=0UL; i<1000000UL; i++ ) {
    int r0 = check_hash( sample_vote, sample_vote_sz );
    int r1 = check_hash( transaction1, transaction1_sz );
    int r2 = check_hash( transaction2, transaction2_sz );
    int r3 = check_hash( transaction3, transaction3_sz );

    FD_COMPILER_FORGET( r0 );
    FD_COMPILER_FORGET( r1 );
    FD_COMPILER_FORGET( r2 );
    FD_COMPILER_FORGET( r3 );
    FD_VOLATILE( sum ) = r0+r1+r2+r3;
  }
  end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "%f ns mean per validation hash (overhead excluded)", (double)(end-start-dummyt)/4000000.0 ));

  hash_pubkeys_delete( _map );


  sum = 0;
  start = fd_log_wallclock( );
  for( ulong i=0UL; i<1000000UL; i++ ) {
    int r0 = check_avx( sample_vote, sample_vote_sz );
    int r1 = check_avx( transaction1, transaction1_sz );
    int r2 = check_avx( transaction2, transaction2_sz );
    int r3 = check_avx( transaction3, transaction3_sz );

    FD_COMPILER_FORGET( r0 );
    FD_COMPILER_FORGET( r1 );
    FD_COMPILER_FORGET( r2 );
    FD_COMPILER_FORGET( r3 );
    FD_VOLATILE( sum ) = r0+r1+r2+r3;
  }
  end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "%f ns mean per validation avx (overhead excluded)", (double)(end-start-dummyt)/4000000.0 ));

  hash_ul_new( _map );

  sum = 0;
  start = fd_log_wallclock( );
  for( ulong i=0UL; i<1000000UL; i++ ) {
    int r0 = check_hash64( sample_vote, sample_vote_sz );
    int r1 = check_hash64( transaction1, transaction1_sz );
    int r2 = check_hash64( transaction2, transaction2_sz );
    int r3 = check_hash64( transaction3, transaction3_sz );

    FD_COMPILER_FORGET( r0 );
    FD_COMPILER_FORGET( r1 );
    FD_COMPILER_FORGET( r2 );
    FD_COMPILER_FORGET( r3 );
    FD_VOLATILE( sum ) = r0+r1+r2+r3;
  }
  end = fd_log_wallclock( );
  FD_LOG_NOTICE(( "%f ns mean per validation hash64 (overhead excluded)", (double)(end-start-dummyt)/4000000.0 ));

  hash_ul_delete( _map );

  fd_halt();
  return 0;
}
