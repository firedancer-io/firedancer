#include "fd_footer_cache.h"

static void
test_memo( void ) {
  static fd_footer_cache_memo_t memo[1];
  static uchar                  data[ FD_FOOTER_CACHE_MEMO_DATA_MAX+1UL ];
  uchar pk[ 32 ], ow[ 32 ];
  for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)i;
  fd_memset( pk, 1, 32UL );
  fd_memset( ow, 2, 32UL );
  ulong la = 42UL;
  ulong dl = FD_FOOTER_CACHE_MEMO_DATA_MAX;

  /* empty: never hits */
  FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la, 0, data, dl ) );

  /* kept: hits only on the exact image; executable is a flag */
  FD_TEST( fd_footer_cache_memo_insert( memo, pk, ow, la, 1, data, dl ) );
  fd_lthash_value_t const * h = fd_footer_cache_memo_query( memo, pk, ow, la, 2, data, dl );
  FD_TEST( h==&memo->lthash );
  FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la+1UL, 1, data, dl     ) );
  FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la,     0, data, dl     ) );
  FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la,     1, data, dl-1UL ) );
  pk[ 31 ] ^= 1; FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la, 1, data, dl ) ); pk[ 31 ] ^= 1;
  ow[ 31 ] ^= 1; FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la, 1, data, dl ) ); ow[ 31 ] ^= 1;
  data[ dl-1UL ] ^= 1; FD_TEST( !fd_footer_cache_memo_query( memo, pk, ow, la, 1, data, dl ) ); data[ dl-1UL ] ^= 1;

  /* zero lamports and oversized data empty the memo */
  FD_TEST( !fd_footer_cache_memo_insert( memo, pk, ow, 0UL, 1, data, dl ) );
  FD_TEST( !memo->lamports && !fd_footer_cache_memo_query( memo, pk, ow, la, 1, data, dl ) );
  FD_TEST(  fd_footer_cache_memo_insert( memo, pk, ow, la,  1, data, dl ) );
  FD_TEST( !fd_footer_cache_memo_insert( memo, pk, ow, la,  1, data, dl+1UL ) );
  FD_TEST( !memo->lamports && !fd_footer_cache_memo_query( memo, pk, ow, la, 1, data, dl ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_memo();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
