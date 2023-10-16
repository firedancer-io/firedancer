#include "fd_compact_u16.h"

/* Test up to slightly larger than can fit in a u16 */
#define TEST_U16_MAX    (0x10201UL)
#define TEST_U16_BUF_SZ (4UL)
uchar compact_u16[TEST_U16_MAX][TEST_U16_BUF_SZ];
uchar found[TEST_U16_MAX];
uchar encoded_sz[TEST_U16_MAX];


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Since writing the encoding function from ushort -> (compact_u16, encoded
     size) is relatively simple, we test the decoding function,
     fd_cu16_dec, by ensuring it is (excluding the byte patterns it
     rejects) exactly the inverse of the encoding function.  The real trouble
     is that fd_cu16_dec may be fed arguments outside its proper domain,
     which it must reject.  By checking that it is injective and surjective
     onto the proper domain, we also ensure that it rejects everything outside
     its domain. */

  for( ulong i = 0; i < TEST_U16_MAX; i++ )
    encoded_sz[ i ] = (uchar) fd_cu16_enc((ushort)i, compact_u16[ i ]);

  for( ulong test_j = 0UL; test_j<=TEST_U16_BUF_SZ; test_j++ ) {
    ulong max = 1UL << (8*test_j);
    for( ulong i = 0UL; i < max; i++ ) {
      if( (test_j==TEST_U16_BUF_SZ) & !(i&0xFFFFFFF) ) FD_LOG_NOTICE(( "fd_cu16_dec progress: %3lu/256", i>>24UL ));
      uchar * buf = (uchar *)&i;
      ushort result = (ushort)0xFFFF;
      ulong consumed = fd_cu16_dec( buf, test_j, &result );
      if( consumed!=0 ) FD_TEST( consumed==encoded_sz[ result ] );
      if( consumed!=0 && consumed==test_j ) {
        /* Injective (one-to-one): No byte pattern (other than an a
           suffix that decoding ignores gives this u16 value. */
        FD_TEST( !found[ result ] );
        FD_TEST( !memcmp( buf, compact_u16[ result ], 4) );
        found[ result ] = 1;
      }
    }
  }
  /* Surjective (onto): We've hit exactly the integers we expect. */
  for( ulong i = 0UL;          i <=  USHORT_MAX; i++ )    FD_TEST(  found[ i ] );
  for( ulong i = USHORT_MAX+1; i < TEST_U16_MAX; i++ )    FD_TEST( !found[ i ] );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

