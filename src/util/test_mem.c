#include "fd_util.h"

#define BUF_SZ (32768UL+64UL)

static uchar src[ BUF_SZ ] __attribute__((aligned(64)));
static uchar ref[ BUF_SZ ] __attribute__((aligned(64)));
static uchar dst[ BUF_SZ ] __attribute__((aligned(64)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static ulong const sizes[] = {
       0UL,    1UL,    2UL,    3UL,    4UL,    5UL,    7UL,    8UL,
       9UL,   15UL,   16UL,   17UL,   31UL,   32UL,   33UL,   63UL,
      64UL,   65UL,   95UL,   96UL,   97UL,  127UL,  128UL,  129UL,
     159UL,  160UL,  161UL,  175UL,  176UL,  177UL,  191UL,  192UL,
     193UL,  255UL,  256UL,  257UL,  383UL,  384UL,  511UL,  512UL,
     767UL,  768UL, 1023UL, 1024UL, 1025UL, 2047UL, 2048UL, 4095UL,
    4096UL, 4097UL, 8191UL, 8192UL, 16384UL, 32768UL
  };

  for( ulong i=0UL; i<BUF_SZ; i++ ) src[ i ] = (uchar)(i*17UL + (i>>8));

  for( ulong size_idx=0UL; size_idx<sizeof(sizes)/sizeof(sizes[0]); size_idx++ ) {
    ulong sz = FD_VOLATILE_CONST( sizes[ size_idx ] );

    for( ulong dst_off=0UL; dst_off<64UL; dst_off++ ) {
      int c = (int)(uchar)(size_idx*13UL + dst_off);

      memset( ref, 0xa5, BUF_SZ );
      memset( dst, 0xa5, BUF_SZ );
      memset( ref+dst_off, c, sz );
      FD_TEST( fd_memset( dst+dst_off, c, sz )==dst+dst_off );
      FD_TEST( !memcmp( dst, ref, BUF_SZ ) );

      ulong src_off = (dst_off*29UL + size_idx*7UL) & 63UL;
      memset( ref, 0xa5, BUF_SZ );
      memset( dst, 0xa5, BUF_SZ );
      memcpy( ref+dst_off, src+src_off, sz );
      FD_TEST( fd_memcpy( dst+dst_off, src+src_off, sz )==dst+dst_off );
      FD_TEST( !memcmp( dst, ref, BUF_SZ ) );
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
