#define _GNU_SOURCE
#include "fd_compress.h"
#include "../fd_util.h"

/* test_decompress tests whether basic BZip2 and Zstandard decompression
   works.  Also checks various edge cases. */


/* Buffer */

static uchar buf[ 1024UL ];
static ulong buf_sz = 0UL;

static int FD_FN_UNUSED
decomp_callback( void *        arg,
                 uchar const * data,
                 ulong         sz ) {
  FD_TEST( arg==NULL );
  FD_TEST( buf_sz + sz < sizeof(buf) );

  fd_memcpy( buf+buf_sz, data, sz );
  buf_sz += sz;
  return 0;
}


/* Test vectors */

static uchar const test_zstd_comp[] FD_FN_UNUSED =  /* zstd("AAAA") */
  { 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x29, 0x00,
    0x00, 0x41, 0x41, 0x41, 0x41, 0x0a, 0x59, 0x0d,
    0xba, 0xfd };

static uchar const test_bzip2_comp[] FD_FN_UNUSED =  /* bzip2("AAAA") */
  { 0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26,
    0x53, 0x59, 0x31, 0x70, 0xdc, 0x53, 0x00, 0x00,
    0x02, 0xc4, 0x00, 0x40, 0x10, 0x20, 0x00, 0x20,
    0x00, 0x21, 0x98, 0x19, 0x84, 0x3b, 0x0b, 0xb9,
    0x22, 0x9c, 0x28, 0x48, 0x18, 0xb8, 0x6e, 0x29,
    0x80 };


/* Fake file I/O helpers */

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

static int FD_FN_UNUSED
create_memfd( void const * buf,
              ulong        bufsz ) {
  buf_sz = 0UL;  /* Reset output stream */

  int fd = memfd_create( "compressed", 0U );
  if( FD_UNLIKELY( fd<0 ) )
    FD_LOG_ERR(( "memfd_create failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  long n = write( fd, buf, bufsz );
  if( FD_UNLIKELY( n!=(long)bufsz ) )
    FD_LOG_ERR(( "write failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  FD_TEST( 0==lseek( fd, 0L, SEEK_SET ) );

  return fd;
}


/* Test program */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int fd; (void)fd;

# if FD_HAS_BZ2

  /* Normal */
  fd = create_memfd( test_bzip2_comp, sizeof(test_bzip2_comp) );
  FD_TEST( 0==fd_decompress_bz2( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Empty stream */
  fd = create_memfd( NULL, 0UL );
  FD_TEST( EPROTO==fd_decompress_bz2( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Incomplete stream */
  fd = create_memfd( test_bzip2_comp, sizeof(test_bzip2_comp)-1UL );
  FD_TEST( EPROTO==fd_decompress_bz2( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Trailing bytes */
  fd = create_memfd( test_bzip2_comp, sizeof(test_bzip2_comp) );
  FD_TEST( 0< lseek( fd, 0L, SEEK_END ) );
  FD_TEST( 4==write( fd, "AAAA", 4 ) );
  FD_TEST( 0==lseek( fd, 0L, SEEK_SET ) );
  FD_TEST( 0==fd_decompress_bz2( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

# endif /* FD_HAS_BZ2 */

# if FD_HAS_ZSTD

  /* Normal */
  fd = create_memfd( test_zstd_comp, sizeof(test_zstd_comp) );
  FD_TEST( 0==fd_decompress_zstd( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Empty stream */
  fd = create_memfd( NULL, 0UL );
  FD_TEST( EPROTO==fd_decompress_zstd( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Incomplete stream */
  fd = create_memfd( test_zstd_comp, sizeof(test_zstd_comp)-1UL );
  FD_TEST( EPROTO==fd_decompress_zstd( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

  /* Trailing bytes */
  fd = create_memfd( test_zstd_comp, sizeof(test_zstd_comp) );
  FD_TEST( 0< lseek( fd, 0L, SEEK_END ) );
  FD_TEST( 4==write( fd, "AAAA", 4 ) );
  FD_TEST( 0==lseek( fd, 0L, SEEK_SET ) );
  FD_TEST( EPROTO==fd_decompress_zstd( fd, decomp_callback, NULL ) );
  FD_TEST( 0==close( fd ) );

# endif /* FD_HAS_ZSTD */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
