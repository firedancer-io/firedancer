#include "../fd_util.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * path  = fd_env_strip_cmdline_cstr( &argc, &argv, "--path", NULL, NULL   );
  char const * _mode = fd_env_strip_cmdline_cstr( &argc, &argv, "--mode", NULL, "0600" );
  int          keep  = fd_env_strip_cmdline_int ( &argc, &argv, "--keep", NULL, 0      );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Create the temp file used for io test */

  int fd;

  char tmp_path[] = "/tmp/test_io.XXXXXX";
  if( path ) {

    ulong mode = fd_cstr_to_ulong_octal( _mode );
    FD_LOG_NOTICE(( "Using --path %s (--mode 0%03lo --keep %i)", path, mode, keep ));
    mode_t old_mask = umask( (mode_t)0 );
    fd = open( path, O_CREAT | O_EXCL | O_RDWR, (mode_t)mode );
    umask( old_mask );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open(O_CREATE | O_EXCL | O_RDWR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  } else {

    FD_LOG_NOTICE(( "--path not specified; using tmp file (--mode ignored, --keep %i)", keep ));
    fd = mkstemp( tmp_path );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "mkstemp(\"%s\")failed (%i-%s)", tmp_path, errno, fd_io_strerror( errno ) ));
    path = tmp_path;
    FD_LOG_NOTICE(( "tmp file at %s", path ));

  }

  /* If keep is not set, we unlink the created file so it gets
     automagically cleaned up at program termination (normal or not).
     That is, as per usual UNIX semantics, the underlying file will
     still exist it has any open file descriptors. */

  if( FD_UNLIKELY( !keep && unlink( path ) ) )
    FD_LOG_ERR(( "unlink( \"%s\" ) failed (%i-%s)", path,  errno, fd_io_strerror( errno ) ));

  /* Write a bunch of test data to the file */

  char const * src     = "The quick brown fox jumps over the lazy dog.\n";
  ulong        src_len = strlen( src );

  ulong wsz;

  /* Test simple write */

  FD_TEST( !fd_io_write( fd, src, src_len, src_len, &wsz ) && wsz==src_len     );

  /* Test compoound write */

  FD_TEST( !fd_io_write( fd, src,     3UL,         3UL,         &wsz ) && wsz==3UL         );
  FD_TEST( !fd_io_write( fd, src+3UL, src_len-3UL, src_len-3UL, &wsz ) && wsz==src_len-3UL );

  /* Test buffered write constructor and accessors (deliberately uses a
     massively undersized buffer to get good edge case coverage) */

# define LG_WBUF_SZ (2)
# define WBUF_SZ    (1UL<<LG_WBUF_SZ)
  uchar wbuf[WBUF_SZ];

  fd_io_buffered_ostream_t out[1];

  FD_TEST( fd_io_buffered_ostream_init( out, fd, wbuf, WBUF_SZ )==out );

  FD_TEST( fd_io_buffered_ostream_fd     ( out )==fd           );
  FD_TEST( fd_io_buffered_ostream_wbuf   ( out )==(void *)wbuf );
  FD_TEST( fd_io_buffered_ostream_wbuf_sz( out )==WBUF_SZ      );

  /* Test basic buffered writes */

  for( ulong iter=0UL; iter<30UL; iter++ ) {
    char const * p   = src;
    ulong        rem = src_len;
    while( rem ) {
      uint  r        = fd_rng_uint( rng );
      ulong sz       = fd_ulong_min( (ulong)(r & 15U), rem ); r >>= 4;
      int   do_flush = !(r & 15U);                            r >>= 4;

      if( FD_UNLIKELY( do_flush ) ) FD_TEST( !fd_io_buffered_ostream_flush( out ) );

      FD_TEST( !fd_io_buffered_ostream_write( out, p, sz ) );

      p   += sz;
      rem -= sz;
    }
  }

  /* Test zero-copy buffered writes */

  for( ulong iter=0UL; iter<32UL; iter++ ) {
    char const * p   = src;
    ulong        rem = src_len;
    while( rem ) {
      uint  r   = fd_rng_uint( rng );
      ulong max = (ulong)(r & (uint)(WBUF_SZ-1UL)); r >>= LG_WBUF_SZ; max += (r & 1UL); r >>= 1; /* In [0,WBUF_SZ] */
      ulong sz  = (ulong)(r & (uint)(WBUF_SZ-1UL)); r >>= LG_WBUF_SZ; sz  += (r & 1UL); r >>= 1; /* In [0,WBUF_SZ] */
      fd_swap_if( sz>max, sz, max ); /* 0<=sz<=max */
      sz = fd_ulong_min( sz, rem );  /* sz<=rem too */

      ulong peek_sz = fd_io_buffered_ostream_peek_sz( out ); FD_TEST( peek_sz<=WBUF_SZ );
      if( FD_UNLIKELY( peek_sz<max ) ) {
        FD_TEST( !fd_io_buffered_ostream_flush( out ) );
        FD_TEST( fd_io_buffered_ostream_peek_sz( out )==WBUF_SZ );
      }

      char * peek = fd_io_buffered_ostream_peek( out ); FD_TEST( peek );
      fd_memcpy( peek, p, sz );
      fd_io_buffered_ostream_seek( out, sz );

      p   += sz;
      rem -= sz;
    }
  }

  /* Test buffered write destructor */

  FD_TEST( !fd_io_buffered_ostream_flush( out ) ); /* Do final flush */
  fd_io_buffered_ostream_fini( out );

  /* At this point, we've written src to the file 64 times.  Test
     reading it back in various ways. */

  char  dst[ 64UL ];
  ulong dst_max = 64UL; FD_TEST( dst_max >= src_len );
  ulong rsz;
  ulong off;

# define REWIND \
  if( FD_UNLIKELY( lseek( fd, (off_t)0, SEEK_SET )==-1 ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, fd_io_strerror( errno ) ))

  /* Test simple read */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ )
    FD_TEST( !fd_io_read( fd, dst, src_len, src_len, &rsz ) && rsz==src_len && !memcmp( src, dst, src_len ) );
  FD_TEST( fd_io_read( fd, dst, 1UL, dst_max, &rsz )<0 && rsz==0UL ); /* Test EOF */

  /* Test static compound read */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    off = 1UL+fd_rng_ulong_roll( rng, src_len-1UL ); /* In [1,src_len-1] */
    FD_TEST( !fd_io_read( fd, dst,     off,         off,         &rsz ) && rsz==off                                           );
    FD_TEST( !fd_io_read( fd, dst+off, src_len-off, src_len-off, &rsz ) && rsz==(src_len-off) && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_read( fd, dst, 1UL, dst_max, &rsz )<0 && rsz==0UL ); /* Test EOF */

  /* Test dynamic compound read */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    FD_TEST( !fd_io_read( fd, dst,     1UL,         src_len-1UL, &off ) && ((1UL<=off) & (off<=(src_len-1UL)))                );
    FD_TEST( !fd_io_read( fd, dst+off, src_len-off, src_len-off, &rsz ) && rsz==(src_len-off) && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_read( fd, dst, 1UL, dst_max, &rsz )<0 && rsz==0UL ); /* Test EOF */

  /* Test dynamic incremental read */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    off = 0UL;
    while( off<src_len ) {
      FD_TEST( !fd_io_read( fd, dst+off, 1UL, src_len-off, &rsz ) && ((1UL<=rsz) & (rsz<=src_len-off)) );
      off += rsz;
    }
    FD_TEST( off==src_len && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_read( fd, dst, 1UL, dst_max, &rsz )<0 && rsz==0UL ); /* Test EOF */

  /* Test non-blocking dynamic incremental read */
  /* TODO: Set nonblocking IO on fd here */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    off = 0UL;
    while( off<src_len ) {
      int err = fd_io_read( fd, dst+off, 0UL, src_len-off, &rsz );
      if( FD_LIKELY( !err ) ) FD_TEST( (!err) & ((1UL<=rsz) & (rsz<=src_len-off)) );
      else                    FD_TEST( (err==EAGAIN) & (!rsz) );
      off += rsz;
    }
    FD_TEST( off==src_len && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_read( fd, dst, 1UL, dst_max, &rsz )<0 && rsz==0UL ); /* Test EOF */

  /* Test buffered read constructor and accessors (deliberately uses a
     massively undersized buffer to get good edge case coverage) */

# define LG_RBUF_SZ (2)
# define RBUF_SZ    (1UL<<LG_RBUF_SZ)
  uchar rbuf[RBUF_SZ];

  fd_io_buffered_istream_t in[1];
  FD_TEST( fd_io_buffered_istream_init( in, fd, rbuf, RBUF_SZ )==in );

  FD_TEST( fd_io_buffered_istream_fd     ( in )==fd           );
  FD_TEST( fd_io_buffered_istream_rbuf   ( in )==(void *)rbuf );
  FD_TEST( fd_io_buffered_istream_rbuf_sz( in )==RBUF_SZ      );

  /* Test basic buffered reads */

  REWIND;
  FD_TEST( !fd_io_buffered_istream_fetch( in ) );
  FD_TEST( !fd_io_buffered_istream_fetch( in ) );
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    off = 0UL;
    while( off<src_len ) {
      uint  r        = fd_rng_uint( rng );
      ulong sz       = fd_ulong_min( (ulong)(r & 15U), src_len-off ); r >>= 4;
      int   do_fetch = !(r & 15U);                                    r >>= 4;

      if( FD_UNLIKELY( do_fetch ) ) FD_TEST( !fd_io_buffered_istream_fetch( in ) );

      FD_TEST( !fd_io_buffered_istream_read( in, dst+off, sz ) );

      off += sz;
    }
    FD_TEST( off==src_len && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_buffered_istream_read( in, dst, dst_max )<0 ); /* Test EOF */

  /* Test zero-copy buffered reads */

  REWIND;
  for( ulong iter=0UL; iter<64UL; iter++ ) {
    off = 0UL;
    while( off<src_len ) {
      uint  r   = fd_rng_uint( rng );
      ulong max = (ulong)(r & (uint)(RBUF_SZ-1UL)); r >>= LG_RBUF_SZ; max += (r & 1UL); r >>= 1; /* In [0,RBUF_SZ] */
      ulong sz  = (ulong)(r & (uint)(RBUF_SZ-1UL)); r >>= LG_RBUF_SZ; sz  += (r & 1UL); r >>= 1; /* In [0,RBUF_SZ] */
      fd_swap_if( sz>max, sz, max );
      max = fd_ulong_min( max, src_len-off );
      sz  = fd_ulong_min( sz,  max         ); /* 0<=sz<=max<=min(rem,RBUF_SZ) */

      ulong peek_sz = fd_io_buffered_istream_peek_sz( in ); FD_TEST( peek_sz<=RBUF_SZ );
      if( FD_UNLIKELY( peek_sz<max ) ) {
        FD_TEST( !fd_io_buffered_istream_fetch( in ) );
        peek_sz = fd_io_buffered_istream_peek_sz( in );
        FD_TEST( (max<=peek_sz) & (peek_sz<=RBUF_SZ) );
      }

      char const * peek = fd_io_buffered_istream_peek( in ); FD_TEST( peek );
      fd_memcpy( dst+off, peek, sz );
      fd_io_buffered_istream_seek( in, sz );

      off += sz;
    }
    FD_TEST( off==src_len && !memcmp( src, dst, src_len ) );
  }
  FD_TEST( fd_io_buffered_istream_read( in, dst, dst_max )<0 ); /* Test EOF */

  fd_io_buffered_istream_fini( in );

  /* Test skip */

  REWIND;
  ulong skip_rem = 64UL*src_len;
  while( skip_rem ) {
    uint  r       = fd_rng_uint( rng );
    ulong skip_sz = fd_ulong_min( (ulong)(r & 15U), skip_rem ); r >>= 4;
    FD_TEST( !fd_io_buffered_istream_skip( in, skip_sz ) );
    skip_rem -= skip_sz;
  }
  FD_TEST( fd_io_buffered_istream_read( in, dst, dst_max )<0 ); /* Test EOF */

# undef REWIND

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

  FD_TEST( fd_io_write( -1, src, src_len, src_len, &wsz )==EBADF );
  FD_TEST( fd_io_write( fd, src, src_len, src_len, &wsz )==EBADF );

  FD_TEST( fd_io_read ( -1, dst, src_len, src_len, &rsz )==EBADF );
  FD_TEST( fd_io_read ( fd, dst, src_len, src_len, &rsz )==EBADF );

  FD_LOG_NOTICE(( "fd_io_strerror(    -1 ) \"%s\"", fd_io_strerror(    -1 ) ));
  FD_LOG_NOTICE(( "fd_io_strerror(     0 ) \"%s\"", fd_io_strerror(     0 ) ));
  FD_LOG_NOTICE(( "fd_io_strerror( EBADF ) \"%s\"", fd_io_strerror( EBADF ) ));

  wsz = 42UL;
  FD_TEST( fd_io_write( -1, NULL, 0UL, 0UL, &wsz )==0 );
  FD_TEST( wsz==0UL );
  wsz = 42UL;
  FD_TEST( fd_io_write( fd, NULL, 0UL, 0UL, &wsz )==0 );
  FD_TEST( wsz==0UL );

  rsz = 42UL;
  FD_TEST( fd_io_read( -1, NULL, 0UL, 0UL, &rsz )==0 );
  FD_TEST( wsz==0UL );
  rsz = 42UL;
  FD_TEST( fd_io_read( fd, NULL, 0UL, 0UL, &rsz )==0 );
  FD_TEST( wsz==0UL );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
