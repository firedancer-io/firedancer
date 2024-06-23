#include "../fd_util.h"

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Note: macros tested in mmio */

#define BUF_MAX (1048576UL)

static uchar in  [ BUF_MAX ];
static uchar out [ BUF_MAX ];
static uchar mmio[ BUF_MAX ];
static uchar rbuf[ BUF_MAX ];
static uchar wbuf[ BUF_MAX ];

static fd_checkpt_t _checkpt[1];
static fd_restore_t _restore[1];

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( !FD_HAS_LZ4 ) FD_LOG_WARNING(( "target does not have lz4 support; lz4 style frames will not be tested" ));

  char const * path    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--path",    NULL, NULL                );
  char const * _mode   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mode",    NULL, "0600"              );
  int          keep    = fd_env_strip_cmdline_int  ( &argc, &argv, "--keep",    NULL, 0                   );
  ulong        data_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-sz", NULL, BUF_MAX             );
  ulong        mmio_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--mmio-sz", NULL, BUF_MAX             );
  ulong        wbuf_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--wbuf-sz", NULL, FD_CHECKPT_WBUF_MIN );
  ulong        rbuf_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--rbuf-sz", NULL, FD_RESTORE_RBUF_MIN );

  FD_LOG_NOTICE(( "Using --data-sz %lu --wbuf-sz %lu --rbuf-sz %lu", data_sz, wbuf_sz, rbuf_sz ));

  if( FD_UNLIKELY( data_sz>BUF_MAX ) ) FD_LOG_ERR(( "--data-sz too large for BUF_MAX" ));
  if( FD_UNLIKELY( mmio_sz>BUF_MAX ) ) FD_LOG_ERR(( "--mmio-sz too large for BUF_MAX" ));
  if( FD_UNLIKELY( wbuf_sz>BUF_MAX ) ) FD_LOG_ERR(( "--wbuf-sz too large for BUF_MAX" ));
  if( FD_UNLIKELY( rbuf_sz>BUF_MAX ) ) FD_LOG_ERR(( "--rbuf-sz too large for BUF_MAX" ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  int style_raw = FD_CHECKPT_FRAME_STYLE_RAW;
  int style_lz4 = FD_HAS_LZ4 ? FD_CHECKPT_FRAME_STYLE_LZ4 : FD_CHECKPT_FRAME_STYLE_RAW;

  FD_LOG_NOTICE(( "Creating test data" ));

  uchar val = (uchar)(fd_rng_ulong( rng ) & 255UL);
  for( ulong in_idx=0UL; in_idx<data_sz; in_idx++ ) {
    ulong r = fd_rng_ulong( rng );
    val = fd_uchar_if( r & 255UL, val, (uchar)(r>>8) );
    in[ in_idx ] = val;
  }

  FD_LOG_NOTICE(( "Creating test stream" ));

  int fd;

  char tmp_path[] = "/tmp/test_checkpt.XXXXXX";
  if( path ) {

    ulong mode = fd_cstr_to_ulong_octal( _mode );
    FD_LOG_NOTICE(( "Using --path %s (--mode 0%03lo --keep %i)", path, mode, keep ));
    mode_t old_mask = umask( (mode_t)0 );
    fd = open( path, O_CREAT | O_EXCL | O_RDWR, (mode_t)mode );
    umask( old_mask );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open(O_CREATE | O_EXCL | O_RDWR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  } else {

    FD_LOG_NOTICE(( "--path not specified; using tmp file (--mode ignored --keep %i)", keep ));
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

  /* Note: strerror tested in mmio */

# define RESET(fd) do {                                                       \
    if( FD_UNLIKELY( lseek( (fd), (off_t)0, SEEK_SET ) ) )                    \
      FD_LOG_ERR(( "lseek failed (%i-%s)", errno, fd_io_strerror( errno ) )); \
  } while(0)

  FD_LOG_NOTICE(( "Testing fd_checkpt_init_stream" ));

  FD_TEST( !fd_checkpt_init_stream( NULL,        fd, wbuf, wbuf_sz                 ) ); /* NULL mem */
  FD_TEST( !fd_checkpt_init_stream( (void *)1UL, fd, wbuf, wbuf_sz                 ) ); /* misaligned mem */
  FD_TEST( !fd_checkpt_init_stream( _checkpt,    -1, wbuf, wbuf_sz                 ) ); /* bad fd */
  FD_TEST( !fd_checkpt_init_stream( _checkpt,    fd, NULL, wbuf_sz                 ) ); /* NULL wbuf */
  FD_TEST( !fd_checkpt_init_stream( _checkpt,    fd, wbuf, FD_CHECKPT_WBUF_MIN-1UL ) ); /* wbuf_sz too small */

  fd_checkpt_t * checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );

  FD_LOG_NOTICE(( "Testing fd_checkpt_fini" ));

  FD_TEST( !fd_checkpt_fini( NULL ) );                      /* NULL checkpt */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, 0 ) );          /* open default (raw) frame */
  FD_TEST( !fd_checkpt_fini( checkpt ) );                   /* fini (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_frame_open" ));

  FD_TEST(  fd_checkpt_frame_open( NULL, 0 )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );                       /* open raw frame */
  FD_TEST(  fd_checkpt_frame_open( checkpt, style_raw )==FD_CHECKPT_ERR_INVAL ); /* in frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );                      /* fini (failed) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_lz4 ) );  /* open lz4 frame (if target supports, raw if not) */
  FD_TEST( !fd_checkpt_fini( checkpt ) );                   /* fini (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (failed) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_frame_open( checkpt, -1 )==FD_CHECKPT_ERR_UNSUP ); /* unsupported frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );               /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_frame_close" ));

  FD_TEST( fd_checkpt_frame_close( NULL )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_frame_close( checkpt )==FD_CHECKPT_ERR_INVAL ); /* close (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );            /* fini (failed) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_checkpt_frame_close( checkpt ) );            /* close (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_buf" ));

  FD_TEST(  fd_checkpt_buf( NULL, in, data_sz )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, in, 1UL )==FD_CHECKPT_ERR_INVAL ); /* not in frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );             /* fini (normal) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, in, 0UL )==FD_CHECKPT_ERR_INVAL ); /* zero sz (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );             /* fini (normal) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, NULL, 0UL )==FD_CHECKPT_ERR_INVAL ); /* NULL with zero sz (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );               /* fini (normal) */

  RESET( fd );
  checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_checkpt_buf( checkpt, in,   0UL ) );         /* zero sz */
  FD_TEST( !fd_checkpt_buf( checkpt, NULL, 0UL ) );         /* NULL with zero sz */
  FD_TEST( !fd_checkpt_frame_close( checkpt ) );            /* close (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_restore_init_stream" ));

  FD_TEST( !fd_restore_init_stream( NULL,        fd, rbuf, rbuf_sz                 ) ); /* NULL mem */
  FD_TEST( !fd_restore_init_stream( (void *)1UL, fd, rbuf, rbuf_sz                 ) ); /* misaligned mem */
  FD_TEST( !fd_restore_init_stream( _restore,    -1, rbuf, rbuf_sz                 ) ); /* bad fd */
  FD_TEST( !fd_restore_init_stream( _restore,    fd, NULL, rbuf_sz                 ) ); /* NULL rbuf */
  FD_TEST( !fd_restore_init_stream( _restore,    fd, rbuf, FD_RESTORE_RBUF_MIN-1UL ) ); /* too small rbuf */
  fd_restore_t * restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );

  FD_LOG_NOTICE(( "Testing fd_restore_fini" ));

  FD_TEST( !fd_restore_fini( NULL ) );                      /* NULL restore */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (normal) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, 0 ) );          /* open default (raw) frame */
  FD_TEST( !fd_restore_fini( restore ) );                   /* fini (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_restore_frame_open" ));

  FD_TEST(  fd_restore_frame_open( NULL, 0 )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw )                       ); /* open raw frame */
  FD_TEST(  fd_restore_frame_open( restore, style_raw )==FD_CHECKPT_ERR_INVAL ); /* in frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );                      /* fini (failed) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_lz4 ) );  /* open lz4 frame (if target supports, raw if not) */
  FD_TEST( !fd_restore_fini( restore ) );                   /* fini (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (failed) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_frame_open( restore, -1 )==FD_CHECKPT_ERR_UNSUP ); /* unsupported frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );               /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_restore_frame_close" ));

  FD_TEST( fd_restore_frame_close( NULL )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_frame_close( restore )==FD_CHECKPT_ERR_INVAL ); /* close (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );            /* fini (failed) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_restore_frame_close( restore           ) );  /* close (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_restore_buf" ));

  FD_TEST(  fd_restore_buf( NULL, in, data_sz )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, in, 1UL )==FD_CHECKPT_ERR_INVAL ); /* not in frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );             /* fini (normal) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, in, 0UL )==FD_CHECKPT_ERR_INVAL ); /* zero sz (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );             /* fini (normal) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, NULL, 0UL )==FD_CHECKPT_ERR_INVAL ); /* NULL with zero sz (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );               /* fini (normal) */

  RESET( fd );
  restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_restore_buf( restore, in,   0UL ) );         /* zero sz */
  FD_TEST( !fd_restore_buf( restore, NULL, 0UL ) );         /* NULL with zero sz */
  FD_TEST( !fd_restore_frame_close( restore ) );            /* open raw frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing end-to-end" ));

  ulong off_open;
  ulong off_close;
  int   style;

  for( ulong iter=0UL; iter<1000UL; iter++ ) {
    style = fd_int_if( !(iter & 1UL), style_raw, style_lz4 );

    uchar const * ibuf;
    uchar       * obuf;
    ulong         rem;
    uint          rng_seq;
    ulong         rng_idx;
    ulong         frame_sz;

    /* checkpt/restore a single buffer in a single frame */

    RESET( fd );
    checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    FD_TEST( !fd_checkpt_buf( checkpt, in, data_sz ) );
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    if( style==style_raw ) FD_TEST( (off_close-off_open)==data_sz );

    memset( out, 0, data_sz );
    RESET( fd );
    restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    FD_TEST( !fd_restore_buf( restore, out, data_sz ) );
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt/restore with mixed sized buffers (including zero sized)
       in a single frame */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    RESET( fd );
    checkpt = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    ibuf = in;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); /* In [0,128KiB) biased toward small */
      FD_TEST( !fd_checkpt_buf( checkpt, ibuf, buf_sz ) );
      ibuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    if( style==style_raw ) FD_TEST( (off_close-off_open)==data_sz );

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );
    RESET( fd );
    restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); /* In [0,128KiB) biased toward small */
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      obuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt/restore with mixed sized buffers (including 0 sized)
       distributed over multiple homegeneous frames (including empty
       frames) */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    memset( out, 0, data_sz );

    RESET( fd );
    checkpt  = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
    frame_sz = 0UL;
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    ibuf     = in;
    rem      = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
        if( style==style_raw ) FD_TEST( (off_close-off_open)==frame_sz );
        frame_sz = 0UL;
        FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
      }
      FD_TEST( !fd_checkpt_buf( checkpt, ibuf, buf_sz ) );
      ibuf     += buf_sz;
      rem      -= buf_sz;
      frame_sz += buf_sz;
    }
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    if( style==style_raw ) FD_TEST( (off_close-off_open)==frame_sz );

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    RESET( fd );
    restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_restore_frame_close( restore ) );
        FD_TEST( !fd_restore_frame_open( restore, style ) );
      }
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      if( FD_LIKELY( buf_sz ) ) FD_TEST( !memcmp( in+(data_sz-rem), obuf, buf_sz ) ); /* Test immedate avail */
      obuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt/restore with mixed sized buffers (including 0 sized)
       distributed over multiple mixed style frames (including empty
       frames) */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    RESET( fd );
    checkpt  = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
    style    = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    frame_sz = 0UL;
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    ibuf     = in;
    rem      = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
        if( style==style_raw ) FD_TEST( (off_close-off_open)==frame_sz );
        /* FIXME: consider comparing frame bytes when raw? */
        style    = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        frame_sz = 0UL;
        FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
      }
      FD_TEST( !fd_checkpt_buf( checkpt, ibuf, buf_sz ) );
      ibuf     += buf_sz;
      rem      -= buf_sz;
      frame_sz += buf_sz;
    }
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    RESET( fd );
    restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
    style   = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_restore_frame_close( restore ) );
        style = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        FD_TEST( !fd_restore_frame_open( restore, style ) );
      }
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      if( FD_LIKELY( buf_sz ) ) FD_TEST( !memcmp( in+(data_sz-rem), obuf, buf_sz ) ); /* Test immedate avail */
      obuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt(mmio)/restore(stream) with mixed sized buffers (including
       0 sized) distributed over multiple mixed style frames (including
       empty frames) */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    memset( out, 0, mmio_sz );

    checkpt  = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
    style    = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    frame_sz = 0UL;
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    ibuf     = in;
    rem      = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
        if( style==style_raw ) FD_TEST( (off_close-off_open)==frame_sz );
        /* FIXME: consider comparing frame bytes when raw? */
        style    = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        frame_sz = 0UL;
        FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
      }
      FD_TEST( !fd_checkpt_buf( checkpt, ibuf, buf_sz ) );
      ibuf     += buf_sz;
      rem      -= buf_sz;
      frame_sz += buf_sz;
    }
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    RESET( fd );
    ulong wsz;
    FD_TEST( !fd_io_write( fd, mmio, mmio_sz, mmio_sz, &wsz ) );

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    RESET( fd );
    restore = fd_restore_init_stream( _restore, fd, rbuf, rbuf_sz ); FD_TEST( restore==_restore );
    style   = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_restore_frame_close( restore ) );
        style = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        FD_TEST( !fd_restore_frame_open( restore, style ) );
      }
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      if( FD_LIKELY( buf_sz ) ) FD_TEST( !memcmp( in+(data_sz-rem), obuf, buf_sz ) ); /* Test immedate avail */
      obuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt(stream)/restore(mmio) with mixed sized buffers (including
       0 sized) distributed over multiple mixed style frames (including
       empty frames) */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    RESET( fd );
    checkpt  = fd_checkpt_init_stream( _checkpt, fd, wbuf, wbuf_sz ); FD_TEST( checkpt==_checkpt );
    style    = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    frame_sz = 0UL;
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    ibuf     = in;
    rem      = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
        if( style==style_raw ) FD_TEST( (off_close-off_open)==frame_sz );
        /* FIXME: consider comparing frame bytes when raw? */
        style    = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        frame_sz = 0UL;
        FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
      }
      FD_TEST( !fd_checkpt_buf( checkpt, ibuf, buf_sz ) );
      ibuf     += buf_sz;
      rem      -= buf_sz;
      frame_sz += buf_sz;
    }
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    RESET( fd );
    ulong rsz;
    FD_TEST( !fd_io_read( fd, mmio, 1UL, mmio_sz, &rsz ) );

    restore = fd_restore_init_mmio( _restore, mmio, rsz ); FD_TEST( restore==_restore );
    style   = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); r >>= 18; /* In [0,128KiB) biased toward small */
      for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
        if( FD_LIKELY( r & 7UL ) ) break;
        r >>= 3;
        FD_TEST( !fd_restore_frame_close( restore ) );
        style = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
        FD_TEST( !fd_restore_frame_open( restore, style ) );
      }
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      if( FD_LIKELY( buf_sz ) ) FD_TEST( !memcmp( in+(data_sz-rem), obuf, buf_sz ) ); /* Test immedate avail */
      obuf += buf_sz;
      rem  -= buf_sz;
    }
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* Note: mmio/mmio tested in test_checkpt_mmio */
  }

# undef RESET

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
