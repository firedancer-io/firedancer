#include "../fd_util.h"

FD_STATIC_ASSERT( FD_CHECKPT_SUCCESS  == 0, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_ERR_INVAL==-1, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_ERR_UNSUP==-2, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_ERR_IO   ==-3, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_ERR_COMP ==-4, unit_test );

FD_STATIC_ASSERT( FD_CHECKPT_FRAME_STYLE_RAW==1, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_FRAME_STYLE_LZ4==2, unit_test );

FD_STATIC_ASSERT( FD_CHECKPT_FRAME_STYLE_DEFAULT==1, unit_test );

FD_STATIC_ASSERT( FD_CHECKPT_WBUF_MIN == 69632UL, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_ALIGN    ==     8UL, unit_test );
FD_STATIC_ASSERT( FD_CHECKPT_FOOTPRINT==196664UL, unit_test );

FD_STATIC_ASSERT( FD_RESTORE_RBUF_MIN == 69632UL, unit_test );
FD_STATIC_ASSERT( FD_RESTORE_ALIGN    ==     8UL, unit_test );
FD_STATIC_ASSERT( FD_RESTORE_FOOTPRINT==196664UL, unit_test );

#define BUF_MAX (1048576UL)
static uchar in  [ BUF_MAX ];
static uchar out [ BUF_MAX ];
static uchar mmio[ BUF_MAX ];

static fd_checkpt_t _checkpt[1];
static fd_restore_t _restore[1];

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( !FD_HAS_LZ4 ) FD_LOG_WARNING(( "target does not have lz4 support; lz4 style frames will not be tested" ));

  ulong data_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-sz", NULL, BUF_MAX );
  ulong mmio_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--mmio-sz", NULL, BUF_MAX );

  FD_LOG_NOTICE(( "Using --data-sz %lu --mmio-sz %lu", data_sz, mmio_sz ));

  if( FD_UNLIKELY( data_sz>BUF_MAX ) ) FD_LOG_ERR(( "--data-sz too large for BUF_MAX" ));
  if( FD_UNLIKELY( mmio_sz>BUF_MAX ) ) FD_LOG_ERR(( "--mmio-sz too large for BUF_MAX" ));

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

  FD_LOG_NOTICE(( "Testing fd_checkpt_strerror" ));

  FD_TEST( !strcmp( fd_checkpt_strerror( FD_CHECKPT_SUCCESS   ), "success"                    ) );
  FD_TEST( !strcmp( fd_checkpt_strerror( FD_CHECKPT_ERR_INVAL ), "bad input args"             ) );
  FD_TEST( !strcmp( fd_checkpt_strerror( FD_CHECKPT_ERR_UNSUP ), "unsupported on this target" ) );
  FD_TEST( !strcmp( fd_checkpt_strerror( FD_CHECKPT_ERR_IO    ), "io error"                   ) );
  FD_TEST( !strcmp( fd_checkpt_strerror( FD_CHECKPT_ERR_COMP  ), "compression error"          ) );
  FD_TEST( !strcmp( fd_checkpt_strerror( 1                    ), "unknown"                    ) );

  FD_LOG_NOTICE(( "Testing fd_checkpt_init_mmio" ));

  FD_TEST( !fd_checkpt_init_mmio( NULL,        mmio, mmio_sz ) ); /* NULL mem */
  FD_TEST( !fd_checkpt_init_mmio( (void *)1UL, mmio, mmio_sz ) ); /* misaligned mem */
  FD_TEST( !fd_checkpt_init_mmio( _checkpt,    NULL, mmio_sz ) ); /* NULL mmio with non-zero sz */
  fd_checkpt_t * checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );

  FD_LOG_NOTICE(( "Testing fd_checkpt_fini" ));

  FD_TEST( !fd_checkpt_fini( NULL ) );                      /* NULL checkpt */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, 0 ) );          /* open default (raw) frame */
  FD_TEST( !fd_checkpt_fini( checkpt ) );                   /* fini (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_frame_open" ));

  FD_TEST(  fd_checkpt_frame_open( NULL, 0 )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );                       /* open raw frame */
  FD_TEST(  fd_checkpt_frame_open( checkpt, style_raw )==FD_CHECKPT_ERR_INVAL ); /* in frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );                      /* fini (failed) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_lz4 ) );  /* open lz4 frame (if target supports, raw if not) */
  FD_TEST( !fd_checkpt_fini( checkpt ) );                   /* fini (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (failed) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_frame_open( checkpt, -1 )==FD_CHECKPT_ERR_UNSUP ); /* unsupported frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );               /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_frame_close" ));

  FD_TEST( fd_checkpt_frame_close( NULL )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_frame_close( checkpt )==FD_CHECKPT_ERR_INVAL ); /* close (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );            /* fini (failed) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_checkpt_frame_close( checkpt ) );            /* close (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_checkpt_buf" ));

  FD_TEST(  fd_checkpt_buf( NULL, in, data_sz )==FD_CHECKPT_ERR_INVAL ); /* NULL checkpt */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, in, 1UL )==FD_CHECKPT_ERR_INVAL ); /* not in frame */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );             /* fini (normal) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, in, 0UL )==FD_CHECKPT_ERR_INVAL ); /* zero sz (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );             /* fini (normal) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST(  fd_checkpt_buf( checkpt, NULL, 0UL )==FD_CHECKPT_ERR_INVAL ); /* NULL with zero sz (not in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );               /* fini (normal) */

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open( checkpt, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_checkpt_buf( checkpt, in,   0UL ) );         /* zero sz */
  FD_TEST( !fd_checkpt_buf( checkpt, NULL, 0UL ) );         /* NULL with zero sz */
  FD_TEST( !fd_checkpt_frame_close( checkpt ) );            /* close (in frame) */
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_restore_init_mmio" ));

  FD_TEST( !fd_restore_init_mmio( NULL,        mmio, mmio_sz ) ); /* NULL mem */
  FD_TEST( !fd_restore_init_mmio( (void *)1UL, mmio, mmio_sz ) ); /* misaligned mem */
  FD_TEST( !fd_restore_init_mmio( _restore,    NULL, mmio_sz ) ); /* NULL mmio with non-zero sz */
  fd_restore_t * restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );

  FD_LOG_NOTICE(( "Testing fd_restore_fini" ));

  FD_TEST( !fd_restore_fini( NULL ) );                      /* NULL restore */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (normal) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, 0 ) );          /* open default (raw) frame */
  FD_TEST( !fd_restore_fini( restore ) );                   /* fini (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_restore_frame_open" ));

  FD_TEST(  fd_restore_frame_open( NULL, 0 )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw )                       ); /* open raw frame */
  FD_TEST(  fd_restore_frame_open( restore, style_raw )==FD_CHECKPT_ERR_INVAL ); /* in frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );                      /* fini (failed) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_lz4 ) );  /* open lz4 frame (if target supports, raw if not) */
  FD_TEST( !fd_restore_fini( restore ) );                   /* fini (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (failed) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_frame_open( restore, -1 )==FD_CHECKPT_ERR_UNSUP ); /* unsupported frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );               /* fini (failed) */

  FD_LOG_NOTICE(( "Testing fd_restore_frame_close" ));

  FD_TEST( fd_restore_frame_close( NULL )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_frame_close( restore )==FD_CHECKPT_ERR_INVAL ); /* close (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );            /* fini (failed) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_restore_frame_close( restore           ) );  /* close (in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore ); /* fini (normal) */

  FD_LOG_NOTICE(( "Testing fd_restore_buf" ));

  FD_TEST(  fd_restore_buf( NULL, in, data_sz )==FD_CHECKPT_ERR_INVAL ); /* NULL restore */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, in, 1UL )==FD_CHECKPT_ERR_INVAL ); /* not in frame */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );             /* fini (normal) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, in, 0UL )==FD_CHECKPT_ERR_INVAL ); /* zero sz (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );             /* fini (normal) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST(  fd_restore_buf( restore, NULL, 0UL )==FD_CHECKPT_ERR_INVAL ); /* NULL with zero sz (not in frame) */
  FD_TEST(  fd_restore_fini( restore )==(void *)_restore );               /* fini (normal) */

  restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
  FD_TEST( !fd_restore_frame_open( restore, style_raw ) );  /* open raw frame */
  FD_TEST( !fd_restore_buf( restore, in,   0UL ) );         /* zero sz */
  FD_TEST( !fd_restore_buf( restore, NULL, 0UL ) );         /* NULL with zero sz */
  FD_TEST( !fd_restore_frame_close( restore ) );            /* close (in frame) */
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

    memset( mmio, 0, mmio_sz );
    memset( out,  0, data_sz );

    checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
    FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
    FD_TEST( !fd_checkpt_buf( checkpt, in, data_sz ) );
    FD_TEST( !fd_checkpt_frame_close_advanced( checkpt, &off_close ) );
    FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

    if( style==style_raw ) {
      FD_TEST( (off_close-off_open)==data_sz );
      FD_TEST( !memcmp( in, mmio, data_sz ) );
    }

    restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    FD_TEST( !fd_restore_buf( restore, out, data_sz ) );
    FD_TEST( !fd_restore_frame_close( restore ) );
    FD_TEST(  fd_restore_fini( restore )==(void *)_restore );

    FD_TEST( !memcmp( in, out, data_sz ) );

    /* checkpt/restore with mixed sized buffers (including zero sized)
       in a single frame */

    rng_seq = fd_rng_seq( rng ); rng_idx = fd_rng_idx( rng ); /* save rng for restore */

    memset( mmio, 0, mmio_sz );

    checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
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

    if( style==style_raw ) {
      FD_TEST( (off_close-off_open)==data_sz );
      FD_TEST( !memcmp( in, mmio, data_sz ) );
    }

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
    FD_TEST( !fd_restore_frame_open( restore, style ) );
    obuf = out;
    rem  = data_sz;
    while( rem ) {
      ulong r      = fd_rng_ulong( rng );
      ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
      ulong buf_sz = fd_ulong_min( rem, r & mask ); /* In [0,128KiB) biased toward small */
      FD_TEST( !fd_restore_buf( restore, obuf, buf_sz ) );
      if( FD_LIKELY( buf_sz ) ) FD_TEST( !memcmp( in+(data_sz-rem), obuf, buf_sz ) ); /* Test immedate avail */
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

    memset( mmio, 0, mmio_sz );

    checkpt  = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
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

    if( style==style_raw ) {
      FD_TEST( (off_close-off_open)==frame_sz );
      FD_TEST( !memcmp( in, mmio, data_sz ) );
    }

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
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

    memset( mmio, 0, mmio_sz );

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

    fd_rng_seq_set( rng, rng_seq ); fd_rng_idx_set( rng, rng_idx ); /* Restore to recreate same checkpt open/buf/close */

    memset( out, 0, data_sz );

    restore = fd_restore_init_mmio( _restore, mmio, mmio_sz ); FD_TEST( restore==_restore );
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
  }

  FD_LOG_NOTICE(( "Testing checkpt too small (raw)" ));

  memset( mmio, 0, mmio_sz );

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style_raw, &off_open ) );
  ulong rem;
  for( rem=mmio_sz; rem>=data_sz; rem-=data_sz ) FD_TEST( !fd_checkpt_buf( checkpt, in, data_sz ) );
  FD_TEST(  fd_checkpt_buf( checkpt, in, rem+1UL )==FD_CHECKPT_ERR_IO );
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

  FD_LOG_NOTICE(( "Testing checkpt too small (lz4)" ));

  memset( mmio, 0, mmio_sz );

  checkpt = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style_lz4, &off_open ) );
  while( !fd_checkpt_buf( checkpt, in, data_sz ) ) /**/;
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

  FD_LOG_NOTICE(( "Testing checkpt too small (mixed)" ));

  memset( mmio, 0, mmio_sz );

  checkpt  = fd_checkpt_init_mmio( _checkpt, mmio, mmio_sz ); FD_TEST( checkpt==_checkpt );
  style    = fd_int_if( !(fd_rng_ulong( rng ) & 1UL), style_raw, style_lz4 );
  FD_TEST( !fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) );
  for(;;) {
    ulong r      = fd_rng_ulong( rng );
    ulong mask   = (1UL << fd_rng_int_roll( rng, 18 )) - 1UL;
    ulong buf_sz = r & mask; r >>= 18; /* In [0,128KiB) biased toward small */
    for( ulong i=0UL; i<11UL; i++ ) { /* Random break up inputs into frames (including empty ones) */
      if( FD_LIKELY( r & 7UL ) ) break;
      r >>= 3;
      if( fd_checkpt_frame_close_advanced( checkpt, &off_close ) ) goto err;
      style = fd_int_if( !(r & 1UL), style_raw, style_lz4 ); r >>= 1;
      if( fd_checkpt_frame_open_advanced( checkpt, style, &off_open ) ) goto err;
    }
    if( fd_checkpt_buf( checkpt, in, buf_sz ) ) goto err;
  }
err:
  FD_TEST(  fd_checkpt_fini( checkpt )==(void *)_checkpt );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
