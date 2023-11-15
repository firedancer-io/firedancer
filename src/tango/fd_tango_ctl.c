#include "fd_tango.h"
#include "mcache/fd_mcache_private.h"
#include "dcache/fd_dcache_private.h"

#if FD_HAS_HOSTED

#include <stdio.h>

FD_IMPORT_CSTR( fd_tango_ctl_help, "src/tango/fd_tango_ctl_help" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  /* FIXME: CACHE ATTACHMENTS? */

  ulong tag = 1UL;

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fputs( fd_tango_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "tag" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      tag = fd_cstr_to_ulong( argv[0] );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, tag ));
      SHIFT(1);

    } else if( !strcmp( cmd, "new-mcache" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp  =                   argv[0];
      ulong        depth  = fd_cstr_to_ulong( argv[1] );
      ulong        app_sz = fd_cstr_to_ulong( argv[2] );
      ulong        seq0   = fd_cstr_to_ulong( argv[3] );

      ulong align     = fd_mcache_align();
      ulong footprint = fd_mcache_footprint( depth, app_sz );
      if( FD_UNLIKELY( !footprint ) )
        FD_LOG_ERR(( "%i: %s: depth (%lu) must a power-of-2 and at least %lu and depth and app_sz (%lu) must result in a "
                     "footprint smaller than 2^64.\n\tDo %s help for help", cnt, cmd, depth, FD_MCACHE_BLOCK, app_sz, bin ));

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shmcache = fd_mcache_new( shmem, depth, app_sz, seq0 );
      if( FD_UNLIKELY( !shmcache ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_mcache_new( %s:%lu, %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, depth, app_sz, seq0, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu %lu: success", cnt, cmd, _wksp, depth, app_sz, seq0 ));
      SHIFT( 4 );

    } else if( !strcmp( cmd, "delete-mcache" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shmcache = argv[0];

      void * shmcache = fd_wksp_map( _shmcache );
      if( FD_UNLIKELY( !shmcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));
      if( FD_UNLIKELY( !fd_mcache_delete( shmcache ) ) )
        FD_LOG_ERR(( "%i: %s: fd_mcache_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));
      fd_wksp_unmap( shmcache );

      fd_wksp_cstr_free( _shmcache );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shmcache ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "query-mcache" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shmcache =                 argv[0];
      int          verbose   = fd_cstr_to_int( argv[1] );

      void * shmcache = fd_wksp_map( _shmcache );
      if( FD_UNLIKELY( !shmcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));

      fd_frag_meta_t const * mcache = fd_mcache_join( shmcache );
      if( FD_UNLIKELY( !mcache ) )
        FD_LOG_ERR(( "%i: %s: fd_mcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));

      fd_mcache_private_hdr_t const * hdr = fd_mcache_private_hdr_const( mcache );
      if( !verbose ) printf( "%lu\n", *hdr->seq );
      else {
        printf( "mcache %s\n", _shmcache );
        printf( "\tdepth   %lu\n", hdr->depth  );
        printf( "\tapp-sz  %lu\n", hdr->app_sz );
        printf( "\tseq0    %lu\n", hdr->seq0   );

        ulong seq_cnt;
        for( seq_cnt=FD_MCACHE_SEQ_CNT; seq_cnt; seq_cnt-- ) if( hdr->seq[seq_cnt-1UL] ) break;
        printf( "\tseq[ 0] %lu\n", *hdr->seq );
        for( ulong idx=1UL; idx<seq_cnt; idx++ ) printf( "\tseq[%2lu] %lu\n", idx, hdr->seq[idx] );
        if( seq_cnt<FD_MCACHE_SEQ_CNT ) printf( "\t        ... snip (all remaining are zero) ...\n" );

        if( hdr->app_sz ) {
          uchar const * a = fd_mcache_app_laddr_const( mcache );
          ulong app_sz;
          for( app_sz=hdr->app_sz; app_sz; app_sz-- ) if( a[app_sz-1UL] ) break;
          ulong         off = 0UL;
          printf( "\tapp     %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                  (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                  (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
          for( off+=16UL, a+=16UL; off<app_sz; off+=16UL, a+=16UL )
            printf( "\t        %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                    (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                    (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
          if( off<hdr->app_sz ) printf( "\t        ... snip (all remaining are zero) ...\n" );
        }
      }

      fd_wksp_unmap( fd_mcache_leave( mcache ) );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, _shmcache, verbose ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "new-dcache" ) ) {

      if( FD_UNLIKELY( argc<6 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp   =                   argv[0];
      ulong        mtu     = fd_cstr_to_ulong( argv[1] );
      ulong        depth   = fd_cstr_to_ulong( argv[2] );
      ulong        burst   = fd_cstr_to_ulong( argv[3] );
      int          compact = fd_cstr_to_int  ( argv[4] );
      ulong        app_sz  = fd_cstr_to_ulong( argv[5] );

      ulong data_sz = fd_dcache_req_data_sz( mtu, depth, burst, compact );
      if( FD_UNLIKELY( !data_sz ) ) {
        FD_LOG_ERR(( "%i: %s: mtu (%lu), depth (%lu), burst (%lu) all must be positive and mtu, depth, burst and compact (%i) "
                     "must result in a data_sz smaller than 2^64.\n\tDo %s help for help",
                     cnt, cmd, mtu, depth, burst, compact, bin ));
      }

      ulong align     = fd_dcache_align();
      ulong footprint = fd_dcache_footprint( data_sz, app_sz );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: mtu (%lu), depth (%lu), burst (%lu), compact (%i) and app_sz (%lu) must result in a footprint "
                     "smaller than 2^64.\n\tDo %s help for help", cnt, cmd, mtu, depth, burst, compact, app_sz, bin ));
      }

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shdcache = fd_dcache_new( shmem, data_sz, app_sz );
      if( FD_UNLIKELY( !shdcache ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_dcache_new( %s:%lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, data_sz, app_sz, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu %lu %i %lu: success", cnt, cmd, _wksp, mtu, depth, burst, compact, app_sz ));
      SHIFT( 6 );

    } else if( !strcmp( cmd, "new-dcache-raw" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp   =                   argv[0];
      ulong        data_sz = fd_cstr_to_ulong( argv[1] );
      ulong        app_sz  = fd_cstr_to_ulong( argv[2] );

      ulong align     = fd_dcache_align();
      ulong footprint = fd_dcache_footprint( data_sz, app_sz );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: data_sz (%lu) and app_sz (%lu) must result a footprint smaller than 2^64.\n\tDo %s help for help",
                     cnt, cmd, data_sz, app_sz, bin ));
      }

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shdcache = fd_dcache_new( shmem, data_sz, app_sz );
      if( FD_UNLIKELY( !shdcache ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_dcache_new( %s:%lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, data_sz, app_sz, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success", cnt, cmd, _wksp, data_sz, app_sz ));
      SHIFT( 3 );

    } else if( !strcmp( cmd, "delete-dcache" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shdcache = argv[0];

      void * shdcache = fd_wksp_map( _shdcache );
      if( FD_UNLIKELY( !shdcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));
      if( FD_UNLIKELY( !fd_dcache_delete( shdcache ) ) )
        FD_LOG_ERR(( "%i: %s: fd_dcache_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));
      fd_wksp_unmap( shdcache );

      fd_wksp_cstr_free( _shdcache );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shdcache ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "query-dcache" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shdcache =                 argv[0];
      int          verbose   = fd_cstr_to_int( argv[1] );

      void * shdcache = fd_wksp_map( _shdcache );
      if( FD_UNLIKELY( !shdcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));

      uchar const * dcache = fd_dcache_join( shdcache );
      if( FD_UNLIKELY( !dcache ) )
        FD_LOG_ERR(( "%i: %s: fd_dcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));

      if( !verbose ) printf( "0\n" );
      else {
        fd_dcache_private_hdr_t const * hdr = fd_dcache_private_hdr_const( dcache );
        printf( "dcache %s\n", _shdcache );
        printf( "\tdata-sz %lu\n", hdr->data_sz );
        printf( "\tapp-sz  %lu\n", hdr->app_sz  );

        if( hdr->app_sz ) {
          uchar const * a = fd_dcache_app_laddr_const( dcache );
          ulong app_sz;
          for( app_sz=hdr->app_sz; app_sz; app_sz-- ) if( a[app_sz-1UL] ) break;
          ulong         off = 0UL;
          printf( "\tapp     %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                  (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                  (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
          for( off+=16UL, a+=16UL; off<app_sz; off+=16UL, a+=16UL )
            printf( "\t        %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                    (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                    (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
          if( off<hdr->app_sz ) printf( "\t        ... snip (all remaining are zero) ...\n" );
        }
      }

      fd_wksp_unmap( fd_dcache_leave( dcache ) );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, _shdcache, verbose ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "new-fseq" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp =                   argv[0];
      ulong        seq0  = fd_cstr_to_ulong( argv[1] );

      ulong align     = fd_fseq_align();
      ulong footprint = fd_fseq_footprint();

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shfseq = fd_fseq_new( shmem, seq0 );
      if( FD_UNLIKELY( !shfseq ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_fseq_new( %s:%lu, %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, seq0, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, _wksp, seq0 ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "delete-fseq" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shfseq = argv[0];

      void * shfseq = fd_wksp_map( _shfseq );
      if( FD_UNLIKELY( !shfseq ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));
      if( FD_UNLIKELY( !fd_fseq_delete( shfseq ) ) )
        FD_LOG_ERR(( "%i: %s: fd_fseq_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));
      fd_wksp_unmap( shfseq );

      fd_wksp_cstr_free( _shfseq );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shfseq ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "query-fseq" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shfseq =                 argv[0];
      int          verbose = fd_cstr_to_int( argv[1] );

      void * shfseq = fd_wksp_map( _shfseq );
      if( FD_UNLIKELY( !shfseq ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));

      ulong const * fseq = fd_fseq_join( shfseq );
      if( FD_UNLIKELY( !fseq ) )
        FD_LOG_ERR(( "%i: %s: fd_fseq_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));

      if( !verbose ) printf( "%lu\n", fd_fseq_query( fseq ) );
      else {
        printf( "fseq %s\n", _shfseq );
        printf( "\tseq0 %lu\n", fd_fseq_seq0 ( fseq ) );
        printf( "\tseq  %lu\n", fd_fseq_query( fseq ) );
        uchar const * a = (uchar const *)fd_fseq_app_laddr_const( fseq );
        ulong app_sz;
        for( app_sz=FD_FSEQ_APP_FOOTPRINT; app_sz; app_sz-- ) if( a[app_sz-1UL] ) break;
        ulong off = 0UL;
        printf( "\tapp  %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
        for( off+=16UL, a+=16UL; off<app_sz; off+=16UL, a+=16UL )
          printf( "\t     %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                  (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                  (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
        if( off<FD_FSEQ_APP_FOOTPRINT ) printf( "\t     ... snip (all remaining are zero) ...\n" );
      }

      fd_wksp_unmap( fd_fseq_leave( fseq ) );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, _shfseq, verbose ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "update-fseq" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shfseq =                   argv[0];
      ulong        seq     = fd_cstr_to_ulong( argv[1] );

      void * shfseq = fd_wksp_map( _shfseq );
      if( FD_UNLIKELY( !shfseq ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));

      ulong * fseq = fd_fseq_join( shfseq );
      if( FD_UNLIKELY( !fseq ) )
        FD_LOG_ERR(( "%i: %s: fd_fseq_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shfseq, bin ));

      fd_fseq_update( fseq, seq );

      fd_wksp_unmap( fd_fseq_leave( fseq ) );

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, _shfseq, seq ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "new-cnc" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                                                 argv[0];
      ulong        type      =                               fd_cstr_to_ulong( argv[1] );
      long         heartbeat = (!strcmp( argv[2], "-"   )) ? fd_log_wallclock() :
                             ( (!strcmp( argv[2], "tic" )) ? fd_tickcount()     :
                                                             fd_cstr_to_long ( argv[2] ) );
      ulong        app_sz    =                               fd_cstr_to_ulong( argv[3] );

      ulong align     = fd_cnc_align();
      ulong footprint = fd_cnc_footprint( app_sz );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: bad app-sz (%lu)\n\tDo %s help for help", cnt, cmd, app_sz, bin ));
      }

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shcnc = fd_cnc_new( shmem, app_sz, type, heartbeat );
      if( FD_UNLIKELY( !shcnc ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_cnc_new( %s:%lu, %lu, %lu, %li ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, app_sz, type, heartbeat, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %li %lu: success", cnt, cmd, _wksp, type, heartbeat, app_sz ));
      SHIFT( 4 );

    } else if( !strcmp( cmd, "delete-cnc" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shcnc = argv[0];

      void * shcnc = fd_wksp_map( _shcnc );
      if( FD_UNLIKELY( !shcnc ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));
      if( FD_UNLIKELY( !fd_cnc_delete( shcnc ) ) )
        FD_LOG_ERR(( "%i: %s: fd_cnc_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));
      fd_wksp_unmap( shcnc );

      fd_wksp_cstr_free( _shcnc );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shcnc ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "query-cnc" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shcnc  =                 argv[0];
      int          verbose = fd_cstr_to_int( argv[1] );

      void * shcnc = fd_wksp_map( _shcnc );
      if( FD_UNLIKELY( !shcnc ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      fd_cnc_t const * cnc = fd_cnc_join( shcnc );
      if( FD_UNLIKELY( !cnc ) )
        FD_LOG_ERR(( "%i: %s: fd_cnc_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      if( !verbose ) printf( "%lu\n", cnc->signal );
      else {
        printf( "cnc %s\n", _shcnc );
        printf( "\tapp-sz     %lu\n",      cnc->app_sz                                         );
        printf( "\ttype       %lu\n",      cnc->type                                           );
        printf( "\theartbeat0 %li\n",      cnc->heartbeat0                                     );
        printf( "\theartbeat  %li\n",      cnc->heartbeat                                      );
        printf( "\tlock       %lu\n",      cnc->lock                                           );
        printf( "\tsignal     %s (%lu)\n", fd_cnc_signal_cstr( cnc->signal, buf ), cnc->signal );

        uchar const * a = (uchar const *)fd_cnc_app_laddr_const( cnc );
        ulong app_sz;
        for( app_sz=cnc->app_sz; app_sz; app_sz-- ) if( a[app_sz-1UL] ) break;
        ulong off = 0UL;
        printf( "\tapp        %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
        for( off+=16UL, a+=16UL; off<app_sz; off+=16UL, a+=16UL )
          printf( "\t           %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                  (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                  (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
        if( off<cnc->app_sz ) printf( "\t           ... snip (all remaining are zero) ...\n" );
      }

      fd_wksp_unmap( fd_cnc_leave( cnc ) );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, _shcnc, verbose ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "signal-cnc" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shcnc =                        argv[0];
      ulong        signal = fd_cstr_to_cnc_signal( argv[1] );

      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      if( FD_UNLIKELY( signal<FD_CNC_SIGNAL_HALT ) )
        FD_LOG_ERR(( "%i: %s: invalid signal %s (%lu) to send\n\tDo %s help for help",
                     cnt, cmd, fd_cnc_signal_cstr( signal, buf ), signal, bin ));

      void * shcnc = fd_wksp_map( _shcnc );
      if( FD_UNLIKELY( !shcnc ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      fd_cnc_t * cnc = fd_cnc_join( shcnc );
      if( FD_UNLIKELY( !cnc ) )
        FD_LOG_ERR(( "%i: %s: fd_cnc_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      int err = fd_cnc_open( cnc );
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s: fd_cnc_open( \"%s\" ) failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, _shcnc, err, fd_cnc_strerror( err ), bin ));

      fd_cnc_signal( cnc, signal );

      ulong response = fd_cnc_wait( cnc, signal, LONG_MAX, NULL );
      printf( "%s\n", fd_cnc_signal_cstr( response, buf ) );

      fd_cnc_close( cnc );

      fd_wksp_unmap( fd_cnc_leave( cnc ) );

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, _shcnc, fd_cnc_signal_cstr( signal, buf ) ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "new-tcache" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                   argv[0];
      ulong        depth     = fd_cstr_to_ulong( argv[1] );
      ulong        map_cnt   = fd_cstr_to_ulong( argv[2] );

      ulong align     = fd_tcache_align();
      ulong footprint = fd_tcache_footprint( depth, map_cnt );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: bad depth (%lu) and/or map_cnt (%lu)\n\tDo %s help for help", cnt, cmd, depth, map_cnt, bin ));
      }

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, tag );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, tag, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * _tcache = fd_tcache_new( shmem, depth, map_cnt );
      if( FD_UNLIKELY( !_tcache ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_tcache_new( %s:%lu, %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, depth, map_cnt, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success", cnt, cmd, _wksp, depth, map_cnt ));
      SHIFT( 3 );

    } else if( !strcmp( cmd, "delete-tcache" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * gaddr = argv[0];

      void * _tcache = fd_wksp_map( gaddr );
      if( FD_UNLIKELY( !_tcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));
      if( FD_UNLIKELY( !fd_tcache_delete( _tcache ) ) )
        FD_LOG_ERR(( "%i: %s: fd_tcache_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));
      fd_wksp_unmap( _tcache );

      fd_wksp_cstr_free( gaddr );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, gaddr ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "query-tcache" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * gaddr  =                  argv[0];
      int          verbose = fd_cstr_to_int( argv[1] );

      void * _tcache = fd_wksp_map( gaddr );
      if( FD_UNLIKELY( !_tcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));

      fd_tcache_t * tcache = fd_tcache_join( _tcache );
      if( FD_UNLIKELY( !tcache ) )
        FD_LOG_ERR(( "%i: %s: fd_tcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));

      printf( "tcache %s\n", gaddr );
      printf( "\tdepth   %lu\n", tcache->depth   );
      printf( "\tmap_cnt %lu\n", tcache->map_cnt );

      fd_wksp_unmap( fd_tcache_leave( tcache ) );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, gaddr, verbose ));
      SHIFT( 2 );

    } else if( !strcmp( cmd, "reset-tcache" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * gaddr = argv[0];

      void * _tcache = fd_wksp_map( gaddr );
      if( FD_UNLIKELY( !_tcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));

      fd_tcache_t * tcache = fd_tcache_join( _tcache );
      if( FD_UNLIKELY( !tcache ) )
        FD_LOG_ERR(( "%i: %s: fd_tcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, gaddr, bin ));

      fd_tcache_reset( fd_tcache_ring_laddr( tcache ), fd_tcache_depth  ( tcache ),
                       fd_tcache_map_laddr ( tcache ), fd_tcache_map_cnt( tcache ) );

      fd_wksp_unmap( fd_tcache_leave( tcache ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, gaddr ));
      SHIFT( 1 );

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  if( FD_UNLIKELY( cnt<1 ) ) FD_LOG_NOTICE(( "processed %i commands\n\tDo %s help for help", cnt, bin ));
  else                       FD_LOG_NOTICE(( "processed %i commands", cnt ));

# undef SHIFT
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_tango_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif

