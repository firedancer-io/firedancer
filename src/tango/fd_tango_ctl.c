#include "fd_tango.h"
#include "mcache/fd_mcache_private.h"
#include "dcache/fd_dcache_private.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  /* FIXME: CACHE ATTACHEMENTS? */

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      FD_LOG_NOTICE(( "\n\t"
        "Usage: %s [cmd] [cmd args] [cmd] [cmd args] ...\n\t"
        "Commands are:\n\t"
        "\n\t"
        "\thelp\n\t"
        "\t- Prints this message\n\t"
        "\n\t"
        "\tnew-mcache wksp depth app-sz seq0\n\t"
        "\t- Creates a frag meta cache in wksp with the given depth,\n\t"
        "\t  application region size and initial sequence number.  Prints\n\t"
        "\t  the wksp gaddr of the mcache to stdout.\n\t"
        "\n\t"
        "\tdelete-mcache gaddr\n\t"
        "\t- Destroys the mcache at gaddr.\n\t"
        "\n\t"
        "\tquery-mcache gaddr\n\t"
        "\t- Queries the mcache at gaddr.\n\t"
        "\n\t"
        "\tnew-dcache wksp mtu depth burst compact app-sz\n\t"
        "\t- Creates a frag data cache in wksp optimized for frag payloads\n\t"
        "\t  up to mtu bytes in size where up to depth frags can be\n\t"
        "\t  available to consumers while the producer can be concurrently\n\t"
        "\t  preparing up to burst frags.  A non-zero compact indicates\n\t"
        "\t  the producer will write frag payloads linearly and compactly\n\t"
        "\t  outside wrap around and will not split frags to wrap around.\n\t"
        "\t  A zero compact indicates the producer will partition the data\n\t"
        "\t  region into depth+burst mtu friendly slots and store frag\n\t"
        "\t  payloads into them (potentially in a non-linear order).\n\t"
        "\t  Prints the wksp gaddr of the dcache to stdout.\n\t"
        "\n\t"
        "\tnew-dcache-raw wksp data-sz app-sz\n\t"
        "\t- Creates a frag data cache in wksp with a data region size of\n\t"
        "\t  data-sz and an application region size of app-sz.  Prints\n\t"
        "\t  the wksp gaddr of the dcache to stdout.\n\t"
        "\n\t"
        "\tdelete-dcache gaddr\n\t"
        "\t- Destroys the dcache at gaddr.\n\t"
        "\n\t"
        "\tquery-dcache gaddr\n\t"
        "\t- Queries the dcache at gaddr.\n\t"
        "\n\t"
        "\tnew-cnc wksp type now\n\t"
        "\t- Creates an command and control variable with the given type.\n\t"
        "\t- If now is '-', the wallclock will be used for the initial\n\t"
        "\t  heartbeat value.\n\t"
        "\n\t"
        "\tdelete-cnc gaddr\n\t"
        "\t- Destroys the cnc at gaddr.\n\t"
        "\n\t"
        "\tquery-cnc gaddr\n\t"
        "\t- Queries the cnc at gaddr.\n\t"
        "\n\t"
        "\tsignal-cnc gaddr sig\n\t"
        "\t- Sends signal sig to cnc at gaddr and waits for the response.\n\t"
        "\t- Assumes sig is a valid signal to send.  E.g. halt (3).\n\t"
        "\t- Blocking waits for sig to be processed and prints the\n\t"
        "\t  response to stdout.  Typical responses are:\n\t"
        "\t    run  (0): thread resumed running\n\t"
        "\t    boot (1): thread halted and can be safely restarted.\n\t"
        "\t    fail (2): thread halted and cannot be safely restated.\n\t"
        "\n\t", bin ));
      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

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

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
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

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shmcache = argv[0];

      void * shmcache = fd_wksp_map( _shmcache );
      if( FD_UNLIKELY( !shmcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));

      fd_frag_meta_t const * mcache = fd_mcache_join( shmcache );
      if( FD_UNLIKELY( !mcache ) )
        FD_LOG_ERR(( "%i: %s: fd_mcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shmcache, bin ));

      fd_mcache_private_hdr_t const * hdr = fd_mcache_private_hdr_const( mcache );
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

      fd_wksp_unmap( fd_mcache_leave( mcache ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shmcache ));
      SHIFT( 1 );

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

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
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

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
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

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shdcache = argv[0];

      void * shdcache = fd_wksp_map( _shdcache );
      if( FD_UNLIKELY( !shdcache ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));

      uchar const * dcache = fd_dcache_join( shdcache );
      if( FD_UNLIKELY( !dcache ) )
        FD_LOG_ERR(( "%i: %s: fd_dcache_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shdcache, bin ));

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

      fd_wksp_unmap( fd_dcache_leave( dcache ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shdcache ));
      SHIFT( 1 );

    } else if( !strcmp( cmd, "new-cnc" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                                            argv[0];
      ulong        type      =                          fd_cstr_to_ulong( argv[1] );
      long         heartbeat = strcmp( argv[2], "-" ) ? fd_cstr_to_long ( argv[2] ) : fd_log_wallclock();
      /* FIXME: PRESERVE CREATION HEARTBEAT IN CNC? */

      ulong align     = fd_cnc_align();
      ulong footprint = fd_cnc_footprint();

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));
      }

      /* FIXME: DO ARRAY ALLOCATION GIVEN WKSP_ALIGN_MIN >> ALIGN HERE?
         USE LARGER OR DYNAMICALLY SIZED APP REGION? */
      ulong gaddr = fd_wksp_alloc( wksp, align, footprint );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shcnc = fd_cnc_new( shmem, type, heartbeat );
      if( FD_UNLIKELY( !shcnc ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_cnc_new( %s:%lu, %lu, %li ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, type, heartbeat, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %li: success", cnt, cmd, _wksp, type, heartbeat ));
      SHIFT( 3 );

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

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shcnc = argv[0];

      void * shcnc = fd_wksp_map( _shcnc );
      if( FD_UNLIKELY( !shcnc ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      fd_cnc_t const * cnc = fd_cnc_join( shcnc );
      if( FD_UNLIKELY( !cnc ) )
        FD_LOG_ERR(( "%i: %s: fd_cnc_join( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shcnc, bin ));

      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      printf( "cnc %s\n", _shcnc );
      printf( "\ttype      %u\n",       cnc->type                                           );
      printf( "\theartbeat %li\n",      cnc->heartbeat                                      );
      printf( "\tlock      %lu\n",      cnc->lock                                           );
      printf( "\tsignal    %s (%lu)\n", fd_cnc_signal_cstr( cnc->signal, buf ), cnc->signal );

      uchar const * a = (uchar const *)fd_cnc_app_laddr_const( cnc );
      ulong app_sz;
      for( app_sz=FD_CNC_APP_FOOTPRINT; app_sz; app_sz-- ) if( a[app_sz-1UL] ) break;
      ulong off = 0UL;
      printf( "\tapp       %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
              (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
              (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
      for( off+=16UL, a+=16UL; off<app_sz; off+=16UL, a+=16UL )
        printf( "\t          %04lx: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n", off,
                (uint)a[ 0], (uint)a[ 1], (uint)a[ 2], (uint)a[ 3], (uint)a[ 4], (uint)a[ 5], (uint)a[ 6], (uint)a[ 7],
                (uint)a[ 8], (uint)a[ 9], (uint)a[10], (uint)a[11], (uint)a[12], (uint)a[13], (uint)a[14], (uint)a[15] );
      if( off<FD_CNC_APP_FOOTPRINT ) printf( "\t          ... snip (all remaining are zero) ...\n" );

      fd_wksp_unmap( fd_cnc_leave( cnc ) );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shcnc ));
      SHIFT( 1 );

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

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  FD_LOG_NOTICE(( "processed %i commands", cnt ));

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

