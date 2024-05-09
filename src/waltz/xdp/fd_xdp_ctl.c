#if FD_HAS_HOSTED

#define _POSIX_C_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "fd_xdp.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

/* fd_xdp_redirect_prog is eBPF ELF object containing the XDP program.
   It is embedded into this program. */
FD_IMPORT_BINARY( fd_xdp_redirect_prog, "src/waltz/xdp/fd_xdp_redirect_prog.o" );

FD_IMPORT_CSTR( fd_xdp_ctl_help, "src/waltz/xdp/fd_xdp_ctl_help" );

static uint
fd_cstr_to_xdp_mode( char const * s ) {
       if( 0==strcmp( s, "skb" ) ) return XDP_FLAGS_SKB_MODE;
  else if( 0==strcmp( s, "drv" ) ) return XDP_FLAGS_DRV_MODE;
  else if( 0==strcmp( s, "hw"  ) ) return XDP_FLAGS_HW_MODE;
  else                             return 0U;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( 0==strcmp( cmd, "help" ) ) {

      fputs( fd_xdp_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( 0==strcmp( cmd, "init" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp  =                  argv[0];
      uint        perm    = fd_cstr_to_uint( argv[1] );
      char const * _user  =                  argv[2];
      char const * _group =                  argv[3];

      int uid = -1;
      if( _user[0] ) {
        struct passwd * user = getpwnam( _user );
        if( FD_UNLIKELY( !user ) ) FD_LOG_ERR(( "%i: %s: unknown user %s\n\tDo %s help for help", cnt, cmd, _user, bin ));
        uid = (int)user->pw_uid;
      }

      int gid = -1;
      if( _group[0] ) {
        struct group * group = getgrnam( _group );
        if( FD_UNLIKELY( !group ) ) FD_LOG_ERR(( "%i: %s: unknown user %s\n\tDo %s help for help", cnt, cmd, _group, bin ));
        gid = (int)group->gr_gid;
      }

      if( FD_UNLIKELY( 0!=fd_xdp_init( _wksp, perm, uid, gid ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_init(%s) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %#o %s %s: success", cnt, cmd, _wksp, perm, _user, _group ));
      SHIFT( 4 );

    } else if( 0==strcmp( cmd, "fini" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp =  argv[0];

      if( FD_UNLIKELY( 0!=fd_xdp_fini( _wksp ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_fini(%s) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, bin ));

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _wksp ));
      SHIFT( 1 );

    } else if( 0==strcmp( cmd, "hook-iface" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                 argv[0];
      char const * ifname    =                 argv[1];
      char const * _xdp_mode =                 argv[2];

      uint xdp_mode = fd_cstr_to_xdp_mode( _xdp_mode );
      if( FD_UNLIKELY( xdp_mode==0UL ) )
        FD_LOG_ERR(( "%i: %s: unsupported XDP mode \"%s\"\n\tDo %s help for help", cnt, cmd, _xdp_mode, bin ));

      if( FD_UNLIKELY( 0!=fd_xdp_hook_iface( _wksp, ifname, xdp_mode, fd_xdp_redirect_prog, fd_xdp_redirect_prog_sz ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_hook_iface(%s,%s,%s,%p,%lu) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, ifname, _xdp_mode, (void *)fd_xdp_redirect_prog, fd_xdp_redirect_prog_sz, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %s: success", cnt, cmd, _wksp, ifname, _xdp_mode ));
      SHIFT( 3 );

    } else if( 0==strcmp( cmd, "unhook-iface" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp  = argv[0];
      char const * ifname = argv[1];

      if( FD_UNLIKELY( 0!=fd_xdp_unhook_iface( _wksp, ifname ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_unhook_iface(%s,%s) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, ifname, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, _wksp, ifname ));
      SHIFT( 2 );

    } else if( 0==strcmp( cmd, "listen-udp-port" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp    =                   argv[0];
      char const * _ip_addr =                   argv[1];
      ulong        udp_port = fd_cstr_to_ulong( argv[2] );
      char const * _proto   =                   argv[3];

      uint ip_addr;
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _ip_addr, &ip_addr ) ) )
        FD_LOG_ERR(( "%i: %s: invalid IPv4 address \"%s\"\n\tDo %s help for help",
                     cnt, cmd, _ip_addr, bin ));

      if( FD_UNLIKELY( udp_port==0U || udp_port>USHORT_MAX ) )
        FD_LOG_ERR(( "%i: %s: invalid UDP port number\n\tDo %s help for help",
                     cnt, cmd, bin ));

      /* TODO: Map protocol string to a uint identifier */
      (void)_proto;
      uint proto = 1UL;

      ushort port = (ushort)udp_port;
      if( FD_UNLIKELY( 0!=fd_xdp_listen_udp_ports( _wksp, ip_addr, 1, &port, proto ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_listen_udp_ports(%s,%s,%lu,%s) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, _ip_addr, udp_port, _proto, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %lu %s: success", cnt, cmd, _wksp, _ip_addr, udp_port, _proto ));
      SHIFT( 4 );

    } else if( 0==strcmp( cmd, "release-udp-port" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp    =                   argv[0];
      char const * _ip_addr =                   argv[1];
      ulong        udp_port = fd_cstr_to_ulong( argv[2] );

      uint ip_addr;
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _ip_addr, &ip_addr ) ) )
        FD_LOG_ERR(( "%i: %s: invalid IPv4 address \"%s\"\n\tDo %s help for help",
                     cnt, cmd, _ip_addr, bin ));

      if( FD_UNLIKELY( udp_port==0U || udp_port>USHORT_MAX ) )
        FD_LOG_ERR(( "%i: %s: invalid UDP port number\n\tDo %s help for help",
                     cnt, cmd, bin ));

      if( FD_UNLIKELY( 0!=fd_xdp_release_udp_port( _wksp, ip_addr, (uint)udp_port ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_release_udp_port(%s,%s,%lu) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, _ip_addr, udp_port, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s %lu: success", cnt, cmd, _wksp, _ip_addr, udp_port ));
      SHIFT( 3 );

    } else if( 0==strcmp( cmd, "new-xsk" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                   argv[0];
      ulong        frame_sz  = fd_cstr_to_ulong( argv[1] );
      ulong        rx_depth  = fd_cstr_to_ulong( argv[2] );
      ulong        tx_depth  = fd_cstr_to_ulong( argv[3] );
      int          zero_copy = fd_cstr_to_int  ( argv[4] );
      /* For now, have fill/completion ring depth match rx/tx rings */
      ulong        fr_depth = rx_depth;
      ulong        cr_depth = tx_depth;

      ulong align     = fd_xsk_align();
      ulong footprint = fd_xsk_footprint( frame_sz, fr_depth, rx_depth, tx_depth, cr_depth );
      if( FD_UNLIKELY( !footprint ) )
        FD_LOG_ERR(( "%i: %s: frame_sz (%lu), rx_depth (%lu), and tx_depth (%lu) must be greater than zero and result in "
                     "a footprint smaller than 2^64.\n\tDo %s help for help", cnt, cmd, frame_sz, rx_depth, tx_depth, bin ));

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, 1UL );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, 1UL ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shxsk = fd_xsk_new( shmem, frame_sz, fr_depth, rx_depth, tx_depth, cr_depth, zero_copy );
      if( FD_UNLIKELY( !shxsk ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_xsk_new( %s:%lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu %lu: success", cnt, cmd, _wksp, frame_sz, rx_depth, tx_depth ));
      SHIFT( 5 );

    } else if( 0==strcmp( cmd, "bind-xsk" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shxsk   =                  argv[0];
      char const * app_name =                  argv[1];
      char const * ifname   =                  argv[2];
      uint         ifqueue  = fd_cstr_to_uint( argv[3] );

      void * shxsk = fd_wksp_map( _shxsk );
      if( FD_UNLIKELY( !shxsk ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map(%s) failed\n\tDo %s help for help", cnt, cmd, _shxsk, bin ));
      if( FD_UNLIKELY( !fd_xsk_bind( shxsk, app_name, ifname, ifqueue ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xsk_bind(%s,%s,%u) failed\n\tDo %s help for help",
                     cnt, cmd, _shxsk, ifname, ifqueue, bin ));
      fd_wksp_unmap( shxsk );

      FD_LOG_NOTICE(( "%i: %s %s %s %s %u: success", cnt, cmd, _shxsk, app_name, ifname, ifqueue ));
      SHIFT( 4 );

    } else if( 0==strcmp( cmd, "unbind-xsk" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shxsk = argv[0];

      void * shxsk = fd_wksp_map( _shxsk );
      if( FD_UNLIKELY( !shxsk ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map(%s) failed\n\tDo %s help for help",   cnt, cmd, _shxsk, bin ));
      if( FD_UNLIKELY( !fd_xsk_unbind( shxsk ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xsk_unbind(%s) failed\n\tDo %s help for help", cnt, cmd, _shxsk, bin ));
      fd_wksp_unmap( shxsk );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shxsk ));
      SHIFT( 1 );

    } else if( 0==strcmp( cmd, "delete-xsk" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shxsk = argv[0];

      void * shxsk = fd_wksp_map( _shxsk );
      if( FD_UNLIKELY( !shxsk ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map(%s) failed\n\tDo %s help for help", cnt, cmd, _shxsk, bin ));
      if( FD_UNLIKELY( !fd_xsk_delete( shxsk ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xdp_delete(%s) failed\n\tDo %s help for help", cnt, cmd, _shxsk, bin ));
      fd_wksp_unmap( shxsk );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shxsk ));
      SHIFT( 1 );

    } else if( 0==strcmp( cmd, "new-xsk-aio" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _wksp     =                   argv[0];
      ulong        tx_depth  = fd_cstr_to_ulong( argv[1] );
      ulong        batch_cnt = fd_cstr_to_ulong( argv[2] );

      ulong align     = fd_xsk_aio_align();
      ulong footprint = fd_xsk_aio_footprint( tx_depth, batch_cnt );
      if( FD_UNLIKELY( !footprint ) )
        FD_LOG_ERR(( "%i: %s: tx_depth (%lu) and batch_cnt (%lu) must be greater than zero and result in "
                     "a footprint smaller than 2^64.\n\tDo %s help for help", cnt, cmd, tx_depth, batch_cnt, bin ));

      fd_wksp_t * wksp = fd_wksp_attach( _wksp );
      if( FD_UNLIKELY( !wksp ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _wksp, bin ));

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, 1UL );
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu, 1UL ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, align, footprint, bin ));
      }

      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help", cnt, cmd, _wksp, gaddr, bin ));
      }

      void * shxsk_aio = fd_xsk_aio_new( shmem, tx_depth, batch_cnt );
      if( FD_UNLIKELY( !shxsk_aio ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_xsk_aio_new( %s:%lu ) failed\n\tDo %s help for help",
                     cnt, cmd, _wksp, gaddr, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success",
                      cnt, cmd, _wksp, tx_depth, batch_cnt ));
      SHIFT( 3 );

    } else if( 0==strcmp( cmd, "delete-xsk-aio" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * _shxsk_aio = argv[0];

      void * shxsk_aio = fd_wksp_map( _shxsk_aio );
      if( FD_UNLIKELY( !shxsk_aio ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shxsk_aio, bin ));
      if( FD_UNLIKELY( !fd_xsk_aio_delete( shxsk_aio ) ) )
        FD_LOG_ERR(( "%i: %s: fd_xsk_aio_delete( \"%s\" ) failed\n\tDo %s help for help", cnt, cmd, _shxsk_aio, bin ));
      fd_wksp_unmap( shxsk_aio );

      fd_wksp_cstr_free( _shxsk_aio );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, _shxsk_aio ));
      SHIFT( 1 );

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
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_xdp_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif /* FD_HAS_HOSTED */
