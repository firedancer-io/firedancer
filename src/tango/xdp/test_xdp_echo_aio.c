/* test_xdp_echo_aio is a simple application that binds to an AF_XDP
   queue and echoes incoming UDP packets back to the sender.  The
   most performant way to do this would be via XDP_TX (returning the
   packet at the XDP stage, instead of forwarding to AF_XDP via
   XDP_REDIRECT).  This test deliberately routes packets through
   fd_aio/XSK to test performance.

   DO NOT DEPLOY THIS ON THE INTERNET.  This application is only
   intended for testing. In the real world, it behaves as a
   high-performance UDP reflection attack gadget that can be abused
   from networks that permit source IP spoofing (see BCP 38).  */

#if !FD_HAS_HOSTED
#error "test_xdp_io requires FD_HAS_HOSTED"
#endif

#include "fd_xdp.h"
#include "../fd_tango.h"
#include "../../util/fd_util.h"

static void
echo_packet( fd_xsk_aio_t *            xsk_aio,
             fd_aio_pkt_info_t const * pkt ) {
  (void)xsk_aio;
  (void)pkt;
  FD_LOG_NOTICE(( "got packet" ));
}

int
echo_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx ) {
  (void)opt_batch_idx;

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)ctx;

  for( ulong i=0; i<batch_cnt; i++ )
    echo_packet( xsk_aio, &batch[ i ] );

  return FD_AIO_SUCCESS;
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _cnc     = fd_env_strip_cmdline_cstr( &argc, &argv, "--cnc",     NULL, NULL                 );
  char const * _xsk     = fd_env_strip_cmdline_cstr( &argc, &argv, "--xsk",     NULL, NULL                 );
  char const * _xsk_aio = fd_env_strip_cmdline_cstr( &argc, &argv, "--xsk-aio", NULL, NULL                 );
  uint         seed     = fd_env_strip_cmdline_uint( &argc, &argv, "--seed",    NULL, (uint)fd_tickcount() );
  long         lazy     = fd_env_strip_cmdline_long( &argc, &argv, "--lazy",    NULL, 7L                   );

  if( FD_UNLIKELY( !_cnc     ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_xsk     ) ) FD_LOG_ERR(( "--xsk not specified" ));
  if( FD_UNLIKELY( !_xsk_aio ) ) FD_LOG_ERR(( "--xsk-aio not specified" ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join cnc failed" ));

  FD_LOG_NOTICE(( "Joining to --xsk %s", _xsk ));

  fd_xsk_t * xsk = fd_xsk_join( fd_wksp_map( _xsk ) );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "join xsk failed" ));

  FD_LOG_NOTICE(( "Joining to --xsk-aio %s", _xsk_aio ));

  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_map( _xsk_aio ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "join xsk_aio failed" ));

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, echo_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  FD_LOG_NOTICE(( "Listening on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  ulong async_min   = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, tick_per_ns );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  long now  = fd_tickcount();
  long then = now;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    fd_xsk_aio_service( xsk_aio );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_aio_delete( fd_aio_leave( aio ) );
  fd_wksp_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_unmap( fd_xsk_leave( xsk ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
