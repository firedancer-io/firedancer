#include "../../util/fd_util.h"
#include "fd_gossip.h"

#include <stdlib.h>

static void
send_stub( void *               ctx,
           fd_stem_context_t *  stem,
           uchar const *        data,
           ulong                sz,
           fd_ip4_port_t const *peer_address,
           ulong                now ) {
  (void)ctx; (void)stem; (void)data; (void)sz; (void)peer_address; (void)now;
}

static void
sign_stub( void *        ctx,
           uchar const * data,
           ulong         sz,
           int           sign_type,
           uchar *       out_signature ) {
  (void)ctx; (void)data; (void)sz; (void)sign_type;
  /* Produce a deterministic dummy signature */
  for( ulong i=0UL; i<64UL; i++ ) out_signature[i] = (uchar)i;
}

static void
ping_change_stub( void *        ctx,
                  uchar const * peer_pubkey,
                  fd_ip4_port_t peer_address,
                  long          now,
                  int           change_type ) {
  (void)ctx; (void)peer_pubkey; (void)peer_address; (void)now; (void)change_type;
}

static void
test_gossip_new_basic( void ) {
  ulong max_values      = 1024UL;

  ulong               entrypoints_len = 1UL;
  fd_ip4_port_t const entrypoints[1]  = { { .addr = 0x7f000001U, /* 127.0.0.1 */
                                            .port = fd_ushort_bswap( (ushort)8001 ) } };

  fd_contact_info_t my_ci = {0};
  for( ulong i=0UL; i<32UL; i++ ) my_ci.pubkey.uc[i] = (uchar)i;
  my_ci.shred_version                        = 0U;
  my_ci.instance_creation_wallclock_nanos    = fd_log_wallclock();
  my_ci.wallclock_nanos                      = my_ci.instance_creation_wallclock_nanos;
  my_ci.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].addr = entrypoints[0].addr;
  my_ci.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ].port = entrypoints[0].port;
  my_ci.version.client                       = FD_CONTACT_INFO_VERSION_CLIENT_FIREDANCER;
  my_ci.version.major                        = 0U;
  my_ci.version.minor                        = 0U;
  my_ci.version.patch                        = 0U;
  my_ci.version.commit                       = 0U;
  my_ci.version.feature_set                  = 0U;

  void * mem = aligned_alloc( fd_gossip_align(), fd_gossip_footprint( max_values, entrypoints_len ) );
  FD_TEST( mem );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  static fd_gossip_out_ctx_t gossip_update_out = {0};
  static fd_gossip_out_ctx_t gossip_net_out    = {0};

  void * shgossip = fd_gossip_new( mem,
                                   rng,
                                   max_values,
                                   entrypoints_len,
                                   entrypoints,
                                   &my_ci,
                                   fd_log_wallclock(),
                                   send_stub,
                                   NULL,
                                   sign_stub,
                                   NULL,
                                   ping_change_stub,
                                   NULL,
                                   &gossip_update_out,
                                   &gossip_net_out );
  FD_TEST( shgossip );

  fd_gossip_t * gossip = fd_gossip_join( shgossip );
  FD_TEST( gossip );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_gossip_new_basic();
  FD_LOG_NOTICE(( "test_gossip_new_basic() passed" ));
  fd_halt();
  return 0;
}
