#include "../../util/fd_util.h"
#include "fd_gossip_private.h"
#include "fd_gossip_txbuild.h"

FD_IMPORT_BINARY( fd_gossip_test_vote_txn, "src/flamenco/gossip/test_vote_txn.bin" );

void
gen_pubkey( fd_rng_t * rng, uchar * pubkey ) {
  for( ulong i=0UL; i<32UL; i++ ) pubkey[i] = fd_rng_uchar( rng );
}

void
test_gossip_vote_enc( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  uchar pubkey[32UL];
  gen_pubkey( rng, pubkey );

  fd_gossip_txbuild_t txbuild[1];
  fd_gossip_txbuild_init( txbuild, FD_GOSSIP_MESSAGE_PUSH );

  uchar crds_val[ FD_GOSSIP_CRDS_MAX_SZ ];
  fd_gossip_view_crds_value_t ser_view[1];

  long now = 1234L*1000L*1000L;

  fd_gossip_crds_vote_encode( crds_val,
                              FD_GOSSIP_CRDS_MAX_SZ,
                              fd_gossip_test_vote_txn,
                              fd_gossip_test_vote_txn_sz,
                              pubkey,
                              now,
                              0UL, /* vote_index */
                              ser_view );
  FD_TEST( ser_view->tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( fd_memeq( crds_val+ser_view->pubkey_off, pubkey, 32UL ) );
  FD_TEST( ser_view->vote->index==0UL );
  FD_TEST( ser_view->vote->txn_sz==fd_gossip_test_vote_txn_sz );
  FD_TEST( fd_memeq( crds_val+ser_view->vote->txn_off, fd_gossip_test_vote_txn, fd_gossip_test_vote_txn_sz ) );
  FD_TEST( ser_view->wallclock_nanos==now );

  ulong crds_val_sz = ser_view->length;

  FD_TEST( !!fd_gossip_txbuild_can_fit( txbuild, crds_val_sz ) );
  fd_gossip_txbuild_append( txbuild, crds_val_sz, crds_val );


  /* Simple parse test */
  fd_gossip_view_t parse_view[1];
  ulong sz = fd_gossip_msg_parse( parse_view, txbuild->bytes, txbuild->bytes_len );
  FD_TEST( sz==txbuild->bytes_len );

  fd_gossip_view_crds_value_t * parsed_vote = &parse_view->push->crds_values[0];
  FD_TEST( parsed_vote->tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( fd_memeq( txbuild->bytes+parsed_vote->pubkey_off, pubkey, 32UL ) );
  FD_TEST( parsed_vote->vote->index==0UL );
  FD_TEST( parsed_vote->length==crds_val_sz );
  FD_TEST( parsed_vote->vote->txn_sz==fd_gossip_test_vote_txn_sz );
  FD_TEST( fd_memeq( txbuild->bytes+parsed_vote->vote->txn_off, fd_gossip_test_vote_txn, parsed_vote->vote->txn_sz ) );
  FD_TEST( parsed_vote->wallclock_nanos==now );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_gossip_vote_enc();
  FD_LOG_NOTICE(( "gossip vote encode test passed" ));
  FD_LOG_NOTICE(( "All tests passed!" ));
  return 0;
}
