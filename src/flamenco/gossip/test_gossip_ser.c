#include "../../util/fd_util.h"
#include "fd_gossip_private.h"

void
gen_pubkey( fd_rng_t * rng, uchar * pubkey ) {
  for( ulong i=0UL; i<32UL; i++ ) pubkey[i] = fd_rng_uchar( rng );
}

void
test_prune_enc( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  uchar out_buf[ FD_GOSSIP_MTU ] = {0};
  fd_signature_t signature = {0};
  uchar origins[3][32UL];
  for( ulong i=0UL; i<3UL; i++ ) gen_pubkey( rng, origins[i] );
  uchar relayer[32UL]; gen_pubkey( rng, relayer );
  uchar my_pubkey[32UL]; gen_pubkey( rng, my_pubkey );
  long  now = 1234567890000000L; /* in nanos */

  ulong encode_sz = 0UL;
  int rc = fd_gossip_prune_encode( my_pubkey, relayer, (uchar const *)origins, 3UL, signature.uc, now, out_buf, sizeof(out_buf), &encode_sz );
  FD_TEST( rc==0 );
  FD_TEST( encode_sz>0UL );

  fd_gossip_view_t view[1];
  ulong decoded_sz = fd_gossip_msg_parse( view, out_buf, encode_sz );

  FD_TEST( decoded_sz==encode_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PRUNE );
  fd_gossip_view_prune_t * prune = view->prune;
  FD_TEST( !memcmp( (uchar const *)(out_buf+prune->pubkey_off), my_pubkey, 32UL ) );
  FD_TEST( prune->origins_len==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( !memcmp( (uchar const *)(out_buf+prune->origins_off+i*32UL), origins[i], 32UL ) );
  }
  FD_TEST( !memcmp( (uchar const *)(out_buf+prune->signature_off), signature.uc, 64UL ) );
  FD_TEST( !memcmp( (uchar const *)(out_buf+prune->destination_off), relayer, 32UL ) );
  FD_TEST( prune->wallclock==1234567890UL );
  FD_TEST( prune->wallclock_nanos==1234567890000000L );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_prune_enc();
  FD_LOG_NOTICE(( "test_prune_enc passed!" ));

  FD_LOG_NOTICE(( "All tests passed!" ));
  return 0;
}
