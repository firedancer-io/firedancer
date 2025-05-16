#include "fd_gossip_types.h"
#include "fd_ping_tracker.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/fd_util.h"

#include "test_crds_utils.c"

FD_STATIC_ASSERT( FD_PING_TRACKER_ALIGN==128UL,  unit_test );

static inline long
seconds( long s ) {
  return s*1000L*1000L*1000L;
}

void
test_basic( void ) {
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng ) );
  FD_TEST( ping_tracker );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 50UL );

  long now = fd_log_wallclock();
  for( ulong i=0UL; i<100UL; i++) FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now, crds, NULL, NULL, NULL ) );

  uchar random_pubkey[ 32UL ] = { 0 };
  for( ulong i=0UL; i<32UL; i++ ) random_pubkey[ i ] = fd_rng_uchar( rng );

  /* Nothing is initially active ... */
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, NULL, now ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 1UL, NULL, now ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 1000UL, NULL, now ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 9999UL, NULL, now ) );

  /* Except high stakes nodes are always allowed, to any address ... */
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey, 1000000000UL, NULL, now ) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey, 1000000000UL, NULL, 0L ) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey, 1000000001UL, NULL, 0L ) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey, ULONG_MAX, NULL, 0L ) );

  /* High stake nodes do not get tracked ... */
  fd_ping_tracker_track( ping_tracker, random_pubkey, 1000000000UL, NULL, now );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), crds, NULL, NULL, NULL ) );

  /* Low stake nodes do get tracked ... */
  /* Pick a random peer, doesn't matter if it is staked in the CRDS table */
  fd_contact_info_t const * ci = fd_crds_peer_sample( crds, rng );
  FD_TEST( ci );
  fd_ip4_port_t random_address[1]; *random_address = fd_contact_info_gossip_socket( ci );


  fd_ping_tracker_track( ping_tracker, random_pubkey, 0UL, random_address, now );

  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !memcmp( out_pubkey, random_pubkey, 32UL ) );
  FD_TEST( out_address->addr==random_address->addr );
  FD_TEST( out_address->port==random_address->port );

  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(11), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(12),  crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, random_address, now+seconds(12) ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(13), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(14), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(15), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(16), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, random_address, now+seconds(16) ) );
  FD_TEST( !memcmp( out_pubkey, random_pubkey, 32UL ) );
  FD_TEST( out_address->addr==random_address->addr );
  FD_TEST( out_address->port==random_address->port );
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(20), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, random_address, now+seconds(20) ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(22), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(24), crds, &out_pubkey, &out_address, &out_token ) );
}

void
test_juggle( void ) {
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng ) );
  FD_TEST( ping_tracker );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 50UL );
  FD_TEST( crds );

  long now = fd_log_wallclock();
  for( ulong i=0UL; i<100UL; i++) FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now, crds, NULL, NULL, NULL ) );

  fd_contact_info_t const * ci1 = fd_crds_peer_sample( crds, rng );
  FD_TEST( ci1 );

  uchar const * random_pubkey1 = ci1->pubkey.uc;
  fd_ip4_port_t random_address1[1]; *random_address1 = fd_contact_info_gossip_socket( ci1 );



  uchar random_pubkey2[32] = {0};
  fd_ip4_port_t random_address2[1];
  random_address2->addr = fd_rng_uint( rng );
  random_address2->port  = fd_rng_ushort( rng );

  /* Nothing is initially active ... */
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, NULL, now ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey2, 0UL, NULL, now ) );

  fd_ping_tracker_track( ping_tracker, random_pubkey1, 0UL, random_address1, now );
  fd_ping_tracker_track( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(1) );

  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(2), crds, &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !memcmp( out_pubkey, random_pubkey1, 32UL ) );
  FD_TEST( out_address->addr==random_address1->addr );
  FD_TEST( out_address->port==random_address1->port );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(3) ) );

  /* Different address */
  fd_ping_tracker_register( ping_tracker, crds, random_pubkey1, 0UL, random_address2, valid_pong_token, now+seconds(3) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(3) ) );

  /* Wrong token */
  uchar wrong_pong_token[ 32UL ] = { 0 };
  fd_ping_tracker_register( ping_tracker, crds, random_pubkey1, 0UL, random_address1, wrong_pong_token, now+seconds(3) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(3) ) );

  /* Correct token */
  fd_ping_tracker_register( ping_tracker, crds, random_pubkey1, 0UL, random_address1, valid_pong_token, now+seconds(3) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(3) ) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(60*20) ) );
  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(60*20+3) ) );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey1, 0UL, random_address1, now+seconds(60*20+4) ) );
}

void
test_change_address( void ) {
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng ) );
  FD_TEST( ping_tracker );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 50UL );
  FD_TEST( crds );

  long now = fd_log_wallclock();

  fd_contact_info_t const * ci = fd_crds_peer_sample( crds, rng );
  FD_TEST( ci );
  uchar const * random_pubkey = ci->pubkey.uc;
  fd_ip4_port_t random_address[1]; *random_address = fd_contact_info_gossip_socket( ci );

  fd_ping_tracker_track( ping_tracker, random_pubkey, 0UL, random_address, now );
  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(1), crds, &out_pubkey, &out_address, &out_token ) );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  fd_ping_tracker_register( ping_tracker, crds, random_pubkey, 0UL, random_address, valid_pong_token, now+seconds(2) );

  FD_TEST( fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, random_address, now+seconds(3) ) );

  random_address->addr = fd_rng_uint( rng );
  random_address->port = fd_rng_ushort( rng );
  fd_ping_tracker_track( ping_tracker, random_pubkey, 0UL, random_address, now );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, random_pubkey, 0UL, random_address, now+seconds(3) ) );
}

void
test_random( void ) {
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint() );
  FD_TEST( bytes );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng ) );
  FD_TEST( ping_tracker );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 50UL );
  FD_TEST( crds );

  long now = fd_log_wallclock();

  for( ulong i=0UL; i<100000UL; i++ ) {
    uchar opt = fd_rng_uchar_roll( rng, 4UL );

    if( opt==0UL ) {
      fd_contact_info_t const * ci = fd_crds_peer_sample( crds, rng );
      FD_TEST( ci );
      uchar const * random_pubkey = ci->pubkey.uc;
      fd_ip4_port_t random_address[1]; *random_address = fd_contact_info_gossip_socket( ci );


      ulong random_stake = fd_rng_ulong( rng ) % (1048576000000000UL-1UL)+1UL;

      now += fd_rng_long_roll( rng, 1000000UL );
      fd_ping_tracker_track( ping_tracker, random_pubkey, random_stake, random_address, now );
    } else if( opt==1UL ) {
      uchar const *         out_pubkey;
      fd_ip4_port_t const * out_address;
      uchar const *         out_token;

      now += fd_rng_long_roll( rng, 1000000UL );
      while( fd_ping_tracker_pop_request( ping_tracker, now, crds, &out_pubkey, &out_address, &out_token ) );
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_basic();
  FD_LOG_NOTICE(( "test_basic() passed" ));

  test_juggle();
  FD_LOG_NOTICE(( "test_juggle() passed" ));

  test_change_address();
  FD_LOG_NOTICE(( "test_change_address() passed" ));

  test_random();
  FD_LOG_NOTICE(( "test_random() passed" ));
}
