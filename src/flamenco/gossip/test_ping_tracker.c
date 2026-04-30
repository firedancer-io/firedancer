#include "fd_ping_tracker.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/fd_util.h"

#include <stdlib.h>

FD_STATIC_ASSERT( FD_PING_TRACKER_ALIGN==128UL,  unit_test );

typedef struct ping_tracker_change_ctx {
  struct {
    uchar         pubkey[ 32UL ];
    fd_ip4_port_t address;
    long          now;
    int           change_type;
  } last;
  ulong invoke_cnt; /* number of times the change function was invoked */
} ping_tracker_change_ctx_t;

typedef struct peer {
  uchar         pubkey[ 32UL ];
  fd_ip4_port_t address;
} peer_t;

peer_t
generate_random_peer( fd_rng_t * rng ) {
  peer_t p = {0};
  for( ulong i=0UL; i<32UL; i++ ) p.pubkey[ i ] = fd_rng_uchar( rng );
  p.address.addr = fd_rng_uint( rng );
  p.address.port = fd_rng_ushort( rng );
  return p;
}

void
test_change( void *        ctx,
             uchar const * peer_pubkey,
             fd_ip4_port_t peer_address,
             long          now,
             int           change_type ) {
  ping_tracker_change_ctx_t * c = (ping_tracker_change_ctx_t *)ctx;
  memcpy( c->last.pubkey, peer_pubkey, 32UL );
  c->last.address   = peer_address;
  c->last.now       = now;
  c->last.change_type = change_type;
  c->invoke_cnt++;
}

static inline long
seconds( long s ) {
  return s*1000L*1000L*1000L;
}

void
test_basic( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );


  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );
  long now = fd_log_wallclock();
  for( ulong i=0UL; i<100UL; i++) FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now, NULL, NULL, NULL ) );

  uchar random_pubkey[ 32UL ] = { 0 };
  for( ulong i=0UL; i<32UL; i++ ) random_pubkey[ i ] = fd_rng_uchar( rng );


  /* High stake nodes do not get tracked ... */
  fd_ping_tracker_track( ping_tracker, random_pubkey, 1000000000UL, entrypoints[0], now );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), NULL, NULL, NULL ) );

  /* Entrypoints do not get tracked */
  fd_ping_tracker_track( ping_tracker, random_pubkey, 0UL, entrypoints[0], now );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), NULL, NULL, NULL ) );

  /* Low stake nodes do get tracked ... */
  peer_t p = generate_random_peer( rng );
  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now );

  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !memcmp( out_pubkey, p.pubkey, 32UL ) );
  FD_TEST( out_address->addr==p.address.addr );
  FD_TEST( out_address->port==p.address.port );

  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(10), &out_pubkey, &out_address, &out_token ) );
  FD_TEST ( fd_ping_tracker_pop_request( ping_tracker, now+seconds(11), &out_pubkey, &out_address, &out_token ) );
  /* Peer should still be in invalid state, so no invocations to change fn */
  FD_TEST( !change_ctx->invoke_cnt );

  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(11), &out_pubkey, &out_address, &out_token ) );
  FD_TEST ( fd_ping_tracker_pop_request( ping_tracker, now+seconds(14), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(14), &out_pubkey, &out_address, &out_token ) );
  FD_TEST ( fd_ping_tracker_pop_request( ping_tracker, now+seconds(16), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !change_ctx->invoke_cnt );
  FD_TEST( !memcmp( out_pubkey, p.pubkey, 32UL ) );
  FD_TEST( out_address->addr==p.address.addr );
  FD_TEST( out_address->port==p.address.port );
  FD_TEST( !change_ctx->invoke_cnt );
  FD_TEST ( fd_ping_tracker_pop_request( ping_tracker, now+seconds(20), &out_pubkey, &out_address, &out_token ) );
  /* Peer should get dropped after 20s if no pong */
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(22), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(24), &out_pubkey, &out_address, &out_token ) );
  /* Peer was never valid, so no invocations to change fn */
  FD_TEST( !change_ctx->invoke_cnt );

  free( bytes );
}


void
test_register( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };

  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );


  long now = fd_log_wallclock();
  for( ulong i=0UL; i<100UL; i++) FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now, NULL, NULL, NULL ) );

  peer_t p1 = generate_random_peer( rng );
  peer_t p2 = generate_random_peer( rng );

  fd_ping_tracker_track( ping_tracker, p1.pubkey, 0UL, p1.address, now );
  fd_ping_tracker_track( ping_tracker, p1.pubkey, 0UL, p1.address, now+seconds(1) );

  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(2), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !memcmp( out_pubkey, p1.pubkey, 32UL ) );
  FD_TEST( out_address->addr==p1.address.addr );
  FD_TEST( out_address->port==p1.address.port );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  /* Different address */
  fd_ping_tracker_register( ping_tracker, p1.pubkey, 0UL, p2.address, valid_pong_token, now+seconds(3) );
  /* No state change, so no invocation to change fn */
  FD_TEST( change_ctx->invoke_cnt==0UL );

  /* Wrong token */
  uchar wrong_pong_token[ 32UL ] = { 0 };
  fd_ping_tracker_register( ping_tracker, p1.pubkey, 0UL, p1.address, wrong_pong_token, now+seconds(3) );
  FD_TEST( change_ctx->invoke_cnt==0UL );

  /* Unknown peer */
  fd_ping_tracker_register( ping_tracker, p2.pubkey, 0UL, p2.address, valid_pong_token, now+seconds(3) );
  FD_TEST( change_ctx->invoke_cnt==0UL );

  /* Correct token */
  fd_ping_tracker_register( ping_tracker, p1.pubkey, 0UL, p1.address, valid_pong_token, now+seconds(3) );
  FD_TEST( change_ctx->invoke_cnt==1UL );
  FD_TEST( change_ctx->last.now==now+seconds(3) );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_ACTIVE );
  FD_TEST( !memcmp( change_ctx->last.pubkey, p1.pubkey, 32UL ) );
  FD_TEST( change_ctx->last.address.addr==p1.address.addr );

  /* Second pong will not result in a change fn invocation */
  fd_ping_tracker_register( ping_tracker, p1.pubkey, 0UL, p1.address, valid_pong_token, now+seconds(4) );
  FD_TEST( change_ctx->invoke_cnt==1UL );

  free( bytes );
}

void
test_change_address( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };

  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );

  long now = fd_log_wallclock();

  peer_t p = generate_random_peer( rng );

  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now );
  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(1), &out_pubkey, &out_address, &out_token ) );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  fd_ping_tracker_register( ping_tracker, p.pubkey, 0UL, p.address, valid_pong_token, now+seconds(2) );
  FD_TEST( change_ctx->invoke_cnt==1UL );
  FD_TEST( change_ctx->last.now==now+seconds(2) );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_ACTIVE );
  FD_TEST( !memcmp( change_ctx->last.pubkey, p.pubkey, 32UL ) );

  p.address.addr = fd_rng_uint( rng );
  p.address.port = fd_rng_ushort( rng );
  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now );
  FD_TEST( change_ctx->invoke_cnt==2UL );
  FD_TEST( change_ctx->last.now==now );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );
  FD_TEST( !memcmp( change_ctx->last.pubkey, p.pubkey, 32UL ) );
  FD_TEST( change_ctx->last.address.addr==p.address.addr );
  FD_TEST( change_ctx->last.address.port==p.address.port );

  free( bytes );
}

void
test_active_address_binding( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };

  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );

  long now = fd_log_wallclock();

  /* Generate a peer and drive it into the VALID state by completing
     a full ping/pong handshake. */

  peer_t p = generate_random_peer( rng );
  /* Make sure the peer address is non-zero so it is eligible. */
  while( FD_UNLIKELY( !p.address.addr ) ) p.address.addr = 1U;

  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now );

  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(1), &out_pubkey, &out_address, &out_token ) );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  fd_ping_tracker_register( ping_tracker, p.pubkey, 0UL, p.address, valid_pong_token, now+seconds(2) );
  FD_TEST( change_ctx->invoke_cnt==1UL );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_ACTIVE );

  /* ---- Tests on a peer that is now in VALID state ---- */

  /* 1) Exact address match -> active==1 */
  FD_TEST( fd_ping_tracker_active( ping_tracker, p.pubkey, p.address ) );

  /* 2) addr==0 (zero address) -> active==0 regardless of state */
  fd_ip4_port_t zero_addr = { .addr=0U, .port=p.address.port };
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p.pubkey, zero_addr ) );

  fd_ip4_port_t zero_both = { .addr=0U, .port=0U };
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p.pubkey, zero_both ) );

  /* 3) Different addr, same port -> active==0 */
  fd_ip4_port_t wrong_addr = { .addr=p.address.addr ^ 0x01000000U, .port=p.address.port };
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p.pubkey, wrong_addr ) );

  /* 4) Same addr, different port -> active==0 */
  fd_ip4_port_t wrong_port = { .addr=p.address.addr, .port=(ushort)(p.address.port ^ (ushort)1) };
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p.pubkey, wrong_port ) );

  /* 5) Both addr and port different -> active==0 */
  fd_ip4_port_t wrong_both = { .addr=p.address.addr ^ 0x01000000U, .port=(ushort)(p.address.port ^ (ushort)1) };
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p.pubkey, wrong_both ) );

  /* 6) Unknown pubkey -> active==0 even with valid address */
  peer_t unknown = generate_random_peer( rng );
  FD_TEST( !fd_ping_tracker_active( ping_tracker, unknown.pubkey, p.address ) );

  /* 7) Peer in INVALID state (not yet ponged) -> active==0 even
     with matching address. */
  peer_t p2 = generate_random_peer( rng );
  if( FD_UNLIKELY( !p2.address.addr ) ) p2.address.addr = 2U;
  fd_ping_tracker_track( ping_tracker, p2.pubkey, 0UL, p2.address, now );
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(1), &out_pubkey, &out_address, &out_token ) );
  /* p2 is now in INVALID state (pinged, no pong received). */
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p2.pubkey, p2.address ) );

  /* 8) Peer in UNPINGED state -> active==0 */
  peer_t p3 = generate_random_peer( rng );
  if( FD_UNLIKELY( !p3.address.addr ) ) p3.address.addr = 3U;
  fd_ping_tracker_track( ping_tracker, p3.pubkey, 0UL, p3.address, now );
  /* p3 is UNPINGED (tracked but pop_request not called for it). */
  FD_TEST( !fd_ping_tracker_active( ping_tracker, p3.pubkey, p3.address ) );

  free( bytes );
}

void
test_random( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );

  long now = fd_log_wallclock();

  for( ulong i=0UL; i<100000UL; i++ ) {
    uchar opt = fd_rng_uchar_roll( rng, 4UL );

    if( opt==0UL ) {
      peer_t p = generate_random_peer( rng );
      ulong p_stake = fd_rng_ulong( rng ) % (1048576000000000UL-1UL)+1UL;

      now += fd_rng_long_roll( rng, 1000000UL );
      fd_ping_tracker_track( ping_tracker, p.pubkey, p_stake, p.address, now );
    } else if( opt==1UL ) {
      uchar const *         out_pubkey;
      fd_ip4_port_t const * out_address;
      uchar const *         out_token;

      now += fd_rng_long_roll( rng, 1000000UL );
      while( fd_ping_tracker_pop_request( ping_tracker, now, &out_pubkey, &out_address, &out_token ) );
    }
  }

  free( bytes );
}

void
test_invalid_transitions( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  const ulong         entrypoints_len = 1UL;
  const fd_ip4_port_t entrypoints[1]  = { {.addr=fd_rng_uint(rng), .port=fd_rng_ushort(rng)} };
  void * bytes = aligned_alloc( fd_ping_tracker_align(), fd_ping_tracker_footprint( entrypoints_len ) );
  FD_TEST( bytes );

  ping_tracker_change_ctx_t change_ctx[1] = {0};
  fd_ping_tracker_t * ping_tracker = fd_ping_tracker_join( fd_ping_tracker_new( bytes, rng, entrypoints_len, entrypoints, test_change, change_ctx ) );
  FD_TEST( ping_tracker );

  long now = fd_log_wallclock();
  peer_t p = generate_random_peer( rng );

  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now );
  uchar const *         out_pubkey;
  fd_ip4_port_t const * out_address;
  uchar const *         out_token;

  /* Unpinged to invalid */
  FD_TEST( fd_ping_tracker_pop_request( ping_tracker, now+seconds(1), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !memcmp( out_pubkey, p.pubkey, 32UL ) );

  uchar valid_pong_token[ 32UL ];
  fd_sha256_t sha[1];
  FD_TEST( fd_sha256_join( fd_sha256_new( sha ) ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, out_token, 32UL );
  fd_sha256_fini( sha, valid_pong_token );

  /* Invalid to Valid */
  fd_ping_tracker_register( ping_tracker, p.pubkey, 0UL, p.address, valid_pong_token, now+seconds(2) );
  FD_TEST( change_ctx->invoke_cnt==1UL );
  FD_TEST( memcmp( change_ctx->last.pubkey, p.pubkey, 32UL )==0 );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_ACTIVE );

  /* Valid to Valid Refreshing */
  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now+seconds(18*60) ); /* refresh last rx */
  fd_ping_tracker_pop_request( ping_tracker, now+seconds(18*60+4), &out_pubkey, &out_address, &out_token );
  FD_TEST( change_ctx->invoke_cnt==1UL );

  /* Valid Refreshing to Invalid */
  fd_ping_tracker_track( ping_tracker, p.pubkey, 0UL, p.address, now+seconds(20*60) ); /* refresh last rx */
  fd_ping_tracker_pop_request( ping_tracker, now+seconds(20*60+3), &out_pubkey, &out_address, &out_token );
  FD_TEST( change_ctx->invoke_cnt==2UL );
  FD_TEST( memcmp( change_ctx->last.pubkey, p.pubkey, 32UL )==0 );
  FD_TEST( change_ctx->last.change_type==FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );

  /* pop */
  fd_ping_tracker_pop_request( ping_tracker, now+seconds(20*60+4), &out_pubkey, &out_address, &out_token );
  FD_TEST( !memcmp( out_pubkey, p.pubkey, 32UL ) );
  FD_TEST( out_address->addr==p.address.addr );
  FD_TEST( out_address->port==p.address.port );



  /* Invalid to dropped after 20s no rx */
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(20*60+24), &out_pubkey, &out_address, &out_token ) );
  FD_TEST( !fd_ping_tracker_pop_request( ping_tracker, now+seconds(20*60+25), &out_pubkey, &out_address, &out_token ) );

  free( bytes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_basic();
  FD_LOG_NOTICE(( "test_basic() passed" ));

  test_register();
  FD_LOG_NOTICE(( "test_register() passed" ));

  test_change_address();
  FD_LOG_NOTICE(( "test_change_address() passed" ));

  test_invalid_transitions();
  FD_LOG_NOTICE(( "test_invalid_transitions() passed" ));

  test_active_address_binding();
  FD_LOG_NOTICE(( "test_active_address_binding() passed" ));

  test_random();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
