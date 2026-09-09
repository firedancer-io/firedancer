#include "fd_failover_channel.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/net/fd_ip4.h"

static uchar       scratch[ 2 ][ 8UL<<20 ] __attribute__((aligned(128)));
static uchar       keys[ 3 ][ 64 ] = { { 1 }, { 2 }, { 9 } };
static fd_sha512_t sha[ 1 ];

/* Stands in for the sign tile, the member's junk key signs its TLS. */
static void
sign_fn( void *      ctx,
         uchar       sig[ static FD_ED25519_SIG_SZ ],
         uchar const payload[ static FD_TLS_CV_SIGN_SZ ] ) {
  uchar const * key = ctx;
  fd_ed25519_sign( sig, payload, FD_TLS_CV_SIGN_SZ, key+32UL, key, sha );
}

static fd_failover_channel_t *
member( ulong idx, ulong staked_idx ) {
  fd_failover_channel_t * ch = fd_failover_channel_join( fd_failover_channel_new( scratch[idx] ) );
  FD_TEST( ch );
  fd_failover_hello_t hello = { .version=FD_FAILOVER_VERSION, .boot_id=idx+1UL,
                                .role=(uchar)(idx ? FD_FAILOVER_ROLE_STANDBY : FD_FAILOVER_ROLE_ACTIVE),
                                .mode=FD_FAILOVER_MODE_TOWER };
  fd_memcpy( hello.junk_pubkey, keys[idx]+32UL, 32UL );
  fd_memcpy( hello.staked_pubkey, keys[staked_idx]+32UL, 32UL );
  fd_memset( hello.vote_account, 0xBB, 32UL );
  FD_TEST( !fd_failover_channel_set_identity( ch, keys[idx]+32UL, (fd_tls_sign_t){ .ctx=keys[idx], .sign_fn=sign_fn }, &hello ) );
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ], cert[ 64 ];
  fd_failover_member_cert_msg( msg, keys[idx]+32UL );
  fd_ed25519_sign( cert, msg, sizeof(msg), keys[staked_idx]+32UL, keys[staked_idx], sha );
  FD_TEST( !fd_failover_channel_set_member_cert( ch, cert ) );
  fd_failover_channel_init_listener( ch, FD_IP4_ADDR(127,0,0,1), 0 );
  return ch;
}

static int
poll_one( fd_failover_channel_t * ch, ushort * type, uchar * payload, ulong * sz ) {
  int busy = 0;
  return fd_failover_channel_poll( ch, fd_failover_clock(), &busy, type, payload, sz );
}

static void
test_pair_and_transfer( void ) {
  fd_failover_channel_t * a = member( 0UL, 2UL );
  fd_failover_channel_t * b = member( 1UL, 2UL );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), fd_failover_channel_listen_port( a ) );
  long   until = fd_failover_clock()+5000000000L;
  ushort type;
  ulong  sz;
  uchar  payload[ FD_FAILOVER_PAYLOAD_MAX ];
  while( fd_failover_channel_state( a )!=FD_FAILOVER_SESSION_PAIRED ||
         fd_failover_channel_state( b )!=FD_FAILOVER_SESSION_PAIRED ) {
    FD_TEST( fd_failover_clock()<until );
    FD_TEST( !poll_one( a, &type, payload, &sz ) );
    FD_TEST( !poll_one( b, &type, payload, &sz ) );
  }
  FD_TEST( fd_failover_channel_generation( a )==1UL && fd_failover_channel_generation( b )==1UL );
  fd_failover_handoff_request_t req = { .handoff_id=42UL, .target_boot_id=1UL };
  FD_TEST( !fd_failover_channel_send( b, fd_failover_clock(), FD_FAILOVER_MSG_HANDOFF_REQUEST, (uchar const *)&req, sizeof(req) ) );
  while( !poll_one( a, &type, payload, &sz ) ) {
    FD_TEST( fd_failover_clock()<until );
    FD_TEST( !poll_one( b, &type, payload, &sz ) );
  }
  FD_TEST( type==FD_FAILOVER_MSG_HANDOFF_REQUEST && sz==sizeof(req) && fd_memeq( payload, &req, sz ) );
  fd_failover_channel_fini( a );
  fd_failover_channel_fini( b );
}

static void
test_wrong_staked_key( void ) {
  fd_failover_channel_t * a = member( 0UL, 2UL );
  fd_failover_channel_t * b = member( 1UL, 0UL );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), fd_failover_channel_listen_port( a ) );
  long   until         = fd_failover_clock()+5000000000L;
  ushort type;
  ulong  sz;
  uchar  payload[ FD_FAILOVER_PAYLOAD_MAX ];
  int    hello_started = 0;
  while( !hello_started || fd_failover_channel_state( b )!=FD_FAILOVER_SESSION_BACKOFF ) {
    FD_TEST( fd_failover_clock()<until );
    FD_TEST( !poll_one( a, &type, payload, &sz ) );
    FD_TEST( !poll_one( b, &type, payload, &sz ) );
    hello_started |= fd_failover_channel_state( b )==FD_FAILOVER_SESSION_HELLO;
  }
  FD_TEST( !fd_failover_channel_generation( a ) && !fd_failover_channel_generation( b ) );
  FD_TEST( fd_failover_channel_state( a )!=FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_channel_state( b )!=FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( !fd_failover_channel_peer_hello( a )->boot_id && !fd_failover_channel_peer_hello( b )->boot_id );
  fd_failover_channel_fini( a );
  fd_failover_channel_fini( b );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_failover_channel_footprint()<=sizeof(scratch[0]) );
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<3UL; i++ ) fd_ed25519_public_from_private( keys[i]+32UL, keys[i], sha );
  test_pair_and_transfer();
  test_wrong_staked_key();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
