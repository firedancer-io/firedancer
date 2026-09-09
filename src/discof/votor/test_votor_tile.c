#include "../../waltz/quic/fd_quic.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"

static ulong quic_init_cnt;
static ulong quic_fini_cnt;

static fd_quic_t *
test_quic_init( fd_quic_t * quic ) {
  quic_init_cnt++;
  return quic;
}

static fd_quic_t *
test_quic_fini( fd_quic_t * quic ) {
  quic_fini_cnt++;
  return quic;
}

static ulong
test_get_next_leader_slot( fd_multi_epoch_leaders_t const * mleaders,
                           ulong                            start_slot,
                           fd_pubkey_t const *               leader ) {
  (void)mleaders;
  (void)leader;
  return start_slot;
}

#define fd_quic_init test_quic_init
#define fd_quic_fini test_quic_fini
#define fd_multi_epoch_leaders_get_next_slot test_get_next_leader_slot
#include "fd_votor_tile.c"
#undef fd_multi_epoch_leaders_get_next_slot
#undef fd_quic_fini
#undef fd_quic_init

static uchar publishes_mem[ 1UL<<20 ] __attribute__((aligned(128UL)));
static uchar peers_mem   [ 1UL<<20 ] __attribute__((aligned(128UL)));

static void
test_halted_votor_does_not_connect( void ) {
  fd_votor_tile_t ctx[1] __attribute__((aligned(128UL)));
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->halted      = 1;
  ctx->quic_client = (fd_quic_t *)1UL;
  connect_peers( ctx, 0L );
}

static void
test_identity_keyswitch( void ) {
  fd_votor_tile_t ctx[1] __attribute__((aligned(128UL)));
  fd_keyswitch_t  keyswitch[1] __attribute__((aligned(FD_KEYSWITCH_ALIGN)));
  fd_quic_t       quic_client[1];
  fd_quic_t       quic_server[1];

  fd_memset( ctx,       0, sizeof(ctx)       );
  fd_memset( keyswitch, 0, sizeof(keyswitch) );
  fd_memset( quic_client, 0, sizeof(quic_client) );
  fd_memset( quic_server, 0, sizeof(quic_server) );

  FD_TEST( publishes_footprint( 4UL )<=sizeof(publishes_mem) );
  FD_TEST( peers_footprint()<=sizeof(peers_mem) );
  ctx->publishes          = publishes_join( publishes_new( publishes_mem, 4UL ) );
  ctx->peers              = peers_join( peers_new( peers_mem ) );
  ctx->quic_client        = quic_client;
  ctx->quic_server        = quic_server;
  ctx->mleaders           = (fd_multi_epoch_leaders_t *)1UL;
  ctx->identity_keyswitch = keyswitch;
  ctx->replay_in_seq      = 7UL;
  ctx->replay_slot        = 5UL;

  fd_memset( keyswitch->bytes, 0x42, 32UL );
  keyswitch->param = 8UL;
  keyswitch->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;

  during_housekeeping( ctx );

  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( !ctx->halted );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( !ctx->id_key.uc[ i ] );

  ctx->replay_in_seq = 8UL;
  during_housekeeping( ctx );

  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( quic_fini_cnt==2UL );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( ctx->id_key.uc[ i ]==0x42 );
  FD_TEST( ctx->next_leader_slot==8UL );

  keyswitch->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
  during_housekeeping( ctx );

  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !ctx->halted );
  FD_TEST( quic_init_cnt==2UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_halted_votor_does_not_connect();
  test_identity_keyswitch();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
