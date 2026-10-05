#include "fd_gossip_tile.c"

#include <stdlib.h>

static fd_gossip_tile_ctx_t ctx;
static fd_keyswitch_t       keyswitch[1];
static ulong                sign_cnt;

static uchar txsend_mem[ FD_TPU_RAW_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static void
test_sign_fn( void *        sign_ctx  FD_PARAM_UNUSED,
              uchar const * data      FD_PARAM_UNUSED,
              ulong         sz        FD_PARAM_UNUSED,
              int           sign_type FD_PARAM_UNUSED ) {
  sign_cnt++;
}

/* txsend_vote delivers the TxSend vote frag with sequence seq.  The
   vote is paid for by our identity, which follows the signature and
   the 4 byte message header. */

static void
txsend_vote( ulong seq ) {
  fd_txn_m_t * txn_m = (fd_txn_m_t *)txsend_mem;
  uchar *      txn   = fd_txn_m_payload( txn_m );
  memset( txn, 0, 101UL );
  txn[ 0 ] = 1;
  memcpy( txn+69UL, ctx.identity_key, sizeof(fd_pubkey_t) );
  txn_m->payload_sz = 101;
  FD_TEST( !returnable_frag( &ctx, 0UL, seq, 1UL, 0UL, fd_txn_m_realized_footprint( txn_m, 0, 0 ), 0UL, 0UL, 0UL, NULL ) );
}

/* Votes TxSend published before set-identity are signed by the old
   identity, so gossip must push them before it halts signing. */

static void
test_switch_drains_txsend( void ) {
  fd_clock_tile_init( ctx.clock );
  memset( ctx.identity_key, 0x11, sizeof(fd_pubkey_t) );

  ulong  max_values = 256UL;
  void * mem        = aligned_alloc( fd_gossip_align(), fd_gossip_footprint( max_values, 1UL ) );
  FD_TEST( mem );

  uchar         ping_seed[ 32 ] = {0};
  fd_ip4_port_t entrypoint[1]   = {0};
  ctx.gossip = fd_gossip_join( fd_gossip_new( mem, fd_rng_join( fd_rng_new( ctx.rng, 0U, 0UL ) ), ping_seed, max_values, 1UL, entrypoint,
                                              ctx.identity_key->uc, ctx.my_contact_info, fd_clock_tile_now( ctx.clock ),
                                              gossip_send_fn,                &ctx,
                                              test_sign_fn,                  NULL,
                                              gossip_ping_tracker_change_fn, &ctx,
                                              gossip_activity_update_fn,     &ctx,
                                              ctx.update_out, ctx.net_out ) );
  FD_TEST( ctx.gossip );

  ctx.in[ 0 ]   = (fd_gossip_in_ctx_t){ .kind = IN_KIND_TXSEND, .mem = (fd_wksp_t *)txsend_mem, .mtu = FD_TPU_RAW_MTU };
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );

  /* TxSend published two votes before it switched */
  keyswitch->param = 2UL;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );

  during_housekeeping( &ctx );
  FD_TEST( !ctx.is_halting_signing );

  txsend_vote( 0UL );
  during_housekeeping( &ctx );
  FD_TEST( !ctx.is_halting_signing );

  txsend_vote( 1UL );
  during_housekeeping( &ctx );
  FD_TEST( ctx.is_halting_signing && sign_cnt==2UL );

  /* Halting completes once both votes are signed */
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_switch_drains_txsend();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
