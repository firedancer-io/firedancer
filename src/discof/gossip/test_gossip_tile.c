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


static uchar * manifest_mem;

/* Drives snapin_manif: the manifest carries the boot slot, the
   FD_SSMSG_DONE that follows classifies it (see fd_wfs.h). */

static void
wfs_manifest( ulong slot ) {
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)manifest_mem;
  manifest->slot              = slot;
  manifest->vote_accounts_len = 0UL;
  FD_TEST( !returnable_frag( &ctx, 1UL, 0UL, fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ), 0UL,
                             sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL, NULL ) );
}

static void
wfs_done( void ) {
  FD_TEST( !returnable_frag( &ctx, 1UL, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
}

/* Boots with the given WFS config, feeds a manifest at boot_slot and
   the DONE after it, and returns the state gossip settles in. */

static int
wfs_state_for( ulong  wfs_slot,
               int    hash_is_zero,
               ushort shred_version,
               ulong  boot_slot ) {
  ctx.wfs_slot          = wfs_slot;
  ctx.wfs_hash_is_zero  = hash_is_zero;
  ctx.wfs_shred_version = shred_version;
  ctx.wfs_boot_slot     = ULONG_MAX;
  ctx.wfs_state         = fd_int_if( fd_wfs_configured( wfs_slot, hash_is_zero, (ulong)shred_version ),
                                     FD_GOSSIP_WFS_STATE_INIT, FD_GOSSIP_WFS_STATE_DONE );
  ctx.in[ 1 ] = (fd_gossip_in_ctx_t){ .kind  = IN_KIND_SNAPIN_MANIF,
                                      .mem   = (fd_wksp_t *)manifest_mem,
                                      .mtu   = sizeof(fd_snapshot_manifest_t) };
  wfs_manifest( boot_slot );
  wfs_done();
  return ctx.wfs_state;
}

/* Gossip is the only tile that signals the wait is over, so a
   misclassification here leaves replay waiting forever. */

static void
test_wfs_state_transitions( void ) {
  static ulong metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  fd_metrics_tl = metrics;

  /* aligned_alloc requires a size that is a multiple of the alignment. */
  manifest_mem = aligned_alloc( FD_CHUNK_ALIGN, fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_CHUNK_ALIGN ) );
  FD_TEST( manifest_mem );

  /* MATCH waits for the supermajority. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 100UL )==FD_GOSSIP_WFS_STATE_WAIT );

  /* NOOP and DISABLED are finished at boot and never signal. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 101UL )==FD_GOSSIP_WFS_STATE_DONE );
  FD_TEST( wfs_state_for(   0UL, 1,    0, 100UL )==FD_GOSSIP_WFS_STATE_DONE );

  /* ERROR holds at INIT.  Only WAIT can become PUBLISH, so completion
     is unreachable without ever testing after_credit. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 99UL )==FD_GOSSIP_WFS_STATE_INIT );

  free( manifest_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_switch_drains_txsend();
  test_wfs_state_transitions();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
