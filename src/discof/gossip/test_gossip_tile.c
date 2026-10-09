#include "fd_gossip_tile.c"

#include <stdlib.h>

static fd_gossip_tile_ctx_t ctx;
static fd_keyswitch_t       keyswitch[1];
static ulong                sign_cnt;

static uchar txsend_mem[ FD_TPU_RAW_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

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

static void
fill_pubkey( uchar * dst,
             uchar   b ) {
  memset( dst, b, sizeof(fd_pubkey_t) );
}

/* A snapshot whose bank Stakes field is empty (as emitted by the
   Firedancer snapshot producer) must still provide wait for
   supermajority with the stake distribution, which is taken from the
   leader schedule epoch stakes. */

static void
test_wfs_stakes_from_epoch_stakes( void ) {
  fd_snapshot_manifest_t * manifest = aligned_alloc( FD_CHUNK_ALIGN, fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_CHUNK_ALIGN ) );
  FD_TEST( manifest );
  memset( manifest, 0, sizeof(fd_snapshot_manifest_t) );
  for( ulong i=0UL; i<FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN; i++ ) manifest->epoch_stakes[ i ].epoch = ULONG_MAX;

  /* Slot 1000 in epoch 10, leader schedule epoch 11 */
  manifest->epoch_schedule_params.slots_per_epoch             = 100UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 100UL;
  manifest->epoch_schedule_params.warmup                      = 0;
  manifest->epoch_schedule_params.first_normal_epoch          = 0UL;
  manifest->epoch_schedule_params.first_normal_slot           = 0UL;
  manifest->slot                                              = 1000UL;
  manifest->vote_accounts_len                                 = 0UL;

  /* epoch_stakes_base = 7; epoch 10 (leader schedule stake for the
     current epoch) is decoy data that must not be used. */
  fd_snapshot_manifest_epoch_stakes_t * cur = &manifest->epoch_stakes[ 3 ];
  cur->epoch           = 10UL;
  cur->vote_stakes_len = 1UL;
  fill_pubkey( cur->vote_stakes[ 0 ].vote,     0x01 );
  fill_pubkey( cur->vote_stakes[ 0 ].identity, 0xA1 );
  cur->vote_stakes[ 0 ].stake = 999UL;

  fd_snapshot_manifest_epoch_stakes_t * nxt = &manifest->epoch_stakes[ 4 ];
  nxt->epoch           = 11UL;
  nxt->vote_stakes_len = 3UL;
  fill_pubkey( nxt->vote_stakes[ 0 ].vote,     0x01 );
  fill_pubkey( nxt->vote_stakes[ 0 ].identity, 0xA1 );
  nxt->vote_stakes[ 0 ].stake = 50UL;
  fill_pubkey( nxt->vote_stakes[ 1 ].vote,     0x02 );
  fill_pubkey( nxt->vote_stakes[ 1 ].identity, 0xA1 );
  nxt->vote_stakes[ 1 ].stake = 40UL;
  fill_pubkey( nxt->vote_stakes[ 2 ].vote,     0x03 );
  fill_pubkey( nxt->vote_stakes[ 2 ].identity, 0xB2 );
  nxt->vote_stakes[ 2 ].stake = 10UL;

  FD_TEST( fd_snapshot_manifest_wfs_epoch_stakes( manifest )==nxt );

  ctx.in[ 0 ]   = (fd_gossip_in_ctx_t){ .kind = IN_KIND_SNAPIN_MANIF, .mem = (fd_wksp_t *)manifest, .mtu = sizeof(fd_snapshot_manifest_t) };
  ctx.wfs_state = FD_GOSSIP_WFS_STATE_INIT;
  FD_TEST( !returnable_frag( &ctx, 0UL, 0UL, fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ), 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );

  FD_TEST( ctx.wfs_stake.total==100UL );
  FD_TEST( ctx.wfs_stakes_cnt==2UL );
  FD_TEST( ctx.wfs_peers.total==2UL );

  FD_TEST( !returnable_frag( &ctx, 0UL, 1UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_WAIT );

  ctx.my_contact_info->shred_version = 42;
  fd_gossip_contact_info_t ci[1];
  memset( ci, 0, sizeof(fd_gossip_contact_info_t) );
  ci->shred_version = 42;
  ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].ip4  = 0x0100007fU;
  ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].port = 8001;

  /* 10% of stake online: keep waiting */
  fd_pubkey_t id_b; fill_pubkey( id_b.uc, 0xB2 );
  gossip_activity_update_fn( &ctx, &id_b, ci, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==10UL && ctx.wfs_peers.online==1UL );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_WAIT );

  /* 100% of stake online: publish */
  fd_pubkey_t id_a; fill_pubkey( id_a.uc, 0xA1 );
  gossip_activity_update_fn( &ctx, &id_a, ci, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==100UL && ctx.wfs_peers.online==2UL );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_PUBLISH );

  /* Missing leader schedule epoch stakes */
  nxt->epoch = ULONG_MAX;
  FD_TEST( !fd_snapshot_manifest_wfs_epoch_stakes( manifest ) );

  ctx.my_contact_info->shred_version = 0;
  free( manifest );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  test_switch_drains_txsend();
  test_wfs_stakes_from_epoch_stakes();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
