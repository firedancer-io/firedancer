#include "fd_gossip_tile.c"

#include <stdlib.h>

static fd_gossip_tile_ctx_t ctx;
static fd_keyswitch_t       keyswitch[1];
static ulong                vote_sign_cnt;

static uchar txsend_mem[ FD_TPU_RAW_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar update_mem[ 16UL*FD_NET_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static void
test_sign_fn( void *        sign_ctx  FD_PARAM_UNUSED,
              uchar const * data,
              ulong         sz        FD_PARAM_UNUSED,
              int           sign_type FD_PARAM_UNUSED,
              uchar *       out_signature ) {
  if( FD_LOAD( uint, data )==FD_GOSSIP_VALUE_VOTE ) vote_sign_cnt++;
  memset( out_signature, 0, 64UL );
}

/* txsend_vote delivers the TxSend vote frag with sequence seq.  The
   vote is paid for by our identity, which follows the signature and
   the 4 byte message header. */

static void
txsend_vote( fd_stem_context_t * stem,
             ulong               seq ) {
  fd_txn_m_t * txn_m = (fd_txn_m_t *)txsend_mem;
  uchar *      txn   = fd_txn_m_payload( txn_m );
  memset( txn, 0, 101UL );
  txn[ 0 ] = 1;
  memcpy( txn+69UL, ctx.identity_key, sizeof(fd_pubkey_t) );
  txn_m->payload_sz = 101;
  FD_TEST( !returnable_frag( &ctx, 0UL, seq, 1UL, 0UL, fd_txn_m_realized_footprint( txn_m, 0, 0 ), 0UL, 0UL, 0UL, stem ) );
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

  /* Our signed votes are published to the gossip update link */

  ulong             depth      = 128UL;
  void *            mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( depth, 0UL ) );
  fd_frag_meta_t *  mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  ulong             seq        = 0UL;
  int               reliable   = 0;
  fd_stem_context_t stem[1]    = {{ .mcaches = &mcache, .seqs = &seq, .depths = &depth, .out_reliable = &reliable }};
  FD_TEST( mcache );

  ctx.gossip_out[ 0 ] = (fd_gossip_out_ctx_t){ .mem = (fd_wksp_t *)update_mem, .wmark = (sizeof(update_mem)-FD_NET_MTU)/FD_CHUNK_SZ };

  fd_ip4_port_t entrypoint[1] = {0};
  ctx.gossip = fd_gossip_join( fd_gossip_new( mem, fd_rng_join( fd_rng_new( ctx.rng, 0U, 0UL ) ), max_values, 1UL, entrypoint,
                                              ctx.identity_key->uc, ctx.my_contact_info, fd_clock_tile_now( ctx.clock ),
                                              gossip_send_fn,                &ctx,
                                              test_sign_fn,                  NULL,
                                              gossip_ping_tracker_change_fn, &ctx,
                                              gossip_activity_update_fn,     &ctx,
                                              ctx.gossip_out, ctx.net_out ) );
  FD_TEST( ctx.gossip );

  ctx.in[ 0 ]   = (fd_gossip_in_ctx_t){ .kind = IN_KIND_TXSEND, .mem = (fd_wksp_t *)txsend_mem, .mtu = FD_TPU_RAW_MTU };
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );

  /* TxSend published two votes before it switched */
  keyswitch->param = 2UL;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );

  during_housekeeping( &ctx );
  FD_TEST( !ctx.is_halting_signing );

  txsend_vote( stem, 0UL );
  during_housekeeping( &ctx );
  FD_TEST( !ctx.is_halting_signing );

  txsend_vote( stem, 1UL );
  during_housekeeping( &ctx );
  FD_TEST( ctx.is_halting_signing && vote_sign_cnt==2UL );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );

  free( fd_mcache_delete( fd_mcache_leave( mcache ) ) );
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
