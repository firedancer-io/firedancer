#include "fd_txsend_tile.h"

static ulong sign_cnt;

static void
mock_vote_sign( fd_keyguard_client_t * client FD_FN_UNUSED,
                uchar *                signatures,
                ulong                  authority_idx FD_FN_UNUSED,
                uchar const *          sign_data FD_FN_UNUSED,
                ulong                  sign_data_len FD_FN_UNUSED ) {
  memset( signatures, 0, 64UL );
  sign_cnt++;
}

static void
mock_quic_identity( fd_quic_t * quic FD_FN_UNUSED,
                    uchar const public_key[ static 32 ] FD_FN_UNUSED ) {}

#define fd_keyguard_client_vote_txn_sign mock_vote_sign
#define fd_quic_set_identity_public_key mock_quic_identity
#include "fd_txsend_tile.c"
#undef fd_keyguard_client_vote_txn_sign
#undef fd_quic_set_identity_public_key

FD_IMPORT_BINARY( vote_txn, "src/discof/rpc/fixtures/vote_tower_sync.bin" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  static fd_txsend_tile_t ctx;
  static fd_identity_transition_t shared;
  static fd_keyswitch_t keyswitch;
  static uchar mleaders_mem[FD_MULTI_EPOCH_LEADERS_FOOTPRINT] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
  ctx.mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  FD_TEST( ctx.mleaders );
  fd_clock_tile_init( ctx.clock );
  ctx.keyswitch = &keyswitch;
  ctx.identity_status = &shared;
  memset( ctx.identity_key->uc, 1, 32UL );
  uchar new_identity[32]; memset( new_identity, 2, 32UL );
  fd_identity_record_t record = { .instance = {1UL,2UL} };
  fd_identity_begin( &shared, &record, ctx.identity_key->uc, new_identity );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1024UL, 0UL, "txsend-test", 0UL );
  FD_TEST( wksp );
  void * data = fd_wksp_alloc_laddr( wksp, 128UL, 65536UL, 1UL );
  FD_TEST( data );
  ctx.txsend_out->mem = wksp;
  ctx.txsend_out->chunk = ctx.txsend_out->chunk0 = fd_dcache_compact_chunk0( wksp, data );
  ctx.txsend_out->wmark = ctx.txsend_out->chunk0+512UL;
  void * mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( 128UL, 0UL ), 1UL );
  FD_TEST( mcache_mem );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, 128UL, 0UL, 0UL ) );
  ulong seq = 0UL;
  ulong depth = 128UL;
  int reliable = 0;
  fd_stem_context_t stem = { .mcaches = &mcache, .seqs = &seq, .depths = &depth, .out_reliable = &reliable };
  fd_tower_slot_done_t slot = { .vote_slot = 100UL, .authority_idx = ULONG_MAX };
  handle_vote_msg( &ctx, &stem, &slot );
  FD_TEST( !ctx.identity_submissions.has_slot && !sign_cnt && !seq );
  slot.has_vote_txn = 1;
  slot.vote_slot = ULONG_MAX;
  handle_vote_msg( &ctx, &stem, &slot );
  FD_TEST( !ctx.identity_submissions.has_slot && !sign_cnt && !seq );
  slot.vote_slot = 100UL;
  FD_TEST( vote_txn_sz<=sizeof(slot.vote_txn) );
  memcpy( slot.vote_txn, vote_txn, vote_txn_sz );
  slot.vote_txn_sz = vote_txn_sz;
  handle_vote_msg( &ctx, &stem, &slot );
  FD_TEST( ctx.identity_submissions.has_slot && ctx.identity_submissions.slot==100UL && seq==1UL && sign_cnt==1UL );

  /* Existing replay/Tower barrier still controls acknowledgement.
     A final submission while flushing belongs to the old identity. */
  memcpy( keyswitch.bytes, new_identity, 32UL );
  keyswitch.param = 2UL;
  fd_keyswitch_state( &keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch.state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( !shared.frozen[FD_IDENTITY_FREEZE_TXSEND].generation );
  slot.vote_slot = 101UL;
  handle_vote_msg( &ctx, &stem, &slot );
  ctx.tower_in_expect_seq = 2UL;
  during_housekeeping( &ctx );
  FD_TEST( keyswitch.state==FD_KEYSWITCH_STATE_COMPLETED && keyswitch.result==2UL );
  FD_TEST( !ctx.identity_submissions.has_slot );
  fd_identity_record_t frozen;
  FD_TEST( fd_identity_snapshot_read( &shared.frozen[FD_IDENTITY_FREEZE_TXSEND], &frozen ) );
  FD_TEST( fd_identity_matches( &record, &frozen ) );
  FD_TEST( frozen.has_last_submitted_slot && frozen.last_submitted_slot==101UL );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
