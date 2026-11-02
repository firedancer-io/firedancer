#include "fd_motor_tile.c"

int volatile const fd_startup_skip_checks = 1;

static void *
test_dcache_new( fd_wksp_t * wksp,
                 ulong       depth,
                 ulong       mtu ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  FD_TEST( mem );
  void * dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
  FD_TEST( dcache );
  return dcache;
}

static fd_frag_meta_t *
test_mcache_new( fd_wksp_t * wksp,
                 ulong       depth ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL );
  FD_TEST( mem );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mem, depth, 0UL, 0UL ) );
  FD_TEST( mcache );
  return mcache;
}

/* Pack reads replay_out and Motor replay_slot, independently.
   Exercise work that reaches Motor before its leader notice, then
   retry after the notice. */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, fd_shmem_cpu_idx( 0UL ), "motor_test", 0UL );
  FD_TEST( wksp );

  ulong const depth = 16UL;
  static fd_topo_t topo[1];
  fd_topo_tile_t * tile = topo->tiles;
  topo->workspaces[0].wksp = wksp;
  FD_TEST( fd_pod_new( topo->props, sizeof(topo->props) ) );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  FD_TEST( scratch );
  fd_memset( scratch, 0xA5, scratch_footprint( tile ) );
  topo->objs[0].offset = fd_wksp_gaddr( wksp, scratch );

  char const * names[5] = { "execle_poh", "pack_poh", "replay_slot", "poh_shred", "poh_replay" };
  ulong const mtus[5] = { FD_EXECLE_POH_MTU, sizeof(fd_done_packing_t), sizeof(fd_replay_message_t),
                         FD_POH_SHRED_MTU, sizeof(fd_poh_leader_slot_ended_t) };
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_topo_link_t * link = topo->links+i;
    fd_cstr_ncpy( link->name, names[i], sizeof(link->name) );
    link->mtu           = mtus[i];
    link->dcache_obj_id = i+1UL;
    link->dcache        = test_dcache_new( wksp, depth, mtus[i] );
    topo->objs[i+1UL].id = i+1UL;
    if( i<3UL ) tile->in_link_id[i] = i;
    else        tile->out_link_id[i-3UL] = i;
  }
  tile->in_cnt  = 3UL;
  tile->out_cnt = 2UL;
  unprivileged_init( topo, tile );
  fd_motor_tile_t * ctx = scratch;
  FD_TEST( ctx->slot==ULONG_MAX && !ctx->expect_pack_idx );

  fd_frag_meta_t * mcaches[2] = { test_mcache_new( wksp, depth ), test_mcache_new( wksp, depth ) };
  ulong seqs[2]             = { 0UL, 0UL };
  ulong depths[2]           = { depth, depth };
  int out_reliable[2]       = { 0, 0 };
  fd_stem_context_t stem[1] = {{ .mcaches=mcaches, .seqs=seqs, .depths=depths, .out_reliable=out_reliable }};

  ulong execle_chunk = ctx->in[0].chunk0;
  ulong pack_chunk   = ctx->in[1].chunk0;
  ulong replay_chunk = ctx->in[2].chunk0;
  fd_txn_p_t * txn           = fd_chunk_to_laddr( wksp, execle_chunk );
  fd_done_packing_t * done   = fd_chunk_to_laddr( wksp, pack_chunk );
  void * replay_frag        = fd_chunk_to_laddr( wksp, replay_chunk );

  /* Slot zero must also wait for the first leader notice. */
  FD_TEST( before_frag( ctx, 0UL, 0UL, fd_disco_execle_sig( 0UL, 0UL ) )==-1 );
  FD_TEST( before_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( 0UL, 0UL ) )==-1 );

  for( ulong slot=1UL; slot<=2UL; slot++ ) {
    uint pack_idx = ctx->expect_pack_idx;
    ulong execle_sig = fd_disco_execle_sig( slot, pack_idx );
    ulong pack_sig   = fd_disco_execle_sig( slot, pack_idx+1U );
    FD_TEST( before_frag( ctx, 0UL, 0UL, execle_sig )==-1 );
    FD_TEST( before_frag( ctx, 1UL, 0UL, pack_sig )==-1 );
    FD_TEST( before_frag( ctx, 1UL, 0UL, FD_PACK_MSG_DONE_DRAINING )==1 );
    FD_TEST( before_frag( ctx, 1UL, 0UL, FD_PACK_MSG_REDUCE_MB_BOUND )==1 );

    fd_poh_reset_t * reset = replay_frag;
    fd_memset( reset, 0, sizeof(*reset) );
    reset->completed_slot = slot-1UL;
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_RESET, replay_chunk, sizeof(*reset), 0UL, 0UL, 0UL, stem ) );
    fd_became_leader_t * leader = replay_frag;
    fd_memset( leader, 0, sizeof(*leader) );
    leader->slot = slot;
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_BECAME_LEADER, replay_chunk, sizeof(*leader), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->slot==slot && ctx->expect_pack_idx==pack_idx );

    /* Stale work consumes its pack_idx without being processed. */
    ulong stale_sig = fd_disco_execle_sig( slot-1UL, pack_idx );
    FD_TEST( !before_frag( ctx, 0UL, 0UL, stale_sig ) );
    FD_TEST( !before_frag( ctx, 1UL, 0UL, stale_sig ) );
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, stale_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->expect_pack_idx==pack_idx+1U && seqs[0]==4UL*(slot-1UL)+1UL && seqs[1]==slot-1UL );
    pack_idx++;
    execle_sig = fd_disco_execle_sig( slot, pack_idx );
    pack_sig   = fd_disco_execle_sig( slot, pack_idx+1U );

    fd_memset( done, 0, sizeof(*done) );
    done->end_slot_reason = FD_PACK_END_SLOT_REASON_TIME;
    done->microblocks_in_slot = 1UL;
    FD_TEST( !before_frag( ctx, 1UL, 0UL, pack_sig ) );
    FD_TEST( returnable_frag( ctx, 1UL, 0UL, pack_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem )==1 );
    FD_TEST( ctx->expect_pack_idx==pack_idx && seqs[1]==slot-1UL );

    fd_memset( txn, 0, sizeof(*txn) );
    txn->flags      = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    txn->payload_sz = FD_TXN_SIGNATURE_SZ;
    fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)(txn+1);
    fd_memset( trailer, 0, sizeof(*trailer) );
    FD_TEST( !before_frag( ctx, 0UL, 0UL, execle_sig ) );
    FD_TEST( !returnable_frag( ctx, 0UL, 0UL, execle_sig, execle_chunk, sizeof(*txn)+sizeof(*trailer), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->expect_pack_idx==pack_idx+1U && seqs[0]==4UL*(slot-1UL)+2UL );
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, pack_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->expect_pack_idx==pack_idx+2U && seqs[1]==slot );
    fd_poh_leader_slot_ended_t const * ended = fd_chunk_to_laddr_const( wksp, mcaches[1][slot-1UL].chunk );
    FD_TEST( ended->completed && ended->slot==slot && ended->microblock_count==1UL );

    fd_replay_leader_footer_t * footer = replay_frag;
    fd_memset( footer, 0, sizeof(*footer) );
    footer->slot = slot;
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_LEADER_FOOTER, replay_chunk, sizeof(*footer), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[0]==4UL*slot && seqs[1]==slot );
    fd_entry_batch_meta_t const * meta = fd_chunk_to_laddr_const( wksp, mcaches[0][4UL*slot-1UL].chunk );
    FD_TEST( meta->block_complete==1 );
  }

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
