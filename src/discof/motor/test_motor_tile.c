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

static fd_pack_vclock_t
test_deps( uint execle0,
           uint execle1,
           uint done_packing ) {
  /* Entries past the live ones are never read, fill them with junk. */
  fd_pack_vclock_t deps;
  fd_memset( &deps, 0xA5, sizeof(deps) );
  deps.execle[ 0 ]  = execle0;
  deps.execle[ 1 ]  = execle1;
  deps.done_packing = done_packing;
  return deps;
}

/* Counters wrap, so readiness must compare through the signed
   difference. */

static void
test_deps_wrap( void ) {
  fd_pack_vclock_t seen = test_deps( 0xFFFFFFFEU, 0U, 0U );
  fd_pack_vclock_t deps = test_deps( 1U,          0U, 0U ); /* 3 frags ahead, across the wrap */
  FD_TEST( !fd_pack_vclock_covers( &seen, &deps, 2UL ) );
  seen = test_deps( 1U,          0U, 0U );
  deps = test_deps( 0xFFFFFFFFU, 0U, 0U ); /* 2 frags behind, across the wrap */
  FD_TEST( fd_pack_vclock_covers( &seen, &deps, 2UL ) );
  FD_TEST( fd_pack_vclock_admit( &seen, &deps, 0UL, 2UL ) );
  FD_TEST( seen.execle[ 0 ]==2U );

  /* done_packing waits for its pack_idx frags, counted across the
     wrap. */
  seen = test_deps( 0xFFFFFFFFU, 1U, 0U );
  FD_TEST( !fd_pack_vclock_admit_done_packing( &seen, 1U, 2UL ) );
  FD_TEST( fd_pack_vclock_admit_done_packing( &seen, 0U, 2UL ) );
  FD_TEST( seen.done_packing==1U );

  /* fd_pack_vclock_copy copies the live entries only. */
  fd_pack_vclock_t dst;
  fd_memset( &dst, 0, sizeof(dst) );
  fd_pack_vclock_copy( &dst, &deps, 2UL );
  FD_TEST( dst.done_packing==0U && dst.execle[ 0 ]==0xFFFFFFFFU );
  FD_TEST( dst.execle[ 1 ]==0U && dst.execle[ 2 ]==0U );
}

/* test_microblock sends Motor a microblock with one executed txn on
   input link in_idx, and returns what returnable_frag returned. */

static int
test_microblock( fd_motor_tile_t *        ctx,
                 fd_stem_context_t *      stem,
                 ulong                    in_idx,
                 ulong                    slot,
                 uint                     pack_idx,
                 fd_pack_vclock_t const * deps ) {
  ulong chunk = ctx->in[ in_idx ].chunk0;
  fd_txn_p_t * txn = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
  fd_memset( txn, 0, sizeof(*txn) );
  txn->flags      = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  txn->payload_sz = FD_TXN_SIGNATURE_SZ;
  fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)(txn+1);
  fd_memset( trailer, 0, sizeof(*trailer) );
  trailer->deps = *deps;
  ulong sig = fd_disco_execle_sig( slot, pack_idx );
  FD_TEST( !before_frag( ctx, in_idx, 0UL, sig ) );
  return returnable_frag( ctx, in_idx, 0UL, sig, chunk, sizeof(*txn)+sizeof(*trailer), 0UL, 0UL, 0UL, stem );
}

/* Pack reads replay_out and Motor replay_slot, independently.
   Exercise work that reaches Motor before its leader notice, then
   retry after the notice.  Then check that microblocks are held only
   behind the frags pack says they depend on. */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_deps_wrap();
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

  /* Two execle tiles: input links 0 and 3. */
  char const * names[6] = { "execle_poh", "pack_poh", "replay_slot", "execle_poh", "poh_shred", "poh_replay" };
  ulong const mtus[6] = { FD_EXECLE_POH_MTU, sizeof(fd_done_packing_t), sizeof(fd_replay_message_t),
                         FD_EXECLE_POH_MTU, FD_POH_SHRED_MTU, sizeof(fd_poh_leader_slot_ended_t) };
  for( ulong i=0UL; i<6UL; i++ ) {
    fd_topo_link_t * link = topo->links+i;
    fd_cstr_ncpy( link->name, names[i], sizeof(link->name) );
    link->kind_id       = fd_ulong_if( i==3UL, 1UL, 0UL );
    link->mtu           = mtus[i];
    link->dcache_obj_id = i+1UL;
    link->dcache        = test_dcache_new( wksp, depth, mtus[i] );
    topo->objs[i+1UL].id = i+1UL;
    if( i<4UL ) tile->in_link_id[i] = i;
    else        tile->out_link_id[i-4UL] = i;
  }
  tile->in_cnt  = 4UL;
  tile->out_cnt = 2UL;
  unprivileged_init( topo, tile );
  fd_motor_tile_t * ctx = scratch;
  FD_TEST( ctx->slot==ULONG_MAX && ctx->execle_cnt==2UL );
  FD_TEST( ctx->in_execle[0]==0UL && ctx->in_execle[3]==1UL );
  FD_TEST( !ctx->seen.done_packing );
  for( ulong i=0UL; i<FD_PACK_MAX_EXECLE_TILES; i++ ) FD_TEST( !ctx->seen.execle[ i ] );

  fd_frag_meta_t * mcaches[2] = { test_mcache_new( wksp, depth ), test_mcache_new( wksp, depth ) };
  ulong seqs[2]             = { 0UL, 0UL };
  ulong depths[2]           = { depth, depth };
  int out_reliable[2]       = { 0, 0 };
  fd_stem_context_t stem[1] = {{ .mcaches=mcaches, .seqs=seqs, .depths=depths, .out_reliable=out_reliable }};

  ulong pack_chunk   = ctx->in[1].chunk0;
  ulong replay_chunk = ctx->in[2].chunk0;
  fd_done_packing_t * done   = fd_chunk_to_laddr( wksp, pack_chunk );
  void * replay_frag        = fd_chunk_to_laddr( wksp, replay_chunk );

  /* Slot zero must also wait for the first leader notice. */
  FD_TEST( before_frag( ctx, 0UL, 0UL, fd_disco_execle_sig( 0UL, 0UL ) )==-1 );
  FD_TEST( before_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( 0UL, 0UL ) )==-1 );

  uint pack_idx = 0U;
  for( ulong slot=1UL; slot<=2UL; slot++ ) {
    uint e0 = ctx->seen.execle[ 0 ];
    uint e1 = ctx->seen.execle[ 1 ];
    uint pk = ctx->seen.done_packing;

    FD_TEST( before_frag( ctx, 0UL, 0UL, fd_disco_execle_sig( slot, pack_idx ) )==-1 );
    FD_TEST( before_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( slot, pack_idx ) )==-1 );
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
    FD_TEST( ctx->slot==slot );
    ulong s0 = seqs[0];
    ulong s1 = seqs[1];

    /* Stale work is counted without being processed. */
    ulong stale_sig = fd_disco_execle_sig( slot-1UL, pack_idx );
    FD_TEST( !before_frag( ctx, 1UL, 0UL, stale_sig ) );
    fd_memset( done, 0, sizeof(*done) );
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, stale_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->seen.done_packing==pk+1U && seqs[0]==s0 && seqs[1]==s1 );
    pack_idx++;
    pk++;

    /* Pack schedules A on execle 0, then B on execle 1 while A is still
       executing, so B does not depend on A.  Once A completes, pack
       schedules C on execle 1, which depends on A (and B). */
    fd_pack_vclock_t deps_a = test_deps( e0,     e1,     pk );
    fd_pack_vclock_t deps_b = test_deps( e0,     e1,     pk );
    fd_pack_vclock_t deps_c = test_deps( e0+1U,  e1+1U,  pk );
    uint idx_a = pack_idx;
    uint idx_b = pack_idx+1U;
    uint idx_c = pack_idx+2U;
    uint idx_d = pack_idx+3U;
    pack_idx += 4U;

    /* done_packing waits for every microblock of the slot. */
    ulong done_sig = fd_disco_execle_sig( slot, idx_d );
    fd_memset( done, 0, sizeof(*done) );
    done->end_slot_reason     = FD_PACK_END_SLOT_REASON_TIME;
    done->microblocks_in_slot = 3UL;
    FD_TEST( !before_frag( ctx, 1UL, 0UL, done_sig ) );
    FD_TEST( returnable_frag( ctx, 1UL, 0UL, done_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem )==1 );
    FD_TEST( ctx->seen.done_packing==pk && seqs[1]==s1 );

    /* B overtakes A, which is still executing. */
    FD_TEST( !test_microblock( ctx, stem, 3UL, slot, idx_b, &deps_b ) );
    FD_TEST( ctx->seen.execle[ 1 ]==e1+1U && seqs[0]==s0+1UL );

    /* C is held until A is processed. */
    FD_TEST( test_microblock( ctx, stem, 3UL, slot, idx_c, &deps_c )==1 );
    FD_TEST( ctx->seen.execle[ 1 ]==e1+1U && seqs[0]==s0+1UL );
    FD_TEST( !test_microblock( ctx, stem, 0UL, slot, idx_a, &deps_a ) );
    FD_TEST( ctx->seen.execle[ 0 ]==e0+1U && seqs[0]==s0+2UL );
    FD_TEST( !test_microblock( ctx, stem, 3UL, slot, idx_c, &deps_c ) );
    FD_TEST( ctx->seen.execle[ 1 ]==e1+2U && seqs[0]==s0+3UL );

    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, done_sig, pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->seen.done_packing==pk+1U && seqs[1]==s1+1UL );
    fd_poh_leader_slot_ended_t const * ended = fd_chunk_to_laddr_const( wksp, mcaches[1][ seqs[1]-1UL ].chunk );
    FD_TEST( ended->completed && ended->slot==slot && ended->microblock_count==3UL );

    fd_replay_leader_footer_t * footer = replay_frag;
    fd_memset( footer, 0, sizeof(*footer) );
    footer->slot = slot;
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_LEADER_FOOTER, replay_chunk, sizeof(*footer), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[0]==s0+5UL && seqs[1]==s1+1UL );
    fd_entry_batch_meta_t const * meta = fd_chunk_to_laddr_const( wksp, mcaches[0][ seqs[0]-1UL ].chunk );
    FD_TEST( meta->block_complete==1 );
  }

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
