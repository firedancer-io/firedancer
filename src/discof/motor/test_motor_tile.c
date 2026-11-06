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

    /* The leader notice carries the parent: the header names it, the
       first entry batch chains to its last FEC set, and its blockhash
       seeds the PoH hash. */
    fd_became_leader_t * leader = replay_frag;
    fd_memset( leader, 0, sizeof(*leader) );
    leader->slot        = slot;
    leader->parent_slot = slot-1UL;
    fd_memset( leader->parent_cmr.uc,       (int)( 0x10UL+slot ), sizeof(fd_hash_t) );
    fd_memset( leader->parent_dmr.uc,       (int)( 0x20UL+slot ), sizeof(fd_hash_t) );
    fd_memset( leader->parent_blockhash.uc, (int)( 0x30UL+slot ), sizeof(fd_hash_t) );
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_BECAME_LEADER, replay_chunk, sizeof(*leader), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->slot==slot && ctx->expect_pack_idx==pack_idx );
    FD_TEST( ctx->parent_slot==slot-1UL );
    FD_TEST( fd_hash_eq( &ctx->poh_hash, &leader->parent_blockhash ) );
    fd_frag_meta_t const *        header_frag = mcaches[0] + fd_mcache_line_idx( 4UL*(slot-1UL), depth );
    fd_entry_batch_meta_t const * header_meta = fd_chunk_to_laddr_const( wksp, header_frag->chunk );
    FD_TEST( header_meta->parent_offset==1UL && header_meta->parent_block_id_valid );
    FD_TEST( !memcmp( header_meta->parent_block_id, leader->parent_cmr.uc, sizeof(fd_hash_t) ) );
    fd_block_marker_t header[1];
    FD_TEST( fd_block_marker_de( header, (uchar const *)( header_meta+1 ), header_frag->sz-sizeof(fd_entry_batch_meta_t) )==FD_BLOCK_MARKER_DE_SUCCESS );
    FD_TEST( header->kind==FD_BLOCK_MARKER_KIND_HEADER && header->header.parent_slot==slot-1UL );
    FD_TEST( fd_hash_eq( &header->header.parent_block_id, &leader->parent_dmr ) );

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

  /* Fast leader handover: a slot pack gave up (its optimistic parent
     never confirmed) ends with no alpentick, reported aborted. */
  {
    ulong slot = 3UL;
    fd_became_leader_t * leader = replay_frag;
    fd_memset( leader, 0, sizeof(*leader) );
    leader->slot        = slot;
    leader->parent_slot = 2UL;
    fd_memset( leader->parent_blockhash.uc, 0x33, sizeof(fd_hash_t) );
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_BECAME_LEADER, replay_chunk, sizeof(*leader), 0UL, 0UL, 0UL, stem ) );
    fd_hash_t poh0 = ctx->poh_hash;

    uint  pack_idx = ctx->expect_pack_idx;
    ulong rseq0    = seqs[1];
    fd_memset( done, 0, sizeof(*done) );
    done->end_slot_reason = FD_PACK_END_SLOT_REASON_ABANDONED;
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( slot, pack_idx ), pack_chunk, sizeof(*done), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[1]==rseq0+1UL );
    FD_TEST( !memcmp( ctx->poh_hash.uc, poh0.uc, sizeof(fd_hash_t) ) ); /* no alpentick */
    fd_poh_leader_slot_ended_t const * ended = fd_chunk_to_laddr_const( wksp, mcaches[1][ fd_mcache_line_idx( rseq0, depth ) ].chunk );
    FD_TEST( !ended->completed && ended->slot==slot && ended->pack_end_reason==FD_PACK_END_SLOT_REASON_ABANDONED );
  }

  /* Fast leader handover, sad path: our slot switches parent.  Pack's
     prefix_drained, after the old bank's last microblock, makes motor
     send the UpdateParent marker naming the new parent as a batch of
     its own, with the header's parent offset, and tell replay the old
     bank is drained. */
  {
    ulong slot = 4UL;
    fd_became_leader_t * leader = replay_frag;
    fd_memset( leader, 0, sizeof(*leader) );
    leader->slot        = slot;
    leader->parent_slot = 3UL;
    leader->bank_seq    = 40UL;
    fd_memset( leader->parent_blockhash.uc, 0x44, sizeof(fd_hash_t) );
    ulong sseq0 = seqs[0];
    FD_TEST( !returnable_frag( ctx, 2UL, 0UL, REPLAY_SIG_BECAME_LEADER, replay_chunk, sizeof(*leader), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[0]==sseq0+1UL ); /* the header */

    /* An old bank microblock goes into the prefix. */
    uint pack_idx = ctx->expect_pack_idx;
    fd_memset( txn, 0, sizeof(*txn) );
    txn->flags      = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    txn->payload_sz = FD_TXN_SIGNATURE_SZ;
    fd_microblock_trailer_t * trailer = (fd_microblock_trailer_t *)(txn+1);
    fd_memset( trailer, 0, sizeof(*trailer) );
    trailer->bank_seq = 40UL;
    FD_TEST( !returnable_frag( ctx, 0UL, 0UL, fd_disco_execle_sig( slot, pack_idx ), execle_chunk, sizeof(*txn)+sizeof(*trailer), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[0]==sseq0+2UL );
    pack_idx++;

    ulong rseq0 = seqs[1];
    fd_pack_prefix_drained_t * drained = (fd_pack_prefix_drained_t *)done;
    fd_memset( drained, 0, sizeof(*drained) );
    drained->slot        = slot;
    drained->parent_slot = 1UL;
    fd_memset( drained->parent_dmr, 0x55, sizeof(fd_hash_t) );
    drained->bank_idx    = 7UL;
    drained->bank_seq    = 40UL;
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( slot, pack_idx ), pack_chunk, sizeof(*drained), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( ctx->expect_pack_idx==pack_idx+1U );

    FD_TEST( seqs[0]==sseq0+3UL );
    fd_frag_meta_t const *        mfrag = mcaches[0] + fd_mcache_line_idx( sseq0+2UL, depth );
    fd_entry_batch_meta_t const * mmeta = fd_chunk_to_laddr_const( wksp, mfrag->chunk );
    FD_TEST( mmeta->block_complete==-1 && mmeta->parent_offset==1UL );
    fd_block_marker_t marker[1];
    FD_TEST( fd_block_marker_de( marker, (uchar const *)( mmeta+1 ), mfrag->sz-sizeof(fd_entry_batch_meta_t) )==FD_BLOCK_MARKER_DE_SUCCESS );
    FD_TEST( marker->kind==FD_BLOCK_MARKER_KIND_UPDATE_PARENT && marker->update_parent.new_parent_slot==1UL );
    FD_TEST( !memcmp( marker->update_parent.new_parent_block_id.uc, drained->parent_dmr, sizeof(fd_hash_t) ) );

    FD_TEST( seqs[1]==rseq0+1UL );
    fd_frag_meta_t const * rfrag = mcaches[1] + fd_mcache_line_idx( rseq0, depth );
    FD_TEST( rfrag->sig==FD_POH_SIG_PREFIX_DRAINED && rfrag->sz==sizeof(fd_poh_prefix_drained_t) );
    fd_poh_prefix_drained_t const * report = fd_chunk_to_laddr_const( wksp, rfrag->chunk );
    FD_TEST( report->slot==slot && report->bank_idx==7UL && report->bank_seq==40UL );
    pack_idx++;

    /* resume: the new bank's entries chain from the new parent's
       alpentick, and its microblocks go after the marker. */
    fd_pack_resume_t * resume = (fd_pack_resume_t *)done;
    fd_memset( resume, 0, sizeof(*resume) );
    resume->slot = slot;
    fd_memset( resume->parent_blockhash, 0x66, sizeof(fd_hash_t) );
    FD_TEST( !returnable_frag( ctx, 1UL, 0UL, fd_disco_execle_sig( slot, pack_idx ), pack_chunk, sizeof(*resume), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( !memcmp( ctx->poh_hash.uc, resume->parent_blockhash, sizeof(fd_hash_t) ) );
    FD_TEST( seqs[0]==sseq0+3UL && seqs[1]==rseq0+1UL ); /* nothing published */
    pack_idx++;

    fd_hash_t poh_before = ctx->poh_hash;
    trailer->bank_seq = 41UL;
    FD_TEST( !returnable_frag( ctx, 0UL, 0UL, fd_disco_execle_sig( slot, pack_idx ), execle_chunk, sizeof(*txn)+sizeof(*trailer), 0UL, 0UL, 0UL, stem ) );
    FD_TEST( seqs[0]==sseq0+4UL );
    fd_entry_batch_meta_t const * emeta = fd_chunk_to_laddr_const( wksp, mcaches[0][ fd_mcache_line_idx( sseq0+3UL, depth ) ].chunk );
    fd_entry_batch_header_t const * entry = (fd_entry_batch_header_t const *)( emeta+1 );
    uchar data[ 64 ]; fd_hash_t expect;
    memcpy( data,      poh_before.uc,  sizeof(fd_hash_t) );
    memcpy( data+32UL, trailer->hash, sizeof(fd_hash_t) );
    fd_sha256_hash( data, sizeof(data), expect.uc );
    FD_TEST( !memcmp( entry->hash, expect.uc, sizeof(fd_hash_t) ) );
  }

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
