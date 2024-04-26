#include "./test_consensus.h"

#define TEST_CONSENSUS_MAGIC ( 0x7e57UL ) /* test */

void          online_archive_init(int argc, char ** argv);
fd_replay_t * offline_replay_init(int argc, char ** argv);

int
main( int argc, char ** argv ) {
  const char * _shredcap = fd_env_strip_cmdline_cstr( &argc, &argv, "--shredcap", NULL, NULL );

  if( _shredcap ) {
    /* Replay shreds from the shredcap file */
    fd_replay_t * replay = offline_replay_init(argc, argv);
    fd_shred_cap_replay( _shredcap, replay );  
  } else {
    /* Capture live shreds from turbine & repair */
    online_archive_init(argc, argv);
  }
  
  fd_halt();
  return 0;
}

/* Local variables for online archive */
static int gossip_sockfd = -1;
//static int repair_sockfd = -1;
static fd_keyguard_client_t keyguard_client;
static fd_tvu_gossip_deliver_arg_t gossip_deliver_arg;

#include "./test_consensus_helper.c"

void online_archive_init(int argc, char** argv) {
  /* arguments */
  const char * _gossip_addr = "139.178.68.207:8001"; /* temporary */
  const char * _snapshot = fd_env_strip_cmdline_cstr( &argc, &argv, "--snapshot", NULL, NULL );
  if (!_snapshot) FD_LOG_ERR( ( "must pass in one of --snapshot <FILE> and --shredcap <FILE>" ) );

  /* wksp */
  ulong  page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL );
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* allocator */
  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_CONSENSUS_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_CONSENSUS_MAGIC );
  fd_alloc_t * alloc         = fd_alloc_join( alloc_shalloc, 0UL );
  fd_valloc_t  valloc        = fd_alloc_virtual( alloc );

  /* gossip */
  //FIXME, initialize bft and repair
  //gossip_deliver_arg->bft = bft;
  //gossip_deliver_arg->repair = repair;
  gossip_deliver_arg.valloc = valloc;

  void *        gossip_shmem = fd_wksp_alloc_laddr( wksp, fd_gossip_align(), fd_gossip_footprint(), TEST_CONSENSUS_MAGIC );
  fd_gossip_t * gossip       = fd_gossip_join( fd_gossip_new( gossip_shmem, TEST_CONSENSUS_MAGIC, valloc ) );
  fd_gossip_config_t gossip_config;
  gossip_config.shred_version = 0;
  gossip_config.deliver_fun   = gossip_deliver_fun;
  gossip_config.deliver_arg   = &gossip_deliver_arg;
  gossip_config.send_fun      = gossip_send_packet;
  gossip_config.send_arg      = NULL;
  gossip_config.sign_fun      = signer_fun;
  gossip_config.sign_arg      = &keyguard_client;
  FD_TEST ( fd_gossip_set_config( gossip, &gossip_config ) );

  fd_gossip_peer_addr_t gossip_peer_addr;
  FD_TEST ( resolve_hostport( _gossip_addr, &gossip_peer_addr ) );

  if( fd_gossip_add_active_peer(
            gossip, resolve_hostport( _gossip_addr, &gossip_peer_addr ) ) )
      FD_LOG_ERR( ( "error adding gossip active peer" ) );
  
  FD_LOG_ERR( ( "online_archive_init not ready yet" ) );
}

fd_replay_t * offline_replay_init(int argc, char ** argv) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* wksp */

  ulong  page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL );
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* restore */

  const char * restore = fd_env_strip_cmdline_cstr( &argc, &argv, "--restore", NULL, NULL );
  if( !restore ) FD_LOG_ERR( ( "must pass in --restore <FILE>" ) );

  FD_LOG_NOTICE( ( "fd_wksp_restore %s", restore ) );
  int err = fd_wksp_restore( wksp, restore, 42 );
  if( err ) FD_LOG_ERR( ( "fd_wksp_restore failed: error %d", err ) );

  /* funk */

  fd_wksp_tag_query_info_t funk_info;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( wksp, &funk_tag, 1, &funk_info, 1 ) == 0 ) {
    FD_LOG_ERR( ( "failed to find a funky" ) );
  }
  void *      shfunk = fd_wksp_laddr_fast( wksp, funk_info.gaddr_lo );
  fd_funk_t * funk   = fd_funk_join( shfunk );
  FD_TEST( funk );

  /* blockstore */

  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( wksp, &blockstore_tag, 1, &blockstore_info, 1 ) == 0 ) {
    FD_LOG_ERR( ( "failed to find a blockstore" ) );
  }
  void *            shblockstore = fd_wksp_laddr_fast( wksp, blockstore_info.gaddr_lo );
  fd_blockstore_t * blockstore   = fd_blockstore_join( shblockstore );
  FD_TEST( blockstore );
  fd_blockstore_clear( blockstore );

  /* allocator */

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_CONSENSUS_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_CONSENSUS_MAGIC );
  fd_alloc_t * alloc         = fd_alloc_join( alloc_shalloc, 0UL );
  fd_valloc_t  valloc        = fd_alloc_virtual( alloc );

  /* scratch */

  ulong smax   = 1UL << 21;
  ulong sdepth = 128;
  FD_LOG_NOTICE( ( "smem footprint %lu", fd_scratch_smem_footprint( smax ) ) );
  FD_TEST( fd_scratch_smem_footprint( smax ) > 765312 );
  void * smem =
      fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ), 1UL );
  void * fmem = fd_wksp_alloc_laddr(
      wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 1UL );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /* acc mgr */

  fd_acc_mgr_t acc_mgr[1];
  fd_acc_mgr_new( acc_mgr, funk );

  /* epoch_ctx */

  uchar * epoch_ctx_mem =
      fd_wksp_alloc_laddr( wksp, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint(), 1UL );
  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );
  FD_TEST( epoch_ctx );

  /* forks */

  ulong  forks_max = fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH );
  void * forks_mem =
      fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( forks_max ), 1UL );
  fd_forks_t * forks = fd_forks_join( fd_forks_new( forks_mem, forks_max, 42UL ) );
  FD_TEST( forks );

  /* ghost */

  ulong  ghost_node_max = forks_max;
  ulong  ghost_vote_max = 1UL << 16;
  void * ghost_mem      = fd_wksp_alloc_laddr(
      wksp, fd_ghost_align(), fd_ghost_footprint( ghost_node_max, ghost_vote_max ), 1UL );
  fd_ghost_t * ghost =
      fd_ghost_join( fd_ghost_new( ghost_mem, ghost_node_max, ghost_vote_max, 1UL ) );
  FD_TEST( ghost );

  /* latest votes */

//   void * latest_votes_mem = fd_wksp_alloc_laddr(
//       wksp, fd_latest_vote_deque_align(), fd_latest_vote_deque_footprint(), 42UL );
//   fd_latest_vote_t * latest_votes =
//       fd_latest_vote_deque_join( fd_latest_vote_deque_new( latest_votes_mem ) );
//   FD_TEST( latest_votes );

  /* bft */

  void *     bft_mem = fd_wksp_alloc_laddr( wksp, fd_bft_align(), fd_bft_footprint(), 1UL );
  fd_bft_t * bft     = fd_bft_join( fd_bft_new( bft_mem ) );
  bft->acc_mgr       = acc_mgr;
  bft->blockstore    = blockstore;
  bft->commitment    = NULL;
  bft->forks         = forks;
  bft->ghost         = ghost;
  bft->valloc        = valloc;
  // TODO can this change within an epoch?
  fd_bft_epoch_stake_update( bft, epoch_ctx );

  /* replay */

  void * replay_mem    = fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint(), 1UL );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem ) );
  FD_TEST( replay );
  replay->acc_mgr     = acc_mgr;
  replay->blockstore  = blockstore;
  replay->epoch_ctx   = epoch_ctx;
  replay->forks       = forks;
  replay->funk        = funk;
  replay->gossip      = NULL;
  replay->max_workers = 1;
  replay->tpool       = NULL;
  replay->valloc      = valloc;

  /* snapshot init */

  fd_fork_t *          snapshot_fork = fd_fork_pool_ele_acquire( forks->pool );
  fd_exec_slot_ctx_t * snapshot_slot_ctx =
      fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &snapshot_fork->slot_ctx, valloc ) );
  FD_TEST( snapshot_slot_ctx );

  snapshot_slot_ctx->epoch_ctx  = epoch_ctx;
  snapshot_slot_ctx->acc_mgr    = acc_mgr;
  snapshot_slot_ctx->blockstore = blockstore;
  snapshot_slot_ctx->valloc     = valloc;

  fd_runtime_recover_banks( snapshot_slot_ctx, 0 );
  FD_TEST( snapshot_slot_ctx->funk_txn );

  ulong snapshot_slot = snapshot_slot_ctx->slot_bank.slot;
  FD_LOG_NOTICE( ( "snapshot_slot: %lu", snapshot_slot ) );

  snapshot_slot_ctx->slot_bank.collected_fees = 0;
  snapshot_slot_ctx->slot_bank.collected_rent = 0;
  FD_TEST( !fd_runtime_sysvar_cache_load( snapshot_slot_ctx ) );
  fd_features_restore( snapshot_slot_ctx );
  fd_runtime_update_leaders( snapshot_slot_ctx, snapshot_slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( snapshot_slot_ctx );
  fd_bpf_scan_and_create_bpf_program_cache_entry( snapshot_slot_ctx, snapshot_slot_ctx->funk_txn );
  snapshot_slot_ctx->leader =
      fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( replay->epoch_ctx ), snapshot_slot );

  /* snapshot init: blockstore */

  fd_blockstore_snapshot_insert( blockstore, &snapshot_slot_ctx->slot_bank );

  /* snapshot init: replay */

  replay->smr = snapshot_slot;

  /* snapshot init: forks */

  snapshot_fork->slot = snapshot_slot;
  fd_fork_frontier_ele_insert( replay->forks->frontier, snapshot_fork, replay->forks->pool );

  /* snapshot init: ghost */

  fd_slot_hash_t key = { .slot = snapshot_fork->slot,
                         .hash = snapshot_fork->slot_ctx.slot_bank.banks_hash };
  fd_ghost_leaf_insert( ghost, &key, NULL );
  FD_TEST( fd_ghost_node_map_ele_query( ghost->node_map, &key, NULL, ghost->node_pool ) );

  /* snapshot init: bft */

  bft->snapshot_slot = snapshot_slot;

  return replay;
}
