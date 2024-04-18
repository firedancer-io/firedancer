#include "../../choreo/fd_choreo.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../shred/fd_shred_cap.h"
#include "../tvu/fd_replay.h"
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define TEST_CONSENSUS_MAGIC ( 0x7e57UL ) /* test */

struct fd_shred_cap_replay_args {
  const char *      shred_cap;
  fd_blockstore_t * blockstore;
  fd_replay_t *     replay;
};
typedef struct fd_shred_cap_replay_args fd_shred_cap_replay_args_t;

int
main( int argc, char ** argv ) {
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
      fd_wksp_alloc_laddr( wksp, FD_EXEC_EPOCH_CTX_ALIGN, FD_EXEC_EPOCH_CTX_FOOTPRINT, 1UL );
  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );
  FD_TEST( epoch_ctx );
  epoch_ctx->valloc = valloc;

  /* forks */

  ulong  forks_max = fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH );
  void * forks_mem =
      fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( forks_max ), 1UL );
  fd_forks_t * forks = fd_forks_join( fd_forks_new( forks_mem, forks_max, 42UL ) );
  FD_TEST( forks );
  fd_fork_t * fork = fd_fork_pool_ele_acquire( forks->pool );

  /* ghost */

  ulong  ghost_node_max = forks_max;
  ulong  ghost_vote_max = 1UL << 16;
  void * ghost_mem      = fd_wksp_alloc_laddr(
      wksp, fd_ghost_align(), fd_ghost_footprint( ghost_node_max, ghost_vote_max ), 1UL );
  fd_ghost_t * ghost =
      fd_ghost_join( fd_ghost_new( ghost_mem, ghost_node_max, ghost_vote_max, 1UL ) );
  FD_TEST( ghost );

  /* towers */

  void * towers_mem =
      fd_wksp_alloc_laddr( wksp, fd_latest_vote_deque_align(), fd_latest_vote_deque_footprint(), 1UL );
  fd_latest_vote_t * towers = fd_latest_vote_deque_join( fd_latest_vote_deque_new( towers_mem ) );
  FD_TEST( towers );

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

  /* slot_ctx */

  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx, valloc ) );
  FD_TEST( slot_ctx );
  slot_ctx->acc_mgr    = acc_mgr;
  slot_ctx->blockstore = blockstore;
  slot_ctx->epoch_ctx  = epoch_ctx;

  /* snapshot restore */

  fd_runtime_recover_banks( slot_ctx, 0 );

  ulong snapshot_slot                = slot_ctx->slot_bank.slot;
  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  FD_TEST( !fd_runtime_sysvar_cache_load( slot_ctx ) );
  fd_features_restore( slot_ctx );
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn );

  replay->smr      = snapshot_slot;
  blockstore->min  = snapshot_slot;
  slot_ctx->leader = fd_epoch_leaders_get( replay->epoch_ctx->leaders, snapshot_slot );

  FD_LOG_NOTICE( ( "snapshot_slot: %lu", snapshot_slot ) );

  /* fake the snapshot slot's block and mark it as processed */

  fd_blockstore_slot_map_t * slot_entry =
      fd_blockstore_slot_map_insert( fd_blockstore_slot_map( replay->blockstore ), snapshot_slot );
  fd_blockstore_slot_map_insert( fd_blockstore_slot_map( replay->blockstore ), snapshot_slot );
  slot_entry->block.data_gaddr = ULONG_MAX;
  slot_entry->block.flags = fd_uchar_set_bit( slot_entry->block.flags, FD_BLOCK_FLAG_SNAPSHOT );
  slot_entry->block.flags = fd_uchar_set_bit( slot_entry->block.flags, FD_BLOCK_FLAG_PROCESSED );
  slot_entry->block.bank_hash = fork->slot_ctx.slot_bank.banks_hash;

  /* initialize various structures to snapshot slot */

  bft->snapshot_slot = snapshot_slot;
  fork->slot         = snapshot_slot;

  /* seed frontier and ghost */

  fd_fork_frontier_ele_insert( replay->forks->frontier, fork, replay->forks->pool );

  fd_slot_hash_t key = { .slot = fork->slot, .hash = fork->slot_ctx.slot_bank.banks_hash };
  fd_ghost_leaf_insert( ghost, &key, NULL );
  FD_TEST( fd_ghost_node_map_ele_query( ghost->node_map, &key, NULL, ghost->node_pool ) );

  /* shred cap replay */

  const char * shred_cap = fd_env_strip_cmdline_cstr( &argc, &argv, "--shred-cap", NULL, NULL );
  if( !shred_cap ) FD_LOG_ERR( ( "must pass in --shred-cap <FILE>" ) );

  fd_halt();
  return 0;
}
