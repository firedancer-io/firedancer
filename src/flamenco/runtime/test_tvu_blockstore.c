/* This tests depends on 1.5 components to run. Specifically, you need to have
   run `fddev dev` to stand up a local Frankendancer.

   This test then intercepts Frankendancer's outgoing shreds by joining the
   dcache (an actual prod node wouldn't do this, but would rather be listening
   for shreds on the turbine socket).

   It then validates the block as shreds come in (signaled via SLOT_COMPLETE).
   
   See `fd_tvu_tile.c` for the non-test counterpart. */

#include "fd_tvu.h"

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_replay_stage.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/types/fd_types.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong   blockstore_key_max   = 1 << 16;
  ulong   blockstore_footprint = fd_blockstore_map_footprint( blockstore_key_max );
  uchar * blockstore_mem =
      (uchar *)fd_wksp_alloc_laddr( wksp, fd_blockstore_map_align(), blockstore_footprint, 1UL );
  FD_TEST( blockstore_mem );
  fd_blockstore_map_t * blockstore =
      fd_blockstore_map_join( fd_blockstore_map_new( blockstore_mem, blockstore_key_max, 42UL ) );
  FD_TEST( blockstore );

  // uchar * block = 
  //     (uchar *)fd_wksp_alloc_laddr( wksp, 128UL, 1 << 20, 1UL );

  // fd_replay_stage_t replay_stage = {
  //     .curr = {.slot = 0, .shred_idx = 0},
  //       .blockstore = blockstore, .block = block
  // };

  uchar const * pod = fd_wksp_pod_attach( "fd1_shred_store.wksp:4096" );
  FD_TEST( pod );

  fd_frag_meta_t * in_mcache = fd_mcache_join( fd_wksp_pod_map( pod, "mcache_shred_store_0" ) );
  FD_TEST( in_mcache );
  uchar * in_dcache = fd_dcache_join( fd_wksp_pod_map( pod, "dcache_shred_store_0" ) );
  FD_TEST( in_dcache );
  ulong * in_fseq = fd_fseq_join( fd_wksp_pod_map( pod, "fseq_shred_store_0_store_0" ) );
  FD_TEST( in_fseq );

  fd_flamenco_boot( &argc, &argv );

//   global_state_t state;
//   fd_memset(&state, 0, sizeof(state));

//   uchar epoch_ctx_mem[FD_EXEC_EPOCH_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_EPOCH_CTX_ALIGN)));
//   state.epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );

//   uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
//   state.slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
//   state.slot_ctx->epoch_ctx = state.epoch_ctx;

//   fd_acc_mgr_t _acc_mgr[1];
//   state.slot_ctx->acc_mgr = fd_acc_mgr_new( _acc_mgr, NULL );

  // int rc = fd_tvu_tile( in_mcache, in_dcache, in_fseq, &replay_stage );
  // FD_LOG_NOTICE( ( "rc %d", rc ) );

  fd_flamenco_halt();
  fd_halt();
  return 0;
}
