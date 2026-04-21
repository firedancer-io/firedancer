/* fd_solfuzz.c contains support routines */

#define _GNU_SOURCE
#include "fd_solfuzz.h"
#include "../fd_bank.h"
#include "../fd_runtime_stack.h"
#include "../fd_runtime.h"
#include <errno.h>
#include <sys/mman.h>
#include "../../../util/shmem/fd_shmem_private.h"

fd_wksp_t *
fd_wksp_demand_paged_new( char const * name,
                          uint         seed,
                          ulong        part_max,
                          ulong        data_max ) {
  ulong footprint = fd_wksp_footprint( part_max, data_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid workspace params (part_max=%lu data_max=%lu)", part_max, data_max ));
    return NULL;
  }

  /* Round up footprint to nearest huge page size */
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_HUGE_PAGE_SZ );

  /* Acquire anonymous demand-paged memory */
  void * mem = fd_shmem_private_map_rand( footprint, FD_SHMEM_HUGE_PAGE_SZ, PROT_READ|PROT_WRITE );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "fd_shmem_private_map_rand() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Indicate to kernel that hugepages are a fine backing store
     (Transparent Huge Pages) */
  if( FD_UNLIKELY( 0!=madvise( mem, footprint, MADV_HUGEPAGE ) ) ) {
    FD_LOG_WARNING(( "madvise() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    munmap( mem, footprint );
    return NULL;
  }

  /* Create workspace */
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, name, seed, part_max, data_max ) );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "fd_wksp_new() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    munmap( mem, footprint );
    return NULL;
  }

  /* Register shared memory region */
  ulong fake_page_cnt = footprint>>FD_SHMEM_HUGE_LG_PAGE_SZ;
  int join_err = fd_shmem_join_anonymous(
      name,
      FD_SHMEM_JOIN_MODE_READ_WRITE,
      wksp,
      mem,
      FD_SHMEM_HUGE_PAGE_SZ,
      fake_page_cnt
  );
  if( FD_UNLIKELY( join_err ) ) {
    FD_LOG_WARNING(( "fd_shmem_join_anonymous() failed (%i-%s)", join_err, fd_io_strerror( join_err ) ));
    fd_wksp_delete( fd_wksp_leave( wksp ) );
    munmap( mem, footprint );
    return NULL;
  }

  return wksp;
}

void
fd_wksp_demand_paged_delete( fd_wksp_t * wksp ) {
  fd_shmem_leave_anonymous( wksp, NULL );
  FD_TEST( fd_wksp_delete( fd_wksp_leave( wksp ) ) );
}

fd_solfuzz_runner_t *
fd_solfuzz_runner_new( fd_wksp_t *                         wksp,
                       ulong                               wksp_tag,
                       fd_solfuzz_runner_options_t const * options ) {

  /* Allocate objects */
  ulong const txn_max  = 16UL;
  ulong const rec_max  = 1024UL;
  ulong const spad_max = 1500000000UL; /* 1.5GB to accommodate 128 accounts 10MB each */
  ulong const bank_max = 2UL;
  ulong const fork_max = 2UL;

  ulong const max_accounts        = rec_max;
  ulong const max_live_slots       = txn_max;
  ulong const writes_per_slot      = 1024UL;
  ulong const partition_cnt        = 8192UL;
  ulong const partition_sz         = (1UL<<30UL);
  ulong const cache_footprint      = (16UL<<30UL);

  ulong accdb_shmem_sz = fd_accdb_shmem_footprint( max_accounts, max_live_slots,
                                                    writes_per_slot, partition_cnt,
                                                    cache_footprint, 1UL );
  ulong accdb_join_sz  = fd_accdb_footprint( max_live_slots );

  fd_solfuzz_runner_t * runner       = fd_wksp_alloc_laddr( wksp, alignof(fd_solfuzz_runner_t), sizeof(fd_solfuzz_runner_t),                                 wksp_tag );
  void *                accdb_shmem  = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(),       accdb_shmem_sz,                                              wksp_tag );
  void *                accdb_join   = fd_wksp_alloc_laddr( wksp, fd_accdb_align(),             accdb_join_sz,                                               wksp_tag );
  void *                pcache_mem   = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(),   fd_progcache_shmem_footprint( txn_max, rec_max ),            wksp_tag );
  uchar *               scratch      = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT,                              wksp_tag );
  void *                spad_mem     = fd_wksp_alloc_laddr( wksp, fd_spad_align(),              fd_spad_footprint( spad_max ),                               wksp_tag );
  void *                banks_mem    = fd_wksp_alloc_laddr( wksp, fd_banks_align(),             fd_banks_footprint( bank_max, fork_max, 2048UL, 2048UL ),    wksp_tag );
  if( FD_UNLIKELY( !runner       ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(solfuzz_runner) failed"                                            )); goto bail1; }
  if( FD_UNLIKELY( !accdb_shmem  ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(accdb_shmem) failed"                                               )); goto bail1; }
  if( FD_UNLIKELY( !accdb_join   ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(accdb_join) failed"                                                )); goto bail1; }
  if( FD_UNLIKELY( !pcache_mem   ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(pcache) failed"                                                    )); goto bail1; }
  if( FD_UNLIKELY( !scratch      ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(scratch) failed"                                                   )); goto bail1; }
  if( FD_UNLIKELY( !spad_mem     ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(spad) failed (spad_max=%g)", (double)spad_max                      )); goto bail1; }
  if( FD_UNLIKELY( !banks_mem    ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(banks) failed (bank_max=%lu fork_max=%lu)", bank_max, fork_max     )); goto bail1; }

  /* Create objects */
  fd_memset( runner, 0, sizeof(fd_solfuzz_runner_t) );
  runner->wksp     = wksp;
  runner->wksp_tag = wksp_tag;

  /* Create accdb backed by memfd */
  int accdb_fd = memfd_create( "accdb_fuzz", 0 );
  if( FD_UNLIKELY( accdb_fd<0 ) ) { FD_LOG_WARNING(( "memfd_create failed (%i-%s)", errno, fd_io_strerror( errno ) )); goto bail1; }

  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( accdb_shmem, max_accounts, max_live_slots,
                          writes_per_slot, partition_cnt,
                          partition_sz, cache_footprint, 42UL, 1UL ) );
  if( FD_UNLIKELY( !shmem ) ) goto bail1;
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_join, shmem, accdb_fd ) );
  if( FD_UNLIKELY( !accdb ) ) goto bail1;
  runner->accdb = accdb;

  /* Create root fork (sentinel parent) */
  runner->root_fork_id = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val=USHORT_MAX } );

  void * shpcache = fd_progcache_shmem_new( pcache_mem, wksp_tag, 1UL, txn_max, rec_max );
  if( FD_UNLIKELY( !shpcache ) ) goto bail2;
  if( FD_UNLIKELY( !fd_progcache_join( runner->progcache, pcache_mem, scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) ) ) goto bail2;

  runner->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  if( FD_UNLIKELY( !runner->runtime ) ) goto bail2;
  runner->runtime->accounts.executable_cnt = 0UL;
  runner->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), wksp_tag );
  if( FD_UNLIKELY( !runner->runtime_stack ) ) goto bail2;
  if( FD_UNLIKELY( !fd_runtime_stack_join( fd_runtime_stack_new( runner->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) ) ) goto bail2;

  runner->spad = fd_spad_join( fd_spad_new( spad_mem, spad_max ) );
  if( FD_UNLIKELY( !runner->spad ) ) goto bail2;
  /* Use 2048 for max_vote_accounts to match fd_banks_footprint above (avoids buffer overrun) */
  runner->banks = fd_banks_join( fd_banks_new( banks_mem, bank_max, fork_max, 2048UL, 2048UL, 0, 8888UL ) );
  if( FD_UNLIKELY( !runner->banks ) ) goto bail2;
  runner->bank = fd_banks_init_bank( runner->banks );
  if( FD_UNLIKELY( !runner->bank ) ) goto bail2;
  runner->bank->f.slot = 0UL;

  runner->enable_vm_tracing = options->enable_vm_tracing;
  FD_TEST( runner->progcache->join->shmem );

  ulong tags[1] = { wksp_tag };
  fd_wksp_usage_t usage[1];
  fd_wksp_usage( wksp, tags, 1UL, usage );
  runner->wksp_baseline_used_sz = usage->used_sz;

  return runner;

bail2:
  if( runner->spad ) fd_spad_delete( fd_spad_leave( runner->spad ) );
  if( shpcache     ) fd_progcache_shmem_delete( shpcache );
bail1:
  fd_wksp_free_laddr( scratch      );
  fd_wksp_free_laddr( pcache_mem   );
  fd_wksp_free_laddr( accdb_join   );
  fd_wksp_free_laddr( accdb_shmem  );
  fd_wksp_free_laddr( spad_mem     );
  fd_wksp_free_laddr( banks_mem    );
  fd_wksp_free_laddr( runner       );
  FD_LOG_WARNING(( "fd_solfuzz_runner_new failed" ));
  return NULL;
}

void
fd_solfuzz_runner_delete( fd_solfuzz_runner_t * runner ) {

  /* accdb cleanup is handled by the memfd close */
  /* TODO: proper accdb teardown if needed */

  fd_progcache_shmem_t * shpcache = NULL;
  fd_progcache_leave( runner->progcache, &shpcache );
  if( shpcache ) fd_wksp_free_laddr( fd_progcache_shmem_delete( shpcache ) );

  if( runner->spad  ) fd_wksp_free_laddr( fd_spad_delete( fd_spad_leave( runner->spad ) ) );
  fd_wksp_free_laddr( runner->banks );
  fd_wksp_free_laddr( runner );
}

void
fd_solfuzz_runner_leak_check( fd_solfuzz_runner_t * runner ) {
  if( FD_UNLIKELY( fd_spad_frame_used( runner->spad ) ) ) {
    FD_LOG_CRIT(( "leaked spad frame" ));
  }

  if( FD_UNLIKELY( runner->progcache->join->shmem->txn.child_head_idx != UINT_MAX ) ) {
    FD_LOG_CRIT(( "leaked a funk txn in progcache" ));
  }

  ulong tags[1] = { runner->wksp_tag };
  fd_wksp_usage_t usage[1];
  fd_wksp_usage( runner->wksp, tags, 1UL, usage );
  if( FD_UNLIKELY( usage->used_sz != runner->wksp_baseline_used_sz ) ) {
    FD_LOG_CRIT(( "leaked wksp allocations: %lu bytes with tag %lu (baseline %lu bytes, delta %+ld)",
                  usage->used_sz, runner->wksp_tag,
                  runner->wksp_baseline_used_sz,
                  (long)usage->used_sz - (long)runner->wksp_baseline_used_sz ));
  }
}
