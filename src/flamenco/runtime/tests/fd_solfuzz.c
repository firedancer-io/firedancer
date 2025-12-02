/* fd_solfuzz.c contains support routines */

#define _GNU_SOURCE
#include "fd_solfuzz.h"
#include "../fd_bank.h"
#include "../fd_runtime_stack.h"
#include "../fd_runtime.h"
#include "../../accdb/fd_accdb_impl_v1.h"
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
  ulong const bank_max = 1UL;
  ulong const fork_max = 1UL;
  fd_solfuzz_runner_t * runner     = fd_wksp_alloc_laddr( wksp, alignof(fd_solfuzz_runner_t), sizeof(fd_solfuzz_runner_t),              wksp_tag );
  void *                funk_mem   = fd_wksp_alloc_laddr( wksp, fd_funk_align(),              fd_funk_footprint( txn_max, rec_max ),    wksp_tag );
  void *                pcache_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(),              fd_funk_footprint( txn_max, rec_max ),    wksp_tag );
  uchar *               scratch    = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT,           wksp_tag );
  void *                spad_mem   = fd_wksp_alloc_laddr( wksp, fd_spad_align(),              fd_spad_footprint( spad_max ),            wksp_tag );
  void *                banks_mem  = fd_wksp_alloc_laddr( wksp, fd_banks_align(),             fd_banks_footprint( bank_max, fork_max ), wksp_tag );
  if( FD_UNLIKELY( !runner     ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(solfuzz_runner) failed" )); goto bail1; }
  if( FD_UNLIKELY( !funk_mem   ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(funk) failed"           )); goto bail1; }
  if( FD_UNLIKELY( !pcache_mem ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(funk) failed"           )); goto bail1; }
  if( FD_UNLIKELY( !scratch    ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(scratch) failed"        )); goto bail1; }
  if( FD_UNLIKELY( !spad_mem   ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(spad) failed (spad_max=%g)", (double)spad_max )); goto bail1; }
  if( FD_UNLIKELY( !banks_mem  ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(banks) failed (bank_max=%lu fork_max=%lu)", bank_max, fork_max )); goto bail1; }

  /* Create objects */
  fd_memset( runner, 0, sizeof(fd_solfuzz_runner_t) );
  runner->wksp     = wksp;
  runner->wksp_tag = wksp_tag;

  void * shfunk   = fd_funk_new( funk_mem,   wksp_tag, 1UL, txn_max, rec_max );
  void * shpcache = fd_funk_new( pcache_mem, wksp_tag, 1UL, txn_max, rec_max );
  if( FD_UNLIKELY( !shfunk   ) ) goto bail1;
  if( FD_UNLIKELY( !shpcache ) ) goto bail1;

  if( FD_UNLIKELY( !fd_accdb_admin_join  ( runner->accdb_admin, funk_mem ) ) ) goto bail2;
  if( FD_UNLIKELY( !fd_accdb_user_v1_init( runner->accdb,       funk_mem ) ) ) goto bail2;
  if( FD_UNLIKELY( !fd_progcache_join( runner->progcache, pcache_mem, scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) ) ) goto bail2;
  if( FD_UNLIKELY( !fd_progcache_admin_join( runner->progcache_admin, pcache_mem ) ) ) goto bail2;

  runner->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  if( FD_UNLIKELY( !runner->runtime ) ) goto bail2;
  runner->runtime_stack = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t), wksp_tag );
  if( FD_UNLIKELY( !runner->runtime_stack ) ) goto bail2;

# if FD_HAS_FLATCC
  /* TODO: Consider implementing custom allocators and emitters.
     The default builder / emitter uses libc allocators */
  int builder_err = flatcc_builder_init( runner->fb_builder );
  if( FD_UNLIKELY( builder_err ) ) goto bail2;
# endif

  runner->spad = fd_spad_join( fd_spad_new( spad_mem, spad_max ) );
  if( FD_UNLIKELY( !runner->spad ) ) goto bail2;
  runner->banks = fd_banks_join( fd_banks_new( banks_mem, bank_max, fork_max, 0, 8888UL ) );
  if( FD_UNLIKELY( !runner->banks ) ) goto bail2;
  runner->bank = fd_banks_init_bank( runner->banks );
  if( FD_UNLIKELY( !runner->bank ) ) {
    FD_LOG_WARNING(( "fd_banks_init_bank failed" ));
    goto bail2;
  }
  fd_bank_slot_set( runner->bank, 0UL );

  runner->enable_vm_tracing = options->enable_vm_tracing;
  FD_TEST( runner->progcache->funk->shmem );

  ulong tags[1] = { wksp_tag };
  fd_wksp_usage_t usage[1];
  fd_wksp_usage( wksp, tags, 1UL, usage );
  runner->wksp_baseline_used_sz = usage->used_sz;

  return runner;

bail2:
  if( runner->spad      ) fd_spad_delete( fd_spad_leave( runner->spad ) );
  if( shfunk            ) fd_funk_delete( shfunk ); /* free underlying fd_alloc instance */
  if( shpcache          ) fd_funk_delete( shpcache );
  if( runner->banks     ) fd_banks_delete( fd_banks_leave( runner->banks ) );
bail1:
  fd_wksp_free_laddr( scratch    );
  fd_wksp_free_laddr( pcache_mem );
  fd_wksp_free_laddr( funk_mem   );
  fd_wksp_free_laddr( spad_mem   );
  fd_wksp_free_laddr( banks_mem  );
  fd_wksp_free_laddr( runner     );
  FD_LOG_WARNING(( "fd_solfuzz_runner_new failed" ));
  return NULL;
}

void
fd_solfuzz_runner_delete( fd_solfuzz_runner_t * runner ) {

  fd_accdb_user_fini( runner->accdb );
  void * shfunk = NULL;
  fd_accdb_admin_leave( runner->accdb_admin, &shfunk );
  if( shfunk ) fd_wksp_free_laddr( fd_funk_delete( shfunk ) );

  fd_progcache_leave( runner->progcache, NULL );
  void * shpcache = NULL;
  fd_progcache_admin_leave( runner->progcache_admin, &shpcache );
  if( shpcache ) fd_wksp_free_laddr( fd_funk_delete( shpcache ) );

# if FD_HAS_FLATCC
  flatcc_builder_clear( runner->fb_builder );
# endif

  if( runner->spad  ) fd_wksp_free_laddr( fd_spad_delete( fd_spad_leave( runner->spad ) ) );
  if( runner->banks ) fd_wksp_free_laddr( fd_banks_delete( fd_banks_leave( runner->banks ) ) );
  fd_wksp_free_laddr( runner );
}

void
fd_solfuzz_runner_leak_check( fd_solfuzz_runner_t * runner ) {
  if( FD_UNLIKELY( fd_spad_frame_used( runner->spad ) ) ) {
    FD_LOG_CRIT(( "leaked spad frame" ));
  }

  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( runner->accdb_admin->funk->shmem->child_head_cidx ) ) ) ) {
    FD_LOG_CRIT(( "leaked a funk txn in accdb" ));
  }
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( runner->progcache_admin->funk->shmem->child_head_cidx ) ) ) ) {
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
