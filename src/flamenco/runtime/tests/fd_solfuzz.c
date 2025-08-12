/* fd_solfuzz.c contains support routines */

#define _GNU_SOURCE
#include "fd_solfuzz.h"
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
  void * mem = fd_shmem_private_map_rand( footprint, FD_SHMEM_HUGE_PAGE_SZ );
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
fd_solfuzz_runner_new( fd_wksp_t * wksp,
                       ulong       wksp_tag ) {

  /* Allocate objects */
  ulong const txn_max  =   64UL;
  ulong const rec_max  = 1024UL;
  ulong const spad_max = FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_FUZZ;
  ulong const bank_max = 1UL;
  ulong const fork_max = 1UL;
  fd_solfuzz_runner_t * runner    = fd_wksp_alloc_laddr( wksp, alignof(fd_solfuzz_runner_t), sizeof(fd_solfuzz_runner_t),              wksp_tag );
  void *                funk_mem  = fd_wksp_alloc_laddr( wksp, fd_funk_align(),              fd_funk_footprint( txn_max, rec_max ),    wksp_tag );
  void *                spad_mem  = fd_wksp_alloc_laddr( wksp, fd_spad_align(),              fd_spad_footprint( spad_max ),            wksp_tag );
  void *                banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(),             fd_banks_footprint( bank_max, fork_max ), wksp_tag );
  if( FD_UNLIKELY( !runner    ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(solfuzz_runner) failed" )); goto bail1; }
  if( FD_UNLIKELY( !funk_mem  ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(funk) failed"           )); goto bail1; }
  if( FD_UNLIKELY( !spad_mem  ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(spad) failed (spad_max=%g)", (double)spad_max )); goto bail1; }
  if( FD_UNLIKELY( !banks_mem ) ) { FD_LOG_WARNING(( "fd_wksp_alloc(banks) failed (bank_max=%lu fork_max=%lu)", bank_max, fork_max )); goto bail1; }

  /* Create objects */
  fd_memset( runner, 0, sizeof(fd_solfuzz_runner_t) );
  runner->wksp = wksp;
  void * shfunk = fd_funk_new( funk_mem, wksp_tag, 1UL, txn_max, rec_max );
  if( FD_UNLIKELY( !shfunk ) ) goto bail1;
  if( FD_UNLIKELY( !fd_funk_join( runner->funk, funk_mem ) ) ) goto bail2;
  runner->spad = fd_spad_join( fd_spad_new( spad_mem, spad_max ) );
  if( FD_UNLIKELY( !runner->spad ) ) goto bail2;
  runner->banks = fd_banks_join( fd_banks_new( banks_mem, bank_max, fork_max ) );
  if( FD_UNLIKELY( !runner->banks ) ) goto bail2;
  runner->bank = fd_banks_init_bank( runner->banks, 0UL );
  if( FD_UNLIKELY( !runner->bank ) ) {
    FD_LOG_WARNING(( "fd_banks_init_bank failed" ));
    goto bail2;
  }
  return runner;

bail2:
  if( runner->spad  ) fd_spad_delete( fd_spad_leave( runner->spad ) );
  if( shfunk        ) fd_funk_delete( funk_mem ); /* free underlying fd_alloc instance */
  if( runner->banks ) fd_banks_delete( fd_banks_leave( runner->banks ) );
bail1:
  fd_wksp_free_laddr( funk_mem  );
  fd_wksp_free_laddr( spad_mem  );
  fd_wksp_free_laddr( banks_mem );
  fd_wksp_free_laddr( runner    );
  FD_LOG_WARNING(( "fd_solfuzz_runner_new failed" ));
  return NULL;
}

void
fd_solfuzz_runner_delete( fd_solfuzz_runner_t * runner ) {
  void * shfunk = NULL;
  fd_funk_leave( runner->funk, &shfunk );
  if( shfunk        ) fd_wksp_free_laddr( fd_funk_delete( shfunk ) );
  if( runner->spad  ) fd_wksp_free_laddr( fd_spad_delete( fd_spad_leave( runner->spad ) ) );
  if( runner->banks ) fd_wksp_free_laddr( fd_banks_delete( fd_banks_leave( runner->banks ) ) );
  fd_wksp_free_laddr( runner );
}
