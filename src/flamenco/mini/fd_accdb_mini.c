#define _GNU_SOURCE /* MAP_ANONYMOUS */
#include "fd_accdb_mini.h"
#include <sys/mman.h>

/* Used to estimate wksp partition count */
#define MINI_WKSP_ALLOC_SZ_TYPICAL (64UL<<10)

/* accdb_mini uses a dedicated wksp, therefore the wksp alloc tag can
   be hardcoded */
#define MINI_WKSP_TAG 1UL

static ulong
wksp_footprint_est( ulong rec_max,
                    ulong txn_max,
                    ulong heap_min ) {
  ulong overhead  = 1UL<<20;  /* 1 MiB arbitrary slack */
  ulong funk_sz   = fd_funk_footprint( txn_max, rec_max );
  if( FD_UNLIKELY( !funk_sz ) ) return 0UL;
  ulong usable_sz = overhead + funk_sz + heap_min;
  ulong part_cnt  = fd_wksp_part_max_est( usable_sz, MINI_WKSP_ALLOC_SZ_TYPICAL );
  return fd_wksp_footprint( part_cnt, usable_sz );
}

fd_accdb_mini_t *
fd_accdb_mini_create( fd_accdb_mini_t * const mini,
                      ulong             const rec_max,
                      ulong             const txn_max,
                      char const *      const wksp_name,
                      ulong             const heap_min,
                      ulong             const seed ) {

  if( FD_UNLIKELY( !mini ) ) {
    FD_LOG_WARNING(( "NULL mini" ));
    return NULL;
  }

  ulong const wksp_footprint = fd_ulong_align_up( wksp_footprint_est( rec_max, txn_max, heap_min ), FD_SHMEM_NORMAL_PAGE_SZ );
  if( FD_UNLIKELY( !wksp_footprint ) ) {
    FD_LOG_WARNING(( "invalid accdb_mini parameters (rec_max=%lu txn_max=%lu heap_min=%lu)", rec_max, txn_max, heap_min ));
    return NULL;
  }

  void * const mem = mmap( NULL, wksp_footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) failed", wksp_footprint>>10 ));
    return NULL;
  }

  ulong       const wksp_part_max = fd_wksp_part_max_est( wksp_footprint, MINI_WKSP_ALLOC_SZ_TYPICAL );
  ulong       const wksp_data_max = fd_wksp_data_max_est( wksp_footprint, wksp_part_max );
  fd_wksp_t * const wksp = fd_wksp_join( fd_wksp_new( mem, wksp_name, (uint)seed, wksp_part_max, wksp_data_max ) );
  if( FD_UNLIKELY( !wksp ) ) goto fail1;

  ulong const page_sz  = FD_SHMEM_NORMAL_PAGE_SZ;
  ulong const page_cnt = wksp_footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ;
  FD_TEST( 0==fd_shmem_join_anonymous( wksp_name, FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, page_sz, page_cnt ) );

  void * const funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), MINI_WKSP_TAG );
  if( FD_UNLIKELY( !funk_mem ) ) goto fail2;
  if( FD_UNLIKELY( !fd_funk_new( funk_mem, MINI_WKSP_TAG, seed+1UL, txn_max, rec_max ) ) ) goto fail3;

  mini->wksp           = wksp;
  mini->wksp_footprint = wksp_footprint;
  mini->funk_shmem     = funk_mem;
  return mini;

fail3:
  fd_wksp_free_laddr( funk_mem );
fail2:
  FD_TEST( 0==fd_shmem_leave_anonymous( mini->wksp, NULL ) );
fail1:
  FD_TEST( 0==munmap( mem, wksp_footprint ) );
  return NULL;
}

void
fd_accdb_mini_destroy( fd_accdb_mini_t * mini ) {
  if( FD_UNLIKELY( !mini ) ) return;
  FD_TEST( mini->wksp );  /* double free? */
  FD_TEST( 0==fd_shmem_leave_anonymous( mini->wksp, NULL ) );
  FD_TEST( fd_wksp_delete( fd_wksp_leave( mini->wksp ) ) );
  mini->wksp = NULL;
}

fd_accdb_admin_t *
fd_accdb_mini_join_admin( fd_accdb_mini_t *  mini,
                          fd_accdb_admin_t * join ) {
  return fd_accdb_admin_join( join, mini->funk_shmem );
}

fd_accdb_user_t *
fd_accdb_mini_join_user( fd_accdb_mini_t * mini,
                         fd_accdb_user_t * join ) {
  return fd_accdb_user_v1_init( join, mini->funk_shmem );
}
