#include "fd_eqvoc.h"
#include <stdlib.h>

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
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  ulong  key_max = 1 << 10UL;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_eqvoc_align(), fd_eqvoc_footprint( key_max ), 1UL );
  FD_TEST( mem );
  fd_eqvoc_t * eqvoc = fd_eqvoc_join( fd_eqvoc_new( mem, key_max, 0UL ) );

  /* Insert 13-15, 15-20 */

  fd_shred_t shred13 = { .variant     = 0x60,
                         .slot        = 42,
                         .fec_set_idx = 13,
                         .signature   = { 13 },
                         .code        = { .data_cnt = 3 } };
  fd_eqvoc_insert( eqvoc, &shred13 );
  fd_shred_t shred15 = { .variant     = 96,
                         .slot        = 42,
                         .fec_set_idx = 15,
                         .signature   = { 15 },
                         .code        = { .data_cnt = 6 } };
  FD_TEST( !fd_eqvoc_test( eqvoc, &shred15 ) );

  fd_wksp_free_laddr( mem );

  fd_halt();
  return 0;
}
