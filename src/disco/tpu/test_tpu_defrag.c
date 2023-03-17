#include "fd_tpu_defrag_private.h"
#include "../../util/fd_util.h"
#include <stddef.h>

static uchar _defrag[ 0x3000 ] __attribute__((aligned(FD_TPU_DEFRAG_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Alignment checks */

  FD_TEST( fd_tpu_defrag_align()==FD_TPU_DEFRAG_ALIGN );

  FD_TEST( fd_ulong_is_aligned( offsetof( fd_tpu_defrag_entry_t, chunk ), 64UL ) );

  FD_TEST( fd_tpu_defrag_footprint( 0UL )==0UL );

  /* Test fd_tpu_defrag_new */

  FD_TEST( fd_tpu_defrag_new( NULL,      8UL )==NULL ); /* NULL mem       */
  FD_TEST( fd_tpu_defrag_new( _defrag+1, 8UL )==NULL ); /* misaligned mem */
  FD_TEST( fd_tpu_defrag_new( _defrag,   0UL )==NULL ); /* zero entry_cnt */

  /* Create defragger */

  ulong footprint = fd_tpu_defrag_footprint( 8UL );
  FD_TEST( footprint>0UL && footprint<=0x3000UL );
  ulong defrag_laddr_end = (ulong)_defrag + footprint;

  fd_tpu_defrag_t * defragger = fd_tpu_defrag_join( fd_tpu_defrag_new( _defrag, 8UL ) );
  FD_TEST( defragger );

  /* Check initial freelist */

  uint * freelist = fd_tpu_defrag_get_freelist( defragger );
  FD_TEST( fd_tpu_defrag_freelist_max  ( freelist )==8UL );
  FD_TEST( fd_tpu_defrag_freelist_cnt  ( freelist )==8UL );
  FD_TEST( fd_tpu_defrag_freelist_avail( freelist )==0UL );

  /* Test fd_tpu_defrag_entry_start */

  fd_tpu_defrag_entry_t * entry_arr[ 8UL ];
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_tpu_defrag_entry_t * entry = fd_tpu_defrag_entry_start( defragger, 12UL+i, 23UL+i );
    FD_TEST( entry );
    FD_TEST( fd_ulong_is_aligned( (ulong)entry, FD_TPU_DEFRAG_ENTRY_ALIGN ) );

    FD_TEST( entry->conn_id  ==12UL+i );
    FD_TEST( entry->stream_id==23UL+i );

    /* Ensure that entry is not out-of-bounds */
    FD_TEST( (ulong)entry+sizeof(fd_tpu_defrag_entry_t) <= defrag_laddr_end );

    entry_arr[ i ]=entry;
  }

  FD_TEST( fd_tpu_defrag_freelist_cnt( freelist )==0UL );
  for( ulong i=0UL; i<8UL; i++ )
    FD_TEST( freelist[i]==(uint)i );

  FD_TEST( fd_tpu_defrag_entry_start( defragger, 9UL, 9UL )==NULL );
  FD_TEST( fd_tpu_defrag_freelist_cnt( freelist )==0UL );

  for( ulong i=0UL; i<8UL; i++ ) {
    FD_TEST( fd_tpu_defrag_entry_exists( entry_arr[ i ], 12UL+i, 23UL+i )==entry_arr[ i ] );
    FD_TEST( fd_tpu_defrag_entry_exists( entry_arr[ i ], 39UL,   23UL+i )==NULL           );
    FD_TEST( fd_tpu_defrag_entry_exists( entry_arr[ i ], 12UL+i, 19UL   )==NULL           );
  }

  /* Test fd_tpu_defrag_entry_fini */

  for( ulong i=0UL; i<8UL; i++ )
    fd_tpu_defrag_entry_fini( defragger, entry_arr[ i ], 12UL+i, 23UL+i );

  FD_TEST( fd_tpu_defrag_freelist_cnt( freelist )==8UL );

  fd_tpu_defrag_entry_fini( defragger, entry_arr[ 0 ], 12UL, 23UL ); /* handle double-free */
  FD_TEST( fd_tpu_defrag_freelist_cnt( freelist )==8UL );

  /* Test fd_tpu_defrag_delete */

  FD_TEST( fd_tpu_defrag_delete( fd_tpu_defrag_leave( defragger ) )==(void *)_defrag );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
