#include "fd_pcapng_private.h"
#include "../fd_util.h"

#include <stddef.h>


FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, byte_order_magic )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, version_major    )==12UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, version_minor    )==14UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_shb_t, section_sz       )==16UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_shb_t                   )==24UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, link_type        )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_idb_t, snap_len         )==12UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_idb_t                   )==16UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, if_idx           )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, ts_hi            )==12UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, ts_lo            )==16UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, cap_len          )==20UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_epb_t, orig_len         )==24UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_epb_t                   )==28UL, layout );

FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, block_type       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, block_sz         )== 4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, secret_type      )== 8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_pcapng_dsb_t, secret_sz        )==12UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_pcapng_dsb_t                   )==16UL, layout );


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* TODO test functions */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

