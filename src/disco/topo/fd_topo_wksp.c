#include "fd_topo.h"
#include "fd_topo_pod_helper.h"

#include "../../util/shmem/fd_shmem_private.h"

#include <errno.h>
#include <sys/stat.h>

/*static ulong
fd_topo_mcache_footprint( fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  (void)topo;
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)vert;
  return fd_mcache_footprint( link->depth, 0UL );
}

static void
fd_topo_mcache_new( void * shmem, fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  (void)topo;
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)vert;
  fd_mcache_new( shmem, link->depth, 0UL, 0UL );
}

static void *
fd_topo_mcache_join( void * shmem, fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  (void)topo; (void)vert;
  return fd_mcache_join( shmem );
}

static ulong
fd_topo_dcache_footprint( fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_LINK_DCACHE ).v;
  ulong data_sz = fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 );
  return fd_dcache_footprint( data_sz, 0UL );
}

static void
fd_topo_dcache_new( void * shmem, fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_LINK_DCACHE ).v;
  ulong data_sz = fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 );
  return fd_dcache_new( shmem, data_sz, 0UL );
}

static void *
fd_topo_dcache_join( void * shmem, fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  (void)topo; (void)vert;
  return fd_dcache_join( shmem );
}

static ulong
fd_topo_reasm_footprint( fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_LINK_REASM ).v;
  return fd_tpu_reasm_footprint( link->depth, link->burst );
}

static void
fd_topo_reasm_new( void * shmem, fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_LINK_REASM ).v;
  fd_tpu_reasm_new( shmem, link->depth, link->burst, 0UL, NULL ); TODO: mcache 
}

static void *
fd_topo_reasm_join( void * shmem, fd_topo_t const * topo,  fd_topo_vert_t const * vert ) {
  (void)topo; (void)vert;
  return fd_tpu_reasm_join( shmem );
}

static ulong
fd_topo_tile_align( fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_edge_wksp_contains_t const * wksp_contains = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_WKSP_CONTAINS ).e;
  return wksp_contains->align();
}

static ulong
fd_topo_tile_footprint( fd_topo_t const * topo, fd_topo_vert_t const * vert ) {
  fd_topo_vert_link_t const * link = (fd_topo_vert_link_t const *)fd_topo_query_adjr1( topo, vert, FD_TOPO_EDGE_ID_LINK_REASM ).v;
  return fd_tpu_reasm_footprint( link->depth, link->burst );
}*/

void
fd_topo_wksp_layout( uchar * pod,
                     ulong (* align    )( uchar const * pod, char const * id ),
                     ulong (* footprint)( uchar const * pod, char const * id ) ) {
  ulong wksp_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp_cnt" );

  for( ulong i=0UL; i<wksp_cnt; i++ ) {
    ulong loose_sz = fd_pod_queryf_ulong( pod, 0UL, "wksp.%lu.loose_sz", i );
    ulong part_max = 1UL + (loose_sz / (64UL << 10));
    ulong offset = fd_ulong_align_up( fd_wksp_private_data_off( part_max ), 4096UL );

    ulong contains_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp.%lu.contains_cnt", i );
    for( ulong j=0UL; j<contains_cnt; j++ ) {
      char const * contains = fd_pod_queryf_cstr( pod, NULL, "wksp.%lu.contains.%lu.id", i, j );
      offset = fd_ulong_align_up( offset, align( pod, contains ) );
      FD_TEST( fd_pod_insertf_ulong( pod, offset, "%s.offset", contains ) );
      offset += footprint( pod, contains );
    }

    offset = fd_ulong_align_up( offset, 4096UL );
    FD_TEST( fd_pod_insertf_ulong( pod, offset, "wksp.%lu.footprint", i ) );
    FD_LOG_WARNING(( "wksp.%lu.footprint = %lu", i, offset ));
  }
}

fd_topo_wksp_sz_t
wksp_sz( uchar const * pod, char const * name ) {
  ulong found_idx = ULONG_MAX;
  for( ulong idx=0UL; ; idx++ ) {
    char const * wksp_name = fd_pod_queryf_cstr( pod, NULL, "wksp.%lu.name", idx );
    if( !wksp_name ) break;
    if( !strcmp( wksp_name, name ) ) {
      found_idx = idx;
      break;
    }
  }
  FD_TEST( found_idx!=ULONG_MAX );

  ulong loose_sz = fd_pod_queryf_ulong( pod, 0UL, "wksp.%lu.loose_sz", found_idx );
  ulong part_max = 1UL + (loose_sz / (64UL << 10));

  ulong footprint = fd_pod_queryf_ulong( pod, ULONG_MAX, "wksp.%lu.footprint", found_idx );
  FD_TEST( footprint!=ULONG_MAX );

  /* Compute footprint for a workspace that can store our footprint,
      with an extra align of padding incase gaddr_lo is not aligned. */

  ulong total_wksp_footprint = fd_wksp_footprint( part_max, footprint + 4096UL + loose_sz );

  ulong page_sz = FD_SHMEM_GIGANTIC_PAGE_SZ;
  if( FD_UNLIKELY( total_wksp_footprint < 4 * FD_SHMEM_HUGE_PAGE_SZ ) ) page_sz = FD_SHMEM_HUGE_PAGE_SZ;

  ulong wksp_aligned_footprint = fd_ulong_align_up( total_wksp_footprint, page_sz );

  return (fd_topo_wksp_sz_t){
    .part_max        = part_max,
    .known_footprint = footprint,
    .total_footprint = wksp_aligned_footprint - fd_ulong_align_up( fd_wksp_private_data_off( part_max ), 4096UL ),
    .page_sz         = page_sz,
    .page_cnt        = wksp_aligned_footprint / page_sz
  };
}

void
fd_topo_wksp_new( uchar * pod ) {
  char const * app_name = fd_pod_queryf_cstr( pod, NULL, "app_name" );
  ulong wksp_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp_cnt" );

  for( ulong i=0UL; i<wksp_cnt; i++ ) {
    char const * wksp_name = fd_pod_queryf_cstr( pod, NULL, "wksp.%lu.name", i );

    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", app_name, wksp_name ) );

    fd_topo_wksp_sz_t sz = wksp_sz( pod, wksp_name );

    ulong sub_page_cnt[ 1 ] = { sz.page_cnt };
    ulong sub_cpu_idx [ 1 ] = { 0 }; /* todo, use CPU nearest to the workspace consumers */

    int err = fd_shmem_create_multi( name, sz.page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
    if( FD_UNLIKELY( err && errno==ENOMEM ) ) {
      char mount_path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
      FD_TEST( fd_cstr_printf_check( mount_path, FD_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s", fd_shmem_private_base, fd_shmem_page_sz_to_cstr( sz.page_sz ) ) );
      FD_LOG_ERR(( "ENOMEM-Out of memory when trying to create workspace `%s` at `%s` "
                   "with %lu %s pages. The memory needed should already be successfully "
                   "reserved by the `large-pages` configure step, so there are two "
                   "likely reasons. You might have workspaces leftover in the same "
                   "directory from an older release of Firedancer which can be removed "
                   "with `fdctl configure fini workspace`, or another process on the "
                   "system is using the pages we reserved.",
                   name, mount_path, sz.page_cnt, fd_shmem_page_sz_to_cstr( sz.page_sz ) ));
    }
    else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi failed" ));

    void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ); /* logs details */

    void * wkspmem = fd_wksp_new( shmem, name, 0U, sz.part_max, sz.total_footprint ); /* logs details */
    if( FD_UNLIKELY( !wkspmem ) ) FD_LOG_ERR(( "fd_wksp_new failed" ));

    fd_wksp_t * join = fd_wksp_join( wkspmem );
    if( FD_UNLIKELY( !join ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

    /* Footprint has been predetermined so that this alloc() call must
       succeed inside the data region.  The difference between total_footprint
       and known_footprint is given to "loose" data, that may be dynamically
       allocated out of the workspace at runtime. */

    if( FD_LIKELY( sz.known_footprint ) ) {
      ulong offset = fd_wksp_alloc( join, 4096UL, sz.known_footprint, 1UL );
      if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));

      /* gaddr_lo is the start of the workspace data region that can be
         given out in response to wksp alloc requests.  We rely on an
         implicit assumption everywhere that the bytes we are given by
         this single allocation will be at gaddr_lo, so that we can find
         them, so we verify this here for paranoia in case the workspace
         alloc implementation changes. */

      if( FD_UNLIKELY( fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, 4096UL ) != offset ) )
        FD_LOG_ERR(( "wksp gaddr_lo %lu != offset %lu", fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, 4096UL ), offset ));
    }

    fd_wksp_leave( join );

    if( FD_UNLIKELY( fd_shmem_leave( shmem, NULL, NULL ) ) ) /* logs details */
      FD_LOG_ERR(( "fd_shmem_leave failed" ));
  }
}

void
fd_topo_wksp_attach( fd_topo_wksp_t * wksp, int mode ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", wksp->topo->app_name, wksp->name ) );

  void * shmem = fd_shmem_join( name, mode, NULL, NULL, NULL ); /* logs details */
  if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));

  void * wkspmem = fd_wksp_join( shmem );
  if( FD_UNLIKELY( !wkspmem ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

  wksp->wksp = wkspmem;
}

void
fd_topo_wksp_attach_all( fd_topo_t * topo, int mode ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_LIKELY( topo->wksps[ i ]->wksp ) ) continue;
    fd_topo_wksp_attach( topo->wksps[ i ], mode );
  }
}

void
fd_topo_wksp_attach_tile( fd_topo_tile_t * tile ) {
  for( ulong i=0UL; i<tile->joins_cnt; i++ ) {
    fd_topo_wksp_t * wksp = tile->joins[ i ];
    if( FD_LIKELY( wksp->wksp ) ) continue;
    fd_topo_wksp_attach( wksp, (int)(tile->joins_mode[ i ]-1UL) );
  }
}

void
fd_topo_wksp_join( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( !topo->wksps[ i ]->wksp ) ) continue;
    fd_wksp_t * join = fd_wksp_join( topo->wksps[ i ]->wksp );
    if( FD_UNLIKELY( !join ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));
  }
}

void
fd_topo_wksp_detach( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_LIKELY( !topo->wksps[ i ]->wksp ) ) continue;
    FD_TEST( !fd_wksp_detach( topo->wksps[ i ]->wksp ) );
  }
}
