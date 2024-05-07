#include "fd_topo.h"

#include "../fd_disco_base.h"
#include "../metrics/fd_metrics.h"
#include "../quic/fd_tpu.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../util/shmem/fd_shmem_private.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

void
fd_topo_join_workspace( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp,
                        int              mode ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );

  wksp->wksp = fd_wksp_join( fd_shmem_join( name, mode, NULL, NULL, NULL ) );
  if( FD_UNLIKELY( !wksp->wksp ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));
}

FD_FN_PURE static int
tile_needs_wksp( fd_topo_t const * topo, fd_topo_tile_t * tile, ulong wksp_id ) {
  int mode = -1;
  for( ulong i=0UL; i<tile->uses_obj_cnt; i++ ) {
    if( FD_UNLIKELY( topo->objs[ tile->uses_obj_id[ i ] ].wksp_id==wksp_id ) ) {
      mode = fd_int_max( mode, tile->uses_obj_mode[ i ] );
    }
  }
  return mode;
}

void
fd_topo_join_tile_workspaces( fd_topo_t *      topo,
                              fd_topo_tile_t * tile ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    int needs_wksp = tile_needs_wksp( topo, tile, i );
    if( FD_LIKELY( -1!=needs_wksp ) ) {
      fd_topo_join_workspace( topo, &topo->workspaces[ i ], needs_wksp );
    }
  }
}

void
fd_topo_join_workspaces( fd_topo_t *  topo,
                         int          mode ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_join_workspace( topo, &topo->workspaces[ i ], mode );
  }
}

void
fd_topo_leave_workspace( fd_topo_t *      topo,
                         fd_topo_wksp_t * wksp ) {
  (void)topo;

  if( FD_LIKELY( wksp->wksp ) ) {
    if( FD_UNLIKELY( fd_wksp_detach( wksp->wksp ) ) ) FD_LOG_ERR(( "fd_wksp_detach failed" ));
    wksp->wksp            = NULL;
    wksp->known_footprint = 0UL;
    wksp->total_footprint = 0UL;
  }
}

void
fd_topo_leave_workspaces( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_leave_workspace( topo, &topo->workspaces[ i ] );
  }
}

extern char fd_shmem_private_base[ FD_SHMEM_PRIVATE_BASE_MAX ];

int
fd_topo_create_workspace( fd_topo_t *      topo,
                          fd_topo_wksp_t * wksp,
                          int              update_existing ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );

  ulong sub_page_cnt[ 1 ] = { wksp->page_cnt };
  ulong sub_cpu_idx [ 1 ] = { fd_shmem_cpu_idx( wksp->numa_idx ) };

  int err;
  if( FD_UNLIKELY( update_existing ) ) {
    err = fd_shmem_update_multi( name, wksp->page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
  } else {
    err = fd_shmem_create_multi( name, wksp->page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
  }
  if( FD_UNLIKELY( err && errno==ENOMEM ) ) return -1;
  else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi failed" ));

  void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ); /* logs details */

  void * wkspmem = fd_wksp_new( shmem, name, 0U, wksp->part_max, wksp->total_footprint ); /* logs details */
  if( FD_UNLIKELY( !wkspmem ) ) FD_LOG_ERR(( "fd_wksp_new failed" ));

  fd_wksp_t * join = fd_wksp_join( wkspmem );
  if( FD_UNLIKELY( !join ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

  /* Footprint has been predetermined so that this alloc() call must
      succeed inside the data region.  The difference between total_footprint
      and known_footprint is given to "loose" data, that may be dynamically
      allocated out of the workspace at runtime. */
  if( FD_LIKELY( wksp->known_footprint ) ) {
    ulong offset = fd_wksp_alloc( join, fd_topo_workspace_align(), wksp->known_footprint, 1UL );
    if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));

    /* gaddr_lo is the start of the workspace data region that can be
        given out in response to wksp alloc requests.  We rely on an
        implicit assumption everywhere that the bytes we are given by
        this single allocation will be at gaddr_lo, so that we can find
        them, so we verify this here for paranoia in case the workspace
        alloc implementation changes. */
    if( FD_UNLIKELY( fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ) != offset ) )
      FD_LOG_ERR(( "wksp gaddr_lo %lu != offset %lu", fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ), offset ));
  }

  fd_wksp_leave( join );

  if( FD_UNLIKELY( fd_shmem_leave( shmem, NULL, NULL ) ) ) /* logs details */
    FD_LOG_ERR(( "fd_shmem_leave failed" ));

  return 0;
}

void
fd_topo_wksp_apply( fd_topo_t *      topo,
                    fd_topo_wksp_t * wksp,
                    void (* fn )( fd_topo_t const * topo, fd_topo_obj_t const * obj ) ) {
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t * obj = &topo->objs[ i ];
    if( FD_LIKELY( obj->wksp_id!=wksp->id ) ) continue;
    fn( topo, obj );
  }
}

void
fd_topo_workspace_fill( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp ) {
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];

    if( FD_UNLIKELY( topo->objs[ link->mcache_obj_id ].wksp_id!=wksp->id ) ) continue;
    link->mcache = fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) );
    FD_TEST( link->mcache );

    if( FD_LIKELY( link->is_reasm ) ) {
      if( FD_UNLIKELY( topo->objs[ link->reasm_obj_id].wksp_id!=wksp->id ) ) continue;
      link->reasm = fd_tpu_reasm_join( fd_topo_obj_laddr( topo, link->reasm_obj_id ) );
      FD_TEST( link->reasm );
    } else if ( link->mtu ) {
      if( FD_UNLIKELY( topo->objs[ link->dcache_obj_id ].wksp_id!=wksp->id ) ) continue;
      link->dcache = fd_dcache_join( fd_topo_obj_laddr( topo, link->dcache_obj_id ) );
      FD_TEST( link->dcache );
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    if( FD_LIKELY( topo->objs[ tile->metrics_obj_id ].wksp_id==wksp->id ) ) {
      tile->metrics = fd_metrics_join( fd_topo_obj_laddr( topo, tile->metrics_obj_id ) );
      FD_TEST( tile->metrics );
    }

    if( FD_LIKELY( topo->objs[ tile->cnc_obj_id ].wksp_id==wksp->id ) ) {
      tile->cnc = fd_cnc_join( fd_topo_obj_laddr( topo, tile->cnc_obj_id ) );
      FD_TEST( tile->cnc );
    }

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( topo->objs[ tile->in_link_fseq_obj_id[ j ] ].wksp_id!=wksp->id ) ) continue;
      tile->in_link_fseq[ j ] = fd_fseq_join( fd_topo_obj_laddr( topo, tile->in_link_fseq_obj_id[ j ] ) );
      FD_TEST( tile->in_link_fseq[ j ] );
    }
  }
}

void
fd_topo_fill_tile( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( -1!=tile_needs_wksp( topo, tile, i ) ) )
      fd_topo_workspace_fill( topo, &topo->workspaces[ i ] );
  }
}

void
fd_topo_fill( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_workspace_fill( topo, &topo->workspaces[ i ] );
  }
}

FD_FN_CONST static ulong
fd_topo_tile_extra_huge_pages( fd_topo_tile_t const * tile ) {
  (void)tile;

  /* Every tile maps an additional set of pages for the stack. */
  return (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;
}

FD_FN_PURE static ulong
fd_topo_tile_extra_normal_pages( fd_topo_tile_t const * tile ) {
  ulong key_pages = 0UL;
  if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ||
                   !strcmp( tile->name, "pack" ) ) ) {
    /* Shred and pack tiles use 5 normal pages to hold key material. */
    key_pages = 5UL;
  }

  /* All tiles lock one normal page for the fd_log shared lock. */
  return key_pages + 1UL;
}

FD_FN_PURE static ulong
fd_topo_mlock_max_tile1( fd_topo_t const * topo,
                         fd_topo_tile_t *  tile ) {
  ulong tile_mem = 0UL;

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( -1!=tile_needs_wksp( topo, tile, i ) ) )
      tile_mem += topo->workspaces[ i ].page_cnt * topo->workspaces[ i ].page_sz;
  }

  return tile_mem +
      fd_topo_tile_extra_huge_pages( tile ) * FD_SHMEM_HUGE_PAGE_SZ +
      fd_topo_tile_extra_normal_pages( tile ) * FD_SHMEM_NORMAL_PAGE_SZ;
}

FD_FN_PURE ulong
fd_topo_mlock_max_tile( fd_topo_t * topo ) {
  ulong highest_tile_mem = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    highest_tile_mem = fd_ulong_max( highest_tile_mem, fd_topo_mlock_max_tile1( topo, tile ) );
  }

  return highest_tile_mem;
}

FD_FN_PURE ulong
fd_topo_gigantic_page_cnt( fd_topo_t * topo,
                           ulong       numa_idx ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = &topo->workspaces[ i ];
    if( FD_LIKELY( wksp->numa_idx!=numa_idx ) ) continue;

    if( FD_LIKELY( wksp->page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
      result += wksp->page_cnt;
    }
  }
  return result;
}

FD_FN_PURE ulong
fd_topo_huge_page_cnt( fd_topo_t * topo,
                       ulong       numa_idx,
                       int         include_anonymous ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = &topo->workspaces[ i ];
    if( FD_LIKELY( wksp->numa_idx!=numa_idx ) ) continue;

    if( FD_LIKELY( wksp->page_sz==FD_SHMEM_HUGE_PAGE_SZ ) ) {
      result += wksp->page_cnt;
    }
  }

  /* The stack huge pages are also placed in the hugetlbfs. */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    result += fd_topo_tile_extra_huge_pages( &topo->tiles[ i ] );
  }

  /* No anonymous huge pages in use yet. */
  (void)include_anonymous;

  return result;
}

FD_FN_PURE ulong
fd_topo_normal_page_cnt( fd_topo_t * topo ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    result += fd_topo_tile_extra_normal_pages( &topo->tiles[ i ] );
  }
  return result;
}

FD_FN_PURE ulong
fd_topo_mlock( fd_topo_t * topo ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    result += topo->workspaces[ i ].page_cnt * topo->workspaces[ i ].page_sz;
  }
  return result;
}

static void
fd_topo_mem_sz_string( ulong sz, char out[static 24] ) {
  if( FD_LIKELY( sz >= FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%lu GiB", sz / (1 << 30) ) );
  } else {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%lu MiB", sz / (1 << 20) ) );
  }
}

void
fd_topo_print_log( int         stdout,
                   fd_topo_t * topo ) {
  char message[ 8UL*4096UL ] = {0}; /* Same as FD_LOG_BUF_SZ */

  char * cur = message;
  ulong remaining = sizeof(message) - 1; /* Leave one character at the end to ensure NUL terminated */

#define PRINT( ... ) do {                                                           \
    int n = snprintf( cur, remaining, __VA_ARGS__ );                                \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                   \
    if( FD_UNLIKELY( (ulong)n >= remaining ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining -= (ulong)n;                                                          \
    cur += n;                                                                       \
  } while( 0 )

  PRINT( "\nSUMMARY\n" );

  /* The logic to compute number of stack pages is taken from
     fd_tile_thread.cxx, in function fd_topo_tile_stack_new, and this
     should match that. */
  ulong stack_pages = topo->tile_cnt * FD_SHMEM_HUGE_PAGE_SZ * ((FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL);

  /* The logic to map these private pages into memory is in utility.c,
     under fd_keyload_load, and the amount of pages should be kept in
     sync. */
  ulong private_key_pages = 5UL * FD_SHMEM_NORMAL_PAGE_SZ;
  ulong total_bytes = fd_topo_mlock( topo ) + stack_pages + private_key_pages;

  PRINT("  %23s: %lu\n", "Total Tiles", topo->tile_cnt );
  PRINT("  %23s: %lu bytes (%lu GiB + %lu MiB + %lu KiB)\n",
    "Total Memory Locked",
    total_bytes,
    total_bytes / (1 << 30),
    (total_bytes % (1 << 30)) / (1 << 20),
    (total_bytes % (1 << 20)) / (1 << 10) );

  ulong required_gigantic_pages = 0UL;
  ulong required_huge_pages = 0UL;

  ulong numa_node_cnt = fd_shmem_numa_cnt();
  for( ulong i=0UL; i<numa_node_cnt; i++ ) {
    required_gigantic_pages += fd_topo_gigantic_page_cnt( topo, i );
    required_huge_pages += fd_topo_huge_page_cnt( topo, i, 0 );
  }
  PRINT("  %23s: %lu\n", "Required Gigantic Pages", required_gigantic_pages );
  PRINT("  %23s: %lu\n", "Required Huge Pages", required_huge_pages );
  PRINT("  %23s: %lu\n", "Required Normal Pages", fd_topo_normal_page_cnt( topo ) );
  for( ulong i=0UL; i<numa_node_cnt; i++ ) {
    PRINT("  %23s (NUMA node %lu): %lu\n", "Required Gigantic Pages", i, fd_topo_gigantic_page_cnt( topo, i ) );
    PRINT("  %23s (NUMA node %lu): %lu\n", "Required Huge Pages", i, fd_topo_huge_page_cnt( topo, i, 0 ) );
  }

  PRINT( "\nWORKSPACES\n");
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    char size[ 24 ];
    fd_topo_mem_sz_string( wksp->page_sz * wksp->page_cnt, size );
    PRINT( "  %2lu (%7s): %12s  page_cnt=%lu  page_sz=%-8s  numa_idx=%-2lu  footprint=%-10lu  loose=%lu\n", i, size, wksp->name, wksp->page_cnt, fd_shmem_page_sz_to_cstr( wksp->page_sz ), wksp->numa_idx, wksp->known_footprint, wksp->total_footprint - wksp->known_footprint );
  }

  PRINT( "\nLINKS\n" );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];

    char size[ 24 ];
    if( FD_UNLIKELY( !strcmp( link->name, "quic_verify" ) ) ) {
      fd_topo_mem_sz_string( fd_tpu_reasm_footprint( link->depth, link->burst ), size );
    } else {
      fd_topo_mem_sz_string( fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ), size );
    }
    PRINT( "  %2lu (%7s): %12s  kind_id=%-2lu  wksp_id=%-2lu  depth=%-5lu  mtu=%-9lu  burst=%lu\n", i, size, link->name, link->kind_id, topo->objs[ link->dcache_obj_id ].wksp_id, link->depth, link->mtu, link->burst );
  }

#define PRINTIN( ... ) do {                                                            \
    int n = snprintf( cur_in, remaining_in, __VA_ARGS__ );                             \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                      \
    if( FD_UNLIKELY( (ulong)n >= remaining_in ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_in -= (ulong)n;                                                          \
    cur_in += n;                                                                       \
  } while( 0 )

#define PRINTOUT( ... ) do {                                                            \
    int n = snprintf( cur_out, remaining_in, __VA_ARGS__ );                             \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                       \
    if( FD_UNLIKELY( (ulong)n >= remaining_out ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_out -= (ulong)n;                                                          \
    cur_out += n;                                                                       \
  } while( 0 )

  PRINT( "\nTILES\n" );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    char in[ 1024 ] = {0};
    char * cur_in = in;
    ulong remaining_in = sizeof( in ) - 1;

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTIN( ", " );
      if( FD_LIKELY( tile->in_link_reliable[ j ] ) ) PRINTIN( "%2lu", tile->in_link_id[ j ] );
      else PRINTIN( "%2ld", -tile->in_link_id[ j ] );
    }

    char out[ 1024 ] = {0};
    char * cur_out = out;
    ulong remaining_out = sizeof( out ) - 1;

    for( ulong j=0UL; j<tile->out_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTOUT( ", " );
      PRINTOUT( "%2lu", tile->out_link_id[ j ] );
    }

    char out_link_id[ 24 ] = "-1";
    if( tile->out_link_id_primary != ULONG_MAX )
      FD_TEST( fd_cstr_printf_check( out_link_id, 24, NULL, "%lu", tile->out_link_id_primary ) );
    char size[ 24 ];
    fd_topo_mem_sz_string( fd_topo_mlock_max_tile1( topo, tile ), size );
    PRINT( "  %2lu (%7s): %12s  kind_id=%-2lu  wksp_id=%-2lu  cpu_idx=%-2lu  out_link=%-2s  in=[%s]  out=[%s]", i, size, tile->name, tile->kind_id, topo->objs[ tile->tile_obj_id ].wksp_id, tile->cpu_idx, out_link_id, in, out );
    if( FD_LIKELY( i != topo->tile_cnt-1 ) ) PRINT( "\n" );
  }

  if( FD_UNLIKELY( stdout ) ) FD_LOG_STDOUT(( "%s\n", message ));
  else                        FD_LOG_NOTICE(( "%s", message ));
}
