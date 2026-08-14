#include "fd_topo.h"

#include "../metrics/fd_metrics.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../util/shmem/fd_shmem_private.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

void *
fd_topo_obj_laddr( fd_topo_t const * topo,
                   ulong             obj_id ) {
  fd_topo_obj_t const * obj = &topo->objs[ obj_id ];
  if( FD_UNLIKELY( obj_id==ULONG_MAX ) ) FD_LOG_CRIT(( "invalid obj_id ULONG_MAX" ));
  if( FD_UNLIKELY( obj_id>=FD_TOPO_MAX_OBJS ) ) FD_LOG_CRIT(( "invalid obj_id %lu", obj_id ));
  FD_TEST( obj->id == obj_id );
  FD_TEST( obj->offset );
  return (void *)((ulong)topo->workspaces[ obj->wksp_id ].wksp + obj->offset);
}

void
fd_topo_join_workspace( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp,
                        int              mode,
                        int              dump ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );

  wksp->wksp = fd_wksp_join( fd_shmem_join( name, mode, dump, NULL, NULL, NULL ) );
  if( FD_UNLIKELY( !wksp->wksp ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));
}

FD_FN_PURE static int
tile_needs_wksp( fd_topo_t const * topo, fd_topo_tile_t const * tile, ulong wksp_id ) {
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
                              fd_topo_tile_t * tile,
                              int              core_dump_level ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    int needs_wksp = tile_needs_wksp( topo, tile, i );
    if( FD_LIKELY( -1!=needs_wksp ) ) {
      int dump = core_dump_level >= topo->workspaces[ i ].core_dump_level ? 1 : 0;
      fd_topo_join_workspace( topo, &topo->workspaces[ i ], needs_wksp, dump );
    }
  }
}

void
fd_topo_join_workspaces( fd_topo_t * topo,
                         int         mode,
                         int         core_dump_level ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    int dump = core_dump_level >= topo->workspaces[ i ].core_dump_level ? 1 : 0;
    fd_topo_join_workspace( topo, &topo->workspaces[ i ], mode, dump  );
  }
}

void
fd_topo_leave_workspace( fd_topo_t *      topo FD_PARAM_UNUSED,
                         fd_topo_wksp_t * wksp ) {
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

  void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, 0, NULL, NULL, NULL ); /* logs details */

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
fd_topo_wksp_new( fd_topo_t const *          topo,
                  fd_topo_wksp_t const *     wksp,
                  fd_topo_obj_callbacks_t ** callbacks ) {
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t const * obj = &topo->objs[ i ];
    if( FD_LIKELY( obj->wksp_id!=wksp->id ) ) continue;

    for( ulong j=0UL; callbacks[ j ]; j++ ) {
      if( FD_LIKELY( strcmp( callbacks[ j ]->name, obj->name ) ) ) continue;

      long ts = -fd_log_wallclock();
      if( FD_LIKELY( callbacks[ j ]->new ) ) callbacks[ j ]->new( topo, obj );
      long elapsed = fd_log_wallclock() + ts;
      if( FD_UNLIKELY( elapsed>(1000L*1000L*150L ) ) ) FD_LOG_WARNING(( "fd_topo_wksp_new(%s) took %ld ms", obj->name, elapsed/(1000L*1000L) ));
      else if( FD_UNLIKELY( elapsed>(1000L*1000L*5L ) ) ) FD_LOG_INFO(( "fd_topo_wksp_new(%s) took %ld ms", obj->name, elapsed/(1000L*1000L) ));
      break;
    }
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

    if( link->mtu ) {
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
  /* Every tile maps an additional set of pages for the stack. */
  (void)tile;
  return (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;
}

FD_FN_PURE static ulong
fd_topo_tile_extra_normal_pages( fd_topo_tile_t const * tile ) {
  ulong key_pages = 0UL;
  if( FD_UNLIKELY( tile->id_keyswitch_obj_id!=ULONG_MAX ) ) {
    /* Certain tiles using fd_keyload_load need normal pages to hold
       key material. */
    key_pages += 5UL;
  }
  if( FD_UNLIKELY( tile->av_keyswitch_obj_id!=ULONG_MAX ) ) {
    /* Certain tiles using fd_keyload_load need normal pages to hold
       key material. */
    key_pages += 5UL;
  }

  if( !strcmp( tile->name, "net" ) ) {
      /* net tile uses normal pages to hold xsk rings */

      /* xdp_desc struct is in linux UAPI so its size can be
         safely assumed */
      ulong xdp_desc_sz_bytes    = 16UL;
      ulong xsk_rings_sz_bytes   = 0UL;
      ulong xdp_address_sz_bytes = sizeof(ulong);

      /* rx ring */
      xsk_rings_sz_bytes += tile->xdp.xdp_rx_queue_size * xdp_desc_sz_bytes;
      /* tx ring */
      xsk_rings_sz_bytes += tile->xdp.xdp_tx_queue_size * xdp_desc_sz_bytes;

      /* completion ring */
      xsk_rings_sz_bytes += tile->xdp.xdp_tx_queue_size * xdp_address_sz_bytes;
      /* free ring */
      xsk_rings_sz_bytes += tile->xdp.free_ring_depth   * xdp_address_sz_bytes;

      key_pages += fd_ulong_align_up( xsk_rings_sz_bytes, FD_SHMEM_NORMAL_PAGE_SZ ) / FD_SHMEM_NORMAL_PAGE_SZ;

      /* All 4 rings must store a ring header. This is 320 bytes
         per ring as of linux v6.18.3, however could change in
         the future so allow up to a full 4KB page per ring to
         be safe. */
      key_pages += 4UL;
  }

  return key_pages;
}

FD_FN_PURE static ulong
fd_topo_mlock_max_tile1( fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile ) {
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
fd_topo_mlock_max_tile( fd_topo_t const * topo ) {
  ulong highest_tile_mem = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    highest_tile_mem = fd_ulong_max( highest_tile_mem, fd_topo_mlock_max_tile1( topo, tile ) );
  }

  return highest_tile_mem;
}

FD_FN_PURE ulong
fd_topo_gigantic_page_cnt( fd_topo_t const * topo,
                           ulong             numa_idx ) {
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
fd_topo_huge_page_cnt( fd_topo_t const * topo,
                       ulong             numa_idx,
                       int               include_anonymous ) {
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
fd_topo_normal_page_cnt( fd_topo_t const * topo ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    result += fd_topo_tile_extra_normal_pages( &topo->tiles[ i ] );
  }
  return result;
}

FD_FN_PURE ulong
fd_topo_mlock( fd_topo_t const * topo ) {
  ulong result = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    result += topo->workspaces[ i ].page_cnt * topo->workspaces[ i ].page_sz;
  }
  return result;
}

static void
fd_topo_mem_sz_string( ulong sz, char out[static 24] ) {
  if( FD_LIKELY( sz >= FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%.1f GiB", (double)sz / (double)(1UL << 30) ) );
  } else if( FD_LIKELY( sz >= 1048576 ) ) {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%.1f MiB", (double)sz / (double)(1UL << 20) ) );
  } else if( FD_LIKELY( sz >= 1024 ) ) {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%.1f KiB", (double)sz / (double)(1UL << 10) ) );
  } else {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%lu B", sz ) );
  }
}

/* Style sizes by magnitude so the big numbers pop */

static char const *
fd_topo_mem_sz_style( ulong        sz,
                      char const * bold,
                      char const * dim ) {
  if( sz>=(1UL<<30) ) return bold;
  if( sz< (1UL<<20) ) return dim;
  return "";
}

void
fd_topo_print_log( int         stdout,
                   fd_topo_t * topo ) {
  char message[ 32UL*4096UL ] = {0}; /* Same as FD_LOG_BUF_SZ */

  char * cur = message;
  ulong remaining = sizeof(message) - 1; /* Leave one character at the end to ensure NUL terminated */

#define PRINT( ... ) do {                                                             \
    int n = snprintf( cur, remaining, __VA_ARGS__ );                                  \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                     \
    if( FD_UNLIKELY( (ulong)n >= remaining ) ) {                                      \
      /* stdout mode flushes and retries, log mode keeps one message */               \
      if( FD_UNLIKELY( !stdout ) ) FD_LOG_ERR(( "snprintf overflow" ));               \
      *cur = '\0';                                                                    \
      FD_LOG_STDOUT(( "%s", message ));                                               \
      cur = message; remaining = sizeof(message) - 1;                                 \
      n = snprintf( cur, remaining, __VA_ARGS__ );                                    \
      if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                   \
      if( FD_UNLIKELY( (ulong)n >= remaining ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    }                                                                                 \
    remaining -= (ulong)n;                                                            \
    cur += n;                                                                         \
  } while( 0 )

  int color = stdout && fd_log_colorize() && isatty( STDOUT_FILENO );
  char const * c_bold   = color ? "\033[1m" : "";
  char const * c_dim    = color ? "\033[2m" : "";
  char const * c_normal = color ? "\033[0m" : "";

  char const * sep = "";

#define SECTION( ... ) do {                                                            \
    char _title[ 64 ];                                                                \
    FD_TEST( fd_cstr_printf_check( _title, sizeof(_title), NULL, __VA_ARGS__ ) );     \
    PRINT( "%s%s──%s %s%s%s %s", sep, c_dim, c_normal, c_bold, _title, c_normal, c_dim ); \
    for( ulong _i=strlen( _title ); _i<76UL; _i++ ) PRINT( "─" );                     \
    PRINT( "%s\n", c_normal );                                                        \
    sep = "\n";                                                                       \
  } while( 0 )

  SECTION( "Summary" );

  /* The logic to compute number of stack pages is taken from
     fd_tile_thread.cxx, in function fd_topo_tile_stack_join, and this
     should match that. */
  ulong stack_pages = topo->tile_cnt * FD_SHMEM_HUGE_PAGE_SZ * ((FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL);

  ulong normal_page_bytes = fd_topo_normal_page_cnt( topo ) * FD_SHMEM_NORMAL_PAGE_SZ;
  ulong total_bytes = fd_topo_mlock( topo ) + stack_pages + normal_page_bytes;

  PRINT("  %s%-23s%s  %lu\n", c_dim, "Total Tiles", c_normal, topo->tile_cnt );
  PRINT("  %s%-23s%s  %s%lu GiB + %lu MiB + %lu KiB%s  %s(%lu bytes)%s\n",
    c_dim, "Total Memory Locked", c_normal,
    c_bold,
    total_bytes / (1 << 30),
    (total_bytes % (1 << 30)) / (1 << 20),
    (total_bytes % (1 << 20)) / (1 << 10),
    c_normal,
    c_dim, total_bytes, c_normal );

  ulong required_gigantic_pages = 0UL;
  ulong required_huge_pages = 0UL;

  ulong numa_node_cnt = fd_shmem_numa_cnt();
  for( ulong i=0UL; i<numa_node_cnt; i++ ) {
    required_gigantic_pages += fd_topo_gigantic_page_cnt( topo, i );
    required_huge_pages += fd_topo_huge_page_cnt( topo, i, 0 );
  }
  PRINT("  %s%-23s%s  %lu\n", c_dim, "Required Gigantic Pages", c_normal, required_gigantic_pages );
  PRINT("  %s%-23s%s  %lu\n", c_dim, "Required Huge Pages", c_normal, required_huge_pages );
  PRINT("  %s%-23s%s  %lu\n", c_dim, "Required Normal Pages", c_normal, fd_topo_normal_page_cnt( topo ) );
  if( FD_UNLIKELY( numa_node_cnt>1UL ) ) {
    for( ulong i=0UL; i<numa_node_cnt; i++ ) {
      char label[ 40 ];
      FD_TEST( fd_cstr_printf_check( label, sizeof(label), NULL, "NUMA node %lu", i ) );
      PRINT("  %s%-23s%s  %lu gigantic, %lu huge\n", c_dim, label, c_normal, fd_topo_gigantic_page_cnt( topo, i ), fd_topo_huge_page_cnt( topo, i, 0 ) );
    }
  }

  if( FD_UNLIKELY( topo->agave_affinity_cnt>0UL ) ) {
    char agave_affinity[4096];
    ulong offset = 0UL;
    for ( ulong i = 0UL; i < topo->agave_affinity_cnt; i++ ) {
      ulong sz;
      if( FD_LIKELY( i != 0UL )) FD_TEST( fd_cstr_printf_check( agave_affinity+offset, 4096-offset, &sz, ", %lu", topo->agave_affinity_cpu_idx[ i ] ) );
      else                       FD_TEST( fd_cstr_printf_check( agave_affinity+offset, 4096-offset, &sz, "%lu", topo->agave_affinity_cpu_idx[ i ] ) );
      offset += sz;
    }
    PRINT( "  %s%-23s%s  %s\n", c_dim, "Agave Affinity", c_normal, agave_affinity );
  }

  SECTION( "Workspaces (%lu)", topo->wksp_cnt );
  PRINT( "  %s%3s  %10s  %-13s  %5s  %-8s  %4s  %12s  %12s%s\n", c_dim, "ID", "SIZE", "NAME", "PAGES", "PAGE SZ", "NUMA", "FOOTPRINT", "LOOSE", c_normal );
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    ulong sz = wksp->page_sz * wksp->page_cnt;
    char size[ 24 ];
    fd_topo_mem_sz_string( sz, size );
    PRINT( "  %3lu  %s%10s%s  %-13s  %5lu  %-8s  %4lu  %12lu  %s%12lu%s\n",
           i, fd_topo_mem_sz_style( sz, c_bold, c_dim ), size, c_normal,
           wksp->name, wksp->page_cnt, fd_shmem_page_sz_to_cstr( wksp->page_sz ), wksp->numa_idx,
           wksp->known_footprint, c_dim, wksp->total_footprint - wksp->known_footprint, c_normal );
  }

  SECTION( "Objects (%lu)", topo->obj_cnt );
  PRINT( "  %s%4s  %10s  %-13s  %-13s  %4s  %12s  %s%s\n", c_dim, "ID", "SIZE", "WORKSPACE", "OBJECT", "WKSP", "OFFSET", "PROPERTIES", c_normal );
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t * obj = &topo->objs[ i ];

    char size[ 24 ];
    fd_topo_mem_sz_string( obj->footprint, size );
    PRINT( "  %4lu  %s%10s%s  %-13s  %-13s  %4lu  %12lu ",
           i, fd_topo_mem_sz_style( obj->footprint, c_bold, c_dim ), size, c_normal,
           topo->workspaces[ obj->wksp_id ].name, obj->name,
           obj->wksp_id, obj->offset );
    for( fd_pod_iter_t iter=fd_pod_iter_init( fd_pod_queryf_subpod( topo->props, "obj.%lu", obj->id ) );
         !fd_pod_iter_done( iter );
         iter=fd_pod_iter_next( iter ) ) {
      fd_pod_info_t info = fd_pod_iter_info( iter );
      if( !strcmp( info.key, "seed" ) ) continue; /* key is a cstr (key_sz includes NUL) */
      PRINT( " %s%.*s=%s", c_dim, (int)info.key_sz, info.key, c_normal );
      switch( info.val_type ) {
      case FD_POD_VAL_TYPE_CSTR:
        PRINT( "%.*s", (int)info.val_sz, (char const *)info.val );
        break;
      case FD_POD_VAL_TYPE_ULONG: {
        ulong val; fd_ulong_svw_dec( info.val, &val );
        PRINT( "%lu", val );
        break;
      }
      case FD_POD_VAL_TYPE_INT: {
        ulong u; fd_ulong_svw_dec( info.val, &u );
        PRINT( "%i", (int)fd_long_zz_dec( u ) );
        break;
      }
      }
    }
    PRINT( "\n" );
  }

  SECTION( "Links (%lu)", topo->link_cnt );
  PRINT( "  %s%3s  %10s  %-13s  %4s  %4s  %8s  %9s  %5s%s\n", c_dim, "ID", "SIZE", "NAME", "KIND", "WKSP", "DEPTH", "MTU", "BURST", c_normal );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];

    ulong sz = fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 );
    char size[ 24 ];
    fd_topo_mem_sz_string( sz, size );
    PRINT( "  %3lu  %s%10s%s  %-13s  %4lu  %4lu  %8lu  %9lu  %5lu\n",
           i, fd_topo_mem_sz_style( sz, c_bold, c_dim ), size, c_normal,
           link->name, link->kind_id, topo->objs[ link->mcache_obj_id ].wksp_id, link->depth, link->mtu, link->burst );
  }

#define PRINTIN( ... ) do {                                                            \
    int n = snprintf( cur_in, remaining_in, __VA_ARGS__ );                             \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                      \
    if( FD_UNLIKELY( (ulong)n >= remaining_in ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_in -= (ulong)n;                                                          \
    cur_in += n;                                                                       \
  } while( 0 )

#define PRINTOUT( ... ) do {                                                            \
    int n = snprintf( cur_out, remaining_out, __VA_ARGS__ );                            \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                       \
    if( FD_UNLIKELY( (ulong)n >= remaining_out ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_out -= (ulong)n;                                                          \
    cur_out += n;                                                                       \
  } while( 0 )

  SECTION( "Tiles (%lu)", topo->tile_cnt );
  PRINT( "  %s%3s  %10s  %-13s  %4s  %4s  %4s  %4s  %s%s\n", c_dim, "ID", "MLOCK", "NAME", "KIND", "WKSP", "CPU", "NUMA", "LINKS / OBJECTS", c_normal );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    char in[ 256 ] = {0};
    char * cur_in = in;
    ulong remaining_in = sizeof( in ) - 1;

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTIN( ", " );
      if( FD_LIKELY( tile->in_link_reliable[ j ] ) ) PRINTIN( "%2lu", tile->in_link_id[ j ] );
      else PRINTIN( "%2ld", (long)-tile->in_link_id[ j ] );
    }

    char out[ 256 ] = {0};
    char * cur_out = out;
    ulong remaining_out = sizeof( out ) - 1;

    for( ulong j=0UL; j<tile->out_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTOUT( ", " );
      PRINTOUT( "%2lu", tile->out_link_id[ j ] );
    }

    /* Determine tile's NUMA node either based on CPU or wksp affinity */
    ulong tile_numa = 0UL;
    if( tile->cpu_idx!=ULONG_MAX ) {
      tile_numa = fd_shmem_numa_idx( tile->cpu_idx );
    } else {
      tile_numa = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].numa_idx;
    }

    ulong mlock = fd_topo_mlock_max_tile1( topo, tile );
    char size[ 24 ];
    fd_topo_mem_sz_string( mlock, size );
    PRINT( "  %3lu  %s%10s%s  %-13s  %4lu  %4lu  ",
           i, fd_topo_mem_sz_style( mlock, c_bold, c_dim ), size, c_normal,
           tile->name, tile->kind_id, topo->objs[ tile->tile_obj_id ].wksp_id );
    if( tile->cpu_idx!=ULONG_MAX ) {
      PRINT( "%4lu", tile->cpu_idx );
    } else {
      PRINT( "%s%4s%s", c_dim, "any", c_normal );
    }

    PRINT( "  %4lu  %sin=%s[%s]  %sout=%s[%s]  %sobjs=[", tile_numa, c_dim, c_normal, in, c_dim, c_normal, out, c_dim );
    for( ulong j=0UL; j<tile->uses_obj_cnt; j++ ) {
      if( FD_LIKELY( j!=0 ) ) PRINT( " " );
      int is_rw = tile->uses_obj_mode[ j ] == FD_SHMEM_JOIN_MODE_READ_WRITE;
      PRINT( "%lu:%s", tile->uses_obj_id[ j ], is_rw?"rw":"ro" );
    }
    PRINT( "]%s", c_normal );

#if 0
    PRINT( "  wksps=[" );
    for( ulong j=0UL; j<topo->wksp_cnt; j++ ) {
      int mode = tile_needs_wksp( topo, tile, j );
      if( FD_UNLIKELY( -1!=mode ) ) {
        if( FD_LIKELY( j!=0 ) ) PRINT( " " );
        PRINT( "%s:%s", topo->workspaces[ j ].name, mode==FD_SHMEM_JOIN_MODE_READ_WRITE?"rw":"ro" );
      }
    }
    PRINT( "]" );
#endif

    if( FD_LIKELY( i != topo->tile_cnt-1 ) ) PRINT( "\n" );
  }

  if( FD_UNLIKELY( stdout ) ) FD_LOG_STDOUT(( "%s\n", message ));
  else                        FD_LOG_INFO(( "%s", message ));

#undef PRINT
#undef PRINTIN
#undef PRINTOUT
#undef SECTION
}

/* PRINT_JSON_CSTR streams src (sz bytes, embedded NULs stop early)
   as a JSON string literal, escaping quotes, backslashes and control
   characters.  No fixed intermediate buffer: expansion cannot
   truncate regardless of src length or content. */

#define PRINT_JSON_CSTR( src, sz ) do {                                               \
    char const * _s  = (src);                                                         \
    ulong        _sz = (sz);                                                          \
    PRINT( "\"" );                                                                    \
    for( ulong _i=0UL; _i<_sz && _s[ _i ]; _i++ ) {                                   \
      uchar _c = (uchar)_s[ _i ];                                                     \
      if(      FD_UNLIKELY( _c=='"' || _c=='\\' ) ) PRINT( "\\%c", (char)_c );        \
      else if( FD_UNLIKELY( _c<0x20 ) )             PRINT( "\\u%04x", (uint)_c );     \
      else                                          PRINT( "%c", (char)_c );          \
    }                                                                                 \
    PRINT( "\"" );                                                                    \
  } while( 0 )

void
fd_topo_print_json( fd_topo_t * topo ) {
  char message[ 32UL*4096UL ] = {0};

  char * cur = message;
  ulong remaining = sizeof(message) - 1;

#define PRINT( ... ) do {                                                             \
    int n = snprintf( cur, remaining, __VA_ARGS__ );                                  \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                     \
    if( FD_UNLIKELY( (ulong)n >= remaining ) ) {                                      \
      *cur = '\0';                                                                    \
      FD_LOG_STDOUT(( "%s", message ));                                               \
      cur = message; remaining = sizeof(message) - 1;                                 \
      n = snprintf( cur, remaining, __VA_ARGS__ );                                    \
      if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));                   \
      if( FD_UNLIKELY( (ulong)n >= remaining ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    }                                                                                 \
    remaining -= (ulong)n;                                                            \
    cur += n;                                                                         \
  } while( 0 )

  ulong stack_pages = topo->tile_cnt * FD_SHMEM_HUGE_PAGE_SZ * ((FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL);
  ulong normal_page_bytes = fd_topo_normal_page_cnt( topo ) * FD_SHMEM_NORMAL_PAGE_SZ;
  ulong total_bytes = fd_topo_mlock( topo ) + stack_pages + normal_page_bytes;

  ulong required_gigantic_pages = 0UL;
  ulong required_huge_pages = 0UL;
  ulong numa_node_cnt = fd_shmem_numa_cnt();
  for( ulong i=0UL; i<numa_node_cnt; i++ ) {
    required_gigantic_pages += fd_topo_gigantic_page_cnt( topo, i );
    required_huge_pages += fd_topo_huge_page_cnt( topo, i, 0 );
  }

  PRINT( "{\n  \"summary\": {\n" );
  PRINT( "    \"tile_cnt\": %lu,\n", topo->tile_cnt );
  PRINT( "    \"total_memory_locked_bytes\": %lu,\n", total_bytes );
  PRINT( "    \"required_gigantic_pages\": %lu,\n", required_gigantic_pages );
  PRINT( "    \"required_huge_pages\": %lu,\n", required_huge_pages );
  PRINT( "    \"required_normal_pages\": %lu,\n", fd_topo_normal_page_cnt( topo ) );
  PRINT( "    \"numa_nodes\": [" );
  for( ulong i=0UL; i<numa_node_cnt; i++ ) {
    PRINT( "%s\n      { \"node\": %lu, \"gigantic_pages\": %lu, \"huge_pages\": %lu }", i ? "," : "", i, fd_topo_gigantic_page_cnt( topo, i ), fd_topo_huge_page_cnt( topo, i, 0 ) );
  }
  PRINT( "\n    ],\n" );
  PRINT( "    \"agave_affinity\": [" );
  for( ulong i=0UL; i<topo->agave_affinity_cnt; i++ ) PRINT( "%s%lu", i ? ", " : "", topo->agave_affinity_cpu_idx[ i ] );
  PRINT( "]\n  },\n" );

  PRINT( "  \"workspaces\": [\n" );
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];
    PRINT( "    { \"id\": %lu, \"name\": ", i );
    PRINT_JSON_CSTR( wksp->name, sizeof(wksp->name) );
    PRINT( ", \"page_cnt\": %lu, \"page_sz\": \"%s\", \"numa_idx\": %lu, \"total_bytes\": %lu, \"footprint\": %lu, \"loose\": %lu }%s\n",
           wksp->page_cnt, fd_shmem_page_sz_to_cstr( wksp->page_sz ), wksp->numa_idx,
           wksp->page_cnt * wksp->page_sz, wksp->known_footprint, wksp->total_footprint - wksp->known_footprint,
           i==topo->wksp_cnt-1UL ? "" : "," );
  }
  PRINT( "  ],\n" );

  PRINT( "  \"objects\": [\n" );
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t * obj = &topo->objs[ i ];
    PRINT( "    { \"id\": %lu, \"name\": ", i );
    PRINT_JSON_CSTR( obj->name, sizeof(obj->name) );
    PRINT( ", \"wksp\": " );
    PRINT_JSON_CSTR( topo->workspaces[ obj->wksp_id ].name, sizeof(topo->workspaces[ obj->wksp_id ].name) );
    PRINT( ", \"wksp_id\": %lu, \"footprint\": %lu, \"offset\": %lu, \"props\": {",
           obj->wksp_id, obj->footprint, obj->offset );
    int first = 1;
    for( fd_pod_iter_t iter=fd_pod_iter_init( fd_pod_queryf_subpod( topo->props, "obj.%lu", obj->id ) );
         !fd_pod_iter_done( iter );
         iter=fd_pod_iter_next( iter ) ) {
      fd_pod_info_t info = fd_pod_iter_info( iter );
      if( !strcmp( info.key, "seed" ) ) continue; /* key is a cstr (key_sz includes NUL) */
      switch( info.val_type ) {
      case FD_POD_VAL_TYPE_CSTR: {
        PRINT( "%s ", first ? "" : "," );
        PRINT_JSON_CSTR( info.key, info.key_sz );
        PRINT( ": " );
        PRINT_JSON_CSTR( (char const *)info.val, info.val_sz );
        first = 0;
        break;
      }
      case FD_POD_VAL_TYPE_ULONG: {
        ulong val; fd_ulong_svw_dec( info.val, &val );
        PRINT( "%s ", first ? "" : "," );
        PRINT_JSON_CSTR( info.key, info.key_sz );
        PRINT( ": %lu", val );
        first = 0;
        break;
      }
      case FD_POD_VAL_TYPE_INT: {
        ulong u; fd_ulong_svw_dec( info.val, &u );
        PRINT( "%s ", first ? "" : "," );
        PRINT_JSON_CSTR( info.key, info.key_sz );
        PRINT( ": %i", (int)fd_long_zz_dec( u ) );
        first = 0;
        break;
      }
      }
    }
    PRINT( "%s} }%s\n", first ? "" : " ", i==topo->obj_cnt-1UL ? "" : "," );
  }
  PRINT( "  ],\n" );

  PRINT( "  \"links\": [\n" );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];
    PRINT( "    { \"id\": %lu, \"name\": ", i );
    PRINT_JSON_CSTR( link->name, sizeof(link->name) );
    PRINT( ", \"kind_id\": %lu, \"wksp_id\": %lu, \"depth\": %lu, \"mtu\": %lu, \"burst\": %lu, \"dcache_bytes\": %lu }%s\n",
           link->kind_id, topo->objs[ link->mcache_obj_id ].wksp_id, link->depth, link->mtu, link->burst,
           fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ),
           i==topo->link_cnt-1UL ? "" : "," );
  }
  PRINT( "  ],\n" );

  PRINT( "  \"tiles\": [\n" );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    ulong tile_numa = 0UL;
    if( tile->cpu_idx!=ULONG_MAX ) tile_numa = fd_shmem_numa_idx( tile->cpu_idx );
    else                           tile_numa = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].numa_idx;

    PRINT( "    { \"id\": %lu, \"name\": ", i );
    PRINT_JSON_CSTR( tile->name, sizeof(tile->name) );
    PRINT( ", \"kind_id\": %lu, \"wksp_id\": %lu, ",
           tile->kind_id, topo->objs[ tile->tile_obj_id ].wksp_id );
    if( tile->cpu_idx!=ULONG_MAX ) PRINT( "\"cpu_idx\": %lu, ", tile->cpu_idx );
    else                           PRINT( "\"cpu_idx\": null, " );
    PRINT( "\"numa_idx\": %lu, \"mlock_bytes\": %lu, \"in_links\": [", tile_numa, fd_topo_mlock_max_tile1( topo, tile ) );
    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      PRINT( "%s{ \"link_id\": %lu, \"reliable\": %s }", j ? ", " : "", tile->in_link_id[ j ], tile->in_link_reliable[ j ] ? "true" : "false" );
    }
    PRINT( "], \"out_links\": [" );
    for( ulong j=0UL; j<tile->out_cnt; j++ ) PRINT( "%s%lu", j ? ", " : "", tile->out_link_id[ j ] );
    PRINT( "], \"objects\": [" );
    for( ulong j=0UL; j<tile->uses_obj_cnt; j++ ) {
      int is_rw = tile->uses_obj_mode[ j ] == FD_SHMEM_JOIN_MODE_READ_WRITE;
      PRINT( "%s{ \"obj_id\": %lu, \"mode\": \"%s\" }", j ? ", " : "", tile->uses_obj_id[ j ], is_rw ? "rw" : "ro" );
    }
    PRINT( "] }%s\n", i==topo->tile_cnt-1UL ? "" : "," );
  }
  PRINT( "  ]\n}" );

#undef PRINT

  FD_LOG_STDOUT(( "%s\n", message ));
}
