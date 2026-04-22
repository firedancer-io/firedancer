#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>

struct mem_obj_entry {
  ulong footprint;
  char  wksp[ 13 ];
  char  obj[ 13 ];
};
typedef struct mem_obj_entry mem_obj_entry_t;

#define SORT_NAME        sort_obj_by_footprint
#define SORT_KEY_T       mem_obj_entry_t
#define SORT_BEFORE(a,b) ((a).footprint>(b).footprint)
#include "../../../util/tmpl/fd_sort.c"

extern action_t * ACTIONS[];

static void
mem_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );
  args->mem.sort = fd_env_strip_cmdline_contains( pargc, pargv, "--sort" );

  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->mem.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->mem.topo ), topo_name, topo_name_len ) );
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; *a; a++ ) {
    action_t const * action = *a;
    if( 0==strcmp( action->name, topo_name ) ) {
      selected = action;
      break;
    }
  }

  if( !selected       ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  if( !selected->topo ) FD_LOG_ERR(( "Cannot recover topology for --topo %s", topo_name ));

  selected->topo( config );
}

void
mem_cmd_fn( args_t *   args,
            config_t * config ) {
  reconstruct_topo( config, args->mem.topo );

  if( FD_UNLIKELY( args->mem.sort ) ) {
    fd_topo_t * topo = &config->topo;

    /* Max entries: objects + per-wksp loose + per-wksp overhead + extra pages */
    mem_obj_entry_t entries[ FD_TOPO_MAX_OBJS + 2UL*FD_TOPO_MAX_WKSPS + 2UL ];
    ulong cnt = 0UL;

    /* Real topology objects */
    for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
      fd_topo_obj_t * obj = &topo->objs[ i ];
      entries[ cnt ].footprint = obj->footprint;
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].wksp ), topo->workspaces[ obj->wksp_id ].name, sizeof(entries[ cnt ].wksp)-1 ) );
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].obj ), obj->name, sizeof(entries[ cnt ].obj)-1 ) );
      cnt++;
    }

    /* Per-workspace loose memory and page rounding overhead */
    for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
      fd_topo_wksp_t * wksp = &topo->workspaces[ i ];
      ulong loose = wksp->total_footprint - wksp->known_footprint;
      if( loose ) {
        entries[ cnt ].footprint = loose;
        fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].wksp ), wksp->name, sizeof(entries[ cnt ].wksp)-1 ) );
        fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].obj ), "loose", 5 ) );
        cnt++;
      }
      ulong pages_sz = wksp->page_cnt * wksp->page_sz;
      ulong overhead = pages_sz - wksp->total_footprint;
      if( overhead ) {
        entries[ cnt ].footprint = overhead;
        fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].wksp ), wksp->name, sizeof(entries[ cnt ].wksp)-1 ) );
        fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].obj ), "padding", 7 ) );
        cnt++;
      }
    }

    /* Tile stacks: each tile maps (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2
       huge pages for its stack (see fd_topo_tile_extra_huge_pages). */
    ulong stack_huge_pages = topo->tile_cnt * ((FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL);
    if( stack_huge_pages ) {
      entries[ cnt ].footprint = stack_huge_pages * FD_SHMEM_HUGE_PAGE_SZ;
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].wksp ), "", 0 ) );
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].obj ), "tile_stacks", 11 ) );
      cnt++;
    }

    /* Extra normal pages (private keys, XSK rings, log locks, etc.) */
    ulong extra_normal = fd_topo_normal_page_cnt( topo );
    if( extra_normal ) {
      entries[ cnt ].footprint = extra_normal * FD_SHMEM_NORMAL_PAGE_SZ;
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].wksp ), "", 0 ) );
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( entries[ cnt ].obj ), "normal_pages", 12 ) );
      cnt++;
    }

    sort_obj_by_footprint_inplace( entries, cnt );

    ulong total = 0UL;
    for( ulong i=0UL; i<cnt; i++ ) total += entries[ i ].footprint;

    FD_LOG_STDOUT(( "%7s  %6s  %15s  %10s  %7s  %15s  %12s  %12s\n", "SIZE", "PCT", "BYTES", "CUM SIZE", "CUM PCT", "CUM BYTES", "WORKSPACE", "OBJECT" ));
    FD_LOG_STDOUT(( "-------  ------  ---------------  ----------  -------  ---------------  ------------  ------------\n" ));
    ulong cum = 0UL;
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong sz = entries[ i ].footprint;
      cum += sz;
      char sz_str[ 24 ], cum_str[ 24 ];
      if( FD_LIKELY( sz >= (1UL<<30) ) )      FD_TEST( fd_cstr_printf_check( sz_str, 24, NULL, "%lu GiB", sz / (1UL<<30) ) );
      else if( FD_LIKELY( sz >= (1UL<<20) ) ) FD_TEST( fd_cstr_printf_check( sz_str, 24, NULL, "%lu MiB", sz / (1UL<<20) ) );
      else if( FD_LIKELY( sz >= (1UL<<10) ) ) FD_TEST( fd_cstr_printf_check( sz_str, 24, NULL, "%lu KiB", sz / (1UL<<10) ) );
      else                                    FD_TEST( fd_cstr_printf_check( sz_str, 24, NULL, "%lu B",   sz             ) );
      if( FD_LIKELY( cum >= (1UL<<30) ) )      FD_TEST( fd_cstr_printf_check( cum_str, 24, NULL, "%lu GiB", cum / (1UL<<30) ) );
      else if( FD_LIKELY( cum >= (1UL<<20) ) ) FD_TEST( fd_cstr_printf_check( cum_str, 24, NULL, "%lu MiB", cum / (1UL<<20) ) );
      else if( FD_LIKELY( cum >= (1UL<<10) ) ) FD_TEST( fd_cstr_printf_check( cum_str, 24, NULL, "%lu KiB", cum / (1UL<<10) ) );
      else                                     FD_TEST( fd_cstr_printf_check( cum_str, 24, NULL, "%lu B",   cum             ) );
      double pct     = total ? 100.0 * (double)sz  / (double)total : 0.0;
      double cum_pct = total ? 100.0 * (double)cum / (double)total : 0.0;
      FD_LOG_STDOUT(( "%7s  %5.1f%%  %15lu  %10s  %6.1f%%  %15lu  %12s  %12s\n", sz_str, pct, sz, cum_str, cum_pct, cum, entries[ i ].wksp, entries[ i ].obj ));
    }

    char total_str[ 24 ];
    if( FD_LIKELY( total >= (1UL<<30) ) )      FD_TEST( fd_cstr_printf_check( total_str, 24, NULL, "%lu GiB", total / (1UL<<30) ) );
    else if( FD_LIKELY( total >= (1UL<<20) ) ) FD_TEST( fd_cstr_printf_check( total_str, 24, NULL, "%lu MiB", total / (1UL<<20) ) );
    else if( FD_LIKELY( total >= (1UL<<10) ) ) FD_TEST( fd_cstr_printf_check( total_str, 24, NULL, "%lu KiB", total / (1UL<<10) ) );
    else                                       FD_TEST( fd_cstr_printf_check( total_str, 24, NULL, "%lu B",   total             ) );
    FD_LOG_STDOUT(( "-------  ------  ---------------  ----------  -------  ---------------  ------------  ------------\n" ));
    FD_LOG_STDOUT(( "%7s  %5.1f%%  %15lu  %10s  %6.1f%%  %15lu  %12s\n", total_str, 100.0, total, total_str, 100.0, total, "TOTAL" ));
    return;
  }

  fd_topo_print_log( 1, &config->topo );
}

action_t fd_action_mem = {
  .name           = "mem",
  .args           = mem_cmd_args,
  .fn             = mem_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Print workspace memory and tile topology information",
};
