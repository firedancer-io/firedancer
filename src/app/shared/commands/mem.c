#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>

struct mem_obj_entry {
  ulong footprint;
  char  wksp[ 14 ]; /* fd_topo_wksp_t.name */
  char  obj[ 13 ];  /* fd_topo_obj_t.name */
};
typedef struct mem_obj_entry mem_obj_entry_t;

#define SORT_NAME        sort_obj_by_footprint
#define SORT_KEY_T       mem_obj_entry_t
#define SORT_BEFORE(a,b) ((a).footprint>(b).footprint)
#include "../../../util/tmpl/fd_sort.c"

extern action_t * ACTIONS[];

static void
fmt_size( char * buf, ulong sz ) {
  if( FD_LIKELY( sz >= (1UL<<30) ) )      FD_TEST( fd_cstr_printf_check( buf, 24, NULL, "%.1f GiB", (double)sz/(double)(1UL<<30) ) );
  else if( FD_LIKELY( sz >= (1UL<<20) ) ) FD_TEST( fd_cstr_printf_check( buf, 24, NULL, "%.1f MiB", (double)sz/(double)(1UL<<20) ) );
  else if( FD_LIKELY( sz >= (1UL<<10) ) ) FD_TEST( fd_cstr_printf_check( buf, 24, NULL, "%.1f KiB", (double)sz/(double)(1UL<<10) ) );
  else                                    FD_TEST( fd_cstr_printf_check( buf, 24, NULL, "%lu B",    sz                           ) );
}

/* json_escaped copies src into out as JSON string contents, escaping
   quotes, backslashes and control characters.  out must hold at
   least 6*strlen(src)+1 (worst case: every byte becomes \uXXXX). */

static void
json_escaped( char const * src, char * out, ulong out_sz ) {
  ulong j = 0UL;
  for( ulong i=0UL; src[ i ]; i++ ) {
    uchar c = (uchar)src[ i ];
    if( FD_UNLIKELY( c=='"' || c=='\\' ) ) { FD_TEST( j+2UL<out_sz ); out[ j++ ] = '\\'; out[ j++ ] = (char)c; }
    else if( FD_UNLIKELY( c<0x20 ) ) {
      FD_TEST( j+7UL<=out_sz && fd_cstr_printf_check( out+j, out_sz-j, NULL, "\\u%04x", (uint)c ) );
      j += 6UL;
    }
    else { FD_TEST( j+1UL<out_sz ); out[ j++ ] = (char)c; }
  }
  out[ j ] = '\0';
}

#define BAR_W (24UL)

/* fmt_bar renders val/max as a BAR_W cell wide bar with 1/8th cell
   resolution, space padded to exactly BAR_W display cells.  buf must
   hold at least 3*BAR_W+1 bytes. */

static void
fmt_bar( char * buf, ulong val, ulong max ) {
  static char const * const eighth[ 8 ] = { "", "▏", "▎", "▍", "▌", "▋", "▊", "▉" };

  ulong eighths = max ? (val*BAR_W*8UL)/max : 0UL;
  if( val && !eighths ) eighths = 1UL;
  ulong full = eighths/8UL;
  ulong rem  = eighths%8UL;

  char * p = fd_cstr_init( buf );
  ulong cells = 0UL;
  for( ulong i=0UL; i<full; i++, cells++ ) p = fd_cstr_append_cstr( p, "█" );
  if( rem ) { p = fd_cstr_append_cstr( p, eighth[ rem ] ); cells++; }
  for( ulong i=cells; i<BAR_W; i++ ) p = fd_cstr_append_char( p, ' ' );
  fd_cstr_fini( p );
}

static void
mem_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );
  args->mem.sort = fd_env_strip_cmdline_contains( pargc, pargv, "--sort" );
  args->mem.json = fd_env_strip_cmdline_contains( pargc, pargv, "--json" );

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
    ulong max = cnt ? entries[ 0 ].footprint : 0UL;

    if( FD_UNLIKELY( args->mem.json ) ) {
      FD_LOG_STDOUT(( "{\n  \"total_bytes\": %lu,\n  \"entries\": [\n", total ));
      ulong cum = 0UL;
      for( ulong i=0UL; i<cnt; i++ ) {
        cum += entries[ i ].footprint;
        /* 6x worst case expansion (\uXXXX) of the 12 char names */
        char wksp[ 6UL*sizeof(entries[ i ].wksp)+1UL ]; json_escaped( entries[ i ].wksp, wksp, sizeof(wksp) );
        char obj [ 6UL*sizeof(entries[ i ].obj )+1UL ]; json_escaped( entries[ i ].obj,  obj,  sizeof(obj)  );
        FD_LOG_STDOUT(( "    { \"workspace\": \"%s\", \"object\": \"%s\", \"bytes\": %lu, \"cum_bytes\": %lu }%s\n",
                        wksp, obj, entries[ i ].footprint, cum, i==cnt-1UL ? "" : "," ));
      }
      FD_LOG_STDOUT(( "  ]\n}\n" ));
      return;
    }

    int color = fd_log_colorize() && isatty( STDOUT_FILENO );
    char const * c_bold   = color ? "\033[1m"  : "";
    char const * c_dim    = color ? "\033[2m"  : "";
    char const * c_normal = color ? "\033[0m"  : "";
    char const * c_blue   = color ? "\033[34m" : "";

    char rule[ 3UL*110UL+1UL ];
    char * p = fd_cstr_init( rule );
    for( ulong i=0UL; i<110UL; i++ ) p = fd_cstr_append_cstr( p, "─" );
    fd_cstr_fini( p );

    FD_LOG_STDOUT(( "%s%10s  %6s  %-*s  %15s  %10s  %7s  %-12s  %-12s%s\n", c_dim, "SIZE", "PCT", (int)BAR_W, "", "BYTES", "CUM SIZE", "CUM PCT", "WORKSPACE", "OBJECT", c_normal ));
    ulong cum = 0UL;
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong sz = entries[ i ].footprint;
      cum += sz;
      char sz_str[ 24 ], cum_str[ 24 ], bar[ 3UL*BAR_W+1UL ];
      fmt_size( sz_str,  sz  );
      fmt_size( cum_str, cum );
      fmt_bar( bar, sz, max );
      double pct     = total ? 100.0 * (double)sz  / (double)total : 0.0;
      double cum_pct = total ? 100.0 * (double)cum / (double)total : 0.0;
      char const * sz_style  = sz>=(1UL<<30) ? c_bold : (sz<(1UL<<20) ? c_dim : "");
      char const * pct_style = pct>=10.0 ? c_bold : "";
      FD_LOG_STDOUT(( "%s%10s%s  %s%5.1f%%%s  %s%s%s  %s%15lu%s  %s%10s%s  %s%6.1f%%%s  %-12s  %s\n",
                      sz_style, sz_str, sz_style[0] ? c_normal : "",
                      pct_style, pct, pct_style[0] ? c_normal : "",
                      c_blue, bar, c_normal,
                      c_dim, sz, c_normal,
                      c_dim, cum_str, c_normal,
                      c_dim, cum_pct, c_normal,
                      entries[ i ].wksp, entries[ i ].obj ));
    }

    char total_str[ 24 ];
    fmt_size( total_str, total );
    FD_LOG_STDOUT(( "%s%s%s\n", c_dim, rule, c_normal ));
    FD_LOG_STDOUT(( "%s%10s  %5.1f%%  %-*s  %15lu  %10s  %6.1f%%  %-12s%s\n",
                    c_bold, total_str, 100.0, (int)BAR_W, "", total, total_str, 100.0, "TOTAL", c_normal ));
    return;
  }

  if( FD_UNLIKELY( args->mem.json ) ) fd_topo_print_json( &config->topo );
  else                                fd_topo_print_log( 1, &config->topo );
}

static void
mem_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--topo", "<command>", "Build the topology from another subcommand (e.g. `gossip`) instead of\n"
                                                   "the default validator topology.  <command> is the name of a subcommand\n"
                                                   "that builds its own topology" );
  fd_action_help_arg( help, "--sort", NULL,        "List objects largest first, with per object and cumulative memory\n"
                                                   "footprint, instead of the default per memory region layout" );
  fd_action_help_arg( help, "--json", NULL,        "Print the output as JSON" );
}

action_t fd_action_mem = {
  .name           = "mem",
  .args           = mem_cmd_args,
  .fn             = mem_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Print the validator's memory regions and tile layout",
  .detail         = "Prints the shared memory regions and tiles that the validator topology\n"
                    "allocates, including how much memory each object reserves.  A tile is a\n"
                    "single thread pinned to a CPU core that performs one part of the validator's\n"
                    "work.  This is computed from the configuration without attaching to a\n"
                    "running validator.",
  .usage          = "mem [OPTIONS]",
  .args_help      = mem_args_help,
};
