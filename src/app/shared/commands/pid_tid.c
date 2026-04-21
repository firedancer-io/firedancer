#include "pid_tid.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <stdio.h> /* printf */

ulong
fd_topo_match_tiles( fd_topo_t const * topo,
                     ushort            tile_idxs[ static 128 ],
                     char const *      query,
                     _Bool *           whole_process ) {
  *whole_process = 0;
  ulong tile_cnt = 0UL;
  if( FD_UNLIKELY( !strcmp( "all", query ) ) ) {
    FD_TEST( topo->tile_cnt < 128 );
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      tile_idxs[ tile_cnt ] = (ushort)i;
      tile_cnt++;
    }
  } else if( FD_UNLIKELY( !strcmp( "agave", query ) ) ) {
    /* Find the bank tile so we can get the Agave PID */
    ulong bank_tile_idx = fd_topo_find_tile( topo, "bank", 0UL );
    if( FD_UNLIKELY( bank_tile_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `bank` not found" ));
    *whole_process = 1;
    tile_idxs[ 0 ] = (ushort)bank_tile_idx;
    tile_cnt = 1UL;
  } else {
    char * sep = strchr( query, ':' );

    ulong tile_idx;
    if( FD_UNLIKELY( !sep ) ) {
      tile_idx = fd_topo_find_tile( topo, query, 0UL );
    } else {
      char * endptr;
      *sep = '\0';
      ulong kind_id = strtoul( sep+1, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || kind_id==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tile kind id provided `%s`", sep+1 ));
      tile_idx = fd_topo_find_tile( topo, query, kind_id );
    }

    if( FD_UNLIKELY( tile_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `%s` not found", query ));
    tile_idxs[ 0 ] = (ushort)tile_idx;
    tile_cnt = 1UL;
  }
  return tile_cnt;
}

static void
pid_tid_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {

  if( FD_UNLIKELY( !*pargc ) ) FD_LOG_ERR(( "usage: %s [tile|tile:idx]", args->pid_tid.name ));
  fd_cstr_ncpy( args->pid_tid.name, **pargv, sizeof(args->pid_tid.name) );

  (*pargc)--;
  (*pargv)++;
}

static void
pid_tid_cmd_fn( args_t *   args,
                config_t * config,
                int        is_tid ) {
  /* Topology boilerplate: Find tile metric region */
  fd_topo_t * topo = &config->topo;
  ulong metric_wksp_id = fd_topo_find_wksp( topo, "metric_in" ); FD_TEST( metric_wksp_id!=ULONG_MAX );
  fd_topo_wksp_t * metric_topo_wksp = &topo->workspaces[ metric_wksp_id ];
  fd_topo_join_workspace( topo, metric_topo_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_REGULAR );
  fd_topo_workspace_fill( topo, metric_topo_wksp );

  ushort tile_idxs[ 128 ];
  _Bool whole_process;
  ulong tile_cnt = fd_topo_match_tiles( &config->topo, tile_idxs, args->flame.name, &whole_process );

  ulong midx = is_tid ? MIDX( GAUGE, TILE, TID ) : MIDX( GAUGE, TILE, PID );
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ tile_idxs[ i ] ];
    ulong volatile * tile_metrics = fd_metrics_tile( tile->metrics );
    int id = (int)tile_metrics[ midx ];
    printf( "%d\n", id );
  }
}

void
pid_cmd_fn( args_t *   args,
            config_t * config ) {
  pid_tid_cmd_fn( args, config, 0 );
}

void
tid_cmd_fn( args_t *   args,
            config_t * config ) {
  pid_tid_cmd_fn( args, config, 1 );
}

action_t fd_action_pid = {
  .name           = "pid",
  .args           = pid_tid_cmd_args,
  .fn             = pid_cmd_fn,
  .require_config = 1,
  .is_diagnostic  = 1,
  .description    = "Print tile PID",
};

action_t fd_action_tid = {
  .name           = "tid",
  .args           = pid_tid_cmd_args,
  .fn             = tid_cmd_fn,
  .require_config = 1,
  .is_diagnostic  = 1,
  .description    = "Print tile TID",
};
