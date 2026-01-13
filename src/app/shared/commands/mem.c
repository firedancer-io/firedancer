#include "../fd_config.h"
#include "../fd_action.h"

extern action_t * ACTIONS[];

static void
mem_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );

  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->mem.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->mem.topo ), topo_name, topo_name_len ) );
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; a; a++ ) {
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
