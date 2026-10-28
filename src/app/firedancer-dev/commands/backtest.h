#ifndef HEADER_fd_src_app_firedancer_dev_commands_backtest_h
#define HEADER_fd_src_app_firedancer_dev_commands_backtest_h

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

/* The topology, permission and run functions of the backtest command.
   snapshot-minimize runs a backtest with its own arguments. */

void
backtest_cmd_topo( config_t * config );

void
backtest_cmd_perm( args_t *         args,
                   fd_cap_chk_t *   chk,
                   config_t const * config );

void
backtest_cmd_fn( args_t *   args,
                 config_t * config );

#endif /* HEADER_fd_src_app_firedancer_dev_commands_backtest_h */
