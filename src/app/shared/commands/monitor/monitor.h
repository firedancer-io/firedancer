#ifndef HEADER_fd_src_app_shared_commands_monitor_h
#define HEADER_fd_src_app_shared_commands_monitor_h

#include "../../fd_config.h"

void monitor_cmd_args( int * pargc, char *** pargv, args_t * args );
void monitor_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void monitor_cmd_fn  ( args_t * args, config_t * config );

#endif /* HEADER_fd_src_app_shared_commands_monitor_h */
