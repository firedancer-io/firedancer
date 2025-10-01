#ifndef HEADER_fd_src_app_shared_commands_watch_watch_h
#define HEADER_fd_src_app_shared_commands_watch_watch_h

#include "../../fd_config.h"
#include "../../fd_action.h"

FD_PROTOTYPES_BEGIN

void watch_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void watch_cmd_fn  ( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_watch;

#endif /* HEADER_fd_src_app_shared_commands_watch_watch_h */
