#ifndef HEADER_fd_src_app_fdctl_commands_get_identityh_h
#define HEADER_fd_src_app_fdctl_commands_get_identityh_h

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

FD_PROTOTYPES_BEGIN

void get_identityh_cmd_fn( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_get_identityh;

#endif /* HEADER_fd_src_app_fdctl_commands_get_identityh_h */
