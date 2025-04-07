#ifndef HEADER_fd_src_app_shared_commands_netconf_h
#define HEADER_fd_src_app_shared_commands_netconf_h

#include "../fd_config.h"

FD_PROTOTYPES_BEGIN

void netconf_cmd_fn( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_netconf;

#endif /* HEADER_fd_src_app_shared_commands_netconf_h */
