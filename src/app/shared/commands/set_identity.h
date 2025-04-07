#ifndef HEADER_fd_src_app_shared_commands_set_identity_h
#define HEADER_fd_src_app_shared_commands_set_identity_h

#include "../fd_config.h"

FD_PROTOTYPES_BEGIN

void set_identity_cmd_fn( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_set_identity;

#endif /* HEADER_fd_src_app_shared_commands_set_identity_h */
