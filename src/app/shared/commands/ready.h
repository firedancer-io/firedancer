#ifndef HEADER_fd_src_app_shared_commands_ready_h
#define HEADER_fd_src_app_shared_commands_ready_h

#include "../fd_config.h"

FD_PROTOTYPES_BEGIN

void ready_cmd_fn( args_t *   args,
                   config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_ready;

#endif /* HEADER_fd_src_app_shared_commands_ready_h */
