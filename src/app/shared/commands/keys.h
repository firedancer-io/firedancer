#ifndef HEADER_fd_src_app_shared_commands_keys_h
#define HEADER_fd_src_app_shared_commands_keys_h

#include "../fd_config.h"

FD_PROTOTYPES_BEGIN

void keys_cmd_args( int * pargc, char *** pargv, args_t * args );
void keys_cmd_fn( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_keys;

#endif /* HEADER_fd_src_app_shared_commands_keys_h */
