#ifndef HEADER_fd_src_app_shared_dev_commands_wksp_h
#define HEADER_fd_src_app_shared_dev_commands_wksp_h

#include "../../shared/fd_config.h"

FD_PROTOTYPES_BEGIN

void
wksp_cmd_perm( args_t *         args,
               fd_cap_chk_t *   chk,
               config_t const * config );

void
wksp_cmd_fn( args_t *   args,
             config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_wksp;

#endif /* HEADER_fd_src_app_shared_dev_commands_wksp_h */
