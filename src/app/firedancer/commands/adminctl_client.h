#ifndef HEADER_fd_src_app_firedancer_commands_adminctl_client_h
#define HEADER_fd_src_app_firedancer_commands_adminctl_client_h

#include "../../shared/fd_config.h"
#include "../../../discof/admin/fd_adminctl.h"

FD_PROTOTYPES_BEGIN

/* adminctl_client_attach joins the adminctl ring of a running
   validator.  If --config was given, the workspace is located from the
   reconstructed topology as before.  Otherwise the running validator
   is discovered from its bootinfo descriptor; opt_name selects an
   instance when more than one is running (NULL or empty for auto).
   Logs an error and exits on failure. */

fd_adminctl_t *
adminctl_client_attach( config_t *   config,
                        char const * opt_name );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_commands_adminctl_client_h */
