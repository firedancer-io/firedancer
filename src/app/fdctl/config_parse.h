#ifndef HEADER_fd_src_app_fdctl_config_parse_h
#define HEADER_fd_src_app_fdctl_config_parse_h

#include "config.h"

FD_PROTOTYPES_BEGIN

/* fdctl_pod_to_cfg extracts configuration from pod to the typed config
   struct.  Any recognized keys are removed from pod.  Logs errors to
   warning log.  Returns config on success, NULL on error.

   Not thread safe (uses global buffer).  */

config_t *
fdctl_pod_to_cfg( config_t * config,
                  uchar *    pod );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_config_parse_h */
