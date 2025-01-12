#ifndef HEADER_fd_src_app_fdctl_config_parse_h
#define HEADER_fd_src_app_fdctl_config_parse_h

#include "config.h"

FD_PROTOTYPES_BEGIN

extern uchar const fdctl_default_config[];
extern ulong const fdctl_default_config_sz;

extern uchar const fdctl_default_firedancer_config[];
extern ulong const fdctl_default_firedancer_config_sz;

/* fdctl_pod_to_cfg extracts configuration from pod to the typed config
   struct.  Any recognized keys are removed from pod.  Logs errors to
   warning log.  Returns config on success, NULL on error.  Does not
   zero initialize config fields.

   Not thread safe (uses global buffer).  */

config_t *
fdctl_pod_to_cfg( config_t * config,
                  uchar *    pod );

/* fdctl_cfg_validate checks for missing config keys.  Exits with code 1
   if anything is missing. */

void
fdctl_cfg_validate( config_t * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_config_parse_h */
