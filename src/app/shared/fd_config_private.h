#ifndef HEADER_fd_src_app_shared_fd_config_private_h
#define HEADER_fd_src_app_shared_fd_config_private_h

#include "fd_config.h"

FD_PROTOTYPES_BEGIN

/* fd_config_extract_pod() extracts the configuration from the provided
   pod to a typed config struct.  Logs errors to warning log.  Returns
   config on success, NULL on error.  Does not zero initialize config
   fields.

   Not thread safe (uses global buffer).  */

config_t *
fd_config_extract_pod( uchar *    pod,
                       config_t * config );

void
fd_config_load_buf( config_t *   out,
                    char const * buf,
                    ulong        sz,
                    char const * path );

/* fd_config_transform() takes a raw configuration that has been loaded
   from a file and fills in any missing fields.  For example, the
   configuration file might specific a "user" to run as, but the config
   object fills this to a uid and gid to run as.

   This function can fail for various reasons, if the configuration is
   not valid.  On failure, an error message will be printed and the
   process will exit.  The function will not return. */

void
fd_config_fill( fd_config_t * config,
                int           netns,
                int           is_local_cluster );

/* fd_config_validate() checks that the configuration object provided is
   valid.  On any error, the function will print an error message and
   exit the process, the function will not return.

   Validation is comprehensive, and the function checks, among other
   things that required options are provided, that string enumerations
   are a valid string, that ports do not overlap, that paths are all
   valid, and so on. */

void
fd_config_validate( fd_config_t const * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_config_private_h */
