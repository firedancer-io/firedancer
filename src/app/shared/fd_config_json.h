#ifndef HEADER_fd_src_app_shared_fd_config_json_h
#define HEADER_fd_src_app_shared_fd_config_json_h

/* fd_config_to_json renders the fully resolved config as a JSON
   document for the boot telemetry event: every effective setting
   after defaults, overrides and system-derived values are merged.
   Filesystem paths, host identity (user, hostname, advertised and
   bind addresses), and external service URLs are redacted.  The
   embedded topology is not rendered; the boot event carries it
   separately.

   Returns the rendered length.  Logs an error and exits the process
   if buf_sz is too small. */

#include "fd_config.h"

FD_PROTOTYPES_BEGIN

ulong
fd_config_to_json( fd_config_t const * config,
                   char *              buf,
                   ulong               buf_sz );

/* fd_config_user_toml_to_json renders config->user_config (the raw
   TOML of the operator's own config file, i.e. just their overrides)
   as a JSON document.  String values whose keys suggest paths,
   addresses, hosts, users, servers, or keys are redacted.  Returns the
   rendered length, 0 if there is no user config.  Logs an error and
   exits the process on a parse failure (the file already parsed once
   during config load) or if buf_sz is too small. */

ulong
fd_config_user_toml_to_json( fd_config_t const * config,
                             char *              buf,
                             ulong               buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_config_json_h */
