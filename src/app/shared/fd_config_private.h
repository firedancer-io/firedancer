#ifndef HEADER_fd_src_app_shared_fd_config_private_h
#define HEADER_fd_src_app_shared_fd_config_private_h

#include "fd_config.h"
#include "../../ballet/toml/fd_toml.h"

FD_PROTOTYPES_BEGIN

/* fd_config_extract_toml() extracts the configuration from the parsed
   TOML document to a typed config struct.  Marks every node it handled
   as consumed and rejects documents with unrecognized keys.  Logs
   errors to warning log.  Returns config on success, NULL on error.
   Does not zero initialize config fields. */

config_t *
fd_config_extract_toml( fd_toml_doc_t * doc,
                        config_t *      config );

/* fd_config_toml_parse copies [buf,buf+sz) into a static transient
   buffer and parses it into *doc.  The doc aliases that static storage
   and is valid until the next call.  Returns an FD_TOML_* error code.
   Not thread safe. */

int
fd_config_toml_parse( fd_toml_doc_t *      doc,
                      char const *         buf,
                      ulong                sz,
                      fd_toml_err_info_t * opt_err );

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
                int           is_local_cluster,
                int           dev );

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
