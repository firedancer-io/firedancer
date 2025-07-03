#ifndef HEADER_fd_src_waltz_h2_fd_url_h
#define HEADER_fd_src_waltz_h2_fd_url_h

/* fd_url.h provides an API for handling URLs.

   This API is by no means compliant.  Works only for basic strings.  */

#include "../../util/fd_util_base.h"

/* fd_url_t holds a bunch of pointers into an URL string. */

struct fd_url {
  char const * scheme;
  ulong        scheme_len;

  char const * host;
  ulong        host_len; /* <=255 */

  char const * port;
  ulong        port_len;

  char const * tail; /* path, query, fragment */
  ulong        tail_len;
};

typedef struct fd_url fd_url_t;

#define FD_URL_SUCCESS         0
#define FD_URL_ERR_SCHEME      1
#define FD_URL_ERR_HOST_OVERSZ 2
#define FD_URL_ERR_USERINFO    3

FD_PROTOTYPES_BEGIN

/* fd_url_parse_cstr is a basic URL parser.  It is not RFC compliant.

   Non-exhaustive list of what this function cannot do:
   - Schemes other than http and https are not supported
   - userinfo (e.g. 'user:pass@') is not supported
   - Anything after the authority is ignored

   If opt_err!=NULL, on return *opt_err holds an FD_URL_ERR_{...} code. */

fd_url_t *
fd_url_parse_cstr( fd_url_t *   url,
                   char const * url_str,
                   ulong        url_str_len,
                   int *        opt_err );

/* fd_url_unescape undoes % escapes in-place. */

ulong
fd_url_unescape( char * const msg,
                 ulong  const len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_url_h */
