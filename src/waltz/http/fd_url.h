#ifndef HEADER_fd_src_waltz_http_fd_url_h
#define HEADER_fd_src_waltz_http_fd_url_h

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

/* Shared validator/runtime URL gate.
   Accepts a http(s):// URL, fills fd_url_t `url` parameter.
     - Only `http://` and `https://` schemes are permitted.  Anything
       else (including missing schemes or stray slashes) is rejected.
       The `context` string is echoed in the log so operators know which
       knob supplied the bad value.
     - If the URL omits an explicit port we default to 443/80 and then flip
       `is_ssl` based on the scheme so downstream sockets know whether
       to open TLS.
     - Host names larger than 255 bytes are rejected
   The function does not enforce the host being non-empty; that is left to
   the caller because some control paths treat an empty host differently
   (e.g. surfacing a custom error message).
   Returns 0 on success, -1 on failure (and logs a warning). */

int
fd_url_parse_endpoint( fd_url_t *   url,
                       char const * url_str,
                       ulong        url_str_len,
                       ushort *     tcp_port,
                       _Bool *      is_ssl,
                       char const * context );

/* fd_url_unescape undoes % escapes in-place.  Returns the unescaped
   length on success, or 0 on failure (invalid hex digit or truncated
   percent encoding). */

ulong
fd_url_unescape( char * msg,
                 ulong  len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_http_fd_url_h */
