#include "fd_url.h"

fd_url_t *
fd_url_parse_cstr( fd_url_t *   const url,
                   char const * const url_str,
                   ulong        const url_str_len,
                   int *              opt_err ) {
  int err_[1];
  if( !opt_err ) opt_err = err_;
  *opt_err = FD_URL_SUCCESS;

  char const * const url_end = url_str+url_str_len;

  char const * const scheme     = url_str;
  ulong              scheme_len = 0UL;
  if( FD_UNLIKELY( url_str_len<8UL ) ) return NULL;
  if( fd_memeq( scheme, "http://", 7 ) ) {
    scheme_len = 7;
  } else if( fd_memeq( scheme, "https://", 8 ) ) {
    scheme_len = 8;
  } else {
    *opt_err = FD_URL_ERR_SCHEME;
    return NULL;
  }

  char const * const authority = scheme+scheme_len;

  /* Find beginning of path */
  char const * authority_end;
  for( authority_end = authority;
       authority_end < url_end && *authority_end!='/';
       authority_end++ ) {
    if( FD_UNLIKELY( *authority_end=='@' ) ) {
      *opt_err = FD_URL_ERR_USERINFO;
      return NULL; /* userinfo not supported */
    }
  }
  ulong const authority_len = (ulong)( authority_end-authority );

  /* Find port number */
  char const * const host     = authority;
  ulong              host_len = authority_len;
  char const *       port     = NULL;
  ulong              port_len = 0UL;
  for( ulong j=0UL; j<authority_len; j++ ) {
    if( authority[ j ]==':' ) {
      host_len = j;
      port     = authority    +j+1;
      port_len = authority_len-j-1;
      break;
    }
  }

  if( FD_UNLIKELY( host_len>255 ) ) {
    *opt_err = FD_URL_ERR_HOST_OVERSZ;
    return NULL;
  }


  *url = (fd_url_t){
    .scheme     = scheme,
    .scheme_len = scheme_len,
    .host       = host,
    .host_len   = host_len,
    .port       = port,
    .port_len   = port_len,
    .tail       = authority+authority_len,
    .tail_len   = (ulong)( url_end-(authority+authority_len) )
  };

  return url;
}
