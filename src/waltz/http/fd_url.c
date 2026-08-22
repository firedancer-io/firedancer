#include "fd_url.h"
#include "../../util/cstr/fd_cstr.h"
#include "../../util/log/fd_log.h"

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

  /* Find end of authority */
  char const * authority_end;
  for( authority_end = authority;
       authority_end < url_end &&
       *authority_end != '/'   &&
       *authority_end != '?'   &&
       *authority_end != '#';
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

  if( FD_UNLIKELY( host_len>=FD_FQDN_BUF_MAX ) ) {
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

int
fd_url_parse_endpoint( fd_url_t *   url_,
                       char const * url_str,
                       ulong        url_str_len,
                       ushort *     tcp_port,
                       _Bool *      is_ssl,
                       char const * context ) {
  char const * ctx = context ? context : "URL";

  int url_err[1];
  fd_url_t * url = fd_url_parse_cstr( url_, url_str, url_str_len, url_err );
  if( FD_UNLIKELY( !url ) ) {
    switch( *url_err ) {
    case FD_URL_ERR_SCHEME:
      FD_LOG_WARNING(( "Invalid %s `%.*s`: must start with `http://` or `https://`", ctx, (int)url_str_len, url_str ));
      return -1;
    case FD_URL_ERR_HOST_OVERSZ:
      FD_LOG_WARNING(( "Invalid %s `%.*s`: domain name is too long", ctx, (int)url_str_len, url_str ));
      return -1;
    case FD_URL_ERR_USERINFO:
      FD_LOG_WARNING(( "Invalid %s `%.*s`: userinfo is not supported", ctx, (int)url_str_len, url_str ));
      return -1;
    default:
      FD_LOG_WARNING(( "Invalid %s `%.*s`", ctx, (int)url_str_len, url_str ));
      return -1;
    }
  }

  /* fd_url_parse_cstr() already guarantees http:// or https:// */
  *is_ssl = ( url->scheme_len==8UL );

  *tcp_port = *is_ssl ? 443 : 80;
  if( FD_LIKELY( !url->port ) ) return 0;
  if( FD_UNLIKELY( !url->port_len || url->port_len>5UL ) ) goto invalid_port;

  ulong port_no = 0UL;
  for( ulong i=0UL; i<url->port_len; i++ ) {
    uchar c = (uchar)url->port[ i ];
    if( FD_UNLIKELY( c<(uchar)'0' || c>(uchar)'9' ) ) goto invalid_port;
    port_no = 10UL*port_no + (ulong)(c-(uchar)'0');
  }
  if( FD_UNLIKELY( !port_no || port_no>USHORT_MAX ) ) goto invalid_port;

  *tcp_port = (ushort)port_no;

  return 0;

invalid_port:
  FD_LOG_WARNING(( "Invalid %s `%.*s`: invalid port number", ctx, (int)url_str_len, url_str ));
  return -1;
}


static inline int
fd_hex_unhex( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+0xa;
  if( c>='A' && c<='F' ) return c-'A'+0xa;
  return -1;
}

ulong
fd_url_unescape( char * const msg,
                 ulong  const len ) {
  char * end = msg+len;
  char * dst = msg;
  for( char * src=msg; src<end; src++ ) {
    /* invariant: dst<=src */
    if( FD_LIKELY( (*src)!='%' ) ) {
      *(dst++) = *src;
    } else {
      if( FD_UNLIKELY( src+2>=end ) ) return 0UL; /* truncated percent encoding */
      int hi = fd_hex_unhex( src[1] );
      int lo = fd_hex_unhex( src[2] );
      if( FD_UNLIKELY( (hi|lo)<0 ) ) return 0UL; /* invalid hex digit */
      *(dst++) = (char)( (hi<<4) | lo );
      src += 2;
    }
  }
  return (ulong)( dst-msg );
}
