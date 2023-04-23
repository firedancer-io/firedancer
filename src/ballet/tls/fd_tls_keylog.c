#include "fd_tls_keylog.h"
#include "../hex/fd_hex.h"

#include <stdlib.h>


static char const
fd_tls_keylog_label_1[ 28 ] = "CLIENT_EARLY_TRAFFIC_SECRET ";

static char const
fd_tls_keylog_label_2[ 29 ] = "EARLY_EXPORTER_MASTER_SECRET ";

static char const
fd_tls_keylog_label_3[ 32 ] = "CLIENT_HANDSHAKE_TRAFFIC_SECRET ";

static char const
fd_tls_keylog_label_4[ 32 ] = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";

static char const
fd_tls_keylog_label_5[ 22 ] = "CLIENT_TRAFFIC_SECRET_";

static char const
fd_tls_keylog_label_6[ 22 ] = "SERVER_TRAFFIC_SECRET_";


ulong
fd_tls_keylog_parse( fd_tls_keylog_t * keylog,
                     char const *      str,
                     ulong             str_sz ) {

  char const * str0 = str;

# define ADVANCE(n)          \
    do {                     \
      ulong _n=(n);          \
      FD_TEST( str_sz>=_n ); \
      str   +=_n;            \
      str_sz-=_n;            \
    } while(0)

  /* Skip empty lines and trailing whitespace */

  while( str_sz ) {
    char c = str[0];
    if( (c!=' ') & (c!='\t') & (c!='\n') ) break;
    ADVANCE( 1 );
  }

  /* Zero out */

  memset( keylog, 0, sizeof(fd_tls_keylog_t) );

  /* Identify label */

  uint label;

  if( str_sz>=sizeof(fd_tls_keylog_label_1) && 0==memcmp( str, fd_tls_keylog_label_1, sizeof(fd_tls_keylog_label_1) ) ) {
    label = FD_TLS_KEYLOG_LABEL_CLIENT_EARLY_TRAFFIC_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_1) );
  } else
  if( str_sz>=sizeof(fd_tls_keylog_label_2) && 0==memcmp( str, fd_tls_keylog_label_2, sizeof(fd_tls_keylog_label_2) ) ) {
    label = FD_TLS_KEYLOG_LABEL_EARLY_EXPORTER_MASTER_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_2) );
  } else
  if( str_sz>=sizeof(fd_tls_keylog_label_3) && 0==memcmp( str, fd_tls_keylog_label_3, sizeof(fd_tls_keylog_label_3) ) ) {
    label = FD_TLS_KEYLOG_LABEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_3) );
  } else
  if( str_sz>=sizeof(fd_tls_keylog_label_4) && 0==memcmp( str, fd_tls_keylog_label_4, sizeof(fd_tls_keylog_label_4) ) ) {
    label = FD_TLS_KEYLOG_LABEL_SERVER_HANDSHAKE_TRAFFIC_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_4) );
  } else
  if( str_sz>=sizeof(fd_tls_keylog_label_5) && 0==memcmp( str, fd_tls_keylog_label_5, sizeof(fd_tls_keylog_label_5) ) ) {
    label = FD_TLS_KEYLOG_LABEL_CLIENT_TRAFFIC_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_5) );
  } else
  if( str_sz>=sizeof(fd_tls_keylog_label_6) && 0==memcmp( str, fd_tls_keylog_label_6, sizeof(fd_tls_keylog_label_6) ) ) {
    label = FD_TLS_KEYLOG_LABEL_SERVER_TRAFFIC_SECRET;
    ADVANCE( sizeof(fd_tls_keylog_label_6) );
  } else
  if( str_sz>0 && str[ 0 ]=='#' ) {
    label = FD_TLS_KEYLOG_LABEL_COMMENT;
    while( str_sz ) {
      char c = str[ 0 ];
      ADVANCE( 1 );
      if( c=='\n' )
        break;
    }
  } else {
    return 0UL;
  }

  uint counter = 0;

  switch( label ) {

  /* Parse counter */
  case FD_TLS_KEYLOG_LABEL_CLIENT_TRAFFIC_SECRET:
  case FD_TLS_KEYLOG_LABEL_SERVER_TRAFFIC_SECRET: {
    /* Copy number into cstr */
    char num[ 11UL ];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( num ), str, fd_ulong_min( str_sz, 10UL ) ) );

    /* Parse number */
    char const * num_end;
    counter = (uint)strtoul( num, (char **)&num_end, 10 );
    if( FD_UNLIKELY( num_end==num || counter==UINT_MAX ) )
      return 0UL;
    ADVANCE( (ulong)( num_end-num ) );

    /* Expect space */
    if( FD_UNLIKELY( str_sz<1UL || str[ 0 ]!=' ' ) )
      return 0UL;
    ADVANCE( 1UL );

    __attribute__((fallthrough));
  }

  /* Parse client random and secret */
  case FD_TLS_KEYLOG_LABEL_CLIENT_EARLY_TRAFFIC_SECRET:
  case FD_TLS_KEYLOG_LABEL_EARLY_EXPORTER_MASTER_SECRET:
  case FD_TLS_KEYLOG_LABEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
  case FD_TLS_KEYLOG_LABEL_SERVER_HANDSHAKE_TRAFFIC_SECRET: {
    /* Decode client random */
    if( FD_UNLIKELY( str_sz<65UL ) )
      return 0UL;
    if( FD_UNLIKELY( 32UL!=fd_hex_decode( keylog->client_random, str, 32UL ) ) )
      return 0UL;
    if( FD_UNLIKELY( str[ 64UL ]!=' ' ) )
      return 0UL;
    ADVANCE( 65UL );

    /* Decode secret */
    if( FD_UNLIKELY( str_sz<2UL ) )
      return 0UL;
    ulong secret_sz = fd_hex_decode( keylog->secret, str, fd_ulong_min( str_sz/2UL, 64UL ) );
    if( FD_UNLIKELY( secret_sz==0UL ) )
      return 0UL;
    keylog->secret_sz = (ushort)secret_sz;
    ADVANCE( secret_sz*2UL );

    /* Expect newline or EOF */
    if( FD_UNLIKELY( str_sz>0UL ) ) {
      if( FD_UNLIKELY( str[ 0 ]!='\n' ) )
        return 0UL;
      ADVANCE( 1UL );
    }

    __attribute__((fallthrough));
  }

  /* Success */
  default: {
    keylog->label   = (ushort)label;
    keylog->counter = counter;
    return (ulong)( str-str0 );
  }

  }

# undef ADVANCE
}

