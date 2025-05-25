#include "fd_lookup.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../../util/cstr/fd_cstr.h"
#include "../../util/log/fd_log.h"
#include "../../util/io/fd_io.h"
#include "fd_io_readline.h"

int
fd_get_resolv_conf( fd_resolvconf_t * conf ) {
  int nns = 0;

  conf->ndots = 1;
  conf->timeout = 5;
  conf->attempts = 2;

  if( fd_etc_resolv_conf_fd<0 ) goto no_resolv_conf;

  if( FD_UNLIKELY( -1==lseek( fd_etc_resolv_conf_fd, 0, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "lseek(/etc/resolv.conf,0,SEEK_SET) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  uchar rbuf[256];
  fd_io_buffered_istream_t istream[1];
  fd_io_buffered_istream_init( istream, fd_etc_resolv_conf_fd, rbuf, sizeof(rbuf) );

  char line[256];
  int err;
  while( fd_io_fgets( line, sizeof(line), istream, &err ) ) {
    char * p, * z;
    if( !strchr( line, '\n' ) && err==0 ) {
      /* Ignore lines that get truncated rather than
       * potentially misinterpreting them. */
      int c;
      do c = fd_io_fgetc( istream, &err );
      while( c!='\n' && c!=-1 );
      continue;
    }
    if( !strncmp( line, "options", 7 ) && fd_isspace( line[7] ) ) {
      p = strstr( line, "ndots:" );
      if( p && fd_isdigit(p[6]) ) {
        p += 6;
        ulong x = strtoul( p, &z, 10 );
        if( z != p ) conf->ndots = (uint)( x > 15 ? 15 : x );
      }
      p = strstr( line, "attempts:" );
      if( p && fd_isdigit(p[9]) ) {
        p += 9;
        ulong x = strtoul( p, &z, 10 );
        if( z != p ) conf->attempts = (uint)( x > 10 ? 10 : x );
      }
      p = strstr( line, "timeout:" );
      if( p && (isdigit(p[8]) || p[8]=='.') ) {
        p += 8;
        ulong x = strtoul( p, &z, 10 );
        if( z != p ) conf->timeout = (uint)( x > 60 ? 60 : x );
      }
      continue;
    }
    if( !strncmp( line, "nameserver", 10 ) && isspace( line[10] ) ) {
      if( nns >= MAXNS ) continue;
      for( p=line+11; isspace(*p); p++ );
      for( z=p; *z && !isspace(*z); z++ );
      *z=0;
      if( fd_lookup_ipliteral( conf->ns+nns, p, AF_UNSPEC ) > 0 )
        nns++;
      continue;
    }
  }

no_resolv_conf:
  if( !nns ) {
    fd_lookup_ipliteral( conf->ns, "127.0.0.1", AF_UNSPEC );
    nns = 1;
  }

  conf->nns = (uint)nns;

  return 0;
}
