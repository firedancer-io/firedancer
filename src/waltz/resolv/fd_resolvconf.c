#include "fd_lookup.h"
#include <stdio.h>
#include <ctype.h>
#include "../../util/cstr/fd_cstr.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

int
fd_get_resolv_conf( fd_resolvconf_t * conf ) {
  int nns = 0;

  conf->ndots = 1;
  conf->timeout = 5;
  conf->attempts = 2;

  FILE * f = fopen( "/etc/resolv.conf", "rb ");
  if( !f ) switch( errno ) {
  case ENOENT:
  case ENOTDIR:
  case EACCES:
    goto no_resolv_conf;
  default:
    return -1;
  }

  char line[256];
  while( fgets( line, sizeof(line), f ) ) {
    char * p, * z;
    if( !strchr( line, '\n' ) && !feof( f ) ) {
      /* Ignore lines that get truncated rather than
       * potentially misinterpreting them. */
      int c;
      do c = getc( f );
      while( c != '\n' && c != EOF );
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

  fclose( f );

no_resolv_conf:
  if( !nns ) {
    fd_lookup_ipliteral( conf->ns, "127.0.0.1", AF_UNSPEC );
    nns = 1;
  }

  conf->nns = (uint)nns;

  return 0;
}
