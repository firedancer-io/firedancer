#include "tiles.h"

#include <stdarg.h>
#include <stdio.h>

void *
fd_wksp_pod_map1( uchar const * pod,
                  char const *  format,
                  ... ) {
  char s[ 256 ];

  va_list args;
  va_start( args, format );
  int len = vsnprintf( s, sizeof(s), format, args );
  va_end( args );
  if( FD_UNLIKELY( len < 0 ) )
    FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)len >= sizeof(s) ) )
    FD_LOG_ERR(( "vsnprintf truncated output (maxlen=%lu)", sizeof(s) ));

  return fd_wksp_pod_map( pod, s );
}
