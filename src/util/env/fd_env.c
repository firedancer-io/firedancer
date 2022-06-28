#include "fd_env.h"

#if FD_HAS_HOSTED
#include <stdlib.h>
char const * fd_env_get( char const * key ) { return getenv( key ); }
#else
/* Work around -Wsuggest-attribute=const */
char const * fd_env_get( char const * key ) { key = NULL; return FD_VOLATILE_CONST( key ); }
#endif

#define FD_ENV_STRIP_CMDLINE_IMPL( T, what )                                   \
T                                                                              \
fd_env_strip_cmdline_##what( int        *   pargc,                             \
                             char       *** pargv,                             \
                             char const *   key,                               \
                             char const *   env_key,                           \
                             T              val ) {                            \
  int new_argc = 0;                                                            \
  int arg;                                                                     \
                                                                               \
  if( env_key ) {                                                              \
    char const * cstr = fd_env_get( env_key );                                 \
    if( cstr ) val = fd_cstr_to_##what( cstr );                                \
  }                                                                            \
                                                                               \
  if( key && pargc && pargv ) {                                                \
    for( arg=0; arg<(*pargc); arg++ )                                          \
      if( strcmp( key, (*pargv)[arg] ) ) (*pargv)[new_argc++] = (*pargv)[arg]; \
      else if( (++arg)<(*pargc) ) val = fd_cstr_to_##what( (*pargv)[arg] );    \
    (*pargc)           = new_argc;                                             \
    (*pargv)[new_argc] = NULL; /* ANSI - argv is NULL terminated */            \
  }                                                                            \
                                                                               \
  return val;                                                                  \
}

FD_ENV_STRIP_CMDLINE_IMPL( char const *, cstr   )
FD_ENV_STRIP_CMDLINE_IMPL( char,         char   )
FD_ENV_STRIP_CMDLINE_IMPL( schar,        schar  )
FD_ENV_STRIP_CMDLINE_IMPL( short,        short  )
FD_ENV_STRIP_CMDLINE_IMPL( int,          int    )
FD_ENV_STRIP_CMDLINE_IMPL( long,         long   )
FD_ENV_STRIP_CMDLINE_IMPL( uchar,        uchar  )
FD_ENV_STRIP_CMDLINE_IMPL( ushort,       ushort )
FD_ENV_STRIP_CMDLINE_IMPL( uint,         uint   )
FD_ENV_STRIP_CMDLINE_IMPL( ulong,        ulong  )
FD_ENV_STRIP_CMDLINE_IMPL( float,        float  )
#if FD_HAS_DOUBLE
FD_ENV_STRIP_CMDLINE_IMPL( double,       double )
#endif

#undef FD_ENV_STRIP_CMDLINE_IMPL

