#ifndef FD_ENV_STYLE
#if FD_HAS_HOSTED /* Use POSIX */
#define FD_ENV_STYLE 0
#else
#error "Define FD_ENV_STYLE for this build target"
#endif
#endif

#if FD_ENV_STYLE==0

#include "fd_env.h"

#include <stdlib.h>
#include <stdio.h>

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
    char const * cstr = getenv( env_key );                                     \
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

int
fd_env_strip_cmdline_contains( int * pargc, char *** pargv, char const * key ) {
  int new_argc = 0;
  int found = 0;
  if( key && pargc && pargv ) {
    for( int arg=0; arg<(*pargc); arg++ )
      if( strcmp( key, (*pargv)[arg] ) ) (*pargv)[new_argc++] = (*pargv)[arg];
      else found = 1;
    (*pargc)           = new_argc;
    (*pargv)[new_argc] = NULL; /* ANSI - argv is NULL terminated */
  }
  return found;
}


int fd_env_strip_cmdline_bool(int *pargc, char ***pargv, const char *key, int *value) {
    int found = 0;
    if (key && pargc && pargv && value) {
        for (int arg = 0; arg < *pargc; arg++) {
            if (!strcmp((*pargv)[arg], key)) {
                found = 1; // Mark key as found
                if (arg + 1 < *pargc) { // Ensure next argument exists
                    arg++; // Move to value of the flag
                    if (!strcmp((*pargv)[arg], "true") || !strcmp((*pargv)[arg], "1")) {
                        *value = 1;
                    } else if (!strcmp((*pargv)[arg], "false") || !strcmp((*pargv)[arg], "0")) {
                        *value = 0;
                    } else {
                        fprintf(stderr, "Error: Invalid value for %s. Use true/false or 1/0.\n", key);
                        return -1; // Error code for invalid argument
                    }
                } else {
                    *value = 1; // No argument implies true
                }
            } else if (arg > 0 && !strcmp((*pargv)[arg-1], key)) {
                // Skip value already processed
            } else {
                (*pargv)[(*pargc) - arg - 1] = (*pargv)[arg]; // Shift arguments
            }
        }
        (*pargv)[*pargc - 1] = NULL; // Ensure NULL termination
    }
    return found;
}

#else
#error "Unknown FD_ENV_STYLE"
#endif

