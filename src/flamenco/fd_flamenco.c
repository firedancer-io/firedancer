#include "fd_flamenco_base.h"
#include <stdio.h>
#include <string.h>

/* glibc specific *****************************************************/

#if defined(__GLIBC__)

#include <printf.h>
#include "../ballet/base58/fd_base58.h"

static int
fd_printf_specifier_base58( FILE *                     stream,
                            struct printf_info const * info,
                            void const * const *       args ) {

  void const * mem = *((void const * const *)args[0]);
  char out[ FD_BASE58_ENCODED_64_SZ ];

  if( FD_UNLIKELY( !mem ) )
    return fprintf( stream, "<NULL>" );

  switch( info->width ) {
  case 32:
    fd_base58_encode_32( mem, NULL, out );
    break;
  case 64:
    fd_base58_encode_64( mem, NULL, out );
    break;
  default:
    return fprintf( stream, "<unsupported Base58 width>" );
  }
  return fprintf( stream, "%s", out );
}

static int
fd_printf_specifier_base58_arginfo( struct printf_info const * info __attribute__((unused)),
                                    ulong                      n,
                                    int *                      argtypes,
                                    int *                      size ) {
  if( FD_LIKELY( n>=1UL ) ) {
    argtypes[ 0 ] = PA_POINTER;
    size    [ 0 ] = sizeof(void *);
  }
  return 1;
}

#endif

void
fd_flamenco_boot( int *    pargc __attribute__((unused)),
                  char *** pargv __attribute__((unused)) ) {
  #if defined(__GLIBC__)
  FD_TEST( 0==register_printf_specifier( 'J', fd_printf_specifier_base58, fd_printf_specifier_base58_arginfo ) );
  #endif
  /* TODO implement printf specifiers for non-glibc */
}

void
fd_flamenco_halt( void ) {}
