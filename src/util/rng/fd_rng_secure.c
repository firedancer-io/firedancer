#include "fd_rng.h"
#include "../log/fd_log.h"

/* Choose best fd_rng_secure based on platform */

#if defined(__linux__) || defined(__FreeBSD__)

#include <assert.h>
#include <errno.h>
#include <sys/random.h>

FD_FN_SENSITIVE __attribute__((warn_unused_result))
void *
fd_rng_secure( void * d,
               ulong  sz ) {
  uchar * out = d;
  while( sz ) {
    long res = getrandom( out, sz, 0 );
    if( FD_UNLIKELY( res<0 ) ) {
      FD_LOG_WARNING(( "getrandom(sz=%lu) failed (%d-%s)", sz, errno, fd_io_strerror( errno ) ));
      return NULL;
    }
    assert( (ulong)res <= sz );
    sz -= (ulong)res;
  }
  return d;
}

#elif defined(__APPLE__)

#include <CommonCrypto/CommonRandom.h>

FD_FN_SENSITIVE __attribute__((warn_unused_result))
void *
fd_rng_secure( void * d,
               ulong  sz ) {

  int status = CCRandomGenerateBytes( d, sz );
  if( FD_UNLIKELY( status!=kCCSuccess ) ) {
    FD_LOG_WARNING(( "CCRandomGenerateBytes(sz=%lu) failed (%d)", sz, status ));
    return NULL;
  }

  return d;
}

#else

FD_FN_SENSITIVE __attribute__((warn_unused_result))
void *
fd_rng_secure( void * d,
               ulong  sz ) {
  FD_LOG_WARNING(( "fd_rng_secure failed (not supported by this build)" ));
  return NULL;
}

#endif
