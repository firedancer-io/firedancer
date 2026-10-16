/* LD_PRELOAD: deterministic getrandom() for threads whose comm matches $FIXRAND_COMM (comma-separated substrings, or *) */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
static __thread uint64_t ctr;
ssize_t getrandom( void * buf, size_t len, unsigned flags ) {
  char comm[ 32 ] = {0}; prctl( PR_GET_NAME, comm, 0, 0, 0 );
  char const * want = getenv( "FIXRAND_COMM" );
  int match = 0;
  if( want && !strcmp( want, "*" ) ) match = 1;
  else if( want ) { char w[ 256 ]; strncpy( w, want, 255 ); w[255]=0;
    for( char * t=strtok( w, "," ); t; t=strtok( NULL, "," ) ) if( strstr( comm, t ) ) match = 1; }
  if( !match ) return syscall( SYS_getrandom, buf, len, flags );
  unsigned char * p = buf;
  uint64_t h = 1469598103934665603ULL; for( char * c=comm; *c; c++ ) h = (h ^ (uint64_t)*c) * 1099511628211ULL;
  for( size_t i=0; i<len; i+=8 ) {
    uint64_t x = h + 0x9E3779B97F4A7C15ULL * ++ctr; x ^= x>>31; x *= 0xBF58476D1CE4E5B9ULL; x ^= x>>29;
    memcpy( p+i, &x, len-i<8 ? len-i : 8 );
  }
  return (ssize_t)len;
}
