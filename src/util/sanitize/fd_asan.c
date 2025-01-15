#include "../fd_util.h"
#include "../log/fd_log.h"
#include "fd_asan.h"

#ifdef FD_HAS_DEEPASAN_WATCH
#include "fd_backtrace.h"
#include <stdio.h>

static volatile ulong fd_asan_watch_addrs[64] = { 0 };
static volatile uint fd_asan_watch_addrs_cnt = 0;

void
fd_asan_watch( void const * addr ) {
  uint n = FD_ATOMIC_FETCH_AND_ADD(&fd_asan_watch_addrs_cnt, 1U);
  if( n >= 64 ) FD_LOG_CRIT(( "watching too many addresses" ));
  fd_asan_watch_addrs[n] = (ulong)addr;
  int poison = __asan_address_is_poisoned( addr );
  fprintf( stderr, "watching 0x%lx under asan (now %s)", (ulong)addr, (poison ? "POISONED" : "NOT POISONED") );
  fflush( stderr );
  fd_backtrace_print( fileno(stderr) );
}

void
fd_asan_check_watch( int poison, void * addr, ulong sz ) {
  for( uint i = 0; i < fd_asan_watch_addrs_cnt; ++i ) {
    ulong x = fd_asan_watch_addrs[ i ];
    if( x < (ulong)addr + sz && x >= (ulong)addr ) {
      fprintf( stderr, "updating 0x%lx under asan (now %s)", (ulong)x, (poison ? "POISONED" : "NOT POISONED") );
      fflush( stderr );
      fd_backtrace_print( fileno(stderr) );
    }
  }
}
#endif
