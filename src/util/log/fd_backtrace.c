#define _GNU_SOURCE
#include "fd_backtrace.h"
#include "../fd_util_base.h"
#include "../log/fd_log.h"

#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

void
fd_backtrace_log( void ** addrs,
                  ulong   addrs_cnt ) {
  for( ulong i=0UL; i<addrs_cnt; i++ ) {
    void * addr = addrs[ i ];
    Dl_info info;

    void * _map = NULL;
    if( FD_LIKELY( dladdr1( addr, &info, &_map, RTLD_DL_LINKMAP ) && info.dli_fname && info.dli_fname[0]!='\0' ) ) {
      struct link_map * map = _map;
      info.dli_fbase = (void*)map->l_addr;
      if( FD_UNLIKELY( !info.dli_sname ) ) info.dli_saddr = info.dli_fbase;
      if( FD_UNLIKELY( !info.dli_sname && !info.dli_saddr ) ) fd_log_private_fprintf_0( STDERR_FILENO, "%s(%s) [%p]\n", info.dli_fname ? info.dli_fname : "", info.dli_sname ? info.dli_sname : "", addr );
      else {
        char sign;
        long offset;
        if( addr>=info.dli_saddr ) { sign = '+'; offset = (long)( (ulong)addr - (ulong)info.dli_saddr ); }
        else                       { sign = '-'; offset = (long)( (ulong)info.dli_saddr - (ulong)addr ); }
        fd_log_private_fprintf_0( STDERR_FILENO, "%s(%s%c%#lx) [%p]\n", info.dli_fname ? info.dli_fname : "", info.dli_sname ? info.dli_sname : "", sign, (ulong)offset, addr );
      }
    } else {
      fd_log_private_fprintf_0( STDERR_FILENO, "%p\n", addr );
    }
  }
}
