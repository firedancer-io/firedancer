#ifndef HEADER_fd_src_util_log_fd_backtrace_h
#define HEADER_fd_src_util_log_fd_backtrace_h

#include "../fd_util_base.h"

/* fd_backtrace_init primes dladdr so that the dynamic linker is
   loaded before we might be in a signal handler context.  Should
   be called once during boot. */

void
fd_backtrace_init( void );

/* fd_backtrace_elf_preload iterates all currently loaded shared
   objects (and the main executable) via dl_iterate_phdr, and
   mmap's each one to parse and cache DWARF .debug_line info.

   This must be called before entering the sandbox (before
   fd_sandbox_enter) so that the ELF mappings persist.  After this,
   fd_backtrace_log can resolve file:line info without any syscalls
   beyond write(). */

void
fd_backtrace_elf_preload( void );

/* fd_backtrace_log walks the stack via frame pointers, resolves
   each return address to symbol name + file:line:col (if DWARF
   debug info is available), and prints the backtrace to the given
   file descriptor.  Async-signal-safe (uses only pre-cached ELF
   data and write()). */

void
fd_backtrace_log( int fd );

#endif /* HEADER_fd_src_util_log_fd_backtrace_h */
