#ifndef HEADER_fd_src_util_sandbox_fd_shstk_h
#define HEADER_fd_src_util_sandbox_fd_shstk_h

/* fd_shstk.h enables x86 shadow stack even if the libc is too old to
   support shadow stacks. */

#include "../fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_shstk_enter attempts to enable x86 shadow stack support, then
   runs *main_fn.  The return value of main_fn is passed to exit(3).
   If shadow stack enabling fails (due to lack of arch/kernel support),
   logs warning, but continues running main_fn.  Should be run after
   fd_boot.

   WARNING: Incompatible with setjmp/longjmp, which may not support
            shadow stacks. */

__attribute__((noreturn))
void
fd_shstk_enter( int (* main_fn)( int     argc,
                                 char ** argv ),
                int     argc,
                char ** argv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sandbox_fd_shstk_h */
