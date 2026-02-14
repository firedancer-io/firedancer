#ifndef HEADER_fd_fdos_x86_fd_x86_disasm_h
#define HEADER_fd_fdos_x86_fd_x86_disasm_h

#define FD_X86_DISASM_MAX 512

#if FD_HAS_LIBLLVM

#include "../../util/fd_util_base.h"

char *
fd_x86_disasm( char          str[ FD_X86_DISASM_MAX ],
               ulong         rip,
               uchar const * code,
               ulong         code_sz,
               ulong         code_base );

#endif /* FD_HAS_LIBLLVM */

#endif /* HEADER_fd_fdos_x86_fd_x86_disasm_h */
