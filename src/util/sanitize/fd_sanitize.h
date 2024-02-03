#ifndef HEADER_fd_src_util_sanitize_fd_sanitize_h
#define HEADER_fd_src_util_sanitize_fd_sanitize_h

/* APIs provided by compiler sanitizers.

   Sanitizers are error detection tools built from a combination of
   hardware facilities, hooks injected into compiled code, special
   memory mappings, and library functions.

   For example, the AddressSanitizer can be used to detect out-of-bounds
   memory accesses that otherwise don't crash a process and various
   other undefined behavior. */

#include "fd_asan.h"
#include "fd_msan.h"

#endif /* HEADER_fd_src_util_sanitize_fd_sanitize_h */
