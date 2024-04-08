#ifndef HEADER_fd_src_util_sanitize_fd_msan_h
#define HEADER_fd_src_util_sanitize_fd_msan_h

#include "../fd_util_base.h"

/* MemorySanitizer (MSan) detects uninitialized access via a global
   bitmap.

   More info on MSan:
     - https://clang.llvm.org/docs/MemorySanitizer.html
     - https://github.com/google/sanitizers/wiki/MemorySanitizer */

/* Based on https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/msan_interface.h

   Part of the LLVM Project, under the Apache License v2.0 with LLVM
   Exceptions.  See https://llvm.org/LICENSE.txt for license
   information.  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

   This file was originally part of MemorySanitizer (MSan). */

#ifndef FD_HAS_MSAN
#if defined(__has_feature)
#define FD_HAS_MSAN __has_feature(memory_sanitizer)
#else
#define FD_HAS_MSAN 0
#endif
#endif

#if FD_HAS_MSAN
#define FD_FN_NO_MSAN __attribute__((no_sanitize("memory")))
#else
#define FD_FN_NO_MSAN
#endif

FD_PROTOTYPES_BEGIN

#if FD_HAS_ASAN

/* These are for internal use only */

void __msan_poison                  ( void const volatile * addr, ulong sz );
void __msan_unpoison                ( void const volatile * addr, ulong sz );
void __msan_check_mem_is_initialized( void const volatile * addr, ulong sz );

static inline void * fd_msan_poison  ( void * addr, ulong sz ) { __msan_poison  ( addr, sz ); return addr; }
static inline void * fd_msan_unpoison( void * addr, ulong sz ) { __msan_unpoison( addr, sz ); return addr; }
static inline void   fd_msan_check   ( void * addr, ulong sz ) { __msan_check_mem_is_initialized( addr, sz ); }

#else

static inline void * fd_msan_poison  ( void * addr, ulong sz ) { (void)sz; return addr; }
static inline void * fd_msan_unpoison( void * addr, ulong sz ) { (void)sz; return addr; }
static inline void   fd_msan_check   ( void * addr, ulong sz ) { (void)addr; (void)sz; }

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sanitize_fd_msan_h */
