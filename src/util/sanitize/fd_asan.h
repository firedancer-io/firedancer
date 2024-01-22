#ifndef HEADER_fd_src_util_sanitize_fd_asan_h
#define HEADER_fd_src_util_sanitize_fd_asan_h

#include "../fd_util_base.h"

/* AddressSanitizer (ASan) tracks allocated memory regions and
   instruments all memory accesses to detect possible out-of-bounds
   errors.

   This API is used to mark memory regions at runtime where default ASan
   instrumentation is missing.  Firedancer objects are mainly backed by
   shared memory segments via huge pages managed by a custom memory
   allocator.

   More info on ASan:
     - https://clang.llvm.org/docs/AddressSanitizer.html
     - https://github.com/google/sanitizers/wiki/AddressSanitizer

   For a guide on how to setup manual ASan memory poisoning, see
   https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning */

/* Based on https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h

   Part of the LLVM Project, under the Apache License v2.0 with LLVM
   Exceptions.  See https://llvm.org/LICENSE.txt for license
   information.  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

   This file was originally part of AddressSanitizer (ASan). */

#ifndef FD_HAS_ASAN
#if defined(__has_feature)
#define FD_HAS_ASAN __has_feature(address_sanitizer)
#elif defined(__SANITIZE_ADDRESS__)
#define FD_HAS_ASAN 1
#else
#define FD_HAS_ASAN 0
#endif
#endif

/* FD_FN_NO_ASAN is a function attribute to disable ASan instrumentation
   when FD_HAS_ASAN is set (and expands to nothing if not). */

#if FD_HAS_ASAN
#define FD_FN_NO_ASAN __attribute__((no_sanitize("address")))
#else
#define FD_FN_NO_ASAN
#endif

FD_PROTOTYPES_BEGIN

/* If FD_HAS_ASAN is set:

   fd_asan_poison marks a memory region `[addr,addr+sz)` as
   unaddressable and returns addr.  This memory must be previously
   allocated by your program.  Instrumented code is forbidden from
   accessing addresses in this region until it is unpoisoned.  This
   function is not guaranteed to poison the entire region; it might
   poison only a sub-region of `[addr,addr+sz)` due to ASan alignment
   restrictions.

   fd_asan_unpoison marks a memory region `[addr,addr+sz)` as
   addressable and returns addr.  This memory must be previously
   allocated by your program.  Accessing addresses in this region is
   allowed until this region is poisoned again.  This function might
   unpoison a super-region of `[addr,addr+sz)` due to ASan alignment
   restrictions.

   fd_asan_test tests if an address is poisoned.  Returns 1 if addr is
   poisoned (that is, a 1-byte read/write access to this address would
   result in an error report from ASan).  Otherwise returns 0.

   fd_asan_query checks if a region is poisoned.  If at least one byte
   in `[addr,addr+sz)` is poisoned, returns the address of the first
   such byte.  Otherwise returns NULL.

   If FD_HAS_ASAN is not set fd_asan_{poison,unpoison} just return addr,
   fd_asan_test returns 0 and fd_asan_query returns NULL.

   FIXME: CONST CORRECT VERSIONS? */

#if FD_HAS_ASAN

/* These are for internal use only */

void   __asan_poison_memory_region  ( void const volatile * addr, ulong sz );
void   __asan_unpoison_memory_region( void const volatile * addr, ulong sz );
int    __asan_address_is_poisoned   ( void const volatile * addr           );
void * __asan_region_is_poisoned    ( void *                addr, ulong sz );

static inline void * fd_asan_poison  ( void * addr, ulong sz ) { __asan_poison_memory_region  ( addr, sz ); return addr; }
static inline void * fd_asan_unpoison( void * addr, ulong sz ) { __asan_unpoison_memory_region( addr, sz ); return addr; }
static inline int    fd_asan_test    ( void * addr           ) { return __asan_address_is_poisoned( addr );     }
static inline void * fd_asan_query   ( void * addr, ulong sz ) { return __asan_region_is_poisoned ( addr, sz ); }

#else

static inline void * fd_asan_poison  ( void * addr, ulong sz ) { (void)sz;             return addr; }
static inline void * fd_asan_unpoison( void * addr, ulong sz ) { (void)sz;             return addr; }
static inline int    fd_asan_test    ( void * addr           ) { (void)addr;           return 0;    }
static inline void * fd_asan_query   ( void * addr, ulong sz ) { (void)addr; (void)sz; return NULL; }

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sanitize_fd_asan_h */
