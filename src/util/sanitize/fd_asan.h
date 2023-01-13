#ifndef HEADER_fd_src_util_sanitize_fd_asan_h
#define HEADER_fd_src_util_sanitize_fd_asan_h

/* AddressSanitizer (ASan) tracks allocated memory regions and
   instruments all memory accesses to detect possible out-of-bounds
   errors.

   This API is used to mark memory regions at runtime where default ASan
   instrumentation is missing. Firedancer objects are mainly backed by
   shared memory segments via huge pages managed by a custom memory
   allocator.

   More info on ASan:
     - https://clang.llvm.org/docs/AddressSanitizer.html
     - https://github.com/google/sanitizers/wiki/AddressSanitizer

   For a guide on how to setup manual ASan memory posioning, see
   https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning */

/* Copied from https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h

   Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
   See https://llvm.org/LICENSE.txt for license information.
   SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

   This file was originally part of AddressSanitizer (ASan). */

#if defined(__has_feature)
#define FD_HAS_ASAN __has_feature(address_sanitizer)
#elif defined(__SANITIZE_ADDRESS__)
#define FD_HAS_ASAN 1
#else
#define FD_HAS_ASAN 0
#endif

/* Macros provided for convenience.
   Defined as no-ops if ASan is not enabled. */

#if FD_HAS_ASAN

/* FD_FN_NO_ASAN: function attribute to disable ASan instrumentation */
#define FD_FN_NO_ASAN __attribute__((no_sanitize("address")))

/* ASAN_POISON_MEMORY_REGION: Marks a memory region as unaddressable. */
#define ASAN_POISON_MEMORY_REGION(addr, size) \
  __asan_poison_memory_region((addr), (size))

/* ASAN_UNPOISON_MEMORY_REGION: Marks a memory region as addressable. */
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
  __asan_unpoison_memory_region((addr), (size))

#else

#define FD_FN_NO_ASAN

#define ASAN_POISON_MEMORY_REGION(addr, size) \
  ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
  ((void)(addr), (void)(size))

#endif

FD_PROTOTYPES_BEGIN

/* __asan_poison_memory_region:
   Marks a memory region `[addr, addr+size)` as unaddressable.

   This memory must be previously allocated by your program. Instrumented
   code is forbidden from accessing addresses in this region until it is
   unpoisoned. This function is not guaranteed to poison the entire region -
   it could poison only a subregion of `[addr, addr+size)` due to ASan
   alignment restrictions. */
void
__asan_poison_memory_region( void const volatile * addr,
                             ulong                 size );

/* __asan_unpoison_memory_region:
   Marks a memory region as addressable.

   This memory must be previously allocated by your program. Accessing
   addresses in this region is allowed until this region is poisoned again.
   This function could unpoison a super-region of `[addr, addr+size)` due
   to ASan alignment restrictions. */
void
__asan_unpoison_memory_region( void const volatile * addr,
                               ulong                 size );

/* Checks if an address is poisoned.

   Returns 1 if addr is poisoned (that is, 1-byte read/write
   access to this address would result in an error report from ASan).
   Otherwise returns 0. */
int
__asan_address_is_poisoned( void const volatile * addr );

/* Checks if a region is poisoned.

   If at least one byte in `[beg, beg+size)` is poisoned, returns the
   address of the first such byte. Otherwise returns 0. */
void *
__asan_region_is_poisoned( void * beg,
                           ulong  size );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sanitize_fd_asan_h */
