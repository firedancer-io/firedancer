#ifndef HEADER_fd_src_net_ebpf_fd_ebpf_base_h
#define HEADER_fd_src_net_ebpf_fd_ebpf_base_h
#if defined(__bpf__)

/* eBPF base development environment

   This file is a minimal port of fd_util_base.h to a non-hosted
   Clang/LLVM eBPF little endian target.  This is a temporary measure
   working around the fact that eBPF does not support libc yet, which is
   a dependency of fd_util_base.  For documentations, see fd_util_base.h */

/* Minimal libc-like environment **************************************/

/* Not even the pre-processor definition is NULL is available on eBPF.
   We define the bare minimum to resemble libc. */

#define NULL (void *)0

#define asm    __asm__
#define typeof __typeof__

/* Integer types ******************************************************/

typedef   signed char  schar;
typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

/* Optimizer tricks ***************************************************/

/* FD_{LIKELY,UNLIKELY}(c):  Evaluates c and returns whether it is
   logical true/false as long (1L/0L).  It also hints to the optimizer
   whether it should optimize for the case of c evaluating as
   true/false. */

#define FD_LIKELY(c)   __builtin_expect( !!(c), 1L )
#define FD_UNLIKELY(c) __builtin_expect( !!(c), 0L )

#endif /* defined(__bpf__) */
#endif /* HEADER_fd_src_net_ebpf_fd_ebpf_base_h */
