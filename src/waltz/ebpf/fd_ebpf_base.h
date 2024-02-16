#ifndef HEADER_fd_src_waltz_ebpf_fd_ebpf_base_h
#define HEADER_fd_src_waltz_ebpf_fd_ebpf_base_h
#if defined(__bpf__)

/* eBPF base development environment

   This file is a minimal port of fd_util_base.h to a non-hosted
   Clang/LLVM eBPF little endian target.  This is a temporary measure
   working around the fact that eBPF does not support libc yet, which is
   a dependency of fd_util_base.  For documentations, see fd_util_base.h

   ### eBPF Instruction Set Architecture

   The eBPF ISA is similar to modern RISC instruction sets.  It provides
   a small number of general-purpose registers and common memory access,
   arithmetic, and control-flow instructions.

   Linux docs: https://docs.kernel.org/bpf/instruction-set.html

   ### eBPF Kernel Verifier

   As eBPF allows userspace to deploy arbitrary programs, the kernel
   enforces strict rules on program behavior.  Namely, given any
   arbitrary packet input, ...

     ... programs must terminate in finite time
     ... programs must not make arbitrary memory accesses

   Linux docs: https://docs.kernel.org/bpf/verifier.html

   ### eBPF Build Process

   The eBPF virtual machine loads code from ELF binaries not unlike
   native programs on Linux-based operating systems.  While this allows
   using the familiar C build system, it requires a cross-compiler that
   is capable of generating eBPF bytecode that abides the the afore-
   mentioned kernel verifier rules, such as upstream Clang/LLVM 14 or
   later.

   For a mostly up-to-date blog post on the topic, see:
   https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/

   ### eBPF Program State

   The environment by the eBPF virtual machine is restricted:  There is
   no access to most system features like the file system, and the life-
   time of an XDP program execution is no longer than it takes to
   process a single packet.  Instead, eBPF maps provide a set of generic
   interfaces for sharing and persisting data, as well as accessing
   kernel objects like XSKs.

   Linux docs: https://docs.kernel.org/bpf/maps.html
               https://docs.kernel.org/bpf/map_xskmap.html */

/* Minimal libc-like environment **************************************/

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
#endif /* HEADER_fd_src_waltz_ebpf_fd_ebpf_base_h */
