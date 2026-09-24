/*
** This file has been pre-processed with DynASM.
** https://luajit.org/dynasm.html
** DynASM version 1.5.0, DynASM x64 version 1.5.0
** DO NOT EDIT! The original file is in "fd_transpile_x86.dasc".
*/

#line 1 "fd_transpile_x86.dasc"
/* fd_transpile_x86.dasc translates sBPF v0, v1, and v3 programs to
   native x86 code.

   The path from an sBPF program to executable x86 code is a little
   complicated:
   - fd_transpile_x86.dasc is C code with inline x86 assembly templates
   - fd_transpile_x86.c is pure C code that is capable of generating x86
     machine code.  It is generated from the .dasc file using LuaJIT
     DynASM, and is checked into the repo, to avoid Lua from becoming a
     required build dependency
   - fd_transpile_x86 is compiled, producing the compiler
   - fd_transpile_x86 is executed against sBPF programs to generate
     relocatable x86 code
   - This relocatable code is statically linked into the Firedancer VM,
     allowing it to execute programs natively

   This "transpiler" itself converts each sBPF instruction to one or
   more native x86_64 instructions.  Transpiled execution is usually
   much faster than interpreted execution: no need to parse sBPF
   instructions, superscalar execution, speculative execution, etc.

   sBPF registers are assigned to x86 registers as follows:

   BPF | r0  | r1  | r2  | r3  | r4  | r5  | r6  | r7  | r8  | r9  | r10
   x86 | rax | rsi | rdx | rcx | r8  | r9  | r10 | r11 | rbx | r13 | r14

   The remaining x86 registers are used as follows:
   - r12: fd_vm_t context pointer
   - rsp: stack pointer (used for BPF call stack)
   - rbp: frame pointer of the current sBPF function (see below)
   - rdi: scratch
   - r15: scratch

   Note: Why this assignment?
   - BPF r0 and psABI rax are used as "return register 0"
   - BPF r1..r5 and psABI rsi, rdx, rcx, r8, r9 are used as scalar
     arguments to fd_vm_syscall handlers
   - x86 r12 and r13 have unique instruction coding quirks when used
     as base pointers (r12 needs an SIB byte, r13 needs 8-bit
     displacement)

   sBPF virtual memory is emulated.  Every sBPF memory access undergoes
   virtual address translation and bounds checks in software (often
   using x86 helper routines.)

   More complex logic that cannot trivially be implemented in transpiled
   x86 falls back to C code.  The process of switching between C code
   and transpiled code is called a "context switch".

   Context switches allow arbitrarily switching between the interpreter
   and transpiled code during sBPF program execution.  This works
   because transpiled code and load/save its native state (in x86
   registers) from/to the fd_vm_t struct.

   The transpiler requires sBPF programs to be split up into "basic
   blocks" ahead of time.

   CUs are consumed and checked at the end of each basic block.  This
   means that transpiled code does not fault precisely when running out
   of CU, but may have executed a few instructions too much.  This is
   SVM spec compliant.

   BPF-to-BPF and syscalls do not end a basic block.  They only settle
   CUs, such that syscalls see an accurate vm->cu (possibly negative,
   in which case the first CU charge in the syscall fails).
   Faults charge the instructions executed so far in the current basic
   block, like the interpreter.

   A jump or call destination must be the first instruction of a basic
   block.  If a callx instruction (indirect call) attempts to jump into
   the middle of a basic block, the transpiled code traps and switches
   to the interpreter for the remaining program execution ("bail").

   sBPF faults (e.g. divide-by-zero, invalid memory access) causes
   transpiled code to unwind.  The caller of the transpiled code main
   function then sees an abnormal-exit return code.  Unwinding locates
   the root frame through the x86 stack (see below), restores rsp, and
   pops the root frame, like longjmp.

   Every sBPF function invocation has a psABI style x86 frame: the
   return address at [rbp+8] and the caller's rbp at [rbp].  The root
   frame links to the C caller.  Frame pointer based stack walkers
   (perf record --call-graph fp, gdb, fd_log backtraces) thus see the
   sBPF call stack.  Helper subroutines (mmu_*, syscall thunks, ...) do
   not create frames of their own, so their self time is attributed to
   the calling sBPF function.  Transpiled code does not yet ship with
   .eh_frame or DWARF line info.

   Every transpiled frame (root and sBPF) additionally holds the root
   frame pointer at [rbp-8], copied from its caller's frame on entry
   (the root frame points to itself).  Unwinding thus only trusts the
   x86 stack, which sBPF code cannot address, and keeps working if the
   fd_vm_t struct is corrupted.  The root frame saves the callee-saved
   registers and the CET shadow stack pointer below that slot (see the
   root prologue).  sBPF function bodies run with rsp==rbp-16.

   Additional optimizations:
   - fast r10-relative accesses: '{ldx,stx}{b,h,w,dw} [r10+???]'
     instructions to the current sBPF stack frame translate to x86 'mov'
     instructions without bounds checks
   - memory access fast path: stack and heap accesses are translated and
     bounds checked without a context switch
   - 1-slot soft TLB: repeated memory accesses to the same account
     result in fewer context switches by caching address translation
     results
   - lazy stack/heap initialization: execution starts with dirty/uninit
     stack and heap.  accesses to uninitialized but valid regions fall
     through to the slow path, and are zeroed just-in-time

   TODO
   - x86 protection keys
   - x86 CET shadow stack compatibility
   - x86 CET indirect branch tracking compatibility
   - Set vm->pc correctly on fault */

#include "fd_transpile.h"
#include <setjmp.h>

static FD_TL jmp_buf dasm_oom;
__attribute__((noreturn)) static void
dasm_trap_oom( char const * msg ) {
  FD_LOG_WARNING(( "transpile scratch buffer out of memory (%s)", msg ));
  longjmp( dasm_oom, 1 );
}

/* all DynASM state is preallocated, so just trap to OOM on grow request */
#define Dst_DECL fd_transpiler_t * Dst
#define Dst_REF  (Dst->state)
#define DASM_M_GROW( ctx, t, p, sz, need ) dasm_trap_oom( #t " " #p )
#define DASM_M_FREE( ctx, p, sz )

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wempty-body"
#include "../../../third_party/luajit/dasm_proto.h"
#include "../../../third_party/luajit/dasm_x86.h"
#pragma GCC diagnostic pop
#include "../fd_vm_private.h"
#include "../syscall/fd_vm_syscall.h"
#include "../../../ballet/murmur3/fd_murmur3.h"

//|.arch x64
#if DASM_VERSION != 10500
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 146 "fd_transpile_x86.dasc"
//|.actionlist actions
static const unsigned char actions[4814] = {
  248,10,73,137,132,253,36,233,73,137,180,253,36,233,73,137,148,253,36,233,
  73,137,140,253,36,233,77,137,132,253,36,233,77,137,140,253,36,233,77,137,
  148,253,36,233,77,137,156,253,36,233,73,137,156,253,36,233,77,137,172,253,
  36,233,77,137,180,253,36,233,195,255,248,11,73,139,132,253,36,233,73,139,
  180,253,36,233,73,139,148,253,36,233,73,139,140,253,36,233,77,139,132,253,
  36,233,77,139,140,253,36,233,77,139,148,253,36,233,77,139,156,253,36,233,
  73,139,156,253,36,233,77,139,172,253,36,233,77,139,180,253,36,233,195,255,
  232,249,0,0,0,0,255,72,141,5,249,0,0,0,0,255,72,131,252,236,8,73,199,132,
  253,36,233,252,255,252,255,252,255,252,255,232,244,10,73,139,188,253,36,233,
  73,43,188,253,36,233,73,137,188,253,36,233,255,76,137,231,255,73,139,188,
  253,36,233,73,3,188,253,36,233,73,137,188,253,36,233,133,192,15,133,244,247,
  232,244,11,72,131,196,8,195,248,1,72,131,196,8,129,252,248,239,15,133,244,
  248,73,199,132,253,36,233,0,0,0,0,248,2,65,191,237,49,252,255,252,233,244,
  12,255,250,31,248,13,77,59,188,253,36,233,15,130,244,255,73,139,188,253,36,
  233,76,41,252,255,15,130,244,255,72,131,252,255,1,15,130,244,255,252,233,
  244,14,248,9,76,137,252,255,72,193,252,239,32,129,252,255,239,15,133,244,
  250,68,137,252,255,73,131,188,253,36,233,1,15,134,244,249,255,252,247,199,
  0,16,0,0,15,133,244,248,209,252,239,68,49,252,255,129,231,0,252,240,252,255,
  252,255,68,49,252,255,248,3,131,199,1,15,130,244,248,65,59,188,253,36,233,
  15,135,244,248,131,252,239,1,73,3,188,253,36,233,15,132,244,248,73,137,252,
  255,252,233,244,15,248,4,129,252,255,239,15,132,244,247,129,252,255,239,15,
  133,244,248,255,65,139,188,253,36,233,72,131,252,255,1,15,130,244,248,72,
  131,252,239,1,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,36,
  233,15,132,244,248,73,137,252,255,252,233,244,15,248,1,65,139,188,253,36,
  233,72,131,252,255,1,15,130,244,248,72,131,252,239,1,65,57,252,255,15,135,
  244,248,68,137,252,255,73,3,188,253,36,233,15,132,244,248,255,73,137,252,
  255,252,233,244,15,248,2,191,237,252,233,244,16,250,31,248,17,77,59,188,253,
  36,233,15,130,244,255,73,139,188,253,36,233,76,41,252,255,15,130,244,255,
  72,131,252,255,2,15,130,244,255,252,233,244,14,248,9,255,76,137,252,255,72,
  193,252,239,32,129,252,255,239,15,133,244,250,68,137,252,255,73,131,188,253,
  36,233,1,15,134,244,249,252,247,199,0,16,0,0,15,133,244,248,209,252,239,68,
  49,252,255,129,231,0,252,240,252,255,252,255,68,49,252,255,248,3,131,199,
  2,15,130,244,248,65,59,188,253,36,233,15,135,244,248,131,252,239,2,73,3,188,
  253,36,233,15,132,244,248,73,137,252,255,252,233,244,15,248,4,255,129,252,
  255,239,15,132,244,247,129,252,255,239,15,133,244,248,65,139,188,253,36,233,
  72,131,252,255,2,15,130,244,248,72,131,252,239,2,65,57,252,255,15,135,244,
  248,68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,252,
  233,244,15,248,1,65,139,188,253,36,233,72,131,252,255,2,15,130,244,248,255,
  72,131,252,239,2,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,
  36,233,15,132,244,248,73,137,252,255,252,233,244,15,248,2,191,237,252,233,
  244,16,250,31,248,18,77,59,188,253,36,233,15,130,244,255,73,139,188,253,36,
  233,76,41,252,255,15,130,244,255,255,72,131,252,255,4,15,130,244,255,252,
  233,244,14,248,9,76,137,252,255,72,193,252,239,32,129,252,255,239,15,133,
  244,250,68,137,252,255,73,131,188,253,36,233,1,15,134,244,249,252,247,199,
  0,16,0,0,15,133,244,248,209,252,239,68,49,252,255,129,231,0,252,240,252,255,
  252,255,68,49,252,255,248,3,131,199,4,15,130,244,248,65,59,188,253,36,233,
  15,135,244,248,255,131,252,239,4,73,3,188,253,36,233,15,132,244,248,73,137,
  252,255,252,233,244,15,248,4,129,252,255,239,15,132,244,247,129,252,255,239,
  15,133,244,248,65,139,188,253,36,233,72,131,252,255,4,15,130,244,248,72,131,
  252,239,4,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,36,233,
  15,132,244,248,255,73,137,252,255,252,233,244,15,248,1,65,139,188,253,36,
  233,72,131,252,255,4,15,130,244,248,72,131,252,239,4,65,57,252,255,15,135,
  244,248,68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,
  252,233,244,15,248,2,191,237,252,233,244,16,250,31,248,19,255,77,59,188,253,
  36,233,15,130,244,255,73,139,188,253,36,233,76,41,252,255,15,130,244,255,
  72,131,252,255,8,15,130,244,255,252,233,244,14,248,9,76,137,252,255,72,193,
  252,239,32,129,252,255,239,15,133,244,250,68,137,252,255,73,131,188,253,36,
  233,1,15,134,244,249,252,247,199,0,16,0,0,15,133,244,248,255,209,252,239,
  68,49,252,255,129,231,0,252,240,252,255,252,255,68,49,252,255,248,3,131,199,
  8,15,130,244,248,65,59,188,253,36,233,15,135,244,248,131,252,239,8,73,3,188,
  253,36,233,15,132,244,248,73,137,252,255,252,233,244,15,248,4,129,252,255,
  239,15,132,244,247,129,252,255,239,15,133,244,248,65,139,188,253,36,233,255,
  72,131,252,255,8,15,130,244,248,72,131,252,239,8,65,57,252,255,15,135,244,
  248,68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,252,
  233,244,15,248,1,65,139,188,253,36,233,72,131,252,255,8,15,130,244,248,72,
  131,252,239,8,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,36,
  233,15,132,244,248,73,137,252,255,252,233,244,15,248,2,255,191,237,252,233,
  244,16,250,31,248,20,77,59,188,253,36,233,15,130,244,255,73,139,188,253,36,
  233,76,41,252,255,15,130,244,255,72,131,252,255,1,15,130,244,255,252,233,
  244,14,248,9,76,137,252,255,72,193,252,239,32,129,252,255,239,15,133,244,
  250,255,68,137,252,255,73,131,188,253,36,233,1,15,134,244,249,252,247,199,
  0,16,0,0,15,133,244,248,209,252,239,68,49,252,255,129,231,0,252,240,252,255,
  252,255,68,49,252,255,248,3,131,199,1,15,130,244,248,65,59,188,253,36,233,
  15,135,244,248,131,252,239,1,73,3,188,253,36,233,15,132,244,248,73,137,252,
  255,252,233,244,15,248,4,129,252,255,239,15,132,244,247,255,129,252,255,239,
  15,133,244,248,65,139,188,253,36,233,72,131,252,255,1,15,130,244,248,72,131,
  252,239,1,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,36,233,
  15,132,244,248,73,137,252,255,252,233,244,15,248,1,65,139,188,253,36,233,
  72,131,252,255,1,15,130,244,248,72,131,252,239,1,65,57,252,255,15,135,244,
  248,255,68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,
  252,233,244,15,248,2,191,237,252,233,244,16,250,31,248,21,77,59,188,253,36,
  233,15,130,244,255,73,139,188,253,36,233,76,41,252,255,15,130,244,255,72,
  131,252,255,2,15,130,244,255,255,252,233,244,14,248,9,76,137,252,255,72,193,
  252,239,32,129,252,255,239,15,133,244,250,68,137,252,255,73,131,188,253,36,
  233,1,15,134,244,249,252,247,199,0,16,0,0,15,133,244,248,209,252,239,68,49,
  252,255,129,231,0,252,240,252,255,252,255,68,49,252,255,248,3,131,199,2,15,
  130,244,248,65,59,188,253,36,233,15,135,244,248,131,252,239,2,73,3,188,253,
  36,233,15,132,244,248,255,73,137,252,255,252,233,244,15,248,4,129,252,255,
  239,15,132,244,247,129,252,255,239,15,133,244,248,65,139,188,253,36,233,72,
  131,252,255,2,15,130,244,248,72,131,252,239,2,65,57,252,255,15,135,244,248,
  68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,252,233,
  244,15,248,1,255,65,139,188,253,36,233,72,131,252,255,2,15,130,244,248,72,
  131,252,239,2,65,57,252,255,15,135,244,248,68,137,252,255,73,3,188,253,36,
  233,15,132,244,248,73,137,252,255,252,233,244,15,248,2,191,237,252,233,244,
  16,250,31,248,22,77,59,188,253,36,233,15,130,244,255,255,73,139,188,253,36,
  233,76,41,252,255,15,130,244,255,72,131,252,255,4,15,130,244,255,252,233,
  244,14,248,9,76,137,252,255,72,193,252,239,32,129,252,255,239,15,133,244,
  250,68,137,252,255,73,131,188,253,36,233,1,15,134,244,249,252,247,199,0,16,
  0,0,15,133,244,248,209,252,239,68,49,252,255,129,231,0,252,240,252,255,252,
  255,68,49,252,255,248,3,131,199,4,15,130,244,248,255,65,59,188,253,36,233,
  15,135,244,248,131,252,239,4,73,3,188,253,36,233,15,132,244,248,73,137,252,
  255,252,233,244,15,248,4,129,252,255,239,15,132,244,247,129,252,255,239,15,
  133,244,248,65,139,188,253,36,233,72,131,252,255,4,15,130,244,248,72,131,
  252,239,4,65,57,252,255,15,135,244,248,255,68,137,252,255,73,3,188,253,36,
  233,15,132,244,248,73,137,252,255,252,233,244,15,248,1,65,139,188,253,36,
  233,72,131,252,255,4,15,130,244,248,72,131,252,239,4,65,57,252,255,15,135,
  244,248,68,137,252,255,73,3,188,253,36,233,15,132,244,248,73,137,252,255,
  252,233,244,15,248,2,191,237,252,233,244,16,250,31,248,23,255,191,237,252,
  233,244,16,248,14,77,43,188,253,36,233,77,3,188,253,36,233,248,15,77,133,
  252,255,15,136,244,24,195,255,248,16,80,81,86,82,65,80,65,81,65,82,65,83,
  72,131,252,236,8,137,252,250,129,226,252,255,0,0,0,193,252,239,8,137,252,
  249,76,137,231,76,137,252,254,255,73,137,199,72,131,196,8,65,91,65,90,65,
  89,65,88,90,94,89,88,252,233,244,15,255,248,25,77,139,188,253,36,233,73,105,
  252,255,239,73,141,188,253,60,233,76,137,151,233,76,137,159,233,72,137,95,
  16,76,137,111,24,76,137,119,32,77,139,188,253,36,233,76,137,127,40,77,139,
  188,253,36,233,73,252,255,199,77,137,188,253,36,233,73,129,252,255,239,15,
  131,244,248,73,139,188,253,36,233,72,193,231,12,73,1,252,254,73,141,127,1,
  72,193,231,12,73,3,188,253,36,233,73,137,188,253,36,233,77,59,188,253,36,
  233,15,131,244,26,69,49,252,255,195,248,2,255,65,191,1,0,0,0,195,255,248,
  26,72,131,252,236,8,73,199,132,253,36,233,252,255,252,255,252,255,252,255,
  232,244,10,73,139,188,253,36,233,73,43,188,253,36,233,73,137,188,253,36,233,
  76,137,231,255,73,139,188,253,36,233,73,3,188,253,36,233,73,137,188,253,36,
  233,232,244,11,72,131,196,8,69,49,252,255,195,255,248,27,77,139,188,253,36,
  233,77,133,252,255,15,132,244,247,73,252,255,207,77,137,188,253,36,233,73,
  105,252,255,239,73,141,188,253,60,233,76,139,151,233,76,139,159,233,72,139,
  95,16,76,139,111,24,76,139,119,32,73,141,127,1,72,193,231,12,73,3,188,253,
  36,233,73,137,188,253,36,233,201,195,248,1,232,244,10,73,139,188,253,36,233,
  73,43,188,253,36,233,73,137,188,253,36,233,69,49,252,255,252,233,244,28,255,
  248,29,232,244,10,65,191,237,49,252,255,252,233,244,12,255,248,30,85,252,
  255,117,252,248,72,141,108,36,8,72,131,252,236,24,72,137,68,36,16,76,137,
  188,253,36,233,68,137,252,255,73,193,252,239,32,73,131,252,255,1,15,133,244,
  247,73,43,188,253,36,233,72,193,252,239,3,73,59,188,253,36,233,15,131,244,
  247,72,137,124,36,8,232,244,25,69,133,252,255,15,133,244,250,72,139,124,36,
  8,255,72,15,163,56,15,131,244,248,73,137,252,255,73,131,231,63,72,193,252,
  239,6,196,98,128,252,245,60,252,248,252,243,77,15,184,252,255,255,76,3,60,
  252,248,255,78,99,60,184,73,1,199,72,139,68,36,16,72,131,196,16,62,65,252,
  255,231,248,1,65,191,237,252,233,244,249,248,4,65,191,237,252,233,244,249,
  248,2,72,139,124,36,8,73,137,188,253,36,233,65,191,237,248,3,72,139,68,36,
  16,232,244,10,49,252,255,252,233,244,12,255,64,184,240,42,237,255,72,199,
  192,240,35,237,255,72,184,240,34,237,237,255,254,0,72,131,191,233,0,15,137,
  244,247,184,237,195,248,1,85,72,137,229,85,83,65,84,65,85,65,86,65,87,49,
  201,252,243,72,15,30,201,81,72,131,252,236,8,73,137,252,252,73,139,188,253,
  36,233,73,3,188,253,36,233,73,137,188,253,36,233,73,199,132,253,36,233,252,
  255,252,255,252,255,252,255,73,139,188,253,36,233,72,193,252,239,12,73,137,
  188,253,36,233,77,139,188,253,36,233,73,141,127,1,72,193,231,12,73,3,188,
  253,36,233,73,137,188,253,36,233,232,244,11,77,59,188,253,36,233,15,130,244,
  247,255,232,244,26,248,1,232,244,248,15,11,248,2,85,252,255,117,252,248,72,
  141,108,36,8,72,131,252,236,8,252,233,245,255,73,129,172,253,36,233,239,15,
  136,244,31,255,77,139,188,253,36,233,65,139,135,253,240,131,233,255,76,141,
  184,253,240,3,233,232,244,18,191,237,65,139,7,240,131,255,77,139,188,253,
  36,233,65,15,183,135,253,240,132,233,255,76,141,184,253,240,3,233,232,244,
  17,191,237,65,15,183,7,240,132,255,77,139,188,253,36,233,65,15,182,135,253,
  240,132,233,255,76,141,184,253,240,3,233,232,244,13,191,237,65,15,182,7,240,
  132,255,77,139,188,253,36,233,73,139,135,253,240,131,233,255,76,141,184,253,
  240,3,233,232,244,19,191,237,73,139,7,240,131,255,77,139,188,253,36,233,65,
  199,135,233,237,255,76,141,184,253,240,3,233,232,244,22,191,237,65,199,7,
  237,255,77,139,188,253,36,233,65,137,135,253,240,131,233,255,76,141,184,253,
  240,3,233,232,244,22,191,237,65,137,7,240,131,255,77,139,188,253,36,233,102,
  65,199,135,233,236,255,76,141,184,253,240,3,233,232,244,21,191,237,102,65,
  199,7,236,255,77,139,188,253,36,233,102,65,137,135,253,240,131,233,255,76,
  141,184,253,240,3,233,232,244,21,191,237,102,65,137,7,240,131,255,77,139,
  188,253,36,233,65,198,135,233,235,255,76,141,184,253,240,3,233,232,244,20,
  191,237,65,198,7,235,255,77,139,188,253,36,233,65,136,135,253,240,131,233,
  255,76,141,184,253,240,3,233,232,244,20,191,237,65,136,7,240,131,255,77,139,
  188,253,36,233,73,199,135,233,237,255,76,141,184,253,240,3,233,232,244,23,
  191,237,73,199,7,237,255,77,139,188,253,36,233,73,137,135,253,240,131,233,
  255,76,141,184,253,240,3,233,232,244,23,191,237,73,137,7,240,131,255,64,129,
  192,240,43,239,72,99,192,240,131,240,35,255,72,129,192,240,35,239,255,64,
  1,192,240,131,240,51,72,99,192,240,131,240,35,255,72,1,192,240,131,240,35,
  255,64,129,232,240,43,239,72,99,192,240,131,240,35,255,72,129,232,240,35,
  239,255,64,41,192,240,131,240,51,72,99,192,240,131,240,35,255,72,41,192,240,
  131,240,35,255,64,105,192,240,131,240,51,239,72,99,192,240,131,240,35,255,
  72,105,192,240,131,240,35,239,255,64,15,175,192,240,132,240,52,72,99,192,
  240,131,240,35,255,72,15,175,192,240,132,240,36,255,72,137,4,36,255,72,137,
  84,36,8,255,64,137,192,240,139,49,210,191,237,252,247,252,247,255,137,194,
  255,64,137,192,240,43,255,72,139,4,36,255,72,139,84,36,8,255,72,137,192,240,
  131,49,210,255,72,252,247,252,247,255,72,137,194,255,72,137,192,240,35,255,
  64,137,199,240,139,133,252,255,15,133,244,247,191,237,252,233,244,32,248,
  1,255,72,137,68,36,252,240,255,72,137,84,36,252,248,255,64,137,192,240,139,
  49,210,252,247,252,247,255,72,139,68,36,252,240,255,72,139,84,36,252,248,
  255,72,137,199,240,131,72,133,252,255,15,133,244,247,191,237,252,233,244,
  32,248,1,255,72,137,192,240,131,49,210,72,252,247,252,247,255,64,129,200,
  240,43,239,255,72,129,200,240,35,239,255,64,9,192,240,131,240,51,255,72,9,
  192,240,131,240,35,255,64,129,224,240,43,239,255,72,129,224,240,35,239,255,
  64,33,192,240,131,240,51,255,72,33,192,240,131,240,35,255,64,193,224,240,
  43,235,255,72,193,224,240,35,235,255,196,226,121,240,160,252,247,192,240,
  133,240,37,255,196,226,252,249,240,160,252,247,192,240,133,240,37,255,64,
  193,232,240,43,235,255,72,193,232,240,35,235,255,196,226,123,240,160,252,
  247,192,240,133,240,37,255,196,226,252,251,240,160,252,247,192,240,133,240,
  37,255,64,252,247,216,240,43,255,72,252,247,216,240,35,255,72,137,208,255,
  72,137,208,240,35,255,64,137,208,240,43,255,64,129,252,240,240,43,239,255,
  72,129,252,240,240,35,239,255,64,49,192,240,131,240,51,255,72,49,192,240,
  131,240,35,255,64,137,192,240,131,240,51,255,72,137,192,240,131,240,35,255,
  64,193,252,248,240,43,235,255,72,193,252,248,240,35,235,255,196,226,122,240,
  160,252,247,192,240,133,240,37,255,196,226,252,250,240,160,252,247,192,240,
  133,240,37,255,64,15,183,192,240,132,240,52,255,102,64,193,192,240,43,8,64,
  15,183,192,240,132,240,52,255,64,15,200,240,43,255,72,15,200,240,35,255,72,
  133,192,240,131,240,35,255,72,129,252,248,240,35,239,255,15,132,245,255,64,
  133,192,240,131,240,51,255,64,129,252,248,240,43,239,255,72,57,192,240,131,
  240,35,15,132,245,255,64,57,192,240,131,240,51,15,132,245,255,72,129,252,
  248,240,35,239,15,135,245,255,64,129,252,248,240,43,239,15,135,245,255,72,
  57,192,240,131,240,35,15,135,245,255,64,57,192,240,131,240,51,15,135,245,
  255,72,129,252,248,240,35,239,15,131,245,255,64,129,252,248,240,43,239,15,
  131,245,255,72,57,192,240,131,240,35,15,131,245,255,64,57,192,240,131,240,
  51,15,131,245,255,72,252,247,192,240,35,237,15,133,245,255,64,252,247,192,
  240,43,237,15,133,245,255,72,133,192,240,131,240,35,15,133,245,255,64,133,
  192,240,131,240,51,15,133,245,255,72,57,192,240,131,240,35,15,133,245,255,
  64,57,192,240,131,240,51,15,133,245,255,72,129,252,248,240,35,239,15,143,
  245,255,64,129,252,248,240,43,239,15,143,245,255,72,57,192,240,131,240,35,
  15,143,245,255,64,57,192,240,131,240,51,15,143,245,255,72,129,252,248,240,
  35,239,15,141,245,255,64,129,252,248,240,43,239,15,141,245,255,72,57,192,
  240,131,240,35,15,141,245,255,64,57,192,240,131,240,51,15,141,245,255,72,
  129,252,248,240,35,239,15,130,245,255,64,129,252,248,240,43,239,15,130,245,
  255,72,57,192,240,131,240,35,15,130,245,255,64,57,192,240,131,240,51,15,130,
  245,255,72,129,252,248,240,35,239,15,134,245,255,64,129,252,248,240,43,239,
  15,134,245,255,72,57,192,240,131,240,35,15,134,245,255,64,57,192,240,131,
  240,51,15,134,245,255,72,129,252,248,240,35,239,15,140,245,255,64,129,252,
  248,240,43,239,15,140,245,255,72,57,192,240,131,240,35,15,140,245,255,64,
  57,192,240,131,240,51,15,140,245,255,72,129,252,248,240,35,239,15,142,245,
  255,64,129,252,248,240,43,239,15,142,245,255,72,57,192,240,131,240,35,15,
  142,245,255,64,57,192,240,131,240,51,15,142,245,255,73,129,172,253,36,233,
  239,255,73,199,132,253,36,233,237,232,245,255,252,233,244,33,255,73,129,172,
  253,36,233,239,73,199,132,253,36,233,237,73,137,199,240,131,232,244,30,255,
  252,233,244,27,255,232,244,10,65,191,237,191,1,0,0,0,252,233,244,12,249,255,
  249,85,252,255,117,252,248,72,141,108,36,8,72,131,252,236,8,232,244,25,69,
  133,252,255,15,133,244,29,252,233,245,255,248,32,232,244,10,65,191,237,252,
  233,244,12,255,248,24,72,139,60,36,139,127,1,232,244,10,252,233,244,12,255,
  248,33,232,244,10,65,191,237,49,252,255,252,233,244,12,255,248,31,232,244,
  10,65,191,237,49,252,255,255,248,12,73,41,188,253,36,233,73,139,188,253,36,
  233,73,43,188,253,36,233,73,137,188,253,36,233,73,131,188,253,36,233,0,15,
  141,244,247,73,199,132,253,36,233,0,0,0,0,65,191,237,248,1,190,237,252,233,
  244,28,255,248,28,72,139,109,252,248,49,210,252,243,72,15,30,202,72,133,210,
  15,132,244,247,72,139,77,200,72,41,209,72,193,252,233,3,133,201,15,132,244,
  247,72,137,200,252,243,72,15,174,232,248,1,68,137,252,248,72,141,101,208,
  65,95,65,94,65,93,65,92,91,201,195,255
};

#line 147 "fd_transpile_x86.dasc"
//|.globals fd_xlat_
enum {
  fd_xlat_regs_save,
  fd_xlat_regs_restore,
  fd_xlat_exception_charge,
  fd_xlat_mmu_translate_ld_1,
  fd_xlat_mmu_tlb_hit,
  fd_xlat_mmu_translate_check,
  fd_xlat_mmu_tlb_miss,
  fd_xlat_mmu_translate_ld_2,
  fd_xlat_mmu_translate_ld_4,
  fd_xlat_mmu_translate_ld_8,
  fd_xlat_mmu_translate_st_1,
  fd_xlat_mmu_translate_st_2,
  fd_xlat_mmu_translate_st_4,
  fd_xlat_mmu_translate_st_8,
  fd_xlat_exception_segfault,
  fd_xlat_bpfcall_frame_push,
  fd_xlat_bpfcall_frame_init,
  fd_xlat_bpfcall_frame_pop,
  fd_xlat_unwind,
  fd_xlat_call_imm_depth,
  fd_xlat_callx,
  fd_xlat_exception_cost,
  fd_xlat_exception_div_zero,
  fd_xlat_exception_ill,
  fd_xlat__MAX
};
#line 148 "fd_transpile_x86.dasc"
//|.globalnames fd_xlat_names
static const char *const fd_xlat_names[] = {
  "regs_save",
  "regs_restore",
  "exception_charge",
  "mmu_translate_ld_1",
  "mmu_tlb_hit",
  "mmu_translate_check",
  "mmu_tlb_miss",
  "mmu_translate_ld_2",
  "mmu_translate_ld_4",
  "mmu_translate_ld_8",
  "mmu_translate_st_1",
  "mmu_translate_st_2",
  "mmu_translate_st_4",
  "mmu_translate_st_8",
  "exception_segfault",
  "bpfcall_frame_push",
  "bpfcall_frame_init",
  "bpfcall_frame_pop",
  "unwind",
  "call_imm_depth",
  "callx",
  "exception_cost",
  "exception_div_zero",
  "exception_ill",
  (const char *)0
};
#line 149 "fd_transpile_x86.dasc"
//|.type vm, fd_vm_t, r12
#define Dt1(_V) (int)(ptrdiff_t)&(((fd_vm_t *)0)_V)
#line 150 "fd_transpile_x86.dasc"
//|.section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 151 "fd_transpile_x86.dasc"

/* emit_regs_subroutines: emit helper functions for reg save/restore */

static void
emit_regs_subroutines( fd_transpiler_t * Dst ) {
  /* regs_save: save BPF register state into fd_vm_t */
  //|->regs_save:
  //| mov vm->reg[0],  rax
  //| mov vm->reg[1],  rsi
  //| mov vm->reg[2],  rdx
  //| mov vm->reg[3],  rcx
  //| mov vm->reg[4],  r8
  //| mov vm->reg[5],  r9
  //| mov vm->reg[6],  r10
  //| mov vm->reg[7],  r11
  //| mov vm->reg[8],  rbx
  //| mov vm->reg[9],  r13
  //| mov vm->reg[10], r14
  //| ret
  dasm_put(Dst, 0, Dt1(->reg[0]), Dt1(->reg[1]), Dt1(->reg[2]), Dt1(->reg[3]), Dt1(->reg[4]), Dt1(->reg[5]), Dt1(->reg[6]), Dt1(->reg[7]), Dt1(->reg[8]), Dt1(->reg[9]), Dt1(->reg[10]));
#line 170 "fd_transpile_x86.dasc"

  /* regs_restore: load BPF register state from fd_vm_t */
  //|->regs_restore:
  //| mov rax, vm->reg[0]
  //| mov rsi, vm->reg[1]
  //| mov rdx, vm->reg[2]
  //| mov rcx, vm->reg[3]
  //| mov r8,  vm->reg[4]
  //| mov r9,  vm->reg[5]
  //| mov r10, vm->reg[6]
  //| mov r11, vm->reg[7]
  //| mov rbx, vm->reg[8]
  //| mov r13, vm->reg[9]
  //| mov r14, vm->reg[10]
  //| ret
  dasm_put(Dst, 70, Dt1(->reg[0]), Dt1(->reg[1]), Dt1(->reg[2]), Dt1(->reg[3]), Dt1(->reg[4]), Dt1(->reg[5]), Dt1(->reg[6]), Dt1(->reg[7]), Dt1(->reg[8]), Dt1(->reg[9]), Dt1(->reg[10]));
#line 185 "fd_transpile_x86.dasc"
}

/* CU budgeting math

   Let:
   - budget: initial CU budget (constant)
   - ic:     number of sBPF instructions executed
   - sc:     CUs consumed outside of sBPF instructions (e.g. syscalls)
   - cu:     remaining CU budget
   - anchor: a helper variable

   Because each sBPF instruction costs 1 CU, this holds:
     cu      = budget - ic - sc
     cu + ic = budget - sc = anchor

   cu decrements, and ic and sc increment.

   Transpiled code (excluding syscalls) conceptually does cu-- and ic++
   for each instruction, so 'anchor' stays constant.  'anchor' only
   changes when syscalls charge extra CU.  Therefore, only cu is kept
   up-to-date (at basic block boundaries), and ic is restored lazily.
   - cu is decremented at the end of each basic block
   - 'anchor = ic+cu' is derived before switching to transpiled code
     (e.g. when returning from an sBPF syscall, which increased sc)
   - 'ic = anchor-cu' is derived before context switching away from
     transpiled code (ic is used by the interpreter) */

//| // Settle internal CU state into fd_vm_t (updates 'ic')
//|.macro cu_save
//| mov rdi, vm->transpiled.ic_cu_anchor
//| sub rdi, vm->cu
//| mov vm->ic, rdi
//|.endmacro

//| // Restore internal CU state from fd_vm_t (e.g. after a syscall
//| // decreased 'cu' without incrementing 'ic')
//|.macro cu_restore
//| mov rdi, vm->ic
//| add rdi, vm->cu
//| mov vm->transpiled.ic_cu_anchor, rdi
//|.endmacro

//| // Charge CUs and check for overrun
//|.macro cu_charge, n
//| sub qword vm->cu, n
//| js ->exception_cost
//|.endmacro

//| // Charge CUs without checking
//|.macro cu_settle, n
//| sub qword vm->cu, n
//|.endmacro

/* External function calls

   Some logic is either too complex to transpile, or too common across
   programs to duplicate.  Transpiled code can backup its VM execution
   state, switch back to x86_64 psABI, and call regular C functions.

   This mechanism also allows nesting transpiled code executions via
   cross-program invocations. */

static uint
sym_id_syscall_handler( ulong syscall_slot_id ) {
  return (uint)( FD_VM_TRANSPILE_SYM_MAX + syscall_slot_id );
}

/* emit_ffi_call generates a relocatable call to a C function.  Assumes
   the current CPU state is psABI compliant and rsp is 16 byte aligned. */

static void
emit_ffi_call( fd_transpiler_t * Dst,
               uint              sym ) {
  ulong idx = Dst->reloc_cnt++;
  if( FD_UNLIKELY( idx>=FD_TRANSPILER_RELOC_MAX ) ) {
    longjmp( dasm_oom, 1 );
  }
  Dst->reloc[ idx ] = (fd_elf64_rela){
    .r_info   = FD_ELF64_R_INFO( sym, FD_ELF_R_X86_64_PLT32 ),
    .r_addend = -4L,
  };
  //| .byte 0xe8 // CALL rel32
  //|=>(Dst->dasm_lbl_reloc0 + idx):
  //| .dword 0
  dasm_put(Dst, 140, (Dst->dasm_lbl_reloc0 + idx));
#line 269 "fd_transpile_x86.dasc"
}

/* emit_rodata_lea generates `lea rax, [rodata+off]` */

static void
emit_rodata_lea( fd_transpiler_t * Dst,
                 ulong             off ) {
  ulong idx = Dst->reloc_cnt++;
  if( FD_UNLIKELY( idx>=FD_TRANSPILER_RELOC_MAX ) ) {
    longjmp( dasm_oom, 1 );
  }
  Dst->reloc[ idx ] = (fd_elf64_rela){
    .r_info   = FD_ELF64_R_INFO( FD_VM_TRANSPILE_SYM_RODATA, FD_ELF_R_X86_64_PC32 ),
    .r_addend = (long)off-4L,
  };
  //| .byte 0x48, 0x8d, 0x05 // lea rax, [rip+imm32]
  //|=>(Dst->dasm_lbl_reloc0 + idx):
  //| .dword 0
  dasm_put(Dst, 147, (Dst->dasm_lbl_reloc0 + idx));
#line 287 "fd_transpile_x86.dasc"
}

//|.macro mmu_tlb_invalidate
//| mov qword vm->transpiled.tlb_vaddr_lo, -1
//|.endmacro

//| // Recompute the host address of the current stack frame end (what
//| // r10 points to) from r15=vm->frame_cnt.  Clobbers rdi.  Holds for
//| // both gapped (v0) and non-gapped stack layouts, since the host
//| // mapping is dense either way.
//|.macro frame_haddr_update
//| lea rdi, [r15+1]
//| shl rdi, 12
//| add rdi, vm->region_haddr[FD_VM_STACK_REGION]
//| mov vm->transpiled.frame_haddr, rdi
//|.endmacro

/* emit_syscall_call generates an FFI call to an sBPF syscall handler.
   Assumes the current CPU state is in transpiled ABI. */

static void
emit_syscall_call( fd_transpiler_t * Dst,
                   ulong             slot_idx ) {
  //| sub rsp, 8
  //| mmu_tlb_invalidate
  //| call ->regs_save
  //| cu_save
  dasm_put(Dst, 156, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 314 "fd_transpile_x86.dasc"
  /* TODO a full register file save isn't required for most syscalls */
  //| mov rdi, r12 // fd_vm_t * vm
  dasm_put(Dst, 197);
#line 316 "fd_transpile_x86.dasc"
  emit_ffi_call( Dst, sym_id_syscall_handler( slot_idx ) );
  //| cu_restore
  //| test eax, eax
  //| jnz >1
  //| call ->regs_restore
  //| add rsp, 8
  //| ret
  //|1:
  //| add rsp, 8
  //| cmp eax, FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED
  //| jne >2
  //| mov qword vm->cu, 0
  //|2:
  //| mov r15d, FD_VM_ERR_EBPF_SYSCALL_ERROR
  //| xor edi, edi
  //| jmp ->exception_charge
  dasm_put(Dst, 201, Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED, Dt1(->cu), FD_VM_ERR_EBPF_SYSCALL_ERROR);
#line 332 "fd_transpile_x86.dasc"
}

/* Software address translation routines

   These are called very frequently and are performance critical.  */

static void
emit_mmu_routines( fd_transpiler_t * Dst ) {
  //|// mmu_translate_flat: attempt to translate virtual address (in r15) to
  //|// host address in given flat memory region.
  //|.macro mmu_translate_flat, region, limits, width
  //| mov edi, vm->limits[region]
  //| cmp rdi, width
  //| jb >2
  //| sub rdi, width
  //| cmp r15d, edi
  //| ja >2
  //| mov edi, r15d
  //| add rdi, vm->region_haddr[region]
  //| jz >2
  //| mov r15, rdi
  //| jmp ->mmu_translate_check
  //|.endmacro

  //|// mmu_translate_stack: attempt to translate virtual address (in r15)
  //|// to host address in striped stack memory region.
  //|.macro mmu_translate_stack, limits, width
  //| mov edi, r15d
  //| cmp qword vm->stack_push_frame_count, 1
  //| jbe >3
  //| test edi, 0x1000
  //| jnz >2
  //| shr edi, 1
  //| xor edi, r15d
  //| and edi, -4096
  //| xor edi, r15d
  //|3:
  //| add edi, width
  //| jc >2
  //| cmp edi, vm->limits[FD_VM_STACK_REGION]
  //| ja >2
  //| sub edi, width
  //| add rdi, vm->region_haddr[FD_VM_STACK_REGION]
  //| jz >2
  //| mov r15, rdi
  //| jmp ->mmu_translate_check
  //|.endmacro

  //|// mmu_translate_fast: generate soft MMU hot path (parametrized by
  //|// load/store (limits), and access width)
  //|.macro mmu_translate_fast, limits, width
  //| mov rdi, r15
  //| shr rdi, 32
  //| cmp edi, FD_VM_STACK_REGION
  //| jne >4
  //| mmu_translate_stack limits, width
  //|4:
  //| cmp edi, FD_VM_PROG_REGION
  //| je >1
  //| cmp edi, FD_VM_HEAP_REGION
  //| jne >2
  //| mmu_translate_flat FD_VM_HEAP_REGION, limits, width
  //|1:
  //| mmu_translate_flat FD_VM_PROG_REGION, limits, width
  //|2:
  //|.endmacro

  //|// mmu_translate: generate address translation subroutine
  //|.macro mmu_translate, acc, tlb_hi, limits, sz
  //| cmp r15, vm->transpiled.tlb_vaddr_lo
  //| jb >9
  //| mov rdi, vm->transpiled.tlb_hi
  //| sub rdi, r15
  //| jb >9
  //| cmp rdi, sz
  //| jb >9
  //| jmp ->mmu_tlb_hit
  //|9:
  //| mmu_translate_fast limits, sz  // translate fast path
  //| mov edi, (acc*0x100)+sz        // none matched, FFI to C
  //| jmp ->mmu_tlb_miss
  //|.endmacro

  //|.macro mmu_translate_ld, sz
  //| mmu_translate 0, tlb_vaddr_ld_hi, region_ld_sz, sz
  //|.endmacro

  //|.macro mmu_translate_st, sz
  //| mmu_translate 1, tlb_vaddr_st_hi, region_st_sz, sz
  //|.endmacro

  /* generate subroutines for scalar memory access address translation.
     We could just have a single subroutine taking access type (load/store)
     and width (1/2/4/8) parameters.  Templating results in a measurable
     performance boost though. */

  //|.align 32
  //|->mmu_translate_ld_1:
  //|  mmu_translate_ld,1
  dasm_put(Dst, 270, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count));
  dasm_put(Dst, 346, Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION);
  dasm_put(Dst, 437, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]));
#line 431 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_ld_2:
  //|  mmu_translate_ld,2
  dasm_put(Dst, 532, (0*0x100)+1, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi));
  dasm_put(Dst, 592, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]));
  dasm_put(Dst, 699, FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]));
#line 434 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_ld_4:
  //|  mmu_translate_ld,4
  dasm_put(Dst, 783, Dt1(->region_haddr[FD_VM_PROG_REGION]), (0*0x100)+2, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi));
  dasm_put(Dst, 855, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]));
  dasm_put(Dst, 953, Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]));
#line 437 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_ld_8:
  //|  mmu_translate_ld,8
  dasm_put(Dst, 1036, Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), (0*0x100)+4);
  dasm_put(Dst, 1109, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count));
  dasm_put(Dst, 1192, Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]));
  dasm_put(Dst, 1278, Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]));
#line 440 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_st_1:
  //|  mmu_translate_st,1
  dasm_put(Dst, 1377, (0*0x100)+8, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi), FD_VM_STACK_REGION);
  dasm_put(Dst, 1444, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION);
  dasm_put(Dst, 1542, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]));
#line 443 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_st_2:
  //|  mmu_translate_st,2
  dasm_put(Dst, 1631, Dt1(->region_haddr[FD_VM_PROG_REGION]), (1*0x100)+1, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi));
  dasm_put(Dst, 1699, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]));
  dasm_put(Dst, 1802, FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]));
#line 446 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_st_4:
  //|  mmu_translate_st,4
  dasm_put(Dst, 1881, Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), (1*0x100)+2, Dt1(->transpiled.tlb_vaddr_lo));
  dasm_put(Dst, 1954, Dt1(->transpiled.tlb_vaddr_st_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count));
  dasm_put(Dst, 2056, Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]));
#line 449 "fd_transpile_x86.dasc"
  //|.align 32
  //|->mmu_translate_st_8:
  //|  mmu_translate_st,8
  dasm_put(Dst, 2135, Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), (1*0x100)+4);
  dasm_put(Dst, 1109, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count));
  dasm_put(Dst, 1192, Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]));
  dasm_put(Dst, 1278, Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]));
#line 452 "fd_transpile_x86.dasc"
  //|->mmu_tlb_hit:
  //| // mem_translate_* jump to this label on fast path success
  //| sub r15, vm->transpiled.tlb_vaddr_lo
  //| add r15, vm->transpiled.tlb_haddr_lo
  //| // fall through
  //|->mmu_translate_check:
  //| test r15, r15
  //| js ->exception_segfault
  //| ret
  //| // Above ret is special because it returns to any of tens of thousands
  //| // of possible callers.  Needs the CPU Return Address Stack (RAS) to
  //| // be enabled to avoid frequent mis-speculation.  The RAS is sometimes
  //| // disabled due to Spectre mitigations (e.g. Linux 7.0 Zen5 with
  //| // SEV-SNP enabled).
  dasm_put(Dst, 2222, (1*0x100)+8, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_haddr_lo));
#line 466 "fd_transpile_x86.dasc"

  //|// mmu_tlb_miss: arbitrary virtual address translation via C fallback.
  //|// Input args:
  //|// - r15: ulong vaddr
  //|// - edi: (is_write<<8) | access_width
  //|// Output in r15: ulong haddr
  //|// Faults and unwinds on access violation
  //|->mmu_tlb_miss:
  //| push rax
  //| push rcx
  //| push rsi
  //| push rdx
  //| push r8
  //| push r9
  //| push r10
  //| push r11
  //| sub rsp, 8    // psABI 16 byte align
  //| mov edx, edi
  //| and edx, 0xff // arg 2: ulong     access_width
  //| shr edi, 8
  //| mov ecx, edi  // arg 3: bool      is_write
  //| mov rdi, r12  // arg 0: fd_vm_t * vm
  //| mov rsi, r15  // arg 1: ulong     vaddr
  dasm_put(Dst, 2254);
#line 489 "fd_transpile_x86.dasc"
  emit_ffi_call( Dst, FD_VM_TRANSPILE_SYM_MMU_TRANSLATE );
  //| mov r15, rax
  //| add rsp, 8
  //| pop r11
  //| pop r10
  //| pop r9
  //| pop r8
  //| pop rdx
  //| pop rsi
  //| pop rcx
  //| pop rax
  //| jmp ->mmu_translate_check
  dasm_put(Dst, 2298);
#line 501 "fd_transpile_x86.dasc"
}

/* BPF to BPF calls */

//| // Open a transpiled frame: [rbp+8] return address, [rbp] caller rbp,
//| // [rbp-8] root frame pointer (inherited from the caller's frame).
//| // Leaves rsp==rbp-8.
//|.macro sbpf_frame_enter
//| push rbp
//| push qword [rbp-8]
//| lea rbp, [rsp+8]
//|.endmacro

/* emit_frame_helpers: generate subroutines for BPF-to-BPF calls */

static void
emit_frame_helpers( fd_transpiler_t * Dst ) {
  //|->bpfcall_frame_push:
  //| mov r15, vm->frame_cnt
  //| imul rdi, r15, (int)sizeof(fd_vm_shadow_t)
  //| lea rdi, [r12+rdi+offsetof(fd_vm_t, shadow)]
  //| mov [rdi+ 0], r10
  //| mov [rdi+ 8], r11
  //| mov [rdi+16], rbx
  //| mov [rdi+24], r13
  //| mov [rdi+32], r14
  //| mov r15, vm->pc
  //| mov [rdi+40], r15
  //| mov r15, vm->frame_cnt
  //| inc r15
  //| mov vm->frame_cnt, r15
  //| cmp r15, FD_VM_STACK_FRAME_MAX
  //| jae >2
  //| mov rdi, vm->stack_push_frame_count
  //| shl rdi, 12
  //| add r14, rdi
  //| frame_haddr_update
  //| cmp r15, vm->transpiled.frame_clean_cnt
  //| jae ->bpfcall_frame_init
  //| xor r15d, r15d
  //| ret
  //|2:
  //| mov r15d, 1
  dasm_put(Dst, 2322, Dt1(->frame_cnt), (int)sizeof(fd_vm_shadow_t), offsetof(fd_vm_t, shadow), 0, 8, Dt1(->pc), Dt1(->frame_cnt), Dt1(->frame_cnt), FD_VM_STACK_FRAME_MAX, Dt1(->stack_push_frame_count), Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.frame_clean_cnt));
#line 544 "fd_transpile_x86.dasc"
  //| ret
  dasm_put(Dst, 2448);
#line 545 "fd_transpile_x86.dasc"

  //|->bpfcall_frame_init:
  //| sub rsp, 8
  //| mmu_tlb_invalidate
  //| call ->regs_save
  //| cu_save
  //| mov rdi, r12
  dasm_put(Dst, 2456, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 552 "fd_transpile_x86.dasc"
  emit_ffi_call( Dst, FD_VM_TRANSPILE_SYM_FRAME_INIT );
  //| cu_restore
  //| call ->regs_restore
  //| add rsp, 8
  //| xor r15d, r15d
  //| ret
  dasm_put(Dst, 2502, Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor));
#line 558 "fd_transpile_x86.dasc"

  //|->bpfcall_frame_pop:
  //| mov r15, vm->frame_cnt
  //| test r15, r15
  //| jz >1
  //| dec r15
  //| mov vm->frame_cnt, r15
  //| imul rdi, r15, (int)sizeof(fd_vm_shadow_t)
  //| lea rdi, [r12+rdi+offsetof(fd_vm_t, shadow)]
  //| mov r10, [rdi+ 0]
  //| mov r11, [rdi+ 8]
  //| mov rbx, [rdi+16]
  //| mov r13, [rdi+24]
  //| mov r14, [rdi+32]
  //| frame_haddr_update
  //| leave
  //| ret
  //|1:
  //| call ->regs_save
  //| cu_save
  //| xor r15d, r15d
  //| jmp ->unwind
  dasm_put(Dst, 2533, Dt1(->frame_cnt), Dt1(->frame_cnt), (int)sizeof(fd_vm_shadow_t), offsetof(fd_vm_t, shadow), 0, 8, Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 580 "fd_transpile_x86.dasc"

  //|->call_imm_depth:
  //| call ->regs_save
  //| mov r15d, FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED
  //| xor edi, edi
  //| jmp ->exception_charge
  dasm_put(Dst, 2644, FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED);
#line 586 "fd_transpile_x86.dasc"
}

/* emit_callx_handler: generate subroutine for interpreting callx
   instructions.  This function is scary, because it jumps to an
   arbitrary (user-controlled) location.  The generated assembly is thus
   hardened that it cannot jump out-of-bounds or into the middle of an
   instruction, even if the fd_vm_t struct is compromised.

   This is equivalent to FD_VM_INTERP_BRANCH_BEGIN(0x8d). */

static void
emit_callx_handler( fd_transpiler_t * Dst ) {
  //|->callx:
  //| // frame of the callee (the sBPF function jumped to below):
  //| //   [rbp+ 8]: return address
  //| //   [rbp+ 0]: caller rbp
  //| //   [rbp- 8]: root frame pointer
  //| //   [rsp+16]: BPF r0 (rax) save
  //| //   [rsp+ 8]: target BPF program counter
  //| //   [rsp+ 0]: target BPF virtual address
  //| sbpf_frame_enter
  //| sub rsp, 24
  //| mov [rsp+16], rax
  //| mov [rsp+ 0], r15
  //| // scratch registers: rax, rdi
  //|
  //| // r15 contains the BPF virtual address
  //| // bounds check and convert to a BPF program counter
  //|
  //| mov edi, r15d
  //| shr r15, 32
  //| cmp r15, 1
  //| jne >1 // if( (vaddr>>32)!=1 )
  //| sub rdi, vm->text_off
  //| shr rdi, 3
  //| cmp rdi, vm->text_cnt
  //| jae >1 // if( (uint)(vaddr - vm->text)/8 > (uint)vm->text_cnt )
  //| mov [rsp+8], rdi
  //|
  //| call ->bpfcall_frame_push
  //| test r15d, r15d
  //| jnz >4 // sigstack: call depth exceeded
  //|
  //| mov rdi, [rsp+8]
  //|
  //| // rdi contains the BPF program counter
  //| // check if it is a valid call destination (start of BB)
  //|
  dasm_put(Dst, 2660, 0, Dt1(->text_off), Dt1(->text_cnt));
#line 634 "fd_transpile_x86.dasc"
  ulong bb_word_cnt = (Dst->bpf_text_cnt+63UL)>>6;
  ulong bitmap_off  = 0UL;
  ulong seq_off     = bitmap_off + bb_word_cnt*sizeof(ulong);
  ulong jmp_off     = seq_off    + bb_word_cnt*sizeof(ulong);
  emit_rodata_lea( Dst, bitmap_off );
  //| bt [rax], rdi
  //| jnc >2 // jump into middle of a basic block, bail to interpreter
  //|
  //| // rax points to the BB bitmap
  //| // rdi contains the BPF program counter
  //| // map it to a BB index
  //|
  //| mov r15, rdi
  //| and r15, 63
  //| shr rdi, 6
  //| bzhi r15, [rax + rdi*8], r15
  //| popcnt r15, r15
  dasm_put(Dst, 2750);
#line 651 "fd_transpile_x86.dasc"
  emit_rodata_lea( Dst, seq_off );
  //| add r15, qword [rax + rdi*8]
  //|
  //| // r15 contains the BB index
  //| // map it to the address of its first x86 instruction
  //|
  dasm_put(Dst, 2787);
#line 657 "fd_transpile_x86.dasc"
  emit_rodata_lea( Dst, jmp_off );
  //| movsxd r15, dword [rax+r15*4]
  //| add r15, rax
  //|
  //| // restore state and jump to BB (body runs with rsp==rbp-16)
  //| mov rax, [rsp+16]
  //| add rsp, 16
  //| ds // notrack
  //| jmp r15
  //|
  //|1: // sigtextbr
  //| mov r15d, FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT
  //| jmp >3
  //|4: // sigstack: call depth exceeded
  //| mov r15d, FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED
  //| jmp >3
  //|2: // bail to interpreter
  //| mov rdi, [rsp+8]
  //| mov vm->pc, rdi
  //| mov r15d, FD_VM_ERR_EBPF_BAIL
  //|3:
  //| mov rax, [rsp+16]
  //| call ->regs_save
  //| xor edi, edi
  //| jmp ->exception_charge
  dasm_put(Dst, 2793, FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT, FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED, Dt1(->pc), FD_VM_ERR_EBPF_BAIL);
#line 682 "fd_transpile_x86.dasc"
}

/* emit_const64: load a 64-bit immediate into an x86 register. */

static void
emit_const64( fd_transpiler_t * Dst,
              uchar             reg,
              ulong             value ) {
  if( value<=(ulong)UINT_MAX ) {
    //| mov Rd(reg), (uint)value
    dasm_put(Dst, 2866, (reg), (uint)value);
#line 692 "fd_transpile_x86.dasc"
  } else if( value==(ulong)(long)(int)(uint)value ) {
    //| mov Rq(reg), (int)(uint)value
    dasm_put(Dst, 2872, (reg), (int)(uint)value);
#line 694 "fd_transpile_x86.dasc"
  } else {
    //| mov64 Rq(reg), value
    dasm_put(Dst, 2879, (reg), (unsigned int)(value), (unsigned int)((value)>>32));
#line 696 "fd_transpile_x86.dasc"
  }
}

static inline int
is_stack_frame_access( ulong sbpf_version,
                       ulong bpf_reg,
                       long  offset,
                       ulong width ) {
  return !FD_VM_SBPF_MANUAL_STACK_FRAME_BUMP( sbpf_version ) &&
         bpf_reg==10 &&
         offset>=-(long)FD_VM_STACK_FRAME_SZ &&
         offset<=-(long)width;
}

/* bb_splits_compute heuristically guesses the bounds of basic blocks.
   Control flow transitions in transpiled programs are restricted to
   the starts of basic blocks.  (Otherwise, transpiled execution bails
   transparently to the interpreter.)  Writes a bit vector of
   ceil(bpf_text_cnt/64) words to bb_splits and returns the popcount. */

static ulong
bb_splits_compute( ulong *       bb_splits,
                   ulong         sbpf_version,
                   ulong const * bpf_text,
                   ulong         bpf_text_cnt,
                   ulong         bpf_entry_pc,
                   ulong const * bpf_calldests,
                   uchar const * bpf_rodata,
                   ulong         bpf_rodata_sz,
                   ulong         bpf_text_off ) {
  ulong word_cnt = (bpf_text_cnt+63UL)>>6;
  memset( bb_splits, 0, word_cnt*sizeof(ulong) );

# define SET_BB_SPLIT( pc ) do {                    \
    ulong _pc = (pc);                               \
    if( _pc<bpf_text_cnt )                          \
      bb_splits[ _pc>>6 ] |= ( 1UL<<( _pc&63UL ) ); \
  } while(0)

  SET_BB_SPLIT( 0UL );
  SET_BB_SPLIT( bpf_entry_pc );

  /* Address-taken functions (vtables, closures) reach callx through
     pointers the loader relocated into the read-only segment.  Any
     64-bit word in the loaded image pointing at an instruction slot is
     treated as a possible call target.  Pointers in .data.rel.ro are
     only 4-byte aligned, and false positives merely split a block. */
  ulong text_lo = FD_VM_MEM_MAP_PROGRAM_REGION_START + bpf_text_off;
  ulong text_hi = text_lo + 8UL*bpf_text_cnt;
  for( ulong off=0UL; off+8UL<=bpf_rodata_sz; off+=4UL ) {
    ulong v = FD_LOAD( ulong, bpf_rodata+off );
    if( v>=text_lo && v<text_hi && !((v-text_lo)&7UL) ) SET_BB_SPLIT( (v-text_lo)>>3 );
  }

  int static_syscalls = FD_VM_SBPF_STATIC_SYSCALLS( sbpf_version );
  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    ulong instr  = bpf_text[ pc ];
    ulong opcode = fd_vm_instr_opcode( instr );
    ulong src    = fd_vm_instr_src   ( instr );
    uint  imm    = fd_vm_instr_imm   ( instr );
    long  offset = (long)fd_vm_instr_offset( instr );

    if( bpf_calldests && fd_sbpf_calldests_test( bpf_calldests, pc ) ) {
      SET_BB_SPLIT( pc );
    }

    if( opcode==0x18UL ) { /* LDDW */
      if( pc+1UL<bpf_text_cnt ) {
        ulong v = (ulong)imm | ( bpf_text[ pc+1UL ] & 0xffffffff00000000UL );
        if( v>=text_lo && v<text_hi && !((v-text_lo)&7UL) ) SET_BB_SPLIT( (v-text_lo)>>3 );
      }
      pc++;
      continue;
    }

    ulong cls = opcode & 0x07UL;
    if( cls==0x05UL || cls==0x06UL ) {
      if( opcode==0x85UL /* CALL */ ) {
        if( static_syscalls && src==1UL ) { /* v3 internal call */
          long target = (long)pc + (long)(int)imm + 1L;
          if( target>=0 && (ulong)target<bpf_text_cnt &&
              fd_vm_instr_opcode( bpf_text[ target ] )!=0x00UL /* not inside an LDDW */ ) {
            SET_BB_SPLIT( (ulong)target );
          }
        }
      } else if( opcode==0x95UL /* EXIT */ ) {
        if( pc+1UL<bpf_text_cnt )                    SET_BB_SPLIT( pc+1UL );
      } else if( opcode!=0x8dUL /* CALLX */ ) {
        long target = (long)pc + 1L + offset;
        if( target>=0 && (ulong)target<bpf_text_cnt ) SET_BB_SPLIT( (ulong)target );
        if( pc+1UL<bpf_text_cnt )                    SET_BB_SPLIT( pc+1UL );
      }
    }
  }
# undef SET_BB_SPLIT

  for( ulong pc=0UL; pc+1UL<bpf_text_cnt; pc++ ) {
    if( fd_vm_instr_opcode( bpf_text[ pc ] )==0x18UL ) {
      bb_splits[ (pc+1UL)>>6 ] &= ~( 1UL<<( (pc+1UL)&63UL ) );
      pc++;
    }
  }

  ulong cnt = 0UL;
  for( ulong w=0UL; w<word_cnt; w++ ) cnt += (ulong)fd_ulong_popcnt( bb_splits[ w ] );
  return cnt;
}

/* syms_compute names code ranges for debuggers: sBPF functions (any
   valid call destination, plus the entrypoint), call thunks, syscall
   stubs, and the fd_xlat_ helper routines.  Sizes extend to the next
   named offset (helper routines all end in an unconditional transfer
   and are contiguous, so this is exact for them and an upper bound for
   sBPF functions whose text contains unreachable slots). */

#define SORT_NAME        sym_sort
#define SORT_KEY_T       fd_transpiler_sym_t
#define SORT_BEFORE(a,b) ( (a).off<(b).off || ( (a).off==(b).off && (a).kind>(b).kind ) )
#include "../../../util/tmpl/fd_sort.c"

static void
syms_compute( fd_transpiler_t * Dst,
              ulong             bpf_text_cnt,
              ulong             bpf_entry_pc,
              ulong const *     bpf_calldests,
              ulong const *     syscall_used,
              ulong             code_sz ) {
  ulong cnt = 0UL;
# define PUSH( _kind, _arg, _lbl ) do {                                  \
    int _ofs = dasm_getpclabel( Dst, (uint)(_lbl) );                     \
    if( _ofs>=0 && (ulong)_ofs<code_sz && cnt<FD_TRANSPILER_SYM_MAX ) { \
      Dst->sym[ cnt++ ] = (fd_transpiler_sym_t){                         \
        .off=(uint)_ofs, .arg=(uint)(_arg), .kind=(uchar)(_kind) };      \
    }                                                                    \
  } while(0)

  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    int is_func = pc==bpf_entry_pc || ( bpf_calldests && fd_sbpf_calldests_test( bpf_calldests, pc ) );
    if( is_func ) PUSH( FD_TRANSPILER_SYM_KIND_FUNC, pc, pc );
    if( Dst->thunk_bv[ pc>>6 ] & (1UL<<( pc&63UL )) ) {
      PUSH( FD_TRANSPILER_SYM_KIND_THUNK, pc, Dst->dasm_lbl_thunk0+pc );
    }
  }
  for( ulong slot=0UL; slot<FD_SBPF_SYSCALLS_SLOT_CNT; slot++ ) {
    if( syscall_used[ slot>>6 ] & (1UL<<( slot&63UL )) ) {
      PUSH( FD_TRANSPILER_SYM_KIND_SYSCALL, slot, Dst->dasm_lbl_sys0+slot );
    }
  }
# undef PUSH
  for( ulong g=0UL; g<(ulong)fd_xlat__MAX; g++ ) {
    void * addr = Dst->glob[ g ];
    if( !addr ) continue; /* not emitted (e.g. callx) */
    ulong ofs = (ulong)( (uchar *)addr - Dst->code );
    if( ofs>=code_sz || cnt>=FD_TRANSPILER_SYM_MAX ) continue;
    Dst->sym[ cnt++ ] = (fd_transpiler_sym_t){ .off=(uint)ofs, .arg=(uint)g, .kind=FD_TRANSPILER_SYM_KIND_HELPER };
  }

  sym_sort_inplace( Dst->sym, cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong end = i+1UL<cnt ? Dst->sym[ i+1UL ].off : code_sz;
    Dst->sym[ i ].sz = (uint)( end - Dst->sym[ i ].off );
  }
  Dst->sym_cnt = cnt;
}

char const *
fd_transpiler_helper_name( ulong idx ) {
  if( FD_UNLIKELY( idx>=(ulong)fd_xlat__MAX ) ) return NULL;
  return fd_xlat_names[ idx ];
}

static void
fd_transpiler_init( fd_transpiler_t * Dst,
                    ulong             bpf_text_cnt ) {
  memset( Dst, 0, sizeof(fd_transpiler_t) ); /* ~10 MiB :( */
  Dst->bpf_text_cnt = bpf_text_cnt;
  Dst->reloc_cnt    = 0UL;

  /* Segment DynASM label indices by use case */
  ulong dasm_lbl = bpf_text_cnt;

  /* each instruction might be a call destination, which needs a thunk */
  Dst->dasm_lbl_thunk0 = dasm_lbl;
  dasm_lbl += bpf_text_cnt;

  /* up to one thunk for each syscall descriptor */
  Dst->dasm_lbl_sys0 = dasm_lbl;
  dasm_lbl += FD_SBPF_SYSCALLS_SLOT_CNT;

  /* end of instruction stream */
  dasm_lbl++;
  /* relocations */
  Dst->dasm_lbl_reloc0 = FD_VM_TRANSPILE_DASM_LBL_RELOC0( bpf_text_cnt );
  FD_TEST( dasm_lbl==Dst->dasm_lbl_reloc0 );
  dasm_lbl = Dst->dasm_lbl_reloc0 + FD_TRANSPILER_RELOC_MAX;

  Dst->dasm_lbl_max = dasm_lbl;
  FD_TEST( dasm_lbl<=FD_DASM_PCLABELS_MAX );

  dasm_State * D = Dst->state = (dasm_State *)Dst->state_;
  D->psize       = sizeof(Dst->state_);
  D->actionlist  = actions;
  D->lglabels    = Dst->lglabels;
  D->lgsize      = sizeof(Dst->lglabels);
  D->pclabels    = Dst->pclabels;
  D->pcsize      = sizeof(Dst->pclabels);
  D->globals     = Dst->glob;
  D->section     = &D->sections[0];
  D->codesize    = 0UL;
  D->maxsection  = 1;
  D->status      = DASM_S_OK;
  D->sections[0] = (dasm_Section) {
    .buf   = Dst->code_bits,
    .rbuf  = Dst->code_bits - DASM_SEC2POS( 0 ),
    .bsize = sizeof(Dst->code_bits),
    .pos   = DASM_SEC2POS( 0 ),
    .epos  = (int)( sizeof(Dst->code_bits) / sizeof(int) ) - DASM_MAXSECPOS + DASM_POS2BIAS( DASM_SEC2POS( 0 ) ),
    .ofs   = 0
  };
}

int
fd_vm_transpile_code( fd_transpiler_t *          Dst,
                      ulong                      sbpf_version,
                      uchar const *              bpf_text,
                      ulong                      bpf_text_cnt,
                      ulong                      bpf_entry_pc,
                      ulong const *              bpf_calldests,
                      fd_sbpf_syscalls_t const * syscalls,
                      uchar const *              bpf_rodata,
                      ulong                      bpf_rodata_sz,
                      ulong                      bpf_text_off ) {

  int is_oom = setjmp( dasm_oom );
  if( FD_UNLIKELY( is_oom ) ) return -1;

  if( FD_UNLIKELY( sbpf_version!=0 && sbpf_version!=1 && sbpf_version!=3 ) ) {
    FD_LOG_WARNING(( "sBPF v%lu programs are not supported", sbpf_version ));
    return -1;
  }
  if( FD_UNLIKELY( bpf_text_cnt>FD_TRANSPILER_TEXT_CNT_MAX ) ) {
    FD_LOG_WARNING(( "program too large (%lu instruction slots, max %lu)", bpf_text_cnt, FD_TRANSPILER_TEXT_CNT_MAX ));
    return -1;
  }

  fd_transpiler_init( Dst, bpf_text_cnt );

  /* The basic block bitmap is the first rodata table */
  ulong   bb_word_cnt   = (bpf_text_cnt+63UL)>>6;
  ulong * bpf_bb_splits = (ulong *)Dst->rodata;
  Dst->bb_cnt = bb_splits_compute( bpf_bb_splits, sbpf_version, (ulong const *)bpf_text, bpf_text_cnt, bpf_entry_pc, bpf_calldests, bpf_rodata, bpf_rodata_sz, bpf_text_off );
  if( FD_UNLIKELY( Dst->bb_cnt>FD_TRANSPILER_BB_MAX ) ) {
    FD_LOG_WARNING(( "program too large (%lu basic blocks, max %lu)", Dst->bb_cnt, FD_TRANSPILER_BB_MAX ));
    return -1;
  }
  ulong rodata_sz = 2UL*bb_word_cnt*sizeof(ulong) + Dst->bb_cnt*sizeof(int);
  if( FD_UNLIKELY( rodata_sz>FD_TRANSPILER_RODATA_MAX ) ) {
    FD_LOG_WARNING(( "program too large (%lu rodata bytes, max %lu)", rodata_sz, FD_TRANSPILER_RODATA_MAX ));
    return -1;
  }

  //|.code
  dasm_put(Dst, 2886);
#line 958 "fd_transpile_x86.dasc"
  //| cmp qword [rdi+offsetof(fd_vm_t, cu)], 0
  //| jns >1
  //| mov eax, FD_VM_ERR_INVAL
  //| ret
  //|1:
  //| // root stack frame:
  //| //   [rbp+ 8]: return address (C caller)
  //| //   [rbp+ 0]: caller rbp
  //| //   [rbp- 8]: root frame pointer (self)
  //| //   [rbp-16..rbp-48]: callee-saved rbx, r12, r13, r14, r15
  //| //   [rbp-56]: CET shadow stack pointer at entry, 0 if disabled
  //| //   [rbp-64]: alignment pad
  //| push rbp
  //| mov rbp, rsp
  //| push rbp
  //| push rbx
  //| push r12
  //| push r13
  //| push r14
  //| push r15
  //| xor ecx, ecx
  //| .byte 0xf3, 0x48, 0x0f, 0x1e, 0xc9 // rdsspq rcx (nop if shadow stack off)
  //| push rcx
  //| sub rsp, 8 // psABI 16 byte align
  //| mov r12, rdi
  //| // initial transpiled CU state
  //| cu_restore
  //| // initial transpiled MMU state
  //| mmu_tlb_invalidate
  //| // initial transpiled lazy stack state
  //| mov rdi, vm->stack_clean
  //| shr rdi, 12
  //| mov vm->transpiled.frame_clean_cnt, rdi
  //| mov r15, vm->frame_cnt
  //| frame_haddr_update
  //| // initial transpiled register state
  //| call ->regs_restore
  //| // zero-init current frame if needed
  //| cmp r15, vm->transpiled.frame_clean_cnt
  //| jb >1
  //| call ->bpfcall_frame_init
  dasm_put(Dst, 2888, offsetof(fd_vm_t, cu), FD_VM_ERR_INVAL, Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->stack_clean), Dt1(->transpiled.frame_clean_cnt), Dt1(->frame_cnt), Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.frame_clean_cnt));
#line 999 "fd_transpile_x86.dasc"
  //|1:
  //| // enter the entrypoint function with a regular sBPF function frame
  //| // (program exit unwinds to the root frame, so the call never returns)
  //| call >2
  //| .byte 0x0f, 0x0b // ud2
  //|2:
  //| sbpf_frame_enter
  //| sub rsp, 8
  //| jmp =>bpf_entry_pc
  dasm_put(Dst, 3023, bpf_entry_pc);
#line 1008 "fd_transpile_x86.dasc"

  static uchar const bpf_x86_reg[] = {
    /* r0  - rax */  0U,
    /* r1  - rsi */  6U,
    /* r2  - rdx */  2U,
    /* r3  - rcx */  1U,
    /* r4  - r8  */  8U,
    /* r5  - r9  */  9U,
    /* r6  - r10 */ 10U,
    /* r7  - r11 */ 11U,
    /* r8  - rbx */  3U,
    /* r9  - r13 */ 13U,
    /* r10 - r14 */ 14U
  };

  /* Translate all instructions in a single pass */

  int   has_callx = 0;
  ulong bb_start  = 0UL; /* first pc of the block being translated */
  ulong bb_lddw   = 0UL; /* LDDW count in the block so far (2 slots, 1 CU each) */
  ulong syscall_used[ FD_SBPF_SYSCALLS_SLOT_CNT >> 6 ] = {0};

  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    ulong instr   = FD_LOAD( ulong, bpf_text + (pc<<3) );
    ulong opcode  = fd_vm_instr_opcode( instr );
    ulong dst     = fd_vm_instr_dst   ( instr );
    ulong src     = fd_vm_instr_src   ( instr );
    uint  imm     = fd_vm_instr_imm   ( instr );
    long  offset  = (long)fd_vm_instr_offset( instr );
    if( FD_UNLIKELY( dst>=11UL || src>=11UL ) ) {
      FD_LOG_WARNING(( "invalid register at pc %lu", pc ));
      return -1;
    }
    uchar x86_dst = bpf_x86_reg[ dst ];
    uchar x86_src = bpf_x86_reg[ src ];

    if( bpf_bb_splits[ pc>>6 ] & (1UL<<( pc&63UL )) ) {
      if( pc>bb_start ) {
        //| cu_charge (pc-bb_start-bb_lddw)
        dasm_put(Dst, 3055, Dt1(->cu), (pc-bb_start-bb_lddw));
#line 1047 "fd_transpile_x86.dasc"
      }
      bb_start = pc;
      bb_lddw  = 0UL;
    }
    //|=>pc:
    dasm_put(Dst, 344, pc);
#line 1052 "fd_transpile_x86.dasc"

    int is_branch = ( ( (opcode&7UL)==5UL ) |
                      ( (opcode&7UL)==6UL ) ) &
                    ( opcode!=0x85UL ) &
                    ( opcode!=0x8dUL );
    if( is_branch ) {
      //| cu_charge (pc+1UL-bb_start-bb_lddw)
      dasm_put(Dst, 3055, Dt1(->cu), (pc+1UL-bb_start-bb_lddw));
#line 1059 "fd_transpile_x86.dasc"
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
    }

    if( (opcode&7UL)==6UL && !FD_VM_SBPF_ENABLE_JMP32( sbpf_version ) ) {
      FD_LOG_WARNING(( "invalid opcode 0x%02lx at pc %lu", opcode, pc ));
      return -1;
    }

    if( is_branch && opcode!=0x95UL ) {
      long jmp_dst = (long)pc + 1L + offset;
      if( FD_UNLIKELY( jmp_dst<0L || jmp_dst>=(long)bpf_text_cnt ||
                       fd_vm_instr_opcode( FD_LOAD( ulong, bpf_text + (jmp_dst<<3) ) )==0x00UL ) ) {
        FD_LOG_WARNING(( "invalid jump target at pc %lu", pc ));
        return -1;
      }
    }

    switch( opcode ) {

    /* Memory accesses */

    case 0x18: { /* LDDW */
      pc++;
      bb_lddw++;
      ulong ins1 = FD_LOAD( ulong, bpf_text + (pc<<3) );
      ulong imm64 = (ulong)imm | ((ulong)fd_vm_instr_imm( ins1 ) << 32);
      emit_const64( Dst, x86_dst, imm64 );
      break;
    }
    case 0x61: /* LDXW */
      if( is_stack_frame_access( sbpf_version, src, offset, 4 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov Rd(x86_dst), [r15+offset]
        dasm_put(Dst, 3067, Dt1(->transpiled.frame_haddr), (x86_dst), offset);
#line 1093 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_src)+offset]
        //| call ->mmu_translate_ld_4
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov Rd(x86_dst), [r15]
        dasm_put(Dst, 3081, (x86_src), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_dst));
#line 1098 "fd_transpile_x86.dasc"
      }
      break;
    case 0x69: /* LDXH */
      if( is_stack_frame_access( sbpf_version, src, offset, 2 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| movzx Rd(x86_dst), word [r15+offset]
        dasm_put(Dst, 3099, Dt1(->transpiled.frame_haddr), (x86_dst), offset);
#line 1104 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_src)+offset]
        //| call ->mmu_translate_ld_2
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| movzx Rd(x86_dst), word [r15]
        dasm_put(Dst, 3114, (x86_src), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_dst));
#line 1109 "fd_transpile_x86.dasc"
      }
      break;
    case 0x71: /* LDXB */
      if( is_stack_frame_access( sbpf_version, src, offset, 1 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| movzx Rd(x86_dst), byte [r15+offset]
        dasm_put(Dst, 3133, Dt1(->transpiled.frame_haddr), (x86_dst), offset);
#line 1115 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_src)+offset]
        //| call ->mmu_translate_ld_1
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| movzx Rd(x86_dst), byte [r15]
        dasm_put(Dst, 3148, (x86_src), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_dst));
#line 1120 "fd_transpile_x86.dasc"
      }
      break;
    case 0x79: /* LDXDW */
      if( is_stack_frame_access( sbpf_version, src, offset, 8 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov Rq(x86_dst), [r15+offset]
        dasm_put(Dst, 3167, Dt1(->transpiled.frame_haddr), (x86_dst), offset);
#line 1126 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_src)+offset]
        //| call ->mmu_translate_ld_8
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov Rq(x86_dst), [r15]
        dasm_put(Dst, 3181, (x86_src), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_dst));
#line 1131 "fd_transpile_x86.dasc"
      }
      break;

    /* Memory store */

    case 0x62: /* STW */
      if( is_stack_frame_access( sbpf_version, dst, offset, 4 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov dword [r15+offset], imm
        dasm_put(Dst, 3199, Dt1(->transpiled.frame_haddr), offset, imm);
#line 1140 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_4
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov dword [r15], imm
        dasm_put(Dst, 3211, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), imm);
#line 1145 "fd_transpile_x86.dasc"
      }
      break;
    case 0x63: /* STXW */
      if( is_stack_frame_access( sbpf_version, dst, offset, 4 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov [r15+offset], Rd(x86_src)
        dasm_put(Dst, 3228, Dt1(->transpiled.frame_haddr), (x86_src), offset);
#line 1151 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_4
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov [r15], Rd(x86_src)
        dasm_put(Dst, 3242, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_src));
#line 1156 "fd_transpile_x86.dasc"
      }
      break;
    case 0x6a: /* STH */
      if( is_stack_frame_access( sbpf_version, dst, offset, 2 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov word [r15+offset], (ushort)imm
        dasm_put(Dst, 3260, Dt1(->transpiled.frame_haddr), offset, (ushort)imm);
#line 1162 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_2
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov word [r15], (ushort)imm
        dasm_put(Dst, 3273, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (ushort)imm);
#line 1167 "fd_transpile_x86.dasc"
      }
      break;
    case 0x6b: /* STXH */
      if( is_stack_frame_access( sbpf_version, dst, offset, 2 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov [r15+offset], Rw(x86_src)
        dasm_put(Dst, 3291, Dt1(->transpiled.frame_haddr), (x86_src), offset);
#line 1173 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_2
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov [r15], Rw(x86_src)
        dasm_put(Dst, 3306, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_src));
#line 1178 "fd_transpile_x86.dasc"
      }
      break;
    case 0x72: /* STB */
      if( is_stack_frame_access( sbpf_version, dst, offset, 1 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov byte [r15+offset], (uchar)imm
        dasm_put(Dst, 3325, Dt1(->transpiled.frame_haddr), offset, (uchar)imm);
#line 1184 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_1
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov byte [r15], (uchar)imm
        dasm_put(Dst, 3337, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (uchar)imm);
#line 1189 "fd_transpile_x86.dasc"
      }
      break;
    case 0x73: /* STXB */
      if( is_stack_frame_access( sbpf_version, dst, offset, 1 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov [r15+offset], Rb(x86_src)
        dasm_put(Dst, 3354, Dt1(->transpiled.frame_haddr), (x86_src), offset);
#line 1195 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_1
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov [r15], Rb(x86_src)
        dasm_put(Dst, 3368, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_src));
#line 1200 "fd_transpile_x86.dasc"
      }
      break;
    case 0x7a: /* STDW */
      if( is_stack_frame_access( sbpf_version, dst, offset, 8 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov qword [r15+offset], (int)imm
        dasm_put(Dst, 3386, Dt1(->transpiled.frame_haddr), offset, (int)imm);
#line 1206 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_8
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov qword [r15], (int)imm
        dasm_put(Dst, 3398, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (int)imm);
#line 1211 "fd_transpile_x86.dasc"
      }
      break;
    case 0x7b: /* STXDW */
      if( is_stack_frame_access( sbpf_version, dst, offset, 8 ) ) {
        //| mov r15, vm->transpiled.frame_haddr
        //| mov [r15+offset], Rq(x86_src)
        dasm_put(Dst, 3415, Dt1(->transpiled.frame_haddr), (x86_src), offset);
#line 1217 "fd_transpile_x86.dasc"
      } else {
        //| lea r15, [Rq(x86_dst)+offset]
        //| call ->mmu_translate_st_8
        //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
        //| mov [r15], Rq(x86_src)
        dasm_put(Dst, 3429, (x86_dst), offset, (uint)(pc+1UL-bb_start-bb_lddw), (x86_src));
#line 1222 "fd_transpile_x86.dasc"
      }
      break;

    /* ALU */

    case 0x04: /* ADD32_IMM */
      //| add Rd(x86_dst), imm
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3447, (x86_dst), imm, (x86_dst), (x86_dst));
#line 1230 "fd_transpile_x86.dasc"
      break;
    case 0x07: /* ADD64_IMM */
      //| add Rq(x86_dst), (int)imm
      dasm_put(Dst, 3461, (x86_dst), (int)imm);
#line 1233 "fd_transpile_x86.dasc"
      break;
    case 0x0c: /* ADD32_REG */
      //| add Rd(x86_dst), Rd(x86_src)
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3468, (x86_src), (x86_dst), (x86_dst), (x86_dst));
#line 1237 "fd_transpile_x86.dasc"
      break;
    case 0x0f: /* ADD64_REG */
      //| add Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3483, (x86_src), (x86_dst));
#line 1240 "fd_transpile_x86.dasc"
      break;
    case 0x14: /* SUB32_IMM */
      //| sub Rd(x86_dst), imm
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3491, (x86_dst), imm, (x86_dst), (x86_dst));
#line 1244 "fd_transpile_x86.dasc"
      break;
    case 0x17: /* SUB64_IMM */
      //| sub Rq(x86_dst), (int)imm
      dasm_put(Dst, 3505, (x86_dst), (int)imm);
#line 1247 "fd_transpile_x86.dasc"
      break;
    case 0x1c: /* SUB32_REG */
      //| sub Rd(x86_dst), Rd(x86_src)
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3512, (x86_src), (x86_dst), (x86_dst), (x86_dst));
#line 1251 "fd_transpile_x86.dasc"
      break;
    case 0x1f: /* SUB64_REG */
      //| sub Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3527, (x86_src), (x86_dst));
#line 1254 "fd_transpile_x86.dasc"
      break;
    case 0x24: /* MUL32_IMM */
      //| imul Rd(x86_dst), Rd(x86_dst), imm
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3535, (x86_dst), (x86_dst), imm, (x86_dst), (x86_dst));
#line 1258 "fd_transpile_x86.dasc"
      break;
    case 0x27: /* MUL64_IMM */
      //| imul Rq(x86_dst), Rq(x86_dst), (int)imm
      dasm_put(Dst, 3551, (x86_dst), (x86_dst), (int)imm);
#line 1261 "fd_transpile_x86.dasc"
      break;
    case 0x2c: /* MUL32_REG */
      //| imul Rd(x86_dst), Rd(x86_src)
      //| movsxd Rq(x86_dst), Rd(x86_dst)
      dasm_put(Dst, 3560, (x86_dst), (x86_src), (x86_dst), (x86_dst));
#line 1265 "fd_transpile_x86.dasc"
      break;
    case 0x2f: /* MUL64_REG */
      //| imul Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3576, (x86_dst), (x86_src));
#line 1268 "fd_transpile_x86.dasc"
      break;
    case 0x34: /* DIV32_IMM */
      if( dst!=0UL ) {
        //| mov [rsp+0], rax
        dasm_put(Dst, 3585);
#line 1272 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp+8], rdx
        dasm_put(Dst, 3590);
#line 1275 "fd_transpile_x86.dasc"
      }
      //| mov eax, Rd(x86_dst)
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      dasm_put(Dst, 3596, (x86_dst), imm);
#line 1280 "fd_transpile_x86.dasc"
      if( dst==2UL ) {
        //| mov edx, eax
        dasm_put(Dst, 3610);
#line 1282 "fd_transpile_x86.dasc"
      } else if( dst!=0UL ) {
        //| mov Rd(x86_dst), eax
        dasm_put(Dst, 3613, (x86_dst));
#line 1284 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp+0]
        dasm_put(Dst, 3619);
#line 1287 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp+8]
        dasm_put(Dst, 3624);
#line 1290 "fd_transpile_x86.dasc"
      }
      break;
    case 0x37: { /* DIV64_IMM */
      ulong imm64 = (ulong)(long)(int)imm;
      if( dst!=0UL ) {
        //| mov [rsp+0], rax
        dasm_put(Dst, 3585);
#line 1296 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp+8], rdx
        dasm_put(Dst, 3590);
#line 1299 "fd_transpile_x86.dasc"
      }
      //| mov rax, Rq(x86_dst)
      //| xor edx, edx
      dasm_put(Dst, 3630, (x86_dst));
#line 1302 "fd_transpile_x86.dasc"
      emit_const64( Dst, 7U, imm64 );
      //| div rdi
      dasm_put(Dst, 3638);
#line 1304 "fd_transpile_x86.dasc"
      if( dst==2UL ) {
        //| mov rdx, rax
        dasm_put(Dst, 3644);
#line 1306 "fd_transpile_x86.dasc"
      } else if( dst!=0UL ) {
        //| mov Rq(x86_dst), rax
        dasm_put(Dst, 3648, (x86_dst));
#line 1308 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp+0]
        dasm_put(Dst, 3619);
#line 1311 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp+8]
        dasm_put(Dst, 3624);
#line 1314 "fd_transpile_x86.dasc"
      }
      break;
    }
    case 0x3c: /* DIV32_REG */
      //| mov edi, Rd(x86_src)
      //| test edi, edi
      //| jnz >1
      //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
      //| jmp ->exception_div_zero
      //|1:
      dasm_put(Dst, 3654, (x86_src), (uint)(pc+1UL-bb_start-bb_lddw));
#line 1324 "fd_transpile_x86.dasc"
      if( dst!=0UL ) {
        //| mov [rsp-16], rax
        dasm_put(Dst, 3675);
#line 1326 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp-8], rdx
        dasm_put(Dst, 3682);
#line 1329 "fd_transpile_x86.dasc"
      }
      //| mov eax, Rd(x86_dst)
      //| xor edx, edx
      //| div edi
      dasm_put(Dst, 3689, (x86_dst));
#line 1333 "fd_transpile_x86.dasc"
      if( dst==2UL ) {
        //| mov edx, eax
        dasm_put(Dst, 3610);
#line 1335 "fd_transpile_x86.dasc"
      } else if( dst!=0UL ) {
        //| mov Rd(x86_dst), eax
        dasm_put(Dst, 3613, (x86_dst));
#line 1337 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp-16]
        dasm_put(Dst, 3701);
#line 1340 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp-8]
        dasm_put(Dst, 3708);
#line 1343 "fd_transpile_x86.dasc"
      }
      break;
    case 0x3f: /* DIV64_REG */
      //| mov rdi, Rq(x86_src)
      //| test rdi, rdi
      //| jnz >1
      //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
      //| jmp ->exception_div_zero
      //|1:
      dasm_put(Dst, 3715, (x86_src), (uint)(pc+1UL-bb_start-bb_lddw));
#line 1352 "fd_transpile_x86.dasc"
      if( dst!=0UL ) {
        //| mov [rsp-16], rax
        dasm_put(Dst, 3675);
#line 1354 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp-8], rdx
        dasm_put(Dst, 3682);
#line 1357 "fd_transpile_x86.dasc"
      }
      //| mov rax, Rq(x86_dst)
      //| xor edx, edx
      //| div rdi
      dasm_put(Dst, 3737, (x86_dst));
#line 1361 "fd_transpile_x86.dasc"
      if( dst==2UL ) {
        //| mov rdx, rax
        dasm_put(Dst, 3644);
#line 1363 "fd_transpile_x86.dasc"
      } else if( dst!=0UL ) {
        //| mov Rq(x86_dst), rax
        dasm_put(Dst, 3648, (x86_dst));
#line 1365 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp-16]
        dasm_put(Dst, 3701);
#line 1368 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp-8]
        dasm_put(Dst, 3708);
#line 1371 "fd_transpile_x86.dasc"
      }
      break;
    case 0x44: /* OR32_IMM */
      //| or Rd(x86_dst), imm
      dasm_put(Dst, 3750, (x86_dst), imm);
#line 1375 "fd_transpile_x86.dasc"
      break;
    case 0x47: /* OR64_IMM */
      //| or Rq(x86_dst), (int)imm
      dasm_put(Dst, 3757, (x86_dst), (int)imm);
#line 1378 "fd_transpile_x86.dasc"
      break;
    case 0x4c: /* OR32_REG */
      //| or Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3764, (x86_src), (x86_dst));
#line 1381 "fd_transpile_x86.dasc"
      break;
    case 0x4f: /* OR64_REG */
      //| or Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3772, (x86_src), (x86_dst));
#line 1384 "fd_transpile_x86.dasc"
      break;
    case 0x54: /* AND32_IMM */
      //| and Rd(x86_dst), imm
      dasm_put(Dst, 3780, (x86_dst), imm);
#line 1387 "fd_transpile_x86.dasc"
      break;
    case 0x57: /* AND64_IMM */
      //| and Rq(x86_dst), (int)imm
      dasm_put(Dst, 3787, (x86_dst), (int)imm);
#line 1390 "fd_transpile_x86.dasc"
      break;
    case 0x5c: /* AND32_REG */
      //| and Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3794, (x86_src), (x86_dst));
#line 1393 "fd_transpile_x86.dasc"
      break;
    case 0x5f: /* AND64_REG */
      //| and Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3802, (x86_src), (x86_dst));
#line 1396 "fd_transpile_x86.dasc"
      break;
    case 0x64: /* LSH32_IMM */
      //| shl Rd(x86_dst), imm
      dasm_put(Dst, 3810, (x86_dst), imm);
#line 1399 "fd_transpile_x86.dasc"
      break;
    case 0x67: /* LSH64_IMM */
      //| shl Rq(x86_dst), imm
      dasm_put(Dst, 3817, (x86_dst), imm);
#line 1402 "fd_transpile_x86.dasc"
      break;
    case 0x6c: /* LSH32_REG */
      //| shlx Rd(x86_dst), Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3824, (x86_src), (x86_dst), (x86_dst));
#line 1405 "fd_transpile_x86.dasc"
      break;
    case 0x6f: /* LSH64_REG */
      //| shlx Rq(x86_dst), Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3837, (x86_src), (x86_dst), (x86_dst));
#line 1408 "fd_transpile_x86.dasc"
      break;
    case 0x74: /* RSH32_IMM */
      //| shr Rd(x86_dst), imm
      dasm_put(Dst, 3851, (x86_dst), imm);
#line 1411 "fd_transpile_x86.dasc"
      break;
    case 0x77: /* RSH64_IMM */
      //| shr Rq(x86_dst), imm
      dasm_put(Dst, 3858, (x86_dst), imm);
#line 1414 "fd_transpile_x86.dasc"
      break;
    case 0x7c: /* RSH32_REG */
      //| shrx Rd(x86_dst), Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3865, (x86_src), (x86_dst), (x86_dst));
#line 1417 "fd_transpile_x86.dasc"
      break;
    case 0x7f: /* RSH64_REG */
      //| shrx Rq(x86_dst), Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3878, (x86_src), (x86_dst), (x86_dst));
#line 1420 "fd_transpile_x86.dasc"
      break;
    case 0x84: /* NEG32 */
      //| neg Rd(x86_dst)
      dasm_put(Dst, 3892, (x86_dst));
#line 1423 "fd_transpile_x86.dasc"
      break;
    case 0x87: /* NEG64 */
      //| neg Rq(x86_dst)
      dasm_put(Dst, 3899, (x86_dst));
#line 1426 "fd_transpile_x86.dasc"
      break;
    case 0x97: { /* MOD64_IMM */
      ulong imm64 = (ulong)(long)(int)imm;
      if( dst!=0UL ) {
        //| mov [rsp+0], rax
        dasm_put(Dst, 3585);
#line 1431 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp+8], rdx
        dasm_put(Dst, 3590);
#line 1434 "fd_transpile_x86.dasc"
      }
      //| mov rax, Rq(x86_dst)
      //| xor edx, edx
      dasm_put(Dst, 3630, (x86_dst));
#line 1437 "fd_transpile_x86.dasc"
      emit_const64( Dst, 7U, imm64 );
      //| div rdi
      dasm_put(Dst, 3638);
#line 1439 "fd_transpile_x86.dasc"
      if( dst==0UL ) {
        //| mov rax, rdx
        dasm_put(Dst, 3906);
#line 1441 "fd_transpile_x86.dasc"
      } else if( dst!=2UL ) {
        //| mov Rq(x86_dst), rdx
        dasm_put(Dst, 3910, (x86_dst));
#line 1443 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp+0]
        dasm_put(Dst, 3619);
#line 1446 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp+8]
        dasm_put(Dst, 3624);
#line 1449 "fd_transpile_x86.dasc"
      }
      break;
    }
    case 0x9f: /* MOD64_REG */
      //| mov rdi, Rq(x86_src)
      //| test rdi, rdi
      //| jnz >1
      //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
      //| jmp ->exception_div_zero
      //|1:
      dasm_put(Dst, 3715, (x86_src), (uint)(pc+1UL-bb_start-bb_lddw));
#line 1459 "fd_transpile_x86.dasc"
      if( dst!=0UL ) {
        //| mov [rsp-16], rax
        dasm_put(Dst, 3675);
#line 1461 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp-8], rdx
        dasm_put(Dst, 3682);
#line 1464 "fd_transpile_x86.dasc"
      }
      //| mov rax, Rq(x86_dst)
      //| xor edx, edx
      //| div rdi
      dasm_put(Dst, 3737, (x86_dst));
#line 1468 "fd_transpile_x86.dasc"
      if( dst==0UL ) {
        //| mov rax, rdx
        dasm_put(Dst, 3906);
#line 1470 "fd_transpile_x86.dasc"
      } else if( dst!=2UL ) {
        //| mov Rq(x86_dst), rdx
        dasm_put(Dst, 3910, (x86_dst));
#line 1472 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp-16]
        dasm_put(Dst, 3701);
#line 1475 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp-8]
        dasm_put(Dst, 3708);
#line 1478 "fd_transpile_x86.dasc"
      }
      break;
    case 0x94: /* MOD32_IMM */
      if( dst!=0UL ) {
        //| mov [rsp+0], rax
        dasm_put(Dst, 3585);
#line 1483 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp+8], rdx
        dasm_put(Dst, 3590);
#line 1486 "fd_transpile_x86.dasc"
      }
      //| mov eax, Rd(x86_dst)
      //| xor edx, edx
      //| mov edi, imm
      //| div edi
      dasm_put(Dst, 3596, (x86_dst), imm);
#line 1491 "fd_transpile_x86.dasc"
      if( dst==0UL ) {
        //| mov eax, edx
        dasm_put(Dst, 3907);
#line 1493 "fd_transpile_x86.dasc"
      } else if( dst!=2UL ) {
        //| mov Rd(x86_dst), edx
        dasm_put(Dst, 3916, (x86_dst));
#line 1495 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp+0]
        dasm_put(Dst, 3619);
#line 1498 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp+8]
        dasm_put(Dst, 3624);
#line 1501 "fd_transpile_x86.dasc"
      }
      break;
    case 0x9c: /* MOD32_REG */
      //| mov edi, Rd(x86_src)
      //| test edi, edi
      //| jnz >1
      //| mov edi, (uint)(pc+1UL-bb_start-bb_lddw)
      //| jmp ->exception_div_zero
      //|1:
      dasm_put(Dst, 3654, (x86_src), (uint)(pc+1UL-bb_start-bb_lddw));
#line 1510 "fd_transpile_x86.dasc"
      if( dst!=0UL ) {
        //| mov [rsp-16], rax
        dasm_put(Dst, 3675);
#line 1512 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov [rsp-8], rdx
        dasm_put(Dst, 3682);
#line 1515 "fd_transpile_x86.dasc"
      }
      //| mov eax, Rd(x86_dst)
      //| xor edx, edx
      //| div edi
      dasm_put(Dst, 3689, (x86_dst));
#line 1519 "fd_transpile_x86.dasc"
      if( dst==0UL ) {
        //| mov eax, edx
        dasm_put(Dst, 3907);
#line 1521 "fd_transpile_x86.dasc"
      } else if( dst!=2UL ) {
        //| mov Rd(x86_dst), edx
        dasm_put(Dst, 3916, (x86_dst));
#line 1523 "fd_transpile_x86.dasc"
      }
      if( dst!=0UL ) {
        //| mov rax, [rsp-16]
        dasm_put(Dst, 3701);
#line 1526 "fd_transpile_x86.dasc"
      }
      if( dst!=2UL ) {
        //| mov rdx, [rsp-8]
        dasm_put(Dst, 3708);
#line 1529 "fd_transpile_x86.dasc"
      }
      break;
    case 0xa4: /* XOR32_IMM */
      //| xor Rd(x86_dst), imm
      dasm_put(Dst, 3922, (x86_dst), imm);
#line 1533 "fd_transpile_x86.dasc"
      break;
    case 0xa7: /* XOR64_IMM */
      //| xor Rq(x86_dst), (int)imm
      dasm_put(Dst, 3930, (x86_dst), (int)imm);
#line 1536 "fd_transpile_x86.dasc"
      break;
    case 0xac: /* XOR32_REG */
      //| xor Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3938, (x86_src), (x86_dst));
#line 1539 "fd_transpile_x86.dasc"
      break;
    case 0xaf: /* XOR64_REG */
      //| xor Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3946, (x86_src), (x86_dst));
#line 1542 "fd_transpile_x86.dasc"
      break;
    case 0xb4: /* MOV32_IMM */
      //| mov Rd(x86_dst), imm
      dasm_put(Dst, 2866, (x86_dst), imm);
#line 1545 "fd_transpile_x86.dasc"
      break;
    case 0xb7: { /* MOV64_IMM */
      if( !imm ) {
        //| xor Rd(x86_dst), Rd(x86_dst)
        dasm_put(Dst, 3938, (x86_dst), (x86_dst));
#line 1549 "fd_transpile_x86.dasc"
      } else {
        ulong imm64 = (ulong)(long)(int)imm;
        emit_const64( Dst, x86_dst, imm64 );
      }
      break;
    }
    case 0xbc: /* MOV32_REG */
      //| mov Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3954, (x86_src), (x86_dst));
#line 1557 "fd_transpile_x86.dasc"
      break;
    case 0xbf: /* MOV64_REG */
      //| mov Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3962, (x86_src), (x86_dst));
#line 1560 "fd_transpile_x86.dasc"
      break;
    case 0xc4: /* ARSH32_IMM */
      //| sar Rd(x86_dst), imm
      dasm_put(Dst, 3970, (x86_dst), imm);
#line 1563 "fd_transpile_x86.dasc"
      break;
    case 0xc7: /* ARSH64_IMM */
      //| sar Rq(x86_dst), imm
      dasm_put(Dst, 3978, (x86_dst), imm);
#line 1566 "fd_transpile_x86.dasc"
      break;
    case 0xcc: /* ARSH32_REG */
      //| sarx Rd(x86_dst), Rd(x86_dst), Rd(x86_src)
      dasm_put(Dst, 3986, (x86_src), (x86_dst), (x86_dst));
#line 1569 "fd_transpile_x86.dasc"
      break;
    case 0xcf: /* ARSH64_REG */
      //| sarx Rq(x86_dst), Rq(x86_dst), Rq(x86_src)
      dasm_put(Dst, 3999, (x86_src), (x86_dst), (x86_dst));
#line 1572 "fd_transpile_x86.dasc"
      break;
    case 0xd4: /* END_LE */
      if( imm==16U ) {
        //| movzx Rd(x86_dst), Rw(x86_dst)
        dasm_put(Dst, 4013, (x86_dst), (x86_dst));
#line 1576 "fd_transpile_x86.dasc"
      } else if( imm==32U ) {
        //| mov Rd(x86_dst), Rd(x86_dst)
        dasm_put(Dst, 3954, (x86_dst), (x86_dst));
#line 1578 "fd_transpile_x86.dasc"
      }
      break;
    case 0xdc: /* END_BE */
      if( imm==16U ) {
        //| rol Rw(x86_dst), 8
        //| movzx Rd(x86_dst), Rw(x86_dst)
        dasm_put(Dst, 4022, (x86_dst), (x86_dst), (x86_dst));
#line 1584 "fd_transpile_x86.dasc"
      } else if( imm==32U ) {
        //| bswap Rd(x86_dst)
        dasm_put(Dst, 4038, (x86_dst));
#line 1586 "fd_transpile_x86.dasc"
      } else {
        //| bswap Rq(x86_dst)
        dasm_put(Dst, 4044, (x86_dst));
#line 1588 "fd_transpile_x86.dasc"
      }
      break;

    /* Branches */

    case 0x05: /* JA */
      //| jmp =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 3051, ((ulong)((long)pc + 1L + offset)));
#line 1595 "fd_transpile_x86.dasc"
      break;
    case 0x15: /* JEQ_IMM */
      if( !imm ) {
        //| test Rq(x86_dst), Rq(x86_dst)
        dasm_put(Dst, 4050, (x86_dst), (x86_dst));
#line 1599 "fd_transpile_x86.dasc"
      } else {
        //| cmp Rq(x86_dst), (int)imm
        dasm_put(Dst, 4058, (x86_dst), (int)imm);
#line 1601 "fd_transpile_x86.dasc"
      }
      //| je =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4066, ((ulong)((long)pc + 1L + offset)));
#line 1603 "fd_transpile_x86.dasc"
      break;
    case 0x16: /* JEQ32_IMM */
      if( !imm ) {
        //| test Rd(x86_dst), Rd(x86_dst)
        dasm_put(Dst, 4070, (x86_dst), (x86_dst));
#line 1607 "fd_transpile_x86.dasc"
      } else {
        //| cmp Rd(x86_dst), (int)imm
        dasm_put(Dst, 4078, (x86_dst), (int)imm);
#line 1609 "fd_transpile_x86.dasc"
      }
      //| je =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4066, ((ulong)((long)pc + 1L + offset)));
#line 1611 "fd_transpile_x86.dasc"
      break;
    case 0x1d: /* JEQ_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| je =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4086, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1615 "fd_transpile_x86.dasc"
      break;
    case 0x1e: /* JEQ32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| je =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4097, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1619 "fd_transpile_x86.dasc"
      break;
    case 0x25: /* JGT_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| ja =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4108, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1623 "fd_transpile_x86.dasc"
      break;
    case 0x26: /* JGT32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| ja =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4119, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1627 "fd_transpile_x86.dasc"
      break;
    case 0x2d: /* JGT_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| ja =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4130, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1631 "fd_transpile_x86.dasc"
      break;
    case 0x2e: /* JGT32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| ja =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4141, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1635 "fd_transpile_x86.dasc"
      break;
    case 0x35: /* JGE_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jae =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4152, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1639 "fd_transpile_x86.dasc"
      break;
    case 0x36: /* JGE32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jae =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4163, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1643 "fd_transpile_x86.dasc"
      break;
    case 0x3d: /* JGE_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jae =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4174, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1647 "fd_transpile_x86.dasc"
      break;
    case 0x3e: /* JGE32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jae =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4185, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1651 "fd_transpile_x86.dasc"
      break;
    case 0x45: /* JSET_IMM */
      //| test Rq(x86_dst), (int)imm
      //| jnz =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4196, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1655 "fd_transpile_x86.dasc"
      break;
    case 0x46: /* JSET32_IMM */
      //| test Rd(x86_dst), (int)imm
      //| jnz =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4207, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1659 "fd_transpile_x86.dasc"
      break;
    case 0x4d: /* JSET_REG */
      //| test Rq(x86_dst), Rq(x86_src)
      //| jnz =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4218, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1663 "fd_transpile_x86.dasc"
      break;
    case 0x4e: /* JSET32_REG */
      //| test Rd(x86_dst), Rd(x86_src)
      //| jnz =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4229, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1667 "fd_transpile_x86.dasc"
      break;
    case 0x55: /* JNE_IMM */
      if( !imm ) {
        //| test Rq(x86_dst), Rq(x86_dst)
        dasm_put(Dst, 4050, (x86_dst), (x86_dst));
#line 1671 "fd_transpile_x86.dasc"
      } else {
        //| cmp Rq(x86_dst), (int)imm
        dasm_put(Dst, 4058, (x86_dst), (int)imm);
#line 1673 "fd_transpile_x86.dasc"
      }
      //| jne =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4203, ((ulong)((long)pc + 1L + offset)));
#line 1675 "fd_transpile_x86.dasc"
      break;
    case 0x56: /* JNE32_IMM */
      if( !imm ) {
        //| test Rd(x86_dst), Rd(x86_dst)
        dasm_put(Dst, 4070, (x86_dst), (x86_dst));
#line 1679 "fd_transpile_x86.dasc"
      } else {
        //| cmp Rd(x86_dst), (int)imm
        dasm_put(Dst, 4078, (x86_dst), (int)imm);
#line 1681 "fd_transpile_x86.dasc"
      }
      //| jne =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4203, ((ulong)((long)pc + 1L + offset)));
#line 1683 "fd_transpile_x86.dasc"
      break;
    case 0x5d: /* JNE_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jne =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4240, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1687 "fd_transpile_x86.dasc"
      break;
    case 0x5e: /* JNE32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jne =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4251, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1691 "fd_transpile_x86.dasc"
      break;
    case 0x65: /* JSGT_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jg =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4262, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1695 "fd_transpile_x86.dasc"
      break;
    case 0x66: /* JSGT32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jg =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4273, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1699 "fd_transpile_x86.dasc"
      break;
    case 0x6d: /* JSGT_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jg =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4284, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1703 "fd_transpile_x86.dasc"
      break;
    case 0x6e: /* JSGT32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jg =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4295, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1707 "fd_transpile_x86.dasc"
      break;
    case 0x75: /* JSGE_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jge =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4306, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1711 "fd_transpile_x86.dasc"
      break;
    case 0x76: /* JSGE32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jge =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4317, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1715 "fd_transpile_x86.dasc"
      break;
    case 0x7d: /* JSGE_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jge =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4328, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1719 "fd_transpile_x86.dasc"
      break;
    case 0x7e: /* JSGE32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jge =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4339, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1723 "fd_transpile_x86.dasc"
      break;
    case 0xa5: /* JLT_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jb =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4350, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1727 "fd_transpile_x86.dasc"
      break;
    case 0xa6: /* JLT32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jb =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4361, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1731 "fd_transpile_x86.dasc"
      break;
    case 0xad: /* JLT_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jb =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4372, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1735 "fd_transpile_x86.dasc"
      break;
    case 0xae: /* JLT32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jb =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4383, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1739 "fd_transpile_x86.dasc"
      break;
    case 0xb5: /* JLE_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jbe =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4394, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1743 "fd_transpile_x86.dasc"
      break;
    case 0xb6: /* JLE32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jbe =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4405, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1747 "fd_transpile_x86.dasc"
      break;
    case 0xbd: /* JLE_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jbe =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4416, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1751 "fd_transpile_x86.dasc"
      break;
    case 0xbe: /* JLE32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jbe =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4427, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1755 "fd_transpile_x86.dasc"
      break;
    case 0xc5: /* JSLT_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jl =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4438, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1759 "fd_transpile_x86.dasc"
      break;
    case 0xc6: /* JSLT32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jl =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4449, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1763 "fd_transpile_x86.dasc"
      break;
    case 0xcd: /* JSLT_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jl =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4460, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1767 "fd_transpile_x86.dasc"
      break;
    case 0xce: /* JSLT32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jl =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4471, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1771 "fd_transpile_x86.dasc"
      break;
    case 0xd5: /* JSLE_IMM */
      //| cmp Rq(x86_dst), (int)imm
      //| jle =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4482, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1775 "fd_transpile_x86.dasc"
      break;
    case 0xd6: /* JSLE32_IMM */
      //| cmp Rd(x86_dst), (int)imm
      //| jle =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4493, (x86_dst), (int)imm, ((ulong)((long)pc + 1L + offset)));
#line 1779 "fd_transpile_x86.dasc"
      break;
    case 0xdd: /* JSLE_REG */
      //| cmp Rq(x86_dst), Rq(x86_src)
      //| jle =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4504, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1783 "fd_transpile_x86.dasc"
      break;
    case 0xde: /* JSLE32_REG */
      //| cmp Rd(x86_dst), Rd(x86_src)
      //| jle =>((ulong)((long)pc + 1L + offset))
      dasm_put(Dst, 4515, (x86_src), (x86_dst), ((ulong)((long)pc + 1L + offset)));
#line 1787 "fd_transpile_x86.dasc"
      break;

    /* Call */

    case 0x85: { /* CALL_IMM (BPF call or syscall) */
      fd_sbpf_syscalls_t const * sys = NULL;
      long target_pc = -1L;
      if( FD_VM_SBPF_STATIC_SYSCALLS( sbpf_version ) ) {
        if( src==0UL ) {
          sys = fd_sbpf_syscalls_query_const( syscalls, imm, NULL );
        } else if( src==1UL ) {
          target_pc = (long)pc + (long)(int)imm + 1L;
          if( target_pc<0L || target_pc>=(long)bpf_text_cnt ) target_pc = -1L;
        }
      } else {
        sys = fd_sbpf_syscalls_query_const( syscalls, imm, NULL );
        if( !sys ) {
          if( imm==0x71e3cf81U ) { /* hash of "entrypoint" */
            target_pc = (long)bpf_entry_pc;
          } else {
            target_pc = (long)(ulong)fd_pchash_inverse( imm );
            if( target_pc>=(long)bpf_text_cnt ||
                !fd_sbpf_calldests_test( bpf_calldests, (ulong)target_pc ) ) {
              target_pc = -1L;
            }
          }
        }
      }
      //| cu_settle (pc+1UL-bb_start-bb_lddw)
      dasm_put(Dst, 4526, Dt1(->cu), (pc+1UL-bb_start-bb_lddw));
#line 1816 "fd_transpile_x86.dasc"
      if( sys ) {
        ulong slot_idx = (ulong)( sys-syscalls );
        syscall_used[ slot_idx >> 6 ] |= 1UL<<( slot_idx & 63UL );
        //| mov qword vm->pc, pc
        //| call =>(Dst->dasm_lbl_sys0 + slot_idx)
        dasm_put(Dst, 4534, Dt1(->pc), pc, (Dst->dasm_lbl_sys0 + slot_idx));
#line 1821 "fd_transpile_x86.dasc"
      } else if( target_pc>=0L ) {
        ulong tpc = (ulong)target_pc;
        if( fd_vm_instr_opcode( FD_LOAD( ulong, bpf_text + (tpc<<3) ) )==0x00UL ) {
          //| jmp ->exception_ill
          dasm_put(Dst, 4544);
#line 1825 "fd_transpile_x86.dasc"
        } else {
          Dst->thunk_bv[ tpc >> 6 ] |= 1UL<<( tpc & 63UL );
          //| mov qword vm->pc, pc
          //| call =>(Dst->dasm_lbl_thunk0 + tpc)
          dasm_put(Dst, 4534, Dt1(->pc), pc, (Dst->dasm_lbl_thunk0 + tpc));
#line 1829 "fd_transpile_x86.dasc"
        }
      } else {
        //| jmp ->exception_ill
        dasm_put(Dst, 4544);
#line 1832 "fd_transpile_x86.dasc"
      }
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
      break;
    }
    case 0x8d: /* CALLX */
      has_callx = 1;
      ulong callx_reg =
          FD_VM_SBPF_CALLX_USES_SRC_REG( sbpf_version ) ? src :
          FD_VM_SBPF_CALLX_USES_DST_REG( sbpf_version ) ? dst :
          (ulong)imm;
      if( FD_UNLIKELY( callx_reg>9UL ) ) {
        FD_LOG_WARNING(( "invalid callx register at pc %lu", pc ));
        return -1;
      }
      //| cu_settle (pc+1UL-bb_start-bb_lddw)
      //| mov qword vm->pc, pc
      //| mov r15, Rq(bpf_x86_reg[callx_reg])
      //| call ->callx
      dasm_put(Dst, 4549, Dt1(->cu), (pc+1UL-bb_start-bb_lddw), Dt1(->pc), pc, (bpf_x86_reg[callx_reg]));
#line 1851 "fd_transpile_x86.dasc"
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
      break;
    case 0x95: /* EXIT */
      //| jmp ->bpfcall_frame_pop
      dasm_put(Dst, 4572);
#line 1856 "fd_transpile_x86.dasc"
      break;

    default:
      FD_LOG_WARNING(( "invalid opcode 0x%02lx at pc %lu", opcode, pc ));
      return -1;
    }
  }

  /* Execution fell off the end of the text segment */
  if( bb_start<bpf_text_cnt ) {
    //| cu_charge (bpf_text_cnt-bb_start-bb_lddw)
    dasm_put(Dst, 3055, Dt1(->cu), (bpf_text_cnt-bb_start-bb_lddw));
#line 1867 "fd_transpile_x86.dasc"
  }
  //| call ->regs_save
  //| mov r15d, FD_VM_ERR_EBPF_EXECUTION_OVERRUN
  //| mov edi, 1 // bill 1 more CU before faulting
  //| jmp ->exception_charge
  //|=>(Dst->dasm_lbl_reloc0-1UL):
  dasm_put(Dst, 4577, FD_VM_ERR_EBPF_EXECUTION_OVERRUN, (Dst->dasm_lbl_reloc0-1UL));
#line 1873 "fd_transpile_x86.dasc"


  emit_mmu_routines( Dst );

  /* BPF-to-BPF call thunks */

  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    if( Dst->thunk_bv[ pc>>6 ] & (1UL<<( pc&63UL )) ) {
      //|=>(Dst->dasm_lbl_thunk0 + pc):
      //| sbpf_frame_enter
      //| sub rsp, 8
      //| call ->bpfcall_frame_push
      //| test r15d, r15d
      //| jnz ->call_imm_depth
      //| jmp =>pc
      dasm_put(Dst, 4594, (Dst->dasm_lbl_thunk0 + pc), pc);
#line 1888 "fd_transpile_x86.dasc"
    }
  }

  for( ulong word_idx=0UL; word_idx<(FD_SBPF_SYSCALLS_SLOT_CNT>>6); word_idx++ ) {
    ulong word = syscall_used[ word_idx ];
    while( word ) {
      int bit = fd_ulong_find_lsb( word );
      word &= ~(1UL<<bit);
      ulong slot_idx = (word_idx<<6) + (ulong)bit;
      //|=>(Dst->dasm_lbl_sys0 + slot_idx):
      dasm_put(Dst, 344, (Dst->dasm_lbl_sys0 + slot_idx));
#line 1898 "fd_transpile_x86.dasc"
      emit_syscall_call( Dst, slot_idx );
    }
  }

  emit_regs_subroutines( Dst );
  emit_frame_helpers( Dst );
  if( has_callx ) {
    emit_callx_handler( Dst );
  }

  /* Fault handlers */

  //|->exception_div_zero:
  //| // edi: CUs consumed by the current block so far (incl. this instr)
  //| call ->regs_save
  //| mov r15d, FD_VM_ERR_EBPF_DIVIDE_BY_ZERO
  //| jmp ->exception_charge
  dasm_put(Dst, 4626, FD_VM_ERR_EBPF_DIVIDE_BY_ZERO);
#line 1915 "fd_transpile_x86.dasc"

  //|->exception_segfault:
  //| // r15: negative FD_VM_ERR_EBPF_* code returned by mmu_tlb_miss
  //| // [rsp]: return address, followed by the memory access site's
  //| //        cost marker
  //| mov rdi, [rsp]
  //| mov edi, [rdi+1]
  //| call ->regs_save
  //| jmp ->exception_charge
  dasm_put(Dst, 4639);
#line 1924 "fd_transpile_x86.dasc"

  //|->exception_ill:
  //| // Call to an invalid target (the verifier does not check call
  //| // targets).  Block CUs were settled before the jump here.
  //| call ->regs_save
  //| mov r15d, FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION
  //| xor edi, edi
  //| jmp ->exception_charge
  dasm_put(Dst, 4656, FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION);
#line 1932 "fd_transpile_x86.dasc"

  //|->exception_cost:
  //| // Reached from cu_charge in the instruction stream when the CU
  //| // budget went negative.
  //| call ->regs_save
  //| mov r15d, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS
  //| xor edi, edi
  //| // fall through
  dasm_put(Dst, 4672, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS);
#line 1940 "fd_transpile_x86.dasc"

  //|->exception_charge:
  //| // Bills the pending block and unwinds.  Expects BPF registers to
  //| // be saved already.
  //| // - r15d: error code
  //| // - edi:  CUs consumed by the pending block so far
  //| sub vm->cu, rdi
  //| cu_save // ic counts everything, even if over budget
  //| cmp qword vm->cu, 0
  //| jge >1
  //| mov qword vm->cu, 0
  //| mov r15d, FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS
  //|1:
  //| mov esi, (FD_VM_STACK_FRAME_MAX-1)*48
  //| jmp ->unwind
  dasm_put(Dst, 4684, Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic), Dt1(->cu), Dt1(->cu), FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS, (FD_VM_STACK_FRAME_MAX-1)*48);
#line 1955 "fd_transpile_x86.dasc"

  //|->unwind:
  //| // - r15d: return value
  //| // - rbp:  any transpiled frame (sBPF function or root)
  //| mov rbp, [rbp-8] // root frame
  //| xor edx, edx
  //| .byte 0xf3, 0x48, 0x0f, 0x1e, 0xca // rdsspq rdx
  //| test rdx, rdx
  //| jz >1
  //| mov rcx, [rbp-56]
  //| sub rcx, rdx
  //| shr rcx, 3
  //| test ecx, ecx
  //| jz >1
  //| mov rax, rcx
  //| .byte 0xf3, 0x48, 0x0f, 0xae, 0xe8 // incsspq rax
  //|1:
  //| mov eax, r15d
  //| lea rsp, [rbp-48]
  //| pop r15
  //| pop r14
  //| pop r13
  //| pop r12
  //| pop rbx
  //| leave
  //| ret
  dasm_put(Dst, 4743);
#line 1981 "fd_transpile_x86.dasc"

  size_t code_sz;
  int link_res = dasm_link( Dst, &code_sz );
  if( link_res!=0 ) {
    FD_LOG_WARNING(( "dasm_link failed: %d", link_res ));
    return -1;
  }
  if( FD_UNLIKELY( code_sz > FD_TRANSPILER_CODE_MAX ) ) {
    FD_LOG_WARNING(( "transpiled code is too big: %lu bytes larger than FD_TRANSPILER_CODE_MAX", code_sz-FD_TRANSPILER_CODE_MAX ));
    return -1;
  }

  int enc_res = dasm_encode( Dst, Dst->code );
  if( enc_res!=0 ) {
    FD_LOG_WARNING(( "dasm_encode failed: %d", enc_res ));
    return -1;
  }

  /* Resolve relocation site labels to code offsets */
  for( ulong i=0UL; i<Dst->reloc_cnt; i++ ) {
    int ofs = dasm_getpclabel( Dst, (uint)( Dst->dasm_lbl_reloc0+i ) );
    if( FD_UNLIKELY( ofs<0 || (ulong)ofs+4UL>code_sz ) ) {
      FD_LOG_WARNING(( "failed to resolve relocation %lu site label (%d)", i, ofs ));
      return -1;
    }
    Dst->reloc[ i ].r_offset = (ulong)ofs;
  }

  /* Basic block tables (layout documented in fd_transpile.h) */
  ulong * seq     = bpf_bb_splits + bb_word_cnt;
  ulong   jmp_off = 2UL*bb_word_cnt*sizeof(ulong);
  ulong bb_idx = 0UL;
  for( ulong w=0UL; w<bb_word_cnt; w++ ) {
    seq[ w ] = bb_idx;
    ulong word = bpf_bb_splits[ w ];
    while( word ) {
      ulong pc = (w<<6) + (ulong)fd_ulong_find_lsb( word );
      word &= word-1UL;
      int ofs = dasm_getpclabel( Dst, (uint)pc );
      if( FD_UNLIKELY( ofs<0 || (ulong)ofs>=code_sz ) ) {
        FD_LOG_WARNING(( "failed to resolve basic block %lu label (%d)", pc, ofs ));
        return -1;
      }
      /* entry holds text+ofs relative to the table base */
      Dst->rodata_reloc[ bb_idx ] = (fd_elf64_rela){
        .r_offset = jmp_off + bb_idx*sizeof(int),
        .r_info   = FD_ELF64_R_INFO( FD_VM_TRANSPILE_SYM_TEXT, FD_ELF_R_X86_64_PC32 ),
        .r_addend = (long)( (ulong)ofs + bb_idx*sizeof(int) )
      };
      bb_idx++;
    }
  }
  Dst->rodata_reloc_cnt  = bb_idx;
  Dst->rodata_sz         = jmp_off + bb_idx*sizeof(int);

  Dst->code_sz           = (ulong)code_sz;
  Dst->entrypoint_off    = 0UL;
  syms_compute( Dst, bpf_text_cnt, bpf_entry_pc, bpf_calldests, syscall_used, (ulong)code_sz );
  Dst->meta.text_cnt     = bpf_text_cnt;
  Dst->meta.text_sz      = bpf_text_cnt * 8UL;
  Dst->meta.entry_pc     = bpf_entry_pc;
  Dst->meta.sbpf_version = sbpf_version;

  return 0;
}
