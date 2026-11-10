/*
** This file has been pre-processed with DynASM.
** https://luajit.org/dynasm.html
** DynASM version 1.5.0, DynASM arm version 1.5.0
** DO NOT EDIT! The original file is in "fd_transpile_arm64.dasc".
*/

#line 1 "fd_transpile_arm64.dasc"
/* fd_transpile_arm64.dasc translates sBPF v0, v1, and v3 programs to
   native AArch64 code.  It is the arm64 twin of fd_transpile_x86.dasc,
   which documents the overall design (basic blocks, CU budgeting, soft
   MMU, frames, bail, unwind).  Only the register assignment and the
   points where the two backends differ are described here.

   sBPF registers are assigned to arm64 registers as follows:

   BPF | r0 | r1 | r2 | r3 | r4 | r5 | r6  | r7  | r8  | r9  | r10
   arm | x0 | x1 | x2 | x3 | x4 | x5 | x20 | x21 | x22 | x23 | x24

   The remaining registers are used as follows:
   - x19: fd_vm_t context pointer
   - x29: frame pointer of the current sBPF function
   - x30: link register
   - sp:  stack pointer (used for the sBPF call stack)
   - x9, x10, x11, x12: scratch (x9 and x10 play the roles of rdi and
     r15 in the x86 backend: x9 carries block CU counts and C call
     arguments, x10 carries virtual/host addresses and error codes)
   - x16, x17: intra-procedure-call scratch (veneers)

   Note: Why this assignment?
   - BPF r0 and AAPCS64 x0 are both "return register 0"
   - BPF r1..r5 and AAPCS64 x1..x5 are the scalar syscall arguments
   - BPF r6..r10 are callee-saved across syscalls either way, so they
     live in callee-saved x20..x24 and survive C calls untouched

   Frames follow AAPCS64: every sBPF function invocation has a frame
   record at x29 ([x29] = caller x29, [x29+8] = return address) so
   frame pointer based unwinders see the sBPF call stack.  Each frame
   also holds the root frame pointer at [x29-8] (the root frame points
   to itself), and sBPF function bodies run with sp==x29-16.

   Branch Target Identification is not used: the only indirect branch
   in transpiled code is callx, which jumps to a basic block start
   looked up in a read-only table.

   Load/store immediates: AArch64 unsigned scaled offsets cover
   [0,4095*width] and unscaled signed offsets [-256,255].  sBPF
   offsets are 16 bit signed, so memory accesses add the offset into
   a scratch register first.  The frame-relative fast path reaches
   [-4096,-1] through a second scratch add.

   Division: arm64 udiv never traps, so only the zero check remains,
   and division by a constant uses the same Granlund-Montgomery
   magic as x86 via umulh. */

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
#pragma GCC diagnostic ignored "-Wunused-function"
#define DASM_CHECKS 1
#include "../../../third_party/luajit/dasm_proto.h"
#include "../../../third_party/luajit/dasm_arm64.h"
#pragma GCC diagnostic pop
#include "../fd_vm_private.h"
#include "../syscall/fd_vm_syscall.h"
#include "../../../ballet/murmur3/fd_murmur3.h"
#include "fd_transpile_idiv.h"
#include "fd_transpile_bb.h"
#include "fd_transpile_target.h"

//|.arch arm64
#if DASM_VERSION != 10500
#error "Version mismatch between DynASM and included encoding engine"
#endif
#line 83 "fd_transpile_arm64.dasc"
//|.actionlist actions
static const unsigned int actions[2002] = {
0x00060014,
0xa9000660,
0x000a8cef,
0xa9000e62,
0x000a8cef,
0xa9001664,
0x000a8cef,
0xa9005674,
0x000a8cef,
0xa9005e76,
0x000a8cef,
0xf8000278,
0x000f0003,
0xd65f03c0,
0x00000000,
0x00060015,
0xa9400660,
0x000a8cef,
0xa9400e62,
0x000a8cef,
0xa9401664,
0x000a8cef,
0xa9405674,
0x000a8cef,
0xa9405e76,
0x000a8cef,
0xf8400278,
0x000f0003,
0xd65f03c0,
0x00000000,
0xd2800000,
0x00110000,
0x000a0205,
0x00000000,
0xd2a00000,
0x00110000,
0x000a0205,
0x00000000,
0xd2c00000,
0x00110000,
0x000a0205,
0x00000000,
0xd2e00000,
0x00110000,
0x000a0205,
0x00000000,
0x92800000,
0x00110000,
0x000a0205,
0x00000000,
0x92a00000,
0x00110000,
0x000a0205,
0x00000000,
0x92c00000,
0x00110000,
0x000a0205,
0x00000000,
0x92e00000,
0x00110000,
0x000a0205,
0x00000000,
0xf2800000,
0x00110000,
0x000a0205,
0x00000000,
0xf2a00000,
0x00110000,
0x000a0205,
0x00000000,
0xf2c00000,
0x00110000,
0x000a0205,
0x00000000,
0xf2e00000,
0x00110000,
0x000a0205,
0x00000000,
0xaa1f03e0,
0x00110000,
0x00000000,
0x92800000,
0x00110000,
0x00000000,
0xf8400269,
0x000f0003,
0x00000000,
0xf1000129,
0x000c0000,
0x00000000,
0xeb0b0129,
0x00000000,
0xf8000269,
0x000f0003,
0x00000000,
0x54000005,
0x00050808,
0x14000000,
0x00050016,
0x00060012,
0x00000000,
0x00080000,
0x94000000,
0x00000000,
0x00080000,
0x9000000b,
0x00080000,
0x9100016b,
0x00000000,
0xf81f0ffe,
0x92800009,
0xf8000269,
0x000f0003,
0x94000000,
0x00050014,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0xcb0b0129,
0xf8000269,
0x000f0003,
0xaa1303e0,
0x00000000,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0x35000000,
0x00050801,
0x94000000,
0x00050015,
0xf84107fe,
0xd65f03c0,
0x0006000b,
0x910043ff,
0x52800009,
0x000a0205,
0x2b09001f,
0x54000001,
0x00050802,
0xf800027f,
0x000f0003,
0x0006000c,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0xaa1f03e9,
0x14000000,
0x00050017,
0x00000000,
0x0004001f,
0x00060018,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100053f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31000529,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51000529,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x00000000,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100053f,
0x54000003,
0x00050802,
0xd1000529,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100053f,
0x54000003,
0x00050802,
0xd1000529,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52800029,
0x14000000,
0x0005001b,
0x0004001f,
0x0006001c,
0x00000000,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100093f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31000929,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51000929,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x00000000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100093f,
0x54000003,
0x00050802,
0xd1000929,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100093f,
0x54000003,
0x00050802,
0xd1000929,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52800049,
0x14000000,
0x0005001b,
0x0004001f,
0x0006001d,
0xf8400269,
0x000f0003,
0x00000000,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100113f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31001129,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51001129,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x00000000,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100113f,
0x54000003,
0x00050802,
0xd1001129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100113f,
0x54000003,
0x00050802,
0xd1001129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52800089,
0x14000000,
0x0005001b,
0x0004001f,
0x0006001e,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0x00000000,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100213f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31002129,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51002129,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x00000000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100213f,
0x54000003,
0x00050802,
0xd1002129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100213f,
0x54000003,
0x00050802,
0xd1002129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52800109,
0x14000000,
0x0005001b,
0x0004001f,
0x0006001f,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0x00000000,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100053f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31000529,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51000529,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0x00000000,
0xb8400269,
0x000f0002,
0xf100053f,
0x54000003,
0x00050802,
0xd1000529,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100053f,
0x54000003,
0x00050802,
0xd1000529,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52802029,
0x14000000,
0x0005001b,
0x0004001f,
0x00060020,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0x00000000,
0xf100093f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31000929,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51000929,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0x00000000,
0xf100093f,
0x54000003,
0x00050802,
0xd1000929,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100093f,
0x54000003,
0x00050802,
0xd1000929,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52802049,
0x14000000,
0x0005001b,
0x0004001f,
0x00060021,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100113f,
0x54000003,
0x00050809,
0x00000000,
0x14000000,
0x00050019,
0x00060013,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31001129,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51001129,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100113f,
0x54000003,
0x00050802,
0x00000000,
0xd1001129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100113f,
0x54000003,
0x00050802,
0xd1001129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52802089,
0x14000000,
0x0005001b,
0x0004001f,
0x00060022,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050809,
0xf8400269,
0x000f0003,
0xeb0a0129,
0x54000003,
0x00050809,
0xf100213f,
0x54000003,
0x00050809,
0x14000000,
0x00050019,
0x00060013,
0x00000000,
0xd360fd49,
0x7100013f,
0x000c0000,
0x54000001,
0x00050804,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xf100057f,
0x54000009,
0x00050803,
0x37600009,
0x00051002,
0x53017d29,
0x4a0a0129,
0x12144d29,
0x4a0a0129,
0x0006000d,
0x31002129,
0x54000002,
0x00050802,
0xb840026b,
0x000f0002,
0x6b0b013f,
0x54000008,
0x00050802,
0x51002129,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000e,
0x7100013f,
0x000c0000,
0x54000000,
0x00050801,
0x7100013f,
0x000c0000,
0x54000001,
0x00050802,
0xb8400269,
0x000f0002,
0xf100213f,
0x54000003,
0x00050802,
0xd1002129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0x00000000,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000b,
0xb8400269,
0x000f0002,
0xf100213f,
0x54000003,
0x00050802,
0xd1002129,
0x6b09015f,
0x54000008,
0x00050802,
0x2a0a03e9,
0xf840026b,
0x000f0003,
0xab0b0129,
0x54000000,
0x00050802,
0xaa0903ea,
0x14000000,
0x0005001a,
0x0006000c,
0x52802109,
0x14000000,
0x0005001b,
0x00060019,
0xf8400269,
0x000f0003,
0xcb09014a,
0xf8400269,
0x000f0003,
0x8b09014a,
0x0006001a,
0xb7f8000a,
0x00051001,
0xd65f03c0,
0x0006000b,
0x14000000,
0x00050023,
0x00000000,
0x0006001b,
0xa9bc03fe,
0xa9010be1,
0xa90213e3,
0xf9001be5,
0x92401d22,
0x53087d23,
0xaa1303e0,
0xaa0a03e1,
0x00000000,
0xaa0003ea,
0xf9401be5,
0xa94213e3,
0xa9410be1,
0xa8c403fe,
0x14000000,
0x0005001a,
0x00000000,
0x00060024,
0xf840026a,
0x000f0003,
0x52800009,
0x000a0205,
0x9b097d49,
0x8b090269,
0x91000129,
0x000c0000,
0xa9005534,
0xa9015d36,
0xf840026b,
0x000f0003,
0xa9022d38,
0x9100054a,
0xf800026a,
0x000f0003,
0xf100015f,
0x000c0000,
0x54000002,
0x00050802,
0xf8400269,
0x000f0003,
0x8b093318,
0x91000549,
0xd374cd29,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000002,
0x00050825,
0x2a1f03ea,
0xd65f03c0,
0x0006000c,
0x5280002a,
0xd65f03c0,
0x00000000,
0x00060025,
0xf81f0ffe,
0x92800009,
0xf8000269,
0x000f0003,
0x94000000,
0x00050014,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0xcb0b0129,
0xf8000269,
0x000f0003,
0xaa1303e0,
0x00000000,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0x94000000,
0x00050015,
0xf84107fe,
0x2a1f03ea,
0xd65f03c0,
0x00000000,
0x00060026,
0xf840026a,
0x000f0003,
0xb400000a,
0x00050801,
0xd100054a,
0xf800026a,
0x000f0003,
0x52800009,
0x000a0205,
0x9b097d49,
0x8b090269,
0x91000129,
0x000c0000,
0xa9405534,
0xa9415d36,
0xf9401138,
0x91000549,
0xd374cd29,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0xaa1d03e9,
0xa940793d,
0x9100413f,
0xd65f03c0,
0x0006000b,
0x94000000,
0x00050014,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0xcb0b0129,
0xf8000269,
0x000f0003,
0x2a1f03ea,
0x14000000,
0x00050027,
0x00000000,
0x00060028,
0x94000000,
0x00050014,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0xaa1f03e9,
0x14000000,
0x00050017,
0x00000000,
0x00060029,
0xf85f83a9,
0xd10083ff,
0xa9017bfd,
0xf90007e9,
0x910043fd,
0xd10083ff,
0xf9000be0,
0xf90003ea,
0x2a0a03e9,
0xd360fd4a,
0xf100055f,
0x54000001,
0x00050801,
0xf840026b,
0x000f0003,
0xcb0b0129,
0xd343fd29,
0xf840026b,
0x000f0003,
0xeb0b013f,
0x54000002,
0x00050801,
0xf90007e9,
0x94000000,
0x00050024,
0x3500000a,
0x00050804,
0xf94007e9,
0x00000000,
0xd346fd2a,
0xf86a796c,
0x9ac9258c,
0x3600000c,
0x00051002,
0xf86a796c,
0x92401529,
0xd37ff98c,
0xaa2903e9,
0x9ac9218c,
0x9e670180,
0x0e205800,
0x0e31b800,
0x1e26000c,
0x00000000,
0xf86a7969,
0x8b09018c,
0x00000000,
0xb8ac796a,
0x8b0b014a,
0xf9400be0,
0x910083ff,
0xd61f0140,
0x0006000b,
0x5280000a,
0x000a0205,
0x14000000,
0x00050003,
0x0006000e,
0x5280000a,
0x000a0205,
0x14000000,
0x00050003,
0x0006000c,
0xf94007e9,
0xf8000269,
0x000f0003,
0x5280000a,
0x000a0205,
0x0006000d,
0x4b0a03ea,
0xf9400be0,
0x94000000,
0x00050014,
0xaa1f03e9,
0x14000000,
0x00050017,
0x00000000,
0x2a1f03e0,
0x00110000,
0x00000000,
0x12000000,
0x00110000,
0x00110005,
0x000d0000,
0x00000000,
0x2a0003e0,
0x00110000,
0x00110010,
0x00000000,
0x53007c00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0x2a0003e9,
0x00110010,
0x00000000,
0x9b0a7d29,
0xd340fd29,
0x000a00d0,
0x00000000,
0x9b0a7d2a,
0x8b4a8129,
0xd340fd29,
0x000a00d0,
0x00000000,
0x1b0a8129,
0x0011000a,
0x2a0903e0,
0x00110000,
0x00000000,
0x2a0903e0,
0x00110000,
0x00000000,
0xeb0a001f,
0x00110005,
0x00000000,
0x9a9f2149,
0xcb090000,
0x00110000,
0x00110005,
0x00000000,
0x9a9f37e0,
0x00110000,
0x00000000,
0xaa1f03e0,
0x00110000,
0x00000000,
0x92000000,
0x00110000,
0x00110005,
0x000e0000,
0x00000000,
0xd340fc00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0x9bca7c09,
0x00110005,
0x00000000,
0xab000129,
0x00110010,
0x9a9f37ea,
0x93c90549,
0x00000000,
0xd340fd29,
0x000a00d0,
0x00000000,
0xd340fd29,
0x000a00d0,
0x00000000,
0x9b0a8129,
0x0011000a,
0x00000000,
0xaa0903e0,
0x00110000,
0x00000000,
0x9100000a,
0x00110005,
0x000c0000,
0x00000000,
0x9100014a,
0x000c0000,
0x00000000,
0x9100000a,
0x00110005,
0x000c0000,
0x00000000,
0xd100000a,
0x00110005,
0x000c0000,
0x00000000,
0xd100014a,
0x000c0000,
0x00000000,
0xd100000a,
0x00110005,
0x000c0000,
0x00000000,
0xf840026a,
0x000f0003,
0xd100014a,
0x000c0000,
0x00000000,
0xd1000000,
0x00110000,
0x00110005,
0x000c0000,
0x00000000,
0x91000000,
0x00110000,
0x00110005,
0x000c0000,
0x00000000,
0x51000000,
0x00110000,
0x00110005,
0x000c0000,
0x00000000,
0x11000000,
0x00110000,
0x00110005,
0x000c0000,
0x00000000,
0x8b090000,
0x00110000,
0x00110005,
0x00000000,
0x0b090000,
0x00110000,
0x00110005,
0x00000000,
0xf100001f,
0x00110005,
0x000c0000,
0x00000000,
0x7100001f,
0x00110005,
0x000c0000,
0x00000000,
0xb100001f,
0x00110005,
0x000c0000,
0x00000000,
0x3100001f,
0x00110005,
0x000c0000,
0x00000000,
0xeb09001f,
0x00110005,
0x00000000,
0x6b09001f,
0x00110005,
0x00000000,
0x92000000,
0x00110000,
0x00110005,
0x000e0000,
0x00000000,
0xb2000000,
0x00110000,
0x00110005,
0x000e0000,
0x00000000,
0xd2000000,
0x00110000,
0x00110005,
0x000e0000,
0x00000000,
0xf200001f,
0x00110005,
0x000e0000,
0x00000000,
0x12000000,
0x00110000,
0x00110005,
0x000d0000,
0x00000000,
0x32000000,
0x00110000,
0x00110005,
0x000d0000,
0x00000000,
0x52000000,
0x00110000,
0x00110005,
0x000d0000,
0x00000000,
0x7200001f,
0x00110005,
0x000d0000,
0x00000000,
0x8a090000,
0x00110000,
0x00110005,
0x00000000,
0xaa090000,
0x00110000,
0x00110005,
0x00000000,
0xca090000,
0x00110000,
0x00110005,
0x00000000,
0xea09001f,
0x00110005,
0x00000000,
0x0a090000,
0x00110000,
0x00110005,
0x00000000,
0x2a090000,
0x00110000,
0x00110005,
0x00000000,
0x4a090000,
0x00110000,
0x00110005,
0x00000000,
0x6a09001f,
0x00110005,
0x00000000,
0x52800009,
0x000a0205,
0x00000000,
0x72a00009,
0x000a0205,
0x00000000,
0x94000000,
0x0005001f,
0x00000000,
0x94000000,
0x00050020,
0x00000000,
0x94000000,
0x00050021,
0x00000000,
0x94000000,
0x00050022,
0x00000000,
0x94000000,
0x00050018,
0x00000000,
0x94000000,
0x0005001c,
0x00000000,
0x94000000,
0x0005001d,
0x00000000,
0x94000000,
0x0005001e,
0x00000000,
0x39400140,
0x00110000,
0x00000000,
0x79400140,
0x00110000,
0x00000000,
0xb9400140,
0x00110000,
0x00000000,
0xf9400140,
0x00110000,
0x00000000,
0x39000140,
0x00110000,
0x00000000,
0x79000140,
0x00110000,
0x00000000,
0xb9000140,
0x00110000,
0x00000000,
0xf9000140,
0x00110000,
0x00000000,
0x54000001,
0x00050808,
0x00000000,
0x54000000,
0x00050808,
0x00000000,
0x54000003,
0x00050808,
0x00000000,
0x54000002,
0x00050808,
0x00000000,
0x54000009,
0x00050808,
0x00000000,
0x54000008,
0x00050808,
0x00000000,
0x5400000b,
0x00050808,
0x00000000,
0x5400000a,
0x00050808,
0x00000000,
0x5400000d,
0x00050808,
0x00000000,
0x5400000c,
0x00050808,
0x00000000,
0x14000000,
0x00070000,
0x00060012,
0x00000000,
0xea00001f,
0x00110005,
0x00110010,
0x00000000,
0x6a00001f,
0x00110005,
0x00110010,
0x00000000,
0xeb00001f,
0x00110005,
0x00110010,
0x00000000,
0x6b00001f,
0x00110005,
0x00110010,
0x00000000,
0x00010000,
0xf8400009,
0x000f0003,
0xb6f80009,
0x00051001,
0x52800000,
0x000a0205,
0x4b0003e0,
0xd65f03c0,
0x0006000b,
0xd10143ff,
0xa9047bfd,
0x910103fd,
0xf9001ffd,
0xa902d3f3,
0xa901dbf5,
0xa900e3f7,
0xaa0003f3,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0x92800009,
0xf8000269,
0x000f0003,
0xf8400269,
0x000f0003,
0xd34cfd29,
0xf8000269,
0x000f0003,
0xf840026a,
0x000f0003,
0x91000549,
0xd374cd29,
0xf840026b,
0x000f0003,
0x8b0b0129,
0xf8000269,
0x000f0003,
0x94000000,
0x00050015,
0xf8400269,
0x000f0003,
0xeb09015f,
0x54000003,
0x00050801,
0x94000000,
0x00050025,
0x0006000b,
0x94000000,
0x00050002,
0xd4200000,
0x0006000c,
0xf85f83a9,
0xd10083ff,
0xa9017bfd,
0xf90007e9,
0x910043fd,
0x14000000,
0x00070000,
0x00000000,
0x00080000,
0x00000000,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0x0b000000,
0x00110000,
0x00110005,
0x00110010,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0x8b000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0x4b000000,
0x00110000,
0x00110005,
0x00110010,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0xcb000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x1b097c00,
0x00110000,
0x00110005,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0x9b097c00,
0x00110000,
0x00110005,
0x00000000,
0x1b007c00,
0x00110000,
0x00110005,
0x00110010,
0x93407c00,
0x00110000,
0x00110005,
0x00000000,
0x9b007c00,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x35000000,
0x00110000,
0x00050801,
0x00000000,
0x14000000,
0x0005002a,
0x0006000b,
0x1ac00800,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0xb5000000,
0x00110000,
0x00050801,
0x00000000,
0x14000000,
0x0005002a,
0x0006000b,
0x9ac00800,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x2a000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0xaa000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x0a000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x8a000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x53000000,
0x00110000,
0x00110005,
0x000a00d0,
0x000a00ca,
0x00000000,
0xd3400000,
0x00110000,
0x00110005,
0x000a00d0,
0x000a00ca,
0x00000000,
0x1ac02000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x9ac02000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x53007c00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0xd340fc00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0x1ac02400,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x9ac02400,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x4b0003e0,
0x00110000,
0x00110010,
0x00000000,
0xcb0003e0,
0x00110000,
0x00110010,
0x00000000,
0x35000000,
0x00110000,
0x00050801,
0x00000000,
0x14000000,
0x0005002a,
0x0006000b,
0x1ac00809,
0x00110005,
0x00110010,
0x1b008120,
0x00110000,
0x00110010,
0x0011000a,
0x00000000,
0xb5000000,
0x00110000,
0x00050801,
0x00000000,
0x14000000,
0x0005002a,
0x0006000b,
0x9ac00809,
0x00110005,
0x00110010,
0x9b008120,
0x00110000,
0x00110010,
0x0011000a,
0x00000000,
0x4a000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0xca000000,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x2a0003e0,
0x00110000,
0x00110010,
0x00000000,
0xaa0003e0,
0x00110000,
0x00110010,
0x00000000,
0x13007c00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0x9340fc00,
0x00110000,
0x00110005,
0x000a00d0,
0x00000000,
0x1ac02800,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x9ac02800,
0x00110000,
0x00110005,
0x00110010,
0x00000000,
0x53003c00,
0x00110000,
0x00110005,
0x00000000,
0x2a0003e0,
0x00110000,
0x00110010,
0x00000000,
0x5ac00400,
0x00110000,
0x00110005,
0x53003c00,
0x00110000,
0x00110005,
0x00000000,
0x5ac00800,
0x00110000,
0x00110005,
0x00000000,
0xdac00c00,
0x00110000,
0x00110005,
0x00000000,
0x14000000,
0x00070000,
0x00000000,
0xf8000269,
0x000f0003,
0x94000000,
0x00070000,
0x00000000,
0x14000000,
0x0005002b,
0x00000000,
0xf8000269,
0x000f0003,
0x94000000,
0x00070000,
0x00000000,
0x14000000,
0x0005002b,
0x00000000,
0xf8000269,
0x000f0003,
0xaa0003ea,
0x00110010,
0x94000000,
0x00050029,
0x00000000,
0x14000000,
0x00050026,
0x00000000,
0x94000000,
0x00050014,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0x52800029,
0x14000000,
0x00050017,
0x00080000,
0x00000000,
0x00080000,
0xf85f83a9,
0xd10083ff,
0xa9017bfd,
0xf90007e9,
0x910043fd,
0x94000000,
0x00050024,
0x3500000a,
0x00050828,
0x14000000,
0x00070000,
0x00000000,
0x00080000,
0x00000000,
0x0006002a,
0x94000000,
0x00050014,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0x14000000,
0x00050017,
0x00000000,
0x00060023,
0xb94003c9,
0x53055129,
0xb94007cb,
0x120b3d6c,
0x52800130,
0x72ae5410,
0x6b10019f,
0x54000001,
0x00050801,
0x5305516b,
0x0b0b4129,
0x0006000b,
0x94000000,
0x00050014,
0x14000000,
0x00050017,
0x00000000,
0x0006002b,
0x94000000,
0x00050014,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0xaa1f03e9,
0x14000000,
0x00050017,
0x00000000,
0x00060016,
0x94000000,
0x00050014,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0xaa1f03e9,
0x00000000,
0x00060017,
0xf840026b,
0x000f0003,
0xcb09016b,
0xf800026b,
0x000f0003,
0xf8400269,
0x000f0003,
0xf840026b,
0x000f0003,
0xcb0b0129,
0xf8000269,
0x000f0003,
0xf840026b,
0x000f0003,
0xb6f8000b,
0x00051001,
0xf800027f,
0x000f0003,
0x5280000a,
0x000a0205,
0x4b0a03ea,
0x0006000b,
0x14000000,
0x00050027,
0x00000000,
0x00060027,
0xf85f83bd,
0x2a0a03e0,
0xd10103bf,
0xa940e3f7,
0xa941dbf5,
0xa942d3f3,
0xa9447bfd,
0x910143ff,
0xd65f03c0,
0x00000000
};

#line 84 "fd_transpile_arm64.dasc"
//|.globals fd_xlat_
enum {
  fd_xlat_regs_save,
  fd_xlat_regs_restore,
  fd_xlat_exception_cost,
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
  fd_xlat_exception_div_zero,
  fd_xlat_exception_ill,
  fd_xlat__MAX
};
#line 85 "fd_transpile_arm64.dasc"
//|.globalnames fd_xlat_names
static const char *const fd_xlat_names[] = {
  "regs_save",
  "regs_restore",
  "exception_cost",
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
  "exception_div_zero",
  "exception_ill",
  (const char *)0
};
#line 86 "fd_transpile_arm64.dasc"
//|.type vm, fd_vm_t, x19
#define Dt1(_V) (int)(ptrdiff_t)&(((fd_vm_t *)0)_V)
#line 87 "fd_transpile_arm64.dasc"
//|.section code
#define DASM_SECTION_CODE	0
#define DASM_MAXSECTION		1
#line 88 "fd_transpile_arm64.dasc"

/* fd_vm_t field offsets reachable by scaled 12 bit immediates (the
   .type form) go up to 32 KiB; shadow and syscalls are within that,
   region tables too.  Nothing emitted below exceeds it. */

FD_STATIC_ASSERT( offsetof( fd_vm_t, shadow )+FD_VM_STACK_FRAME_MAX*sizeof(fd_vm_shadow_t) < 32768UL, vm_shadow );
FD_STATIC_ASSERT( offsetof( fd_vm_t, stack_push_frame_count ) < 32768UL, vm_stack_push_frame_count );

/* emit_regs_subroutines: emit helper functions for reg save/restore */

static void
emit_regs_subroutines( fd_transpiler_t * Dst ) {
  //|->regs_save:
  //| stp x0,  x1,  vm->reg[0]
  //| stp x2,  x3,  vm->reg[2]
  //| stp x4,  x5,  vm->reg[4]
  //| stp x20, x21, vm->reg[6]
  //| stp x22, x23, vm->reg[8]
  //| str x24,      vm->reg[10]
  //| ret
  dasm_put(Dst, 0, Dt1(->reg[0]), Dt1(->reg[2]), Dt1(->reg[4]), Dt1(->reg[6]), Dt1(->reg[8]), Dt1(->reg[10]));
#line 108 "fd_transpile_arm64.dasc"

  //|->regs_restore:
  //| ldp x0,  x1,  vm->reg[0]
  //| ldp x2,  x3,  vm->reg[2]
  //| ldp x4,  x5,  vm->reg[4]
  //| ldp x20, x21, vm->reg[6]
  //| ldp x22, x23, vm->reg[8]
  //| ldr x24,      vm->reg[10]
  //| ret
  dasm_put(Dst, 15, Dt1(->reg[0]), Dt1(->reg[2]), Dt1(->reg[4]), Dt1(->reg[6]), Dt1(->reg[8]), Dt1(->reg[10]));
#line 117 "fd_transpile_arm64.dasc"
}

/* emit_mov16 emits movz (kind 0), movn (kind 1, c is the chunk of the
   final value) or movk (kind 2) of 16 bit chunk c at position i. */

static void
emit_mov16( fd_transpiler_t * Dst,
            uint              reg,
            ushort            c,
            int               i,
            int               kind ) {
  ushort n = (ushort)~c;
  switch( kind*4 + i ) {
  case  0:
    //| movz Rx(reg), #c, lsl #0
    dasm_put(Dst, 30, (reg), c);
#line 132 "fd_transpile_arm64.dasc"
           break;
  case  1:
    //| movz Rx(reg), #c, lsl #16
    dasm_put(Dst, 34, (reg), c);
#line 135 "fd_transpile_arm64.dasc"
           break;
  case  2:
    //| movz Rx(reg), #c, lsl #32
    dasm_put(Dst, 38, (reg), c);
#line 138 "fd_transpile_arm64.dasc"
           break;
  case  3:
    //| movz Rx(reg), #c, lsl #48
    dasm_put(Dst, 42, (reg), c);
#line 141 "fd_transpile_arm64.dasc"
           break;
  case  4:
    //| movn Rx(reg), #n, lsl #0
    dasm_put(Dst, 46, (reg), n);
#line 144 "fd_transpile_arm64.dasc"
           break;
  case  5:
    //| movn Rx(reg), #n, lsl #16
    dasm_put(Dst, 50, (reg), n);
#line 147 "fd_transpile_arm64.dasc"
           break;
  case  6:
    //| movn Rx(reg), #n, lsl #32
    dasm_put(Dst, 54, (reg), n);
#line 150 "fd_transpile_arm64.dasc"
           break;
  case  7:
    //| movn Rx(reg), #n, lsl #48
    dasm_put(Dst, 58, (reg), n);
#line 153 "fd_transpile_arm64.dasc"
           break;
  case  8:
    //| movk Rx(reg), #c, lsl #0
    dasm_put(Dst, 62, (reg), c);
#line 156 "fd_transpile_arm64.dasc"
           break;
  case  9:
    //| movk Rx(reg), #c, lsl #16
    dasm_put(Dst, 66, (reg), c);
#line 159 "fd_transpile_arm64.dasc"
           break;
  case 10:
    //| movk Rx(reg), #c, lsl #32
    dasm_put(Dst, 70, (reg), c);
#line 162 "fd_transpile_arm64.dasc"
           break;
  default:
    //| movk Rx(reg), #c, lsl #48
    dasm_put(Dst, 74, (reg), c);
#line 165 "fd_transpile_arm64.dasc"
           break;
  }
}

/* emit_const64: load a 64-bit immediate into a register. */

static void
emit_const64( fd_transpiler_t * Dst,
              uint              reg,
              ulong             value ) {
  if( value==0UL ) {
    //| mov Rx(reg), xzr
    dasm_put(Dst, 78, (reg));
#line 177 "fd_transpile_arm64.dasc"
    return;
  }
  if( ~value==0UL ) {
    //| movn Rx(reg), #0
    dasm_put(Dst, 81, (reg));
#line 181 "fd_transpile_arm64.dasc"
    return;
  }
  /* count 16 bit chunks that are zero / ones */
  int zeros = 0, ones = 0;
  for( int i=0; i<4; i++ ) {
    ushort c = (ushort)( value>>(16*i) );
    zeros += c==0;
    ones  += c==0xffff;
  }
  int first = 1;
  ushort skip = ones>zeros ? (ushort)0xffff : (ushort)0;
  for( int i=0; i<4; i++ ) {
    ushort c = (ushort)( value>>(16*i) );
    if( c==skip ) continue;
    emit_mov16( Dst, reg, c, i, first ? ( skip ? 1 : 0 ) : 2 );
    first = 0;
  }
}

/* emit_const32: load a 32 bit immediate, zero extending. */

static void
emit_const32( fd_transpiler_t * Dst,
              uint              reg,
              uint              value ) {
  emit_const64( Dst, reg, (ulong)value );
}

/* Scratch register numbers */
#define SCR0 (9U)
#define SCR1 (10U)
#define SCR2 (11U)

/* CU budgeting: see fd_transpile_x86.dasc.  x9 and x11 are scratch. */

//| // Settle internal CU state into fd_vm_t (updates 'ic')
//|.macro cu_save
//| ldr x9, vm->transpiled.ic_cu_anchor
//| ldr x11, vm->cu
//| sub x9, x9, x11
//| str x9, vm->ic
//|.endmacro

//| // Restore internal CU state from fd_vm_t
//|.macro cu_restore
//| ldr x9, vm->ic
//| ldr x11, vm->cu
//| add x9, x9, x11
//| str x9, vm->transpiled.ic_cu_anchor
//|.endmacro

/* cu_charge / cu_settle take a C expression; the count fits 12 bits
   (blocks are split well before that) but emit_cu_sub handles the
   general case. */

static void
emit_cu_sub( fd_transpiler_t * Dst,
             ulong             n ) {
  //| ldr x9, vm->cu
  dasm_put(Dst, 84, Dt1(->cu));
#line 240 "fd_transpile_arm64.dasc"
  if( n<4096UL ) {
    //| subs x9, x9, #n
    dasm_put(Dst, 87, n);
#line 242 "fd_transpile_arm64.dasc"
  } else {
    emit_const64( Dst, SCR2, n );
    //| subs x9, x9, x11
    dasm_put(Dst, 90);
#line 245 "fd_transpile_arm64.dasc"
  }
  //| str x9, vm->cu
  dasm_put(Dst, 92, Dt1(->cu));
#line 247 "fd_transpile_arm64.dasc"
}

static void
emit_cu_charge( fd_transpiler_t * Dst,
                ulong             n ) {
  emit_cu_sub( Dst, n );
  //| bpl >8
  //| b ->exception_cost
  //|8:
  dasm_put(Dst, 95);
#line 256 "fd_transpile_arm64.dasc"
}

/* External function calls */

static uint
sym_id_syscall_handler( ulong syscall_slot_id ) {
  return (uint)( FD_VM_TRANSPILE_SYM_MAX + syscall_slot_id );
}

/* emit_ffi_call generates a relocatable `bl` to a C function.  Assumes
   the CPU state is AAPCS64 compliant and sp is 16 byte aligned. */

static void
emit_ffi_call( fd_transpiler_t * Dst,
               uint              sym ) {
  ulong idx = Dst->reloc_cnt++;
  if( FD_UNLIKELY( idx>=FD_TRANSPILER_RELOC_MAX ) ) {
    longjmp( dasm_oom, 1 );
  }
  Dst->reloc[ idx ] = (fd_elf64_rela){
    .r_info   = FD_ELF64_R_INFO( sym, FD_TRANSPILE_R_CALL ),
    .r_addend = 0L,
  };
  //|=>(Dst->dasm_lbl_reloc0 + idx):
  //| .long 0x94000000 // bl #0
  dasm_put(Dst, 101, (Dst->dasm_lbl_reloc0 + idx));
#line 281 "fd_transpile_arm64.dasc"
}

/* emit_rodata_adr generates `adrp x11, rodata+off; add x11, x11,
   :lo12:rodata+off` (two relocations). */

static void
emit_rodata_adr( fd_transpiler_t * Dst,
                 ulong             off ) {
  ulong idx = Dst->reloc_cnt;
  if( FD_UNLIKELY( idx+2UL>FD_TRANSPILER_RELOC_MAX ) ) {
    longjmp( dasm_oom, 1 );
  }
  Dst->reloc_cnt += 2UL;
  Dst->reloc[ idx ] = (fd_elf64_rela){
    .r_info   = FD_ELF64_R_INFO( FD_VM_TRANSPILE_SYM_RODATA, FD_TRANSPILE_R_ADRP ),
    .r_addend = (long)off,
  };
  Dst->reloc[ idx+1UL ] = (fd_elf64_rela){
    .r_info   = FD_ELF64_R_INFO( FD_VM_TRANSPILE_SYM_RODATA, FD_TRANSPILE_R_ADD_LO12 ),
    .r_addend = (long)off,
  };
  //|=>(Dst->dasm_lbl_reloc0 + idx):
  //| .long 0x9000000b // adrp x11, #0
  //|=>(Dst->dasm_lbl_reloc0 + idx + 1UL):
  //| add x11, x11, #0
  dasm_put(Dst, 104, (Dst->dasm_lbl_reloc0 + idx), (Dst->dasm_lbl_reloc0 + idx + 1UL));
#line 306 "fd_transpile_arm64.dasc"
}

//|.macro mmu_tlb_invalidate
//| movn x9, #0
//| str x9, vm->transpiled.tlb_vaddr_lo
//|.endmacro

//| // Recompute the host address of the current stack frame end from
//| // x10=vm->frame_cnt.  Clobbers x9, x11.
//|.macro frame_haddr_update
//| add x9, x10, #1
//| lsl x9, x9, #12
//| ldr x11, vm->region_haddr[FD_VM_STACK_REGION]
//| add x9, x9, x11
//| str x9, vm->transpiled.frame_haddr
//|.endmacro

/* emit_syscall_call generates an FFI call to an sBPF syscall handler.
   Entered via bl from the instruction stream (x30 = return address
   into the sBPF function body, whose sp is 16 byte aligned). */

static void
emit_syscall_call( fd_transpiler_t * Dst,
                   ulong             slot_idx ) {
  //| str x30, [sp, #-16]!
  //| mmu_tlb_invalidate
  //| bl ->regs_save
  //| cu_save
  //| mov x0, x19 // handlers take (vm, r1..r5); r1..r5 already sit in x1..x5
  dasm_put(Dst, 109, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 335 "fd_transpile_arm64.dasc"
  emit_ffi_call( Dst, sym_id_syscall_handler( slot_idx ) );
  //| cu_restore
  //| cbnz w0, >1
  //| bl ->regs_restore
  //| ldr x30, [sp], #16
  //| ret
  //|1:
  //| add sp, sp, #16
  //| mov w9, #(uint)(-FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED)
  //| cmn w0, w9
  //| bne >2
  //| str xzr, vm->cu
  //|2:
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_SYSCALL_ERROR)
  //| neg w10, w10
  //| mov x9, xzr
  //| b ->exception_charge
  dasm_put(Dst, 124, Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), (uint)(-FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED), Dt1(->cu), (uint)(-FD_VM_ERR_EBPF_SYSCALL_ERROR));
#line 352 "fd_transpile_arm64.dasc"
}

/* Software address translation routines

   Input: x10 = vaddr.  Output: x10 = haddr.  Clobber x9, x11.
   Faults unwind. */

static void
emit_mmu_routines( fd_transpiler_t * Dst ) {
  //|// mmu_translate_flat: flat region (prog/heap).  w9/x9 scratch.
  //|.macro mmu_translate_flat, region, limits, width
  //| ldr w9, vm->limits[region]
  //| cmp x9, #width
  //| blo >2
  //| sub x9, x9, #width
  //| cmp w10, w9
  //| bhi >2
  //| mov w9, w10
  //| ldr x11, vm->region_haddr[region]
  //| adds x9, x9, x11
  //| beq >2
  //| mov x10, x9
  //| b ->mmu_translate_check
  //|.endmacro

  //|// mmu_translate_stack: striped (v0) or dense stack region
  //|.macro mmu_translate_stack, limits, width
  //| mov w9, w10
  //| ldr x11, vm->stack_push_frame_count
  //| cmp x11, #1
  //| bls >3
  //| tbnz w9, #12, >2
  //| lsr w9, w9, #1
  //| eor w9, w9, w10
  //| and w9, w9, #0xfffff000
  //| eor w9, w9, w10
  //|3:
  //| adds w9, w9, #width
  //| bcs >2
  //| ldr w11, vm->limits[FD_VM_STACK_REGION]
  //| cmp w9, w11
  //| bhi >2
  //| sub w9, w9, #width
  //| ldr x11, vm->region_haddr[FD_VM_STACK_REGION]
  //| adds x9, x9, x11
  //| beq >2
  //| mov x10, x9
  //| b ->mmu_translate_check
  //|.endmacro

  //|.macro mmu_translate_fast, limits, width
  //| lsr x9, x10, #32
  //| cmp w9, #FD_VM_STACK_REGION
  //| bne >4
  //| mmu_translate_stack limits, width
  //|4:
  //| cmp w9, #FD_VM_PROG_REGION
  //| beq >1
  //| cmp w9, #FD_VM_HEAP_REGION
  //| bne >2
  //| mmu_translate_flat FD_VM_HEAP_REGION, limits, width
  //|1:
  //| mmu_translate_flat FD_VM_PROG_REGION, limits, width
  //|2:
  //|.endmacro

  //|.macro mmu_translate, acc, tlb_hi, limits, sz
  //| ldr x9, vm->transpiled.tlb_vaddr_lo
  //| cmp x10, x9
  //| blo >9
  //| ldr x9, vm->transpiled.tlb_hi
  //| subs x9, x9, x10
  //| blo >9
  //| cmp x9, #sz
  //| blo >9
  //| b ->mmu_tlb_hit
  //|9:
  //| mmu_translate_fast limits, sz
  //| mov w9, #((acc*0x100)+sz)
  //| b ->mmu_tlb_miss
  //|.endmacro

  //|.macro mmu_translate_ld, sz
  //| mmu_translate 0, tlb_vaddr_ld_hi, region_ld_sz, sz
  //|.endmacro

  //|.macro mmu_translate_st, sz
  //| mmu_translate 1, tlb_vaddr_st_hi, region_st_sz, sz
  //|.endmacro

  //|.align 32
  //|->mmu_translate_ld_1:
  //|  mmu_translate_ld,1
  dasm_put(Dst, 154, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]));
#line 445 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_ld_2:
  //|  mmu_translate_ld,2
  dasm_put(Dst, 209, FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]));
  dasm_put(Dst, 261, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION);
#line 448 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_ld_4:
  //|  mmu_translate_ld,4
  dasm_put(Dst, 316, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo));
  dasm_put(Dst, 368, Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION);
#line 451 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_ld_8:
  //|  mmu_translate_ld,8
  dasm_put(Dst, 423, FD_VM_HEAP_REGION, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo));
  dasm_put(Dst, 476, Dt1(->transpiled.tlb_vaddr_ld_hi), FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_ld_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION);
#line 454 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_st_1:
  //|  mmu_translate_st,1
  dasm_put(Dst, 530, Dt1(->region_ld_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_ld_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi));
  dasm_put(Dst, 583, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION);
#line 457 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_st_2:
  //|  mmu_translate_st,2
  dasm_put(Dst, 637, Dt1(->region_st_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi));
  dasm_put(Dst, 691, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]));
#line 460 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_st_4:
  //|  mmu_translate_st,4
  dasm_put(Dst, 744, Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi));
  dasm_put(Dst, 799, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]));
#line 463 "fd_transpile_arm64.dasc"
  //|.align 32
  //|->mmu_translate_st_8:
  //|  mmu_translate_st,8
  dasm_put(Dst, 852, Dt1(->region_haddr[FD_VM_HEAP_REGION]), Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_vaddr_st_hi));
  dasm_put(Dst, 907, FD_VM_STACK_REGION, Dt1(->stack_push_frame_count), Dt1(->region_st_sz[FD_VM_STACK_REGION]), Dt1(->region_haddr[FD_VM_STACK_REGION]), FD_VM_PROG_REGION, FD_VM_HEAP_REGION, Dt1(->region_st_sz[FD_VM_HEAP_REGION]), Dt1(->region_haddr[FD_VM_HEAP_REGION]));
#line 466 "fd_transpile_arm64.dasc"
  //|->mmu_tlb_hit:
  //| ldr x9, vm->transpiled.tlb_vaddr_lo
  //| sub x10, x10, x9
  //| ldr x9, vm->transpiled.tlb_haddr_lo
  //| add x10, x10, x9
  //|->mmu_translate_check:
  //| tbnz x10, #63, >1
  //| ret
  //|1:
  //| b ->exception_segfault
  dasm_put(Dst, 964, Dt1(->region_st_sz[FD_VM_PROG_REGION]), Dt1(->region_haddr[FD_VM_PROG_REGION]), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.tlb_haddr_lo));
#line 476 "fd_transpile_arm64.dasc"

  //|// mmu_tlb_miss: C fallback.  x10 = vaddr, w9 = (is_write<<8)|width.
  //|// Returns haddr (or negative error) in x10.  Preserves r0..r5.
  //|->mmu_tlb_miss:
  //| stp x30, x0, [sp, #-64]!
  //| stp x1, x2, [sp, #16]
  //| stp x3, x4, [sp, #32]
  //| str x5, [sp, #48]
  //| and x2, x9, #0xff   // arg 2: access_width
  //| lsr w3, w9, #8      // arg 3: is_write
  //| mov x0, x19         // arg 0: vm
  //| mov x1, x10         // arg 1: vaddr
  dasm_put(Dst, 1008);
#line 488 "fd_transpile_arm64.dasc"
  emit_ffi_call( Dst, FD_VM_TRANSPILE_SYM_MMU_TRANSLATE );
  //| mov x10, x0
  //| ldr x5, [sp, #48]
  //| ldp x3, x4, [sp, #32]
  //| ldp x1, x2, [sp, #16]
  //| ldp x30, x0, [sp], #64
  //| b ->mmu_translate_check
  dasm_put(Dst, 1018);
#line 495 "fd_transpile_arm64.dasc"
}

/* BPF to BPF calls */

//| // Open a transpiled frame: [x29+8] return address, [x29] caller x29,
//| // [x29-8] root frame pointer (inherited).  Leaves sp==x29-16.
//|.macro sbpf_frame_enter
//| ldr x9, [x29, #-8]
//| sub sp, sp, #32
//| stp x29, x30, [sp, #16]
//| str x9, [sp, #8]
//| add x29, sp, #16
//|.endmacro

/* emit_frame_helpers: generate subroutines for BPF-to-BPF calls.
   bpfcall_frame_push returns 0 in w10 on success, 1 on depth overflow.
   Clobbers x9, x10, x11. */

static void
emit_frame_helpers( fd_transpiler_t * Dst ) {
  //|->bpfcall_frame_push:
  //| ldr x10, vm->frame_cnt
  //| mov x9, #sizeof(fd_vm_shadow_t)
  //| mul x9, x10, x9
  //| add x9, x19, x9
  //| add x9, x9, #offsetof(fd_vm_t, shadow)
  //| stp x20, x21, [x9, #0]
  //| stp x22, x23, [x9, #16]
  //| ldr x11, vm->pc
  //| stp x24, x11, [x9, #32]
  //| add x10, x10, #1
  //| str x10, vm->frame_cnt
  //| cmp x10, #FD_VM_STACK_FRAME_MAX
  //| bhs >2
  //| ldr x9, vm->stack_push_frame_count
  //| add x24, x24, x9, lsl #12
  //| frame_haddr_update
  //| ldr x9, vm->transpiled.frame_clean_cnt
  //| cmp x10, x9
  //| bhs ->bpfcall_frame_init
  //| mov w10, wzr
  //| ret
  //|2:
  //| mov w10, #1
  //| ret
  dasm_put(Dst, 1026, Dt1(->frame_cnt), sizeof(fd_vm_shadow_t), offsetof(fd_vm_t, shadow), Dt1(->pc), Dt1(->frame_cnt), FD_VM_STACK_FRAME_MAX, Dt1(->stack_push_frame_count), Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.frame_clean_cnt));
#line 540 "fd_transpile_arm64.dasc"

  //|->bpfcall_frame_init:
  //| str x30, [sp, #-16]!
  //| mmu_tlb_invalidate
  //| bl ->regs_save
  //| cu_save
  //| mov x0, x19
  dasm_put(Dst, 1068, Dt1(->transpiled.tlb_vaddr_lo), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 547 "fd_transpile_arm64.dasc"
  emit_ffi_call( Dst, FD_VM_TRANSPILE_SYM_FRAME_INIT );
  //| cu_restore
  //| bl ->regs_restore
  //| ldr x30, [sp], #16
  //| mov w10, wzr
  //| ret
  dasm_put(Dst, 1084, Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor));
#line 553 "fd_transpile_arm64.dasc"

  //|->bpfcall_frame_pop:
  //| ldr x10, vm->frame_cnt
  //| cbz x10, >1
  //| sub x10, x10, #1
  //| str x10, vm->frame_cnt
  //| mov x9, #sizeof(fd_vm_shadow_t)
  //| mul x9, x10, x9
  //| add x9, x19, x9
  //| add x9, x9, #offsetof(fd_vm_t, shadow)
  //| ldp x20, x21, [x9, #0]
  //| ldp x22, x23, [x9, #16]
  //| ldr x24, [x9, #32]
  //| frame_haddr_update
  //| // leave: [x29] = caller fp, [x29+8] = lr, caller sp = x29+16
  //| mov x9, x29
  //| ldp x29, x30, [x9]
  //| add sp, x9, #16
  //| ret
  //|1:
  //| bl ->regs_save
  //| cu_save
  //| mov w10, wzr
  //| b ->unwind
  dasm_put(Dst, 1097, Dt1(->frame_cnt), Dt1(->frame_cnt), sizeof(fd_vm_shadow_t), offsetof(fd_vm_t, shadow), Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic));
#line 577 "fd_transpile_arm64.dasc"

  //|->call_imm_depth:
  //| bl ->regs_save
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED)
  //| neg w10, w10
  //| mov x9, xzr
  //| b ->exception_charge
  dasm_put(Dst, 1139, (uint)(-FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED));
#line 584 "fd_transpile_arm64.dasc"
}

/* emit_callx_handler: see fd_transpile_x86.dasc.  Entered via bl with
   x10 = target virtual address. */

static void
emit_callx_handler( fd_transpiler_t * Dst ) {
  //|->callx:
  //| // callee frame:
  //| //   [x29+ 8]: return address
  //| //   [x29+ 0]: caller x29
  //| //   [x29- 8]: root frame pointer
  //| //   [sp+16]:  BPF r0 save
  //| //   [sp+ 8]:  target BPF program counter
  //| //   [sp+ 0]:  target BPF virtual address
  //| sbpf_frame_enter
  //| sub sp, sp, #32
  //| str x0, [sp, #16]
  //| str x10, [sp, #0]
  //|
  //| mov w9, w10
  //| lsr x10, x10, #32
  //| cmp x10, #1
  //| bne >1 // if( (vaddr>>32)!=1 )
  //| ldr x11, vm->text_off
  //| sub x9, x9, x11
  //| lsr x9, x9, #3
  //| ldr x11, vm->text_cnt
  //| cmp x9, x11
  //| bhs >1
  //| str x9, [sp, #8]
  //|
  //| bl ->bpfcall_frame_push
  //| cbnz w10, >4 // call depth exceeded
  //|
  //| ldr x9, [sp, #8]
  //|
  dasm_put(Dst, 1149, Dt1(->text_off), Dt1(->text_cnt));
#line 621 "fd_transpile_arm64.dasc"
  ulong bb_word_cnt = (Dst->bpf_text_cnt+63UL)>>6;
  ulong bitmap_off  = 0UL;
  ulong seq_off     = bitmap_off + bb_word_cnt*sizeof(ulong);
  ulong jmp_off     = seq_off    + bb_word_cnt*sizeof(ulong);
  emit_rodata_adr( Dst, bitmap_off );
  //| // bit test: word = bitmap[pc>>6], bit = pc&63
  //| lsr x10, x9, #6
  //| ldr x12, [x11, x10, lsl #3]
  //| lsr x12, x12, x9  // shift amount is taken mod 64
  //| tbz x12, #0, >2  // middle of a basic block: bail
  //|
  //| // BB index = popcount(word & ((1<<bit)-1)) + seq[pc>>6]
  //| ldr x12, [x11, x10, lsl #3]
  //| and x9, x9, #63
  //| lsl x12, x12, #1  // (word << 1) << (63-bit) keeps bits below 'bit'
  //| mvn x9, x9        // x9 = ~bit = -bit-1, low 6 bits = 63-bit
  //| lsl x12, x12, x9
  //| fmov d0, x12
  //| .long 0x0e205800 // cnt  v0.8b, v0.8b
  //| .long 0x0e31b800 // addv b0, v0.8b
  //| fmov w12, s0
  dasm_put(Dst, 1179);
#line 642 "fd_transpile_arm64.dasc"
  emit_rodata_adr( Dst, seq_off );
  //| ldr x9, [x11, x10, lsl #3]
  //| add x12, x12, x9
  //|
  //| // BB index -> address of first instruction
  dasm_put(Dst, 1194);
#line 647 "fd_transpile_arm64.dasc"
  emit_rodata_adr( Dst, jmp_off );
  //| ldrsw x10, [x11, x12, lsl #2]
  //| add x10, x10, x11
  //|
  //| ldr x0, [sp, #16]
  //| add sp, sp, #32
  //| br x10
  //|
  //|1: // sigtextbr
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT)
  //| b >3
  //|4: // call depth exceeded
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED)
  //| b >3
  //|2: // bail to interpreter
  //| ldr x9, [sp, #8]
  //| str x9, vm->pc
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_BAIL)
  //|3:
  //| neg w10, w10
  //| ldr x0, [sp, #16]
  //| bl ->regs_save
  //| mov x9, xzr
  //| b ->exception_charge
  dasm_put(Dst, 1197, (uint)(-FD_VM_ERR_EBPF_CALL_OUTSIDE_TEXT_SEGMENT), (uint)(-FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED), Dt1(->pc), (uint)(-FD_VM_ERR_EBPF_BAIL));
#line 671 "fd_transpile_arm64.dasc"
}

/* emit_udiv32_imm: reg = (uint)reg / d (or % d), zero extended.
   d non-zero.  Clobbers x9, x10. */

static void
emit_udiv32_imm( fd_transpiler_t * Dst,
                 uint              reg,
                 uint              d,
                 int               is_mod ) {
  if( fd_uint_is_pow2( d ) ) {
    int s = fd_uint_find_msb( d );
    if( is_mod ) {
      if( s==0 ) {
        //| mov Rw(reg), wzr
        dasm_put(Dst, 1227, (reg));
#line 686 "fd_transpile_arm64.dasc"
      } else {
        //| and Rw(reg), Rw(reg), #(d-1U)
        dasm_put(Dst, 1230, (reg), (reg), (d-1U));
#line 688 "fd_transpile_arm64.dasc"
      }
    } else if( s==0 ) {
      //| mov Rw(reg), Rw(reg)
      dasm_put(Dst, 1235, (reg), (reg));
#line 691 "fd_transpile_arm64.dasc"
    } else {
      //| lsr Rw(reg), Rw(reg), #s
      dasm_put(Dst, 1239, (reg), (reg), s);
#line 693 "fd_transpile_arm64.dasc"
    }
    return;
  }
  int   k;
  ulong m = fd_transpile_udiv32_magic( d, &k );
  //| mov w9, Rw(reg)
  dasm_put(Dst, 1244, (reg));
#line 699 "fd_transpile_arm64.dasc"
  if( m<=(ulong)UINT_MAX ) {
    /* q = (n*m)>>k, n*m < 2^64 */
    emit_const64( Dst, SCR1, m );
    //| mul x9, x9, x10
    //| lsr x9, x9, #k
    dasm_put(Dst, 1247, k);
#line 704 "fd_transpile_arm64.dasc"
  } else {
    /* m = 2^32+m', (n*m)>>32 = n + ((n*m')>>32) < 2^33 */
    emit_const64( Dst, SCR1, m & 0xffffffffUL );
    //| mul x10, x9, x10
    //| add x9, x9, x10, lsr #32
    //| lsr x9, x9, #(k-32)
    dasm_put(Dst, 1251, (k-32));
#line 710 "fd_transpile_arm64.dasc"
  }
  if( is_mod ) {
    emit_const32( Dst, SCR1, d );
    //| msub w9, w9, w10, Rw(reg)
    //| mov Rw(reg), w9
    dasm_put(Dst, 1256, (reg), (reg));
#line 715 "fd_transpile_arm64.dasc"
  } else {
    //| mov Rw(reg), w9
    dasm_put(Dst, 1261, (reg));
#line 717 "fd_transpile_arm64.dasc"
  }
}

/* emit_udiv64_imm: reg = reg / d (or % d).  d is the sign extended
   imm32, non-zero.  Clobbers x9, x10, x11. */

static void
emit_udiv64_imm( fd_transpiler_t * Dst,
                 uint              reg,
                 uint              imm,
                 int               is_mod ) {
  ulong d = (ulong)(long)(int)imm;

  if( (long)d<0L ) {
    /* d>=2^63, so q = n>=d */
    emit_const64( Dst, SCR1, d );
    //| cmp Rx(reg), x10
    dasm_put(Dst, 1264, (reg));
#line 734 "fd_transpile_arm64.dasc"
    if( is_mod ) {
      //| csel x9, x10, xzr, hs
      //| sub Rx(reg), Rx(reg), x9
      dasm_put(Dst, 1267, (reg), (reg));
#line 737 "fd_transpile_arm64.dasc"
    } else {
      //| cset Rx(reg), hs
      dasm_put(Dst, 1272, (reg));
#line 739 "fd_transpile_arm64.dasc"
    }
    return;
  }

  if( fd_ulong_is_pow2( d ) ) {
    int s = fd_ulong_find_msb( d );
    if( is_mod ) {
      if( s==0 ) {
        //| mov Rx(reg), xzr
        dasm_put(Dst, 1275, (reg));
#line 748 "fd_transpile_arm64.dasc"
      } else {
        //| and Rx(reg), Rx(reg), #(d-1UL)
        dasm_put(Dst, 1278, (reg), (reg), (unsigned int)((d-1UL)), (unsigned int)((unsigned long long)((d-1UL))>>32));
#line 750 "fd_transpile_arm64.dasc"
      }
    } else if( s ) {
      //| lsr Rx(reg), Rx(reg), #s
      dasm_put(Dst, 1283, (reg), (reg), s);
#line 753 "fd_transpile_arm64.dasc"
    }
    return;
  }

  int     k;
  uint128 m = fd_transpile_udiv64_magic( d, &k );
  emit_const64( Dst, SCR1, (ulong)m );
  //| umulh x9, Rx(reg), x10
  dasm_put(Dst, 1288, (reg));
#line 761 "fd_transpile_arm64.dasc"
  if( m>>64 ) {
    /* m = 2^64+m': (n*m)>>64 = n + hi(n*m') < 2^65 */
    //| adds x9, x9, Rx(reg)
    //| cset x10, cs
    //| extr x9, x10, x9, #1
    dasm_put(Dst, 1291, (reg));
#line 766 "fd_transpile_arm64.dasc"
    if( k>65 ) {
      //| lsr x9, x9, #(k-65)
      dasm_put(Dst, 1296, (k-65));
#line 768 "fd_transpile_arm64.dasc"
    }
  } else if( k>64 ) {
    //| lsr x9, x9, #(k-64)
    dasm_put(Dst, 1299, (k-64));
#line 771 "fd_transpile_arm64.dasc"
  }
  if( is_mod ) {
    emit_const64( Dst, SCR1, d );
    //| msub x9, x9, x10, Rx(reg)
    dasm_put(Dst, 1302, (reg));
#line 775 "fd_transpile_arm64.dasc"
  }
  //| mov Rx(reg), x9
  dasm_put(Dst, 1305, (reg));
#line 777 "fd_transpile_arm64.dasc"
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

/* emit_add_off: x10 = Rx(reg) + offset (16 bit signed) */

static void
emit_add_off( fd_transpiler_t * Dst,
              uint              reg,
              long              offset ) {
  if( offset>=0L ) {
    ulong hi = (ulong)offset & ~0xfffUL;
    ulong lo = (ulong)offset &  0xfffUL;
    if( hi ) {
      //| add x10, Rx(reg), #hi
      dasm_put(Dst, 1308, (reg), hi);
#line 801 "fd_transpile_arm64.dasc"
      if( lo ) {
        //| add x10, x10, #lo
        dasm_put(Dst, 1312, lo);
#line 803 "fd_transpile_arm64.dasc"
      }
    } else {
      //| add x10, Rx(reg), #lo
      dasm_put(Dst, 1315, (reg), lo);
#line 806 "fd_transpile_arm64.dasc"
    }
  } else {
    ulong mag = (ulong)-offset;
    ulong hi  = mag & ~0xfffUL;
    ulong lo  = mag &  0xfffUL;
    if( hi ) {
      //| sub x10, Rx(reg), #hi
      dasm_put(Dst, 1319, (reg), hi);
#line 813 "fd_transpile_arm64.dasc"
      if( lo ) {
        //| sub x10, x10, #lo
        dasm_put(Dst, 1323, lo);
#line 815 "fd_transpile_arm64.dasc"
      }
    } else {
      //| sub x10, Rx(reg), #lo
      dasm_put(Dst, 1326, (reg), lo);
#line 818 "fd_transpile_arm64.dasc"
    }
  }
}

/* emit_frame_addr: x10 = frame_haddr + offset, offset in [-4096,-1]
   (4096 encodes as a shifted imm12) */

static void
emit_frame_addr( fd_transpiler_t * Dst,
                 long              offset ) {
  //| ldr x10, vm->transpiled.frame_haddr
  //| sub x10, x10, #(-offset)
  dasm_put(Dst, 1330, Dt1(->transpiled.frame_haddr), (-offset));
#line 830 "fd_transpile_arm64.dasc"
}

/* emit_addsub_imm: reg += v (is_add) or reg -= v, where v is the sign
   extended imm32, in 32 or 64 bits. */

static void
emit_addsub_imm( fd_transpiler_t * Dst,
                 int               is_add,
                 int               is64,
                 uint              reg,
                 uint              imm ) {
  long v = (long)(int)imm;
  if( !is_add ) v = -v;
  ulong mag = v<0L ? (ulong)-v : (ulong)v;
  int   sub = v<0L;
  if( mag<4096UL || ( !(mag&0xfffUL) && mag<(1UL<<24) ) ) {
    if( is64 ) {
      if( sub ) {
        //| sub Rx(reg), Rx(reg), #mag
        dasm_put(Dst, 1335, (reg), (reg), mag);
#line 849 "fd_transpile_arm64.dasc"
      } else {
        //| add Rx(reg), Rx(reg), #mag
        dasm_put(Dst, 1340, (reg), (reg), mag);
#line 851 "fd_transpile_arm64.dasc"
      }
    } else {
      if( sub ) {
        //| sub Rw(reg), Rw(reg), #mag
        dasm_put(Dst, 1345, (reg), (reg), mag);
#line 855 "fd_transpile_arm64.dasc"
      } else {
        //| add Rw(reg), Rw(reg), #mag
        dasm_put(Dst, 1350, (reg), (reg), mag);
#line 857 "fd_transpile_arm64.dasc"
      }
    }
    return;
  }
  emit_const64( Dst, SCR0, (ulong)v );
  if( is64 ) {
    //| add Rx(reg), Rx(reg), x9
    dasm_put(Dst, 1355, (reg), (reg));
#line 864 "fd_transpile_arm64.dasc"
  } else {
    //| add Rw(reg), Rw(reg), w9
    dasm_put(Dst, 1359, (reg), (reg));
#line 866 "fd_transpile_arm64.dasc"
  }
}

/* emit_cmp_imm: compare reg with the sign extended imm32 */

static void
emit_cmp_imm( fd_transpiler_t * Dst,
              int               is64,
              uint              reg,
              uint              imm ) {
  long v = (long)(int)imm;
  if( v>=0L && v<4096L ) {
    if( is64 ) {
      //| cmp Rx(reg), #v
      dasm_put(Dst, 1363, (reg), v);
#line 880 "fd_transpile_arm64.dasc"
    } else {
      //| cmp Rw(reg), #v
      dasm_put(Dst, 1367, (reg), v);
#line 882 "fd_transpile_arm64.dasc"
    }
  } else if( v<0L && v>-4096L ) {
    if( is64 ) {
      //| cmn Rx(reg), #(-v)
      dasm_put(Dst, 1371, (reg), (-v));
#line 886 "fd_transpile_arm64.dasc"
    } else {
      //| cmn Rw(reg), #(-v)
      dasm_put(Dst, 1375, (reg), (-v));
#line 888 "fd_transpile_arm64.dasc"
    }
  } else {
    emit_const64( Dst, SCR0, (ulong)v );
    if( is64 ) {
      //| cmp Rx(reg), x9
      dasm_put(Dst, 1379, (reg));
#line 893 "fd_transpile_arm64.dasc"
    } else {
      //| cmp Rw(reg), w9
      dasm_put(Dst, 1382, (reg));
#line 895 "fd_transpile_arm64.dasc"
    }
  }
}

/* is_bitmask_imm: can v be encoded as a logical immediate? */

static int
is_bitmask_imm( ulong v,
                int   is64 ) {
  if( !is64 ) return dasm_imm13( (int)(uint)v, (int)(uint)v )!=-1;
  return dasm_imm13( (int)(uint)v, (int)(uint)(v>>32) )!=-1;
}

/* emit_logic_imm: reg = reg OP v (op: 0 and, 1 orr, 2 eor, 3 tst) */

#define LOGIC_AND (0)
#define LOGIC_ORR (1)
#define LOGIC_EOR (2)
#define LOGIC_TST (3)

static void
emit_logic_imm( fd_transpiler_t * Dst,
                int               op,
                int               is64,
                uint              reg,
                ulong             v ) {
  if( is_bitmask_imm( v, is64 ) ) {
    if( is64 ) {
      switch( op ) {
      case LOGIC_AND:
        //| and Rx(reg), Rx(reg), #v
        dasm_put(Dst, 1385, (reg), (reg), (unsigned int)(v), (unsigned int)((unsigned long long)(v)>>32));
#line 926 "fd_transpile_arm64.dasc"
                      break;
      case LOGIC_ORR:
        //| orr Rx(reg), Rx(reg), #v
        dasm_put(Dst, 1390, (reg), (reg), (unsigned int)(v), (unsigned int)((unsigned long long)(v)>>32));
#line 929 "fd_transpile_arm64.dasc"
                      break;
      case LOGIC_EOR:
        //| eor Rx(reg), Rx(reg), #v
        dasm_put(Dst, 1395, (reg), (reg), (unsigned int)(v), (unsigned int)((unsigned long long)(v)>>32));
#line 932 "fd_transpile_arm64.dasc"
                      break;
      default:
        //| tst Rx(reg), #v
        dasm_put(Dst, 1400, (reg), (unsigned int)(v), (unsigned int)((unsigned long long)(v)>>32));
#line 935 "fd_transpile_arm64.dasc"
                      break;
      }
    } else {
      uint w = (uint)v;
      switch( op ) {
      case LOGIC_AND:
        //| and Rw(reg), Rw(reg), #w
        dasm_put(Dst, 1404, (reg), (reg), w);
#line 942 "fd_transpile_arm64.dasc"
                      break;
      case LOGIC_ORR:
        //| orr Rw(reg), Rw(reg), #w
        dasm_put(Dst, 1409, (reg), (reg), w);
#line 945 "fd_transpile_arm64.dasc"
                      break;
      case LOGIC_EOR:
        //| eor Rw(reg), Rw(reg), #w
        dasm_put(Dst, 1414, (reg), (reg), w);
#line 948 "fd_transpile_arm64.dasc"
                      break;
      default:
        //| tst Rw(reg), #w
        dasm_put(Dst, 1419, (reg), w);
#line 951 "fd_transpile_arm64.dasc"
                      break;
      }
    }
    return;
  }
  emit_const64( Dst, SCR0, v );
  if( is64 ) {
    switch( op ) {
    case LOGIC_AND:
      //| and Rx(reg), Rx(reg), x9
      dasm_put(Dst, 1423, (reg), (reg));
#line 961 "fd_transpile_arm64.dasc"
                    break;
    case LOGIC_ORR:
      //| orr Rx(reg), Rx(reg), x9
      dasm_put(Dst, 1427, (reg), (reg));
#line 964 "fd_transpile_arm64.dasc"
                    break;
    case LOGIC_EOR:
      //| eor Rx(reg), Rx(reg), x9
      dasm_put(Dst, 1431, (reg), (reg));
#line 967 "fd_transpile_arm64.dasc"
                    break;
    default:
      //| tst Rx(reg), x9
      dasm_put(Dst, 1435, (reg));
#line 970 "fd_transpile_arm64.dasc"
                    break;
    }
  } else {
    switch( op ) {
    case LOGIC_AND:
      //| and Rw(reg), Rw(reg), w9
      dasm_put(Dst, 1438, (reg), (reg));
#line 976 "fd_transpile_arm64.dasc"
                    break;
    case LOGIC_ORR:
      //| orr Rw(reg), Rw(reg), w9
      dasm_put(Dst, 1442, (reg), (reg));
#line 979 "fd_transpile_arm64.dasc"
                    break;
    case LOGIC_EOR:
      //| eor Rw(reg), Rw(reg), w9
      dasm_put(Dst, 1446, (reg), (reg));
#line 982 "fd_transpile_arm64.dasc"
                    break;
    default:
      //| tst Rw(reg), w9
      dasm_put(Dst, 1450, (reg));
#line 985 "fd_transpile_arm64.dasc"
                    break;
    }
  }
}

/* emit_cost_marker loads the block CU count into w9 as
   `movz w9, #lo16` optionally followed by `movk w9, #hi16, lsl #16`.
   exception_segfault decodes this exact shape from the return address
   of a failed mmu_translate call, so it must not be changed without
   updating that decoder. */

static void
emit_cost_marker( fd_transpiler_t * Dst,
                  ulong             cost ) {
  uint lo = (uint)( cost & 0xffffUL );
  uint hi = (uint)( cost>>16 );
  //| movz w9, #lo
  dasm_put(Dst, 1453, lo);
#line 1002 "fd_transpile_arm64.dasc"
  if( hi ) {
    //| movk w9, #hi, lsl #16
    dasm_put(Dst, 1456, hi);
#line 1004 "fd_transpile_arm64.dasc"
  }
}

/* emit_mem_addr: x10 = host address for the access.  Frame-relative
   accesses skip translation.  cost is the block CU marker that
   exception_segfault decodes from the instruction after the bl. */

static void
emit_mem_addr( fd_transpiler_t * Dst,
               int               frame_fast,
               int               is_store,
               ulong             width,
               uint              reg,
               long              offset,
               ulong             cost ) {
  if( frame_fast ) {
    emit_frame_addr( Dst, offset );
    return;
  }
  emit_add_off( Dst, reg, offset );
  if( is_store ) {
    switch( width ) {
    case 1UL:
      //| bl ->mmu_translate_st_1
      dasm_put(Dst, 1459);
#line 1028 "fd_transpile_arm64.dasc"
              break;
    case 2UL:
      //| bl ->mmu_translate_st_2
      dasm_put(Dst, 1462);
#line 1031 "fd_transpile_arm64.dasc"
              break;
    case 4UL:
      //| bl ->mmu_translate_st_4
      dasm_put(Dst, 1465);
#line 1034 "fd_transpile_arm64.dasc"
              break;
    default:
      //| bl ->mmu_translate_st_8
      dasm_put(Dst, 1468);
#line 1037 "fd_transpile_arm64.dasc"
              break;
    }
  } else {
    switch( width ) {
    case 1UL:
      //| bl ->mmu_translate_ld_1
      dasm_put(Dst, 1471);
#line 1043 "fd_transpile_arm64.dasc"
              break;
    case 2UL:
      //| bl ->mmu_translate_ld_2
      dasm_put(Dst, 1474);
#line 1046 "fd_transpile_arm64.dasc"
              break;
    case 4UL:
      //| bl ->mmu_translate_ld_4
      dasm_put(Dst, 1477);
#line 1049 "fd_transpile_arm64.dasc"
              break;
    default:
      //| bl ->mmu_translate_ld_8
      dasm_put(Dst, 1480);
#line 1052 "fd_transpile_arm64.dasc"
              break;
    }
  }
  emit_cost_marker( Dst, cost );
}

static void
emit_load( fd_transpiler_t * Dst,
           ulong             width,
           uint              rd ) {
  switch( width ) {
  case 1UL:
    //| ldrb Rw(rd), [x10]
    dasm_put(Dst, 1483, (rd));
#line 1065 "fd_transpile_arm64.dasc"
            break;
  case 2UL:
    //| ldrh Rw(rd), [x10]
    dasm_put(Dst, 1486, (rd));
#line 1068 "fd_transpile_arm64.dasc"
            break;
  case 4UL:
    //| ldr Rw(rd), [x10]
    dasm_put(Dst, 1489, (rd));
#line 1071 "fd_transpile_arm64.dasc"
            break;
  default:
    //| ldr Rx(rd), [x10]
    dasm_put(Dst, 1492, (rd));
#line 1074 "fd_transpile_arm64.dasc"
            break;
  }
}

static void
emit_store( fd_transpiler_t * Dst,
            ulong             width,
            uint              rs ) {
  switch( width ) {
  case 1UL:
    //| strb Rw(rs), [x10]
    dasm_put(Dst, 1495, (rs));
#line 1085 "fd_transpile_arm64.dasc"
            break;
  case 2UL:
    //| strh Rw(rs), [x10]
    dasm_put(Dst, 1498, (rs));
#line 1088 "fd_transpile_arm64.dasc"
            break;
  case 4UL:
    //| str Rw(rs), [x10]
    dasm_put(Dst, 1501, (rs));
#line 1091 "fd_transpile_arm64.dasc"
            break;
  default:
    //| str Rx(rs), [x10]
    dasm_put(Dst, 1504, (rs));
#line 1094 "fd_transpile_arm64.dasc"
            break;
  }
}

/* emit_branch: conditional branch to a pc label.  b.cond reaches
   +-1 MiB, not enough for large programs, so the condition is
   inverted to skip an unconditional b (+-128 MiB).  cond is the
   AArch64 condition code of the taken branch. */

#define COND_EQ ( 0)
#define COND_NE ( 1)
#define COND_HS ( 2)
#define COND_LO ( 3)
#define COND_HI ( 8)
#define COND_LS ( 9)
#define COND_GE (10)
#define COND_LT (11)
#define COND_GT (12)
#define COND_LE (13)

static void
emit_branch( fd_transpiler_t * Dst,
             int               cond,
             ulong             target ) {
  switch( cond ) {
  case COND_EQ:
    //| bne >8
    dasm_put(Dst, 1507);
#line 1121 "fd_transpile_arm64.dasc"
                break;
  case COND_NE:
    //| beq >8
    dasm_put(Dst, 1510);
#line 1124 "fd_transpile_arm64.dasc"
                break;
  case COND_HS:
    //| blo >8
    dasm_put(Dst, 1513);
#line 1127 "fd_transpile_arm64.dasc"
                break;
  case COND_LO:
    //| bhs >8
    dasm_put(Dst, 1516);
#line 1130 "fd_transpile_arm64.dasc"
                break;
  case COND_HI:
    //| bls >8
    dasm_put(Dst, 1519);
#line 1133 "fd_transpile_arm64.dasc"
                break;
  case COND_LS:
    //| bhi >8
    dasm_put(Dst, 1522);
#line 1136 "fd_transpile_arm64.dasc"
                break;
  case COND_GE:
    //| blt >8
    dasm_put(Dst, 1525);
#line 1139 "fd_transpile_arm64.dasc"
                break;
  case COND_LT:
    //| bge >8
    dasm_put(Dst, 1528);
#line 1142 "fd_transpile_arm64.dasc"
                break;
  case COND_GT:
    //| ble >8
    dasm_put(Dst, 1531);
#line 1145 "fd_transpile_arm64.dasc"
                break;
  default:
    //| bgt >8
    dasm_put(Dst, 1534);
#line 1148 "fd_transpile_arm64.dasc"
                break;
  }
  //| b =>target
  //|8:
  dasm_put(Dst, 1537, target);
#line 1152 "fd_transpile_arm64.dasc"
}

/* emit_jcc: compare and branch, covering the J* opcode family.
   is_set selects JSET (tst) over cmp. */

static void
emit_jcc( fd_transpiler_t * Dst,
          int               cond,
          int               is_set,
          int               is_imm,
          int               is64,
          uint              rd,
          uint              rs,
          uint              imm,
          ulong             target ) {
  if( is_set ) {
    if( is_imm ) {
      emit_logic_imm( Dst, LOGIC_TST, is64, rd, is64 ? (ulong)(long)(int)imm : (ulong)imm );
    } else if( is64 ) {
      //| tst Rx(rd), Rx(rs)
      dasm_put(Dst, 1541, (rd), (rs));
#line 1172 "fd_transpile_arm64.dasc"
    } else {
      //| tst Rw(rd), Rw(rs)
      dasm_put(Dst, 1545, (rd), (rs));
#line 1174 "fd_transpile_arm64.dasc"
    }
  } else if( is_imm ) {
    emit_cmp_imm( Dst, is64, rd, imm );
  } else if( is64 ) {
    //| cmp Rx(rd), Rx(rs)
    dasm_put(Dst, 1549, (rd), (rs));
#line 1179 "fd_transpile_arm64.dasc"
  } else {
    //| cmp Rw(rd), Rw(rs)
    dasm_put(Dst, 1553, (rd), (rs));
#line 1181 "fd_transpile_arm64.dasc"
  }
  emit_branch( Dst, cond, target );
}

/* syms_compute: see fd_transpile_x86.dasc */

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
    if( !addr ) continue;
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
  memset( Dst, 0, sizeof(fd_transpiler_t) );
  Dst->bpf_text_cnt = bpf_text_cnt;
  Dst->reloc_cnt    = 0UL;

  ulong dasm_lbl = bpf_text_cnt;
  Dst->dasm_lbl_thunk0 = dasm_lbl;
  dasm_lbl += bpf_text_cnt;
  Dst->dasm_lbl_sys0 = dasm_lbl;
  dasm_lbl += FD_SBPF_SYSCALLS_SLOT_CNT;
  dasm_lbl++;
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

  ulong   bb_word_cnt   = (bpf_text_cnt+63UL)>>6;
  ulong * bpf_bb_splits = (ulong *)Dst->rodata;
  Dst->bb_cnt = fd_transpile_bb_splits( bpf_bb_splits, sbpf_version, (ulong const *)bpf_text, bpf_text_cnt, bpf_entry_pc, bpf_calldests, bpf_rodata, bpf_rodata_sz, bpf_text_off );
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
  dasm_put(Dst, 1557);
#line 1324 "fd_transpile_arm64.dasc"
  //| ldr x9, [x0, #offsetof(fd_vm_t, cu)]
  //| tbz x9, #63, >1
  //| mov w0, #(uint)(-FD_VM_ERR_INVAL)
  //| neg w0, w0
  //| ret
  //|1:
  //| // root stack frame:
  //| //   [x29+ 8]: return address (C caller)
  //| //   [x29+ 0]: caller x29
  //| //   [x29- 8]: root frame pointer (self)
  //| //   [x29-16..x29-64]: callee-saved x19..x24 (6 regs, 48 bytes)
  //| //   [x29-72]: alignment pad
  //| sub sp, sp, #80
  //| stp x29, x30, [sp, #64]
  //| add x29, sp, #64
  //| str x29, [sp, #56]
  //| stp x19, x20, [sp, #40]
  //| stp x21, x22, [sp, #24]
  //| stp x23, x24, [sp, #8]
  //| mov x19, x0
  //| cu_restore
  //| mmu_tlb_invalidate
  //| ldr x9, vm->stack_clean
  //| lsr x9, x9, #12
  //| str x9, vm->transpiled.frame_clean_cnt
  //| ldr x10, vm->frame_cnt
  //| frame_haddr_update
  //| bl ->regs_restore
  //| ldr x9, vm->transpiled.frame_clean_cnt
  //| cmp x10, x9
  //| blo >1
  //| bl ->bpfcall_frame_init
  //|1:
  //| bl >2
  //| brk #0
  //|2:
  //| sbpf_frame_enter
  //| b =>bpf_entry_pc
  dasm_put(Dst, 1558, offsetof(fd_vm_t, cu), (uint)(-FD_VM_ERR_INVAL), Dt1(->ic), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), Dt1(->transpiled.tlb_vaddr_lo), Dt1(->stack_clean), Dt1(->transpiled.frame_clean_cnt), Dt1(->frame_cnt), Dt1(->region_haddr[FD_VM_STACK_REGION]), Dt1(->transpiled.frame_haddr), Dt1(->transpiled.frame_clean_cnt), bpf_entry_pc);
#line 1362 "fd_transpile_arm64.dasc"

  static uchar const bpf_arm_reg[] = {
    /* r0  */  0U,
    /* r1  */  1U,
    /* r2  */  2U,
    /* r3  */  3U,
    /* r4  */  4U,
    /* r5  */  5U,
    /* r6  */ 20U,
    /* r7  */ 21U,
    /* r8  */ 22U,
    /* r9  */ 23U,
    /* r10 */ 24U
  };

  int   has_callx = 0;
  ulong bb_start  = 0UL;
  ulong bb_lddw   = 0UL;
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
    uint rd = bpf_arm_reg[ dst ];
    uint rs = bpf_arm_reg[ src ];
    ulong imm64 = (ulong)(long)(int)imm;

    if( bpf_bb_splits[ pc>>6 ] & (1UL<<( pc&63UL )) ) {
      if( pc>bb_start ) emit_cu_charge( Dst, pc-bb_start-bb_lddw );
      bb_start = pc;
      bb_lddw  = 0UL;
    }
    //|=>pc:
    dasm_put(Dst, 1621, pc);
#line 1403 "fd_transpile_arm64.dasc"

    int is_branch = ( ( (opcode&7UL)==5UL ) |
                      ( (opcode&7UL)==6UL ) ) &
                    ( opcode!=0x85UL ) &
                    ( opcode!=0x8dUL );
    if( is_branch ) {
      emit_cu_charge( Dst, pc+1UL-bb_start-bb_lddw );
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
    }

    if( (opcode&7UL)==6UL && !FD_VM_SBPF_ENABLE_JMP32( sbpf_version ) ) {
      FD_LOG_WARNING(( "invalid opcode 0x%02lx at pc %lu", opcode, pc ));
      return -1;
    }

    ulong jmp_dst = 0UL;
    if( is_branch && opcode!=0x95UL ) {
      long jd = (long)pc + 1L + offset;
      if( FD_UNLIKELY( jd<0L || jd>=(long)bpf_text_cnt ||
                       fd_vm_instr_opcode( FD_LOAD( ulong, bpf_text + (jd<<3) ) )==0x00UL ) ) {
        FD_LOG_WARNING(( "invalid jump target at pc %lu", pc ));
        return -1;
      }
      jmp_dst = (ulong)jd;
    }

    /* cost marker: block CUs consumed including this instruction */
    ulong cost = pc+1UL-bb_start-bb_lddw;

    switch( opcode ) {

    /* Memory accesses.  Loads of less than 8 bytes zero extend by
       writing a w register. */

    case 0x61: case 0x69: case 0x71: case 0x79: { /* LDX{W,H,B,DW} */
      ulong width = opcode==0x61 ? 4UL : opcode==0x69 ? 2UL : opcode==0x71 ? 1UL : 8UL;
      emit_mem_addr( Dst, is_stack_frame_access( sbpf_version, src, offset, width ), 0, width, rs, offset, cost );
      emit_load( Dst, width, rd );
      break;
    }
    case 0x62: case 0x6a: case 0x72: case 0x7a: { /* ST{W,H,B,DW} */
      ulong width = opcode==0x62 ? 4UL : opcode==0x6a ? 2UL : opcode==0x72 ? 1UL : 8UL;
      emit_mem_addr( Dst, is_stack_frame_access( sbpf_version, dst, offset, width ), 1, width, rd, offset, cost );
      emit_const64( Dst, SCR2, width==8UL ? imm64 : (ulong)imm );
      emit_store( Dst, width, SCR2 );
      break;
    }
    case 0x63: case 0x6b: case 0x73: case 0x7b: { /* STX{W,H,B,DW} */
      ulong width = opcode==0x63 ? 4UL : opcode==0x6b ? 2UL : opcode==0x73 ? 1UL : 8UL;
      emit_mem_addr( Dst, is_stack_frame_access( sbpf_version, dst, offset, width ), 1, width, rd, offset, cost );
      emit_store( Dst, width, rs );
      break;
    }

    case 0x18: { /* LDDW */
      pc++;
      bb_lddw++;
      ulong ins1 = FD_LOAD( ulong, bpf_text + (pc<<3) );
      ulong v = (ulong)imm | ((ulong)fd_vm_instr_imm( ins1 ) << 32);
      emit_const64( Dst, rd, v );
      break;
    }

    /* ALU.  32 bit add/sub/mul results are sign extended to 64 bits
       (pre SIMD-0174 semantics, the only ones v0/v1/v3 use); other
       32 bit ops zero extend, which w-register writes do for free. */

    case 0x04: /* ADD32_IMM */
      emit_addsub_imm( Dst, 1, 0, rd, imm );
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1623, (rd), (rd));
#line 1474 "fd_transpile_arm64.dasc"
      break;
    case 0x07: /* ADD64_IMM */
      emit_addsub_imm( Dst, 1, 1, rd, imm );
      break;
    case 0x0c: /* ADD32_REG */
      //| add Rw(rd), Rw(rd), Rw(rs)
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1627, (rd), (rd), (rs), (rd), (rd));
#line 1481 "fd_transpile_arm64.dasc"
      break;
    case 0x0f: /* ADD64_REG */
      //| add Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1635, (rd), (rd), (rs));
#line 1484 "fd_transpile_arm64.dasc"
      break;
    case 0x14: /* SUB32_IMM */
      emit_addsub_imm( Dst, 0, 0, rd, imm );
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1640, (rd), (rd));
#line 1488 "fd_transpile_arm64.dasc"
      break;
    case 0x17: /* SUB64_IMM */
      emit_addsub_imm( Dst, 0, 1, rd, imm );
      break;
    case 0x1c: /* SUB32_REG */
      //| sub Rw(rd), Rw(rd), Rw(rs)
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1644, (rd), (rd), (rs), (rd), (rd));
#line 1495 "fd_transpile_arm64.dasc"
      break;
    case 0x1f: /* SUB64_REG */
      //| sub Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1652, (rd), (rd), (rs));
#line 1498 "fd_transpile_arm64.dasc"
      break;
    case 0x24: /* MUL32_IMM */
      emit_const32( Dst, SCR0, imm );
      //| mul Rw(rd), Rw(rd), w9
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1657, (rd), (rd), (rd), (rd));
#line 1503 "fd_transpile_arm64.dasc"
      break;
    case 0x27: /* MUL64_IMM */
      emit_const64( Dst, SCR0, imm64 );
      //| mul Rx(rd), Rx(rd), x9
      dasm_put(Dst, 1664, (rd), (rd));
#line 1507 "fd_transpile_arm64.dasc"
      break;
    case 0x2c: /* MUL32_REG */
      //| mul Rw(rd), Rw(rd), Rw(rs)
      //| sxtw Rx(rd), Rw(rd)
      dasm_put(Dst, 1668, (rd), (rd), (rs), (rd), (rd));
#line 1511 "fd_transpile_arm64.dasc"
      break;
    case 0x2f: /* MUL64_REG */
      //| mul Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1676, (rd), (rd), (rs));
#line 1514 "fd_transpile_arm64.dasc"
      break;
    case 0x34: /* DIV32_IMM */
      emit_udiv32_imm( Dst, rd, imm, 0 );
      break;
    case 0x37: /* DIV64_IMM */
      emit_udiv64_imm( Dst, rd, imm, 0 );
      break;
    case 0x3c: /* DIV32_REG */
      //| cbnz Rw(rs), >1
      dasm_put(Dst, 1681, (rs));
#line 1523 "fd_transpile_arm64.dasc"
      emit_const32( Dst, SCR0, (uint)cost );
      //| b ->exception_div_zero
      //|1:
      //| udiv Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1685, (rd), (rd), (rs));
#line 1527 "fd_transpile_arm64.dasc"
      break;
    case 0x3f: /* DIV64_REG */
      //| cbnz Rx(rs), >1
      dasm_put(Dst, 1693, (rs));
#line 1530 "fd_transpile_arm64.dasc"
      emit_const32( Dst, SCR0, (uint)cost );
      //| b ->exception_div_zero
      //|1:
      //| udiv Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1697, (rd), (rd), (rs));
#line 1534 "fd_transpile_arm64.dasc"
      break;
    case 0x44: /* OR32_IMM */
      emit_logic_imm( Dst, LOGIC_ORR, 0, rd, (ulong)imm );
      break;
    case 0x47: /* OR64_IMM */
      emit_logic_imm( Dst, LOGIC_ORR, 1, rd, imm64 );
      break;
    case 0x4c: /* OR32_REG */
      //| orr Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1705, (rd), (rd), (rs));
#line 1543 "fd_transpile_arm64.dasc"
      break;
    case 0x4f: /* OR64_REG */
      //| orr Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1710, (rd), (rd), (rs));
#line 1546 "fd_transpile_arm64.dasc"
      break;
    case 0x54: /* AND32_IMM */
      emit_logic_imm( Dst, LOGIC_AND, 0, rd, (ulong)imm );
      break;
    case 0x57: /* AND64_IMM */
      emit_logic_imm( Dst, LOGIC_AND, 1, rd, imm64 );
      break;
    case 0x5c: /* AND32_REG */
      //| and Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1715, (rd), (rd), (rs));
#line 1555 "fd_transpile_arm64.dasc"
      break;
    case 0x5f: /* AND64_REG */
      //| and Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1720, (rd), (rd), (rs));
#line 1558 "fd_transpile_arm64.dasc"
      break;
    case 0x64: /* LSH32_IMM */
      //| lsl Rw(rd), Rw(rd), #(imm&31U)
      dasm_put(Dst, 1725, (rd), (rd), (32-((imm&31U)))%32, 31-((imm&31U)));
#line 1561 "fd_transpile_arm64.dasc"
      break;
    case 0x67: /* LSH64_IMM */
      //| lsl Rx(rd), Rx(rd), #(imm&63U)
      dasm_put(Dst, 1731, (rd), (rd), (64-((imm&63U)))%64, 63-((imm&63U)));
#line 1564 "fd_transpile_arm64.dasc"
      break;
    case 0x6c: /* LSH32_REG */
      //| lsl Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1737, (rd), (rd), (rs));
#line 1567 "fd_transpile_arm64.dasc"
      break;
    case 0x6f: /* LSH64_REG */
      //| lsl Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1742, (rd), (rd), (rs));
#line 1570 "fd_transpile_arm64.dasc"
      break;
    case 0x74: /* RSH32_IMM */
      //| lsr Rw(rd), Rw(rd), #(imm&31U)
      dasm_put(Dst, 1747, (rd), (rd), (imm&31U));
#line 1573 "fd_transpile_arm64.dasc"
      break;
    case 0x77: /* RSH64_IMM */
      //| lsr Rx(rd), Rx(rd), #(imm&63U)
      dasm_put(Dst, 1752, (rd), (rd), (imm&63U));
#line 1576 "fd_transpile_arm64.dasc"
      break;
    case 0x7c: /* RSH32_REG */
      //| lsr Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1757, (rd), (rd), (rs));
#line 1579 "fd_transpile_arm64.dasc"
      break;
    case 0x7f: /* RSH64_REG */
      //| lsr Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1762, (rd), (rd), (rs));
#line 1582 "fd_transpile_arm64.dasc"
      break;
    case 0x84: /* NEG32 */
      //| neg Rw(rd), Rw(rd)
      dasm_put(Dst, 1767, (rd), (rd));
#line 1585 "fd_transpile_arm64.dasc"
      break;
    case 0x87: /* NEG64 */
      //| neg Rx(rd), Rx(rd)
      dasm_put(Dst, 1771, (rd), (rd));
#line 1588 "fd_transpile_arm64.dasc"
      break;
    case 0x94: /* MOD32_IMM */
      emit_udiv32_imm( Dst, rd, imm, 1 );
      break;
    case 0x97: /* MOD64_IMM */
      emit_udiv64_imm( Dst, rd, imm, 1 );
      break;
    case 0x9c: /* MOD32_REG */
      //| cbnz Rw(rs), >1
      dasm_put(Dst, 1775, (rs));
#line 1597 "fd_transpile_arm64.dasc"
      emit_const32( Dst, SCR0, (uint)cost );
      //| b ->exception_div_zero
      //|1:
      //| udiv w9, Rw(rd), Rw(rs)
      //| msub Rw(rd), w9, Rw(rs), Rw(rd)
      dasm_put(Dst, 1779, (rd), (rs), (rd), (rs), (rd));
#line 1602 "fd_transpile_arm64.dasc"
      break;
    case 0x9f: /* MOD64_REG */
      //| cbnz Rx(rs), >1
      dasm_put(Dst, 1790, (rs));
#line 1605 "fd_transpile_arm64.dasc"
      emit_const32( Dst, SCR0, (uint)cost );
      //| b ->exception_div_zero
      //|1:
      //| udiv x9, Rx(rd), Rx(rs)
      //| msub Rx(rd), x9, Rx(rs), Rx(rd)
      dasm_put(Dst, 1794, (rd), (rs), (rd), (rs), (rd));
#line 1610 "fd_transpile_arm64.dasc"
      break;
    case 0xa4: /* XOR32_IMM */
      emit_logic_imm( Dst, LOGIC_EOR, 0, rd, (ulong)imm );
      break;
    case 0xa7: /* XOR64_IMM */
      emit_logic_imm( Dst, LOGIC_EOR, 1, rd, imm64 );
      break;
    case 0xac: /* XOR32_REG */
      //| eor Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1805, (rd), (rd), (rs));
#line 1619 "fd_transpile_arm64.dasc"
      break;
    case 0xaf: /* XOR64_REG */
      //| eor Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1810, (rd), (rd), (rs));
#line 1622 "fd_transpile_arm64.dasc"
      break;
    case 0xb4: /* MOV32_IMM */
      emit_const32( Dst, rd, imm );
      break;
    case 0xb7: /* MOV64_IMM */
      emit_const64( Dst, rd, imm64 );
      break;
    case 0xbc: /* MOV32_REG */
      //| mov Rw(rd), Rw(rs)
      dasm_put(Dst, 1815, (rd), (rs));
#line 1631 "fd_transpile_arm64.dasc"
      break;
    case 0xbf: /* MOV64_REG */
      //| mov Rx(rd), Rx(rs)
      dasm_put(Dst, 1819, (rd), (rs));
#line 1634 "fd_transpile_arm64.dasc"
      break;
    case 0xc4: /* ARSH32_IMM */
      //| asr Rw(rd), Rw(rd), #(imm&31U)
      dasm_put(Dst, 1823, (rd), (rd), (imm&31U));
#line 1637 "fd_transpile_arm64.dasc"
      break;
    case 0xc7: /* ARSH64_IMM */
      //| asr Rx(rd), Rx(rd), #(imm&63U)
      dasm_put(Dst, 1828, (rd), (rd), (imm&63U));
#line 1640 "fd_transpile_arm64.dasc"
      break;
    case 0xcc: /* ARSH32_REG */
      //| asr Rw(rd), Rw(rd), Rw(rs)
      dasm_put(Dst, 1833, (rd), (rd), (rs));
#line 1643 "fd_transpile_arm64.dasc"
      break;
    case 0xcf: /* ARSH64_REG */
      //| asr Rx(rd), Rx(rd), Rx(rs)
      dasm_put(Dst, 1838, (rd), (rd), (rs));
#line 1646 "fd_transpile_arm64.dasc"
      break;
    case 0xd4: /* END_LE */
      if( imm==16U ) {
        //| uxth Rw(rd), Rw(rd)
        dasm_put(Dst, 1843, (rd), (rd));
#line 1650 "fd_transpile_arm64.dasc"
      } else if( imm==32U ) {
        //| mov Rw(rd), Rw(rd)
        dasm_put(Dst, 1847, (rd), (rd));
#line 1652 "fd_transpile_arm64.dasc"
      }
      break;
    case 0xdc: /* END_BE */
      if( imm==16U ) {
        //| rev16 Rw(rd), Rw(rd)
        //| uxth Rw(rd), Rw(rd)
        dasm_put(Dst, 1851, (rd), (rd), (rd), (rd));
#line 1658 "fd_transpile_arm64.dasc"
      } else if( imm==32U ) {
        //| rev Rw(rd), Rw(rd)
        dasm_put(Dst, 1858, (rd), (rd));
#line 1660 "fd_transpile_arm64.dasc"
      } else {
        //| rev Rx(rd), Rx(rd)
        dasm_put(Dst, 1862, (rd), (rd));
#line 1662 "fd_transpile_arm64.dasc"
      }
      break;

    /* Branches.  Opcode bits: 0x?5 64 bit, 0x?6 32 bit; src bit 3
       (0x08) selects the register form. */

    case 0x05: /* JA */
      //| b =>jmp_dst
      dasm_put(Dst, 1866, jmp_dst);
#line 1670 "fd_transpile_arm64.dasc"
      break;
    case 0x15: case 0x16: case 0x1d: case 0x1e: /* JEQ */
      emit_jcc( Dst, COND_EQ, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x25: case 0x26: case 0x2d: case 0x2e: /* JGT */
      emit_jcc( Dst, COND_HI, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x35: case 0x36: case 0x3d: case 0x3e: /* JGE */
      emit_jcc( Dst, COND_HS, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x45: case 0x46: case 0x4d: case 0x4e: /* JSET */
      emit_jcc( Dst, COND_NE, 1, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x55: case 0x56: case 0x5d: case 0x5e: /* JNE */
      emit_jcc( Dst, COND_NE, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x65: case 0x66: case 0x6d: case 0x6e: /* JSGT */
      emit_jcc( Dst, COND_GT, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0x75: case 0x76: case 0x7d: case 0x7e: /* JSGE */
      emit_jcc( Dst, COND_GE, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0xa5: case 0xa6: case 0xad: case 0xae: /* JLT */
      emit_jcc( Dst, COND_LO, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0xb5: case 0xb6: case 0xbd: case 0xbe: /* JLE */
      emit_jcc( Dst, COND_LS, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0xc5: case 0xc6: case 0xcd: case 0xce: /* JSLT */
      emit_jcc( Dst, COND_LT, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;
    case 0xd5: case 0xd6: case 0xdd: case 0xde: /* JSLE */
      emit_jcc( Dst, COND_LE, 0, !(opcode&8UL), (opcode&7UL)==5UL, rd, rs, imm, jmp_dst ); break;

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
      emit_cu_sub( Dst, cost );
      if( sys ) {
        ulong slot_idx = (ulong)( sys-syscalls );
        syscall_used[ slot_idx >> 6 ] |= 1UL<<( slot_idx & 63UL );
        emit_const64( Dst, SCR0, pc );
        //| str x9, vm->pc
        //| bl =>(Dst->dasm_lbl_sys0 + slot_idx)
        dasm_put(Dst, 1869, Dt1(->pc), (Dst->dasm_lbl_sys0 + slot_idx));
#line 1727 "fd_transpile_arm64.dasc"
      } else if( target_pc>=0L ) {
        ulong tpc = (ulong)target_pc;
        if( fd_vm_instr_opcode( FD_LOAD( ulong, bpf_text + (tpc<<3) ) )==0x00UL ) {
          //| b ->exception_ill
          dasm_put(Dst, 1874);
#line 1731 "fd_transpile_arm64.dasc"
        } else {
          Dst->thunk_bv[ tpc >> 6 ] |= 1UL<<( tpc & 63UL );
          emit_const64( Dst, SCR0, pc );
          //| str x9, vm->pc
          //| bl =>(Dst->dasm_lbl_thunk0 + tpc)
          dasm_put(Dst, 1877, Dt1(->pc), (Dst->dasm_lbl_thunk0 + tpc));
#line 1736 "fd_transpile_arm64.dasc"
        }
      } else {
        //| b ->exception_ill
        dasm_put(Dst, 1882);
#line 1739 "fd_transpile_arm64.dasc"
      }
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
      break;
    }
    case 0x8d: { /* CALLX */
      has_callx = 1;
      ulong callx_reg =
          FD_VM_SBPF_CALLX_USES_SRC_REG( sbpf_version ) ? src :
          FD_VM_SBPF_CALLX_USES_DST_REG( sbpf_version ) ? dst :
          (ulong)imm;
      if( FD_UNLIKELY( callx_reg>9UL ) ) {
        FD_LOG_WARNING(( "invalid callx register at pc %lu", pc ));
        return -1;
      }
      emit_cu_sub( Dst, cost );
      emit_const64( Dst, SCR0, pc );
      //| str x9, vm->pc
      //| mov x10, Rx(bpf_arm_reg[callx_reg])
      //| bl ->callx
      dasm_put(Dst, 1885, Dt1(->pc), (bpf_arm_reg[callx_reg]));
#line 1759 "fd_transpile_arm64.dasc"
      bb_start = pc+1UL;
      bb_lddw  = 0UL;
      break;
    }
    case 0x95: /* EXIT */
      //| b ->bpfcall_frame_pop
      dasm_put(Dst, 1892);
#line 1765 "fd_transpile_arm64.dasc"
      break;

    default:
      FD_LOG_WARNING(( "invalid opcode 0x%02lx at pc %lu", opcode, pc ));
      return -1;
    }
  }

  /* Execution fell off the end of the text segment */
  if( bb_start<bpf_text_cnt ) emit_cu_charge( Dst, bpf_text_cnt-bb_start-bb_lddw );
  //| bl ->regs_save
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_EXECUTION_OVERRUN)
  //| neg w10, w10
  //| mov w9, #1
  //| b ->exception_charge
  //|=>(Dst->dasm_lbl_reloc0-1UL):
  dasm_put(Dst, 1895, (uint)(-FD_VM_ERR_EBPF_EXECUTION_OVERRUN), (Dst->dasm_lbl_reloc0-1UL));
#line 1781 "fd_transpile_arm64.dasc"

  emit_mmu_routines( Dst );

  /* BPF-to-BPF call thunks */

  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    if( Dst->thunk_bv[ pc>>6 ] & (1UL<<( pc&63UL )) ) {
      //|=>(Dst->dasm_lbl_thunk0 + pc):
      //| sbpf_frame_enter
      //| bl ->bpfcall_frame_push
      //| cbnz w10, ->call_imm_depth
      //| b =>pc
      dasm_put(Dst, 1905, (Dst->dasm_lbl_thunk0 + pc), pc);
#line 1793 "fd_transpile_arm64.dasc"
    }
  }

  for( ulong word_idx=0UL; word_idx<(FD_SBPF_SYSCALLS_SLOT_CNT>>6); word_idx++ ) {
    ulong word = syscall_used[ word_idx ];
    while( word ) {
      int bit = fd_ulong_find_lsb( word );
      word &= ~(1UL<<bit);
      ulong slot_idx = (word_idx<<6) + (ulong)bit;
      //|=>(Dst->dasm_lbl_sys0 + slot_idx):
      dasm_put(Dst, 1918, (Dst->dasm_lbl_sys0 + slot_idx));
#line 1803 "fd_transpile_arm64.dasc"
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
  //| // w9: CUs consumed by the current block so far (incl. this instr)
  //| bl ->regs_save
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_DIVIDE_BY_ZERO)
  //| neg w10, w10
  //| b ->exception_charge
  dasm_put(Dst, 1920, (uint)(-FD_VM_ERR_EBPF_DIVIDE_BY_ZERO));
#line 1821 "fd_transpile_arm64.dasc"

  //|->exception_segfault:
  //| // x10: negative FD_VM_ERR_EBPF_* code from mmu_tlb_miss
  //| // x30: return address into the body, followed by `mov w9, #cost`
  //| ldr w9, [x30]
  //| ubfx w9, w9, #5, #16        // movz w9, #lo16
  //| ldr w11, [x30, #4]
  //| and w12, w11, #0xffe0001f
  //| mov w16, #0x0009
  //| movk w16, #0x72a0, lsl #16  // movk w9, #hi16, lsl #16
  //| cmp w12, w16
  //| bne >1
  //| ubfx w11, w11, #5, #16
  //| add w9, w9, w11, lsl #16
  //|1:
  //| bl ->regs_save
  //| b ->exception_charge
  dasm_put(Dst, 1929);
#line 1838 "fd_transpile_arm64.dasc"

  //|->exception_ill:
  //| bl ->regs_save
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION)
  //| neg w10, w10
  //| mov x9, xzr
  //| b ->exception_charge
  dasm_put(Dst, 1947, (uint)(-FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION));
#line 1845 "fd_transpile_arm64.dasc"

  //|->exception_cost:
  //| bl ->regs_save
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS)
  //| neg w10, w10
  //| mov x9, xzr
  //| // fall through
  dasm_put(Dst, 1957, (uint)(-FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS));
#line 1852 "fd_transpile_arm64.dasc"

  //|->exception_charge:
  //| // Bills the pending block and unwinds.  BPF registers saved.
  //| // - w10: error code
  //| // - x9:  CUs consumed by the pending block so far
  //| ldr x11, vm->cu
  //| sub x11, x11, x9
  //| str x11, vm->cu
  //| cu_save
  //| ldr x11, vm->cu
  //| tbz x11, #63, >1
  //| str xzr, vm->cu
  //| mov w10, #(uint)(-FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS)
  //| neg w10, w10
  //|1:
  //| b ->unwind
  dasm_put(Dst, 1965, Dt1(->cu), Dt1(->cu), Dt1(->transpiled.ic_cu_anchor), Dt1(->cu), Dt1(->ic), Dt1(->cu), Dt1(->cu), (uint)(-FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS));
#line 1868 "fd_transpile_arm64.dasc"

  //|->unwind:
  //| // - w10: return value
  //| // - x29: any transpiled frame (sBPF function or root)
  //| ldr x29, [x29, #-8] // root frame
  //| mov w0, w10
  //| sub sp, x29, #64
  //| ldp x23, x24, [sp, #8]
  //| ldp x21, x22, [sp, #24]
  //| ldp x19, x20, [sp, #40]
  //| ldp x29, x30, [sp, #64]
  //| add sp, sp, #80
  //| ret
  dasm_put(Dst, 1991);
#line 1881 "fd_transpile_arm64.dasc"

  size_t code_sz;
  int link_res = dasm_link( Dst, &code_sz );
  if( link_res!=0 ) {
    FD_LOG_WARNING(( "dasm_link failed: %#x", (uint)link_res ));
    return -1;
  }
  if( FD_UNLIKELY( code_sz > FD_TRANSPILER_CODE_MAX ) ) {
    FD_LOG_WARNING(( "transpiled code is too big: %lu bytes larger than FD_TRANSPILER_CODE_MAX", code_sz-FD_TRANSPILER_CODE_MAX ));
    return -1;
  }

  int enc_res = dasm_encode( Dst, Dst->code );
  if( enc_res!=0 ) {
    FD_LOG_WARNING(( "dasm_encode failed: %#x", (uint)enc_res ));
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

  /* Basic block tables */
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
        .r_info   = FD_ELF64_R_INFO( FD_VM_TRANSPILE_SYM_TEXT, FD_TRANSPILE_R_PCREL32 ),
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
