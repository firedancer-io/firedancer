@
@ The eXtended Keccak Code Package (XKCP)
@ https://github.com/XKCP/XKCP
@
@ The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.
@
@ Implementation by Ronny Van Keer, hereby denoted as "the implementer".
@
@ For more information, feedback or questions, please refer to the Keccak Team website:
@ https://keccak.team/
@
@ To the extent possible under law, the implementer has waived all copyright
@ and related or neighboring rights to the source code in this file.
@ http://creativecommons.org/publicdomain/zero/1.0/
@
@ ---
@
@ This file implements Keccak-p[1600] in a SnP-compatible way.
@ Please refer to SnP-documentation.h for more details.
@
@ This implementation comes with KeccakP-1600-SnP.h in the same folder.
@ Please refer to LowLevel.build for the exact list of other files it must be combined with.
@

@ WARNING: These functions work only on little endian CPU with@ ARMv7A + NEON architecture
@ WARNING: State must be 256 bit (32 bytes) aligned, best is 64-byte (cache alignment).
@ INFO: Tested on Cortex-A8 (BeagleBone Black), using gcc.


.text

@ conditional assembly settings
.equ LoopUnroll , 1   @ possible values 1, 2, 4, 6, 12

@ offsets in state
.equ _ba    , 0*8
.equ _be    , 1*8
.equ _bi    , 2*8
.equ _bo    , 3*8
.equ _bu    , 4*8
.equ _ga    , 5*8
.equ _ge    , 6*8
.equ _gi    , 7*8
.equ _go    , 8*8
.equ _gu    , 9*8
.equ _ka    , 10*8
.equ _ke    , 11*8
.equ _ki    , 12*8
.equ _ko    , 13*8
.equ _ku    , 14*8
.equ _ma    , 15*8
.equ _me    , 16*8
.equ _mi    , 17*8
.equ _mo    , 18*8
.equ _mu    , 19*8
.equ _sa    , 20*8
.equ _se    , 21*8
.equ _si    , 22*8
.equ _so    , 23*8
.equ _su    , 24*8

@ macros

.macro    LoadState
    vld1.64 d0, [r0:64]!
    vld1.64 d2, [r0:64]!
    vld1.64 d4, [r0:64]!
    vld1.64 d6, [r0:64]!
    vld1.64 d8, [r0:64]!
    vld1.64 d1, [r0:64]!
    vld1.64 d3, [r0:64]!
    vld1.64 d5, [r0:64]!
    vld1.64 d7, [r0:64]!
    vld1.64 d9, [r0:64]!
    vld1.64 d10, [r0:64]!
    vld1.64 d12, [r0:64]!
    vld1.64 d14, [r0:64]!
    vld1.64 d16, [r0:64]!
    vld1.64 d18, [r0:64]!
    vld1.64 d11, [r0:64]!
    vld1.64 d13, [r0:64]!
    vld1.64 d15, [r0:64]!
    vld1.64 d17, [r0:64]!
    vld1.64 d19, [r0:64]!
    vld1.64 { d20, d21 }, [r0:128]!
    vld1.64 { d22, d23 }, [r0:128]!
    vld1.64 d24, [r0:64]
    sub     r0, r0, #24*8
    .endm

.macro    StoreState
    vst1.64 d0, [r0:64]!
    vst1.64 d2, [r0:64]!
    vst1.64 d4, [r0:64]!
    vst1.64 d6, [r0:64]!
    vst1.64 d8, [r0:64]!
    vst1.64 d1, [r0:64]!
    vst1.64 d3, [r0:64]!
    vst1.64 d5, [r0:64]!
    vst1.64 d7, [r0:64]!
    vst1.64 d9, [r0:64]!
    vst1.64 d10, [r0:64]!
    vst1.64 d12, [r0:64]!
    vst1.64 d14, [r0:64]!
    vst1.64 d16, [r0:64]!
    vst1.64 d18, [r0:64]!
    vst1.64 d11, [r0:64]!
    vst1.64 d13, [r0:64]!
    vst1.64 d15, [r0:64]!
    vst1.64 d17, [r0:64]!
    vst1.64 d19, [r0:64]!
    vst1.64 { d20, d21 }, [r0:128]!
    vst1.64 { d22, d23 }, [r0:128]!
    vst1.64 d24, [r0:64]
    .endm

.macro    RhoPi4      dst1, src1, rot1, dst2, src2, rot2, dst3, src3, rot3, dst4, src4, rot4
    .if (\rot1  &  7) != 0
    vshl.u64    \dst1, \src1, #\rot1
    .else
    vext.8      \dst1, \src1, \src1, #8-\rot1/8
    .endif
    .if (\rot2  &  7) != 0
    vshl.u64    \dst2, \src2, #\rot2
    .else
    vext.8      \dst2, \src2, \src2, #8-\rot2/8
    .endif
    .if (\rot3  &  7) != 0
    vshl.u64    \dst3, \src3, #\rot3
    .else
    vext.8      \dst3, \src3, \src3, #8-\rot3/8
    .endif
    .if (\rot4  &  7) != 0
    vshl.u64    \dst4, \src4, #\rot4
    .else
    vext.8      \dst4, \src4, \src4, #8-\rot4/8
    .endif
    .if (\rot1  &  7) != 0
    vsri.u64    \dst1, \src1, #64-\rot1
    .endif
    .if (\rot2  &  7) != 0
    vsri.u64    \dst2, \src2, #64-\rot2
    .endif
    .if (\rot3  &  7) != 0
    vsri.u64    \dst3, \src3, #64-\rot3
    .endif
    .if (\rot4  &  7) != 0
    vsri.u64    \dst4, \src4, #64-\rot4
    .endif
    .endm

.macro    KeccakRound

    @Prepare Theta
    veor.64     q13, q0, q5
    vst1.64     {q12}, [r0:128]!
    veor.64     q14, q1, q6
    vst1.64     {q4}, [r0:128]!
    veor.64     d26,  d26,  d27
    vst1.64     {q9}, [r0:128]
    veor.64     d28,  d28,  d29
    veor.64     d26,  d26,  d20
    veor.64     d27,  d28,  d21

    veor.64     q14, q2, q7
    veor.64     q15, q3, q8
    veor.64     q4, q4, q9
    veor.64     d28,  d28,  d29
    veor.64     d30,  d30,  d31
    veor.64     d25,  d8,  d9
    veor.64     d28,  d28,  d22
    veor.64     d29,  d30,  d23
    veor.64     d25,  d25,  d24
    sub         r0, r0, #32

    @Apply Theta
    vadd.u64    d30,  d27,  d27
    vadd.u64    d24,  d28,  d28
    vadd.u64    d8,  d29,  d29
    vadd.u64    d18,  d25,  d25

    vsri.64     d30,  d27,  #63
    vsri.64     d24,  d28,  #63
    vsri.64     d8,  d29,  #63
    vsri.64     d18,  d25,  #63

    veor.64     d30,  d30,  d25
    veor.64     d24,  d24,  d26
    veor.64     d8,  d8,  d27
    vadd.u64    d27,  d26,  d26   @u
    veor.64     d18,  d18,  d28

    vmov.i64    d31,  d30
    vmov.i64    d25,  d24
    vsri.64     d27,  d26,  #63     @u
    vmov.i64    d9,  d8
    vmov.i64    d19,  d18

    veor.64     d20,  d20,  d30
    veor.64     d21,  d21,  d24
    veor.64     d27,  d27,  d29   @u
    veor.64     d22,  d22,  d8
    veor.64     d23,  d23,  d18
    vmov.i64    d26,  d27           @u

    veor.64     q0, q0, q15
    veor.64     q1, q1, q12
    veor.64     q2, q2, q4
    veor.64     q3, q3, q9

    veor.64     q5, q5, q15
    veor.64     q6, q6, q12
    vld1.64     {q12}, [r0:128]!
    veor.64     q7, q7, q4
    vld1.64     {q4}, [r0:128]!
    veor.64     q8, q8, q9
    vld1.64     {q9}, [r0:128]
    veor.64     d24,  d24,  d26   @u
    sub         r0, r0, #32
    veor.64     q4, q4, q13  @u
    veor.64     q9, q9, q13  @u

    @Rho Pi
    vmov.i64    d27, d2
    vmov.i64    d28, d4
    vmov.i64    d29, d6
    vmov.i64    d25, d8

    RhoPi4      d2, d3, 44, d4, d14, 43, d8, d24, 14, d6, d17, 21  @  1 <  6,  2 < 12,  4 < 24,  3 < 18
    RhoPi4      d3, d9, 20, d14, d16, 25, d24, d21,  2, d17, d15, 15  @  6 <  9, 12 < 13, 24 < 21, 18 < 17
    RhoPi4      d9, d22, 61, d16, d19,  8, d21, d7, 55, d15, d12, 10  @  9 < 22, 13 < 19, 21 <  8, 17 < 11
    RhoPi4      d22, d18, 39, d19, d23, 56, d7, d13, 45, d12, d5,  6  @ 22 < 14, 19 < 23,  8 < 16, 11 < 7
    RhoPi4      d18, d20, 18, d23, d11, 41, d13, d1, 36, d5, d10,  3  @ 14 < 20, 23 < 15, 16 <  5,  7 < 10
    RhoPi4      d20, d28, 62, d11, d25, 27, d1, d29, 28, d10, d27,  1  @ 20 <  2, 15 <  4,  5 <  3, 10 < 1

    @Chi    b+g
    vmov.i64    q13, q0
    vbic.64     q15, q2, q1  @ ba ^= ~be & bi
    veor.64     q0, q15
    vmov.i64    q14, q1
    vbic.64     q15, q3, q2  @ be ^= ~bi & bo
    veor.64     q1, q15
    vbic.64     q15, q4, q3  @ bi ^= ~bo & bu
    veor.64     q2, q15
    vbic.64     q15, q13, q4  @ bo ^= ~bu & ba
    vbic.64     q13, q14, q13  @ bu ^= ~ba & be
    veor.64     q3, q15
    veor.64     q4, q13

    @Chi    k+m
    vmov.i64    q13, q5
    vbic.64     q15, q7, q6  @ ba ^= ~be & bi
    veor.64     q5, q15
    vmov.i64    q14, q6
    vbic.64     q15, q8, q7  @ be ^= ~bi & bo
    veor.64     q6, q15
    vbic.64     q15, q9, q8  @ bi ^= ~bo & bu
    veor.64     q7, q15
    vbic.64     q15, q13, q9  @ bo ^= ~bu & ba
    vbic.64     q13, q14, q13  @ bu ^= ~ba & be
    veor.64     q8, q15
    veor.64     q9, q13

    @Chi    s
    vmov.i64    q13, q10
    vbic.64     d30,  d22,  d21   @ ba ^= ~be & bi
    vbic.64     d31,  d23,  d22   @ be ^= ~bi & bo
    veor.64     q10, q15
    vbic.64     d30,  d24,  d23   @ bi ^= ~bo & bu
    vbic.64     d31,  d26,  d24   @ bo ^= ~bu & ba
    vbic.64     d26,  d27,  d26   @ bu ^= ~ba & be
    veor.64     q11, q15
    vld1.64     d30,   [r1:64]!  @ Iota
    veor.64     d24,  d26
    veor.64     d0, d0, d30     @ Iota
    .endm

@----------------------------------------------------------------------------
@
@ void KeccakP1600_StaticInitialize( void )
@
.align 8
.global   KeccakP1600_StaticInitialize
.type	KeccakP1600_StaticInitialize, %function;
KeccakP1600_StaticInitialize:
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_Initialize(void *state)
@
.align 8
.global   KeccakP1600_Initialize
.type	KeccakP1600_Initialize, %function;
KeccakP1600_Initialize:
    vmov.i64    q0, #0
    vmov.i64    q1, #0
    vmov.i64    q2, #0
    vmov.i64    q3, #0
    vstm        r0!, { d0 - d7 }            @ clear 8 lanes at a time
    vstm        r0!, { d0 - d7 }
    vstm        r0!, { d0 - d7 }
    vstm        r0!, { d0 }
    bx          lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_AddByte(void *state, unsigned char byte, unsigned int offset)
@
.align 8
.global   KeccakP1600_AddByte
.type	KeccakP1600_AddByte, %function;
KeccakP1600_AddByte:
    ldrb    r3, [r0, r2]
    eors    r3, r3, r1
    strb    r3, [r0, r2]
    bx      lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_AddBytes
.type	KeccakP1600_AddBytes, %function;
KeccakP1600_AddBytes:
    push    {r4,lr}
    adds    r0, r0, r2                              @ state += offset
    subs    r3, r3, #8                              @ .if length >= lane size
    bcc     KeccakP1600_AddBytes_Bytes
KeccakP1600_AddBytes_LanesLoop:                      @ then, perform on lanes
    ldr     r2, [r0]
    ldr     r4, [r1], #4
    ldr     r12, [r0, #4]
    ldr     lr, [r1], #4
    eors    r2, r2, r4
    eors    r12, r12, lr
    subs    r3, r3, #8
    str     r2, [r0], #4
    str     r12, [r0], #4
    bcs     KeccakP1600_AddBytes_LanesLoop
KeccakP1600_AddBytes_Bytes:
    adds    r3, r3, #7
    bcc     KeccakP1600_AddBytes_Exit
KeccakP1600_AddBytes_BytesLoop:
    ldrb    r2, [r0]
    ldrb    r4, [r1], #1
    eors    r2, r2, r4
    strb    r2, [r0], #1
    subs    r3, r3, #1
    bcs     KeccakP1600_AddBytes_BytesLoop
KeccakP1600_AddBytes_Exit:
    pop     {r4,pc}


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_OverwriteBytes
.type	KeccakP1600_OverwriteBytes, %function;
KeccakP1600_OverwriteBytes:
    adds    r0, r0, r2                              @ state += offset
    subs    r3, r3, #8                              @ .if length >= lane size
    bcc     KeccakP1600_OverwriteBytes_Bytes
KeccakP1600_OverwriteBytes_LanesLoop:                @ then, perform on lanes
    ldr     r2, [r1], #4
    ldr     r12, [r1], #4
    subs    r3, r3, #8
    str     r2, [r0], #4
    str     r12, [r0], #4
    bcs     KeccakP1600_OverwriteBytes_LanesLoop
KeccakP1600_OverwriteBytes_Bytes:
    adds    r3, r3, #7
    bcc     KeccakP1600_OverwriteBytes_Exit
KeccakP1600_OverwriteBytes_BytesLoop:
    ldrb    r2, [r1], #1
    subs    r3, r3, #1
    strb    r2, [r0], #1
    bcs     KeccakP1600_OverwriteBytes_BytesLoop
KeccakP1600_OverwriteBytes_Exit:
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount)
@
.align 8
.global   KeccakP1600_OverwriteWithZeroes
.type	KeccakP1600_OverwriteWithZeroes, %function;
KeccakP1600_OverwriteWithZeroes:
    lsrs    r2, r1, #3
    beq     KeccakP1600_OverwriteWithZeroes_Bytes
    vmov.i64 d0, #0
KeccakP1600_OverwriteWithZeroes_LoopLanes:
    subs    r2, r2, #1
    vstm    r0!, { d0 }
    bne     KeccakP1600_OverwriteWithZeroes_LoopLanes
KeccakP1600_OverwriteWithZeroes_Bytes:
    ands    r1, #7
    beq     KeccakP1600_OverwriteWithZeroes_Exit
    movs    r3, #0
KeccakP1600_OverwriteWithZeroes_LoopBytes:
    subs    r1, r1, #1
    strb    r3, [r0], #1
    bne     KeccakP1600_OverwriteWithZeroes_LoopBytes
KeccakP1600_OverwriteWithZeroes_Exit:
    bx      lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_ExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_ExtractBytes
.type	KeccakP1600_ExtractBytes, %function;
KeccakP1600_ExtractBytes:
    adds    r0, r0, r2                              @ state += offset
    subs    r3, r3, #8                              @ .if length >= lane size
    bcc     KeccakP1600_ExtractBytes_Bytes
KeccakP1600_ExtractBytes_LanesLoop:                  @ then, handle lanes
    ldr     r2, [r0], #4
    ldr     r12, [r0], #4
    subs    r3, r3, #8
    str     r2, [r1], #4
    str     r12, [r1], #4
    bcs     KeccakP1600_ExtractBytes_LanesLoop
KeccakP1600_ExtractBytes_Bytes:
    adds    r3, r3, #7
    bcc     KeccakP1600_ExtractBytes_Exit
KeccakP1600_ExtractBytes_BytesLoop:
    ldrb    r2, [r0], #1
    subs    r3, r3, #1
    strb    r2, [r1], #1
    bcs     KeccakP1600_ExtractBytes_BytesLoop
KeccakP1600_ExtractBytes_Exit:
    bx      lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_ExtractAndAddBytes(void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_ExtractAndAddBytes
.type	KeccakP1600_ExtractAndAddBytes, %function;
KeccakP1600_ExtractAndAddBytes:
    push    {r4,r5}
    add     r0, r0, r3                                  @ state += offset (offset register no longer needed, reuse for length)
    ldr     r3, [sp, #8]                                @ get length argument from stack
    subs    r3, r3, #8                                  @ .if length >= lane size
    bcc     KeccakP1600_ExtractAndAddBytes_Bytes
KeccakP1600_ExtractAndAddBytes_LanesLoop:                @ then, handle lanes
    ldr     r5, [r0], #4
    ldr     r4, [r1], #4
    eor     r5, r5, r4
    str     r5, [r2], #4
    subs    r3, r3, #8
    ldr     r5, [r0], #4
    ldr     r4, [r1], #4
    eor     r5, r5, r4
    str     r5, [r2], #4
    bcs     KeccakP1600_ExtractAndAddBytes_LanesLoop
KeccakP1600_ExtractAndAddBytes_Bytes:
    adds    r3, r3, #7
    bcc     KeccakP1600_ExtractAndAddBytes_Exit
KeccakP1600_ExtractAndAddBytes_BytesLoop:
    ldrb    r5, [r0], #1
    ldrb    r4, [r1], #1
    eor     r5, r5, r4
    strb    r5, [r2], #1
    subs    r3, r3, #1
    bcs     KeccakP1600_ExtractAndAddBytes_BytesLoop
KeccakP1600_ExtractAndAddBytes_Exit:
    pop     {r4,r5}
    bx      lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_Permute_Nrounds(void *state, unsigned int nrounds)
@
.align 8
.global   KeccakP1600_Permute_Nrounds
.type	KeccakP1600_Permute_Nrounds, %function;
KeccakP1600_Permute_Nrounds:
    movs    r2, r1
    adr     r1, KeccakP1600_Permute_RoundConstants0
	sub		r1, r1, r2, LSL #3
    b       KeccakP1600_Permute


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_Permute_12rounds( void *state )
@
.align 8
.global   KeccakP1600_Permute_12rounds
.type	KeccakP1600_Permute_12rounds, %function;
KeccakP1600_Permute_12rounds:
    adr     r1, KeccakP1600_Permute_RoundConstants12
    movs    r2, #12
    b       KeccakP1600_Permute


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_Permute_24rounds( void *state )
@
.align 8
.global   KeccakP1600_Permute_24rounds
.type	KeccakP1600_Permute_24rounds, %function;
KeccakP1600_Permute_24rounds:
    adr     r1, KeccakP1600_Permute_RoundConstants24
    movs    r2, #24
    b       KeccakP1600_Permute


.align 8
KeccakP1600_Permute_RoundConstants24:
		.quad      0x0000000000000001
		.quad      0x0000000000008082
		.quad      0x800000000000808a
		.quad      0x8000000080008000
		.quad      0x000000000000808b
		.quad      0x0000000080000001
		.quad      0x8000000080008081
		.quad      0x8000000000008009
		.quad      0x000000000000008a
		.quad      0x0000000000000088
		.quad      0x0000000080008009
		.quad      0x000000008000000a
KeccakP1600_Permute_RoundConstants12:
		.quad      0x000000008000808b
		.quad      0x800000000000008b
		.quad      0x8000000000008089
		.quad      0x8000000000008003
		.quad      0x8000000000008002
		.quad      0x8000000000000080
		.quad      0x000000000000800a
		.quad      0x800000008000000a
		.quad      0x8000000080008081
		.quad      0x8000000000008080
		.quad      0x0000000080000001
		.quad      0x8000000080008008
KeccakP1600_Permute_RoundConstants0:

.align 8
KeccakP1600_XORandPermuteAsmOnly:

    add     pc, pc, r5, LSL #3
    mov     r1, #0                              @ dummy instruction for PC alignment, not executed
    veor.64 d0, d0, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d2, d2, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d4, d4, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d6, d6, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d8, d8, d30
    b       KeccakP1600_PermuteAsmOnly

    veor.64 d1, d1, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d3, d3, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d5, d5, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d7, d7, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d9, d9, d30
    b       KeccakP1600_PermuteAsmOnly

    veor.64 d10, d10, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d12, d12, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d14, d14, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d16, d16, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d18, d18, d30
    b       KeccakP1600_PermuteAsmOnly

    veor.64 d11, d11, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d13, d13, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d15, d15, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d17, d17, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d19, d19, d30
    b       KeccakP1600_PermuteAsmOnly

    veor.64 d20, d20, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d21, d21, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d22, d22, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d23, d23, d30
    b       KeccakP1600_PermuteAsmOnly
    veor.64 d24, d24, d30
KeccakP1600_PermuteAsmOnly:
KeccakP1600_Permute_RoundLoop:
    KeccakRound
    .if LoopUnroll > 1
    KeccakRound
    .if LoopUnroll > 2
    KeccakRound
    KeccakRound
    .if LoopUnroll > 4
    KeccakRound
    KeccakRound
    .if LoopUnroll > 6
    KeccakRound
    KeccakRound
    KeccakRound
    KeccakRound
    KeccakRound
    KeccakRound
    .endif
    .endif
    .endif
    .endif
    subs    r2, #LoopUnroll
    bne     KeccakP1600_Permute_RoundLoop
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_Permute( void *state, void *roundConstants, unsigned int numberOfRounds )
@
.align 8
.global   KeccakP1600_Permute
.type	KeccakP1600_Permute, %function;
KeccakP1600_Permute:
    mov     r3, lr
    vpush   {q4-q7}
    LoadState
    bl      KeccakP1600_PermuteAsmOnly
    StoreState
    vpop    {q4-q7}
    bx      r3


 .if 0

@----------------------------------------------------------------------------
@
@ size_t KeccakF1600_FastLoop_Absorb(   void *state, unsigned int laneCount, unsigned char *data,
@                                       size_t dataByteLen, unsigned char trailingBits )
@
.align 8
.global   KeccakF1600_FastLoop_Absorb
.type	KeccakF1600_FastLoop_Absorb, %function;
KeccakF1600_FastLoop_Absorb:
    push    {r4-r8,lr}                          @ 6 CPU registers (24 bytes)
    lsr     r3, r3, #3                          @ r3 nbrLanes = dataByteLen / SnP_laneLengthInBytes
    mov     r6, r2                              @ r6 data pointer
    subs    r3, r3, r1                          @ .if (nbrLanes >= laneCount)
    mov     r4, r2                              @ r4 initial data pointer
    bcc     KeccakF1600_FastLoop_Absorb_Exit
    mov     r5, r1
    vpush   {q4-q7}                             @ 4 quad registers (64 bytes)
    LoadState

    sub     sp, sp, #8                          @ alloc space for trailingBits lane
    veor.64 d30, d30, d30
    add     r7, sp, #(6+16+2)*4
    vld1.8  {d30[0]}, [r7]
    vst1.64 {d30}, [sp:64]

    cmp     r5, #21
    bne     KeccakF1600_FastLoop_Absorb_Not21Lanes
KeccakF1600_FastLoop_Absorb_Loop21Lanes:
    vld1.64 { d26, d27, d28, d29 }, [r6]!   @ XOR first 21 lanes
    veor.64 d0, d0, d26
    veor.64 d2, d2, d27
    veor.64 d4, d4, d28
    veor.64 d6, d6, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d8, d8, d26
    veor.64 d1, d1, d27
    veor.64 d3, d3, d28
    veor.64 d5, d5, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d7, d7, d26
    veor.64 d9, d9, d27
    veor.64 d10, d10, d28
    veor.64 d12, d12, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d14, d14, d26
    veor.64 d16, d16, d27
    veor.64 d18, d18, d28
    veor.64 d11, d11, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d13, d13, d26
    veor.64 d15, d15, d27
    veor.64 d17, d17, d28
    veor.64 d19, d19, d29
    vld1.64 { d26 }, [r6]!
    veor.64 d20, d20, d26

    vld1.64 {d30}, [sp:64]                    @ xor trailingBits
    veor.64 d21, d21, d30
    bl      KeccakP1600_PermuteAsmOnly
    subs    r3, r3, r5                          @ nbrLanes -= laneCount
    bcs     KeccakF1600_FastLoop_Absorb_Loop21Lanes
KeccakF1600_FastLoop_Absorb_Done:
    add     sp, sp, #8                          @ free trailingBits lane
    StoreState
    vpop    {q4-q7}
KeccakF1600_FastLoop_Absorb_Exit:
    sub     r0, r6, r4                          @ processed = data pointer - initial data pointer
    pop     {r4-r8,pc}
KeccakF1600_FastLoop_Absorb_Not21Lanes:
    cmp     r5, #16
    mvn     r7, #7                              @ r7 = -8
    blo     KeccakF1600_FastLoop_Absorb_LoopLessThan16Lanes
KeccakF1600_FastLoop_Absorb_Loop16OrMoreLanes:
    vld1.64 { d26, d27, d28, d29 }, [r6]!   @ XOR first 16 lanes
    veor.64 d0, d0, d26
    veor.64 d2, d2, d27
    veor.64 d4, d4, d28
    veor.64 d6, d6, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d8, d8, d26
    veor.64 d1, d1, d27
    veor.64 d3, d3, d28
    veor.64 d5, d5, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d7, d7, d26
    veor.64 d9, d9, d27
    veor.64 d10, d10, d28
    veor.64 d12, d12, d29
    vld1.64 { d26, d27, d28, d29 }, [r6]!
    veor.64 d14, d14, d26
    veor.64 d16, d16, d27
    veor.64 d18, d18, d28
    veor.64 d11, d11, d29

    sub     r2, r5, #16                         @ XOR last n lanes, maximum 9
    rsb     r1, r2, #9
    add     r6, r6, r2, LSL #3                  @ data += n lanes * 8
    sub     r2, r6, #8                          @ r2 tempdata =  data - 8
    add     pc, pc, r1, LSL #3
    mov     r1, #0                              @ dummy instruction for PC alignment, not executed
    vld1.64 d30, [r2], r7
    veor.64 d24, d24, d30
    vld1.64 d30, [r2], r7
    veor.64 d23, d23, d30
    vld1.64 d30, [r2], r7
    veor.64 d22, d22, d30
    vld1.64 d30, [r2], r7
    veor.64 d21, d21, d30
    vld1.64 d30, [r2], r7
    veor.64 d20, d20, d30

    vld1.64 d30, [r2], r7
    veor.64 d19, d19, d30
    vld1.64 d30, [r2], r7
    veor.64 d17, d17, d30
    vld1.64 d30, [r2], r7
    veor.64 d15, d15, d30
    vld1.64 d30, [r2], r7
    veor.64 d13, d13, d30

    vld1.64 {d30}, [sp:64]
    bl      KeccakP1600_XORandPermuteAsmOnly
    subs    r3, r3, r5                          @ nbrLanes -= laneCount
    bcs     KeccakF1600_FastLoop_Absorb_Loop16OrMoreLanes
    b       KeccakF1600_FastLoop_Absorb_Done
KeccakF1600_FastLoop_Absorb_LoopLessThan16Lanes:
    rsb     r1, r5, #15                         @ XOR up to 15 lanes
    add     r6, r6, r5, LSL #3                  @ data += laneCount * 8
    sub     r2, r6, #8                          @ r2 tempdata =  data - 8
    add     pc, pc, r1, LSL #3
    mov     r1, #0                              @ dummy instruction for PC alignment, not executed

    vld1.64 d30, [r2], r7
    veor.64 d18, d18, d30
    vld1.64 d30, [r2], r7
    veor.64 d16, d16, d30
    vld1.64 d30, [r2], r7
    veor.64 d14, d14, d30
    vld1.64 d30, [r2], r7
    veor.64 d12, d12, d30
    vld1.64 d30, [r2], r7
    veor.64 d10, d10, d30

    vld1.64 d30, [r2], r7
    veor.64 d9, d9, d30
    vld1.64 d30, [r2], r7
    veor.64 d7, d7, d30
    vld1.64 d30, [r2], r7
    veor.64 d5, d5, d30
    vld1.64 d30, [r2], r7
    veor.64 d3, d3, d30
    vld1.64 d30, [r2], r7
    veor.64 d1, d1, d30

    vld1.64 d30, [r2], r7
    veor.64 d8, d8, d30
    vld1.64 d30, [r2], r7
    veor.64 d6, d6, d30
    vld1.64 d30, [r2], r7
    veor.64 d4, d4, d30
    vld1.64 d30, [r2], r7
    veor.64 d2, d2, d30
    vld1.64 d30, [r2], r7
    veor.64 d0, d0, d30

    vld1.64 {d30}, [sp:64]
    bl      KeccakP1600_XORandPermuteAsmOnly
    subs    r3, r3, r5                          @ nbrLanes -= laneCount
    bcs     KeccakF1600_FastLoop_Absorb_LoopLessThan16Lanes
    b       KeccakF1600_FastLoop_Absorb_Done


 .endif

