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

@ WARNING: This implementation assumes a little endian CPU with ARMv6M architecture (e.g., Cortex-M0) and the GCC compiler.


    .thumb
	.syntax unified
.text

    @ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro    toBitInterleaving   in0,in1,out0,out1,t,tt,pMask

    mov     \out0, \in0
    ldr     \t, [\pMask, #0]
    ands    \out0, \out0, \t
    lsrs    \t, \out0, #1
    orrs    \out0, \out0, \t
    ldr     \t, [\pMask, #4]
    ands    \out0, \out0, \t
    lsrs    \t, \out0, #2
    orrs    \out0, \out0, \t
    ldr     \t, [\pMask, #8]
    ands    \out0, \out0, \t
    lsrs    \t, \out0, #4
    orrs    \out0, \out0, \t
    ldr     \t, [\pMask, #12]
    ands    \out0, \out0, \t
    lsrs    \t, \out0, #8
    orrs    \out0, \out0, \t

    mov     \out1, \in1
    ldr     \t, [\pMask, #0]
    ands    \out1, \out1, \t
    lsrs    \t, \out1, #1
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #4]
    ands    \out1, \out1, \t
    lsrs    \t, \out1, #2
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #8]
    ands    \out1, \out1, \t
    lsrs    \t, \out1, #4
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #12]
    ands    \out1, \out1, \t
    lsrs    \t, \out1, #8
    orrs    \out1, \out1, \t

    lsls    \out0, \out0, #16
    lsrs    \out0, \out0, #16
    lsls    \out1, \out1, #16
    orrs    \out0, \out0, \out1

    mov     \out1, \in0
    ldr     \t, [\pMask, #16]
    ands    \out1, \out1, \t
    lsls    \t, \out1, #1
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #20]
    ands    \out1, \out1, \t
    lsls    \t, \out1, #2
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #24]
    ands    \out1, \out1, \t
    lsls    \t, \out1, #4
    orrs    \out1, \out1, \t
    ldr     \t, [\pMask, #28]
    ands    \out1, \out1, \t
    lsls    \t, \out1, #8
    orrs    \out1, \out1, \t

    mov     \tt, \in1
    ldr     \t, [\pMask, #16]
    ands    \tt, \tt, \t
    lsls    \t, \tt, #1
    orrs    \tt, \tt, \t
    ldr     \t, [\pMask, #20]
    ands    \tt, \tt, \t
    lsls    \t, \tt, #2
    orrs    \tt, \tt, \t
    ldr     \t, [\pMask, #24]
    ands    \tt, \tt, \t
    lsls    \t, \tt, #4
    orrs    \tt, \tt, \t
    ldr     \t, [\pMask, #28]
    ands    \tt, \tt, \t
    lsls    \t, \tt, #8
    orrs    \tt, \tt, \t

    lsrs    \out1,\out1, #16
    lsrs    \tt, \tt, #16
    lsls    \tt, \tt, #16
    orrs    \out1,\out1,\tt
    .endm

    @ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro    fromBitInterleavingStep x, t, tt, pMask, maskofs, shift

    @ t = (x ^ (x >> shift)) & mask@  x = x ^ t ^ (t << shift)@
    lsrs    \t, \x, #\shift
    eors    \t, \t, \x
    ldr     \tt, [\pMask, #\maskofs]
    ands    \t, \t, \tt
    eors    \x, \x, \t
    lsls    \t, \t, #\shift
    eors    \x, \x, \t
    .endm

.macro    fromBitInterleaving     x0, x1, t, tt, pMask
    movs    \t, \x0                 @ t = x0
    lsls    \x0, \x0, #16           @ x0 = (x0 & 0x0000FFFF) | (x1 << 16)@
    lsrs    \x0, \x0, #16
    lsls    \tt, \x1, #16
    orrs    \x0, \x0, \tt
    lsrs    \x1, \x1, #16           @   x1 = (t >> 16) | (x1 & 0xFFFF0000)@
    lsls    \x1, \x1, #16
    lsrs    \t, \t, #16
    orrs    \x1, \x1, \t
    fromBitInterleavingStep \x0, \t, \tt, \pMask, 0, 8
    fromBitInterleavingStep \x0, \t, \tt, \pMask, 4, 4
    fromBitInterleavingStep \x0, \t, \tt, \pMask, 8, 2
    fromBitInterleavingStep \x0, \t, \tt, \pMask, 12, 1
    fromBitInterleavingStep \x1, \t, \tt, \pMask, 0, 8
    fromBitInterleavingStep \x1, \t, \tt, \pMask, 4, 4
    fromBitInterleavingStep \x1, \t, \tt, \pMask, 8, 2
    fromBitInterleavingStep \x1, \t, \tt, \pMask, 12, 1
    .endm

@ --- offsets in state
.equ Aba0   , 0*4
.equ Aba1   , 1*4
.equ Abe0   , 2*4
.equ Abe1   , 3*4
.equ Abi0   , 4*4
.equ Abi1   , 5*4
.equ Abo0   , 6*4
.equ Abo1   , 7*4
.equ Abu0   , 8*4
.equ Abu1   , 9*4
.equ Aga0   , 10*4
.equ Aga1   , 11*4
.equ Age0   , 12*4
.equ Age1   , 13*4
.equ Agi0   , 14*4
.equ Agi1   , 15*4
.equ Ago0   , 16*4
.equ Ago1   , 17*4
.equ Agu0   , 18*4
.equ Agu1   , 19*4
.equ Aka0   , 20*4
.equ Aka1   , 21*4
.equ Ake0   , 22*4
.equ Ake1   , 23*4
.equ Aki0   , 24*4
.equ Aki1   , 25*4
.equ Ako0   , 26*4
.equ Ako1   , 27*4
.equ Aku0   , 28*4
.equ Aku1   , 29*4
.equ Ama0   , 30*4
.equ Ama1   , 31*4
.equ Ame0   , 32*4
.equ Ame1   , 33*4
.equ Ami0   , 34*4
.equ Ami1   , 35*4
.equ Amo0   , 36*4
.equ Amo1   , 37*4
.equ Amu0   , 38*4
.equ Amu1   , 39*4
.equ Asa0   , 40*4
.equ Asa1   , 41*4
.equ Ase0   , 42*4
.equ Ase1   , 43*4
.equ Asi0   , 44*4
.equ Asi1   , 45*4
.equ Aso0   , 46*4
.equ Aso1   , 47*4
.equ Asu0   , 48*4
.equ Asu1   , 49*4

@ --- offsets on stack
.equ mDa0   , 0*4
.equ mDa1   , 1*4
.equ mDo0   , 2*4
.equ mDo1   , 3*4
.equ mDi0   , 4*4
.equ mRC    , 5*4
.equ mSize  , 6*4

@ --- macros

.macro    load        result,prev,curr,last

    .if \prev >= (32*4)  &&  \curr < (32*4)
    subs        r0, #32*4
    .elseif \prev < (32*4)  &&  \curr >= (32*4)
    adds        r0, #32*4
    .endif
    .if \curr >= (32*4)
    ldr         \result, [r0, #\curr-32*4]
    .if \last == 1
    subs        r0, #32*4
    .endif
    .else
    ldr         \result, [r0, #\curr]
    .endif
    .endm

.macro    store       result,prev,curr,last

    .if \prev >= (32*4)  &&  \curr < (32*4)
    subs        r0, #32*4
    .elseif \prev < (32*4)  &&  \curr >= (32*4)
    adds        r0, #32*4
    .endif
    .if \curr >= (32*4)
    str         \result, [r0, #\curr-32*4]
    .if \last == 1
    subs        r0, #32*4
    .endif
    .else
    str         \result, [r0, #\curr]
    .endif
    .endm

.macro    xor5        result,b,g,k,m,s, prev, last

    load        \result,  0,        \b, 0
    load        r1,     \b,        \g, 0
    eors        \result, \result,   r1
    load        r1,     \g,        \k, 0
    eors        \result, \result,   r1
    load        r1,     \k,        \m, 0
    eors        \result, \result,   r1
    load        r1,     \m,        \s, 1
    eors        \result, \result,   r1
    .endm

.macro    xorrol      result, aa, bb
    movs        \result, \bb
    rors        \result, r2
    eors        \result, \result, \aa
    .endm

.macro    xorrolR2    aa, bb
    rors        \bb, r2
    eors        \bb, \bb, \aa
    .endm

.macro    xorh        result, aa, bb
    mov         r1, \bb
    eors        r1, r1, \aa
    mov         \result, r1
    .endm


.macro    xandnot     resofs, aa, bb, cc, prev, last
    movs        r1, \cc
    bics        r1, r1, \bb
    eors        r1, r1, \aa
    store       r1, \prev, \resofs, \last
    .endm

.macro    xandnotR4   resofs, aa, bb, cc, prev, last
    bics        \cc, \cc, \bb
    eors        \cc, \cc, \aa
    store       \cc, \prev, \resofs, \last
    .endm

.macro    KeccakThetaRhoPiChiIota aA1, aDax, aA2, aDex, rot2, aA3, aDix, rot3, aA4, aDox, rot4, aA5, aDux, rot5, offset, last
    load    r3,    0, \aA1, 0
    load    r4, \aA1, \aA2, 0
    load    r5, \aA2, \aA3, 0
    load    r6, \aA3, \aA4, 0
    load    r7, \aA4, \aA5, 0

    mov     r1, \aDax
    eors    r3, r3, r1
    eors    r5, r5, \aDix
    mov     r1, \aDex
    eors    r4, r4, r1
    mov     r1, \aDox
    eors    r6, r6, r1
    mov     r1, \aDux
    eors    r7, r7, r1
    movs    r1, #32-\rot2
    rors    r4, r1
    movs    r1, #32-\rot3
    rors    r5, r1
    movs    r1, #32-\rot4
    rors    r6, r1
    movs    r1, #32-\rot5
    rors    r7, r1
    xandnot \aA2, r4, r5, r6, \aA5, 0
    xandnot \aA3, r5, r6, r7, \aA2, 0
    xandnot \aA4, r6, r7, r3, \aA3, 0
    xandnot \aA5, r7, r3, r4, \aA4, 1
    ldr     r1, [sp, #mRC]
    bics    r5, r5, r4
    ldr     r4, [r1, #\offset]
    eors    r3, r3, r5
    eors    r3, r3, r4
    .if  \last == 1
    adds    r1, #32
    ldr     r2, [r1]
    str     r1, [sp, #mRC]
    cmp     r2, #0xFF
    .endif
    str     r3, [r0, #\aA1]
    .endm

.macro    KeccakThetaRhoPiChi aB1, aA1, aDax, rot1, aB2, aA2, aDex, rot2, aB3, aA3, aDix, rot3, aB4, aA4, aDox, rot4, aB5, aA5, aDux, rot5
    load    \aB1,    0, \aA1, 0
    load    \aB2, \aA1, \aA2, 0
    load    \aB3, \aA2, \aA3, 0
    load    \aB4, \aA3, \aA4, 0
    load    \aB5, \aA4, \aA5, 0

    mov     r1, \aDax
    eors    \aB1, \aB1, r1
    eors    \aB3, \aB3, \aDix
    mov     r1, \aDex
    eors    \aB2, \aB2, r1
    mov     r1, \aDox
    eors    \aB4, \aB4, r1
    mov     r1, \aDux
    eors    \aB5, \aB5, r1
    movs    r1, #32-\rot1
    rors    \aB1, r1
    .if  \rot2 > 0
    movs    r1, #32-\rot2
    rors    \aB2, r1
    .endif
    movs    r1, #32-\rot3
    rors    \aB3, r1
    movs    r1, #32-\rot4
    rors    \aB4, r1
    movs    r1, #32-\rot5
    rors    \aB5, r1
    xandnot     \aA1, r3, r4, r5, \aA5, 0
    xandnot     \aA2, r4, r5, r6, \aA1, 0
    xandnotR4   \aA5, r7, r3, r4, \aA2, 0
    xandnotR4   \aA4, r6, r7, r3, \aA5, 0
    xandnotR4   \aA3, r5, r6, r7, \aA4, 1
    .endm

.macro    KeccakRound0
    movs        r2,  #31
    xor5        r3,  Abu0, Agu0, Aku0, Amu0, Asu0, 0,    0
    xor5        r7,  Abe1, Age1, Ake1, Ame1, Ase1, Asu0, 0
    xorrol      r6,  r3, r7
    str         r6,  [sp, #mDa0]
    xor5        r6,  Abu1, Agu1, Aku1, Amu1, Asu1, Ase1, 0
    xor5        r5,  Abe0, Age0, Ake0, Ame0, Ase0, Asu1, 0
    xorh        r8, r6, r5
    mov         lr,  r5
    str         r1,  [sp, #mDa1]

    xor5        r5,  Abi0, Agi0, Aki0, Ami0, Asi0, Ase0, 0
    xorrolR2    r5,  r6
    str         r6,  [sp, #mDo0]
    xor5        r4,  Abi1, Agi1, Aki1, Ami1, Asi1, Asi0, 0
    eors        r3,  r3, r4
    str         r3,  [sp, #mDo1]

    xor5        r3,  Aba0, Aga0, Aka0, Ama0, Asa0, Asi1, 0
    xorrolR2    r3,  r4
    mov         r10, r4
    xor5        r6,  Aba1, Aga1, Aka1, Ama1, Asa1, Asa0, 0
    xorh        r11, r6, r5

    xor5        r4,  Abo1, Ago1, Ako1, Amo1, Aso1, Asa1, 0
    mov         r1,  lr
    xorrol      r5,  r1, r4
    str         r5,  [sp, #mDi0]
    xor5        r5,  Abo0, Ago0, Ako0, Amo0, Aso0, Aso1, 1
    eors        r7,  r7, r5

    xorrolR2    r5,  r6
    mov         r12, r6
    eors        r4,  r4, r3
    mov         lr, r4
    movs        r2, r7

    ldr         r1,  [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChi r5, Aka1, r8,  2, r6, Ame1, r11, 23, r7, Asi1, r2, 31, r3, Abo0, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Asa1, r8,  9, r3, Abe0, r10,  0, r4, Agi1, r2,  3, r5, Ako0, r9, 12, r6, Amu1, lr,  4
    ldr         r1, [sp, #mDa0]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Aga0, r8, 18, r5, Ake0, r10,  5, r6, Ami1, r2,  8, r7, Aso0, r9, 28, r3, Abu1, lr, 14
    KeccakThetaRhoPiChi r6, Ama0, r8, 20, r7, Ase1, r11,  1, r3, Abi1, r2, 31, r4, Ago0, r9, 27, r5, Aku0, r12, 19
    ldr         r1, [sp, #mDo1]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba0, r8,          Age0, r10, 22,      Aki1, r2, 22,      Amo1, r9, 11,      Asu0, r12,  7, 0, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aka0, r8,  1, r6, Ame0, r10, 22, r7, Asi0, r2, 30, r3, Abo1, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Asa0, r8,  9, r3, Abe1, r11,  1, r4, Agi0, r2,  3, r5, Ako1, r9, 13, r6, Amu0, r12,  4
    ldr         r1, [sp, #mDa1]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Aga1, r8, 18, r5, Ake1, r11,  5, r6, Ami0, r2,  7, r7, Aso1, r9, 28, r3, Abu0, r12, 13
    KeccakThetaRhoPiChi r6, Ama1, r8, 21, r7, Ase0, r10,  1, r3, Abi0, r2, 31, r4, Ago1, r9, 28, r5, Aku1, lr, 20
    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba1, r8,          Age1, r11, 22,      Aki0, r2, 21,      Amo0, r9, 10,      Asu1, lr,  7, 4, 0
    .endm

.macro    KeccakRound1

    movs        r2,  #31
    xor5        r3,  Asu0, Agu0, Amu0, Abu1, Aku1, 0, 0
    xor5        r7,  Age1, Ame0, Abe0, Ake1, Ase1, Aku1, 0
    xorrol      r6,  r3, r7
    str         r6,  [sp, #mDa0]
    xor5        r6,  Asu1, Agu1, Amu1, Abu0, Aku0, Ase1, 0
    xor5        r5,  Age0, Ame1, Abe1, Ake0, Ase0, Aku0, 0
    xorh        r8, r6, r5
    mov         lr,  r5
    str         r1,  [sp, #mDa1]

    xor5        r5,  Aki1, Asi1, Agi0, Ami1, Abi0, Ase0, 0
    xorrolR2    r5,  r6
    str         r6,  [sp, #mDo0]
    xor5        r4,  Aki0, Asi0, Agi1, Ami0, Abi1, Abi0, 0
    eors        r3,  r3, r4
    str         r3,  [sp, #mDo1]

    xor5        r3,  Aba0, Aka1, Asa0, Aga0, Ama1, Abi1, 0
    xorrolR2    r3,  r4
    mov         r10, r4
    xor5        r6,  Aba1, Aka0, Asa1, Aga1, Ama0, Ama1, 0
    xorh        r11, r6, r5

    xor5        r4,  Amo0, Abo1, Ako0, Aso1, Ago0, Ama0, 0
    mov         r1,  lr
    xorrol      r5,  r1, r4
    str         r5,  [sp, #mDi0]
    xor5        r5,  Amo1, Abo0, Ako1, Aso0, Ago1, Ago0, 1
    eors        r7,  r7, r5

    xorrolR2    r5,  r6
    mov         r12, r6
    eors        r4,  r4, r3
    mov         lr, r4
    movs        r2, r7

    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChi r5, Asa1, r8,  2, r6, Ake1, r11, 23, r7, Abi1, r2, 31, r3, Amo1, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Ama0, r8,  9, r3, Age0, r10,  0, r4, Asi0, r2,  3, r5, Ako1, r9, 12, r6, Abu0, lr,  4
    ldr         r1, [sp, #mDa0]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Aka1, r8, 18, r5, Abe1, r10,  5, r6, Ami0, r2,  8, r7, Ago1, r9, 28, r3, Asu1, lr, 14
    KeccakThetaRhoPiChi r6, Aga0, r8, 20, r7, Ase1, r11,  1, r3, Aki0, r2, 31, r4, Abo0, r9, 27, r5, Amu0, r12, 19
    ldr         r1, [sp, #mDo1]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba0, r8,          Ame1, r10, 22,      Agi1, r2, 22,      Aso1, r9, 11,      Aku1, r12,  7, 8, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Asa0, r8,  1, r6, Ake0, r10, 22, r7, Abi0, r2, 30, r3, Amo0, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Ama1, r8,  9, r3, Age1, r11,  1, r4, Asi1, r2,  3, r5, Ako0, r9, 13, r6, Abu1, r12,  4
    ldr         r1, [sp, #mDa1]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Aka0, r8, 18, r5, Abe0, r11,  5, r6, Ami1, r2,  7, r7, Ago0, r9, 28, r3, Asu0, r12, 13
    KeccakThetaRhoPiChi r6, Aga1, r8, 21, r7, Ase0, r10,  1, r3, Aki1, r2, 31, r4, Abo1, r9, 28, r5, Amu1, lr, 20
    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba1, r8,          Ame0, r11, 22,      Agi0, r2, 21,      Aso0, r9, 10,      Aku0, lr,  7, 12, 0
    .endm

.macro    KeccakRound2

    movs        r2,  #31
    xor5        r3,  Aku1, Agu0, Abu1, Asu1, Amu1, 0, 0
    xor5        r7,  Ame0, Ake0, Age0, Abe0, Ase1, Amu1, 0
    xorrol      r6,  r3, r7
    str         r6,  [sp, #mDa0]
    xor5        r6,  Aku0, Agu1, Abu0, Asu0, Amu0, Ase1, 0
    xor5        r5,  Ame1, Ake1, Age1, Abe1, Ase0, Amu0, 0
    xorh        r8, r6, r5
    mov         lr,  r5
    str         r1,  [sp, #mDa1]

    xor5        r5,  Agi1, Abi1, Asi1, Ami0, Aki1, Ase0, 0
    xorrolR2    r5,  r6
    str         r6,  [sp, #mDo0]
    xor5        r4,  Agi0, Abi0, Asi0, Ami1, Aki0, Aki1, 0
    eors        r3,  r3, r4
    str         r3,  [sp, #mDo1]

    xor5        r3,  Aba0, Asa1, Ama1, Aka1, Aga1, Aki0, 0
    xorrolR2    r3,  r4
    mov         r10, r4
    xor5        r6,  Aba1, Asa0, Ama0, Aka0, Aga0, Aga1, 0
    xorh        r11, r6, r5

    xor5        r4,  Aso0, Amo0, Ako1, Ago0, Abo0, Aga0, 0
    mov         r1,  lr
    xorrol      r5,  r1, r4
    str         r5,  [sp, #mDi0]
    xor5        r5,  Aso1, Amo1, Ako0, Ago1, Abo1, Abo0, 1
    eors        r7,  r7, r5

    xorrolR2    r5,  r6
    mov         r12, r6
    eors        r4,  r4, r3
    mov         lr, r4
    movs        r2, r7

    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChi r5, Ama0, r8,  2, r6, Abe0, r11, 23, r7, Aki0, r2, 31, r3, Aso1, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aga0, r8,  9, r3, Ame1, r10,  0, r4, Abi0, r2,  3, r5, Ako0, r9, 12, r6, Asu0, lr,  4
    ldr         r1, [sp, #mDa0]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Asa1, r8, 18, r5, Age1, r10,  5, r6, Ami1, r2,  8, r7, Abo1, r9, 28, r3, Aku0, lr, 14
    KeccakThetaRhoPiChi r6, Aka1, r8, 20, r7, Ase1, r11,  1, r3, Agi0, r2, 31, r4, Amo1, r9, 27, r5, Abu1, r12, 19
    ldr         r1, [sp, #mDo1]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba0, r8,          Ake1, r10, 22,      Asi0, r2, 22,      Ago0, r9, 11,      Amu1, r12,  7, 16, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Ama1, r8,  1, r6, Abe1, r10, 22, r7, Aki1, r2, 30, r3, Aso0, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Aga1, r8,  9, r3, Ame0, r11,  1, r4, Abi1, r2,  3, r5, Ako1, r9, 13, r6, Asu1, r12,  4
    ldr         r1, [sp, #mDa1]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Asa0, r8, 18, r5, Age0, r11,  5, r6, Ami0, r2,  7, r7, Abo0, r9, 28, r3, Aku1, r12, 13
    KeccakThetaRhoPiChi r6, Aka0, r8, 21, r7, Ase0, r10,  1, r3, Agi1, r2, 31, r4, Amo0, r9, 28, r5, Abu0, lr, 20
    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChiIota Aba1,  r8,          Ake0, r11, 22,      Asi1, r2, 21,      Ago1, r9, 10,      Amu0, lr,  7, 20, 0
    .endm

.macro    KeccakRound3

    movs        r2,  #31
    xor5        r3,  Amu1, Agu0, Asu1, Aku0, Abu0, 0, 0
    xor5        r7,  Ake0, Abe1, Ame1, Age0, Ase1, Abu0, 0
    xorrol      r6,  r3, r7
    str         r6,  [sp, #mDa0]
    xor5        r6,  Amu0, Agu1, Asu0, Aku1, Abu1, Ase1, 0
    xor5        r5,  Ake1, Abe0, Ame0, Age1, Ase0, Abu1, 0
    xorh        r8, r6, r5
    mov         lr,  r5
    str         r1,  [sp, #mDa1]

    xor5        r5,  Asi0, Aki0, Abi1, Ami1, Agi1, Ase0, 0
    xorrolR2    r5,  r6
    str         r6,  [sp, #mDo0]
    xor5        r4,  Asi1, Aki1, Abi0, Ami0, Agi0, Agi1, 0
    eors        r3,  r3, r4
    str         r3,  [sp, #mDo1]

    xor5        r3,  Aba0, Ama0, Aga1, Asa1, Aka0, Agi0, 0
    xorrolR2    r3,  r4
    mov         r10, r4
    xor5        r6,  Aba1, Ama1, Aga0, Asa0, Aka1, Aka0, 0
    xorh        r11, r6, r5

    xor5        r4,  Ago1, Aso0, Ako0, Abo0, Amo1, Aka1, 0
    mov         r1,  lr
    xorrol      r5,  r1, r4
    str         r5,  [sp, #mDi0]
    xor5        r5,  Ago0, Aso1, Ako1, Abo1, Amo0, Amo1, 1
    eors        r7,  r7, r5

    xorrolR2    r5,  r6
    mov         r12, r6
    eors        r4,  r4, r3
    mov         lr, r4
    movs        r2, r7

    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChi r5, Aga0, r8,  2, r6, Age0, r11, 23, r7, Agi0, r2, 31, r3, Ago0, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aka1, r8,  9, r3, Ake1, r10,  0, r4, Aki1, r2,  3, r5, Ako1, r9, 12, r6, Aku1, lr,  4
    ldr         r1, [sp, #mDa0]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Ama0, r8, 18, r5, Ame0, r10,  5, r6, Ami0, r2,  8, r7, Amo0, r9, 28, r3, Amu0, lr, 14
    KeccakThetaRhoPiChi r6, Asa1, r8, 20, r7, Ase1, r11,  1, r3, Asi1, r2, 31, r4, Aso1, r9, 27, r5, Asu1, r12, 19
    ldr         r1, [sp, #mDo1]
    mov         r9, r1
    KeccakThetaRhoPiChiIota  Aba0, r8,          Abe0, r10, 22,      Abi0, r2, 22,      Abo0, r9, 11,      Abu0, r12,  7, 24, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aga1, r8,  1, r6, Age1, r10, 22, r7, Agi1, r2, 30, r3, Ago1, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Aka0, r8,  9, r3, Ake0, r11,  1, r4, Aki0, r2,  3, r5, Ako0, r9, 13, r6, Aku0, r12,  4
    ldr         r1, [sp, #mDa1]
    mov         r8, r1
    KeccakThetaRhoPiChi r4, Ama1, r8, 18, r5, Ame1, r11,  5, r6, Ami1, r2,  7, r7, Amo1, r9, 28, r3, Amu1, r12, 13
    KeccakThetaRhoPiChi r6, Asa0, r8, 21, r7, Ase0, r10,  1, r3, Asi0, r2, 31, r4, Aso0, r9, 28, r5, Asu0, lr, 20
    ldr         r1, [sp, #mDo0]
    mov         r9, r1
    KeccakThetaRhoPiChiIota Aba1,  r8,          Abe1, r11, 22,      Abi1, r2, 21,      Abo1, r9, 10,      Abu1, lr,  7, 28, 1
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
    push    {r4 - r5}
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    movs    r4, #0
    movs    r5, #0
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    stmia   r0!, { r1 - r5 }
    pop     {r4 - r5}
    bx      lr


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_AddByte(void *state, unsigned char byte, unsigned int offset)
@
.align 8
.global   KeccakP1600_AddByte
.type	KeccakP1600_AddByte, %function;
KeccakP1600_AddByte:
    push    {r4 - r7}
    mov     r4, r8
    mov     r5, r9
    push    {r4 - r5}
    lsrs    r4, r2, #3                              @ offset &= ~7
    lsls    r4, r4, #3
    adds    r0, r0, r4                              @ add whole lane offset to state pointer
    lsls    r2, r2, #29                             @ offset &= 7 (part not lane aligned)
    lsrs    r2, r2, #29
    adr     r7, KeccakP1600_AddBytes_ToBitInterleavingConstants
    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    add     r2, r2, sp
    strb    r1, [r2]
    pop     { r4 - r5 }
    mov     r8, r4
    mov     r9, r5
    toBitInterleaving   r8, r9, r4, r5, r6, r2, r7
    ldr     r6, [r0]
    eors    r4, r4, r6
    ldr     r6, [r0, #4]
    eors    r5, r5, r6
    stmia   r0!, { r4, r5 }
    pop     {r4 - r5}
    mov     r8, r4
    mov     r9, r5
    pop     {r4 - r7}
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_AddBytes
.type	KeccakP1600_AddBytes, %function;
KeccakP1600_AddBytes:
    cmp     r3, #0                                  @ .if length != 0
    beq     KeccakP1600_AddBytes_Exit1
    push    {r4 - r6, lr}                           @ then
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    push    {r4 - r7}
    lsrs    r4, r2, #3                              @ offset &= ~7
    lsls    r4, r4, #3
    adds    r0, r0, r4                              @ add whole lane offset to state pointer
    lsls    r2, r2, #29                             @ offset &= 7 (part not lane aligned)
    lsrs    r2, r2, #29
    beq     KeccakP1600_AddBytes_CheckLanes @ .if offset != 0
    movs    r4, r3                                  @ then, do remaining bytes in first lane
    movs    r5, #8
    subs    r5, r2                                  @ max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_AddBytes_BytesAlign
    movs    r4, r5
KeccakP1600_AddBytes_BytesAlign:
    subs    r3, r3, r4                              @ size left
    mov     r10, r3
    movs    r3, r4
    adr     r7, KeccakP1600_AddBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_AddBytesInLane
    mov     r3, r10
KeccakP1600_AddBytes_CheckLanes:
    lsrs    r2, r3, #3                              @ .if length >= 8
    beq     KeccakP1600_AddBytes_Bytes
    mov     r10, r3
    adr     r3, KeccakP1600_AddBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_AddLanes
    mov     r3, r10
    lsls    r3, r3, #29
    lsrs    r3, r3, #29
KeccakP1600_AddBytes_Bytes:
    cmp     r3, #0
    beq     KeccakP1600_AddBytes_Exit
    movs    r2, #0
    adr     r7, KeccakP1600_AddBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_AddBytesInLane
KeccakP1600_AddBytes_Exit:
    pop     {r4 - r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    pop     {r4 - r6, pc}
KeccakP1600_AddBytes_Exit1:
    bx      lr
    nop
KeccakP1600_AddBytes_ToBitInterleavingConstants:
		.long      0x55555555
		.long      0x33333333
		.long      0x0F0F0F0F
		.long      0x00FF00FF
		.long      0xAAAAAAAA
		.long      0xCCCCCCCC
		.long      0xF0F0F0F0
		.long      0xFF00FF00


@----------------------------------------------------------------------------
@
@ __KeccakP1600_AddLanes
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 laneCount
@  r3 to bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r9
@
.align 8
__KeccakP1600_AddLanes:
    lsls    r4, r1, #30
    bne     __KeccakP1600_AddLanes_LoopUnaligned
__KeccakP1600_AddLanes_LoopAligned:
    ldmia   r1!, {r6,r7}
    mov     r8, r6
    mov     r9, r7
    toBitInterleaving   r8, r9, r6, r7, r5, r4, r3
    ldr     r5, [r0]
    eors    r6, r6, r5
    ldr     r5, [r0, #4]
    eors    r7, r7, r5
    stmia   r0!, {r6,r7}
    subs    r2, r2, #1
    bne     __KeccakP1600_AddLanes_LoopAligned
    bx      lr
__KeccakP1600_AddLanes_LoopUnaligned:
    ldrb    r6, [r1, #0]
    ldrb    r4, [r1, #1]
    lsls    r4, r4, #8
    orrs    r6, r6, r4
    ldrb    r4, [r1, #2]
    lsls    r4, r4, #16
    orrs    r6, r6, r4
    ldrb    r4, [r1, #3]
    lsls    r4, r4, #24
    orrs    r6, r6, r4
    ldrb    r7, [r1, #4]
    ldrb    r4, [r1, #5]
    lsls    r4, r4, #8
    orrs    r7, r7, r4
    ldrb    r4, [r1, #6]
    lsls    r4, r4, #16
    orrs    r7, r7, r4
    ldrb    r4, [r1, #7]
    lsls    r4, r4, #24
    orrs    r7, r7, r4
    adds    r1, r1, #8
    mov     r8, r6
    mov     r9, r7
    toBitInterleaving   r8, r9, r6, r7, r5, r4, r3
    ldr     r5, [r0]
    eors    r6, r6, r5
    ldr     r5, [r0, #4]
    eors    r7, r7, r5
    stmia   r0!, {r6, r7}
    subs    r2, r2, #1
    bne     __KeccakP1600_AddLanes_LoopUnaligned
    bx      lr


@----------------------------------------------------------------------------
@
@ __KeccakP1600_AddBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@  r7 to bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r9
@
.align 8
__KeccakP1600_AddBytesInLane:
    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    add     r2, r2, sp
__KeccakP1600_AddBytesInLane_Loop:
    ldrb    r5, [r1]
    strb    r5, [r2]
    adds    r1, r1, #1
    adds    r2, r2, #1
    subs    r3, r3, #1
    bne     __KeccakP1600_AddBytesInLane_Loop
    pop     { r4 - r5 }
    mov     r8, r4
    mov     r9, r5
    toBitInterleaving   r8, r9, r4, r5, r6, r2, r7
    ldr     r6, [r0]
    eors    r4, r4, r6
    ldr     r6, [r0, #4]
    eors    r5, r5, r6
    stmia   r0!, { r4, r5 }
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_OverwriteBytes
.type	KeccakP1600_OverwriteBytes, %function;
KeccakP1600_OverwriteBytes:
    cmp     r3, #0                                  @ .if length != 0
    beq     KeccakP1600_OverwriteBytes_Exit1
    push    {r4 - r6, lr}                           @ then
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    push    {r4 - r7}
    lsrs    r4, r2, #3                              @ offset &= ~7
    lsls    r4, r4, #3
    adds    r0, r0, r4                              @ add whole lane offset to state pointer
    lsls    r2, r2, #29                             @ offset &= 7 (part not lane aligned)
    lsrs    r2, r2, #29
    beq     KeccakP1600_OverwriteBytes_CheckLanes   @ .if offset != 0
    movs    r4, r3                                  @ then, do remaining bytes in first lane
    movs    r5, #8
    subs    r5, r2                                  @ max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_OverwriteBytes_BytesAlign
    movs    r4, r5
KeccakP1600_OverwriteBytes_BytesAlign:
    subs    r3, r3, r4                              @ size left
    mov     r10, r3
    movs    r3, r4
    adr     r7, KeccakP1600_OverwriteBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_OverwriteBytesInLane
    mov     r3, r10
KeccakP1600_OverwriteBytes_CheckLanes:
    lsrs    r2, r3, #3                              @ .if length >= 8
    beq     KeccakP1600_OverwriteBytes_Bytes
    mov     r10, r3
    adr     r3, KeccakP1600_OverwriteBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_OverwriteLanes
    mov     r3, r10
    lsls    r3, r3, #29
    lsrs    r3, r3, #29
KeccakP1600_OverwriteBytes_Bytes:
    cmp     r3, #0
    beq     KeccakP1600_OverwriteBytes_Exit
    movs    r2, #0
    adr     r7, KeccakP1600_OverwriteBytes_ToBitInterleavingConstants
    bl      __KeccakP1600_OverwriteBytesInLane
KeccakP1600_OverwriteBytes_Exit:
    pop     {r4 - r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    pop     {r4 - r6, pc}
KeccakP1600_OverwriteBytes_Exit1:
    bx      lr
    nop
KeccakP1600_OverwriteBytes_ToBitInterleavingConstants:
		.long      0x55555555
		.long      0x33333333
		.long      0x0F0F0F0F
		.long      0x00FF00FF
		.long      0xAAAAAAAA
		.long      0xCCCCCCCC
		.long      0xF0F0F0F0
		.long      0xFF00FF00


@----------------------------------------------------------------------------
@
@ __KeccakP1600_OverwriteLanes
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 laneCount
@  r3 to bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r9
@
.align 8
__KeccakP1600_OverwriteLanes:
    lsls    r4, r1, #30
    bne     __KeccakP1600_OverwriteLanes_LoopUnaligned
__KeccakP1600_OverwriteLanes_LoopAligned:
    ldmia   r1!, {r6,r7}
    mov     r8, r6
    mov     r9, r7
    toBitInterleaving   r8, r9, r6, r7, r5, r4, r3
    stmia   r0!, {r6,r7}
    subs    r2, r2, #1
    bne     __KeccakP1600_OverwriteLanes_LoopAligned
    bx      lr
__KeccakP1600_OverwriteLanes_LoopUnaligned:
    ldrb    r6, [r1, #0]
    ldrb    r4, [r1, #1]
    lsls    r4, r4, #8
    orrs    r6, r6, r4
    ldrb    r4, [r1, #2]
    lsls    r4, r4, #16
    orrs    r6, r6, r4
    ldrb    r4, [r1, #3]
    lsls    r4, r4, #24
    orrs    r6, r6, r4
    ldrb    r7, [r1, #4]
    ldrb    r4, [r1, #5]
    lsls    r4, r4, #8
    orrs    r7, r7, r4
    ldrb    r4, [r1, #6]
    lsls    r4, r4, #16
    orrs    r7, r7, r4
    ldrb    r4, [r1, #7]
    lsls    r4, r4, #24
    orrs    r7, r7, r4
    adds    r1, r1, #8
    mov     r8, r6
    mov     r9, r7
    toBitInterleaving   r8, r9, r6, r7, r5, r4, r3
    stmia   r0!, {r6, r7}
    subs    r2, r2, #1
    bne     __KeccakP1600_OverwriteLanes_LoopUnaligned
    bx      lr


@----------------------------------------------------------------------------
@
@ __KeccakP1600_OverwriteBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@  r7 to bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r9
@
.align 8
__KeccakP1600_OverwriteBytesInLane:
    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    lsls    r6, r2, #2
    add     r2, r2, sp
    movs    r4, #0x0F                       @r4 mask to wipe nibbles(bit interleaved bytes) in state
    lsls    r4, r4, r6
    movs    r6, r4
__KeccakP1600_OverwriteBytesInLane_Loop:
    orrs    r6, r6, r4
    lsls    r4, r4, #4
    ldrb    r5, [r1]
    strb    r5, [r2]
    adds    r1, r1, #1
    adds    r2, r2, #1
    subs    r3, r3, #1
    bne     __KeccakP1600_OverwriteBytesInLane_Loop
    pop     { r4 - r5 }
    mov     r8, r4
    mov     r9, r5
    toBitInterleaving   r8, r9, r4, r5, r3, r2, r7
    ldr     r3, [r0]
    bics    r3, r3, r6
    eors    r4, r4, r3
    ldr     r3, [r0, #4]
    bics    r3, r3, r6
    eors    r5, r5, r3
    stmia   r0!, { r4, r5 }
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount)
@
.align 8
.global   KeccakP1600_OverwriteWithZeroes
.type	KeccakP1600_OverwriteWithZeroes, %function;
KeccakP1600_OverwriteWithZeroes:
    push    {r4 - r5}
    lsrs    r2, r1, #3
    beq     KeccakP1600_OverwriteWithZeroes_Bytes
    movs    r4, #0
    movs    r5, #0
KeccakP1600_OverwriteWithZeroes_LoopLanes:
    stm     r0!, { r4, r5 }
    subs    r2, r2, #1
    bne     KeccakP1600_OverwriteWithZeroes_LoopLanes
KeccakP1600_OverwriteWithZeroes_Bytes:
    lsls    r1, r1, #32-3
    beq     KeccakP1600_OverwriteWithZeroes_Exit
    lsrs    r1, r1, #32-3
    movs    r3, #0x0F                       @r2 already zero, r3 = mask to wipe nibbles(bit interleaved bytes) in state
KeccakP1600_OverwriteWithZeroes_LoopBytes:
    orrs    r2, r2, r3
    lsls    r3, r3, #4
    subs    r1, r1, #1
    bne     KeccakP1600_OverwriteWithZeroes_LoopBytes
    ldr     r4, [r0]
    ldr     r5, [r0, #4]
    bics    r4, r4, r2
    bics    r5, r5, r2
    stm     r0!, { r4, r5 }
KeccakP1600_OverwriteWithZeroes_Exit:
    pop     {r4 - r5}
    bx      lr


@----------------------------------------------------------------------------
@
@ void KeccakP1600_ExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_ExtractBytes
.type	KeccakP1600_ExtractBytes, %function;
KeccakP1600_ExtractBytes:
    cmp     r3, #0                                  @ .if length != 0
    beq     KeccakP1600_ExtractBytes_Exit1
    push    {r4 - r6, lr}                           @ then
    mov     r4, r8
    push    {r4, r7}
    lsrs    r4, r2, #3                              @ offset &= ~7
    lsls    r4, r4, #3
    adds    r0, r0, r4                              @ add whole lane offset to state pointer
    lsls    r2, r2, #29                             @ offset &= 7 (part not lane aligned)
    lsrs    r2, r2, #29
    beq     KeccakP1600_ExtractBytes_CheckLanes @ .if offset != 0
    movs    r4, r3                                  @ then, do remaining bytes in first lane
    movs    r5, #8
    subs    r5, r2                                  @ max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_ExtractBytes_BytesAlign
    movs    r4, r5
KeccakP1600_ExtractBytes_BytesAlign:
    subs    r3, r3, r4                              @ size left
    mov     r8, r3
    movs    r3, r4
    adr     r7, KeccakP1600_ExtractBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractBytesInLane
    mov     r3, r8
KeccakP1600_ExtractBytes_CheckLanes:
    lsrs    r2, r3, #3                              @ .if length >= 8
    beq     KeccakP1600_ExtractBytes_Bytes
    mov     r8, r3
    adr     r3, KeccakP1600_ExtractBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractLanes
    mov     r3, r8
    lsls    r3, r3, #29
    lsrs    r3, r3, #29
KeccakP1600_ExtractBytes_Bytes:
    cmp     r3, #0
    beq     KeccakP1600_ExtractBytes_Exit
    movs    r2, #0
    adr     r7, KeccakP1600_ExtractBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractBytesInLane
KeccakP1600_ExtractBytes_Exit:
    pop     {r4,r7}
    mov     r8, r4
    pop     {r4 - r6, pc}
KeccakP1600_ExtractBytes_Exit1:
    bx      lr
    nop
KeccakP1600_ExtractBytes_FromBitInterleavingConstants:
		.long      0x0000FF00
		.long      0x00F000F0
		.long      0x0C0C0C0C
		.long      0x22222222


@----------------------------------------------------------------------------
@
@ __KeccakP1600_ExtractLanes
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 laneCount
@  r3 from bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to output
@
@  Changed: r2-r7
@
.align 8
__KeccakP1600_ExtractLanes:
    lsls    r4, r1, #30
    bne     __KeccakP1600_ExtractLanes_LoopUnaligned
__KeccakP1600_ExtractLanes_LoopAligned:
    ldmia   r0!, {r6,r7}
    fromBitInterleaving r6, r7, r5, r4, r3
    stmia   r1!, {r6,r7}
    subs    r2, r2, #1
    bne     __KeccakP1600_ExtractLanes_LoopAligned
    bx      lr
__KeccakP1600_ExtractLanes_LoopUnaligned:
    ldmia   r0!, {r6,r7}
    fromBitInterleaving r6, r7, r5, r4, r3
    strb    r6, [r1, #0]
    lsrs    r6, r6, #8
    strb    r6, [r1, #1]
    lsrs    r6, r6, #8
    strb    r6, [r1, #2]
    lsrs    r6, r6, #8
    strb    r6, [r1, #3]
    strb    r7, [r1, #4]
    lsrs    r7, r7, #8
    strb    r7, [r1, #5]
    lsrs    r7, r7, #8
    strb    r7, [r1, #6]
    lsrs    r7, r7, #8
    strb    r7, [r1, #7]
    adds    r1, r1, #8
    subs    r2, r2, #1
    bne     __KeccakP1600_ExtractLanes_LoopUnaligned
    bx      lr


@----------------------------------------------------------------------------
@
@ __KeccakP1600_ExtractBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@  r7 from bit interleaving constants pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to output
@
@  Changed: r2-r7
@
.align 8
__KeccakP1600_ExtractBytesInLane:
    ldmia   r0!, {r4,r5}
    push    {r0, r3}
    fromBitInterleaving r4, r5, r0, r3, r7
    pop     {r0, r3}
    push    {r4, r5}
    mov     r4, sp
    adds    r4, r4, r2
__KeccakP1600_ExtractBytesInLane_Loop:
    ldrb    r2, [r4]
    adds    r4, r4, #1
    strb    r2, [r1]
    adds    r1, r1, #1
    subs    r3, r3, #1
    bne     __KeccakP1600_ExtractBytesInLane_Loop
    add     sp, #8
    bx      lr


@----------------------------------------------------------------------------
@
@  void KeccakP1600_ExtractAndAddBytes(void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakP1600_ExtractAndAddBytes
.type	KeccakP1600_ExtractAndAddBytes, %function;
KeccakP1600_ExtractAndAddBytes:
    push    {r3 - r7, lr}
    mov     r4, r8
    mov     r5, r9
    push    {r4 - r5}
    mov     r9, r2
    mov     r2, r3
    ldr     r3, [sp, #8*4]
    cmp     r3, #0                                  @ .if length != 0
    beq     KeccakP1600_ExtractAndAddBytes_Exit
    lsrs    r4, r2, #3                              @ offset &= ~7
    lsls    r4, r4, #3
    adds    r0, r0, r4                              @ add whole lane offset to state pointer
    lsls    r2, r2, #29                             @ offset &= 7 (part not lane aligned)
    lsrs    r2, r2, #29
    beq     KeccakP1600_ExtractAndAddBytes_CheckLanes   @ .if offset != 0
    movs    r4, r3                                  @ then, do remaining bytes in first lane
    movs    r5, #8
    subs    r5, r2                                  @ max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_ExtractAndAddBytes_BytesAlign
    movs    r4, r5
KeccakP1600_ExtractAndAddBytes_BytesAlign:
    subs    r3, r3, r4                              @ size left
    mov     r8, r3
    movs    r3, r4
    adr     r7, KeccakP1600_ExtractAndAddBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractAndAddBytesInLane
    mov     r3, r8
KeccakP1600_ExtractAndAddBytes_CheckLanes:
    lsrs    r2, r3, #3                              @ .if length >= 8
    beq     KeccakP1600_ExtractAndAddBytes_Bytes
    mov     r8, r3
    adr     r3, KeccakP1600_ExtractAndAddBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractAndAddLanes
    mov     r3, r8
    lsls    r3, r3, #29
    lsrs    r3, r3, #29
KeccakP1600_ExtractAndAddBytes_Bytes:
    cmp     r3, #0
    beq     KeccakP1600_ExtractAndAddBytes_Exit
    movs    r2, #0
    adr     r7, KeccakP1600_ExtractAndAddBytes_FromBitInterleavingConstants
    bl      __KeccakP1600_ExtractAndAddBytesInLane
KeccakP1600_ExtractAndAddBytes_Exit:
    pop     {r4 - r5}
    mov     r8, r4
    mov     r9, r5
    pop     {r3 - r7, pc}
.align 8
KeccakP1600_ExtractAndAddBytes_FromBitInterleavingConstants:
		.long      0x0000FF00
		.long      0x00F000F0
		.long      0x0C0C0C0C
		.long      0x22222222


@----------------------------------------------------------------------------
@
@ __KeccakP1600_ExtractAndAddLanes
@
@ Input:
@  r0 state pointer
@  r1 in pointer
@  r2 laneCount
@  r3 from bit interleaving constants pointer
@  r9 out pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 in pointer (next lane)
@  r9 out pointer (next lane)
@
@  Changed: r2-r7
@
.align 8
__KeccakP1600_ExtractAndAddLanes:
    lsls    r4, r1, #30
    bne     __KeccakP1600_ExtractAndAddLanes_LoopUnaligned
    mov     r4, r9
    lsls    r4, r4, #30
    bne     __KeccakP1600_ExtractAndAddLanes_LoopUnaligned
__KeccakP1600_ExtractAndAddLanes_LoopAligned:
    ldmia   r0!, {r6,r7}
    fromBitInterleaving r6, r7, r5, r4, r3
    mov     r4, r9
    ldm     r1!, {r5}
    eors    r6, r6, r5
    ldm     r1!, {r5}
    eors    r7, r7, r5
    stmia   r4!, {r6,r7}
    mov     r9, r4
    subs    r2, r2, #1
    bne     __KeccakP1600_ExtractAndAddLanes_LoopAligned
    bx      lr
__KeccakP1600_ExtractAndAddLanes_LoopUnaligned:
    ldmia   r0!, {r6,r7}
    fromBitInterleaving r6, r7, r5, r4, r3
    mov     r4, r9
    ldrb    r5, [r1, #0]
    eors    r5, r5, r6
    strb    r5, [r4, #0]
    lsrs    r6, r6, #8
    ldrb    r5, [r1, #1]
    eors    r5, r5, r6
    strb    r5, [r4, #1]
    lsrs    r6, r6, #8
    ldrb    r5, [r1, #2]
    eors    r5, r5, r6
    strb    r5, [r4, #2]
    lsrs    r6, r6, #8
    ldrb    r5, [r1, #3]
    eors    r5, r5, r6
    strb    r5, [r4, #3]
    ldrb    r5, [r1, #4]
    eors    r5, r5, r7
    strb    r5, [r4, #4]
    lsrs    r7, r7, #8
    ldrb    r5, [r1, #5]
    eors    r5, r5, r7
    strb    r5, [r4, #5]
    lsrs    r7, r7, #8
    ldrb    r5, [r1, #6]
    eors    r5, r5, r7
    strb    r5, [r4, #6]
    lsrs    r7, r7, #8
    ldrb    r5, [r1, #7]
    eors    r5, r5, r7
    strb    r5, [r4, #7]
    adds    r1, r1, #8
    adds    r4, r4, #8
    mov     r9, r4
    subs    r2, r2, #1
    bne     __KeccakP1600_ExtractAndAddLanes_LoopUnaligned
    bx      lr


@----------------------------------------------------------------------------
@
@ __KeccakP1600_ExtractAndAddBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@  r7 from bit interleaving constants pointer
@  r9 out pointer
@
@ Output:
@  r0 state pointer next lane
@  r1 in pointer (next byte)
@  r9 out pointer (next byte)
@
@  Changed: r2-r7
@
.align 8
__KeccakP1600_ExtractAndAddBytesInLane:
    ldmia   r0!, {r4,r5}
    push    {r0, r3}
    fromBitInterleaving r4, r5, r0, r3, r7
    pop     {r0, r3}
    push    {r4, r5}
    mov     r4, sp
    adds    r4, r4, r2
    mov     r6, r9
__KeccakP1600_ExtractAndAddBytesInLane_Loop:
    ldrb    r2, [r4]
    adds    r4, r4, #1
    ldrb    r5, [r1]
    eors    r2, r2, r5
    strb    r2, [r6]
    adds    r1, r1, #1
    adds    r6, r6, #1
    subs    r3, r3, #1
    bne     __KeccakP1600_ExtractAndAddBytesInLane_Loop
    add     sp, #8
    mov     r9, r6
    bx      lr



.macro    ldrf    result,offset
    .if      \offset >= 128
    ldr     \result, [r5, #\offset-128]
    .else
    ldr     \result, [r0, #\offset]
    .endif
    .endm

.macro    strf    result,offset
    .if      \offset >= 128
    str     \result, [r5, #\offset-128]
    .else
    str     \result, [r0, #\offset]
    .endif
    .endm

.macro    SwapPI13 in0,in1,in2,in3,eo0,eo1,eo2,eo3
    ldrf    r3, \in0+0
    ldrf    r4, \in0+4
    ldrf    r2, \in1+0
    ldrf    r1, \in1+4
    strf    r2, \in0+\eo0*4
    strf    r1, \in0+(\eo0^1)*4
    ldrf    r2, \in2+0
    ldrf    r1, \in2+4
    strf    r2, \in1+\eo1*4
    strf    r1, \in1+(\eo1^1)*4
    ldrf    r2, \in3+0
    ldrf    r1, \in3+4
    strf    r2, \in2+\eo2*4
    strf    r1, \in2+(\eo2^1)*4
    strf    r3, \in3+\eo3*4
    strf    r4, \in3+(\eo3^1)*4
    .endm

.macro    SwapPI2 in0,in1,in2,in3
    ldrf    r3, \in0+0
    ldrf    r4, \in0+4
    ldrf    r2, \in1+0
    ldrf    r1, \in1+4
    strf    r2, \in0+4
    strf    r1, \in0+0
    strf    r3, \in1+4
    strf    r4, \in1+0
    ldrf    r3, \in2+0
    ldrf    r4, \in2+4
    ldrf    r2, \in3+0
    ldrf    r1, \in3+4
    strf    r2, \in2+4
    strf    r1, \in2+0
    strf    r3, \in3+4
    strf    r4, \in3+0
    .endm

.macro    SwapEO  even,odd
    ldrf    r3, \even
    ldrf    r4, \odd
    strf    r3, \odd
    strf    r4, \even
    .endm

@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_Permute_Nrounds(void *state, unsigned int nrounds)
@
.align 8
.global   KeccakP1600_Permute_Nrounds
.type	KeccakP1600_Permute_Nrounds, %function;
KeccakP1600_Permute_Nrounds:
    lsls    r2, r1, #30
    bne     KeccakP1600_Permute_NroundsNotMultiple4
    lsls    r2, r1, #3
    adr     r1, KeccakP1600_Permute_RoundConstants0Mod4
    subs    r1, r1, r2
    b       KeccakP1600_Permute
KeccakP1600_Permute_NroundsNotMultiple4:     @ nrounds not multiple of 4
    push    { r4 - r6, lr }
    mov     r2, r8
    mov     r3, r9
    mov     r4, r10
    mov     r5, r11
    mov     r6, r12
    push    { r2 - r7 }
    sub     sp, #mSize
    mov     r3, r1
    lsrs    r2, r1, #2
    lsls    r2, r2, #3+2
    adr     r1, KeccakP1600_Permute_RoundConstants0
    subs    r1, r1, r2
    str     r1, [sp, #mRC]
    mov     r5, r0
    adds    r5, r5, #128
    lsls    r3, r3, #31
    bcs     KeccakP1600_Permute_Nrounds23Mod4
KeccakP1600_Permute_Nrounds1Mod4:
    SwapPI13 Aga0, Aka0, Asa0, Ama0, 1, 0, 1, 0
    SwapPI13 Abe0, Age0, Ame0, Ake0, 0, 1, 0, 1
    SwapPI13 Abi0, Aki0, Agi0, Asi0, 1, 0, 1, 0
    SwapEO   Ami0, Ami1
    SwapPI13 Abo0, Amo0, Aso0, Ago0, 1, 0, 1, 0
    SwapEO   Ako0, Ako1
    SwapPI13 Abu0, Asu0, Aku0, Amu0, 0, 1, 0, 1
    ldr     r1, =KeccakP1600_Permute_Round1Mod4+1
    bx      r1
.align 8
    .ltorg
KeccakP1600_Permute_Nrounds23Mod4:
    bpl        KeccakP1600_Permute_Nrounds2Mod4
KeccakP1600_Permute_Nrounds3Mod4:
    SwapPI13 Aga0, Ama0, Asa0, Aka0, 0, 1, 0, 1
    SwapPI13 Abe0, Ake0, Ame0, Age0, 1, 0, 1, 0
    SwapPI13 Abi0, Asi0, Agi0, Aki0, 0, 1, 0, 1
    SwapEO   Ami0, Ami1
    SwapPI13 Abo0, Ago0, Aso0, Amo0, 0, 1, 0, 1
    SwapEO   Ako0, Ako1
    SwapPI13 Abu0, Amu0, Aku0, Asu0, 1, 0, 1, 0
    ldr     r1, =KeccakP1600_Permute_Round3Mod4+1
    bx      r1
.align 8
    .ltorg
KeccakP1600_Permute_Nrounds2Mod4:
    SwapPI2 Aga0, Asa0, Aka0, Ama0
    SwapPI2 Abe0, Ame0, Age0, Ake0
    SwapPI2 Abi0, Agi0, Aki0, Asi0
    SwapPI2 Abo0, Aso0, Ago0, Amo0
    SwapPI2 Abu0, Aku0, Amu0, Asu0
    ldr     r1, =KeccakP1600_Permute_Round2Mod4+1
    bx      r1
.align 8
    .ltorg


@ ----------------------------------------------------------------------------
@
@  void KeccakP1600_Permute_12rounds( void *state )
@
.align 8
.global   KeccakP1600_Permute_12rounds
.type	KeccakP1600_Permute_12rounds, %function;
KeccakP1600_Permute_12rounds:
    adr     r1, KeccakP1600_Permute_RoundConstants12
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
    b       KeccakP1600_Permute


.align 8
KeccakP1600_Permute_RoundConstants24:
    @       0           1
		.long      0x00000001, 0x00000000
		.long      0x00000000, 0x00000089
		.long      0x00000000, 0x8000008b
		.long      0x00000000, 0x80008080
		.long      0x00000001, 0x0000008b
		.long      0x00000001, 0x00008000
		.long      0x00000001, 0x80008088
		.long      0x00000001, 0x80000082
		.long      0x00000000, 0x0000000b
		.long      0x00000000, 0x0000000a
		.long      0x00000001, 0x00008082
		.long      0x00000000, 0x00008003
KeccakP1600_Permute_RoundConstants12:
		.long      0x00000001, 0x0000808b
		.long      0x00000001, 0x8000000b
		.long      0x00000001, 0x8000008a
		.long      0x00000001, 0x80000081
		.long      0x00000000, 0x80000081
		.long      0x00000000, 0x80000008
		.long      0x00000000, 0x00000083
		.long      0x00000000, 0x80008003
KeccakP1600_Permute_RoundConstants0:
		.long      0x00000001, 0x80008088
		.long      0x00000000, 0x80000088
		.long      0x00000001, 0x00008000
		.long      0x00000000, 0x80008082
KeccakP1600_Permute_RoundConstants0Mod4:
		.long      0x000000FF  @terminator

@----------------------------------------------------------------------------
@
@ void KeccakP1600_Permute( void *state, void * rc )
@
.align 8
KeccakP1600_Permute:
    push    { r4 - r6, lr }
    mov     r2, r8
    mov     r3, r9
    mov     r4, r10
    mov     r5, r11
    mov     r6, r12
    push    { r2 - r7 }
    sub     sp, #mSize
    str     r1, [sp, #mRC]
KeccakP1600_Permute_RoundLoop:
    KeccakRound0
KeccakP1600_Permute_Round3Mod4:
    KeccakRound1
KeccakP1600_Permute_Round2Mod4:
    KeccakRound2
KeccakP1600_Permute_Round1Mod4:
    KeccakRound3
    beq     KeccakP1600_Permute_Done
    ldr     r1, =KeccakP1600_Permute_RoundLoop+1
    bx      r1
    .ltorg
KeccakP1600_Permute_Done:
    add     sp, #mSize
    pop     { r1 - r5, r7 }
    mov     r8, r1
    mov     r9, r2
    mov     r10, r3
    mov     r11, r4
    mov     r12, r5
    pop     { r4 - r6, pc }


