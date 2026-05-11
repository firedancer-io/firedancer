;
; The eXtended Keccak Code Package (XKCP)
; https://github.com/XKCP/XKCP
;
; The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.
;
; Implementation by Ronny Van Keer, hereby denoted as "the implementer".
;
; For more information, feedback or questions, please refer to the Keccak Team website:
; https://keccak.team/
;
; To the extent possible under law, the implementer has waived all copyright
; and related or neighboring rights to the source code in this file.
; http://creativecommons.org/publicdomain/zero/1.0/
;
; ---
;
; This file implements Keccak-p[1600] in a SnP-compatible way.
; Please refer to SnP-documentation.h for more details.
;
; This implementation comes with KeccakP-1600-SnP.h in the same folder.
; Please refer to LowLevel.build for the exact list of other files it must be combined with.
;

; WARNING: This implementation assumes a little endian CPU with ARMv7M architecture (e.g., Cortex-M3) and the ARMCC compiler.

    PRESERVE8
    THUMB
    AREA    |.text|, CODE, READONLY

    ; Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
    MACRO
    toBitInterleaving   $x0,$x1,$s0,$s1,$t,$over

    and     $t,$x0,#0x55555555
    orr     $t,$t,$t, LSR #1
    and     $t,$t,#0x33333333
    orr     $t,$t,$t, LSR #2
    and     $t,$t,#0x0F0F0F0F
    orr     $t,$t,$t, LSR #4
    and     $t,$t,#0x00FF00FF
    bfi     $t,$t,#8, #8
    if $over != 0
    lsr     $s0,$t, #8
    else
    eor     $s0,$s0,$t, LSR #8
    endif

    and     $t,$x1,#0x55555555
    orr     $t,$t,$t, LSR #1
    and     $t,$t,#0x33333333
    orr     $t,$t,$t, LSR #2
    and     $t,$t,#0x0F0F0F0F
    orr     $t,$t,$t, LSR #4
    and     $t,$t,#0x00FF00FF
    orr     $t,$t,$t, LSR #8
    eor     $s0,$s0,$t, LSL #16

    and     $t,$x0,#0xAAAAAAAA
    orr     $t,$t,$t, LSL #1
    and     $t,$t,#0xCCCCCCCC
    orr     $t,$t,$t, LSL #2
    and     $t,$t,#0xF0F0F0F0
    orr     $t,$t,$t, LSL #4
    and     $t,$t,#0xFF00FF00
    orr     $t,$t,$t, LSL #8
    if $over != 0
    lsr     $s1,$t, #16
    else
    eor     $s1,$s1,$t, LSR #16
    endif

    and     $t,$x1,#0xAAAAAAAA
    orr     $t,$t,$t, LSL #1
    and     $t,$t,#0xCCCCCCCC
    orr     $t,$t,$t, LSL #2
    and     $t,$t,#0xF0F0F0F0
    orr     $t,$t,$t, LSL #4
    and     $t,$t,#0xFF00FF00
    orr     $t,$t,$t, LSL #8
    bfc     $t, #0, #16
    eors    $s1,$s1,$t
    MEND

    ; Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
    MACRO
    fromBitInterleaving     $x0, $x1, $t

    movs    $t, $x0                 ; t = x0;
    bfi     $x0, $x1, #16, #16      ; x0 = (x0 & 0x0000FFFF) | (x1 << 16);
    bfc     $x1, #0, #16            ;   x1 = (t >> 16) | (x1 & 0xFFFF0000);
    orr     $x1, $x1, $t, LSR #16

    eor     $t, $x0, $x0, LSR #8    ; t = (x0 ^ (x0 >>  8)) & 0x0000FF00UL;  x0 = x0 ^ t ^ (t <<  8);
    and     $t, #0x0000FF00
    eors    $x0, $x0, $t
    eor     $x0, $x0, $t, LSL #8

    eor     $t, $x0, $x0, LSR #4    ; t = (x0 ^ (x0 >>  4)) & 0x00F000F0UL;  x0 = x0 ^ t ^ (t <<  4);
    and     $t, #0x00F000F0
    eors    $x0, $x0, $t
    eor     $x0, $x0, $t, LSL #4

    eor     $t, $x0, $x0, LSR #2    ; t = (x0 ^ (x0 >>  2)) & 0x0C0C0C0CUL;  x0 = x0 ^ t ^ (t <<  2);
    and     $t, #0x0C0C0C0C
    eors    $x0, $x0, $t
    eor     $x0, $x0, $t, LSL #2

    eor     $t, $x0, $x0, LSR #1    ; t = (x0 ^ (x0 >>  1)) & 0x22222222UL;  x0 = x0 ^ t ^ (t <<  1);
    and     $t, #0x22222222
    eors    $x0, $x0, $t
    eor     $x0, $x0, $t, LSL #1

    eor     $t, $x1, $x1, LSR #8    ; t = (x1 ^ (x1 >>  8)) & 0x0000FF00UL;  x1 = x1 ^ t ^ (t <<  8);
    and     $t, #0x0000FF00
    eors    $x1, $x1, $t
    eor     $x1, $x1, $t, LSL #8

    eor     $t, $x1, $x1, LSR #4    ; t = (x1 ^ (x1 >>  4)) & 0x00F000F0UL;  x1 = x1 ^ t ^ (t <<  4);
    and     $t, #0x00F000F0
    eors    $x1, $x1, $t
    eor     $x1, $x1, $t, LSL #4

    eor     $t, $x1, $x1, LSR #2    ; t = (x1 ^ (x1 >>  2)) & 0x0C0C0C0CUL;  x1 = x1 ^ t ^ (t <<  2);
    and     $t, #0x0C0C0C0C
    eors    $x1, $x1, $t
    eor     $x1, $x1, $t, LSL #2

    eor     $t, $x1, $x1, LSR #1    ; t = (x1 ^ (x1 >>  1)) & 0x22222222UL;  x1 = x1 ^ t ^ (t <<  1);
    and     $t, #0x22222222
    eors    $x1, $x1, $t
    eor     $x1, $x1, $t, LSL #1
    MEND

;   --- offsets in state
Aba0    equ  0*4
Aba1    equ  1*4
Abe0    equ  2*4
Abe1    equ  3*4
Abi0    equ  4*4
Abi1    equ  5*4
Abo0    equ  6*4
Abo1    equ  7*4
Abu0    equ  8*4
Abu1    equ  9*4
Aga0    equ 10*4
Aga1    equ 11*4
Age0    equ 12*4
Age1    equ 13*4
Agi0    equ 14*4
Agi1    equ 15*4
Ago0    equ 16*4
Ago1    equ 17*4
Agu0    equ 18*4
Agu1    equ 19*4
Aka0    equ 20*4
Aka1    equ 21*4
Ake0    equ 22*4
Ake1    equ 23*4
Aki0    equ 24*4
Aki1    equ 25*4
Ako0    equ 26*4
Ako1    equ 27*4
Aku0    equ 28*4
Aku1    equ 29*4
Ama0    equ 30*4
Ama1    equ 31*4
Ame0    equ 32*4
Ame1    equ 33*4
Ami0    equ 34*4
Ami1    equ 35*4
Amo0    equ 36*4
Amo1    equ 37*4
Amu0    equ 38*4
Amu1    equ 39*4
Asa0    equ 40*4
Asa1    equ 41*4
Ase0    equ 42*4
Ase1    equ 43*4
Asi0    equ 44*4
Asi1    equ 45*4
Aso0    equ 46*4
Aso1    equ 47*4
Asu0    equ 48*4
Asu1    equ 49*4

;   --- offsets on stack
mDa0    equ 0*4
mDa1    equ 1*4
mDo0    equ 2*4
mDo1    equ 3*4
mDi0    equ 4*4
mRC     equ 5*4
mSize   equ 6*4


    MACRO
    xor5        $result,$b,$g,$k,$m,$s

    ldr         $result, [r0, #$b]
    ldr         r1, [r0, #$g]
    eors        $result, $result, r1
    ldr         r1, [r0, #$k]
    eors        $result, $result, r1
    ldr         r1, [r0, #$m]
    eors        $result, $result, r1
    ldr         r1, [r0, #$s]
    eors        $result, $result, r1
    MEND

    MACRO
    xorrol      $result, $aa, $bb

    eor         $result, $aa, $bb, ROR #31
    MEND

    MACRO
    xandnot     $resofs, $aa, $bb, $cc

    bic         r1, $cc, $bb
    eors        r1, r1, $aa
    str         r1, [r0, #$resofs]
    MEND

    MACRO
    KeccakThetaRhoPiChiIota $aA1, $aDax, $aA2, $aDex, $rot2, $aA3, $aDix, $rot3, $aA4, $aDox, $rot4, $aA5, $aDux, $rot5, $offset, $last
    ldr     r3, [r0, #$aA1]
    ldr     r4, [r0, #$aA2]
    ldr     r5, [r0, #$aA3]
    ldr     r6, [r0, #$aA4]
    ldr     r7, [r0, #$aA5]
    eors    r3, r3, $aDax
    eors    r5, r5, $aDix
    eors    r4, r4, $aDex
    eors    r6, r6, $aDox
    eors    r7, r7, $aDux
    rors    r4, #32-$rot2
    rors    r5, #32-$rot3
    rors    r6, #32-$rot4
    rors    r7, #32-$rot5
    xandnot $aA2, r4, r5, r6
    xandnot $aA3, r5, r6, r7
    xandnot $aA4, r6, r7, r3
    xandnot $aA5, r7, r3, r4
    ldr     r1, [sp, #mRC]
    bics    r5, r5, r4
    ldr     r4, [r1, #$offset]
    eors    r3, r3, r5
    eors    r3, r3, r4
    IF  $last == 1
    ldr     r4, [r1, #32]!
    str     r1, [sp, #mRC]
    cmp     r4, #0xFF
    ENDIF
    str     r3, [r0, #$aA1]
    MEND

    MACRO
    KeccakThetaRhoPiChi $aB1, $aA1, $aDax, $rot1, $aB2, $aA2, $aDex, $rot2, $aB3, $aA3, $aDix, $rot3, $aB4, $aA4, $aDox, $rot4, $aB5, $aA5, $aDux, $rot5
    ldr     $aB1, [r0, #$aA1]
    ldr     $aB2, [r0, #$aA2]
    ldr     $aB3, [r0, #$aA3]
    ldr     $aB4, [r0, #$aA4]
    ldr     $aB5, [r0, #$aA5]
    eors    $aB1, $aB1, $aDax
    eors    $aB3, $aB3, $aDix
    eors    $aB2, $aB2, $aDex
    eors    $aB4, $aB4, $aDox
    eors    $aB5, $aB5, $aDux
    rors    $aB1, #32-$rot1
    IF  $rot2 > 0
    rors    $aB2, #32-$rot2
    ENDIF
    rors    $aB3, #32-$rot3
    rors    $aB4, #32-$rot4
    rors    $aB5, #32-$rot5
    xandnot $aA1, r3, r4, r5
    xandnot $aA2, r4, r5, r6
    xandnot $aA3, r5, r6, r7
    xandnot $aA4, r6, r7, r3
    xandnot $aA5, r7, r3, r4
    MEND

    MACRO
    KeccakRound0

    xor5        r3,  Abu0, Agu0, Aku0, Amu0, Asu0
    xor5        r7, Abe1, Age1, Ake1, Ame1, Ase1
    xorrol      r6, r3, r7
    str         r6, [sp, #mDa0]
    xor5        r6,  Abu1, Agu1, Aku1, Amu1, Asu1
    xor5        lr, Abe0, Age0, Ake0, Ame0, Ase0
    eors        r8, r6, lr
    str         r8, [sp, #mDa1]

    xor5        r5,  Abi0, Agi0, Aki0, Ami0, Asi0
    xorrol      r9, r5, r6
    str         r9, [sp, #mDo0]
    xor5        r4,  Abi1, Agi1, Aki1, Ami1, Asi1
    eors        r3, r3, r4
    str         r3, [sp, #mDo1]

    xor5        r3,  Aba0, Aga0, Aka0, Ama0, Asa0
    xorrol      r10, r3, r4
    xor5        r6,  Aba1, Aga1, Aka1, Ama1, Asa1
    eors        r11, r6, r5

    xor5        r4,  Abo1, Ago1, Ako1, Amo1, Aso1
    xorrol      r5, lr, r4
    str         r5, [sp, #mDi0]
    xor5        r5,  Abo0, Ago0, Ako0, Amo0, Aso0
    eors        r2, r7, r5

    xorrol      r12, r5, r6
    eors        lr, r4, r3

    KeccakThetaRhoPiChi r5, Aka1, r8,  2, r6, Ame1, r11, 23, r7, Asi1, r2, 31, r3, Abo0, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Asa1, r8,  9, r3, Abe0, r10,  0, r4, Agi1, r2,  3, r5, Ako0, r9, 12, r6, Amu1, lr,  4
    ldr         r8, [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Aga0, r8, 18, r5, Ake0, r10,  5, r6, Ami1, r2,  8, r7, Aso0, r9, 28, r3, Abu1, lr, 14
    KeccakThetaRhoPiChi r6, Ama0, r8, 20, r7, Ase1, r11,  1, r3, Abi1, r2, 31, r4, Ago0, r9, 27, r5, Aku0, r12, 19
    ldr         r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota  Aba0, r8,          Age0, r10, 22,      Aki1, r2, 22,      Amo1, r9, 11,      Asu0, r12,  7, 0, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aka0, r8,  1, r6, Ame0, r10, 22, r7, Asi0, r2, 30, r3, Abo1, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Asa0, r8,  9, r3, Abe1, r11,  1, r4, Agi0, r2,  3, r5, Ako1, r9, 13, r6, Amu0, r12,  4
    ldr         r8, [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Aga1, r8, 18, r5, Ake1, r11,  5, r6, Ami0, r2,  7, r7, Aso1, r9, 28, r3, Abu0, r12, 13
    KeccakThetaRhoPiChi r6, Ama1, r8, 21, r7, Ase0, r10,  1, r3, Abi0, r2, 31, r4, Ago1, r9, 28, r5, Aku1, lr, 20
    ldr         r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota  Aba1, r8,          Age1, r11, 22,      Aki0, r2, 21,      Amo0, r9, 10,      Asu1, lr,  7, 4, 0
    MEND

    MACRO
    KeccakRound1

    xor5        r3,  Asu0, Agu0, Amu0, Abu1, Aku1
    xor5        r7, Age1, Ame0, Abe0, Ake1, Ase1
    xorrol      r6, r3, r7
    str         r6, [sp, #mDa0]
    xor5        r6,  Asu1, Agu1, Amu1, Abu0, Aku0
    xor5        lr, Age0, Ame1, Abe1, Ake0, Ase0
    eors        r8, r6, lr
    str         r8, [sp, #mDa1]

    xor5        r5,  Aki1, Asi1, Agi0, Ami1, Abi0
    xorrol      r9, r5, r6
    str         r9, [sp, #mDo0]
    xor5        r4,  Aki0, Asi0, Agi1, Ami0, Abi1
    eors        r3, r3, r4
    str         r3, [sp, #mDo1]

    xor5        r3,  Aba0, Aka1, Asa0, Aga0, Ama1
    xorrol      r10, r3, r4
    xor5        r6,  Aba1, Aka0, Asa1, Aga1, Ama0
    eors        r11, r6, r5

    xor5        r4,  Amo0, Abo1, Ako0, Aso1, Ago0
    xorrol      r5, lr, r4
    str         r5, [sp, #mDi0]
    xor5        r5,  Amo1, Abo0, Ako1, Aso0, Ago1
    eors        r2, r7, r5

    xorrol      r12, r5, r6
    eors        lr, r4, r3

    KeccakThetaRhoPiChi r5, Asa1, r8,  2, r6, Ake1, r11, 23, r7, Abi1, r2, 31, r3, Amo1, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Ama0, r8,  9, r3, Age0, r10,  0, r4, Asi0, r2,  3, r5, Ako1, r9, 12, r6, Abu0, lr,  4
    ldr         r8, [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Aka1, r8, 18, r5, Abe1, r10,  5, r6, Ami0, r2,  8, r7, Ago1, r9, 28, r3, Asu1, lr, 14
    KeccakThetaRhoPiChi r6, Aga0, r8, 20, r7, Ase1, r11,  1, r3, Aki0, r2, 31, r4, Abo0, r9, 27, r5, Amu0, r12, 19
    ldr         r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota  Aba0, r8,          Ame1, r10, 22,      Agi1, r2, 22,      Aso1, r9, 11,      Aku1, r12,  7, 8, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Asa0, r8,  1, r6, Ake0, r10, 22, r7, Abi0, r2, 30, r3, Amo0, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Ama1, r8,  9, r3, Age1, r11,  1, r4, Asi1, r2,  3, r5, Ako0, r9, 13, r6, Abu1, r12,  4
    ldr         r8, [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Aka0, r8, 18, r5, Abe0, r11,  5, r6, Ami1, r2,  7, r7, Ago0, r9, 28, r3, Asu0, r12, 13
    KeccakThetaRhoPiChi r6, Aga1, r8, 21, r7, Ase0, r10,  1, r3, Aki1, r2, 31, r4, Abo1, r9, 28, r5, Amu1, lr, 20
    ldr         r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota  Aba1, r8,          Ame0, r11, 22,      Agi0, r2, 21,      Aso0, r9, 10,      Aku0, lr,  7, 12, 0
    MEND

    MACRO
    KeccakRound2

    xor5        r3, Aku1, Agu0, Abu1, Asu1, Amu1
    xor5        r7, Ame0, Ake0, Age0, Abe0, Ase1
    xorrol      r6, r3, r7
    str         r6, [sp, #mDa0]
    xor5        r6,  Aku0, Agu1, Abu0, Asu0, Amu0
    xor5        lr, Ame1, Ake1, Age1, Abe1, Ase0
    eors        r8, r6, lr
    str         r8, [sp, #mDa1]

    xor5        r5,  Agi1, Abi1, Asi1, Ami0, Aki1
    xorrol      r9, r5, r6
    str         r9, [sp, #mDo0]
    xor5        r4,  Agi0, Abi0, Asi0, Ami1, Aki0
    eors        r3, r3, r4
    str         r3, [sp, #mDo1]

    xor5        r3,  Aba0, Asa1, Ama1, Aka1, Aga1
    xorrol      r10, r3, r4
    xor5        r6,  Aba1, Asa0, Ama0, Aka0, Aga0
    eors        r11, r6, r5

    xor5        r4,  Aso0, Amo0, Ako1, Ago0, Abo0
    xorrol      r5, lr, r4
    str         r5, [sp, #mDi0]
    xor5        r5,  Aso1, Amo1, Ako0, Ago1, Abo1
    eors        r2, r7, r5

    xorrol      r12, r5, r6
    eors        lr, r4, r3

    KeccakThetaRhoPiChi r5, Ama0, r8,  2, r6, Abe0, r11, 23, r7, Aki0, r2, 31, r3, Aso1, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aga0, r8,  9, r3, Ame1, r10,  0, r4, Abi0, r2,  3, r5, Ako0, r9, 12, r6, Asu0, lr,  4
    ldr         r8, [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Asa1, r8, 18, r5, Age1, r10,  5, r6, Ami1, r2,  8, r7, Abo1, r9, 28, r3, Aku0, lr, 14
    KeccakThetaRhoPiChi r6, Aka1, r8, 20, r7, Ase1, r11,  1, r3, Agi0, r2, 31, r4, Amo1, r9, 27, r5, Abu1, r12, 19
    ldr         r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota  Aba0, r8,          Ake1, r10, 22,      Asi0, r2, 22,      Ago0, r9, 11,      Amu1, r12,  7, 16, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Ama1, r8,  1, r6, Abe1, r10, 22, r7, Aki1, r2, 30, r3, Aso0, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Aga1, r8,  9, r3, Ame0, r11,  1, r4, Abi1, r2,  3, r5, Ako1, r9, 13, r6, Asu1, r12,  4
    ldr         r8, [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Asa0, r8, 18, r5, Age0, r11,  5, r6, Ami0, r2,  7, r7, Abo0, r9, 28, r3, Aku1, r12, 13
    KeccakThetaRhoPiChi r6, Aka0, r8, 21, r7, Ase0, r10,  1, r3, Agi1, r2, 31, r4, Amo0, r9, 28, r5, Abu0, lr, 20
    ldr         r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota  Aba1, r8,          Ake0, r11, 22,      Asi1, r2, 21,      Ago1, r9, 10,      Amu0, lr,  7, 20, 0
    MEND

    MACRO
    KeccakRound3

    xor5        r3,  Amu1, Agu0, Asu1, Aku0, Abu0
    xor5        r7, Ake0, Abe1, Ame1, Age0, Ase1
    xorrol      r6, r3, r7
    str         r6, [sp, #mDa0]
    xor5        r6,  Amu0, Agu1, Asu0, Aku1, Abu1
    xor5        lr, Ake1, Abe0, Ame0, Age1, Ase0
    eors        r8, r6, lr
    str         r8, [sp, #mDa1]

    xor5        r5,  Asi0, Aki0, Abi1, Ami1, Agi1
    xorrol      r9, r5, r6
    str         r9, [sp, #mDo0]
    xor5        r4,  Asi1, Aki1, Abi0, Ami0, Agi0
    eors        r3, r3, r4
    str         r3, [sp, #mDo1]

    xor5        r3,  Aba0, Ama0, Aga1, Asa1, Aka0
    xorrol      r10, r3, r4
    xor5        r6,  Aba1, Ama1, Aga0, Asa0, Aka1
    eors        r11, r6, r5

    xor5        r4,  Ago1, Aso0, Ako0, Abo0, Amo1
    xorrol      r5, lr, r4
    str         r5, [sp, #mDi0]
    xor5        r5,  Ago0, Aso1, Ako1, Abo1, Amo0
    eors        r2, r7, r5

    xorrol      r12, r5, r6
    eors        lr, r4, r3

    KeccakThetaRhoPiChi r5, Aga0, r8,  2, r6, Age0, r11, 23, r7, Agi0, r2, 31, r3, Ago0, r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aka1, r8,  9, r3, Ake1, r10,  0, r4, Aki1, r2,  3, r5, Ako1, r9, 12, r6, Aku1, lr,  4
    ldr         r8, [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Ama0, r8, 18, r5, Ame0, r10,  5, r6, Ami0, r2,  8, r7, Amo0, r9, 28, r3, Amu0, lr, 14
    KeccakThetaRhoPiChi r6, Asa1, r8, 20, r7, Ase1, r11,  1, r3, Asi1, r2, 31, r4, Aso1, r9, 27, r5, Asu1, r12, 19
    ldr         r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota  Aba0, r8,          Abe0, r10, 22,      Abi0, r2, 22,      Abo0, r9, 11,      Abu0, r12,  7, 24, 0

    ldr         r2, [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aga1, r8,  1, r6, Age1, r10, 22, r7, Agi1, r2, 30, r3, Ago1, r9, 14, r4, Agu1, lr, 10
    KeccakThetaRhoPiChi r7, Aka0, r8,  9, r3, Ake0, r11,  1, r4, Aki0, r2,  3, r5, Ako0, r9, 13, r6, Aku0, r12,  4
    ldr         r8, [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Ama1, r8, 18, r5, Ame1, r11,  5, r6, Ami1, r2,  7, r7, Amo1, r9, 28, r3, Amu1, r12, 13
    KeccakThetaRhoPiChi r6, Asa0, r8, 21, r7, Ase0, r10,  1, r3, Asi0, r2, 31, r4, Aso0, r9, 28, r5, Asu0, lr, 20
    ldr         r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota  Aba1, r8,          Abe1, r11, 22,      Abi1, r2, 21,      Abo1, r9, 10,      Abu1, lr,  7, 28, 1
    MEND


;----------------------------------------------------------------------------
;
; void KeccakP1600_StaticInitialize( void )
;
    ALIGN
    EXPORT  KeccakP1600_StaticInitialize
KeccakP1600_StaticInitialize   PROC
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600_Initialize(void *state)
;
    ALIGN
    EXPORT  KeccakP1600_Initialize
KeccakP1600_Initialize   PROC
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
    ENDP

; ----------------------------------------------------------------------------
; 
;  void KeccakP1600_AddByte(void *state, unsigned char byte, unsigned int offset)
; 
    ALIGN
    EXPORT  KeccakP1600_AddByte
KeccakP1600_AddByte   PROC
    push    {r4 - r7}
    bic     r3, r2, #7                              ; r3 = offset & ~7
    adds    r0, r0, r3                              ; state += r3
    ands    r2, r2, #7                              ; offset &= 7 (part not lane aligned)

    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    add     r2, r2, sp
    strb    r1, [r2]
    pop     { r4 - r5 }
    ldrd    r6, r7, [r0]
    toBitInterleaving   r4, r5, r6, r7, r3, 0
    strd    r6, r7, [r0]
    pop     {r4 - r7}
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    ALIGN
    EXPORT  KeccakP1600_AddBytes
KeccakP1600_AddBytes   PROC
    cbz     r3, KeccakP1600_AddBytes_Exit1
    push    {r4 - r8, lr}                           ; then
    bic     r4, r2, #7                              ; offset &= ~7
    adds    r0, r0, r4                              ; add whole lane offset to state pointer
    ands    r2, r2, #7                              ; offset &= 7 (part not lane aligned)
    beq     KeccakP1600_AddBytes_CheckLanes ; if offset != 0
    movs    r4, r3                                  ; then, do remaining bytes in first lane
    rsb     r5, r2, #8                              ; max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_AddBytes_BytesAlign
    movs    r4, r5
KeccakP1600_AddBytes_BytesAlign
    sub     r8, r3, r4                              ; size left
    movs    r3, r4
    bl      __KeccakP1600_AddBytesInLane
    mov     r3, r8
KeccakP1600_AddBytes_CheckLanes
    lsrs    r2, r3, #3                              ; if length >= 8
    beq     KeccakP1600_AddBytes_Bytes
    mov     r8, r3
    bl      __KeccakP1600_AddLanes
    and     r3, r8, #7
KeccakP1600_AddBytes_Bytes
    cbz     r3, KeccakP1600_AddBytes_Exit
    movs    r2, #0
    bl      __KeccakP1600_AddBytesInLane
KeccakP1600_AddBytes_Exit
    pop     {r4 - r8, pc}
KeccakP1600_AddBytes_Exit1
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_AddLanes
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 laneCount
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
; Changed: r2-r7
;
    ALIGN
__KeccakP1600_AddLanes   PROC
__KeccakP1600_AddLanes_LoopAligned
    ldr     r4, [r1], #4
    ldr     r5, [r1], #4
    ldrd    r6, r7, [r0]
    toBitInterleaving   r4, r5, r6, r7, r3, 0
    strd    r6, r7, [r0], #8
    subs    r2, r2, #1
    bne     __KeccakP1600_AddLanes_LoopAligned
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_AddBytesInLane
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 offset in lane
;  r3 length
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
;  Changed: r2-r7
;
    ALIGN
__KeccakP1600_AddBytesInLane   PROC
    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    add     r2, r2, sp
__KeccakP1600_AddBytesInLane_Loop
    ldrb    r5, [r1], #1
    strb    r5, [r2], #1
    subs    r3, r3, #1
    bne     __KeccakP1600_AddBytesInLane_Loop
    pop     { r4 - r5 }
    ldrd    r6, r7, [r0]
    toBitInterleaving   r4, r5, r6, r7, r3, 0
    strd    r6, r7, [r0], #8
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    ALIGN
    EXPORT  KeccakP1600_OverwriteBytes
KeccakP1600_OverwriteBytes   PROC
    cbz     r3, KeccakP1600_OverwriteBytes_Exit1    ; if length != 0
    push    {r4 - r8, lr}                           ; then
    bic     r4, r2, #7                              ; offset &= ~7
    adds    r0, r0, r4                              ; add whole lane offset to state pointer
    ands    r2, r2, #7                              ; offset &= 7 (part not lane aligned)
    beq     KeccakP1600_OverwriteBytes_CheckLanes   ; if offset != 0
    movs    r4, r3                                  ; then, do remaining bytes in first lane
    rsb     r5, r2, #8                              ; max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_OverwriteBytes_BytesAlign
    movs    r4, r5
KeccakP1600_OverwriteBytes_BytesAlign
    sub     r8, r3, r4                              ; size left
    movs    r3, r4
    bl      __KeccakP1600_OverwriteBytesInLane
    mov     r3, r8
KeccakP1600_OverwriteBytes_CheckLanes
    lsrs    r2, r3, #3                              ; if length >= 8
    beq     KeccakP1600_OverwriteBytes_Bytes
    mov     r8, r3
    bl      __KeccakP1600_OverwriteLanes
    and     r3, r8, #7
KeccakP1600_OverwriteBytes_Bytes
    cbz     r3, KeccakP1600_OverwriteBytes_Exit
    movs    r2, #0
    bl      __KeccakP1600_OverwriteBytesInLane
KeccakP1600_OverwriteBytes_Exit
    pop     {r4 - r8, pc}
KeccakP1600_OverwriteBytes_Exit1
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_OverwriteLanes
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 laneCount
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
; Changed: r2-r7
;
    ALIGN
__KeccakP1600_OverwriteLanes   PROC
__KeccakP1600_OverwriteLanes_LoopAligned
    ldr     r4, [r1], #4
    ldr     r5, [r1], #4
    ldrd    r6, r7, [r0]
    toBitInterleaving   r4, r5, r6, r7, r3, 1
    strd    r6, r7, [r0], #8
    subs    r2, r2, #1
    bne     __KeccakP1600_OverwriteLanes_LoopAligned
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_OverwriteBytesInLane
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 offset in lane
;  r3 length
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
;  Changed: r2-r7
;
    ALIGN
__KeccakP1600_OverwriteBytesInLane   PROC
    movs    r4, #0
    movs    r5, #0
    push    { r4 - r5 }
    lsl     r7, r2, #2
    add     r2, r2, sp
    movs    r6, #0x0F                       ;r6 mask to wipe nibbles(bit interleaved bytes) in state
    lsls    r6, r6, r7
    movs    r7, r6
KeccakP1600_OverwriteBytesInLane_Loop
    orrs    r6, r6, r7
    lsls    r7, r7, #4
    ldrb    r5, [r1], #1
    subs    r3, r3, #1
    strb    r5, [r2], #1
    bne     KeccakP1600_OverwriteBytesInLane_Loop
    pop     { r4 - r5 }
    toBitInterleaving   r4, r5, r2, r3, r7, 1
    ldrd    r4, r5, [r0]
    bics    r4, r4, r6
    bics    r5, r5, r6
    orrs    r2, r2, r4
    orrs    r3, r3, r5
    strd    r2, r3, [r0], #8
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount)
;
    ALIGN
    EXPORT  KeccakP1600_OverwriteWithZeroes
KeccakP1600_OverwriteWithZeroes PROC
    push    {r4 - r5}
    lsrs    r2, r1, #3
    beq     KeccakP1600_OverwriteWithZeroes_Bytes
    movs    r4, #0
    movs    r5, #0
KeccakP1600_OverwriteWithZeroes_LoopLanes
    strd    r4, r5, [r0], #8
    subs    r2, r2, #1
    bne     KeccakP1600_OverwriteWithZeroes_LoopLanes
KeccakP1600_OverwriteWithZeroes_Bytes
    ands    r1, #7
    beq     KeccakP1600_OverwriteWithZeroes_Exit
    movs    r3, #0x0F                       ;r2 already zero, r3 = mask to wipe nibbles(bit interleaved bytes) in state
KeccakP1600_OverwriteWithZeroes_LoopBytes
    orrs    r2, r2, r3
    lsls    r3, r3, #4
    subs    r1, r1, #1
    bne     KeccakP1600_OverwriteWithZeroes_LoopBytes
    ldrd    r4, r5, [r0]
    bics    r4, r4, r2
    bics    r5, r5, r2
    strd    r4, r5, [r0], #8
KeccakP1600_OverwriteWithZeroes_Exit
    pop     {r4 - r5}
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600_ExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    ALIGN
    EXPORT  KeccakP1600_ExtractBytes
KeccakP1600_ExtractBytes   PROC
    cbz     r3, KeccakP1600_ExtractBytes_Exit1  ; if length != 0
    push    {r4 - r8, lr}                           ; then
    bic     r4, r2, #7                              ; offset &= ~7
    adds    r0, r0, r4                              ; add whole lane offset to state pointer
    ands    r2, r2, #7                              ; offset &= 7 (part not lane aligned)
    beq     KeccakP1600_ExtractBytes_CheckLanes ; if offset != 0
    movs    r4, r3                                  ; then, do remaining bytes in first lane
    rsb     r5, r2, #8                              ; max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_ExtractBytes_BytesAlign
    movs    r4, r5
KeccakP1600_ExtractBytes_BytesAlign
    sub     r8, r3, r4                              ; size left
    movs    r3, r4
    bl      __KeccakP1600_ExtractBytesInLane
    mov     r3, r8
KeccakP1600_ExtractBytes_CheckLanes
    lsrs    r2, r3, #3                              ; if length >= 8
    beq     KeccakP1600_ExtractBytes_Bytes
    mov     r8, r3
    bl      __KeccakP1600_ExtractLanes
    and     r3, r8, #7
KeccakP1600_ExtractBytes_Bytes
    cbz     r3, KeccakP1600_ExtractBytes_Exit
    movs    r2, #0
    bl      __KeccakP1600_ExtractBytesInLane
KeccakP1600_ExtractBytes_Exit
    pop     {r4 - r8, pc}
KeccakP1600_ExtractBytes_Exit1
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_ExtractLanes
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 laneCount
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
; Changed: r2-r5
;
    ALIGN
__KeccakP1600_ExtractLanes   PROC
__KeccakP1600_ExtractLanes_LoopAligned
    ldrd    r4, r5, [r0], #8
    fromBitInterleaving r4, r5, r3
    str     r4, [r1], #4
    subs    r2, r2, #1
    str     r5, [r1], #4
    bne     __KeccakP1600_ExtractLanes_LoopAligned
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_ExtractBytesInLane
;
; Input:
;  r0 state pointer
;  r1 data pointer
;  r2 offset in lane
;  r3 length
;
; Output:
;  r0 state pointer next lane
;  r1 data pointer next byte to input
;
;  Changed: r2-r6
;
    ALIGN
__KeccakP1600_ExtractBytesInLane   PROC
    ldrd    r4, r5, [r0], #8
    fromBitInterleaving r4, r5, r6
    push    {r4, r5}
    add     r2, sp, r2
__KeccakP1600_ExtractBytesInLane_Loop
    ldrb    r4, [r2], #1
    subs    r3, r3, #1
    strb    r4, [r1], #1
    bne     __KeccakP1600_ExtractBytesInLane_Loop
    add     sp, #8
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
;  void KeccakP1600_ExtractAndAddBytes(void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
;
    ALIGN
    EXPORT  KeccakP1600_ExtractAndAddBytes
KeccakP1600_ExtractAndAddBytes   PROC
    push    {r4 - r10, lr}
    mov     r9, r2
    mov     r2, r3
    ldr     r3, [sp, #8*4]
    cbz     r3, KeccakP1600_ExtractAndAddBytes_Exit ; if length != 0
    bic     r4, r2, #7                              ; then, offset &= ~7
    adds    r0, r0, r4                              ; add whole lane offset to state pointer
    ands    r2, r2, #7                              ; offset &= 7 (part not lane aligned)
    beq     KeccakP1600_ExtractAndAddBytes_CheckLanes   ; if offset != 0
    movs    r4, r3                                  ; then, do remaining bytes in first lane
    rsb     r5, r2, #8                              ; max size in lane = 8 - offset
    cmp     r4, r5
    ble     KeccakP1600_ExtractAndAddBytes_BytesAlign
    movs    r4, r5
KeccakP1600_ExtractAndAddBytes_BytesAlign
    sub     r8, r3, r4                              ; size left
    movs    r3, r4
    bl      __KeccakP1600_ExtractAndAddBytesInLane
    mov     r3, r8
KeccakP1600_ExtractAndAddBytes_CheckLanes
    lsrs    r2, r3, #3                              ; if length >= 8
    beq     KeccakP1600_ExtractAndAddBytes_Bytes
    mov     r8, r3
    bl      __KeccakP1600_ExtractAndAddLanes
    and     r3, r8, #7
KeccakP1600_ExtractAndAddBytes_Bytes
    cbz     r3, KeccakP1600_ExtractAndAddBytes_Exit
    movs    r2, #0
    bl      __KeccakP1600_ExtractAndAddBytesInLane
KeccakP1600_ExtractAndAddBytes_Exit
    pop     {r4 - r10, pc}
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_ExtractAndAddLanes
;
; Input:
;  r0 state pointer
;  r1 input pointer
;  r9 output pointer
;  r2 laneCount
;
; Output:
;  r0 state pointer next lane
;  r1 input pointer next 32-bit word
;  r9 output pointer next 32-bit word
;
; Changed: r2-r5
;
    ALIGN
__KeccakP1600_ExtractAndAddLanes   PROC
__KeccakP1600_ExtractAndAddLanes_LoopAligned
    ldrd    r4, r5, [r0], #8
    fromBitInterleaving r4, r5, r3
    ldr     r3, [r1], #4
    eors    r4, r4, r3
    str     r4, [r9], #4
    ldr     r3, [r1], #4
    eors    r5, r5, r3
    subs    r2, r2, #1
    str     r5, [r9], #4
    bne     __KeccakP1600_ExtractAndAddLanes_LoopAligned
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; __KeccakP1600_ExtractAndAddBytesInLane
;
; Input:
;  r0 state pointer
;  r1 input pointer
;  r9 output pointer
;  r2 offset in lane
;  r3 length
;
; Output:
;  r0 state pointer next lane
;  r1 input pointer next byte
;  r9 output pointer next byte
;
;  Changed: r2-r6
;
    ALIGN
__KeccakP1600_ExtractAndAddBytesInLane   PROC
    ldrd    r4, r5, [r0], #8
    fromBitInterleaving r4, r5, r6
    push    {r4, r5}
    add     r2, sp, r2
__KeccakP1600_ExtractAndAddBytesInLane_Loop
    ldrb    r4, [r2], #1
    ldrb    r5, [r1], #1
    eors    r4, r4, r5
    subs    r3, r3, #1
    strb    r4, [r9], #1
    bne     __KeccakP1600_ExtractAndAddBytesInLane_Loop
    add     sp, #8
    bx      lr
    ENDP

    MACRO
    SwapPI13 $in0,$in1,$in2,$in3,$eo0,$eo1,$eo2,$eo3
    ldr     r3, [r0, #$in0+0]
    ldr     r4, [r0, #$in0+4]
    ldr     r2, [r0, #$in1+0]
    ldr     r1, [r0, #$in1+4]
    str     r2, [r0, #$in0+$eo0*4]
    str     r1, [r0, #$in0+($eo0^1)*4]
    ldr     r2, [r0, #$in2+0]
    ldr     r1, [r0, #$in2+4]
    str     r2, [r0, #$in1+$eo1*4]
    str     r1, [r0, #$in1+($eo1^1)*4]
    ldr     r2, [r0, #$in3+0]
    ldr     r1, [r0, #$in3+4]
    str     r2, [r0, #$in2+$eo2*4]
    str     r1, [r0, #$in2+($eo2^1)*4]
    str     r3, [r0, #$in3+$eo3*4]
    str     r4, [r0, #$in3+($eo3^1)*4]
    MEND

    MACRO
    SwapPI2 $in0,$in1,$in2,$in3
    ldr     r3, [r0, #$in0+0]
    ldr     r4, [r0, #$in0+4]
    ldr     r2, [r0, #$in1+0]
    ldr     r1, [r0, #$in1+4]
    str     r2, [r0, #$in0+4]
    str     r1, [r0, #$in0+0]
    str     r3, [r0, #$in1+4]
    str     r4, [r0, #$in1+0]
    ldr     r3, [r0, #$in2+0]
    ldr     r4, [r0, #$in2+4]
    ldr     r2, [r0, #$in3+0]
    ldr     r1, [r0, #$in3+4]
    str     r2, [r0, #$in2+4]
    str     r1, [r0, #$in2+0]
    str     r3, [r0, #$in3+4]
    str     r4, [r0, #$in3+0]
    MEND

    MACRO
    SwapEO  $even,$odd
    ldr     r3, [r0, #$even]
    ldr     r4, [r0, #$odd]
    str     r3, [r0, #$odd]
    str     r4, [r0, #$even]
    MEND

; ----------------------------------------------------------------------------
;
;  void KeccakP1600_Permute_Nrounds(void *state, unsigned int nrounds)
;
    ALIGN
    EXPORT  KeccakP1600_Permute_Nrounds
KeccakP1600_Permute_Nrounds   PROC
    lsls    r3, r1, #30
    bne     KeccakP1600_Permute_NroundsNotMultiple4
    lsls    r2, r1, #3
    adr     r1, KeccakP1600_Permute_RoundConstants0Mod4
    subs    r1, r1, r2
    b       KeccakP1600_Permute
KeccakP1600_Permute_NroundsNotMultiple4     ; nrounds not multiple of 4
    push    { r4 - r12, lr }
    sub     sp, #mSize
    lsrs    r2, r1, #2
    lsls    r2, r2, #3+2
    adr     r1, KeccakP1600_Permute_RoundConstants0
    subs    r1, r1, r2
    str     r1, [sp, #mRC]
    lsls    r3, r3, #1
    bcs     KeccakP1600_Permute_Nrounds23Mod4
KeccakP1600_Permute_Nrounds1Mod4
    SwapPI13    Aga0, Aka0, Asa0, Ama0, 1, 0, 1, 0
    SwapPI13    Abe0, Age0, Ame0, Ake0, 0, 1, 0, 1
    SwapPI13    Abi0, Aki0, Agi0, Asi0, 1, 0, 1, 0
    SwapEO      Ami0, Ami1
    SwapPI13    Abo0, Amo0, Aso0, Ago0, 1, 0, 1, 0
    SwapEO      Ako0, Ako1
    SwapPI13    Abu0, Asu0, Aku0, Amu0, 0, 1, 0, 1
    b.w         KeccakP1600_Permute_Round1Mod4
KeccakP1600_Permute_Nrounds23Mod4
    bpl         KeccakP1600_Permute_Nrounds2Mod4
KeccakP1600_Permute_Nrounds3Mod4
    SwapPI13    Aga0, Ama0, Asa0, Aka0, 0, 1, 0, 1
    SwapPI13    Abe0, Ake0, Ame0, Age0, 1, 0, 1, 0
    SwapPI13    Abi0, Asi0, Agi0, Aki0, 0, 1, 0, 1
    SwapEO      Ami0, Ami1
    SwapPI13    Abo0, Ago0, Aso0, Amo0, 0, 1, 0, 1
    SwapEO      Ako0, Ako1
    SwapPI13    Abu0, Amu0, Aku0, Asu0, 1, 0, 1, 0
    b.w         KeccakP1600_Permute_Round3Mod4
KeccakP1600_Permute_Nrounds2Mod4
    SwapPI2     Aga0, Asa0, Aka0, Ama0
    SwapPI2     Abe0, Ame0, Age0, Ake0
    SwapPI2     Abi0, Agi0, Aki0, Asi0
    SwapPI2     Abo0, Aso0, Ago0, Amo0
    SwapPI2     Abu0, Aku0, Amu0, Asu0
    b.w         KeccakP1600_Permute_Round2Mod4
    ENDP

; ----------------------------------------------------------------------------
; 
;  void KeccakP1600_Permute_12rounds( void *state )
; 
    ALIGN
    EXPORT  KeccakP1600_Permute_12rounds
KeccakP1600_Permute_12rounds   PROC
    adr     r1, KeccakP1600_Permute_RoundConstants12
    b       KeccakP1600_Permute
    ENDP

; ----------------------------------------------------------------------------
; 
;  void KeccakP1600_Permute_24rounds( void *state )
; 
    ALIGN
    EXPORT  KeccakP1600_Permute_24rounds
KeccakP1600_Permute_24rounds   PROC
    adr     r1, KeccakP1600_Permute_RoundConstants24
    b       KeccakP1600_Permute
    ENDP

    ALIGN
KeccakP1600_Permute_RoundConstants24
    ;       0           1
    dcd     0x00000001, 0x00000000
    dcd     0x00000000, 0x00000089
    dcd     0x00000000, 0x8000008b
    dcd     0x00000000, 0x80008080
    dcd     0x00000001, 0x0000008b
    dcd     0x00000001, 0x00008000
    dcd     0x00000001, 0x80008088
    dcd     0x00000001, 0x80000082
    dcd     0x00000000, 0x0000000b
    dcd     0x00000000, 0x0000000a
    dcd     0x00000001, 0x00008082
    dcd     0x00000000, 0x00008003
KeccakP1600_Permute_RoundConstants12
    dcd     0x00000001, 0x0000808b
    dcd     0x00000001, 0x8000000b
    dcd     0x00000001, 0x8000008a
    dcd     0x00000001, 0x80000081
    dcd     0x00000000, 0x80000081
    dcd     0x00000000, 0x80000008
    dcd     0x00000000, 0x00000083
    dcd     0x00000000, 0x80008003
KeccakP1600_Permute_RoundConstants0
    dcd     0x00000001, 0x80008088
    dcd     0x00000000, 0x80000088
    dcd     0x00000001, 0x00008000
    dcd     0x00000000, 0x80008082
KeccakP1600_Permute_RoundConstants0Mod4
    dcd     0x000000FF  ;terminator

;----------------------------------------------------------------------------
;
; void KeccakP1600_Permute( void *state, void * rc )
;
    ALIGN
KeccakP1600_Permute   PROC
    push    { r4 - r12, lr }
    sub     sp, #mSize
    str     r1, [sp, #mRC]
KeccakP1600_Permute_RoundLoop
    KeccakRound0
KeccakP1600_Permute_Round3Mod4
    KeccakRound1
KeccakP1600_Permute_Round2Mod4
    KeccakRound2
KeccakP1600_Permute_Round1Mod4
    KeccakRound3
    bne     KeccakP1600_Permute_RoundLoop
    add     sp, #mSize
    pop     { r4 - r12, pc }
    ENDP

    END
