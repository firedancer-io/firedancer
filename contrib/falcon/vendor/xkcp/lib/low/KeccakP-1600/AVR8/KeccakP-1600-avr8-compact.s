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

; INFO: Tested on ATmega1280 simulator

; Registers used in all routines
#define zero    1
#define rpState 24
#define rX      26
#define rY      28
#define rZ      30
#define sp      0x3D

;----------------------------------------------------------------------------
;
; void KeccakP1600_StaticInitialize( void )
;
.global KeccakP1600_StaticInitialize

;----------------------------------------------------------------------------
;
; void KeccakP1600_Initialize(KeccakP1600_state *state)
;
; argument state   is passed in r24:r25
;
.global KeccakP1600_Initialize
KeccakP1600_Initialize:
    movw    rZ, r24
    ldi     r23, 5*5*8
KeccakP1600_Initialize_Loop:
    st      z+, zero
    dec     r23
    brne    KeccakP1600_Initialize_Loop
KeccakP1600_StaticInitialize:
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_AddByte(KeccakP1600_state *state, unsigned char data, unsigned int offset)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23, only LSB (r22) is used
; argument offset    is passed in r20:r21, only LSB (r20) is used
;
.global KeccakP1600_AddByte
KeccakP1600_AddByte:
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    ld      r0, Z
    eor     r0, r22
    st      Z, r0
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_AddBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global KeccakP1600_AddBytes
KeccakP1600_AddBytes:
    tst     r18
    breq    KeccakP1600_AddBytes_End
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
KeccakP1600_AddBytes_Loop:
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    dec     r18
    brne    KeccakP1600_AddBytes_Loop
KeccakP1600_AddBytes_End:
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_OverwriteBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global KeccakP1600_OverwriteBytes
KeccakP1600_OverwriteBytes:
    tst     r18
    breq    KeccakP1600_OverwriteBytes_End
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
KeccakP1600_OverwriteBytes_Loop:
    ld      r0, X+
    st      Z+, r0
    dec     r18
    brne    KeccakP1600_OverwriteBytes_Loop
KeccakP1600_OverwriteBytes_End:
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_OverwriteWithZeroes(KeccakP1600_state *state, unsigned int byteCount)
;
; argument state        is passed in r24:r25
; argument byteCount    is passed in r22:r23, only LSB (r22) is used
;
.global KeccakP1600_OverwriteWithZeroes
KeccakP1600_OverwriteWithZeroes:
    tst     r22
    breq    KeccakP1600_OverwriteWithZeroes_End
    movw    rZ, r24         ; rZ = state
KeccakP1600_OverwriteWithZeroes_Loop:
    st      Z+, r1
    dec     r22
    brne    KeccakP1600_OverwriteWithZeroes_Loop
KeccakP1600_OverwriteWithZeroes_End:
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_ExtractBytes(KeccakP1600_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global KeccakP1600_ExtractBytes
KeccakP1600_ExtractBytes:
    tst     r18
    breq    KeccakP1600_ExtractBytes_End
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
KeccakP1600_ExtractBytes_Loop:
    ld      r0, Z+
    st      X+, r0
    dec     r18
    brne    KeccakP1600_ExtractBytes_Loop
KeccakP1600_ExtractBytes_End:
    ret

;----------------------------------------------------------------------------
;
; void KeccakP1600_ExtractAndAddBytes(KeccakP1600_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument input     is passed in r22:r23
; argument output    is passed in r20:r21
; argument offset    is passed in r18:r19, only LSB (r18) is used
; argument length    is passed in r16:r17, only LSB (r16) is used
;
.global KeccakP1600_ExtractAndAddBytes
KeccakP1600_ExtractAndAddBytes:
    tst     r16
    breq    KeccakP1600_ExtractAndAddBytes_End
    push    r16
    push    r28
    push    r29
    movw    rZ, r24
    add     rZ, r18
    adc     rZ+1, zero
    movw    rX, r22
    movw    rY, r20
KeccakP1600_ExtractAndAddBytes_Loop:
    ld      r19, X+
    ld      r0, Z+
    eor     r0, r19
    st      Y+, r0
    dec     r16
    brne    KeccakP1600_ExtractAndAddBytes_Loop
    pop     r29
    pop     r28
    pop     r16
KeccakP1600_ExtractAndAddBytes_End:
    ret


#define ROT_BIT(a)      ((a) & 7)
#define ROT_BYTE(a)     (((a)/8 + !!(((a)%8) > 4)) & 7)

KeccakP1600_RhoPiConstants:
    .BYTE   ROT_BIT( 1), ROT_BYTE( 3), 10 * 8
    .BYTE   ROT_BIT( 3), ROT_BYTE( 6),  7 * 8
    .BYTE   ROT_BIT( 6), ROT_BYTE(10), 11 * 8
    .BYTE   ROT_BIT(10), ROT_BYTE(15), 17 * 8
    .BYTE   ROT_BIT(15), ROT_BYTE(21), 18 * 8
    .BYTE   ROT_BIT(21), ROT_BYTE(28),  3 * 8
    .BYTE   ROT_BIT(28), ROT_BYTE(36),  5 * 8
    .BYTE   ROT_BIT(36), ROT_BYTE(45), 16 * 8
    .BYTE   ROT_BIT(45), ROT_BYTE(55),  8 * 8
    .BYTE   ROT_BIT(55), ROT_BYTE( 2), 21 * 8
    .BYTE   ROT_BIT( 2), ROT_BYTE(14), 24 * 8
    .BYTE   ROT_BIT(14), ROT_BYTE(27),  4 * 8
    .BYTE   ROT_BIT(27), ROT_BYTE(41), 15 * 8
    .BYTE   ROT_BIT(41), ROT_BYTE(56), 23 * 8
    .BYTE   ROT_BIT(56), ROT_BYTE( 8), 19 * 8
    .BYTE   ROT_BIT( 8), ROT_BYTE(25), 13 * 8
    .BYTE   ROT_BIT(25), ROT_BYTE(43), 12 * 8
    .BYTE   ROT_BIT(43), ROT_BYTE(62),  2 * 8
    .BYTE   ROT_BIT(62), ROT_BYTE(18), 20 * 8
    .BYTE   ROT_BIT(18), ROT_BYTE(39), 14 * 8
    .BYTE   ROT_BIT(39), ROT_BYTE(61), 22 * 8
    .BYTE   ROT_BIT(61), ROT_BYTE(20),  9 * 8
    .BYTE   ROT_BIT(20), ROT_BYTE(44),  6 * 8
    .BYTE   ROT_BIT(44), ROT_BYTE( 1),  1 * 8

KeccakP1600_RoundConstants_24:
    .BYTE   0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x82, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x8a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x00, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x8b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x81, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x09, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x09, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x0a, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
KeccakP1600_RoundConstants_12:
    .BYTE   0x8b, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x8b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x0a, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x81, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    .BYTE   0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00
    .BYTE   0x08, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80
KeccakP1600_RoundConstants_0:
    .BYTE   0xFF, 0        ; terminator

    .text

#define pRound        22        // 2 regs (22-23)

;----------------------------------------------------------------------------
;
; void KeccakP1600_Permute_Nrounds( KeccakP1600_state *state, unsigned int nrounds )
;
; argument state     is passed in r24:r25
; argument nrounds   is passed in r22:r23 (only LSB (r22) is used)
;
.global KeccakP1600_Permute_Nrounds
KeccakP1600_Permute_Nrounds:
	mov		r26, r22
    ldi     pRound,   lo8(KeccakP1600_RoundConstants_0)
    ldi     pRound+1, hi8(KeccakP1600_RoundConstants_0)
	lsl		r26
	lsl		r26
	lsl		r26
    sub     pRound, r26
    sbc     pRound+1, zero
    rjmp    KeccakP1600_Permute

;----------------------------------------------------------------------------
;
; void KeccakP1600_Permute_24rounds( KeccakP1600_state *state )
;
.global KeccakP1600_Permute_24rounds
KeccakP1600_Permute_24rounds:
    ldi     pRound,   lo8(KeccakP1600_RoundConstants_24)
    ldi     pRound+1, hi8(KeccakP1600_RoundConstants_24)
    rjmp    KeccakP1600_Permute

;----------------------------------------------------------------------------
;
; void KeccakP1600_Permute_12rounds( KeccakP1600_state *state )
;
.global KeccakP1600_Permute_12rounds
KeccakP1600_Permute_12rounds:
    ldi     pRound,   lo8(KeccakP1600_RoundConstants_12)
    ldi     pRound+1, hi8(KeccakP1600_RoundConstants_12)
KeccakP1600_Permute:
    push    r2
    push    r3
    push    r4
    push    r5
    push    r6
    push    r7
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    push    r16
    push    r17
    push    r28
    push    r29

    ; Allocate C variables (5*8)
    in      rZ,   sp
    in      rZ+1, sp+1
    sbiw    rZ, 40
    in      r0, 0x3F
    cli
    out     sp+1, rZ+1
    out     sp, rZ                ; Z points to 5 C lanes
    out     0x3F, r0

    ; Variables used in multiple operations
    #define rTemp        2      // 8 regs (2-9)
    #define rTempBis    10      // 8 regs (10-17)
    #define rTempTer    18      // 2 regs (18-19)
    #define pRound      22      // 2 regs (22-23)

    ; Initial Prepare Theta
    #define TCIPx               rTempTer

    movw    rY, rpState
    ldi     TCIPx, 5*8
KeccakInitialPrepTheta_Loop:
    ld      r0, Y
    adiw    rY, 40
    ld      rTemp, Y
    adiw    rY, 40
    eor     r0, rTemp
    ld      rTemp, Y
    adiw    rY, 40
    eor     r0, rTemp
    ld      rTemp, Y
    eor     r0, rTemp
    ldd     rTemp, Y+40
    eor     r0, rTemp
    st      Z+, r0
    subi    rY, 119
    sbc     rY+1, zero
    dec     TCIPx
    brne    KeccakInitialPrepTheta_Loop
    #undef  TCIPx

Keccak_RoundLoop:

    ; Theta
    #define TCplus          rX
    #define TCminus         rZ
    #define TCcoordX        rTempTer
    #define TCcoordY        rTempTer+1

    in      TCminus, sp
    in      TCminus+1, sp+1
    movw    TCplus, TCminus
    adiw    TCminus, 4*8
    adiw    TCplus, 1*8
    movw    rY, rpState

    ldi     TCcoordX, 0x16
KeccakTheta_Loop1:
    ld      rTemp+0, X+
    ld      rTemp+1, X+
    ld      rTemp+2, X+
    ld      rTemp+3, X+
    ld      rTemp+4, X+
    ld      rTemp+5, X+
    ld      rTemp+6, X+
    ld      rTemp+7, X+

    lsl     rTemp+0
    rol     rTemp+1
    rol     rTemp+2
    rol     rTemp+3
    rol     rTemp+4
    rol     rTemp+5
    rol     rTemp+6
    rol     rTemp+7
    adc     rTemp+0, zero

    ld      r0, Z+
    eor     rTemp+0, r0
    ld      r0, Z+
    eor     rTemp+1, r0
    ld      r0, Z+
    eor     rTemp+2, r0
    ld      r0, Z+
    eor     rTemp+3, r0
    ld      r0, Z+
    eor     rTemp+4, r0
    ld      r0, Z+
    eor     rTemp+5, r0
    ld      r0, Z+
    eor     rTemp+6, r0
    ld      r0, Z+
    eor     rTemp+7, r0

    ldi     TCcoordY, 5
KeccakTheta_Loop2:
    ld      r0, Y
    eor     r0, rTemp+0
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+1
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+2
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+3
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+4
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+5
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+6
    st      Y+, r0
    ld      r0, Y
    eor     r0, rTemp+7
    st      Y+, r0
    adiw    rY, 32

    dec     TCcoordY
    brne    KeccakTheta_Loop2

    subi    rY, 200-8
    sbc     rY+1, zero

    lsr     TCcoordX
    brcc    1f
    breq    KeccakTheta_End
    rjmp    KeccakTheta_Loop1
1:
    cpi     TCcoordX, 0x0B
    brne    2f
    sbiw    TCminus, 40
    rjmp    KeccakTheta_Loop1
2:
    sbiw    TCplus, 40
    rjmp    KeccakTheta_Loop1

KeccakTheta_End:
    #undef  TCplus
    #undef  TCminus
    #undef  TCcoordX
    #undef  TCcoordY


    ; Rho Pi
    #define RPindex         rTempTer+0
    #define RPTemp          rTempTer+1

    sbiw    rY, 32

    ld      rTemp+0, Y+
    ld      rTemp+1, Y+
    ld      rTemp+2, Y+
    ld      rTemp+3, Y+
    ld      rTemp+4, Y+
    ld      rTemp+5, Y+
    ld      rTemp+6, Y+
    ld      rTemp+7, Y+

    ldi     rZ,   lo8(KeccakP1600_RhoPiConstants)
    ldi     rZ+1, hi8(KeccakP1600_RhoPiConstants)

KeccakRhoPi_Loop:
    ; do bit rotation
    lpm     RPTemp, Z+      ; get number of bits to rotate
    cpi     RPTemp, 5
    brcs    rotate64_nbit_leftOrNot
    neg     RPTemp
    andi    RPTemp, 3

rotate64_nbit_right:
    bst     rTemp, 0
    ror     rTemp+7
    ror     rTemp+6
    ror     rTemp+5
    ror     rTemp+4
    ror     rTemp+3
    ror     rTemp+2
    ror     rTemp+1
    ror     rTemp
    bld     rTemp+7, 7
    dec     RPTemp
    brne    rotate64_nbit_right
    rjmp    KeccakRhoPi_RhoBitRotateDone

rotate64_nbit_leftOrNot:
    tst     RPTemp
    breq    KeccakRhoPi_RhoBitRotateDone
rotate64_nbit_left:
    lsl     rTemp
    rol     rTemp+1
    rol     rTemp+2
    rol     rTemp+3
    rol     rTemp+4
    rol     rTemp+5
    rol     rTemp+6
    rol     rTemp+7
    adc     rTemp, r1
    dec     RPTemp
    brne    rotate64_nbit_left

KeccakRhoPi_RhoBitRotateDone:
    lpm     r0, Z+          ; get number of bytes to rotate
    lpm     RPindex, Z+     ; get index in state
    movw    rY, rpState
    add     rY, RPindex
    adc     rY+1, zero

    ldi     rX, rTempBis
    add     rX, r0
    mov     rX+1, zero
    ldi     RPTemp, 8
KeccakRhoPi_PiByteRotLoop:
    ld      r0, Y+
    st      X+, r0
    cpi     rX, rTempBis+8
    brne    KeccakRhoPi_PiByteRotFirst
    ldi     rX, rTempBis
KeccakRhoPi_PiByteRotFirst:
    dec     RPTemp
    brne    KeccakRhoPi_PiByteRotLoop

    sbiw    rY, 8
    st      Y+, rTemp+0
    st      Y+, rTemp+1
    st      Y+, rTemp+2
    st      Y+, rTemp+3
    st      Y+, rTemp+4
    st      Y+, rTemp+5
    st      Y+, rTemp+6
    st      Y+, rTemp+7

    movw    rTemp+0, rTempBis+0
    movw    rTemp+2, rTempBis+2
    movw    rTemp+4, rTempBis+4
    movw    rTemp+6, rTempBis+6
KeccakRhoPi_RhoDone:
    subi    RPindex, 8
    brne    KeccakRhoPi_Loop

    #undef  RPindex
    #undef  RPTemp

    ; Chi Iota prepare Theta
    #define CIPTa0          rTemp
    #define CIPTa1          rTemp+1
    #define CIPTa2          rTemp+2
    #define CIPTa3          rTemp+3
    #define CIPTa4          rTemp+4
    #define CIPTc0          rTempBis
    #define CIPTc1          rTempBis+1
    #define CIPTc2          rTempBis+2
    #define CIPTc3          rTempBis+3
    #define CIPTc4          rTempBis+4
    #define CIPTz           rTempBis+6
    #define CIPTy           rTempBis+7

    movw    rY, rpState
    in      rX, sp          ; 5 C lanes
    in      rX+1, sp+1
    movw    rZ, pRound

    ldi     CIPTz, 8
KeccakChiIotaPrepareTheta_zLoop:
    mov     CIPTc0, zero
    mov     CIPTc1, zero
    movw    CIPTc2, CIPTc0
    mov     CIPTc4, zero

    ldi     CIPTy, 5
KeccakChiIotaPrepareTheta_yLoop:
    ld      CIPTa0, Y
    ldd     CIPTa1, Y+8
    ldd     CIPTa2, Y+16
    ldd     CIPTa3, Y+24
    ldd     CIPTa4, Y+32

    ;*p = t = a0 ^ ((~a1) & a2); c0 ^= t;
    mov     r0, CIPTa1
    com     r0
    and     r0, CIPTa2
    eor     r0, CIPTa0
    eor     CIPTc0, r0
    st      Y, r0

    ;*(p+8) = t = a1 ^ ((~a2) & a3); c1 ^= t;
    mov     r0, CIPTa2
    com     r0
    and     r0, CIPTa3
    eor     r0, CIPTa1
    eor     CIPTc1, r0
    std     Y+8, r0

    ;*(p+16) = a2 ^= ((~a3) & a4); c2 ^= a2;
    mov     r0, CIPTa3
    com     r0
    and     r0, CIPTa4
    eor     r0, CIPTa2
    eor     CIPTc2, r0
    std     Y+16, r0

    ;*(p+24) = a3 ^= ((~a4) & a0); c3 ^= a3;
    mov     r0, CIPTa4
    com     r0
    and     r0, CIPTa0
    eor     r0, CIPTa3
    eor     CIPTc3, r0
    std     Y+24, r0

    ;*(p+32) = a4 ^= ((~a0) & a1); c4 ^= a4;
    com     CIPTa0
    and     CIPTa0, CIPTa1
    eor     CIPTa0, CIPTa4
    eor     CIPTc4, CIPTa0
    std     Y+32, CIPTa0

    adiw    rY, 40
    dec     CIPTy
    brne    KeccakChiIotaPrepareTheta_yLoop

    subi    rY, 200
    sbc     rY+1, zero

    lpm     r0, Z+          ; Round Constant
    ld      CIPTa0, Y
    eor     CIPTa0, r0
    st      Y+, CIPTa0

    movw    pRound, rZ
    movw    rZ, rX
    eor     CIPTc0, r0
    st      Z+, CIPTc0
    std     Z+7, CIPTc1
    std     Z+15, CIPTc2
    std     Z+23, CIPTc3
    std     Z+31, CIPTc4
    movw    rX, rZ
    movw    rZ, pRound

    dec     CIPTz
    brne    KeccakChiIotaPrepareTheta_zLoop

    #undef  CIPTa0
    #undef  CIPTa1
    #undef  CIPTa2
    #undef  CIPTa3
    #undef  CIPTa4
    #undef  CIPTc0
    #undef  CIPTc1
    #undef  CIPTc2
    #undef  CIPTc3
    #undef  CIPTc4
    #undef  CIPTz
    #undef  CIPTy

    ;Check for terminator
    lpm     r0, Z
    inc     r0
    breq    Keccak_Done
    rjmp    Keccak_RoundLoop
Keccak_Done:

    #undef  rTemp
    #undef  rTempBis
    #undef  rTempTer
    #undef  pRound

    ; Free C(on stack) and registers
    in      rX, sp          ; free 5 C lanes
    in      rX+1, sp+1
    adiw    rX, 40
    in      r0, 0x3F
    cli
    out     sp+1, rX+1
    out     sp, rX
    out     0x3F, r0

    pop     r29
    pop     r28
    pop     r17
    pop     r16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     r7
    pop     r6
    pop     r5
    pop     r4
    pop     r3
    pop     r2
    ret

    #undef  rpState
    #undef  zero
    #undef  rX
    #undef  rY
    #undef  rZ
    #undef  sp
