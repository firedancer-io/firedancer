;
; The eXtended Keccak Code Package (XKCP)
; https://github.com/XKCP/XKCP
;
; The Xoodoo permutation, designed by Joan Daemen, Seth Hoffert, Gilles Van Assche and Ronny Van Keer.
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

; WARNING: These functions work only on little endian CPU with ARMv6m architecture (Cortex-M0, ...).

        PRESERVE8
        THUMB
        AREA    |.text|, CODE, READONLY

; ----------------------------------------------------------------------------
;
;  void Xoodoo_Initialize(Xoodoo_plain32_state *state)
;
    align   4
    EXPORT  Xoodoo_Initialize
Xoodoo_Initialize   PROC
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    stmia   r0!, { r1 - r3 }
    stmia   r0!, { r1 - r3 }
    stmia   r0!, { r1 - r3 }
    stmia   r0!, { r1 - r3 }
    bx      lr
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_AddBytes(Xoodoo_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_AddBytes
Xoodoo_AddBytes   PROC
    push    {r4,lr}
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_AddBytes_Bytes
    movs    r2, r0                                  ; and data pointer and offset both 32-bit aligned
    orrs    r2, r2, r1
    lsls    r2, #30
    bne     Xoodoo_AddBytes_Bytes
Xoodoo_AddBytes_LanesLoop                           ; then, perform on words
    ldr     r2, [r0]
    ldmia   r1!, {r4}
    eors    r2, r2, r4
    stmia   r0!, {r2}
    subs    r3, r3, #4
    bcs     Xoodoo_AddBytes_LanesLoop
Xoodoo_AddBytes_Bytes
    adds    r3, r3, #4
    beq     Xoodoo_AddBytes_Exit
    subs    r3, r3, #1
Xoodoo_AddBytes_BytesLoop
    ldrb    r2, [r0, r3]
    ldrb    r4, [r1, r3]
    eors    r2, r2, r4
    strb    r2, [r0, r3]
    subs    r3, r3, #1
    bcs     Xoodoo_AddBytes_BytesLoop
Xoodoo_AddBytes_Exit
    pop     {r4,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_OverwriteBytes(Xoodoo_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_OverwriteBytes
Xoodoo_OverwriteBytes   PROC
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_OverwriteBytes_Bytes
    movs    r2, r0                                  ; and data pointer and offset both 32-bit aligned
    orrs    r2, r2, r1
    lsls    r2, #30
    bne     Xoodoo_OverwriteBytes_Bytes
Xoodoo_OverwriteBytes_LanesLoop                 ; then, perform on words
    ldmia   r1!, {r2}
    stmia   r0!, {r2}
    subs    r3, r3, #4
    bcs     Xoodoo_OverwriteBytes_LanesLoop
Xoodoo_OverwriteBytes_Bytes
    adds    r3, r3, #4
    beq     Xoodoo_OverwriteBytes_Exit
    subs    r3, r3, #1
Xoodoo_OverwriteBytes_BytesLoop
    ldrb    r2, [r1, r3]
    strb    r2, [r0, r3]
    subs    r3, r3, #1
    bcs     Xoodoo_OverwriteBytes_BytesLoop
Xoodoo_OverwriteBytes_Exit
    bx      lr
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_OverwriteWithZeroes(Xoodoo_plain32_state *state, unsigned int byteCount)
;
    EXPORT  Xoodoo_OverwriteWithZeroes
Xoodoo_OverwriteWithZeroes  PROC
    movs    r3, #0
    lsrs    r2, r1, #2
    beq     Xoodoo_OverwriteWithZeroes_Bytes
Xoodoo_OverwriteWithZeroes_LoopLanes
    stm     r0!, { r3 }
    subs    r2, r2, #1
    bne     Xoodoo_OverwriteWithZeroes_LoopLanes
Xoodoo_OverwriteWithZeroes_Bytes
    lsls    r1, r1, #32-2
    beq     Xoodoo_OverwriteWithZeroes_Exit
    lsrs    r1, r1, #32-2
Xoodoo_OverwriteWithZeroes_LoopBytes
    subs    r1, r1, #1
    strb    r3, [r0, r1]
    bne     Xoodoo_OverwriteWithZeroes_LoopBytes
Xoodoo_OverwriteWithZeroes_Exit
    bx      lr
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_ExtractBytes(Xoodoo_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_ExtractBytes
Xoodoo_ExtractBytes   PROC
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_ExtractBytes_Bytes
    movs    r2, r0                                  ; and data pointer and offset both 32-bit aligned
    orrs    r2, r2, r1
    lsls    r2, #30
    bne     Xoodoo_ExtractBytes_Bytes
Xoodoo_ExtractBytes_LanesLoop                       ; then, perform on words
    ldmia   r0!, {r2}
    stmia   r1!, {r2}
    subs    r3, r3, #4
    bcs     Xoodoo_ExtractBytes_LanesLoop
Xoodoo_ExtractBytes_Bytes
    adds    r3, r3, #4
    beq     Xoodoo_ExtractBytes_Exit
    subs    r3, r3, #1
Xoodoo_ExtractBytes_BytesLoop
    ldrb    r2, [r0, r3]
    strb    r2, [r1, r3]
    subs    r3, r3, #1
    bcs     Xoodoo_ExtractBytes_BytesLoop
Xoodoo_ExtractBytes_Exit
    bx      lr
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_ExtractAndAddBytes(Xoodoo_plain32_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_ExtractAndAddBytes
Xoodoo_ExtractAndAddBytes   PROC
    push    {r4,r5}
    adds    r0, r0, r3                              ; state += offset (offset register no longer needed, reuse for length)
    ldr     r3, [sp, #8]                            ; get length argument from stack
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_ExtractAndAddBytes_Bytes
    movs    r5, r0                                  ; and input/output/state pointer all 32-bit aligned
    orrs    r5, r5, r1
    orrs    r5, r5, r2
    lsls    r5, #30
    bne     Xoodoo_ExtractAndAddBytes_Bytes
Xoodoo_ExtractAndAddBytes_LanesLoop                 ; then, perform on words
    ldmia   r0!, {r5}
    ldmia   r1!, {r4}
    eors    r5, r5, r4
    stmia   r2!, {r5}
    subs    r3, r3, #4
    bcs     Xoodoo_ExtractAndAddBytes_LanesLoop
Xoodoo_ExtractAndAddBytes_Bytes
    adds    r3, r3, #4
    beq     Xoodoo_ExtractAndAddBytes_Exit
    subs    r3, r3, #1
Xoodoo_ExtractAndAddBytes_BytesLoop
    ldrb    r5, [r0, r3]
    ldrb    r4, [r1, r3]
    eors    r5, r5, r4
    strb    r5, [r2, r3]
    subs    r3, r3, #1
    bcs     Xoodoo_ExtractAndAddBytes_BytesLoop
Xoodoo_ExtractAndAddBytes_Exit
    pop     {r4,r5}
    bx      lr
    align   4
    ENDP

; ----------------------------------------------------------------------------

; offsets in RAM state
_oA00       equ  0*4
_oA01       equ  1*4
_oA02       equ  2*4
_oA03       equ  3*4
_oA10       equ  4*4
_oA11       equ  5*4
_oA12       equ  6*4
_oA13       equ  7*4
_oA20       equ  8*4
_oA21       equ  9*4
_oA22       equ 10*4
_oA23       equ 11*4

; possible locations of state lanes
locRegL     equ 1
locRegH     equ 2
locMem      equ 3

; ----------------------------------------------------------------------------

_r0    equ 5
_r1    equ 14
_r2    equ 1

_w1    equ 11

_e0    equ 2
_e1    equ 8

; ----------------------------------------------------------------------------

    MACRO
    mXor3   $ro, $a0, $a1, $a2, $loc, $tt
    mov     $ro, $a1
    eors    $ro, $ro, $a2
    if $loc == locRegL
    eors    $ro, $ro, $a0
    else
    if $loc == locRegH
    mov     $tt, $a0
    else
    ldr     $tt, [sp, #$a0]
    endif
    eors    $ro, $ro, $tt
    endif
    MEND

    MACRO
    mXor    $ro, $ri, $tt, $loc
    if $loc == locRegL
    eors    $ro, $ro, $ri
    else
    if $loc == locRegH
    mov     $tt, $ro
    eors    $tt, $tt, $ri
    mov     $ro, $tt
    else
    ldr     $tt, [sp, #$ro]
    eors    $tt, $tt, $ri
    str     $tt, [sp, #$ro]
    endif
    endif
    MEND

    MACRO
    mChi3   $a0,$a1,$a2,$r0,$r1,$a0s,$loc
    mov     $r1, $a2
    mov     $r0, $a1
    bics    $r1, $r1, $r0
    eors    $a0, $a0, $r1
    if $loc != locRegL
    if $loc == locRegH
    mov     $a0s, $a0
    else
    str     $a0, [sp, #$a0s]
    endif
    endif

    mov     $r0, $a0
    bics    $r0, $r0, $a2
    mov     $r1, $a1
    eors    $r1, $r1, $r0
    mov     $a1, $r1

    bics    $r1, $r1, $a0
    eors    $a2, $a2, $r1
    MEND

    MACRO
    mRound  $offsetRC, $offsetA03

    ; Theta: Column Parity Mixer
    mXor3   r0, $offsetA03, lr, r7, locMem, r2
    mov     r1, r0
    movs    r2, #32-(_r1-_r0)
    rors    r1, r1, r2
    eors    r1, r1, r0
    movs    r2, #32-_r0
    rors    r1, r1, r2
    mXor3   r0, r3, r10, r4, locRegL, r2
    mXor    r3, r1, r2, locRegL
    mXor    r10, r1, r2, locRegH
    mXor    r4, r1, r2, locRegL

    mov     r1, r0
    movs    r2, #32-(_r1-_r0)
    rors    r1, r1, r2
    eors    r1, r1, r0
    movs    r2, #32-_r0
    rors    r1, r1, r2
    mXor3   r0, r8, r11, r5, locRegH, r2
    mXor    r8, r1, r2, locRegH
    mXor    r11, r1, r2, locRegH
    mXor    r5, r1, r2, locRegL

    mov     r1, r0
    movs    r2, #32-(_r1-_r0)
    rors    r1, r1, r2
    eors    r1, r1, r0
    movs    r2, #32-_r0
    rors    r1, r1, r2
    mXor3   r0, r9, r12, r6, locRegH, r2
    mXor    r9, r1, r2, locRegH
    mXor    r12, r1, r2, locRegH
    mXor    r6, r1, r2, locRegL

    mov     r1, r0
    movs    r2, #32-(_r1-_r0)
    rors    r1, r1, r2
    eors    r1, r1, r0
    movs    r2, #32-_r0
    rors    r1, r1, r2
    mXor    $offsetA03, r1, r2, locMem
    mXor    lr, r1, r2, locRegH
    mXor    r7, r1, r2, locRegL

    ; Rho-west: Plane shift
    movs    r0, #32-_w1
    rors    r4, r4, r0
    rors    r5, r5, r0
    rors    r6, r6, r0
    rors    r7, r7, r0
    mov     r0, lr
    mov     lr, r12
    mov     r12, r11
    mov     r11, r10
    mov     r10, r0

    ; Iota: round constant
    ldr     r0, [sp, #$offsetRC]
    ldmia   r0!, {r1}
    str     r0, [sp, #$offsetRC]
    eors    r3, r3, r1

    ; Chi: non linear step, on colums
    mChi3   r3, r10, r4, r0, r1, r3, locRegL
    mov     r2, r8
    mChi3   r2, r11, r5, r0, r1, r8, locRegH
    mov     r2, r9
    mChi3   r2, r12, r6, r0, r1, r9, locRegH
    ldr     r2, [sp, #$offsetA03]
    mChi3   r2, lr, r7, r0, r1, $offsetA03, locMem

    ; Rho-east: Plane shift
    movs    r0, #32-1
    mov     r1, r10
    rors    r1, r1, r0
    mov     r10, r1
    mov     r1, r11
    rors    r1, r1, r0
    mov     r11, r1
    mov     r1, r12
    rors    r1, r1, r0
    mov     r12, r1
    mov     r1, lr
    rors    r1, r1, r0
    mov     lr, r1

    movs    r0, #32-_e1
    rors    r4, r4, r0
    rors    r5, r5, r0
    rors    r6, r6, r0
    rors    r7, r7, r0

    mov     r0, r4
    mov     r4, r6
    mov     r6, r0
    mov     r0, r5
    mov     r5, r7
    mov     r7, r0

    MEND

; ----------------------------------------------------------------------------
;
; void Xoodoo_Permute_Nrounds(Xoodoo_plain32_state *state, unsigned int nrounds)
;  

; offsets on stack
Xoodoo_Permute_Nrounds_offsetA03    equ 0
Xoodoo_Permute_Nrounds_offsetRC     equ 4
Xoodoo_Permute_Nrounds_SAS          equ 8
Xoodoo_Permute_Nrounds_offsetState  equ Xoodoo_Permute_Nrounds_SAS

    EXPORT  Xoodoo_Permute_Nrounds
Xoodoo_Permute_Nrounds   PROC
    push    {r4-r6,lr}
    mov     r2, r8
    mov     r3, r9
    mov     r4, r10
    mov     r5, r11
    push    {r0,r2-r5,r7}

    sub     sp, #Xoodoo_Permute_Nrounds_SAS
    adr     r2, Xoodoo_Permute_RoundConstants12
    lsls    r1, r1, #2
    subs    r2, r2, r1
    str     r2, [sp, #Xoodoo_Permute_Nrounds_offsetRC]

    ldm     r0!, {r3,r5,r6,r7}
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_Nrounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodoo_Permute_Nrouds_Loop
    mRound  Xoodoo_Permute_Nrounds_offsetRC, Xoodoo_Permute_Nrounds_offsetA03
    ldr     r0, [sp, #Xoodoo_Permute_Nrounds_offsetRC]
    ldr     r0, [r0]
    cmp     r0, #0
    beq     Xoodoo_Permute_Nrouds_Done
    b       Xoodoo_Permute_Nrouds_Loop
Xoodoo_Permute_Nrouds_Done
    ldr     r0, [sp, #Xoodoo_Permute_Nrounds_offsetState]

    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_Nrounds_offsetA03]
    stm     r0!, {r1,r2,r3}

    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}

    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    
    add     sp, #Xoodoo_Permute_Nrounds_SAS
    pop     {r0-r4,r7}
    mov     r8, r1
    mov     r9, r2
    mov     r10, r3
    mov     r11, r4
    pop     {r4-r6,pc}
    align   4
    ENDP

Xoodoo_Permute_RoundConstants
    dcd     0x00000058
    dcd     0x00000038
    dcd     0x000003C0
    dcd     0x000000D0
    dcd     0x00000120
    dcd     0x00000014
    dcd     0x00000060
    dcd     0x0000002C
    dcd     0x00000380
    dcd     0x000000F0
    dcd     0x000001A0
    dcd     0x00000012
Xoodoo_Permute_RoundConstants12
    dcd     0
    align   4

; ----------------------------------------------------------------------------
;
;  void Xoodoo_Permute_6rounds( Xoodoo_plain32_state *state )
;
    EXPORT  Xoodoo_Permute_6rounds
Xoodoo_Permute_6rounds   PROC
    movs    r1, #6
    b       Xoodoo_Permute_Nrounds
    align   4
    ENDP


; ----------------------------------------------------------------------------
;
;  void Xoodoo_Permute_12rounds( Xoodoo_plain32_state *state )
;
    EXPORT  Xoodoo_Permute_12rounds
Xoodoo_Permute_12rounds   PROC
    movs    r1, #12
    b       Xoodoo_Permute_Nrounds
    align   4
    ENDP


Xoofff_BlockSize        equ 3*4*4

; ----------------------------------------------------------------------------
;
; void Xoofff_AddIs(BitSequence *output, const BitSequence *input, BitLength bitLen)
    EXPORT  Xoofff_AddIs
Xoofff_AddIs   PROC
    push    {r4-r6,lr}
    movs    r3, r0                                  ; check input and output pointer both 32-bit aligned
    orrs    r3, r3, r1
    lsls    r3, r3, #30
    bne     Xoofff_AddIs_Bytes
    subs    r2, r2, #16*8
    bcc     Xoofff_AddIs_LessThan16
Xoofff_AddIs_16Loop
    ldr     r3, [r0, #0]
    ldr     r4, [r0, #4]
    ldmia   r1!, {r5,r6}
    eors    r3, r3, r5
    eors    r4, r4, r6
    stmia   r0!, {r3,r4}
    ldr     r3, [r0, #0]
    ldr     r4, [r0, #4]
    ldmia   r1!, {r5,r6}
    eors    r3, r3, r5
    eors    r4, r4, r6
    stmia   r0!, {r3,r4}
    subs    r2, r2, #16*8
    bcs     Xoofff_AddIs_16Loop
Xoofff_AddIs_LessThan16
    adds    r2, r2, #16*8
    beq     Xoofff_AddIs_Return
    subs    r2, r2, #4*8
    bcc     Xoofff_AddIs_LessThan4
Xoofff_AddIs_4Loop
    ldr     r3, [r0]
    ldmia   r1!, {r4}
    eors    r3, r3, r4
    stmia   r0!, {r3}
    subs    r2, r2, #4*8
    bcs     Xoofff_AddIs_4Loop
Xoofff_AddIs_LessThan4
    adds    r2, r2, #4*8
    beq     Xoofff_AddIs_Return
Xoofff_AddIs_Bytes
    subs    r2, r2, #8
    bcc     Xoofff_AddIs_LessThan1
Xoofff_AddIs_1Loop
    ldrb    r3, [r0]
    ldrb    r4, [r1]
    adds    r1, r1, #1
    eors    r3, r3, r4
    strb    r3, [r0]
    adds    r0, r0, #1
    subs    r2, r2, #8
    bcs     Xoofff_AddIs_1Loop
Xoofff_AddIs_LessThan1
    adds    r2, r2, #8
    beq     Xoofff_AddIs_Return
    ldrb    r3, [r0]
    ldrb    r4, [r1]
    movs    r1, #1
    eors    r3, r3, r4
    lsls    r1, r1, r2
    subs    r1, r1, #1
    ands    r3, r3, r1
    strb    r3, [r0]
Xoofff_AddIs_Return
    pop     {r4-r6,pc}
    align   4
    ENDP

    MACRO
    mLdu    $rv, $ri, $tt
    ldrb    $rv, [$ri, #3]
    lsls    $rv, $rv, #8
    ldrb    $tt, [$ri, #2]
    orrs    $rv, $rv, $tt
    lsls    $rv, $rv, #8
    ldrb    $tt, [$ri, #1]
    orrs    $rv, $rv, $tt
    lsls    $rv, $rv, #8
    ldrb    $tt, [$ri, #0]
    orrs    $rv, $rv, $tt
    adds    $ri, $ri, #4
    MEND

; ----------------------------------------------------------------------------
;
; size_t Xoofff_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length)
;

; offsets on stack
Xoofff_CompressFastLoop_offsetA03   equ 0
Xoofff_CompressFastLoop_offsetRC    equ 4
Xoofff_CompressFastLoop_SAS         equ 8
Xoofff_CompressFastLoop_kRoll       equ Xoofff_CompressFastLoop_SAS+0
Xoofff_CompressFastLoop_input       equ Xoofff_CompressFastLoop_SAS+4
Xoofff_CompressFastLoop_xAccu       equ Xoofff_CompressFastLoop_SAS+8+16
Xoofff_CompressFastLoop_iInput      equ Xoofff_CompressFastLoop_SAS+12+16
Xoofff_CompressFastLoop_length      equ Xoofff_CompressFastLoop_SAS+16+16

    EXPORT  Xoofff_CompressFastLoop
Xoofff_CompressFastLoop   PROC
    subs    r3, #Xoofff_BlockSize       ; length must be greater than block size
    push    {r1-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r0,r2,r4-r7}
    sub     sp, #Xoofff_CompressFastLoop_SAS
    ldm     r0!, {r3,r5,r6,r7}      ; get initial kRoll
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoofff_CompressFastLoop_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoofff_CompressFastLoop_Loop
    adr     r1, Xoofff_CompressFastLoop_RoundConstants6
    str     r1, [sp, #Xoofff_CompressFastLoop_offsetRC]

    ldr     r0, [sp, #Xoofff_CompressFastLoop_input]    ; add input
    lsls    r1, r0, #30
    bne     Xoofff_CompressFastLoop_Unaligned

Xoofff_CompressFastLoop_Aligned
    ldmia   r0!, {r1}
    eors    r3, r3, r1
    ldmia   r0!, {r1}
    mov     r2, r8
    eors    r2, r2, r1
    mov     r8, r2
    ldmia   r0!, {r1}
    mov     r2, r9
    eors    r2, r2, r1
    mov     r9, r2
    ldmia   r0!, {r1}
    ldr     r2, [sp, #Xoofff_CompressFastLoop_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoofff_CompressFastLoop_offsetA03]

    ldmia   r0!, {r1}
    mov     r2, r10
    eors    r2, r2, r1
    mov     r10, r2
    ldmia   r0!, {r1}
    mov     r2, r11
    eors    r2, r2, r1
    mov     r11, r2
    ldmia   r0!, {r1}
    mov     r2, r12
    eors    r2, r2, r1
    mov     r12, r2
    ldmia   r0!, {r1}
    mov     r2, lr
    eors    r2, r2, r1
    mov     lr, r2

    ldmia   r0!, {r1,r2}
    eors    r4, r4, r1
    eors    r5, r5, r2
    ldmia   r0!, {r1,r2}
    eors    r6, r6, r1
    eors    r7, r7, r2

    b       Xoofff_CompressFastLoop_Permute
    align   4
Xoofff_CompressFastLoop_RoundConstants6
    dcd     0x00000060
    dcd     0x0000002C
    dcd     0x00000380
    dcd     0x000000F0
    dcd     0x000001A0
    dcd     0x00000012
    dcd     0

Xoofff_CompressFastLoop_Unaligned
    mLdu    r1, r0, r2
    eors    r3, r3, r1
    mLdu    r1, r0, r2
    mov     r2, r8
    eors    r2, r2, r1
    mov     r8, r2
    mLdu    r1, r0, r2
    mov     r2, r9
    eors    r2, r2, r1
    mov     r9, r2
    mLdu    r1, r0, r2
    ldr     r2, [sp, #Xoofff_CompressFastLoop_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoofff_CompressFastLoop_offsetA03]

    mLdu    r1, r0, r2
    mov     r2, r10
    eors    r2, r2, r1
    mov     r10, r2
    mLdu    r1, r0, r2
    mov     r2, r11
    eors    r2, r2, r1
    mov     r11, r2
    mLdu    r1, r0, r2
    mov     r2, r12
    eors    r2, r2, r1
    mov     r12, r2
    mLdu    r1, r0, r2
    mov     r2, lr
    eors    r2, r2, r1
    mov     lr, r2

    mLdu    r1, r0, r2
    eors    r4, r4, r1
    mLdu    r1, r0, r2
    eors    r5, r5, r1
    mLdu    r1, r0, r2
    eors    r6, r6, r1
    mLdu    r1, r0, r2
    eors    r7, r7, r1

Xoofff_CompressFastLoop_Permute
    str     r0, [sp, #Xoofff_CompressFastLoop_input]
Xoofff_CompressFastLoop_PermuteLoop
    mRound  Xoofff_CompressFastLoop_offsetRC, Xoofff_CompressFastLoop_offsetA03
    ldr     r0, [sp, #Xoofff_CompressFastLoop_offsetRC]
    ldr     r0, [r0]
    cmp     r0, #0
    beq     Xoofff_CompressFastLoop_PermuteDone
    b       Xoofff_CompressFastLoop_PermuteLoop
Xoofff_CompressFastLoop_PermuteDone

    ; Extract and add into xAccu
    ldr     r0, [sp, #Xoofff_CompressFastLoop_xAccu]

    ldr     r1, [r0]
    eors    r1, r1, r3
    stmia   r0!, {r1}

    ldr     r1, [r0]
    mov     r2, r8
    eors    r1, r1, r2
    stmia   r0!, {r1}

    ldr     r1, [r0]
    mov     r2, r9
    eors    r1, r1, r2
    stmia   r0!, {r1}

    ldr     r1, [r0]
    ldr     r2, [sp, #Xoofff_CompressFastLoop_offsetA03]
    eors    r1, r1, r2
    stmia   r0!, {r1}


    ldr     r1, [r0]
    mov     r2, r10
    eors    r1, r1, r2
    stmia   r0!, {r1}
    ldr     r1, [r0]
    mov     r2, r11
    eors    r1, r1, r2
    stmia   r0!, {r1}
    ldr     r1, [r0]
    mov     r2, r12
    eors    r1, r1, r2
    stmia   r0!, {r1}
    ldr     r1, [r0]
    mov     r2, lr
    eors    r1, r1, r2
    stmia   r0!, {r1}

    ldr     r1, [r0, #0]
    ldr     r2, [r0, #4]
    ldr     r3, [r0, #8]
    eors    r1, r1, r4
    ldr     r4, [r0, #12]
    eors    r2, r2, r5
    eors    r3, r3, r6
    eors    r4, r4, r7
    stm     r0!, {r1,r2,r3,r4}

    ;roll kRoll-c
    ldr     r0, [sp, #Xoofff_CompressFastLoop_kRoll]
    ldmia   r0!, {r7}
    ldmia   r0!, {r4-r6}    
    ldmia   r0!, {r3}    
    ldmia   r0!, {r1,r2}
    mov     r8, r1
    mov     r9, r2
    ldmia   r0!, {r1,r2}
    str     r1, [sp, #Xoofff_CompressFastLoop_offsetA03]
    mov     r10, r2
    ldmia   r0!, {r1,r2}
    mov     r11, r1
    mov     r12, r2
    ldmia   r0!, {r1}
    mov     lr, r1

    lsls    r1, r7, #13
    eors    r7, r7, r1
    mov     r1, r3
    movs    r2, #32-3
    rors    r1, r1, r2
    eors    r7, r7, r1

    subs    r0, r0, #Xoofff_BlockSize
    stmia   r0!, {r3}    
    mov     r1, r8
    mov     r2, r9
    stmia   r0!, {r1,r2}
    ldr     r1, [sp, #Xoofff_CompressFastLoop_offsetA03]
    mov     r2, r10
    stmia   r0!, {r1,r2}
    mov     r1, r11
    mov     r2, r12
    stmia   r0!, {r1,r2}
    mov     r1, lr
    stmia   r0!, {r1,r4-r7}

    ; loop management
    ldr     r0, [sp, #Xoofff_CompressFastLoop_length]
    subs    r0, #Xoofff_BlockSize
    str     r0, [sp, #Xoofff_CompressFastLoop_length]
    bcc     Xoofff_CompressFastLoop_Done
    b       Xoofff_CompressFastLoop_Loop
Xoofff_CompressFastLoop_Done
    ; return number of bytes processed
    ldr     r0, [sp, #Xoofff_CompressFastLoop_input]
    ldr     r1, [sp, #Xoofff_CompressFastLoop_iInput]
    subs    r0, r0, r1
    add     sp, #Xoofff_CompressFastLoop_SAS+8
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r1-r7,pc}
    align   4
    ENDP

    MACRO
    mStu    $rv, $ro
    strb    $rv, [$ro, #0]
    lsrs    $rv, $rv, #8
    strb    $rv, [$ro, #1]
    lsrs    $rv, $rv, #8
    strb    $rv, [$ro, #2]
    lsrs    $rv, $rv, #8
    strb    $rv, [$ro, #3]
    adds    $ro, $ro, #4
    MEND

; ----------------------------------------------------------------------------
;
; size_t Xoofff_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
;

; offsets on stack
Xoofff_ExpandFastLoop_offsetA03 equ 0
Xoofff_ExpandFastLoop_offsetRC  equ 4
Xoofff_ExpandFastLoop_SAS       equ 8
Xoofff_ExpandFastLoop_yAccu     equ Xoofff_ExpandFastLoop_SAS+0
Xoofff_ExpandFastLoop_output    equ Xoofff_ExpandFastLoop_SAS+4
Xoofff_ExpandFastLoop_kRoll     equ Xoofff_ExpandFastLoop_SAS+8+16
Xoofff_ExpandFastLoop_iOutput   equ Xoofff_ExpandFastLoop_SAS+12+16
Xoofff_ExpandFastLoop_length    equ Xoofff_ExpandFastLoop_SAS+16+16

    EXPORT  Xoofff_ExpandFastLoop
Xoofff_ExpandFastLoop   PROC
    subs    r3, #Xoofff_BlockSize                       ; length must be greater than block size
    push    {r1-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r0,r2,r4-r7}
    sub     sp, #Xoofff_ExpandFastLoop_SAS

    ldm     r0!, {r3,r5,r6,r7}                      ; get initial yAccu
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoofff_ExpandFastLoop_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoofff_ExpandFastLoop_Loop
    adr     r1, Xoofff_ExpandFastLoop_RoundConstants6
    str     r1, [sp, #Xoofff_ExpandFastLoop_offsetRC]
Xoofff_ExpandFastLoop_PermuteLoop
    mRound  Xoofff_ExpandFastLoop_offsetRC, Xoofff_ExpandFastLoop_offsetA03
    ldr     r0, [sp, #Xoofff_ExpandFastLoop_offsetRC]
    ldr     r0, [r0]
    cmp     r0, #0
    beq     Xoofff_ExpandFastLoop_PermuteDone
    b       Xoofff_ExpandFastLoop_PermuteLoop
Xoofff_ExpandFastLoop_RoundConstants6
    dcd     0x00000060
    dcd     0x0000002C
    dcd     0x00000380
    dcd     0x000000F0
    dcd     0x000001A0
    dcd     0x00000012
    dcd     0
Xoofff_ExpandFastLoop_PermuteDone
    ; Add k and extract
    ldr     r0, [sp, #Xoofff_ExpandFastLoop_kRoll]
    ldr     r1, [sp, #Xoofff_ExpandFastLoop_output]    ; add input
    lsls    r2, r1, #30
    bne     Xoofff_ExpandFastLoop_Unaligned
Xoofff_ExpandFastLoop_Aligned
    ldmia   r0!, {r2}
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    mov     r3, r8
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    mov     r3, r9
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    ldr     r3, [sp, #Xoofff_ExpandFastLoop_offsetA03]
    eors    r2, r2, r3
    stmia   r1!, {r2}

    ldmia   r0!, {r2}
    mov     r3, r10
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    mov     r3, r11
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    mov     r3, r12
    eors    r2, r2, r3
    stmia   r1!, {r2}
    ldmia   r0!, {r2}
    mov     r3, lr
    eors    r2, r2, r3
    stmia   r1!, {r2}

    ldmia   r0!, {r2,r3}
    eors    r2, r2, r4
    eors    r3, r3, r5
    stmia   r1!, {r2,r3}
    ldmia   r0!, {r2,r3}
    eors    r2, r2, r6
    eors    r3, r3, r7
    stmia   r1!, {r2,r3}
    b       Xoofff_ExpandFastLoop_ExtractDone

Xoofff_ExpandFastLoop_Unaligned
    ldmia   r0!, {r2}
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    mov     r3, r8
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    mov     r3, r9
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    ldr     r3, [sp, #Xoofff_ExpandFastLoop_offsetA03]
    eors    r2, r2, r3
    mStu    r2, r1

    ldmia   r0!, {r2}
    mov     r3, r10
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    mov     r3, r11
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    mov     r3, r12
    eors    r2, r2, r3
    mStu    r2, r1
    ldmia   r0!, {r2}
    mov     r3, lr
    eors    r2, r2, r3
    mStu    r2, r1

    ldmia   r0!, {r2,r3}
    eors    r2, r2, r4
    mStu    r2, r1
    eors    r3, r3, r5
    mStu    r3, r1
    ldmia   r0!, {r2,r3}
    eors    r2, r2, r6
    mStu    r2, r1
    eors    r3, r3, r7
    mStu    r3, r1

Xoofff_ExpandFastLoop_ExtractDone
    str     r1, [sp, #Xoofff_ExpandFastLoop_output]

    ; roll-e yAccu
    ldr     r0, [sp, #Xoofff_ExpandFastLoop_yAccu]
    ldmia   r0!, {r7}
    ldmia   r0!, {r4-r6}    
    ldmia   r0!, {r3}    
    ldmia   r0!, {r1,r2}
    mov     r8, r1
    mov     r9, r2
    ldmia   r0!, {r1,r2}
    str     r1, [sp, #Xoofff_ExpandFastLoop_offsetA03]
    mov     r10, r2
    ldmia   r0!, {r1,r2}
    mov     r11, r1
    mov     r12, r2
    ldmia   r0!, {r1}
    mov     lr, r1

    mov     r1, r10
    ands    r1, r1, r3
    movs    r2, #32-5
    rors    r7, r7, r2
    eors    r7, r7, r1
    movs    r2, #32-13
    mov     r1, r3
    rors    r1, r1, r2
    eors    r7, r7, r1
    movs    r1, #7
    eors    r7, r7, r1

    subs    r0, r0, #Xoofff_BlockSize
    stmia   r0!, {r3}    
    mov     r1, r8
    mov     r2, r9
    stmia   r0!, {r1,r2}
    ldr     r1, [sp, #Xoofff_ExpandFastLoop_offsetA03]
    mov     r2, r10
    stmia   r0!, {r1,r2}
    mov     r1, r11
    mov     r2, r12
    stmia   r0!, {r1,r2}
    mov     r1, lr
    stmia   r0!, {r1,r4-r7}

    ; loop management
    ldr     r0, [sp, #Xoofff_ExpandFastLoop_length]
    subs    r0, #Xoofff_BlockSize
    str     r0, [sp, #Xoofff_ExpandFastLoop_length]
    bcc     Xoofff_ExpandFastLoop_Done
    b       Xoofff_ExpandFastLoop_Loop
Xoofff_ExpandFastLoop_Done
    ; return number of bytes processed
    ldr     r0, [sp, #Xoofff_ExpandFastLoop_output]
    ldr     r1, [sp, #Xoofff_ExpandFastLoop_iOutput]
    subs    r0, r0, r1
    add     sp, #Xoofff_ExpandFastLoop_SAS+8
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r1-r7,pc}
    align   4
    ENDP

    END
