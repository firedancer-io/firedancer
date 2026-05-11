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

; WARNING: These functions work only on little endian CPU with ARMv7a + NEON architecture (Cortex-A8, ...).

        PRESERVE8
        AREA    |.text|, CODE, READONLY

; ----------------------------------------------------------------------------
;
;  void Xoodoo_Initialize(Xoodoo_align128plain32_state *state)
;
    ALIGN
    EXPORT  Xoodoo_Initialize
Xoodoo_Initialize   PROC
    vmov.i32    q0, #0
    vstm        r0!, { d0 - d1 }
    vstm        r0!, { d0 - d1 }
    vstm        r0!, { d0 - d1 }
    bx          lr
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_AddBytes(Xoodoo_align128plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_AddBytes
Xoodoo_AddBytes   PROC
    push    {r4,lr}
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_AddBytes_Bytes
Xoodoo_AddBytes_LanesLoop                           ; then, perform on lanes
    ldr     r2, [r0]
    ldr     r4, [r1], #4
    eors    r2, r2, r4
    str     r2, [r0], #4
    subs    r3, r3, #4
    bcs     Xoodoo_AddBytes_LanesLoop
Xoodoo_AddBytes_Bytes
    adds    r3, r3, #3
    bcc     Xoodoo_AddBytes_Exit
Xoodoo_AddBytes_BytesLoop
    ldrb    r2, [r0]
    ldrb    r4, [r1], #1
    eors    r2, r2, r4
    strb    r2, [r0], #1
    subs    r3, r3, #1
    bcs     Xoodoo_AddBytes_BytesLoop
Xoodoo_AddBytes_Exit
    pop     {r4,pc}
    align   8
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_OverwriteBytes(Xoodoo_align128plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_OverwriteBytes
Xoodoo_OverwriteBytes   PROC
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_OverwriteBytes_Bytes
Xoodoo_OverwriteBytes_LanesLoop                     ; then, perform on words
    ldr     r2, [r1], #4
    str     r2, [r0], #4
    subs    r3, r3, #4
    bcs     Xoodoo_OverwriteBytes_LanesLoop
Xoodoo_OverwriteBytes_Bytes
    adds    r3, r3, #3
    bcc     Xoodoo_OverwriteBytes_Exit
Xoodoo_OverwriteBytes_BytesLoop
    ldrb    r2, [r1], #1
    strb    r2, [r0], #1
    subs    r3, r3, #1
    bcs     Xoodoo_OverwriteBytes_BytesLoop
Xoodoo_OverwriteBytes_Exit
    bx      lr
    align   8
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_OverwriteWithZeroes(Xoodoo_align128plain32_state *state, unsigned int byteCount)
;
    EXPORT  Xoodoo_OverwriteWithZeroes
Xoodoo_OverwriteWithZeroes  PROC
    movs    r3, #0
    lsrs    r2, r1, #2
    beq     Xoodoo_OverwriteWithZeroes_Bytes
Xoodoo_OverwriteWithZeroes_LoopLanes
    str     r3, [r0], #4
    subs    r2, r2, #1
    bne     Xoodoo_OverwriteWithZeroes_LoopLanes
Xoodoo_OverwriteWithZeroes_Bytes
    ands    r1, #3
    beq     Xoodoo_OverwriteWithZeroes_Exit
Xoodoo_OverwriteWithZeroes_LoopBytes
    strb    r3, [r0], #1
    subs    r1, r1, #1
    bne     Xoodoo_OverwriteWithZeroes_LoopBytes
Xoodoo_OverwriteWithZeroes_Exit
    bx      lr
    align   8
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_ExtractBytes(Xoodoo_align128plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_ExtractBytes
Xoodoo_ExtractBytes   PROC
    adds    r0, r0, r2                              ; state += offset
    subs    r3, r3, #4                              ; if length >= 4
    bcc     Xoodoo_ExtractBytes_Bytes
Xoodoo_ExtractBytes_LanesLoop                       ; then, handle words
    ldr     r2, [r0], #4
    str     r2, [r1], #4
    subs    r3, r3, #4
    bcs     Xoodoo_ExtractBytes_LanesLoop
Xoodoo_ExtractBytes_Bytes
    adds    r3, r3, #3
    bcc     Xoodoo_ExtractBytes_Exit
Xoodoo_ExtractBytes_BytesLoop
    ldrb    r2, [r0], #1
    strb    r2, [r1], #1
    subs    r3, r3, #1
    bcs     Xoodoo_ExtractBytes_BytesLoop
Xoodoo_ExtractBytes_Exit
    bx      lr
    align   8
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_ExtractAndAddBytes(Xoodoo_align128plain32_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
;
    EXPORT  Xoodoo_ExtractAndAddBytes
Xoodoo_ExtractAndAddBytes   PROC
    push    {r4,r5}
    adds    r0, r0, r3                                  ; state += offset (offset register no longer needed, reuse for length)
    ldr     r3, [sp, #8]                                ; get length argument from stack
    subs    r3, r3, #4                                  ; if length >= 4
    bcc     Xoodoo_ExtractAndAddBytes_Bytes
Xoodoo_ExtractAndAddBytes_LanesLoop                     ; then, handle words
    ldr     r5, [r0], #4
    ldr     r4, [r1], #4
    eors    r5, r5, r4
    str     r5, [r2], #4
    subs    r3, r3, #4
    bcs     Xoodoo_ExtractAndAddBytes_LanesLoop
Xoodoo_ExtractAndAddBytes_Bytes
    adds    r3, r3, #3
    bcc     Xoodoo_ExtractAndAddBytes_Exit
Xoodoo_ExtractAndAddBytes_BytesLoop
    ldrb    r5, [r0], #1
    ldrb    r4, [r1], #1
    eors    r5, r5, r4
    strb    r5, [r2], #1
    subs    r3, r3, #1
    bcs     Xoodoo_ExtractAndAddBytes_BytesLoop
Xoodoo_ExtractAndAddBytes_Exit
    pop     {r4,r5}
    bx      lr
    align   8
    ENDP

; ----------------------------------------------------------------------------

    macro
    mRound

    ; Theta: Column Parity Mixer
    veor.32     q4, q0, q1
    veor.32     q4, q4, q2
    vext.32     q4, q4, q4, #3
    vshl.u32    q3, q4, #5
    vsri.u32    q3, q4, #32-5
    vshl.u32    q5, q4, #14
    vsri.u32    q5, q4, #32-14
    veor.32     q3, q3, q5
    veor.32     q0, q0, q3
    veor.32     q1, q1, q3
    veor.32     q5, q2, q3           ; q2 resides in q5

    ; Rho-west: Plane shift
    ; Iota: add round constant
    vshl.u32    q2, q5, #11
    vext.32     q1, q1, q1, #3
    vldmia      r1!, {d6}             ; iota
    vsri.u32    q2, q5, #32-11
    veor.32     d0, d0, d6        ; iota

    ; Chi: non linear step, on colums
    vbic.32     q3, q2, q1
    vbic.32     q4, q0, q2
    vbic.32     q5, q1, q0
    veor.32     q0, q0, q3
    veor.32     q4, q1, q4           ; q1 resides in q4
    veor.32     q2, q2, q5

    ; Rho-east: Plane shift
    vext.32     q5, q2, q2, #2
    vshl.u32    q1, q4, #1
    vshl.u32    q2, q5, #8
    vsri.u32    q1, q4, #32-1
    vsri.u32    q2, q5, #32-8
    mend

; ----------------------------------------------------------------------------
;
;  void Xoodoo_Permute_6rounds( Xoodoo_align128plain32_state *state )
;
    EXPORT  Xoodoo_Permute_6rounds
Xoodoo_Permute_6rounds   PROC
    vpush       {q4-q5}
    vldmia      r0, {q0-q2}
    adr         r1, _rc6
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    vstmia      r0, {q0-q2}
    vpop        {q4-q5}
    bx          lr
    LTORG
    align       8
_rc12  
    dcq         0x00000058
    dcq         0x00000038
    dcq         0x000003C0
    dcq         0x000000D0
    dcq         0x00000120
    dcq         0x00000014
_rc6
    dcq         0x00000060
    dcq         0x0000002C
    dcq         0x00000380
    dcq         0x000000F0
    dcq         0x000001A0
    dcq         0x00000012
    ENDP

; ----------------------------------------------------------------------------
;
;  void Xoodoo_Permute_12rounds( Xoodoo_align128plain32_state *state )
;
    EXPORT  Xoodoo_Permute_12rounds
Xoodoo_Permute_12rounds   PROC
    vpush       {q4-q5}
    vldmia      r0, {q0-q2}
    adr         r1, _rc12
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    mRound
    vstmia      r0, {q0-q2}
    vpop        {q4-q5}
    bx          lr
    align       8
    ENDP

Xoofff_BlockSize    equ 3*4*4

; ----------------------------------------------------------------------------
;
; void Xoofff_AddIs(BitSequence *output, const BitSequence *input, BitLength bitLen)
    EXPORT  Xoofff_AddIs
Xoofff_AddIs   PROC
    subs        r2, r2, #Xoofff_BlockSize*8
    bcc         Xoofff_AddIs_LessThanBlock
Xoofff_AddIs_BlockLoop
    vld1.32     {q0, q1}, [r1]!
    vld1.32     {q2}, [r1]!
    vld1.32     {q8, q9}, [r0]!
    vld1.32     {q10}, [r0]!
    veor.32     q8, q8, q0
    sub         r0, r0, #Xoofff_BlockSize
    veor.32     q9, q9, q1
    veor.32     q10, q10, q2
    vst1.32     {q8, q9}, [r0]!
    vst1.32     {q10}, [r0]!
    subs        r2, r2, #Xoofff_BlockSize*8
    bcs         Xoofff_AddIs_BlockLoop
Xoofff_AddIs_LessThanBlock
    adds        r2, r2, #Xoofff_BlockSize*8
    beq         Xoofff_AddIs_Return
    subs        r2, r2, #16*8
    bcc         Xoofff_AddIs_LessThan16
Xoofff_AddIs_16Loop
    vld1.32     {q0}, [r1]!
    vld1.32     {q1}, [r0]
    veor.32     q1, q1, q0
    vst1.32     {q1}, [r0]!
    subs        r2, r2, #16*8
    bcs         Xoofff_AddIs_16Loop
Xoofff_AddIs_LessThan16
    adds        r2, r2, #16*8
    beq         Xoofff_AddIs_Return
    subs        r2, r2, #4*8
    bcc         Xoofff_AddIs_LessThan4
Xoofff_AddIs_4Loop
    ldr         r3, [r0]
    ldr         r12, [r1], #4
    eors        r3, r3, r12
    str         r3, [r0], #4
    subs        r2, r2, #4*8
    bcs         Xoofff_AddIs_4Loop
Xoofff_AddIs_LessThan4
    adds        r2, r2, #4*8
    beq         Xoofff_AddIs_Return
    subs        r2, r2, #8
    bcc         Xoofff_AddIs_LessThan1
Xoofff_AddIs_1Loop
    ldrb        r3, [r0]
    ldrb        r12, [r1], #1
    eors        r3, r3, r12
    strb        r3, [r0], #1
    subs        r2, r2, #8
    bcs         Xoofff_AddIs_1Loop
Xoofff_AddIs_LessThan1
    adds        r2, r2, #8
    beq         Xoofff_AddIs_Return
    ldrb        r3, [r0]
    ldrb        r12, [r1]
    movs        r1, #1
    eors        r3, r3, r12
    lsls        r1, r1, r2
    subs        r1, r1, #1
    ands        r3, r3, r1
    strb        r3, [r0]
Xoofff_AddIs_Return
    bx          lr
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoofff_CompressFastLoop(unsigned char *kRoll, unsigned char *xAccu, const unsigned char *input, size_t length)
;
    EXPORT  Xoofff_CompressFastLoop
Xoofff_CompressFastLoop   PROC
    subs        r3, #Xoofff_BlockSize       ; length must be greater than block size
    push        {r4,r5,r6,lr}
    vpush       {q4-q7}
    mov         r4, r0                      ; kRoll
    mov         r5, r1                      ; xAccu
    mov         r6, r2                      ; initial input
    vld1.32     {q6,q7}, [r0]!            ; get kRoll
    vld1.32     {q8}, [r0]
    vld1.32     {q9,q10}, [r1]!            ; get xAccu
    vld1.32     {q11}, [r1]
Xoofff_CompressFastLoop_Loop
    vld1.32     {q0,q1}, [r2]!            ; get input
    adr         r1, _rc6b
    vld1.32     {q2}, [r2]!
    veor.32     q0, q0, q6
    veor.32     q1, q1, q7
    veor.32     q2, q2, q8
    mRound                                  ; permutation
    mRound
    mRound
    mRound
    mRound
    mRound
    veor.32     q9, q9, q0               ; add into xAccu
    veor.32     q10, q10, q1
    veor.32     q11, q11, q2
    vshl.u32    q3, q6, #13               ; roll-c kRoll
    veor.32     q3, q3, q6
    vshl.u32    q4, q7, #3
    vsri.u32    q4, q7, #32-3
    veor.32     q3, q3, q4
    vext.32     q3, q6, q3, #1
    vmov        q6, q7
    vmov        q7, q8
    vmov        q8, q3
    subs        r3, #Xoofff_BlockSize
    bcs         Xoofff_CompressFastLoop_Loop
    vst1.32     {q6,q7}, [r4]!            ; save kRoll
    vst1.32     {q8}, [r4]
    vst1.32     {q9,q10}, [r5]!            ; save xAccu
    vst1.32     {q11}, [r5]
    sub         r0, r2, r6                  ; return number of bytes processed
    vpop        {q4-q7}
    pop         {r4,r5,r6,pc}
    LTORG
    align       8
_rc6b
    dcq         0x00000060
    dcq         0x0000002C
    dcq         0x00000380
    dcq         0x000000F0
    dcq         0x000001A0
    dcq         0x00000012
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoofff_ExpandFastLoop(unsigned char *yAccu, const unsigned char *kRoll, unsigned char *output, size_t length)
;
    EXPORT  Xoofff_ExpandFastLoop
Xoofff_ExpandFastLoop   PROC
    subs        r3, #Xoofff_BlockSize       ; length must be greater than block size
    push        {r4,r5,r6,lr}
    vpush       {q4-q7}
    mov         r5, r0                      ; yAccu
    mov         r6, r2                      ; initial output
    vld1.32     {q6,q7}, [r1]!            ; get kRoll
    vld1.32     {q8}, [r1]
    vld1.32     {q9,q10}, [r0]!            ; get yAccu
    vld1.32     {q11}, [r0]
Xoofff_ExpandFastLoop_Loop
    vmov        q0, q9
    vmov        q1, q10
    vmov        q2, q11
    adr         r1, _rc6b
    mRound                                  ; permutation
    mRound
    mRound
    mRound
    mRound
    mRound
    veor.32     q0, q0, q6               ; add k and extract
    veor.32     q1, q1, q7
    veor.32     q2, q2, q8
    vst1.32     {q0,q1}, [r2]!            ; save output
    vst1.32     {q2}, [r2]!
    vshl.u32    q3, q9, #5                ; roll-e yAccu
    vsri.u32    q3, q9, #32-5
    vshl.u32    q4, q10, #13
    vsri.u32    q4, q10, #32-13
    veor.32     q3, q3, q4
    vand.32     q4, q10, q11
    veor.32     q3, q3, q4
    vmov.i32    q4, #7
    veor.32     q3, q3, q4
    vext.32     q3, q9, q3, #1
    vmov        q9, q10
    vmov        q10, q11
    vmov        q11, q3
    subs        r3, #Xoofff_BlockSize
    bcs         Xoofff_ExpandFastLoop_Loop
    vst1.32     {q9,q10}, [r5]!            ; save yAccu
    sub         r0, r2, r6                  ; return number of bytes processed
    vst1.32     {q11}, [r5]
    vpop        {q4-q7}
    pop         {r4,r5,r6,pc}
    align       8
    ENDP

    END
