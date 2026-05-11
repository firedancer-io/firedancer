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

; WARNING: These functions work only on little endian CPU with ARMv7A architecture (Cortex-A7, ...).

    PRESERVE8
    AREA    |.text|, CODE, READONLY

Xoodyak_Rkin    equ     44
Xoodyak_Rkout   equ     24
Xoodyak_Rhash   equ     16

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
;  Xoodoo_Permute_12roundsAsm: only callable from asm
;
    align   8
Xoodoo_Permute_12roundsAsm   PROC
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
    dcq         0x00000060
    dcq         0x0000002C
    dcq         0x00000380
    dcq         0x000000F0
    dcq         0x000001A0
    dcq         0x00000012
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_AbsorbKeyedFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen)
; {
;     size_t  initialLength = XLen;
;
;     do {
;         SnP_Permute(state );                      /* Xoodyak_Up(instance, NULL, 0, 0); */
;         SnP_AddBytes(state, X, 0, Xoodyak_Rkin);  /* Xoodyak_Down(instance, X, Xoodyak_Rkin, 0); */
;         SnP_AddByte(state, 0x01, Xoodyak_Rkin);
;         X       += Xoodyak_Rkin;
;         XLen    -= Xoodyak_Rkin;
;     } while (XLen >= Xoodyak_Rkin);
;
;     return initialLength - XLen;
; }
;
    EXPORT      Xoodyak_AbsorbKeyedFullBlocks
Xoodyak_AbsorbKeyedFullBlocks   PROC
    push        {r4,lr}
    vpush       {q4-q7}
    vmov.i32    d13, #1
    mov         r3, r1                      ; r3 X
    mov         r4, r1                      ; r4 initial X
    vldmia      r0, {q0-q2}               ; get state
    subs        r2, r2, #Xoodyak_Rkin
Xoodyak_AbsorbKeyedFullBlocks_Loop
    bl          Xoodoo_Permute_12roundsAsm
    vld1.32     {q3,q4}, [r3]!            ; get X Xoodyak_Rkin bytes
    vld1.32     {d12}, [r3]!
    vld1.32     {d13[0]}, [r3]!
    veor.32     q0, q0, q3
    veor.32     q1, q1, q4
    veor.32     q2, q2, q6               ;X + pad
    subs        r2, r2, #Xoodyak_Rkin
    bcs         Xoodyak_AbsorbKeyedFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r3, r4
    vpop        {q4-q7}
    pop         {r4,pc}
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_AbsorbHashFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *X, size_t XLen)
; {
;     size_t  initialLength = XLen;
;
;     do {
;         SnP_Permute(state );                      /* Xoodyak_Up(instance, NULL, 0, 0); */
;         SnP_AddBytes(state, X, 0, Xoodyak_Rhash); /* Xoodyak_Down(instance, X, Xoodyak_Rhash, 0); */
;         SnP_AddByte(state, 0x01, Xoodyak_Rhash);
;         X       += Xoodyak_Rhash;
;         XLen    -= Xoodyak_Rhash;
;     } while (XLen >= Xoodyak_Rhash);
;
;     return initialLength - XLen;
; }
;
    EXPORT  Xoodyak_AbsorbHashFullBlocks
Xoodyak_AbsorbHashFullBlocks   PROC
    push        {r4,lr}
    vpush       {q4-q7}
    mov         r3, r1                      ; r3 X
    vmov.i32    d12, #1
    vshr.u64    d12, d12, #32
    mov         r4, r1                      ; r4 initial X
    vldmia      r0, {q0-q2}               ; get state
    subs        r2, r2, #Xoodyak_Rhash
Xoodyak_AbsorbHashFullBlocks_Loop
    bl          Xoodoo_Permute_12roundsAsm
    vld1.32     {q3}, [r3]!                ; get X Xoodyak_Rhash bytes
    veor.32     d2, d2, d12
    veor.32     q0, q0, q3
    subs        r2, r2, #Xoodyak_Rhash
    bcs         Xoodyak_AbsorbHashFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r3, r4
    vpop        {q4-q7}
    pop         {r4,pc}
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_SqueezeKeyedFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen)
; {
;     size_t  initialLength = YLen;
;
;     do {
;         SnP_AddByte(state, 0x01, 0);  /* Xoodyak_Down(instance, NULL, 0, 0); */
;         SnP_Permute(state );          /* Xoodyak_Up(instance, Y, Xoodyak_Rkout, 0); */
;         SnP_ExtractBytes(state, Y, 0, Xoodyak_Rkout);
;         Y    += Xoodyak_Rkout;
;         YLen -= Xoodyak_Rkout;
;     } while (YLen >= Xoodyak_Rkout);
;
;     return initialLength - YLen;
; }
;
    EXPORT  Xoodyak_SqueezeKeyedFullBlocks
Xoodyak_SqueezeKeyedFullBlocks   PROC
    push        {r4,lr}
    vpush       {q4-q7}
    vmov.i32    d12, #1
    vshr.u64    d12, d12, #32
    mov         r3, r1                      ; r3 Y
    mov         r4, r1                      ; r4 initial Y
    vldmia      r0, {q0-q2}               ; get state
    subs        r2, r2, #Xoodyak_Rkout
Xoodyak_SqueezeKeyedFullBlocks_Loop
    veor.32     d0, d0, d12
    bl          Xoodoo_Permute_12roundsAsm
    vst1.32     {q0}, [r3]!                ; save Y Xoodyak_Rkout bytes
    vst1.32     {d2}, [r3]!
    subs        r2, r2, #Xoodyak_Rkout
    bcs         Xoodyak_SqueezeKeyedFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r3, r4
    vpop        {q4-q7}
    pop         {r4,pc}
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_SqueezeHashFullBlocks(Xoodoo_align128plain32_state *state, uint8_t *Y, size_t YLen)
; {
;     size_t  initialLength = YLen;
;
;     do {
;         SnP_AddByte(state, 0x01, 0);  /* Xoodyak_Down(instance, NULL, 0, 0); */
;         SnP_Permute(state);           /* Xoodyak_Up(instance, Y, Xoodyak_Rhash, 0); */
;         SnP_ExtractBytes(state, Y, 0, Xoodyak_Rhash);
;         Y    += Xoodyak_Rhash;
;         YLen -= Xoodyak_Rhash;
;     } while (YLen >= Xoodyak_Rhash);
;
;     return initialLength - YLen;
; }
;
    EXPORT  Xoodyak_SqueezeHashFullBlocks
Xoodyak_SqueezeHashFullBlocks   PROC
    push        {r4,lr}
    vpush       {q4-q7}
    vmov.i32    d12, #1
    vshr.u64    d12, d12, #32
    mov         r3, r1                      ; r3 Y
    mov         r4, r1                      ; r4 initial Y
    vldmia      r0, {q0-q2}               ; get state
    subs        r2, r2, #Xoodyak_Rhash
Xoodyak_SqueezeHashFullBlocks_Loop
    veor.32     d0, d0, d12
    bl          Xoodoo_Permute_12roundsAsm
    vst1.32     {q0}, [r3]!                ; save Y Xoodyak_Rhash bytes
    subs        r2, r2, #Xoodyak_Rhash
    bcs         Xoodyak_SqueezeHashFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r3, r4
    vpop        {q4-q7}
    pop         {r4,pc}
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_EncryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
; {
;     size_t  initialLength = IOLen;
;
;     do {
;         SnP_Permute(state);
;         SnP_ExtractAndAddBytes(state, I, O, 0, Xoodyak_Rkout);
;         SnP_OverwriteBytes(state, O, 0, Xoodyak_Rkout);
;         SnP_AddByte(state, 0x01, Xoodyak_Rkout);
;         I       += Xoodyak_Rkout;
;         O       += Xoodyak_Rkout;
;         IOLen   -= Xoodyak_Rkout;
;     } while (IOLen >= Xoodyak_Rkout);
;
;     return initialLength - IOLen;
; }
;
    EXPORT  Xoodyak_EncryptFullBlocks
Xoodyak_EncryptFullBlocks   PROC
    push        {r4-r6,lr}
    vpush       {q4-q7}
    mov         r4, r1                      ; r4 I
    vmov.i32    d13, #1
    vshr.u64    d13, d13, #32
    mov         r5, r1                      ; r5 initial I
    vldmia      r0, {q0-q2}               ; get state
    subs        r3, r3, #Xoodyak_Rkout
Xoodyak_EncryptFullBlocks_Loop
    bl          Xoodoo_Permute_12roundsAsm
    vld1.32     {q3}, [r4]!                ; get input
    vld1.32     {d12}, [r4]!
    veor.32     q0, q0, q3
    veor.32     q1, q1, q6
    vst1.32     {q0}, [r2]!
    subs        r3, r3, #Xoodyak_Rkout
    vst1.32     {d2}, [r2]!
    bcs         Xoodyak_EncryptFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r4, r5
    vpop        {q4-q7}
    pop         {r4-r6,pc}
    align       8
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_DecryptFullBlocks(Xoodoo_align128plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
; {
;     size_t  initialLength = IOLen;
;
;     do {
;         SnP_Permute(state);
;         SnP_ExtractAndAddBytes(state, I, O, 0, Xoodyak_Rkout);
;         SnP_AddBytes(state, O, 0, Xoodyak_Rkout);
;         SnP_AddByte(state, 0x01, Xoodyak_Rkout);
;         I       += Xoodyak_Rkout;
;         O       += Xoodyak_Rkout;
;         IOLen   -= Xoodyak_Rkout;
;     } while (IOLen >= Xoodyak_Rkout);
;
;     return initialLength - IOLen;
; }
;
    EXPORT  Xoodyak_DecryptFullBlocks
Xoodyak_DecryptFullBlocks   PROC
    push        {r4-r6,lr}
    vpush       {q4-q7}
    mov         r4, r1                      ; r4 I
    vmov.i32    d13, #1
    mov         r5, r1                      ; r5 initial I
    vshr.u64    d13, d13, #32
    subs        r3, r3, #Xoodyak_Rkout
    vldmia      r0, {q0-q2}               ; get state
Xoodyak_DecryptFullBlocks_Loop
    bl          Xoodoo_Permute_12roundsAsm
    vld1.32     {q3}, [r4]!                ; get input
    vld1.32     {d12}, [r4]!
    veor.32     q0, q0, q3
    veor.32     q1, q1, q6
    vst1.32     {q0}, [r2]!
    vst1.32     {d2}, [r2]!
    vmov        q0, q3
    subs        r3, r3, #Xoodyak_Rkout
    vmov        d2, d12
    bcs         Xoodyak_DecryptFullBlocks_Loop
    vstmia      r0, {q0-q2}               ; save state
    sub         r0, r4, r5
    vpop        {q4-q7}
    pop         {r4-r6,pc}
    align       8
    ENDP

    END
