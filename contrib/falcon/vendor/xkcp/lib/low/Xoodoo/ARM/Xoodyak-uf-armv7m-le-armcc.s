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

; WARNING: These functions work only on little endian CPU with ARMv7m architecture (Cortex-M3, ...).

        PRESERVE8
        THUMB
        AREA    |.text|, CODE, READONLY


; ----------------------------------------------------------------------------

_r0     equ 5
_r1     equ 14
_t3     equ 1

_w1     equ 11

_e0     equ 2
_e1     equ 8

_rc12   equ 0x00000058
_rc11   equ 0x00000038
_rc10   equ 0x000003C0
_rc9    equ 0x000000D0
_rc8    equ 0x00000120
_rc7    equ 0x00000014
_rc6    equ 0x00000060
_rc5    equ 0x0000002C
_rc4    equ 0x00000380
_rc3    equ 0x000000F0
_rc2    equ 0x000001A0
_rc1    equ 0x00000012

_rc6x1  equ 0x00000003
_rc5x2  equ 0x0b000000
_rc4x3  equ 0x07000000
_rc3x4  equ 0x000f0000
_rc2x5  equ 0x0000d000
_rc1x6  equ 0x00000048

_rc12x1 equ 0xc0000002
_rc11x2 equ 0x0e000000
_rc10x3 equ 0x07800000
_rc9x4  equ 0x000d0000
_rc8x5  equ 0x00009000
_rc7x6  equ 0x00000050
_rc6x7  equ 0x0000000c
_rc5x8  equ 0x2c000000
_rc4x9  equ 0x1c000000
_rc3x10 equ 0x003c0000
_rc2x11 equ 0x00034000
_rc1x12 equ 0x00000120

; ----------------------------------------------------------------------------

    MACRO
    mXor3   $ro, $a0, $a1, $a2, $rho_e1, $rho_e2
    if (($rho_e1)%32) == 0
    eors    $ro, $a0, $a1
    else
    eor     $ro, $a0, $a1, ROR #(32-($rho_e1))%32
    endif
    if (($rho_e2)%32) == 0
    eors    $ro, $ro, $a2
    else
    eor     $ro, $ro, $a2, ROR #(32-($rho_e2))%32
    endif
    MEND

    MACRO
    mRliXor $ro, $ri, $rot
    if (($rot)%32) == 0
    eors    $ro, $ro, $ri
    else
    eor     $ro, $ro, $ri, ROR #(32-($rot))%32
    endif
    MEND

    MACRO
    mRloXor $ro, $ri, $rot
    if (($rot)%32) == 0
    eors    $ro, $ro, $ri
    else
    eor     $ro, $ri, $ro, ROR #(32-($rot))%32
    endif
    MEND

    MACRO
    mChi3   $a0,$a1,$a2,$r0,$r1
    bic     $r0, $a2, $a1, ROR #_w1
    eors    $a0, $a0, $r0, ROR #32-_w1
    bic     $r1, $a0, $a2, ROR #32-_w1
    eors    $a1, $a1, $r1
    bic     $r1, $a1, $a0
    eors    $a2, $a2, $r1, ROR #_w1
    MEND

    MACRO
    mRound  $r6i, $r7i, $r8i, $r9i, $r6w, $r7w, $r8w, $r9w, $r10i, $r11i, $r12i, $lri, $rho_e1, $rho_we2, $rc

    ; Theta: Column Parity Mixer (with late Rho-west, Rho-east bit rotations)
    mXor3   r0, r5, $r9i, $lri, $rho_e1, $rho_we2
    mXor3   r1, r2, $r6i, $r10i, $rho_e1, $rho_we2
    mRliXor r0, r0, _r1-_r0
    mRloXor r2, r0, 32-_r0
    mRloXor $r6i, r0, $rho_e1-_r0
    mRloXor $r10i, r0, $rho_we2-_r0

    mXor3   r0, r3, $r7i, $r11i, $rho_e1, $rho_we2
    mRliXor r1, r1, _r1-_r0
    mRloXor r3, r1, 32-_r0
    mRloXor $r7i, r1, $rho_e1-_r0
    mRloXor $r11i, r1, $rho_we2-_r0

    mXor3   r1, r4, $r8i, $r12i, $rho_e1, $rho_we2
    mRliXor r0, r0, _r1-_r0
    mRloXor r4, r0, 32-_r0
    mRloXor $r8i, r0, $rho_e1-_r0
    mRloXor $r12i, r0, $rho_we2-_r0

    mRliXor r1, r1, _r1-_r0
    mRloXor r5, r1, 32-_r0
    mRloXor $r9i, r1, $rho_e1-_r0
    mRloXor $lri, r1, $rho_we2-_r0
    ; After Theta the whole state is rotated -r0
    ; from here we must use a1.w instead of a1.i

    ; Iota: round constant
    if      $rc == 0xc0000002
    eor     r2, r2, #0x00000002
    eor     r2, r2, #0xc0000000
    else
    eor     r2, r2, #$rc
    endif

    ; Chi: non linear step, on colums
    mChi3   r2, $r6w, $r10i, r0, r1
    mChi3   r3, $r7w, $r11i, r0, r1
    mChi3   r4, $r8w, $r12i, r0, r1
    mChi3   r5, $r9w, $lri, r0, r1
    MEND

offsetInstance        equ    0
offsetInitialLen    equ    16
offsetReturn        equ    20

; ----------------------------------------------------------------------------
;
;  Xoodoo_Permute_12roundsAsm: only callable from asm
;
Xoodoo_Permute_12roundsAsm   PROC
    mRound  r6, r7, r8, r9,    r9, r6, r7, r8,    r10, r11, r12, lr,   32,      32, _rc12x1
    mRound  r9, r6, r7, r8,    r8, r9, r6, r7,    r12, lr, r10, r11,    1, _e1+_w1, _rc11x2
    mRound  r8, r9, r6, r7,    r7, r8, r9, r6,    r10, r11, r12, lr,    1, _e1+_w1, _rc10x3
    mRound  r7, r8, r9, r6,    r6, r7, r8, r9,    r12, lr, r10, r11,    1, _e1+_w1, _rc9x4
    mRound  r6, r7, r8, r9,    r9, r6, r7, r8,    r10, r11, r12, lr,    1, _e1+_w1, _rc8x5
    mRound  r9, r6, r7, r8,    r8, r9, r6, r7,    r12, lr, r10, r11,    1, _e1+_w1, _rc7x6
    mRound  r8, r9, r6, r7,    r7, r8, r9, r6,    r10, r11, r12, lr,    1, _e1+_w1, _rc6x7
    mRound  r7, r8, r9, r6,    r6, r7, r8, r9,    r12, lr, r10, r11,    1, _e1+_w1, _rc5x8
    mRound  r6, r7, r8, r9,    r9, r6, r7, r8,    r10, r11, r12, lr,    1, _e1+_w1, _rc4x9
    mRound  r9, r6, r7, r8,    r8, r9, r6, r7,    r12, lr, r10, r11,    1, _e1+_w1, _rc3x10
    mRound  r8, r9, r6, r7,    r7, r8, r9, r6,    r10, r11, r12, lr,    1, _e1+_w1, _rc2x11
    mRound  r7, r8, r9, r6,    r6, r7, r8, r9,    r12, lr, r10, r11,    1, _e1+_w1, _rc1x12
    ror     r2, r2, #32-(12*_r0)%32
    ror     r3, r3, #32-(12*_r0)%32
    ror     r4, r4, #32-(12*_r0)%32
    ror     r5, r5, #32-(12*_r0)%32
    ror     r6, r6, #32-(12*_r0+1)%32
    ror     r7, r7, #32-(12*_r0+1)%32
    ror     r8, r8, #32-(12*_r0+1)%32
    ror     r9, r9, #32-(12*_r0+1)%32
    ror     r10, r10, #32-(12*_r0+_e1+_w1)%32
    ror     r11, r11, #32-(12*_r0+_e1+_w1)%32
    ror     r12, r12, #32-(12*_r0+_e1+_w1)%32
    ror     lr, lr, #32-(12*_r0+_e1+_w1)%32
    ldr     pc, [sp, #offsetReturn]
    align   4
    ENDP


; ----------------------------------------------------------------------------
;
; size_t Xoodyak_AbsorbKeyedFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen)
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
offsetAbsorbX           equ    4
offsetAbsorbXLen        equ    8

    EXPORT  Xoodyak_AbsorbKeyedFullBlocks
Xoodyak_AbsorbKeyedFullBlocks   PROC
    push    {r4-r12,lr}
    mov     r4, r2                    ; r4 initialLength
    subs    r2, r2, #44
    ldr     r5, =Xoodyak_AbsorbKeyedFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_AbsorbKeyedFullBlocks_Loop
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_AbsorbKeyedFullBlocks_Ret
    ldr     r0, [sp, #offsetAbsorbX]
    ldr     r1, [r0], #4
    eors    r2, r2, r1
    ldr     r1, [r0], #4
    eors    r3, r3, r1
    ldr     r1, [r0], #4
    eors    r4, r4, r1
    ldr     r1, [r0], #4
    eors    r5, r5, r1
    ldr     r1, [r0], #4
    eors    r6, r6, r1
    ldr     r1, [r0], #4
    eors    r7, r7, r1
    ldr     r1, [r0], #4
    eors    r8, r8, r1
    ldr     r1, [r0], #4
    eors    r9, r9, r1
    ldr     r1, [r0], #4
    eors    r10, r10, r1
    ldr     r1, [r0], #4
    eors    r11, r11, r1
    ldr     r1, [r0], #4
    eors    lr, lr, #1
    eors    r12, r12, r1
    ldr     r1, [sp, #offsetAbsorbXLen]
    str     r0, [sp, #offsetAbsorbX]
    subs    r1, r1, #44
    str     r1, [sp, #offsetAbsorbXLen]
    bcs     Xoodyak_AbsorbKeyedFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r2, r2, #44
    sub     r0, r4, r2
    pop     {r4-r12,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_AbsorbHashFullBlocks(Xoodoo_plain32_state *state, const uint8_t *X, size_t XLen)
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
    push    {r4-r12,lr}
    mov     r4, r2                    ; r4 initialLength
    subs    r2, r2, #16
    ldr     r5, =Xoodyak_AbsorbHashFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_AbsorbHashFullBlocks_Loop
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_AbsorbHashFullBlocks_Ret
    ldr     r0, [sp, #offsetAbsorbX]
    ldr     r1, [r0], #4
    eors    r2, r2, r1
    ldr     r1, [r0], #4
    eors    r3, r3, r1
    ldr     r1, [r0], #4
    eors    r4, r4, r1
    ldr     r1, [r0], #4
    eors    r6, r6, #1
    eors    r5, r5, r1
    ldr     r1, [sp, #offsetAbsorbXLen]
    str     r0, [sp, #offsetAbsorbX]
    subs    r1, r1, #16
    str     r1, [sp, #offsetAbsorbXLen]
    bcs     Xoodyak_AbsorbHashFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r2, r2, #16
    sub     r0, r4, r2
    pop     {r4-r12,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_SqueezeKeyedFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen)
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
offsetSqueezeY          equ    4
offsetSqueezeYLen       equ    8

    EXPORT  Xoodyak_SqueezeKeyedFullBlocks
Xoodyak_SqueezeKeyedFullBlocks   PROC
    push    {r4-r12,lr}
    mov     r4, r2                    ; r4 initialLength
    subs    r2, r2, #24
    ldr     r5, =Xoodyak_SqueezeKeyedFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_SqueezeKeyedFullBlocks_Loop
    eors    r2, r2, #1
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_SqueezeKeyedFullBlocks_Ret
    ldr     r0, [sp, #offsetSqueezeY]
    str     r2, [r0], #4
    str     r3, [r0], #4
    str     r4, [r0], #4
    str     r5, [r0], #4
    str     r6, [r0], #4
    str     r7, [r0], #4
    ldr     r1, [sp, #offsetSqueezeYLen]
    str     r0, [sp, #offsetSqueezeY]
    subs    r1, r1, #24
    str     r1, [sp, #offsetSqueezeYLen]
    bcs     Xoodyak_SqueezeKeyedFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r2, r2, #24
    sub     r0, r4, r2
    pop     {r4-r12,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_SqueezeHashFullBlocks(Xoodoo_plain32_state *state, uint8_t *Y, size_t YLen)
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
    push    {r4-r12,lr}
    mov     r4, r2                    ; r4 initialLength
    subs    r2, r2, #16
    ldr     r5, =Xoodyak_SqueezeHashFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_SqueezeHashFullBlocks_Loop
    eors    r2, r2, #1
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_SqueezeHashFullBlocks_Ret
    ldr     r0, [sp, #offsetSqueezeY]
    str     r2, [r0], #4
    str     r3, [r0], #4
    str     r4, [r0], #4
    str     r5, [r0], #4
    ldr     r1, [sp, #offsetSqueezeYLen]
    str     r0, [sp, #offsetSqueezeY]
    subs    r1, r1, #16
    str     r1, [sp, #offsetSqueezeYLen]
    bcs     Xoodyak_SqueezeHashFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r2, r2, #16
    sub     r0, r4, r2
    pop     {r4-r12,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_EncryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
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
offsetCryptI            equ    4+8
offsetCryptO            equ    8+8
offsetCryptIOLen        equ    12

    EXPORT  Xoodyak_EncryptFullBlocks
Xoodyak_EncryptFullBlocks   PROC
    push    {r4-r12,lr}
    mov     r4, r3                    ; r4 initialLength
    subs    r3, r3, #24
    ldr     r5, =Xoodyak_EncryptFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_EncryptFullBlocks_Loop
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_EncryptFullBlocks_Ret
    push    {r10, r11}
    ldr     r11, [sp, #offsetCryptI]
    ldr     r10, [sp, #offsetCryptO]
    ldr     r0, [r11], #4
    ldr     r1, [r11], #4
    eors    r2, r2, r0
    str     r2, [r10], #4
    eors    r3, r3, r1
    ldr     r0, [r11], #4
    str     r3, [r10], #4
    eors    r4, r4, r0
    ldr     r1, [r11], #4
    str     r4, [r10], #4
    eors    r5, r5, r1
    ldr     r0, [r11], #4
    str     r5, [r10], #4
    eors    r6, r6, r0
    ldr     r1, [r11], #4
    str     r6, [r10], #4
    eors    r7, r7, r1
    str     r7, [r10], #4
    str     r10, [sp, #offsetCryptO]
    str     r11, [sp, #offsetCryptI]
    pop     {r10, r11}
    ldr     r0, [sp, #offsetCryptIOLen]
    eors    r8, r8, #1
    subs    r0, r0, #24
    str     r0, [sp, #offsetCryptIOLen]
    bcs     Xoodyak_EncryptFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r3, r3, #24
    sub     r0, r4, r3
    pop     {r4-r12,pc}
    align   4
    ENDP

; ----------------------------------------------------------------------------
;
; size_t Xoodyak_DecryptFullBlocks(Xoodoo_plain32_state *state, const uint8_t *I, uint8_t *O, size_t IOLen)
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
    push    {r4-r12,lr}
    mov     r4, r3                    ; r4 initialLength
    subs    r3, r3, #24
    ldr     r5, =Xoodyak_DecryptFullBlocks_Ret+1
    push    {r0-r5}
    ldmia   r0, {r2-r12,lr}    
Xoodyak_DecryptFullBlocks_Loop
    b.w     Xoodoo_Permute_12roundsAsm
Xoodyak_DecryptFullBlocks_Ret
    push    {r10, r11}
    ldr     r11, [sp, #offsetCryptI]
    ldr     r10, [sp, #offsetCryptO]
    ldr     r0, [r11], #4
    ldr     r1, [r11], #4
    eors    r2, r2, r0
    str     r2, [r10], #4
    mov     r2, r0
    eors    r3, r3, r1
    ldr     r0, [r11], #4
    str     r3, [r10], #4
    mov     r3, r1
    eors    r4, r4, r0
    ldr     r1, [r11], #4
    str     r4, [r10], #4
    mov     r4, r0
    eors    r5, r5, r1
    ldr     r0, [r11], #4
    str     r5, [r10], #4
    mov     r5, r1
    eors    r6, r6, r0
    ldr     r1, [r11], #4
    str     r6, [r10], #4
    mov     r6, r0
    eors    r7, r7, r1
    str     r7, [r10], #4
    mov     r7, r1
    str     r10, [sp, #offsetCryptO]
    str     r11, [sp, #offsetCryptI]
    pop     {r10, r11}
    ldr     r0, [sp, #offsetCryptIOLen]
    eors    r8, r8, #1
    subs    r0, r0, #24
    str     r0, [sp, #offsetCryptIOLen]
    bcs     Xoodyak_DecryptFullBlocks_Loop
    ldr     r0, [sp, #offsetInstance]
    stmia   r0, {r2-r12,lr}    
    pop     {r0-r5}
    adds    r3, r3, #24
    sub     r0, r4, r3
    pop     {r4-r12,pc}
    align   4
    ENDP

    END
