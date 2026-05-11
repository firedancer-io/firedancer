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

; WARNING: These functions work only on little endian CPU with ARMv6m architecture (e.g., Cortex-M0).

        PRESERVE8
        THUMB
        AREA    |.text|, CODE, READONLY

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
    mLoadU  $r, $p, $o, $t
    ldrb    $r, [$p, #$o+0]
    ldrb    $t, [$p, #$o+1]
    lsls    $t, $t, #8
    orrs    $r, $r, $t
    ldrb    $t, [$p, #$o+2]
    lsls    $t, $t, #16
    orrs    $r, $r, $t
    ldrb    $t, [$p, #$o+3]
    lsls    $t, $t, #24
    orrs    $r, $r, $t
    MEND

    MACRO
    mStoreU $p, $o, $s, $t, $loc
    if $loc == locRegL
    strb    $s, [$p, #$o+0]
    lsrs    $t, $s, #8
    else
    mov     $t, $s
    strb    $t, [$p, #$o+0]
    lsrs    $t, $t, #8
    endif
    strb    $t, [$p, #$o+1]
    lsrs    $t, $t, #8
    strb    $t, [$p, #$o+2]
    lsrs    $t, $t, #8
    strb    $t, [$p, #$o+3]
    MEND

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
; Xoodoo_Permute_12roundsAsm
;  

; offsets on stack
Xoodoo_Permute_12rounds_offsetA03    equ 0
Xoodoo_Permute_12rounds_offsetRC     equ 4
Xoodoo_Permute_12rounds_offsetReturn equ 8
Xoodoo_Permute_12rounds_SAS          equ 12

    align   4
Xoodoo_Permute_12roundsAsm   PROC
    adr     r2, Xoodoo_Permute_RoundConstants12
    str     r2, [sp, #Xoodoo_Permute_12rounds_offsetRC]
Xoodoo_Permute_12rounds_Loop
    mRound  Xoodoo_Permute_12rounds_offsetRC, Xoodoo_Permute_12rounds_offsetA03
    ldr     r0, [sp, #Xoodoo_Permute_12rounds_offsetRC]
    ldr     r0, [r0]
    cmp     r0, #0
    beq     Xoodoo_Permute_12rounds_Done
    b       Xoodoo_Permute_12rounds_Loop
Xoodoo_Permute_12rounds_Done
    ldr     r0, [sp, #Xoodoo_Permute_12rounds_offsetReturn]
    bx      r0
    align   4
Xoodoo_Permute_RoundConstants12
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
    dcd     0
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
;     return initialLength - XLen;
; }
;
XoodyakAbsorb_offsetState           equ (Xoodoo_Permute_12rounds_SAS+0)
XoodyakAbsorb_offsetX               equ (Xoodoo_Permute_12rounds_SAS+4)
XoodyakAbsorb_offsetXLen            equ (Xoodoo_Permute_12rounds_SAS+8)
XoodyakAbsorb_offsetInitialLen      equ (Xoodoo_Permute_12rounds_SAS+12)

XoodyakAbsorb_SAS                   equ (Xoodoo_Permute_12rounds_SAS+20)

    align   4
    EXPORT  Xoodyak_AbsorbKeyedFullBlocks
Xoodyak_AbsorbKeyedFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakAbsorb_SAS
    str     r0, [sp, #XoodyakAbsorb_offsetState]            ; setup variables on stack
    str     r1, [sp, #XoodyakAbsorb_offsetX]
    str     r2, [sp, #XoodyakAbsorb_offsetInitialLen]
    subs    r2, r2, #44
    str     r2, [sp, #XoodyakAbsorb_offsetXLen]
    ldr     r5, =Xoodyak_AbsorbKeyedFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                          ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_AbsorbKeyedFullBlocks_Loop
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_AbsorbKeyedFullBlocks_Ret
    ldr     r0, [sp, #XoodyakAbsorb_offsetX]
    lsls    r1, r0, #30
    bne     Xoodyak_AbsorbKeyedFullBlocks_Unaligned
Xoodyak_AbsorbKeyedFullBlocks_Aligned
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
    ldr     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]

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

    ldmia   r0!, {r1}
    eors    r4, r4, r1
    ldmia   r0!, {r1}
    eors    r5, r5, r1
    ldmia   r0!, {r1}
    eors    r6, r6, r1
Xoodyak_AbsorbKeyedFullBlocks_EndLoop
    str     r0, [sp, #XoodyakAbsorb_offsetX]
    movs    r2, #1
    eors    r7, r7, r2
    ldr     r1, [sp, #XoodyakAbsorb_offsetXLen]
    subs    r1, r1, #44
    str     r1, [sp, #XoodyakAbsorb_offsetXLen]
    bcs     Xoodyak_AbsorbKeyedFullBlocks_Loop
    ldr     r0, [sp, #XoodyakAbsorb_offsetState]
    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    
    ldr     r0, [sp, #XoodyakAbsorb_offsetInitialLen]
    ldr     r2, [sp, #XoodyakAbsorb_offsetXLen]
    adds    r2, r2, #44
    subs    r0, r0, r2

    add     sp, #XoodyakAbsorb_SAS
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_AbsorbKeyedFullBlocks_Unaligned
    mLoadU  r1, r0, 0, r2
    eors    r3, r3, r1

    mLoadU  r1, r0, 4, r2
    mov     r2, r8
    eors    r2, r2, r1
    mov     r8, r2

    mLoadU  r1, r0, 8, r2
    mov     r2, r9
    eors    r2, r2, r1
    mov     r9, r2

    mLoadU  r1, r0, 12, r2
    ldr     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]

    mLoadU  r1, r0, 16, r2
    mov     r2, r10
    eors    r2, r2, r1
    mov     r10, r2

    mLoadU  r1, r0, 20, r2
    mov     r2, r11
    eors    r2, r2, r1
    mov     r11, r2

    mLoadU  r1, r0, 24, r2
    mov     r2, r12
    eors    r2, r2, r1
    mov     r12, r2

    mLoadU  r1, r0, 28, r2
    mov     r2, lr
    eors    r2, r2, r1
    mov     lr, r2

    adds    r0, r0, #32
    mLoadU  r1, r0, 0, r2
    eors    r4, r4, r1
    mLoadU  r1, r0, 4, r2
    eors    r5, r5, r1
    mLoadU  r1, r0, 8, r2
    eors    r6, r6, r1
    adds    r0, r0, #12
    b       Xoodyak_AbsorbKeyedFullBlocks_EndLoop
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
;     return initialLength - XLen;
; }
;
    align   4
    EXPORT  Xoodyak_AbsorbHashFullBlocks
Xoodyak_AbsorbHashFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakAbsorb_SAS
    str     r0, [sp, #XoodyakAbsorb_offsetState]            ; setup variables on stack
    str     r1, [sp, #XoodyakAbsorb_offsetX]
    str     r2, [sp, #XoodyakAbsorb_offsetInitialLen]
    subs    r2, r2, #16
    str     r2, [sp, #XoodyakAbsorb_offsetXLen]
    ldr     r5, =Xoodyak_AbsorbHashFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                          ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_AbsorbHashFullBlocks_Loop
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_AbsorbHashFullBlocks_Ret
    ldr     r0, [sp, #XoodyakAbsorb_offsetX]
    lsls    r1, r0, #30
    bne     Xoodyak_AbsorbHashFullBlocks_Unaligned
Xoodyak_AbsorbHashFullBlocks_Aligned
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
    ldr     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
Xoodyak_AbsorbHashFullBlocks_EndLoop
    str     r0, [sp, #XoodyakAbsorb_offsetX]
    movs    r2, #1
    mov     r1, r10
    eors    r1, r1, r2
    mov     r10, r1
    ldr     r1, [sp, #XoodyakAbsorb_offsetXLen]
    subs    r1, r1, #16
    str     r1, [sp, #XoodyakAbsorb_offsetXLen]
    bcs     Xoodyak_AbsorbHashFullBlocks_Loop
    ldr     r0, [sp, #XoodyakAbsorb_offsetState]

    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    
    ldr     r0, [sp, #XoodyakAbsorb_offsetInitialLen]
    ldr     r2, [sp, #XoodyakAbsorb_offsetXLen]
    adds    r2, r2, #16
    subs    r0, r0, r2

    add     sp, #XoodyakAbsorb_SAS
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_AbsorbHashFullBlocks_Unaligned
    mLoadU  r1, r0, 0, r2
    eors    r3, r3, r1
    mLoadU  r1, r0, 4, r2
    mov     r2, r8
    eors    r2, r2, r1
    mov     r8, r2
    mLoadU  r1, r0, 8, r2
    mov     r2, r9
    eors    r2, r2, r1
    mov     r9, r2
    mLoadU  r1, r0, 12, r2
    ldr     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    eors    r2, r2, r1
    str     r2, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    adds    r0, r0, #16
    b       Xoodyak_AbsorbHashFullBlocks_EndLoop
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
;     return initialLength - YLen;
; }
;
XoodyakSqueeze_offsetState            equ    (Xoodoo_Permute_12rounds_SAS+0)
XoodyakSqueeze_offsetY                equ    (Xoodoo_Permute_12rounds_SAS+4)
XoodyakSqueeze_offsetYLen            equ    (Xoodoo_Permute_12rounds_SAS+8)
XoodyakSqueeze_offsetInitialLen        equ    (Xoodoo_Permute_12rounds_SAS+12)

XoodyakSqueeze_SAS                      equ (Xoodoo_Permute_12rounds_SAS+20)

    align   4
    EXPORT  Xoodyak_SqueezeKeyedFullBlocks
Xoodyak_SqueezeKeyedFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakSqueeze_SAS
    str     r0, [sp, #XoodyakSqueeze_offsetState]        ; setup variables on stack
    str     r1, [sp, #XoodyakSqueeze_offsetY]
    str     r2, [sp, #XoodyakSqueeze_offsetInitialLen]
    subs    r2, r2, #24
    str     r2, [sp, #XoodyakSqueeze_offsetYLen]
    ldr     r5, =Xoodyak_SqueezeKeyedFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                            ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_SqueezeKeyedFullBlocks_Loop
    movs    r0, #1
    eors    r3, r3, r0
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_SqueezeKeyedFullBlocks_Ret
    ldr     r0, [sp, #XoodyakSqueeze_offsetY]
    lsls    r1, r0, #30
    bne     Xoodyak_SqueezeKeyedFullBlocks_Unaligned
Xoodyak_SqueezeKeyedFullBlocks_Aligned
    stmia   r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    stmia   r0!, {r1, r2}
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    mov     r2, r10
    stmia   r0!, {r1, r2}
    mov     r1, r11
    stmia   r0!, {r1}
Xoodyak_SqueezeKeyedFullBlocks_EndLoop
    str     r0, [sp, #XoodyakSqueeze_offsetY]
    ldr     r1, [sp, #XoodyakSqueeze_offsetYLen]
    subs    r1, r1, #24
    str     r1, [sp, #XoodyakSqueeze_offsetYLen]
    bcs     Xoodyak_SqueezeKeyedFullBlocks_Loop
    ldr     r0, [sp, #XoodyakSqueeze_offsetState]           ; Save state
    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    ldr     r0, [sp, #XoodyakSqueeze_offsetInitialLen]      ; Compute processed length
    ldr     r2, [sp, #XoodyakSqueeze_offsetYLen]
    adds    r2, r2, #24
    subs    r0, r0, r2
    add     sp, #XoodyakSqueeze_SAS                         ; Free stack and pop
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_SqueezeKeyedFullBlocks_Unaligned
    mStoreU r0, 0, r3, r2, locRegL
    mStoreU r0, 4, r8, r2, locRegH
    mStoreU r0, 8, r9, r2, locRegH
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    mStoreU r0, 12, r1, r2, locRegL
    mStoreU r0, 16, r10, r2, locRegH
    mStoreU r0, 20, r11, r2, locRegH
    adds    r0, r0, #24
    b       Xoodyak_SqueezeKeyedFullBlocks_EndLoop
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
;     return initialLength - YLen;
; }
;
    align   4
    EXPORT  Xoodyak_SqueezeHashFullBlocks
Xoodyak_SqueezeHashFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakSqueeze_SAS
    str     r0, [sp, #XoodyakSqueeze_offsetState]        ; setup variables on stack
    str     r1, [sp, #XoodyakSqueeze_offsetY]
    str     r2, [sp, #XoodyakSqueeze_offsetInitialLen]
    subs    r2, r2, #16
    str     r2, [sp, #XoodyakSqueeze_offsetYLen]
    ldr     r5, =Xoodyak_SqueezeHashFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                            ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_SqueezeHashFullBlocks_Loop
    movs    r0, #1
    eors    r3, r3, r0
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_SqueezeHashFullBlocks_Ret
    ldr     r0, [sp, #XoodyakSqueeze_offsetY]
    lsls    r1, r0, #30
    bne     Xoodyak_SqueezeHashFullBlocks_Unaligned
Xoodyak_SqueezeHashFullBlocks_Aligned
    stmia   r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    stmia   r0!, {r1, r2}
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stmia   r0!, {r1}
Xoodyak_SqueezeHashFullBlocks_EndLoop
    str     r0, [sp, #XoodyakSqueeze_offsetY]
    ldr     r1, [sp, #XoodyakSqueeze_offsetYLen]
    subs    r1, r1, #16
    str     r1, [sp, #XoodyakSqueeze_offsetYLen]
    bcs     Xoodyak_SqueezeHashFullBlocks_Loop
    ldr     r0, [sp, #XoodyakSqueeze_offsetState]                ; Save state
    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    ldr     r0, [sp, #XoodyakSqueeze_offsetInitialLen]            ; Compute processed length
    ldr     r2, [sp, #XoodyakSqueeze_offsetYLen]
    adds    r2, r2, #16
    subs    r0, r0, r2
    add     sp, #XoodyakSqueeze_SAS                                ; Free stack and pop
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_SqueezeHashFullBlocks_Unaligned
    mStoreU r0, 0, r3, r2, locRegL
    mStoreU r0, 4, r8, r2, locRegH
    mStoreU r0, 8, r9, r2, locRegH
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    mStoreU r0, 12, r1, r2, locRegL
    adds    r0, r0, #16
    b       Xoodyak_SqueezeHashFullBlocks_EndLoop
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
;     return initialLength - IOLen;
; }
;
XoodyakCrypt_offsetState            equ (Xoodoo_Permute_12rounds_SAS+0)
XoodyakCrypt_offsetI                equ (Xoodoo_Permute_12rounds_SAS+4)
XoodyakCrypt_offsetO                equ (Xoodoo_Permute_12rounds_SAS+8)
XoodyakCrypt_offsetIOLen            equ (Xoodoo_Permute_12rounds_SAS+12)
XoodyakCrypt_offsetInitialLen       equ (Xoodoo_Permute_12rounds_SAS+16)
XoodyakCrypt_SAS                    equ (Xoodoo_Permute_12rounds_SAS+20)

    align   4
    EXPORT  Xoodyak_EncryptFullBlocks
Xoodyak_EncryptFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakCrypt_SAS
    str     r0, [sp, #XoodyakCrypt_offsetState]                ; setup variables on stack
    str     r1, [sp, #XoodyakCrypt_offsetI]
    str     r2, [sp, #XoodyakCrypt_offsetO]
    str     r3, [sp, #XoodyakCrypt_offsetInitialLen]
    subs    r3, r3, #24
    str     r3, [sp, #XoodyakCrypt_offsetIOLen]
    ldr     r5, =Xoodyak_EncryptFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                            ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_EncryptFullBlocks_Loop
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_EncryptFullBlocks_Ret
    push    {r4, r5}
    ldr     r5, [sp, #XoodyakCrypt_offsetI+8]
    ldr     r4, [sp, #XoodyakCrypt_offsetO+8]
    mov     r0, r4
    ands    r0, r0, r5
    lsls    r0, r0, #30
    bne     Xoodyak_EncryptFullBlocks_Unaligned
Xoodyak_EncryptFullBlocks_Aligned
    ldmia   r5!, {r0}
    eors    r3, r3, r0
    stmia   r4!, {r3}

    ldmia   r5!, {r0}
    mov     r1, r8
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r8, r1

    ldmia   r5!, {r0}
    mov     r1, r9
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r9, r1

    ldmia   r5!, {r0}
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]
    eors    r1, r1, r0
    stmia   r4!, {r1}
    str     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]

    ldmia   r5!, {r0}
    mov     r1, r10
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r10, r1

    ldmia   r5!, {r0}
    mov     r1, r11
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r11, r1
Xoodyak_EncryptFullBlocks_EndLoop
    movs    r0, #1
    mov     r1, r12
    eors    r1, r1, r0
    mov     r12, r1
    str     r5, [sp, #XoodyakCrypt_offsetI+8]
    str     r4, [sp, #XoodyakCrypt_offsetO+8]
    pop     {r4, r5}
    ldr     r1, [sp, #XoodyakCrypt_offsetIOLen]
    subs    r1, r1, #24
    str     r1, [sp, #XoodyakCrypt_offsetIOLen]
    bcs     Xoodyak_EncryptFullBlocks_Loop
    ldr     r0, [sp, #XoodyakCrypt_offsetState]                    ; Save state
    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    ldr     r0, [sp, #XoodyakCrypt_offsetInitialLen]            ; Compute processed length
    ldr     r2, [sp, #XoodyakCrypt_offsetIOLen]
    adds    r2, r2, #24
    subs    r0, r0, r2
    add     sp, #XoodyakCrypt_SAS                                ; Free stack and pop
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_EncryptFullBlocks_Unaligned
    mLoadU  r0, r5, 0, r2
    eors    r3, r3, r0
    mStoreU r4, 0, r3, r2, locRegL

    mLoadU  r0, r5, 4, r2
    mov     r1, r8
    eors    r1, r1, r0
    mStoreU r4, 4, r1, r2, locRegL
    mov     r8, r1

    mLoadU  r0, r5, 8, r2
    mov     r1, r9
    eors    r1, r1, r0
    mStoreU r4, 8, r1, r2, locRegL
    mov     r9, r1

    mLoadU  r0, r5, 12, r2
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]
    eors    r1, r1, r0
    mStoreU r4, 12, r1, r2, locRegL
    str     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]

    mLoadU  r0, r5, 16, r2
    mov     r1, r10
    eors    r1, r1, r0
    mStoreU r4, 16, r1, r2, locRegL
    mov     r10, r1

    mLoadU  r0, r5, 20, r2
    mov     r1, r11
    eors    r1, r1, r0
    mStoreU r4, 20, r1, r2, locRegL
    mov     r11, r1

    adds    r4, r4, #24
    adds    r5, r5, #24
    b       Xoodyak_EncryptFullBlocks_EndLoop
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
;     return initialLength - IOLen;
; }
;
    align   4
    EXPORT  Xoodyak_DecryptFullBlocks
Xoodyak_DecryptFullBlocks   PROC
    push    {r3-r7,lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4-r7}

    sub     sp, #XoodyakCrypt_SAS
    str     r0, [sp, #XoodyakCrypt_offsetState]                ; setup variables on stack
    str     r1, [sp, #XoodyakCrypt_offsetI]
    str     r2, [sp, #XoodyakCrypt_offsetO]
    str     r3, [sp, #XoodyakCrypt_offsetInitialLen]
    subs    r3, r3, #24
    str     r3, [sp, #XoodyakCrypt_offsetIOLen]
    ldr     r5, =Xoodyak_DecryptFullBlocks_Ret+1
    str     r5, [sp, #Xoodoo_Permute_12rounds_offsetReturn]

    ldm     r0!, {r3,r5,r6,r7}                            ; state in registers
    mov     r8, r5
    mov     r9, r6
    str     r7, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    ldm     r0!, {r4,r5,r6,r7}
    mov     r10, r4
    mov     r11, r5
    mov     r12, r6
    mov     lr, r7
    ldm     r0!, {r4,r5,r6,r7}
Xoodyak_DecryptFullBlocks_Loop
    ldr     r0, =Xoodoo_Permute_12roundsAsm
    bx      r0
    align   4
    ltorg
Xoodyak_DecryptFullBlocks_Ret
    push    {r4, r5}
    ldr     r5, [sp, #XoodyakCrypt_offsetI+8]
    ldr     r4, [sp, #XoodyakCrypt_offsetO+8]
    mov     r0, r4
    ands    r0, r0, r5
    lsls    r0, r0, #30
    bne     Xoodyak_DecryptFullBlocks_Unaligned
Xoodyak_DecryptFullBlocks_Aligned
    ldmia   r5!, {r0}
    eors    r3, r3, r0
    stmia   r4!, {r3}
    mov     r3, r0

    ldmia   r5!, {r0}
    mov     r1, r8
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r8, r0

    ldmia   r5!, {r0}
    mov     r1, r9
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r9, r0

    ldmia   r5!, {r0}
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]
    eors    r1, r1, r0
    stmia   r4!, {r1}
    str     r0, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]

    ldmia   r5!, {r0}
    mov     r1, r10
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r10, r0

    ldmia   r5!, {r0}
    mov     r1, r11
    eors    r1, r1, r0
    stmia   r4!, {r1}
    mov     r11, r0
Xoodyak_DecryptFullBlocks_EndLoop
    movs    r0, #1
    mov     r1, r12
    eors    r1, r1, r0
    mov     r12, r1
    str     r5, [sp, #XoodyakCrypt_offsetI+8]
    str     r4, [sp, #XoodyakCrypt_offsetO+8]
    pop     {r4, r5}
    ldr     r1, [sp, #XoodyakCrypt_offsetIOLen]
    subs    r1, r1, #24
    str     r1, [sp, #XoodyakCrypt_offsetIOLen]
    bcs     Xoodyak_DecryptFullBlocks_Loop
    ldr     r0, [sp, #XoodyakCrypt_offsetState]                    ; Save state
    stm     r0!, {r3}
    mov     r1, r8
    mov     r2, r9
    ldr     r3, [sp, #Xoodoo_Permute_12rounds_offsetA03]
    stm     r0!, {r1,r2,r3}
    mov     r1, r10
    mov     r2, r11
    mov     r3, r12
    stm     r0!, {r1,r2,r3}
    mov     r1, lr
    stm     r0!, {r1,r4,r5,r6,r7}
    ldr     r0, [sp, #XoodyakCrypt_offsetInitialLen]            ; Compute processed length
    ldr     r2, [sp, #XoodyakCrypt_offsetIOLen]
    adds    r2, r2, #24
    subs    r0, r0, r2
    add     sp, #XoodyakCrypt_SAS                                ; Free stack and pop
    pop     {r4-r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r3-r7,pc}
Xoodyak_DecryptFullBlocks_Unaligned
    mLoadU  r0, r5, 0, r2
    eors    r3, r3, r0
    mStoreU r4, 0, r3, r2, locRegL
    mov     r3, r0

    mLoadU  r0, r5, 4, r2
    mov     r1, r8
    eors    r1, r1, r0
    mStoreU r4, 4, r1, r2, locRegL
    mov     r8, r0

    mLoadU  r0, r5, 8, r2
    mov     r1, r9
    eors    r1, r1, r0
    mStoreU r4, 8, r1, r2, locRegL
    mov     r9, r0

    mLoadU  r0, r5, 12, r2
    ldr     r1, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]
    eors    r1, r1, r0
    mStoreU r4, 12, r1, r2, locRegL
    str     r0, [sp, #Xoodoo_Permute_12rounds_offsetA03+8]

    mLoadU  r0, r5, 16, r2
    mov     r1, r10
    eors    r1, r1, r0
    mStoreU r4, 16, r1, r2, locRegL
    mov     r10, r0

    mLoadU  r0, r5, 20, r2
    mov     r1, r11
    eors    r1, r1, r0
    mStoreU r4, 20, r1, r2, locRegL
    mov     r11, r0

    adds    r4, r4, #24
    adds    r5, r5, #24
    b       Xoodyak_DecryptFullBlocks_EndLoop
    ENDP

    END
