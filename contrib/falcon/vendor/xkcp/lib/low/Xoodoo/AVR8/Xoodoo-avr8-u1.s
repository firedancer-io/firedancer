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
; ---
;
; This file implements Xoodoo in a SnP-compatible way.
; Please refer to SnP-documentation.h for more details.
;
; This implementation comes with Xoodoo-SnP.h in the same folder.
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
; void Xoodoo_StaticInitialize( void )
;
.global Xoodoo_StaticInitialize

;----------------------------------------------------------------------------
;
; void Xoodoo_Initialize(Xoodoo_plain8_state *state)
;
; argument state   is passed in r24:r25
;
.global Xoodoo_Initialize
Xoodoo_Initialize:
    movw    rZ, r24
    ldi     r23, 3*4/2        ; clear state (8 bytes / 2 lanes) per iteration
Xoodoo_Initialize_Loop:
    st      z+, zero
    st      z+, zero
    st      z+, zero
    st      z+, zero
    st      z+, zero
    st      z+, zero
    st      z+, zero
    st      z+, zero
    dec     r23
    brne    Xoodoo_Initialize_Loop
Xoodoo_StaticInitialize:
    ret

;----------------------------------------------------------------------------
;
; void Xoodoo_AddByte(Xoodoo_plain8_state *state, unsigned char data, unsigned int offset)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23, only LSB (r22) is used
; argument offset    is passed in r20:r21, only LSB (r20) is used
;
.global Xoodoo_AddByte
Xoodoo_AddByte:
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    ld      r0, Z
    eor     r0, r22
    st      Z, r0
    ret

;----------------------------------------------------------------------------
;
; void Xoodoo_AddBytes(Xoodoo_plain8_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global Xoodoo_AddBytes
Xoodoo_AddBytes:
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
    subi    r18, 8
    brcs    Xoodoo_AddBytes_Byte
    ;do 8 bytes per iteration
Xoodoo_AddBytes_Loop8:
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    subi    r18, 8
    brcc    Xoodoo_AddBytes_Loop8
Xoodoo_AddBytes_Byte:
    ldi     r19, 8
    add     r18, r19
    breq    Xoodoo_AddBytes_End
Xoodoo_AddBytes_Loop1:
    ld      r21, X+
    ld      r0, Z
    eor     r0, r21
    st      Z+, r0
    dec     r18
    brne    Xoodoo_AddBytes_Loop1
Xoodoo_AddBytes_End:
    ret


;----------------------------------------------------------------------------
;
; void Xoodoo_OverwriteBytes(Xoodoo_plain8_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global Xoodoo_OverwriteBytes
Xoodoo_OverwriteBytes:
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
    subi    r18, 8
    brcs    Xoodoo_OverwriteBytes_Byte
    ;do 8 bytes per iteration
Xoodoo_OverwriteBytes_Loop8:
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    ld      r0, X+
    st      Z+, r0
    subi    r18, 8
    brcc    Xoodoo_OverwriteBytes_Loop8
Xoodoo_OverwriteBytes_Byte:
    ldi     r19, 8
    add     r18, r19
    breq    Xoodoo_OverwriteBytes_End
Xoodoo_OverwriteBytes_Loop1:
    ld      r0, X+
    st      Z+, r0
    dec     r18
    brne    Xoodoo_OverwriteBytes_Loop1
Xoodoo_OverwriteBytes_End:
    ret

;----------------------------------------------------------------------------
;
; void Xoodoo_OverwriteWithZeroes(Xoodoo_plain8_state *state, unsigned int byteCount)
;
; argument state        is passed in r24:r25
; argument byteCount    is passed in r22:r23, only LSB (r22) is used
;
.global Xoodoo_OverwriteWithZeroes
Xoodoo_OverwriteWithZeroes:
    movw    rZ, r24         ; rZ = state
    mov     r23, r22
    lsr     r23
    lsr     r23
    lsr     r23
    breq    Xoodoo_OverwriteWithZeroes_Bytes
Xoodoo_OverwriteWithZeroes_LoopLanes:
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    st      Z+, r1
    dec     r23
    brne    Xoodoo_OverwriteWithZeroes_LoopLanes
Xoodoo_OverwriteWithZeroes_Bytes:
    andi    r22, 7
    breq    Xoodoo_OverwriteWithZeroes_End
Xoodoo_OverwriteWithZeroes_LoopBytes:
    st      Z+, r1
    dec     r22
    brne    Xoodoo_OverwriteWithZeroes_LoopBytes
Xoodoo_OverwriteWithZeroes_End:
    ret

;----------------------------------------------------------------------------
;
; void Xoodoo_ExtractBytes(Xoodoo_plain8_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument data      is passed in r22:r23
; argument offset    is passed in r20:r21, only LSB (r20) is used
; argument length    is passed in r18:r19, only LSB (r18) is used
;
.global Xoodoo_ExtractBytes
Xoodoo_ExtractBytes:
    movw    rZ, r24
    add     rZ, r20
    adc     rZ+1, zero
    movw    rX, r22
    subi    r18, 8
    brcs    Xoodoo_ExtractBytes_Byte
    ;do 8 bytes per iteration
Xoodoo_ExtractBytes_Loop8:
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    ld      r0, Z+
    st      X+, r0
    subi    r18, 8
    brcc    Xoodoo_ExtractBytes_Loop8
Xoodoo_ExtractBytes_Byte:
    ldi     r19, 8
    add     r18, r19
    breq    Xoodoo_ExtractBytes_End
Xoodoo_ExtractBytes_Loop1:
    ld      r0, Z+
    st      X+, r0
    dec     r18
    brne    Xoodoo_ExtractBytes_Loop1
Xoodoo_ExtractBytes_End:
    ret

;----------------------------------------------------------------------------
;
; void Xoodoo_ExtractAndAddBytes(Xoodoo_plain8_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
;
; argument state     is passed in r24:r25
; argument input     is passed in r22:r23
; argument output    is passed in r20:r21
; argument offset    is passed in r18:r19, only LSB (r18) is used
; argument length    is passed in r16:r17, only LSB (r16) is used
;
.global Xoodoo_ExtractAndAddBytes
Xoodoo_ExtractAndAddBytes:
    tst     r16
    breq    Xoodoo_ExtractAndAddBytes_End
    push    r16
    push    r28
    push    r29
    movw    rZ, r24
    add     rZ, r18
    adc     rZ+1, zero
    movw    rX, r22
    movw    rY, r20
    subi    r16, 8
    brcs    Xoodoo_ExtractAndAddBytes_Byte
Xoodoo_ExtractAndAddBytes_LoopLane:
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    subi    r16, 8
    brcc    Xoodoo_ExtractAndAddBytes_LoopLane
Xoodoo_ExtractAndAddBytes_Byte:
    ldi     r19, 8
    add     r16, r19
    breq    Xoodoo_ExtractAndAddBytes_Done
Xoodoo_ExtractAndAddBytes_Loop1:
    ld      r21, Z+
    ld      r0, X+
    eor     r0, r21
    st      Y+, r0
    dec     r16
    brne    Xoodoo_ExtractAndAddBytes_Loop1
Xoodoo_ExtractAndAddBytes_Done:
    pop     r29
    pop     r28
    pop     r16
Xoodoo_ExtractAndAddBytes_End:
    ret

Xoodoo_RoundConstants_12:
    .BYTE   0x58, 0x00
    .BYTE   0x38, 0x00
    .BYTE   0xC0, 0x03
    .BYTE   0xD0, 0x00
    .BYTE   0x20, 0x01
    .BYTE   0x14, 0x00
Xoodoo_RoundConstants_6:
    .BYTE   0x60, 0x00
    .BYTE   0x2C, 0x00
    .BYTE   0x80, 0x03
    .BYTE   0xF0, 0x00
    .BYTE   0xA0, 0x01
    .BYTE   0x12, 0x00
Xoodoo_RoundConstants_0:
    .BYTE   0xFF, 0        ; terminator

    .text

; Register variables used in permutation
#define rC0          2      // 4 regs (2-5)
#define rC1          6      // 4 regs (6-9)
#define rC2         10      // 4 regs (10-13)
#define rC3         14      // 4 regs (14-17)
#define rVv         18      // 4 regs (18-21)
#define rTt         22      // 4 regs (22-25)
// r26-27 free
#define a00          0
#define a01          4
#define a02          8
#define a03         12
#define a10         16
#define a11         20
#define a12         24
#define a13         28
#define a20         32
#define a21         36
#define a22         40
#define a23         44

;----------------------------------------------------------------------------
;
; void Xoodoo_Permute_Nrounds( Xoodoo_plain8_state *state, unsigned int nrounds )
;
; argument state     is passed in r24:r25
; argument nrounds   is passed in r22:r23 (only LSB (r22) is used)
;
.global Xoodoo_Permute_Nrounds
Xoodoo_Permute_Nrounds:
	mov		r26, r22
    ldi     rZ+0, lo8(Xoodoo_RoundConstants_0)
    ldi     rZ+1, hi8(Xoodoo_RoundConstants_0)
	lsl		r26
    sub     rZ, r26
    sbc     rZ+1, zero
    rjmp    Xoodoo_Permute

;----------------------------------------------------------------------------
;
; void Xoodoo_Permute_6rounds( Xoodoo_plain8_state *state )
;
; argument state     is passed in r24:r25
;
.global Xoodoo_Permute_6rounds
Xoodoo_Permute_6rounds:
    ldi     rZ+0, lo8(Xoodoo_RoundConstants_6)
    ldi     rZ+1, hi8(Xoodoo_RoundConstants_6)
    rjmp    Xoodoo_Permute

;----------------------------------------------------------------------------
;
; void Xoodoo_Permute_12rounds( Xoodoo_plain8_state *state )
;
; argument state     is passed in r24:r25
;
.global Xoodoo_Permute_12rounds
Xoodoo_Permute_12rounds:
    ldi     rZ+0, lo8(Xoodoo_RoundConstants_12)
    ldi     rZ+1, hi8(Xoodoo_RoundConstants_12)
Xoodoo_Permute:
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

    ; Initial Prepare Theta
    movw    rY, rpState
    ld      rC0+0, Y+          ; a00
    ld      rC0+1, Y+
    ld      rC0+2, Y+
    ld      rC0+3, Y+
    ld      rC1+0, Y+          ; a01
    ld      rC1+1, Y+
    ld      rC1+2, Y+
    ld      rC1+3, Y+
    ld      rC2+0, Y+          ; a02
    ld      rC2+1, Y+
    ld      rC2+2, Y+
    ld      rC2+3, Y+
    ld      rC3+0, Y+          ; a03
    ld      rC3+1, Y+
    ld      rC3+2, Y+
    ld      rC3+3, Y+

    ld      r0, Y+             ; a10
    eor     rC0+0, r0
    ld      r0, Y+
    eor     rC0+1, r0
    ld      r0, Y+
    eor     rC0+2, r0
    ld      r0, Y+
    eor     rC0+3, r0
    ld      r0, Y+             ; a11
    eor     rC1+0, r0
    ld      r0, Y+
    eor     rC1+1, r0
    ld      r0, Y+
    eor     rC1+2, r0
    ld      r0, Y+
    eor     rC1+3, r0
    ld      r0, Y+             ; a12
    eor     rC2+0, r0
    ld      r0, Y+
    eor     rC2+1, r0
    ld      r0, Y+
    eor     rC2+2, r0
    ld      r0, Y+
    eor     rC2+3, r0
    ld      r0, Y+             ; a13
    eor     rC3+0, r0
    ld      r0, Y+
    eor     rC3+1, r0
    ld      r0, Y+
    eor     rC3+2, r0
    ld      r0, Y+
    eor     rC3+3, r0

    ld      r0, Y+             ; a20
    eor     rC0+0, r0
    ld      r0, Y+
    eor     rC0+1, r0
    ld      r0, Y+
    eor     rC0+2, r0
    ld      r0, Y+
    eor     rC0+3, r0
    ld      r0, Y+             ; a21
    eor     rC1+0, r0
    ld      r0, Y+
    eor     rC1+1, r0
    ld      r0, Y+
    eor     rC1+2, r0
    ld      r0, Y+
    eor     rC1+3, r0
    ld      r0, Y+             ; a22
    eor     rC2+0, r0
    ld      r0, Y+
    eor     rC2+1, r0
    ld      r0, Y+
    eor     rC2+2, r0
    ld      r0, Y+
    eor     rC2+3, r0
    ld      r0, Y+             ; a23
    eor     rC3+0, r0
    ld      r0, Y+
    eor     rC3+1, r0
    ld      r0, Y+
    eor     rC3+2, r0
    ld      r0, Y+
    eor     rC3+3, r0
	sbiw    rY, 48

Xoodoo_RoundLoop:
    ; Theta + Rho west
    ; c0 = ROTL32(c0 ^ ROTL32(c0, 9), 5);
    mov     rVv+1, rC0+0     ; rol 9
    mov     rVv+2, rC0+1
    mov     rVv+3, rC0+2
    mov     rVv+0, rC0+3
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    eor     rVv+0, rC0+0
    eor     rVv+1, rC0+1
    eor     rVv+2, rC0+2
    eor     rVv+3, rC0+3
    bst     rVv, 0           ; rol 5 (= ror 3 + rol 8)
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    mov     rC0+0, rVv+3
    mov     rC0+1, rVv+0
    mov     rC0+2, rVv+1
    mov     rC0+3, rVv+2

    ; c1 = ROTL32(c1 ^ ROTL32(c1, 9), 5);
    mov     rVv+1, rC1+0     ; rol 9
    mov     rVv+2, rC1+1
    mov     rVv+3, rC1+2
    mov     rVv+0, rC1+3
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    eor     rVv+0, rC1+0
    eor     rVv+1, rC1+1
    eor     rVv+2, rC1+2
    eor     rVv+3, rC1+3
    bst     rVv, 0           ; rol 5 (= ror 3 + rol 8)
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    mov     rC1+0, rVv+3
    mov     rC1+1, rVv+0
    mov     rC1+2, rVv+1
    mov     rC1+3, rVv+2

    ; c2 = ROTL32(c2 ^ ROTL32(c2, 9), 5);
    mov     rVv+1, rC2+0     ; rol 9
    mov     rVv+2, rC2+1
    mov     rVv+3, rC2+2
    mov     rVv+0, rC2+3
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    eor     rVv+0, rC2+0
    eor     rVv+1, rC2+1
    eor     rVv+2, rC2+2
    eor     rVv+3, rC2+3
    bst     rVv, 0           ; rol 5 (= ror 3 + rol 8)
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    mov     rC2+0, rVv+3
    mov     rC2+1, rVv+0
    mov     rC2+2, rVv+1
    mov     rC2+3, rVv+2

    ; c3 = ROTL32(c3 ^ ROTL32(c3, 9), 5);
    mov     rVv+1, rC3+0     ; rol 9
    mov     rVv+2, rC3+1
    mov     rVv+3, rC3+2
    mov     rVv+0, rC3+3
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    eor     rVv+0, rC3+0
    eor     rVv+1, rC3+1
    eor     rVv+2, rC3+2
    eor     rVv+3, rC3+3
    bst     rVv, 0           ; rol 5 (= ror 3 + rol 8)
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    bst     rVv, 0
    ror     rVv+3
    ror     rVv+2
    ror     rVv+1
    ror     rVv
    bld     rVv+3, 7
    mov     rC3+0, rVv+3
    mov     rC3+1, rVv+0
    mov     rC3+2, rVv+1
    mov     rC3+3, rVv+2
	
    ; v1 = a13;
	ldd		rVv+0, Y+a13+0
	ldd		rVv+1, Y+a13+1
	ldd		rVv+2, Y+a13+2
	ldd		rVv+3, Y+a13+3

    ; a13 = a12 ^ c1;
	ldd		r0, Y+a12+0
	eor		r0, rC1+0
	std		Y+a13+0, r0
	ldd		r0, Y+a12+1
	eor		r0, rC1+1
	std		Y+a13+1, r0
	ldd		r0, Y+a12+2
	eor		r0, rC1+2
	std		Y+a13+2, r0
	ldd		r0, Y+a12+3
	eor		r0, rC1+3
	std		Y+a13+3, r0

    ; a12 = a11 ^ c0;
	ldd		r0, Y+a11+0
	eor		r0, rC0+0
	std		Y+a12+0, r0
	ldd		r0, Y+a11+1
	eor		r0, rC0+1
	std		Y+a12+1, r0
	ldd		r0, Y+a11+2
	eor		r0, rC0+2
	std		Y+a12+2, r0
	ldd		r0, Y+a11+3
	eor		r0, rC0+3
	std		Y+a12+3, r0

    ; a11 = a10 ^ c3;
	ldd		r0, Y+a10+0
	eor		r0, rC3+0
	std		Y+a11+0, r0
	ldd		r0, Y+a10+1
	eor		r0, rC3+1
	std		Y+a11+1, r0
	ldd		r0, Y+a10+2
	eor		r0, rC3+2
	std		Y+a11+2, r0
	ldd		r0, Y+a10+3
	eor		r0, rC3+3
	std		Y+a11+3, r0

    ; a10 = v1  ^ c2;
	eor		rVv+0, rC2+0
	std		Y+a10+0, rVv+0
	eor		rVv+1, rC2+1
	std		Y+a10+1, rVv+1
	eor		rVv+2, rC2+2
	std		Y+a10+2, rVv+2
	eor		rVv+3, rC2+3
	std		Y+a10+3, rVv+3

    ; a20 = ROTL32(a20 ^ c3, 11);
	ldd		rVv+0, Y+a20+3
	eor		rVv+0, rC3+3
	ldd		rVv+1, Y+a20+0
	eor		rVv+1, rC3+0
	ldd		rVv+2, Y+a20+1
	eor		rVv+2, rC3+1
	ldd		rVv+3, Y+a20+2
	eor		rVv+3, rC3+2
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
	std		Y+a20+0, rVv+0
	std		Y+a20+1, rVv+1
	std		Y+a20+2, rVv+2
	std		Y+a20+3, rVv+3

    ; a21 = ROTL32(a21 ^ c0, 11);
	ldd		rVv+0, Y+a21+3
	eor		rVv+0, rC0+3
	ldd		rVv+1, Y+a21+0
	eor		rVv+1, rC0+0
	ldd		rVv+2, Y+a21+1
	eor		rVv+2, rC0+1
	ldd		rVv+3, Y+a21+2
	eor		rVv+3, rC0+2
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
	std		Y+a21+0, rVv+0
	std		Y+a21+1, rVv+1
	std		Y+a21+2, rVv+2
	std		Y+a21+3, rVv+3

    ; a22 = ROTL32(a22 ^ c1, 11);
	ldd		rVv+0, Y+a22+3
	eor		rVv+0, rC1+3
	ldd		rVv+1, Y+a22+0
	eor		rVv+1, rC1+0
	ldd		rVv+2, Y+a22+1
	eor		rVv+2, rC1+1
	ldd		rVv+3, Y+a22+2
	eor		rVv+3, rC1+2
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
	std		Y+a22+0, rVv+0
	std		Y+a22+1, rVv+1
	std		Y+a22+2, rVv+2
	std		Y+a22+3, rVv+3

    ; a23 = ROTL32(a23 ^ c2, 11);
	ldd		rVv+0, Y+a23+3
	eor		rVv+0, rC2+3
	ldd		rVv+1, Y+a23+0
	eor		rVv+1, rC2+0
	ldd		rVv+2, Y+a23+1
	eor		rVv+2, rC2+1
	ldd		rVv+3, Y+a23+2
	eor		rVv+3, rC2+2
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
    lsl     rVv+0
    rol     rVv+1
    rol     rVv+2
    rol     rVv+3
    adc     rVv+0, zero
	std		Y+a23+0, rVv+0
	std		Y+a23+1, rVv+1
	std		Y+a23+2, rVv+2
	std		Y+a23+3, rVv+3

	; v1 = c3;
	movw    rVv+0, rC3+0
	movw    rVv+2, rC3+2

    ; c3 = a03 ^ c2; /* a03 resides in c3 */
	ldd		rC3+0, Y+a03+0
	eor     rC3+0, rC2+0
	ldd		rC3+1, Y+a03+1
	eor     rC3+1, rC2+1
	ldd		rC3+2, Y+a03+2
	eor     rC3+2, rC2+2
	ldd		rC3+3, Y+a03+3
	eor     rC3+3, rC2+3

    ; c2 = a02 ^ c1; /* a02 resides in c2 */
	ldd		rC2+0, Y+a02+0
	eor     rC2+0, rC1+0
	ldd		rC2+1, Y+a02+1
	eor     rC2+1, rC1+1
	ldd		rC2+2, Y+a02+2
	eor     rC2+2, rC1+2
	ldd		rC2+3, Y+a02+3
	eor     rC2+3, rC1+3

    ; c1 = a01 ^ c0; /* a01 resides in c1 */
	ldd		rC1+0, Y+a01+0
	eor     rC1+0, rC0+0
	ldd		rC1+1, Y+a01+1
	eor     rC1+1, rC0+1
	ldd		rC1+2, Y+a01+2
	eor     rC1+2, rC0+2
	ldd		rC1+3, Y+a01+3
	eor     rC1+3, rC0+3

    ; c0 = a00 ^ v1; /* a00 resides in c0 */
	ldd		rC0+0, Y+a00+0
	eor     rC0+0, rVv+0
	ldd		rC0+1, Y+a00+1
	eor     rC0+1, rVv+1
	ldd		rC0+2, Y+a00+2
	eor     rC0+2, rVv+2
	ldd		rC0+3, Y+a00+3
	eor     rC0+3, rVv+3

    ; c0 ^= __rc;    /* +Iota */
    lpm     rVv+0, Z+
    lpm     rVv+1, Z+
	eor     rC0+0, rVv+0
	eor     rC0+1, rVv+1

    ; Chi + Rho east + Early Theta
    ; a00 = c0 ^= ~a10 & a20;
	ldd		r0, Y+a10+0
    com     r0
	ldd		rTt+0, Y+a20+0		; a20 in rTt
    and     r0, rTt+0
    eor     rC0+0, r0
	std		Y+a00+0, rC0+0
	ldd		r0, Y+a10+1
    com     r0
	ldd		rTt+1, Y+a20+1
    and     r0, rTt+1
    eor     rC0+1, r0
	std		Y+a00+1, rC0+1
	ldd		r0, Y+a10+2
    com     r0
	ldd		rTt+2, Y+a20+2
    and     r0, rTt+2
    eor     rC0+2, r0
	std		Y+a00+2, rC0+2
	ldd		r0, Y+a10+3
    com     r0
	ldd		rTt+3, Y+a20+3
    and     r0, rTt+3
    eor     rC0+3, r0
	std		Y+a00+3, rC0+3

    ; a10 ^= ~a20 & c0;
    com     rTt+0
	and		rTt+0, rC0+0
	ldd     r0, Y+a10+0
    eor     rTt+0, r0			; new a10 in rTt
	std     Y+a10+0, rTt+0
    com     rTt+1
	and		rTt+1, rC0+1
	ldd     r0, Y+a10+1
    eor     rTt+1, r0
	std     Y+a10+1, rTt+1
    com     rTt+2
	and		rTt+2, rC0+2
	ldd     r0, Y+a10+2
    eor     rTt+2, r0
	std     Y+a10+2, rTt+2
    com     rTt+3
	and		rTt+3, rC0+3
	ldd     r0, Y+a10+3
    eor     rTt+3, r0
	std     Y+a10+3, rTt+3

    ; v1(a20) = ROTL32(a20 ^ ~c0 & a10, 8);
	movw	rVv+0, rTt+0	; a10 in rVv
	movw	rVv+2, rTt+2
    mov     r0, rC0+0
    com     r0
	and		rTt+0, r0
	ldd     r0, Y+a20+0
	eor     rTt+0, r0	

    mov     r0, rC0+1
    com     r0
	and		rTt+1, r0
	ldd     r0, Y+a20+1
	eor     rTt+1, r0

    mov     r0, rC0+2
    com     r0
	and		rTt+2, r0
	ldd     r0, Y+a20+2
	eor     rTt+2, r0

    mov     r0, rC0+3
    com     r0
	and		rTt+3, r0
	ldd     r0, Y+a20+3
	eor     rTt+3, r0
	std     Y+a20+0, rTt+3
	std     Y+a20+1, rTt+0
	std     Y+a20+2, rTt+1
	std     Y+a20+3, rTt+2

    ; c0 ^= a10 = ROTL32(a10, 1);
    lsl     rVv+0
    rol     rVv+1
	std     Y+a10+1, rVv+1
	eor		rC0+1, rVv+1
    rol     rVv+2
	std     Y+a10+2, rVv+2
	eor		rC0+2, rVv+2
    rol     rVv+3
	std     Y+a10+3, rVv+3
	eor		rC0+3, rVv+3
    adc     rVv+0, zero
	std     Y+a10+0, rVv+0
	eor		rC0+0, rVv+0

    ; a02 = c2 ^= ~a12 & a22;
	ldd     r0, Y+a12+0
    com     r0
	ldd     rVv+0, Y+a22+0	; a22 in rVv
	and		r0, rVv+0
	eor		rC2+0, r0
	std		Y+a02+0, rC2+0
	ldd     r0, Y+a12+1
    com     r0
	ldd     rVv+1, Y+a22+1
	and		r0, rVv+1
	eor		rC2+1, r0
	std		Y+a02+1, rC2+1
	ldd     r0, Y+a12+2
    com     r0
	ldd     rVv+2, Y+a22+2
	and		r0, rVv+2
	eor		rC2+2, r0
	std		Y+a02+2, rC2+2
	ldd     r0, Y+a12+3
    com     r0
	ldd     rVv+3, Y+a22+3
	and		r0, rVv+3
	eor		rC2+3, r0
	std		Y+a02+3, rC2+3

    ; a12 ^= ~a22 & c2;
	mov     r0, rVv+0		; a12 in rTt
	com		r0
	and		r0, rC2+0
	ldd		rTt+0, Y+a12+0
	eor		rTt+0, r0
	std		Y+a12+0, rTt+0
	mov     r0, rVv+1
	com		r0
	and		r0, rC2+1
	ldd		rTt+1, Y+a12+1
	eor		rTt+1, r0
	std		Y+a12+1, rTt+1
	mov     r0, rVv+2
	com		r0
	and		r0, rC2+2
	ldd		rTt+2, Y+a12+2
	eor		rTt+2, r0
	std		Y+a12+2, rTt+2
	mov     r0, rVv+3
	com		r0
	and		r0, rC2+3
	ldd		rTt+3, Y+a12+3
	eor		rTt+3, r0
	std		Y+a12+3, rTt+3

    ; c0 ^= a20 = ROTL32(a22 ^ ~c2 & a12, 8);
	mov     r0, rC2+0
	com		r0
	and		r0, rTt+0
	eor		r0, rVv+0
	ldd		rVv+0, Y+a20+1		; rVv = a22
	std		Y+a20+1, r0
	eor		rC0+1, r0
	mov     r0, rC2+1
	com		r0
	and		r0, rTt+1
	eor		r0, rVv+1
	ldd		rVv+1, Y+a20+2
	std		Y+a20+2, r0
	eor		rC0+2, r0
	mov     r0, rC2+2
	com		r0
	and		r0, rTt+2
	eor		r0, rVv+2
	ldd		rVv+2, Y+a20+3
	std		Y+a20+3, r0
	eor		rC0+3, r0
	mov     r0, rC2+3
	com		r0
	and		r0, rTt+3
	eor		r0, rVv+3
	ldd		rVv+3, Y+a20+0
	std		Y+a20+0, r0
	eor		rC0+0, r0

    ; c2 ^= a12 = ROTL32(a12, 1);
    lsl     rTt+0
    rol     rTt+1
	eor		rC2+1, rTt+1
	std     Y+a12+1, rTt+1
    rol     rTt+2
	eor		rC2+2, rTt+2
	std     Y+a12+2, rTt+2
    rol     rTt+3
	eor		rC2+3, rTt+3
	std     Y+a12+3, rTt+3
    adc     rTt+0, zero
	eor		rC2+0, rTt+0
	std     Y+a12+0, rTt+0

    ; a22 = v1;
	std     Y+a22+0, rVv+3
	std     Y+a22+1, rVv+0
	std     Y+a22+2, rVv+1
	std     Y+a22+3, rVv+2

	; c2 ^= v1;
	eor		rC2+0, rVv+3
	eor		rC2+1, rVv+0
	eor		rC2+2, rVv+1
	eor		rC2+3, rVv+2

    ; a01 = c1 ^= ~a11 & a21;
	ldd		rTt+0, Y+a11+0  ;rTt holds a11
	mov		r0, rTt+0
	com		r0
	ldd		rVv+0, Y+a21+0  ;rVv holds a21
	and		r0, rVv+0
	eor		rC1+0, r0
	std		Y+a01+0, rC1+0
	ldd		rTt+1, Y+a11+1
	mov		r0, rTt+1
	com		r0
	ldd		rVv+1, Y+a21+1
	and		r0, rVv+1
	eor		rC1+1, r0
	std		Y+a01+1, rC1+1
	ldd		rTt+2, Y+a11+2
	mov		r0, rTt+2
	com		r0
	ldd		rVv+2, Y+a21+2
	and		r0, rVv+2
	eor		rC1+2, r0
	std		Y+a01+2, rC1+2
	ldd		rTt+3, Y+a11+3
	mov		r0, rTt+3
	com		r0
	ldd		rVv+3, Y+a21+3
	and		r0, rVv+3
	eor		rC1+3, r0
	std		Y+a01+3, rC1+3

    ; a11 ^= ~a21 & c1;
	mov		r0, rVv+0
	com		r0
	and		r0, rC1+0
	eor		rTt+0, r0
	std		Y+a11+0, rTt+0
	mov		r0, rVv+1
	com		r0
	and		r0, rC1+1
	eor		rTt+1, r0
	std		Y+a11+1, rTt+1
	mov		r0, rVv+2
	com		r0
	and		r0, rC1+2
	eor		rTt+2, r0
	std		Y+a11+2, rTt+2
	mov		r0, rVv+3
	com		r0
	and		r0, rC1+3
	eor		rTt+3, r0
	std		Y+a11+3, rTt+3

    ; v1 = ROTL32(a21 ^ ~c1 & a11, 8);
	mov     r0, rC1+0
	com		r0
	and		r0, rTt+0
	eor		rVv+0, r0           ; v1 not yet ROTL32'ed(8)
	mov     r0, rC1+1
	com		r0
	and		r0, rTt+1
	eor		rVv+1, r0
	mov     r0, rC1+2
	com		r0
	and		r0, rTt+2
	eor		rVv+2, r0
	mov     r0, rC1+3
	com		r0
	and		r0, rTt+3
	eor		rVv+3, r0

    ; c1 ^= a11 = ROTL32(a11, 1);
    lsl     rTt+0
    rol     rTt+1
	eor		rC1+1, rTt+1
	std     Y+a11+1, rTt+1
    rol     rTt+2
	eor		rC1+2, rTt+2
	std     Y+a11+2, rTt+2
    rol     rTt+3
	eor		rC1+3, rTt+3
	std     Y+a11+3, rTt+3
    adc     rTt+0, zero
	eor		rC1+0, rTt+0
	std     Y+a11+0, rTt+0

    ; a03 = c3 ^= ~a13 & a23;
	ldd     r0, Y+a13+0
    com     r0
	ldd     rTt+0, Y+a23+0	; a23 in rTt
	and		r0, rTt+0
	eor		rC3+0, r0
	std		Y+a03+0, rC3+0
	ldd     r0, Y+a13+1
    com     r0
	ldd     rTt+1, Y+a23+1
	and		r0, rTt+1
	eor		rC3+1, r0
	std		Y+a03+1, rC3+1
	ldd     r0, Y+a13+2
    com     r0
	ldd     rTt+2, Y+a23+2
	and		r0, rTt+2
	eor		rC3+2, r0
	std		Y+a03+2, rC3+2
	ldd     r0, Y+a13+3
    com     r0
	ldd     rTt+3, Y+a23+3
	and		r0, rTt+3
	eor		rC3+3, r0
	std		Y+a03+3, rC3+3

    ; a13 ^= ~a23 & c3;
	mov     r0, rTt+0
    com     r0
	and     r0, rC3+0
	ldd		rTt+0, Y+a13+0		; a13 in rTt
	eor		rTt+0, r0
	mov     r0, rTt+1
    com     r0
	and     r0, rC3+1
	ldd		rTt+1, Y+a13+1
	eor		rTt+1, r0
	mov     r0, rTt+2
    com     r0
	and     r0, rC3+2
	ldd		rTt+2, Y+a13+2
	eor		rTt+2, r0
	mov     r0, rTt+3
    com     r0
	and     r0, rC3+3
	ldd		rTt+3, Y+a13+3
	eor		rTt+3, r0

    ; c1 ^= a21 = ROTL32(a23 ^ ~c3 & a13, 8);
	push	rVv
	mov     r0, rC3+0
    com     r0
	and     r0, rTt+0
	ldd		rVv, Y+a23+0
	eor     r0, rVv
	eor     rC1+1, r0
	std		Y+a21+1, r0
	mov     r0, rC3+1
    com     r0
	and     r0, rTt+1
	ldd		rVv, Y+a23+1
	eor     r0, rVv
	eor     rC1+2, r0
	std		Y+a21+2, r0
	mov     r0, rC3+2
    com     r0
	and     r0, rTt+2
	ldd		rVv, Y+a23+2
	eor     r0, rVv
	eor     rC1+3, r0
	std		Y+a21+3, r0
	mov     r0, rC3+3
    com     r0
	and     r0, rTt+3
	ldd		rVv, Y+a23+3
	eor     r0, rVv
	eor     rC1+0, r0
	std		Y+a21+0, r0
	pop     rVv

    ; a23 = v1;
	std		Y+a23+0, rVv+3 ; rol8(rVv)
	std		Y+a23+1, rVv+0
	std		Y+a23+2, rVv+1
	std		Y+a23+3, rVv+2

	; c3 ^= v1;
	eor     rC3+0, rVv+3
	eor     rC3+1, rVv+0
	eor     rC3+2, rVv+1
	eor     rC3+3, rVv+2

    ; c3 ^= a13 = ROTL32(a13, 1);
    lsl     rTt+0
    rol     rTt+1
	std     Y+a13+1, rTt+1
	eor		rC3+1, rTt+1
    rol     rTt+2
	std     Y+a13+2, rTt+2
	eor		rC3+2, rTt+2
    rol     rTt+3
	std     Y+a13+3, rTt+3
	eor		rC3+3, rTt+3
    adc     rTt+0, zero
	std     Y+a13+0, rTt+0
	eor		rC3+0, rTt+0

    ; Check for terminator
    lpm     r0, Z
    inc     r0
    breq    Xoodoo_Done
    rjmp    Xoodoo_RoundLoop
Xoodoo_Done:
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
