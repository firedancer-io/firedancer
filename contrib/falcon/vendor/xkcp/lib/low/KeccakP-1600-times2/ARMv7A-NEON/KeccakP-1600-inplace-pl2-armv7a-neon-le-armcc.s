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
; This file implements Keccak-p[1600]×2 in a PlSnP-compatible way.
; Please refer to PlSnP-documentation.h for more details.
;
; This implementation comes with KeccakP-1600-times2-SnP.h in the same folder.
; Please refer to LowLevel.build for the exact list of other files it must be combined with.
;

; WARNING: These functions work only on little endian CPU with ARMv7A + NEON architecture
; WARNING: State must be 256 bit (32 bytes) aligned, best is 64-byte (cache alignment).

; INFO: Tested on Cortex-A8 (BeagleBone Black), using gcc.
; INFO: Parallel execution of Keccak-P permutation on 2 lane interleaved states.

; INFO: KeccakP1600times2_PermuteAll_12rounds() execution time is 7690 cycles on a Cortex-A8 (BeagleBone Black)


        PRESERVE8
        AREA    |.text|, CODE, READONLY

;----------------------------------------------------------------------------

; --- offsets in state
_ba     equ  0*16
_be     equ  1*16
_bi     equ  2*16
_bo     equ  3*16
_bu     equ  4*16
_ga     equ  5*16
_ge     equ  6*16
_gi     equ  7*16
_go     equ  8*16
_gu     equ  9*16
_ka     equ 10*16
_ke     equ 11*16
_ki     equ 12*16
_ko     equ 13*16
_ku     equ 14*16
_ma     equ 15*16
_me     equ 16*16
_mi     equ 17*16
_mo     equ 18*16
_mu     equ 19*16
_sa     equ 20*16
_se     equ 21*16
_si     equ 22*16
_so     equ 23*16
_su     equ 24*16

; --- macros for Single permutation

    MACRO
    KeccakS_ThetaRhoPiChiIota $argA1, $argA2, $argA3, $argA4, $argA5

    ;Prepare Theta
    ; Ca = Aba^Aga^Aka^Ama^Asa
    ; Ce = Abe^Age^Ake^Ame^Ase
    ; Ci = Abi^Agi^Aki^Ami^Asi
    ; Co = Abo^Ago^Ako^Amo^Aso
    ; Cu = Abu^Agu^Aku^Amu^Asu
    ; De = Ca^ROL64(Ci, 1)
    ; Di = Ce^ROL64(Co, 1)
    ; Do = Ci^ROL64(Cu, 1)
    ; Du = Co^ROL64(Ca, 1)
    ; Da = Cu^ROL64(Ce, 1)
    veor.64     q4,   q6, q7
    veor.64     q5,   q9, q10
    veor.64     d8,    d8,   d9
    veor.64     d10,    d10,   d11
    veor.64     d1,    d8,   d16
    veor.64     d2,    d10,   d17

    veor.64     q4,   q11, q12
    veor.64     q5,   q14, q15
    veor.64     d8,    d8,   d9
    veor.64     d10,    d10,   d11
    veor.64     d3,    d8,   d26

    vadd.u64    q4,   q1,  q1
    veor.64     d4,    d10,   d27
    vmov.64     d0,    d5
    vsri.64     q4,   q1,  #63

    vadd.u64    q5,   q2,  q2
    veor.64     q4,   q4,  q0
    vsri.64     q5,   q2,  #63
    vadd.u64    d7,    d1,   d1
    veor.64     $argA2, $argA2,  d8
    veor.64     q5,   q5,  q1

    vsri.64     d7,    d1,   #63
    vshl.u64    d1,    $argA2, #44
    veor.64     $argA3, $argA3,  d9
    veor.64     d7,    d7,   d4

    ; Ba = argA1^Da
    ; Be = ROL64((argA2^De), 44)
    ; Bi = ROL64((argA3^Di), 43)
    ; Bo = ROL64((argA4^Do), 21)
    ; Bu = ROL64((argA5^Du), 14)
    ; argA2 =   Be ^((~Bi)& Bo )
    ; argA3 =   Bi ^((~Bo)& Bu )
    ; argA4 =   Bo ^((~Bu)& Ba )
    ; argA5 =   Bu ^((~Ba)& Be )
    ; argA1 =   Ba ^((~Be)& Bi )
    ; argA1 ^= KeccakP1600RoundConstants[i+round]
    vsri.64     d1,    $argA2,   #64-44
    vshl.u64    d2,    $argA3,   #43
    vldr.64     d0,    [r0, #$argA1]
    veor.64     $argA4, $argA4,   d10
    vsri.64     d2,    $argA3,   #64-43
    vshl.u64    d3,    $argA4,   #21
    veor.64     $argA5, $argA5,   d11
    veor.64     d0,    d0,    d7
    vsri.64     d3,    $argA4,  #64-21
    vbic.64     d5,    d2,    d1
    vshl.u64    d4,    $argA5,  #14
    vbic.64     $argA2, d3,     d2
    vld1.64     d6,    [r1]!
    veor.64     d5,    d0
    vsri.64     d4,    $argA5,  #64-14
    veor.64     d5,    d6
    vbic.64     $argA5, d1,     d0
    vbic.64     $argA3, d4,     d3
    vbic.64     $argA4, d0,     d4
    veor.64     $argA2, d1
    vstr.64     d5,    [r0, #$argA1]
    veor.64     $argA3, d2
    veor.64     $argA4, d3
    veor.64     $argA5, d4
    MEND

    MACRO
    KeccakS_ThetaRhoPiChi1 $argA1, $argA2, $argA3, $argA4, $argA5

    ; Bi = ROL64((argA1^Da), 3)
    ; Bo = ROL64((argA2^De), 45)
    ; Bu = ROL64((argA3^Di), 61)
    ; Ba = ROL64((argA4^Do), 28)
    ; Be = ROL64((argA5^Du), 20)
    ; argA1 =   Ba ^((~Be)&  Bi )
    ; Ca ^= argA1
    ; argA2 =   Be ^((~Bi)&  Bo )
    ; argA3 =   Bi ^((~Bo)&  Bu )
    ; argA4 =   Bo ^((~Bu)&  Ba )
    ; argA5 =   Bu ^((~Ba)&  Be )
    veor.64     $argA2, $argA2,    d8
    veor.64     $argA3, $argA3,    d9
    vshl.u64    d3,    $argA2,   #45
    vldr.64     d6,    [r0, #$argA1]
    vshl.u64    d4,    $argA3,   #61
    veor.64     $argA4, $argA4,    d10
    vsri.64     d3,    $argA2,   #64-45
    veor.64     $argA5, $argA5,    d11
    vsri.64     d4,    $argA3,   #64-61
    vshl.u64    d0,    $argA4,   #28
    veor.64     d6,    d6,     d7
    vshl.u64    d1,    $argA5,   #20
    vbic.64     $argA3, d4,      d3
    vsri.64     d0,    $argA4,   #64-28
    vbic.64     $argA4, d0,      d4
    vshl.u64    d2,    d6,     #3
    vsri.64     d1,    $argA5,   #64-20
    veor.64     $argA4, d3
    vsri.64     d2,    d6,     #64-3
    vbic.64     $argA5, d1,      d0
    vbic.64     d6,    d2,     d1
    vbic.64     $argA2, d3,      d2
    veor.64     d6,    d0
    veor.64     $argA2, d1
    vstr.64     d6,    [r0, #$argA1]
    veor.64     $argA3, d2
    veor.64     d5,    d6
    veor.64     $argA5, d4
    MEND

    MACRO
    KeccakS_ThetaRhoPiChi2 $argA1, $argA2, $argA3, $argA4, $argA5

    ; Bu = ROL64((argA1^Da), 18)
    ; Ba = ROL64((argA2^De), 1)
    ; Be = ROL64((argA3^Di), 6)
    ; Bi = ROL64((argA4^Do), 25)
    ; Bo = ROL64((argA5^Du), 8)
    ; argA1 =   Ba ^((~Be)&  Bi )
    ; Ca ^= argA1;
    ; argA2 =   Be ^((~Bi)&  Bo )
    ; argA3 =   Bi ^((~Bo)&  Bu )
    ; argA4 =   Bo ^((~Bu)&  Ba )
    ; argA5 =   Bu ^((~Ba)&  Be )
    veor.64     $argA3, $argA3,    d9
    veor.64     $argA4, $argA4,    d10
    vshl.u64    d1,    $argA3,   #6
    vldr.64     d6,    [r0, #$argA1]
    vshl.u64    d2,    $argA4,   #25
    veor.64     $argA5, $argA5,    d11
    vsri.64     d1,    $argA3,   #64-6
    veor.64     $argA2, $argA2,    d8
    vsri.64     d2,    $argA4,   #64-25
    vext.8      d3,   $argA5,    $argA5, #7
    veor.64     d6,    d6,     d7
    vbic.64     $argA3, d2,      d1
    vadd.u64    d0,    $argA2,   $argA2
    vbic.64     $argA4, d3,      d2
    vsri.64     d0,    $argA2,   #64-1
    vshl.u64    d4,    d6,     #18
    veor.64     $argA2, d1,      $argA4
    veor.64     $argA3, d0
    vsri.64     d4,    d6,     #64-18
    vstr.64     $argA3, [r0,  #$argA1]
    veor.64     d5,    $argA3
    vbic.64     $argA5, d1,      d0
    vbic.64     $argA3, d4,      d3
    vbic.64     $argA4, d0,      d4
    veor.64     $argA3, d2
    veor.64     $argA4, d3
    veor.64     $argA5, d4
    MEND

    MACRO
    KeccakS_ThetaRhoPiChi3 $argA1, $argA2, $argA3, $argA4, $argA5

    ; Be = ROL64((argA1^Da), 36)
    ; Bi = ROL64((argA2^De), 10)
    ; Bo = ROL64((argA3^Di), 15)
    ; Bu = ROL64((argA4^Do), 56)
    ; Ba = ROL64((argA5^Du), 27)
    ; argA1 =   Ba ^((~Be)&  Bi )
    ; Ca ^= argA1
    ; argA2 =   Be ^((~Bi)&  Bo )
    ; argA3 =   Bi ^((~Bo)&  Bu )
    ; argA4 =   Bo ^((~Bu)&  Ba )
    ; argA5 =   Bu ^((~Ba)&  Be )
    veor.64     $argA2, $argA2,    d8
    veor.64     $argA3, $argA3,    d9
    vshl.u64    d2,    $argA2,   #10
    vldr.64     d6,    [r0, #$argA1]
    vshl.u64    d3,    $argA3,   #15
    veor.64     $argA4, $argA4,    d10
    vsri.64     d2,    $argA2,   #64-10
    vsri.64     d3,    $argA3,   #64-15
    veor.64     $argA5, $argA5,    d11
    vext.8      d4,    $argA4,   $argA4, #1
    vbic.64     $argA2, d3,      d2
    vshl.u64    d0,    $argA5,   #27
    veor.64     d6,    d6,     d7
    vbic.64     $argA3, d4,      d3
    vsri.64     d0,    $argA5,   #64-27
    vshl.u64    d1,    d6,     #36
    veor.64     $argA3, d2
    vbic.64     $argA4, d0,      d4
    vsri.64     d1,    d6,     #64-36
    veor.64     $argA4, d3
    vbic.64     d6,    d2,     d1
    vbic.64     $argA5, d1,      d0
    veor.64     d6,    d0
    veor.64     $argA2, d1
    vstr.64     d6,    [r0, #$argA1]
    veor.64     d5,    d6
    veor.64     $argA5, d4
    MEND

    MACRO
    KeccakS_ThetaRhoPiChi4 $argA1, $argA2, $argA3, $argA4, $argA5

    ; Bo = ROL64((argA1^Da), 41)
    ; Bu = ROL64((argA2^De), 2)
    ; Ba = ROL64((argA3^Di), 62)
    ; Be = ROL64((argA4^Do), 55)
    ; Bi = ROL64((argA5^Du), 39)
    ; argA1 =   Ba ^((~Be)&  Bi )
    ; Ca ^= argA1
    ; argA2 =   Be ^((~Bi)&  Bo )
    ; argA3 =   Bi ^((~Bo)&  Bu )
    ; argA4 =   Bo ^((~Bu)&  Ba )
    ; argA5 =   Bu ^((~Ba)&  Be )
    veor.64     $argA2, $argA2,    d8
    veor.64     $argA3, $argA3,    d9
    vshl.u64    d4,    $argA2,   #2
    veor.64     $argA5, $argA5,    d11
    vshl.u64    d0,    $argA3,   #62
    vldr.64     d6,    [r0, #$argA1]
    vsri.64     d4,    $argA2,   #64-2
    veor.64     $argA4, $argA4,    d10
    vsri.64     d0,    $argA3,   #64-62
    vshl.u64    d1,    $argA4,   #55
    veor.64     d6,    d6,     d7
    vshl.u64    d2,    $argA5,   #39
    vsri.64     d1,    $argA4,   #64-55
    vbic.64     $argA4, d0,      d4
    vsri.64     d2,    $argA5,   #64-39
    vbic.64     $argA2, d1,      d0
    vshl.u64    d3,    d6,     #41
    veor.64     $argA5, d4,      $argA2
    vbic.64     $argA2, d2,      d1
    vsri.64     d3,    d6,     #64-41
    veor.64     d6,    d0,     $argA2
    vbic.64     $argA2, d3,      d2
    vbic.64     $argA3, d4,      d3
    veor.64     $argA2, d1
    vstr.64     d6,    [r0, #$argA1]
    veor.64     d5,    d6
    veor.64     $argA3, d2
    veor.64     $argA4, d3
    MEND

; --- macros for Parallel permutation

    MACRO
    m_pls       $start
    if $start  != -1
    add         r3, r0, #$start
    endif
    MEND

    MACRO
    m_ld        $qreg, $next
    if $next == 16
    vld1.64     { $qreg }, [r3:128]!
    else
    vld1.64     { $qreg }, [r3:128], r4
    endif
    MEND

    MACRO
    m_st        $qreg, $next
    if $next == 16
    vst1.64     { $qreg }, [r3:128]!
    else
    vst1.64     { $qreg }, [r3:128], r4
    endif
    MEND

    MACRO
    KeccakP_ThetaRhoPiChiIota $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1

    ; De = Ca ^ ROL64(Ci, 1)
    ; Di = Ce ^ ROL64(Co, 1)
    ; Do = Ci ^ ROL64(Cu, 1)
    ; Du = Co ^ ROL64(Ca, 1)
    ; Da = Cu ^ ROL64(Ce, 1)
    vadd.u64    q6,  q2,  q2
    vadd.u64    q7,  q3,  q3
    vadd.u64    q8,  q4,  q4
    vadd.u64    q9,  q0,  q0
    vadd.u64    q5,  q1,  q1

    vsri.64     q6,  q2,  #63
    vsri.64     q7,  q3,  #63
    vsri.64     q8,  q4,  #63
    vsri.64     q9,  q0,  #63
    vsri.64     q5,  q1,  #63

    veor.64     q6,  q6,  q0
    veor.64     q7,  q7,  q1
    veor.64     q8,  q8,  q2
    if  $next != 16
    mov     r4, #$next
    endif
    veor.64     q9,  q9,  q3
    veor.64     q5,  q5,  q4

    ; Ba = argA1^Da
    ; Be = ROL64(argA2^De, 44)
    ; Bi = ROL64(argA3^Di, 43)
    ; Bo = ROL64(argA4^Do, 21)
    ; Bu = ROL64(argA5^Du, 14)
    m_ld    q10, $next
    m_pls   $ofs2
    m_ld    q1, $next
    m_pls   $ofs3
    veor.64 q10,  q10,  q5
    m_ld    q2, $next
    m_pls   $ofs4
    veor.64 q1,  q1,  q6
    m_ld    q3, $next
    m_pls   $ofs5
    veor.64 q2,  q2,  q7
    m_ld    q4, $next
    veor.64 q3,  q3,  q8
    mov     r6, r5
    veor.64 q4,  q4,  q9

    vst1.64 { q6 }, [r6:128]!
    vshl.u64    q11,  q1,  #44
    vshl.u64    q12,  q2,  #43
    vst1.64 { q7 }, [r6:128]!
    vshl.u64    q13,  q3,  #21
    vshl.u64    q14,  q4,  #14
    vst1.64 { q8 }, [r6:128]!
    vsri.64 q11,  q1,  #64-44
    vsri.64 q12,  q2,  #64-43
    vst1.64 { q9 }, [r6:128]!
    vsri.64 q13,  q3,  #64-21
    vsri.64 q14,  q4,  #64-14

    ; argA1 = Ba ^(~Be & Bi) ^ KeccakP1600RoundConstants[round]
    ; argA2 = Be ^(~Bi & Bo)
    ; argA3 = Bi ^(~Bo & Bu)
    ; argA4 = Bo ^(~Bu & Ba)
    ; argA5 = Bu ^(~Ba & Be)
    vld1.64     { d30 },  [r1:64]
    vbic.64     q0,  q12,  q11
    vbic.64     q1,  q13,  q12
    vld1.64     { d31 },  [r1:64]!
    veor.64     q0,  q10
    vbic.64     q4,  q11,  q10
    veor.64     q0,  q15
    vbic.64     q2,  q14,  q13
    vbic.64     q3,  q10,  q14

    m_pls   $ofs1
    veor.64 q1,  q11
    m_st    q0, $next
    m_pls   $ofs2
    veor.64 q2,  q12
    m_st    q1, $next
    m_pls   $ofs3
    veor.64 q3,  q13
    m_st    q2, $next
    m_pls   $ofs4
    veor.64 q4,  q14
    m_st    q3, $next
    m_pls   $ofs5
    m_st    q4, $next
    m_pls   $ofsn1
    MEND

    MACRO
    KeccakP_ThetaRhoPiChi  $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1, $Bb1, $Bb2, $Bb3, $Bb4, $Bb5, $Rr1, $Rr2, $Rr3, $Rr4, $Rr5

    ; Bb1 = ROL64((argA1^Da), Rr1)
    ; Bb2 = ROL64((argA2^De), Rr2)
    ; Bb3 = ROL64((argA3^Di), Rr3)
    ; Bb4 = ROL64((argA4^Do), Rr4)
    ; Bb5 = ROL64((argA5^Du), Rr5)

    if  $next != 16
    mov     r4, #$next
    endif

    m_ld    $Bb1,   $next
    m_pls   $ofs2
    m_ld    $Bb2,   $next
    m_pls   $ofs3
    veor.64 q15,   q5,  $Bb1
    m_ld    $Bb3,   $next
    m_pls   $ofs4
    veor.64 q6,  q6,  $Bb2
    m_ld    $Bb4,   $next
    m_pls   $ofs5
    veor.64 q7,  q7,  $Bb3
    m_ld    $Bb5,   $next
    veor.64 q8,  q8,  $Bb4
    veor.64 q9,  q9,  $Bb5

    vshl.u64    $Bb1,  q15,   #$Rr1
    vshl.u64    $Bb2,  q6,  #$Rr2
    vshl.u64    $Bb3,  q7,  #$Rr3
    vshl.u64    $Bb4,  q8,  #$Rr4
    vshl.u64    $Bb5,  q9,  #$Rr5

    vsri.64 $Bb1,  q15,   #64-$Rr1
    vsri.64 $Bb2,  q6,  #64-$Rr2
    vsri.64 $Bb3,  q7,  #64-$Rr3
    vsri.64 $Bb4,  q8,  #64-$Rr4
    vsri.64 $Bb5,  q9,  #64-$Rr5

    ; argA1 = Ba ^((~Be)&  Bi ), Ca ^= argA1
    ; argA2 = Be ^((~Bi)&  Bo ), Ce ^= argA2
    ; argA3 = Bi ^((~Bo)&  Bu ), Ci ^= argA3
    ; argA4 = Bo ^((~Bu)&  Ba ), Co ^= argA4
    ; argA5 = Bu ^((~Ba)&  Be ), Cu ^= argA5
    vbic.64 q15,    q12,  q11
    mov     r6, r5
    vbic.64 q6,   q13,  q12
    m_pls   $ofs1
    vbic.64 q7,   q14,  q13
    vbic.64 q8,   q10,  q14
    vbic.64 q9,   q11,  q10

    veor.64 q15,    q15,    q10
    veor.64 q6,   q6,   q11

    m_st    q15, $next
    m_pls   $ofs2
    veor.64 q7,   q7,   q12

    m_st    q6, $next
    m_pls   $ofs3
    veor.64 q1,   q1,  q6
    vld1.64 { q6 }, [r6:128]!
    veor.64 q8,   q8,   q13

    m_st    q7, $next
    m_pls   $ofs4
    veor.64 q2,   q2,  q7
    vld1.64 { q7 }, [r6:128]!
    veor.64 q9,   q9,   q14

    m_st    q8,  $next
    m_pls   $ofs5
    veor.64 q3,  q3,  q8

    m_st    q9,  $next

    vld1.64 { q8 }, [r6:128]!
    veor.64 q4,  q4,  q9
    m_pls   $ofsn1
    vld1.64 { q9 }, [r6:128]!
    veor.64 q0,  q0,  q15
    MEND

    MACRO
    KeccakP_ThetaRhoPiChi1 $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1
    KeccakP_ThetaRhoPiChi  $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1, q12, q13, q14, q10, q11,  3, 45, 61, 28, 20
    MEND

    MACRO
    KeccakP_ThetaRhoPiChi2 $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1
    KeccakP_ThetaRhoPiChi  $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1, q14, q10, q11, q12, q13, 18,  1,  6, 25,  8
    MEND

    MACRO
    KeccakP_ThetaRhoPiChi3 $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1
    KeccakP_ThetaRhoPiChi  $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1, q11, q12, q13, q14, q10, 36, 10, 15, 56, 27
    MEND

    MACRO
    KeccakP_ThetaRhoPiChi4 $ofs1, $ofs2, $ofs3, $ofs4, $ofs5, $next, $ofsn1

    ; Bo = ROL64((argA1^Da), 41)
    ; Bu = ROL64((argA2^De), 2)
    ; Ba = ROL64((argA3^Di), 62)
    ; Be = ROL64((argA4^Do), 55)
    ; Bi = ROL64((argA5^Du), 39)
    ; KeccakChi

    if  $next != 16
    mov     r4, #$next
    endif

    m_ld    q13, $next
    m_pls   $ofs2
    m_ld    q14, $next
    m_pls   $ofs3
    veor.64 q5,  q5,  q13
    m_ld    q10, $next
    m_pls   $ofs4
    veor.64 q6,  q6,  q14
    m_ld    q11, $next
    m_pls   $ofs5
    veor.64 q7,  q7,  q10
    m_ld    q12, $next
    veor.64 q8,  q8,  q11
    veor.64 q9,  q9,  q12

    vshl.u64    q13,  q5,  #41
    vshl.u64    q14,  q6,  #2
    vshl.u64    q10,  q7,  #62
    vshl.u64    q11,  q8,  #55
    vshl.u64    q12,  q9,  #39

    vsri.64 q13,  q5,  #64-41
    vsri.64 q14,  q6,  #64-2
    vsri.64 q11,  q8,  #64-55
    vsri.64 q12,  q9,  #64-39
    vsri.64 q10,  q7,  #64-62

    vbic.64 q5,   q12,  q11
    vbic.64 q6,   q13,  q12
    vbic.64 q7,   q14,  q13
    vbic.64 q8,   q10,  q14
    vbic.64 q9,   q11,  q10
    veor.64 q5,   q5,  q10
    veor.64 q6,   q6,  q11
    veor.64 q7,   q7,  q12
    veor.64 q8,   q8,  q13
    m_pls   $ofs1
    veor.64 q9,   q9,  q14
    m_st    q5,  $next
    m_pls   $ofs2
    veor.64 q0,   q0,  q5
    m_st    q6,  $next
    m_pls   $ofs3
    veor.64 q1,   q1,  q6
    m_st    q7,  $next
    m_pls   $ofs4
    veor.64 q2,   q2,  q7
    m_st    q8,  $next
    m_pls   $ofs5
    veor.64 q3,   q3,  q8
    m_st    q9,  $next
    m_pls   $ofsn1
    veor.64 q4,   q4,  q9
    MEND

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_StaticInitialize( void )
;
    ALIGN
    EXPORT  KeccakP1600times2_StaticInitialize
KeccakP1600times2_StaticInitialize   PROC
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_InitializeAll( KeccakP1600times2_states *states )
;
    ALIGN
    EXPORT  KeccakP1600times2_InitializeAll
KeccakP1600times2_InitializeAll   PROC
    vmov.i64    q0, #0
    vmov.i64    q1, #0
    vmov.i64    q2, #0
    vmov.i64    q3, #0
    vstm        r0!, { d0 - d7 }      ;  8 (clear 8 lanes at a time)
    vstm        r0!, { d0 - d7 }      ; 16
    vstm        r0!, { d0 - d7 }      ; 24
    vstm        r0!, { d0 - d7 }      ; 32
    vstm        r0!, { d0 - d7 }      ; 40
    vstm        r0!, { d0 - d7 }      ; 48
    vstm        r0!, { d0 - d1}       ; 50
    bx          lr
    ENDP


;----------------------------------------------------------------------------
;
; void KeccakP1600times2_AddByte( KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned char byte, unsigned int offset )
;
    ALIGN
    EXPORT  KeccakP1600times2_AddByte
KeccakP1600times2_AddByte   PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    lsr     r1, r3, #3                  ; states += (offset & ~7) * 2
    add     r0, r0, r1, LSL #4
    and     r3, r3, #7
    add     r0, r0, r3                  ; states += offset & 7
    ldrb    r1, [r0]
    eor     r1, r1, r2
    strb    r1, [r0]
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_AddBytes( KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data,
;                                   unsigned int offset, unsigned int length )
;
    ALIGN
    EXPORT  KeccakP1600times2_AddBytes
KeccakP1600times2_AddBytes   PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    ldr     r1, [sp, #0*4]              ; r1 = length
    cmp     r1, #0
    beq     KeccakP1600times2_AddBytes_Exit
    push    { r4- r7 }
    lsr     r4, r3, #3                  ; states += (offset & ~7) * 2
    add     r0, r0, r4, LSL #4
    ands    r3, r3, #7                  ; if (offset & 7) != 0
    beq     KeccakP1600times2_AddBytes_CheckLanes
    add     r0, r0, r3                  ; states += offset & 7
    rsb     r3, r3, #8                  ; lenInLane = 8 - (offset & 7)
KeccakP1600times2_AddBytes_LoopBytesFirst
    ldrb    r4, [r0]
    ldrb    r5, [r2], #1
    eor     r4, r4, r5
    subs    r1, r1, #1
    strb    r4, [r0], #1
    beq     KeccakP1600times2_AddBytes_Done
    subs    r3, r3, #1
    bne     KeccakP1600times2_AddBytes_LoopBytesFirst
    add     r0, r0, #8                  ; states += 8 (next lane of current state part)
KeccakP1600times2_AddBytes_CheckLanes
    lsrs    r3, r1, #3
    beq     KeccakP1600times2_AddBytes_CheckBytesLast
KeccakP1600times2_AddBytes_LoopLanes
    ldr     r4, [r0]
    ldr     r5, [r0, #4]
    ldr     r6, [r2], #4
    ldr     r7, [r2], #4
    eor     r4, r4, r6
    eor     r5, r5, r7
    subs    r3, r3, #1
    str     r4, [r0], #4
    str     r5, [r0], #12               ; states += 8 (next lane of current state part)
    bne     KeccakP1600times2_AddBytes_LoopLanes
KeccakP1600times2_AddBytes_CheckBytesLast
    ands    r1, r1, #7
    beq     KeccakP1600times2_AddBytes_Done
KeccakP1600times2_AddBytes_LoopBytesLast
    ldrb    r4, [r0]
    ldrb    r5, [r2], #1
    eor     r4, r4, r5
    subs    r1, r1, #1
    strb    r4, [r0], #1
    bne     KeccakP1600times2_AddBytes_LoopBytesLast
KeccakP1600times2_AddBytes_Done
    pop     { r4- r7 }
KeccakP1600times2_AddBytes_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_AddLanesAll( KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset )
;
    ALIGN
    EXPORT  KeccakP1600times2_AddLanesAll
KeccakP1600times2_AddLanesAll   PROC
    cmp     r2, #0
    beq     KeccakP1600times2_AddLanesAll_Exit
    add     r3, r1, r3, LSL #3      ; r3: data + 8 * laneOffset
    push    {r4 - r7}
KeccakP1600times2_AddLanesAll_Loop
    ldr     r4, [r1], #4            ; index 0
    ldr     r5, [r1], #4
    ldrd    r6, r7, [r0]
    eor     r6, r6, r4
    eor     r7, r7, r5
    strd    r6, r7, [r0], #8
    ldr     r4, [r3], #4            ; index 1
    ldr     r5, [r3], #4
    ldrd    r6, r7, [r0]
    eor     r6, r6, r4
    eor     r7, r7, r5
    strd    r6, r7, [r0], #8
    subs    r2, r2, #1
    bne     KeccakP1600times2_AddLanesAll_Loop
    pop     {r4 - r7}
KeccakP1600times2_AddLanesAll_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_OverwriteBytes( KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data,
;                                   unsigned int offset, unsigned int length )
;
    ALIGN
    EXPORT  KeccakP1600times2_OverwriteBytes
KeccakP1600times2_OverwriteBytes    PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    ldr     r1, [sp, #0*4]              ; r1 = length
    cmp     r1, #0
    beq     KeccakP1600times2_OverwriteBytes_Exit
    push    { r4-r5 }
    lsr     r4, r3, #3                  ; states += (offset & ~7) * 2
    add     r0, r0, r4, LSL #4
    ands    r3, r3, #7                  ; if (offset & 7) != 0
    beq     KeccakP1600times2_OverwriteBytes_CheckLanes
    add     r0, r0, r3                  ; states += offset & 7
    rsb     r3, r3, #8                  ; lenInLane = 8 - (offset & 7)
KeccakP1600times2_OverwriteBytes_LoopBytesFirst
    ldrb    r4, [r2], #1
    strb    r4, [r0], #1
    subs    r1, r1, #1
    beq     KeccakP1600times2_OverwriteBytes_Done
    subs    r3, r3, #1
    bne     KeccakP1600times2_OverwriteBytes_LoopBytesFirst
    add     r0, r0, #8                  ; states += 8 (next lane of current state part)
KeccakP1600times2_OverwriteBytes_CheckLanes
    lsrs    r3, r1, #3
    beq     KeccakP1600times2_OverwriteBytes_CheckBytesLast
KeccakP1600times2_OverwriteBytes_LoopLanes
    ldr     r4, [r2], #4
    ldr     r5, [r2], #4
    str     r4, [r0], #4
    str     r5, [r0], #12               ; states += 8 (next lane of current state part)
    subs    r3, r3, #1
    bne     KeccakP1600times2_OverwriteBytes_LoopLanes
KeccakP1600times2_OverwriteBytes_CheckBytesLast
    ands    r1, r1, #7
    beq     KeccakP1600times2_OverwriteBytes_Done
KeccakP1600times2_OverwriteBytes_LoopBytesLast
    ldrb    r4, [r2], #1
    subs    r1, r1, #1
    strb    r4, [r0], #1
    bne     KeccakP1600times2_OverwriteBytes_LoopBytesLast
KeccakP1600times2_OverwriteBytes_Done
    pop     { r4- r5 }
KeccakP1600times2_OverwriteBytes_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; KeccakP1600times2_OverwriteLanesAll( KeccakP1600times2_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset )
;
    ALIGN
    EXPORT  KeccakP1600times2_OverwriteLanesAll
KeccakP1600times2_OverwriteLanesAll PROC
    cmp     r2, #0
    beq     KeccakP1600times2_OverwriteLanesAll_Exit
    lsls    r12, r1, #32-3
    bne     KeccakP1600times2_OverwriteLanesAll_Unaligned
    add     r3, r1, r3, LSL #3      ; r3(pointer instance 1): data + 8 * laneOffset
    lsrs    r2, r2, #1
    bcc     KeccakP1600times2_OverwriteLanesAll_LoopAligned
    vldm    r1!, { d0 }
    vldm    r3!, { d1 }
    vstm    r0!, { d0 - d1 }
    beq     KeccakP1600times2_OverwriteLanesAll_Exit
KeccakP1600times2_OverwriteLanesAll_LoopAligned
    vldm    r1!, { d0 }
    vldm    r1!, { d2 }
    vldm    r3!, { d1 }
    vldm    r3!, { d3 }
    subs    r2, r2, #1
    vstm    r0!, { d0 - d3 }
    bne     KeccakP1600times2_OverwriteLanesAll_LoopAligned
    bx      lr
KeccakP1600times2_OverwriteLanesAll_Unaligned
    add     r3, r1, r3, LSL #3      ; r3(pointer instance 1): data + 8 * laneOffset
    push    { r4, r5 }
KeccakP1600times2_OverwriteLanesAll_LoopUnaligned
    ldr     r4, [r1], #4
    ldr     r5, [r1], #4
    strd    r4, r5, [r0], #8
    ldr     r4, [r3], #4
    ldr     r5, [r3], #4
    subs    r2, r2, #1
    strd    r4, r5, [r0], #8
    bne     KeccakP1600times2_OverwriteLanesAll_LoopUnaligned
    pop     { r4, r5 }
KeccakP1600times2_OverwriteLanesAll_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_OverwriteWithZeroes( KeccakP1600times2_states *states, unsigned int instanceIndex, unsigned int byteCount )
;
    ALIGN
    EXPORT  KeccakP1600times2_OverwriteWithZeroes
KeccakP1600times2_OverwriteWithZeroes   PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    lsrs    r1, r2, #3                  ; r1: laneCount
    beq     KeccakP1600times2_OverwriteWithZeroes_Bytes
    vmov.i64 d0, #0
KeccakP1600times2_OverwriteWithZeroes_LoopLanes
    subs    r1, r1, #1
    vstm    r0!, { d0 }
    add     r0, r0, #8
    bne     KeccakP1600times2_OverwriteWithZeroes_LoopLanes
KeccakP1600times2_OverwriteWithZeroes_Bytes
    ands    r2, r2, #7                  ; r2: byteCount remaining
    beq     KeccakP1600times2_OverwriteWithZeroes_Exit
    movs    r3, #0
KeccakP1600times2_OverwriteWithZeroes_LoopBytes
    subs    r2, r2, #1
    strb    r3, [r0], #1
    bne     KeccakP1600times2_OverwriteWithZeroes_LoopBytes
KeccakP1600times2_OverwriteWithZeroes_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_ExtractBytes( KeccakP1600times2_states *states, unsigned int instanceIndex, const unsigned char *data,
;                                   unsigned int offset, unsigned int length )
;
    ALIGN
    EXPORT  KeccakP1600times2_ExtractBytes
KeccakP1600times2_ExtractBytes   PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    ldr     r1, [sp, #0*4]              ; r1 = length
    cmp     r1, #0
    beq     KeccakP1600times2_ExtractBytes_Exit
    push    { r4-r5 }
    lsr     r4, r3, #3                  ; states += (offset & ~7) * 2
    add     r0, r0, r4, LSL #4
    ands    r3, r3, #7                  ; if (offset & 7) != 0
    beq     KeccakP1600times2_ExtractBytes_CheckLanes
    add     r0, r0, r3                  ; states += offset & 7
    rsb     r3, r3, #8                  ; lenInLane = 8 - (offset & 7)
KeccakP1600times2_ExtractBytes_LoopBytesFirst
    ldrb    r4, [r0], #1
    strb    r4, [r2], #1
    subs    r1, r1, #1
    beq     KeccakP1600times2_ExtractBytes_Done
    subs    r3, r3, #1
    bne     KeccakP1600times2_ExtractBytes_LoopBytesFirst
    add     r0, r0, #8                  ; states += 8 (next lane of current state part)
KeccakP1600times2_ExtractBytes_CheckLanes
    lsrs    r3, r1, #3
    beq     KeccakP1600times2_ExtractBytes_CheckBytesLast
KeccakP1600times2_ExtractBytes_LoopLanes
    ldr     r4, [r0], #4
    ldr     r5, [r0], #12               ; states += 8 (next lane of current state part)
    str     r4, [r2], #4
    str     r5, [r2], #4
    subs    r3, r3, #1
    bne     KeccakP1600times2_ExtractBytes_LoopLanes
KeccakP1600times2_ExtractBytes_CheckBytesLast
    ands    r1, r1, #7
    beq     KeccakP1600times2_ExtractBytes_Done
KeccakP1600times2_ExtractBytes_LoopBytesLast
    ldrb    r4, [r0], #1
    subs    r1, r1, #1
    strb    r4, [r2], #1
    bne     KeccakP1600times2_ExtractBytes_LoopBytesLast
KeccakP1600times2_ExtractBytes_Done
    pop     { r4-r5 }
KeccakP1600times2_ExtractBytes_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_ExtractLanesAll( const KeccakP1600times2_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset )
;
    ALIGN
    EXPORT  KeccakP1600times2_ExtractLanesAll
KeccakP1600times2_ExtractLanesAll   PROC
    cmp     r2, #0
    beq     KeccakP1600times2_ExtractLanesAll_Exit
    lsls    r12, r1, #32-3
    bne     KeccakP1600times2_ExtractLanesAll_Unaligned
    add     r3, r1, r3, LSL #3      ; r3(pointer instance 1): data + 8 * laneOffset
    lsrs    r2, r2, #1
    bcc     KeccakP1600times2_ExtractLanesAll_LoopAligned
    vldm    r0!, { d0 - d1 }
    vstm    r1!, { d0 }
    vstm    r3!, { d1 }
    beq     KeccakP1600times2_ExtractLanesAll_Exit
KeccakP1600times2_ExtractLanesAll_LoopAligned
    vldm    r0!, { d0 - d3 }
    subs    r2, r2, #1
    vstm    r1!, { d0 }
    vstm    r1!, { d2 }
    vstm    r3!, { d1 }
    vstm    r3!, { d3 }
    bne     KeccakP1600times2_ExtractLanesAll_LoopAligned
    bx      lr
KeccakP1600times2_ExtractLanesAll_Unaligned
    add     r3, r1, r3, LSL #3      ; r3(pointer instance 1): data + 8 * laneOffset
    push    { r4, r5 }
KeccakP1600times2_ExtractLanesAll_LoopUnaligned
    ldrd    r4, r5, [r0], #8
    str     r4, [r1], #4
    str     r5, [r1], #4
    ldrd    r4, r5, [r0], #8
    subs    r2, r2, #1
    str     r4, [r3], #4
    str     r5, [r3], #4
    bne     KeccakP1600times2_ExtractLanesAll_LoopUnaligned
    pop     { r4, r5 }
KeccakP1600times2_ExtractLanesAll_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_ExtractAndAddBytes(    KeccakP1600times2_states *states, unsigned int instanceIndex,
;                                           const unsigned char *input, unsigned char *output,
;                                           unsigned int offset, unsigned int length )
;
    ALIGN
    EXPORT  KeccakP1600times2_ExtractAndAddBytes
KeccakP1600times2_ExtractAndAddBytes   PROC
    add     r0, r0, r1, LSL #3          ; states += 8 * instanceIndex
    ldr     r1, [sp, #1*4]              ; r1 = length
    cmp     r1, #0
    beq     KeccakP1600times2_ExtractAndAddBytes_Exit
    push    { r4 - r9 }
    ldr     r8, [sp, #6*4]              ; r8 = offset
    lsr     r4, r8, #3                  ; states += (offset & ~7) * 2
    add     r0, r0, r4, LSL #4
    ands    r8, r8, #7                  ; if (offset & 7) != 0
    beq     KeccakP1600times2_ExtractAndAddBytes_CheckLanes
    add     r0, r0, r8                  ; states += offset & 7
    rsb     r8, r8, #8                  ; lenInLane = 8 - (offset & 7)
KeccakP1600times2_ExtractAndAddBytes_LoopBytesFirst
    ldrb    r4, [r0], #1
    ldrb    r5, [r2], #1
    eor     r4, r4, r5
    strb    r4, [r3], #1
    subs    r1, r1, #1
    beq     KeccakP1600times2_ExtractAndAddBytes_Done
    subs    r8, r8, #1
    bne     KeccakP1600times2_ExtractAndAddBytes_LoopBytesFirst
    add     r0, r0, #8                  ; states += 8 (next lane of current state part)
KeccakP1600times2_ExtractAndAddBytes_CheckLanes
    lsrs    r8, r1, #3
    beq     KeccakP1600times2_ExtractAndAddBytes_CheckBytesLast
KeccakP1600times2_ExtractAndAddBytes_LoopLanes
    ldr     r4, [r0], #4
    ldr     r5, [r0], #12
    ldr     r6, [r2], #4
    ldr     r7, [r2], #4
    eor     r4, r4, r6
    eor     r5, r5, r7
    str     r4, [r3], #4
    str     r5, [r3], #4                ; states += 8 (next lane of current state part)
    subs    r8, r8, #1
    bne     KeccakP1600times2_ExtractAndAddBytes_LoopLanes
KeccakP1600times2_ExtractAndAddBytes_CheckBytesLast
    ands    r1, r1, #7
    beq     KeccakP1600times2_ExtractAndAddBytes_Done
KeccakP1600times2_ExtractAndAddBytes_LoopBytesLast
    ldrb    r4, [r0], #1
    ldrb    r5, [r2], #1
    eor     r4, r4, r5
    strb    r4, [r3], #1
    subs    r1, r1, #1
    bne     KeccakP1600times2_ExtractAndAddBytes_LoopBytesLast
KeccakP1600times2_ExtractAndAddBytes_Done
    pop     { r4 - r9 }
KeccakP1600times2_ExtractAndAddBytes_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_ExtractAndAddLanesAll( const KeccakP1600times2_states *states,
;                                               const unsigned char *input, unsigned char *output,
;                                               unsigned int laneCount, unsigned int laneOffset )
;
    ALIGN
    EXPORT  KeccakP1600times2_ExtractAndAddLanesAll
KeccakP1600times2_ExtractAndAddLanesAll PROC
    cmp     r3, #0
    beq     KeccakP1600times2_ExtractAndAddLanesAll_Exit
    orr     r12, r1, r2
    lsls    r12, r12, #32-3         ; unaligned access if input or output unaligned 
    bne     KeccakP1600times2_ExtractAndAddLanesAll_Unaligned
    push    {r4,r5}
    ldr     r12, [sp, #2*4]         ; r12 = laneOffset
    lsrs    r3, r3, #1
    add     r4, r1, r12, LSL #3     ; r4(input instance 1): input + 8 * laneOffset
    add     r5, r2, r12, LSL #3     ; r5(output instance 1): output + 8 * laneOffset
    bcc     KeccakP1600times2_ExtractAndAddLanesAll_LoopAligned
    vldm    r0!, { d0 - d1 }
    vldm    r1!, { d2 }
    vldm    r4!, { d3 }
    veor    q0, q0, q1
    vstm    r2!, { d0 }
    vstm    r5!, { d1 }
    beq     KeccakP1600times2_ExtractAndAddLanesAll_AlignedDone
KeccakP1600times2_ExtractAndAddLanesAll_LoopAligned
    vldm    r0!, { d0 - d3 }
    vldm    r1!, { d4 }
    vldm    r1!, { d6 }
    vldm    r4!, { d5 }
    vldm    r4!, { d7 }
    subs    r3, r3, #1
    veor    q0, q0, q2
    veor    q1, q1, q3
    vstm    r2!, { d0 }
    vstm    r2!, { d2 }
    vstm    r5!, { d1 }
    vstm    r5!, { d3 }
    bne     KeccakP1600times2_ExtractAndAddLanesAll_LoopAligned
KeccakP1600times2_ExtractAndAddLanesAll_AlignedDone
    pop     {r4,r5}
    bx      lr
KeccakP1600times2_ExtractAndAddLanesAll_Unaligned
    push    {r4-r9}
    ldr     r12, [sp, #6*4]         ; r12 = laneOffset
    add     r4, r1, r12, LSL #3     ; r4(input instance 1): input + 8 * laneOffset
    add     r5, r2, r12, LSL #3     ; r5(output instance 1): output + 8 * laneOffset
KeccakP1600times2_ExtractAndAddLanesAll_LoopUnaligned
    ldrd    r8, r9, [r0], #8
    ldr     r6, [r1], #4
    ldr     r7, [r1], #4
    eor     r8, r8, r6
    eor     r9, r9, r7
    str     r8, [r2], #4
    str     r9, [r2], #4
    ldrd    r8, r9, [r0], #8
    ldr     r6, [r4], #4
    ldr     r7, [r4], #4
    eor     r8, r8, r6
    eor     r9, r9, r7
    str     r8, [r5], #4
    subs    r3, r3, #1
    str     r9, [r5], #4
    bne     KeccakP1600times2_ExtractAndAddLanesAll_LoopUnaligned
    pop     { r4 - r9 }
KeccakP1600times2_ExtractAndAddLanesAll_Exit
    bx      lr
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_PermuteAll_6rounds( KeccakP1600times2_states *states )
;
    ALIGN
    EXPORT  KeccakP1600times2_PermuteAll_6rounds
KeccakP1600times2_PermuteAll_6rounds   PROC
    adr     r1, KeccakP1600times2_Permute_RoundConstants6
    movs    r2, #6+2
    vpush   {q4-q7}
    push    {r4-r7}
    sub     sp, #4*2*8+8    ;allocate 4 D double lanes (plus 8bytes to allow alignment on 16 bytes)
    add     r5, sp, #8

    ; ba
    ; be = me, me = be
    ; bi = gi, gi = bi
    ; bo = so, so = bo
    ; bu = ku, ku = bu

    ; ga = sa, sa = ga
    ; ge = ke, ke = ge
    ; go = mo, mo = go
    ; gu

    ; ka = ma, ma = ka
    ; ki = si, si = ki
    ; ko

    ; mu = su, su = mu
    ; mi
    ; se

    ;PrepareTheta
    ; Ca = ba ^ ga ^ ka ^ ma ^ sa
    ; Ce = be ^ ge ^ ke ^ me ^ se
    ; Ci = bi ^ gi ^ ki ^ mi ^ si
    ; Co = bo ^ go ^ ko ^ mo ^ so
    ; Cu = bu ^ gu ^ ku ^ mu ^ su
    vldm    r0, { q0 - q4 }    ; ba be bi bo bu
    bic     r5, #15
    add     r3, r0, #_me
    vldm    r3, { q6 }                ; me
    vstm    r3, { q1 }
    veor.64 q1, q1, q6
    add     r4, r0, #_be
    vstm    r4!, { q6 }               ; be

    add     r3, r0, #_ga
    vldm    r3, { q10 - q14 }        ; ga ge gi go gu
    add     r3, r0, #_gi
    vstm    r3, { q2 }
    veor.64 q2, q2, q12
    vstm    r4!, { q12 }               ; bi

    add     r3, r0, #_so
    vldm    r3, { q8 }                ; so
    vstm    r3, { q3 }
    veor.64 q3, q3, q8
    vstm    r4!, { q8 }               ; bo

    add     r3, r0, #_ku
    vldm    r3, { q9 }                ; ku
    vstm    r3, { q4 }
    veor.64 q4, q4, q9
    vstm    r4!, { q9 }               ; bu

    add     r3, r0, #_sa
    vldm    r3, { q5 }                ; sa
    vstm    r3, { q10 }
    add     r4, r0, #_ga
    veor.64 q0, q0, q5
    veor.64 q0, q0, q10
    vstm    r4!, { q5 }               ; ga

    add     r3, r0, #_ke
    vldm    r3, { q6 }                ; ke
    vstm    r3, { q11 }
    veor.64 q1, q1, q6
    veor.64 q1, q1, q11
    vstm    r4!, { q6 }               ; ge

    add     r3, r0, #_mo
    vldm    r3, { q8 }                ; mo
    vstm    r3, { q13 }
    add     r4, r0, #_go
    veor.64 q3, q3, q8
    veor.64 q3, q3, q13
    vstm    r4!, { q8 }               ; go
    veor.64 q4, q4, q14           ; gu

    add     r4, r0, #_ka             ; ka
    vldm    r4, { q10 }
    add     r3, r0, #_ma            
    vldm    r3, { q5 }                ; ma
    vstm    r3, { q10 }
    veor.64 q0, q0, q5
    veor.64 q0, q0, q10
    vstm    r4!, { q5 }               ; ka

    add     r4, r0, #_ki             ; ki ko
    vldm    r4, { q12, q13 }
    add     r3, r0, #_si
    vldm    r3, { q7 }                ; si
    vstm    r3, { q12 }
    veor.64 q2, q2, q7
    veor.64 q2, q2, q12
    vstm    r4, { q7 }                ; ki
    veor.64 q3, q3, q13           ; ko

    add     r4, r0, #_mu             ; mu
    vldm    r4, { q14 }
    add     r3, r0, #_su
    vldm    r3, { q9 }                ; su
    vstm    r3, { q14 }
    veor.64 q4, q4, q9
    veor.64 q4, q4, q14
    vstm    r4, { q9 }                ; mu

    add     r4, r0, #_mi             ; mi
    vldm    r4, { q12 }
    veor.64 q2, q2, q12
    add     r3, r0, #_se             ; se
    vldm    r3, { q6 }
    veor.64 q1, q1, q6

    mov     r3, r0
    b       KeccakP1600times2_PermuteAll_Round2
    ENDP

    ALIGN
KeccakP1600times2_Permute_RoundConstants24
    dcq     0x0000000000000001
    dcq     0x0000000000008082
    dcq     0x800000000000808a
    dcq     0x8000000080008000
    dcq     0x000000000000808b
    dcq     0x0000000080000001
    dcq     0x8000000080008081
    dcq     0x8000000000008009
    dcq     0x000000000000008a
    dcq     0x0000000000000088
    dcq     0x0000000080008009
    dcq     0x000000008000000a
KeccakP1600times2_Permute_RoundConstants12
    dcq     0x000000008000808b
    dcq     0x800000000000008b
    dcq     0x8000000000008089
    dcq     0x8000000000008003
    dcq     0x8000000000008002
    dcq     0x8000000000000080
KeccakP1600times2_Permute_RoundConstants6
    dcq     0x000000000000800a
    dcq     0x800000008000000a
KeccakP1600times2_Permute_RoundConstants4
    dcq     0x8000000080008081
    dcq     0x8000000000008080
    dcq     0x0000000080000001
    dcq     0x8000000080008008

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_PermuteAll_24rounds( KeccakP1600times2_states *states )
;
    ALIGN
    EXPORT  KeccakP1600times2_PermuteAll_24rounds
KeccakP1600times2_PermuteAll_24rounds   PROC
    adr     r1, KeccakP1600times2_Permute_RoundConstants24
    movs    r2, #24
    b       KeccakP1600times2_PermuteAll
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_PermuteAll_12rounds( KeccakP1600times2_states *states )
;
    ALIGN
    EXPORT  KeccakP1600times2_PermuteAll_12rounds
KeccakP1600times2_PermuteAll_12rounds   PROC
    adr     r1, KeccakP1600times2_Permute_RoundConstants12
    movs    r2, #12
    b       KeccakP1600times2_PermuteAll
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_PermuteAll_4rounds( KeccakP1600times2_states *states )
;
    ALIGN
    EXPORT  KeccakP1600times2_PermuteAll_4rounds
KeccakP1600times2_PermuteAll_4rounds   PROC
    adr     r1, KeccakP1600times2_Permute_RoundConstants4
    movs    r2, #4
    b       KeccakP1600times2_PermuteAll
    ENDP

;----------------------------------------------------------------------------
;
; void KeccakP1600times2_PermuteAll( KeccakP1600times2_states *states, void *rc, unsigned int nr )
;
    ALIGN
KeccakP1600times2_PermuteAll   PROC
    vpush   {q4-q7}
    push    {r4-r7}
    sub     sp, #4*2*8+8    ;allocate 4 D double lanes (plus 8bytes to allow alignment on 16 bytes)
    mov     r3, r0
    add     r5, sp, #8

    ;PrepareTheta
    ; Ca = ba ^ ga ^ ka ^ ma ^ sa
    ; Ce = be ^ ge ^ ke ^ me ^ se
    ; Ci = bi ^ gi ^ ki ^ mi ^ si
    ; Co = bo ^ go ^ ko ^ mo ^ so
    ; Cu = bu ^ gu ^ ku ^ mu ^ su
    vld1.64 { d0, d1, d2, d3 }, [r3:256]!    ; _ba _be
    bic     r5, #15
    vld1.64 { d4, d5, d6, d7 }, [r3:256]!    ; _bi _bo
    vld1.64 { d8, d9, d10, d11 }, [r3:256]!    ; _bu _ga
    vld1.64 { d12, d13 }, [r3:128]!    ; _ge
    veor.64 q0, q0, q5
    vld1.64 { d14, d15 }, [r3:128]!    ; _gi
    veor.64 q1, q1, q6
    vld1.64 { d16, d17 }, [r3:128]!    ; _go
    veor.64 q2, q2, q7
    vld1.64 { d18, d19 }, [r3:128]!    ; _gu
    veor.64 q3, q3, q8
    vld1.64 { d10, d11 }, [r3:128]!    ; _ka
    veor.64 q4, q4, q9
    vld1.64 { d12, d13 }, [r3:128]!    ; _ke
    veor.64 q0, q0, q5
    vld1.64 { d14, d15 }, [r3:128]!    ; _ki
    veor.64 q1, q1, q6
    vld1.64 { d16, d17 }, [r3:128]!    ; _ko
    veor.64 q2, q2, q7
    vld1.64 { d18, d19 }, [r3:128]!    ; _ku
    veor.64 q3, q3, q8
    vld1.64 { d10, d11 }, [r3:128]!    ; _ma
    veor.64 q4, q4, q9
    vld1.64 { d12, d13 }, [r3:128]!    ; _me
    veor.64 q0, q0, q5
    vld1.64 { d14, d15 }, [r3:128]!    ; _mi
    veor.64 q1, q1, q6
    vld1.64 { d16, d17 }, [r3:128]!    ; _mo
    veor.64 q2, q2, q7
    vld1.64 { d18, d19 }, [r3:128]!    ; _mu
    veor.64 q3, q3, q8
    vld1.64 { d10, d11 }, [r3:128]!    ; _sa
    veor.64 q4, q4, q9
    vld1.64 { d12, d13 }, [r3:128]!    ; _se
    veor.64 q0, q0, q5
    vld1.64 { d14, d15 }, [r3:128]!    ; _si
    veor.64 q1, q1, q6
    vld1.64 { d16, d17 }, [r3:128]!    ; _so
    veor.64 q2, q2, q7
    vld1.64 { d18, d19 }, [r3:128]!    ; _su
    mov     r3, r0
    veor.64 q3, q3, q8
    veor.64 q4, q4, q9

KeccakP1600times2_PermuteAll_RoundLoop
    KeccakP_ThetaRhoPiChiIota  _ba,  -1,  -1,  -1,  -1, _ge-_ba, _ka ; _ba, _ge, _ki, _mo, _su
    KeccakP_ThetaRhoPiChi1     _ka,  -1,  -1,  _bo, -1, _me-_ka, _sa ; _ka, _me, _si, _bo, _gu
    KeccakP_ThetaRhoPiChi2     _sa, _be,  -1,  -1,  -1, _gi-_be, _ga ; _sa, _be, _gi, _ko, _mu
    KeccakP_ThetaRhoPiChi3     _ga,  -1,  -1,  -1, _bu, _ke-_ga, _ma ; _ga, _ke, _mi, _so, _bu
    KeccakP_ThetaRhoPiChi4     _ma,  -1, _bi,  -1,  -1, _se-_ma, _ba ; _ma, _se, _bi, _go, _ku

    KeccakP_ThetaRhoPiChiIota  _ba,  -1, _gi,  -1, _ku, _me-_ba, _sa ; _ba, _me, _gi, _so, _ku
    KeccakP_ThetaRhoPiChi1     _sa, _ke, _bi,  -1, _gu, _mo-_bi, _ma ; _sa, _ke, _bi, _mo, _gu
    KeccakP_ThetaRhoPiChi2     _ma, _ge,  -1, _ko, _bu, _si-_ge, _ka ; _ma, _ge, _si, _ko, _bu
    KeccakP_ThetaRhoPiChi3     _ka, _be,  -1, _go,  -1, _mi-_be, _ga ; _ka, _be, _mi, _go, _su
    KeccakP_ThetaRhoPiChi4     _ga,  -1, _ki, _bo,  -1, _se-_ga, _ba ; _ga, _se, _ki, _bo, _mu
KeccakP1600times2_PermuteAll_Round2
    KeccakP_ThetaRhoPiChiIota  _ba,  -1,  -1, _go,  -1, _ke-_ba, _ma ; _ba, _ke, _si, _go, _mu
    KeccakP_ThetaRhoPiChi1     _ma, _be,  -1,  -1, _gu, _ki-_be, _ga ; _ma, _be, _ki, _so, _gu
    KeccakP_ThetaRhoPiChi2     _ga,  -1, _bi,  -1,  -1, _me-_ga, _sa ; _ga, _me, _bi, _ko, _su
    KeccakP_ThetaRhoPiChi3     _sa, _ge,  -1, _bo,  -1, _mi-_ge, _ka ; _sa, _ge, _mi, _bo, _ku
    KeccakP_ThetaRhoPiChi4     _ka,  -1, _gi,  -1, _bu, _se-_ka, _ba ; _ka, _se, _gi, _mo, _bu

    KeccakP_ThetaRhoPiChiIota  _ba,  -1,  -1,  -1,  -1, _be-_ba, _ga ; _ba, _be, _bi, _bo, _bu
    KeccakP_ThetaRhoPiChi1     _ga,  -1,  -1,  -1,  -1, _ge-_ga, _ka ; _ga, _ge, _gi, _go, _gu
    KeccakP_ThetaRhoPiChi2     _ka,  -1,  -1,  -1,  -1, _ke-_ka, _ma ; _ka, _ke, _ki, _ko, _ku
    KeccakP_ThetaRhoPiChi3     _ma,  -1,  -1,  -1,  -1, _me-_ma, _sa ; _ma, _me, _mi, _mo, _mu
    subs    r2, #4
    KeccakP_ThetaRhoPiChi4     _sa,  -1,  -1,  -1,  -1, _se-_sa, _ba ; _sa, _se, _si, _so, _su
    bne     KeccakP1600times2_PermuteAll_RoundLoop
    add     sp, #4*2*8+8    ; free 4.5 D lanes
    pop     {r4-r7}
    vpop    {q4-q7}
    bx      lr
    ENDP

    END
