# =============================================================================
# Keccak-f[1600] x8 batched, AVX-512 — extension of keccak4a to 8 states
# =============================================================================
# Hand-edited from fd_keccak256_avx512_keccak4a.inc.  Round body is identical
# to keccak4a (zmm ops process all 8 lanes regardless of population); only
# the AoS<->SoA boundary transposes are widened to 8 states.
#
# Boundary transposes use the same s2n-style 4x4 ymm transpose, run twice
# (states 0-3 then 4-7), with results joined via vinserti64x4 to fill all 8
# zmm lanes per Keccak slot.
#
# Macro:    _fd_keccak256_avx512_keccak8a_f1600
# Inputs:   %rdi  pointer to 8 contiguous Keccak states (200 u64, 1600 B)
#           %rsi  pointer to 24-entry Keccak round-constant table
# Clobbers: %rax, %rcx, %rsi, %zmm0..%zmm15, ~1728 B stack scratch
# -----------------------------------------------------------------------------

.macro _fd_keccak256_avx512_keccak8a_f1600

    # Save %rsp into %rcx, align to 64 B, allocate 1728 B (0x6c0)
    movq    %rsp, %rcx
    andq    $0xffffffffffffffc0, %rsp
    subq    $0x6c0, %rsp

   # ===== Boundary 1: AoS -> SoA, 8 states =========================
   # Per group of 4 consecutive Keccak lanes z..z+3:
   #   Phase A: 4x4 transpose of states 0-3 -> ymm0..ymm3 (lane k → ymm[k-z])
   #   Phase B: 4x4 transpose of states 4-7 -> ymm8..ymm11
   #   Combine: zmm[k] = vinserti64x4(ymm[k-z+8] hi, ymm[k-z] lo)
   # A[0] (lane 0) lives in zmm5; A[1..24] go to stack slot k*0x40 - 0x40.
   # State s base offset in %rdi: s * 200 = {0,0xc8,0x190,0x258,0x320,0x3e8,0x4b0,0x578}.

   # ---- group 0: lanes 0-3 ----
   vmovdqu (%rdi), %ymm0
   vmovdqu 0xc8(%rdi), %ymm1
   vmovdqu 0x190(%rdi), %ymm2
   vmovdqu 0x258(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm5
   vpunpcklqdq %ymm3, %ymm2, %ymm6
   vpunpckhqdq %ymm3, %ymm2, %ymm7
   vperm2i128 $0x20, %ymm6, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm7, %ymm5, %ymm1
   vperm2i128 $0x31, %ymm6, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm7, %ymm5, %ymm3
   vmovdqu 0x320(%rdi), %ymm8
   vmovdqu 0x3e8(%rdi), %ymm9
   vmovdqu 0x4b0(%rdi), %ymm10
   vmovdqu 0x578(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm5
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, (%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x40(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x80(%rsp)

   # ---- group 1: lanes 4-7 ----
   vmovdqu 0x20(%rdi), %ymm0
   vmovdqu 0xe8(%rdi), %ymm1
   vmovdqu 0x1b0(%rdi), %ymm2
   vmovdqu 0x278(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu 0x340(%rdi), %ymm8
   vmovdqu 0x408(%rdi), %ymm9
   vmovdqu 0x4d0(%rdi), %ymm10
   vmovdqu 0x598(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0xc0(%rsp)
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x100(%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x140(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x180(%rsp)

   # ---- group 2: lanes 8-11 ----
   vmovdqu 0x40(%rdi), %ymm0
   vmovdqu 0x108(%rdi), %ymm1
   vmovdqu 0x1d0(%rdi), %ymm2
   vmovdqu 0x298(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu 0x360(%rdi), %ymm8
   vmovdqu 0x428(%rdi), %ymm9
   vmovdqu 0x4f0(%rdi), %ymm10
   vmovdqu 0x5b8(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0x1c0(%rsp)
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x200(%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x240(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x280(%rsp)

   # ---- group 3: lanes 12-15 ----
   vmovdqu 0x60(%rdi), %ymm0
   vmovdqu 0x128(%rdi), %ymm1
   vmovdqu 0x1f0(%rdi), %ymm2
   vmovdqu 0x2b8(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu 0x380(%rdi), %ymm8
   vmovdqu 0x448(%rdi), %ymm9
   vmovdqu 0x510(%rdi), %ymm10
   vmovdqu 0x5d8(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0x2c0(%rsp)
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x300(%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x340(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x380(%rsp)

   # ---- group 4: lanes 16-19 ----
   vmovdqu 0x80(%rdi), %ymm0
   vmovdqu 0x148(%rdi), %ymm1
   vmovdqu 0x210(%rdi), %ymm2
   vmovdqu 0x2d8(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu 0x3a0(%rdi), %ymm8
   vmovdqu 0x468(%rdi), %ymm9
   vmovdqu 0x530(%rdi), %ymm10
   vmovdqu 0x5f8(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0x3c0(%rsp)
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x400(%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x440(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x480(%rsp)

   # ---- group 5: lanes 20-23 ----
   vmovdqu 0xa0(%rdi), %ymm0
   vmovdqu 0x168(%rdi), %ymm1
   vmovdqu 0x230(%rdi), %ymm2
   vmovdqu 0x2f8(%rdi), %ymm3
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu 0x3c0(%rdi), %ymm8
   vmovdqu 0x488(%rdi), %ymm9
   vmovdqu 0x550(%rdi), %ymm10
   vmovdqu 0x618(%rdi), %ymm11
   vpunpcklqdq %ymm9, %ymm8, %ymm12
   vpunpckhqdq %ymm9, %ymm8, %ymm13
   vpunpcklqdq %ymm11, %ymm10, %ymm14
   vpunpckhqdq %ymm11, %ymm10, %ymm15
   vperm2i128 $0x20, %ymm14, %ymm12, %ymm8
   vperm2i128 $0x20, %ymm15, %ymm13, %ymm9
   vperm2i128 $0x31, %ymm14, %ymm12, %ymm10
   vperm2i128 $0x31, %ymm15, %ymm13, %ymm11
   vinserti64x4 $0x1, %ymm8, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0x4c0(%rsp)
   vinserti64x4 $0x1, %ymm9, %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x500(%rsp)
   vinserti64x4 $0x1, %ymm10, %zmm2, %zmm2
   vmovdqu64 %zmm2, 0x540(%rsp)
   vinserti64x4 $0x1, %ymm11, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x580(%rsp)

   # ---- lane 24 (single u64 per state) ----
   vmovq    0xc0(%rdi), %xmm0
   vpinsrq  $0x1, 0x188(%rdi), %xmm0, %xmm0
   vmovq    0x250(%rdi), %xmm1
   vpinsrq  $0x1, 0x318(%rdi), %xmm1, %xmm1
   vinserti128 $0x1, %xmm1, %ymm0, %ymm0
   vmovq    0x3e0(%rdi), %xmm2
   vpinsrq  $0x1, 0x4a8(%rdi), %xmm2, %xmm2
   vmovq    0x570(%rdi), %xmm3
   vpinsrq  $0x1, 0x638(%rdi), %xmm3, %xmm3
   vinserti128 $0x1, %xmm3, %ymm2, %ymm2
   vinserti64x4 $0x1, %ymm2, %zmm0, %zmm0
   vmovdqu64 %zmm0, 0x5c0(%rsp)

    # ---- 24-round loop ----
    movq    $0x0, %rax
1:



   vmovdqu64 0x100(%rsp), %zmm12
   vmovdqu64 0x240(%rsp), %zmm13
   vmovdqu64 0x380(%rsp), %zmm11
   vmovdqu64 0x4c0(%rsp), %zmm10
   vpxorq  %zmm12, %zmm5, %zmm1
   vpxorq  %zmm13, %zmm11, %zmm0
   vpxorq  %zmm0, %zmm1, %zmm1
   vpxorq  %zmm10, %zmm1, %zmm1

   vmovdqu64 (%rsp), %zmm4
   vmovdqu64 0x3c0(%rsp), %zmm6
   vpxorq  0x140(%rsp), %zmm4, %zmm8
   vpxorq  0x280(%rsp), %zmm6, %zmm0
   vpxorq  %zmm0, %zmm8, %zmm8
   vpxorq  0x500(%rsp), %zmm8, %zmm8

   vmovdqu64 0x40(%rsp), %zmm0
   vpxorq  0x180(%rsp), %zmm0, %zmm7
   vmovdqu64 0x400(%rsp), %zmm14
   vpxorq  0x2c0(%rsp), %zmm14, %zmm0
   vpxorq  %zmm0, %zmm7, %zmm7
   vpxorq  0x540(%rsp), %zmm7, %zmm7

   vmovdqu64 0x80(%rsp), %zmm3
   vpxorq  0x1c0(%rsp), %zmm3, %zmm6
   vmovdqu64 0x440(%rsp), %zmm0
   vpxorq  0x300(%rsp), %zmm0, %zmm0
   vpxorq  %zmm0, %zmm6, %zmm6
   vpxorq  0x580(%rsp), %zmm6, %zmm6

   vmovdqu64 0xc0(%rsp), %zmm4
   vpxorq  0x200(%rsp), %zmm4, %zmm2
   vmovdqu64 0x480(%rsp), %zmm0
   vpxorq  0x340(%rsp), %zmm0, %zmm0
   vpxorq  %zmm0, %zmm2, %zmm2
   vpxorq  0x5c0(%rsp), %zmm2, %zmm2








   vpsllq $0x1, %zmm8, %zmm4
   vpsrlq $0x3f, %zmm8, %zmm0
   vporq   %zmm0, %zmm4, %zmm4


   vpsllq $0x1, %zmm7, %zmm3
   vpsrlq $0x3f, %zmm7, %zmm0
   vporq   %zmm0, %zmm3, %zmm3


   vpsllq $0x1, %zmm6, %zmm0
   vpsrlq $0x3f, %zmm6, %zmm9
   vporq   %zmm9, %zmm0, %zmm0

   vpxorq  %zmm2, %zmm4, %zmm4
   vpxorq  %zmm1, %zmm3, %zmm3
   vpxorq  %zmm8, %zmm0, %zmm0


   vpsllq $0x1, %zmm2, %zmm8
   vpsrlq $0x3f, %zmm2, %zmm2
   vporq   %zmm8, %zmm2, %zmm2

   vpxorq  %zmm5, %zmm4, %zmm14
   vpxorq  0x180(%rsp), %zmm0, %zmm9
   vmovdqu64 %zmm9, 0x640(%rsp)
   vpxorq  %zmm12, %zmm4, %zmm15
   vpxorq  (%rsp), %zmm3, %zmm12
   vpxorq  0x280(%rsp), %zmm3, %zmm8
   vmovdqu64 %zmm14, 0x680(%rsp)
   vpxorq  %zmm13, %zmm4, %zmm14
   vpxorq  %zmm11, %zmm4, %zmm13
   vpxorq  0x140(%rsp), %zmm3, %zmm11
   vpxorq  %zmm10, %zmm4, %zmm4
   vpxorq  0x40(%rsp), %zmm0, %zmm10

   vpxorq  %zmm7, %zmm2, %zmm2


   vpsllq $0x1, %zmm1, %zmm7
   vpsrlq $0x3f, %zmm1, %zmm1
   vporq   %zmm7, %zmm1, %zmm1
   vpxorq  %zmm6, %zmm1, %zmm1

   vpxorq  0x3c0(%rsp), %zmm3, %zmm7
   vpxorq  0x500(%rsp), %zmm3, %zmm3
   vpxorq  0x80(%rsp), %zmm2, %zmm5
   vpxorq  0x2c0(%rsp), %zmm0, %zmm9
   vpxorq  0x400(%rsp), %zmm0, %zmm6
   vpxorq  0x540(%rsp), %zmm0, %zmm0
   vmovdqu64 %zmm5, (%rsp)
   vpxorq  0x1c0(%rsp), %zmm2, %zmm5
   vmovdqu64 %zmm5, 0x140(%rsp)
   vpxorq  0x300(%rsp), %zmm2, %zmm5
   vmovdqu64 %zmm5, 0x280(%rsp)
   vpxorq  0x440(%rsp), %zmm2, %zmm5
   vpxorq  0x580(%rsp), %zmm2, %zmm2
   vmovdqu64 %zmm5, 0x3c0(%rsp)
   vpxorq  0xc0(%rsp), %zmm1, %zmm5
   vmovdqu64 %zmm5, 0x500(%rsp)
   vpxorq  0x200(%rsp), %zmm1, %zmm5
   vmovdqu64 %zmm5, 0x40(%rsp)
   vpxorq  0x340(%rsp), %zmm1, %zmm5
   vmovdqu64 %zmm5, 0x2c0(%rsp)
   vpxorq  0x480(%rsp), %zmm1, %zmm5
   vmovdqu64 %zmm5, 0x400(%rsp)
   vpxorq  0x5c0(%rsp), %zmm1, %zmm1
   vmovdqu64 %zmm1, 0x80(%rsp)






























   vpsrlq $0x1c, %zmm15, %zmm1
   vpsllq $0x24, %zmm15, %zmm15
   vporq   %zmm1, %zmm15, %zmm1
   vmovdqu64 %zmm1, 0x480(%rsp)


   vpsrlq $0x3d, %zmm14, %zmm1
   vpsllq $0x3, %zmm14, %zmm14
   vporq   %zmm1, %zmm14, %zmm15
   vmovdqu64 %zmm15, 0x580(%rsp)


   vpsrlq $0x17, %zmm13, %zmm1
   vpsllq $0x29, %zmm13, %zmm13
   vporq   %zmm1, %zmm13, %zmm13
   vmovdqu64 %zmm13, 0x540(%rsp)


   vpsrlq $0x2e, %zmm4, %zmm1
   vpsllq $0x12, %zmm4, %zmm4
   vporq   %zmm1, %zmm4, %zmm4
   vmovdqu64 %zmm4, 0x300(%rsp)


   vpsrlq $0x3f, %zmm12, %zmm1
   vpsllq $0x1, %zmm12, %zmm12
   vporq   %zmm1, %zmm12, %zmm12
   vmovdqu64 %zmm12, 0x340(%rsp)


   vpsrlq $0x14, %zmm11, %zmm1
   vpsllq $0x2c, %zmm11, %zmm11
   vporq   %zmm1, %zmm11, %zmm11
   vmovdqu64 %zmm11, 0x200(%rsp)


   vpsrlq $0x36, %zmm8, %zmm1
   vpsllq $0xa, %zmm8, %zmm8
   vporq   %zmm1, %zmm8, %zmm8


   vpsrlq $0x13, %zmm7, %zmm1
   vpsllq $0x2d, %zmm7, %zmm7
   vporq   %zmm1, %zmm7, %zmm7


   vpsrlq $0x3e, %zmm3, %zmm1
   vpsllq $0x2, %zmm3, %zmm3
   vporq   %zmm1, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x5c0(%rsp)


   vpsrlq $0x2, %zmm10, %zmm1
   vpsllq $0x3e, %zmm10, %zmm10
   vporq   %zmm1, %zmm10, %zmm10
   vmovdqu64 %zmm10, 0xc0(%rsp)


   vmovdqu64 0x640(%rsp), %zmm3
   vpsllq $0x6, %zmm3, %zmm5
   vpsrlq $0x3a, %zmm3, %zmm1
   vporq   %zmm1, %zmm5, %zmm5


   vpsrlq $0x15, %zmm9, %zmm1
   vpsllq $0x2b, %zmm9, %zmm9
   vporq   %zmm1, %zmm9, %zmm9
   vmovdqu64 %zmm9, 0x640(%rsp)


   vpsrlq $0x31, %zmm6, %zmm1
   vpsllq $0xf, %zmm6, %zmm6
   vporq   %zmm1, %zmm6, %zmm6
   vmovdqu64 (%rsp), %zmm4


   vpsllq $0x1c, %zmm4, %zmm3
   vpsrlq $0x24, %zmm4, %zmm1
   vporq   %zmm1, %zmm3, %zmm3


    vmovdqu64 0x280(%rsp), %zmm9
   vpsllq $0x19, %zmm9, %zmm10
   vpsrlq $0x27, %zmm9, %zmm1
   vporq   %zmm1, %zmm10, %zmm10


   vpsrlq $0x3, %zmm0, %zmm1
   vpsllq $0x3d, %zmm0, %zmm0
   vporq   %zmm1, %zmm0, %zmm0


   vmovdqu64 0x2c0(%rsp), %zmm13
   vpsllq $0x27, %zmm13, %zmm14
   vpsrlq $0x19, %zmm13, %zmm12
   vporq   %zmm12, %zmm14, %zmm14


   vmovdqu64 0x140(%rsp), %zmm4
   vpsrlq $0x9, %zmm4, %zmm1
   vpsllq $0x37, %zmm4, %zmm4
   vporq   %zmm1, %zmm4, %zmm4


   vmovdqu64 0x3c0(%rsp), %zmm12
   vpsllq $0x15, %zmm12, %zmm11
   vpsrlq $0x2b, %zmm12, %zmm1
   vporq   %zmm1, %zmm11, %zmm11


   vpsrlq $0x8, %zmm2, %zmm1
   vpsllq $0x38, %zmm2, %zmm2
   vporq   %zmm1, %zmm2, %zmm2


   vmovdqu64 0x500(%rsp), %zmm1
   vpsrlq $0x25, %zmm1, %zmm9
   vpsllq $0x1b, %zmm1, %zmm1
   vporq   %zmm9, %zmm1, %zmm1


   vmovdqu64 0x40(%rsp), %zmm9
   vpsrlq $0x2c, %zmm9, %zmm12
   vpsllq $0x14, %zmm9, %zmm9
   vporq   %zmm12, %zmm9, %zmm9


   vmovdqu64 0x400(%rsp), %zmm13
   vpsrlq $0x38, %zmm13, %zmm12
   vpsllq $0x8, %zmm13, %zmm13
   vporq   %zmm12, %zmm13, %zmm13


   vmovdqu64 0x80(%rsp), %zmm12
   vpsrlq $0x32, %zmm12, %zmm15
   vpsllq $0xe, %zmm12, %zmm12
   vporq   %zmm15, %zmm12, %zmm12






























   vpandnq 0x580(%rsp), %zmm9, %zmm15
   vpxorq  %zmm3, %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x100(%rsp)


   vpandnq %zmm10, %zmm5, %zmm15
   vpxorq  0x340(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x240(%rsp)


   vmovdqu64 0x480(%rsp), %zmm15
   vpandnq %zmm8, %zmm15, %zmm15
   vpxorq  %zmm1, %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x380(%rsp)


   vpandnq %zmm14, %zmm4, %zmm15
   vpxorq  0xc0(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x4c0(%rsp)


   vmovdqu64 0x640(%rsp), %zmm15
   vpandnq %zmm11, %zmm15, %zmm15
   vpxorq  0x200(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, (%rsp)


   vmovdqu64 0x580(%rsp), %zmm15
   vpandnq %zmm7, %zmm15, %zmm15
   vpxorq  %zmm9, %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x140(%rsp)


   vpandnq %zmm13, %zmm10, %zmm15
   vpxorq  %zmm5, %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x280(%rsp)


   vpandnq %zmm6, %zmm8, %zmm15
   vpxorq  0x480(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x3c0(%rsp)


   vpandnq 0x540(%rsp), %zmm14, %zmm15
   vpxorq  %zmm4, %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x500(%rsp)


   vpandnq %zmm12, %zmm11, %zmm15
   vpxorq  0x640(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x40(%rsp)


   vpandnq %zmm0, %zmm7, %zmm15
   vpxorq  0x580(%rsp), %zmm15, %zmm15
   vmovdqu64 %zmm15, 0x180(%rsp)


   vpandnq 0x300(%rsp), %zmm13, %zmm15
   vpxorq  %zmm10, %zmm15, %zmm10
   vmovdqu64 %zmm10, 0x2c0(%rsp)


   vpandnq %zmm2, %zmm6, %zmm10
   vpxorq  %zmm8, %zmm10, %zmm8
   vmovdqu64 %zmm8, 0x400(%rsp)


   vmovdqu64 0x540(%rsp), %zmm10
   vmovdqu64 0x5c0(%rsp), %zmm15
   vpandnq %zmm15, %zmm10, %zmm8
   vpxorq  %zmm14, %zmm8, %zmm8
   vmovdqu64 %zmm8, 0x540(%rsp)


   vmovdqu64 0x680(%rsp), %zmm14
   vpandnq %zmm14, %zmm12, %zmm8
   vpxorq  %zmm11, %zmm8, %zmm8
   vmovdqu64 %zmm8, 0x80(%rsp)


   vpandnq %zmm3, %zmm0, %zmm8
   vpxorq  %zmm7, %zmm8, %zmm7
   vmovdqu64 %zmm7, 0x1c0(%rsp)


   vmovdqu64 0x300(%rsp), %zmm11
   vmovdqu64 0x340(%rsp), %zmm8
   vpandnq %zmm8, %zmm11, %zmm7
   vpxorq  %zmm13, %zmm7, %zmm7
   vmovdqu64 %zmm7, 0x300(%rsp)


   vmovdqu64 0x200(%rsp), %zmm13
   vpandnq %zmm9, %zmm3, %zmm3
   vpxorq  %zmm0, %zmm3, %zmm3
   vmovdqu64 %zmm3, 0x200(%rsp)


   vpandnq %zmm5, %zmm8, %zmm0
   vpxorq  %zmm11, %zmm0, %zmm3
   vmovdqu64 %zmm3, 0x340(%rsp)


   vpandnq %zmm1, %zmm2, %zmm7
   vpxorq  %zmm6, %zmm7, %zmm6
   vmovdqu64 %zmm6, 0x440(%rsp)


   vmovdqu64 %zmm15, %zmm6
   vmovdqu64 0xc0(%rsp), %zmm15
   vpandnq %zmm15, %zmm6, %zmm6
   vpxorq  %zmm10, %zmm6, %zmm7
   vmovdqu64 %zmm7, 0x580(%rsp)


   vpandnq 0x480(%rsp), %zmm1, %zmm1
   vpxorq  %zmm2, %zmm1, %zmm2
   vmovdqu64 %zmm2, 0x480(%rsp)


   vpandnq 0x640(%rsp), %zmm13, %zmm5
   vpxorq  %zmm14, %zmm5, %zmm5
   vpbroadcastq (%rsi), %zmm0
   vpxorq  %zmm0, %zmm5, %zmm5


   vpandnq %zmm13, %zmm14, %zmm6
   vpxorq  %zmm12, %zmm6, %zmm14
   vmovdqu64 %zmm14, 0xc0(%rsp)
   vpandnq %zmm4, %zmm15, %zmm0
   vpxorq  0x5c0(%rsp), %zmm0, %zmm6
   vmovdqu64 %zmm6, 0x5c0(%rsp)

    addq    $0x8, %rsi
    addq    $0x1, %rax
    cmpq    $0x18, %rax
    jne     1b



   # ===== Boundary 2: SoA -> AoS, 8 states =========================
   # Per group of 4 consecutive Keccak lanes z..z+3:
   #   Load 4 zmm slots (lane k = zmm with [s0..s7]); for group 0 lane 0
   #   is already in zmm5.  Split each zmm into lower ymm (s0..s3) and
   #   upper ymm (s4..s7) via vextracti64x4.  4x4 inverse-transpose each
   #   half, then store the 4 result ymm to %rdi at the per-state offset.
   # State output offsets are the same {0,0xc8,...,0x578} as boundary 1.

   # ---- group 0: lanes 0-3 ----
   # zmm5 already holds lane 0 (A0); lanes 1-3 from stack.
   vmovdqu64 (%rsp), %zmm1
   vmovdqu64 0x40(%rsp), %zmm2
   vmovdqu64 0x80(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm5, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm5, %ymm4
   vpunpckhqdq %ymm1, %ymm5, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm5
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm5, (%rdi)
   vmovdqu %ymm1, 0xc8(%rdi)
   vmovdqu %ymm2, 0x190(%rdi)
   vmovdqu %ymm3, 0x258(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x320(%rdi)
   vmovdqu %ymm13, 0x3e8(%rdi)
   vmovdqu %ymm14, 0x4b0(%rdi)
   vmovdqu %ymm15, 0x578(%rdi)

   # ---- group 1: lanes 4-7 ----
   vmovdqu64 0xc0(%rsp), %zmm0
   vmovdqu64 0x100(%rsp), %zmm1
   vmovdqu64 0x140(%rsp), %zmm2
   vmovdqu64 0x180(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm0, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm0, 0x20(%rdi)
   vmovdqu %ymm1, 0xe8(%rdi)
   vmovdqu %ymm2, 0x1b0(%rdi)
   vmovdqu %ymm3, 0x278(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x340(%rdi)
   vmovdqu %ymm13, 0x408(%rdi)
   vmovdqu %ymm14, 0x4d0(%rdi)
   vmovdqu %ymm15, 0x598(%rdi)

   # ---- group 2: lanes 8-11 ----
   vmovdqu64 0x1c0(%rsp), %zmm0
   vmovdqu64 0x200(%rsp), %zmm1
   vmovdqu64 0x240(%rsp), %zmm2
   vmovdqu64 0x280(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm0, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm0, 0x40(%rdi)
   vmovdqu %ymm1, 0x108(%rdi)
   vmovdqu %ymm2, 0x1d0(%rdi)
   vmovdqu %ymm3, 0x298(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x360(%rdi)
   vmovdqu %ymm13, 0x428(%rdi)
   vmovdqu %ymm14, 0x4f0(%rdi)
   vmovdqu %ymm15, 0x5b8(%rdi)

   # ---- group 3: lanes 12-15 ----
   vmovdqu64 0x2c0(%rsp), %zmm0
   vmovdqu64 0x300(%rsp), %zmm1
   vmovdqu64 0x340(%rsp), %zmm2
   vmovdqu64 0x380(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm0, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm0, 0x60(%rdi)
   vmovdqu %ymm1, 0x128(%rdi)
   vmovdqu %ymm2, 0x1f0(%rdi)
   vmovdqu %ymm3, 0x2b8(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x380(%rdi)
   vmovdqu %ymm13, 0x448(%rdi)
   vmovdqu %ymm14, 0x510(%rdi)
   vmovdqu %ymm15, 0x5d8(%rdi)

   # ---- group 4: lanes 16-19 ----
   vmovdqu64 0x3c0(%rsp), %zmm0
   vmovdqu64 0x400(%rsp), %zmm1
   vmovdqu64 0x440(%rsp), %zmm2
   vmovdqu64 0x480(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm0, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm0, 0x80(%rdi)
   vmovdqu %ymm1, 0x148(%rdi)
   vmovdqu %ymm2, 0x210(%rdi)
   vmovdqu %ymm3, 0x2d8(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x3a0(%rdi)
   vmovdqu %ymm13, 0x468(%rdi)
   vmovdqu %ymm14, 0x530(%rdi)
   vmovdqu %ymm15, 0x5f8(%rdi)

   # ---- group 5: lanes 20-23 ----
   vmovdqu64 0x4c0(%rsp), %zmm0
   vmovdqu64 0x500(%rsp), %zmm1
   vmovdqu64 0x540(%rsp), %zmm2
   vmovdqu64 0x580(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm0, %ymm12
   vextracti64x4 $0x1, %zmm1, %ymm13
   vextracti64x4 $0x1, %zmm2, %ymm14
   vextracti64x4 $0x1, %zmm3, %ymm15
   vpunpcklqdq %ymm1, %ymm0, %ymm4
   vpunpckhqdq %ymm1, %ymm0, %ymm6
   vpunpcklqdq %ymm3, %ymm2, %ymm7
   vpunpckhqdq %ymm3, %ymm2, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm0
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm1
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm2
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm3
   vmovdqu %ymm0, 0xa0(%rdi)
   vmovdqu %ymm1, 0x168(%rdi)
   vmovdqu %ymm2, 0x230(%rdi)
   vmovdqu %ymm3, 0x2f8(%rdi)
   vpunpcklqdq %ymm13, %ymm12, %ymm4
   vpunpckhqdq %ymm13, %ymm12, %ymm6
   vpunpcklqdq %ymm15, %ymm14, %ymm7
   vpunpckhqdq %ymm15, %ymm14, %ymm8
   vperm2i128 $0x20, %ymm7, %ymm4, %ymm12
   vperm2i128 $0x20, %ymm8, %ymm6, %ymm13
   vperm2i128 $0x31, %ymm7, %ymm4, %ymm14
   vperm2i128 $0x31, %ymm8, %ymm6, %ymm15
   vmovdqu %ymm12, 0x3c0(%rdi)
   vmovdqu %ymm13, 0x488(%rdi)
   vmovdqu %ymm14, 0x550(%rdi)
   vmovdqu %ymm15, 0x618(%rdi)

   # ---- lane 24 (single u64 per state) ----
   vmovdqu64 0x5c0(%rsp), %zmm3
   vextracti64x4 $0x1, %zmm3, %ymm0
   vextracti128 $0x0, %ymm3, %xmm1
   vextracti128 $0x1, %ymm3, %xmm2
   vmovq %xmm1, 0xc0(%rdi)
   vpextrq $0x1, %xmm1, 0x188(%rdi)
   vmovq %xmm2, 0x250(%rdi)
   vpextrq $0x1, %xmm2, 0x318(%rdi)
   vextracti128 $0x0, %ymm0, %xmm1
   vextracti128 $0x1, %ymm0, %xmm2
   vmovq %xmm1, 0x3e0(%rdi)
   vpextrq $0x1, %xmm1, 0x4a8(%rdi)
   vmovq %xmm2, 0x570(%rdi)
   vpextrq $0x1, %xmm2, 0x638(%rdi)


    # Restore %rsp
    movq    %rcx, %rsp
.endm
