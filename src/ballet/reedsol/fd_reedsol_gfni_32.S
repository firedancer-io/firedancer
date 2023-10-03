# void
# fd_reedsol_private_encode_32_32( ulong                 shred_sz,      (rdi)
#                                  uchar const * const * data_shred,    (rsi)
#                                  uchar       * const * parity_shred,  (rdx)
#                                  uchar       *         _scratch )     (rcx)
.section .rodata,"a",@progbits
gfni_const_tbl:
.align 32
.incbin "src/ballet/reedsol/constants/gfni_constants.bin"
.previous

fd_reedsol_private_encode_32_32:
.globl fd_reedsol_private_encode_32_32
.cfi_startproc

# This file implements the FFT-like O(n log n) algorithm for computing Reed
# Solomon parity as described in
#   S. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
#   Polynomial Basis With Fast Fourier Transform and Its Application to
#   Reed–Solomon Erasure Codes," in IEEE Transactions on Information Theory,
#   vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi: 10.1109/TIT.2016.2608892.
#
# Like any FFT operation, the core of the computation is a "butterfly":
#
#   x_i >----------- + --\------->  y_i
#                   ^     \
#               *C /       \
#                 /         V
#   x_(i+2^k) >--/---------- + -->  y_(i+2^k)
#
#   i.e. y_i = x_i + C*x_(i+2^k), y_(i+2^k) = x_(i+2^k) + y_i
#
# Unlike typical FFT butterflies, these are not symmetric and only require one
# multiplication, but most of the ideas are similar.  We compute the parity
# shreds by:
#  1. Computing an IFFT with no shift on the data.  This finds the polynomial
#     that interpolates the data, as expressed in the coefficient basis.
#  2. Computing an FFT with a shift of 32 on the result of step 1. This
#     evaluates the polynomial at integers in [32, 64), which exactly gives us
#     the 32 parity shreds we need.
#
# See fd_reedsol_fft.h for more details about the algorithm.  This uses
# the same algorithm as fd_reedsol_fft.h, but this is at least 10%
# faster than the best compiled version of the C code.  Depending on the
# compiler, this can be much, much faster than the compiled C code.
#
# With GFNI, Intel gives us some very useful instructions, but they're
# not exactly the friendliest to use.  vgf2p8mulb seems perfect, but it
# uses the wrong reduction polynomial.  That's okay though, because we
# don't need a fully general GF(2^8) component-wise vector
# multiplication.  We only need GF(2^8) vector scaling, and we can
# achieve that with vgf2p8affineqb which has similar performance.  Using
# vgf2p8affineqb requires encoding constants in an bizarre format, but
# we can just build a table that has these pre-encoded, so it's not a
# deal-breaker.
#
#
# We have 32 working values, so we can almost do the whole thing in registers,
# but we do need at least one scratch register.
#
# Register mapping:
#   * rax: position within each shred
#   * rbx: Temporary scalar variable, used for loading addresses
#   * r_i (for i in [8, 15]): Stores data_shred[ i-8 ]
#   * ymm_i for i in [0, 14) and [15, 31): Stores 32B of data from the ith line
#          of computation
#   * ymm14: Sometimes stores data from the 14th line, sometimes a scratch
#          register used for the butterflies
#   * ymm31: Sometimes stores data from the 31st line, sometimes a scratch
#          register used for the butterflies

# Push registers we clobber
pushq   %r15
.cfi_def_cfa_offset 16
.cfi_offset 15, -16
pushq   %r14
.cfi_def_cfa_offset 24
.cfi_offset 14, -24
pushq   %r13
.cfi_def_cfa_offset 32
.cfi_offset 13, -32
pushq   %r12
.cfi_def_cfa_offset 40
.cfi_offset 12, -40
pushq   %rbx
.cfi_def_cfa_offset 48
.cfi_offset 3, -48

# Load some values from data_shred into scalar registers to save loads later on
mov        (%rsi),%r8
mov    0x08(%rsi),%r9
mov    0x10(%rsi),%r10
mov    0x18(%rsi),%r11
mov    0x20(%rsi),%r12
mov    0x28(%rsi),%r13
mov    0x30(%rsi),%r14
mov    0x38(%rsi),%r15

mov $0, %rax # Init shred_position

.align 16
outer_loop:
  # First handle the ones that we don't need to load from data_shred
  vmovdqu64 (%r8 ,%rax,1),%ymm0
  vmovdqu64 (%r9 ,%rax,1),%ymm1
  vmovdqu64 (%r10,%rax,1),%ymm2
  vmovdqu64 (%r11,%rax,1),%ymm3
  vmovdqu64 (%r12,%rax,1),%ymm4
  vmovdqu64 (%r13,%rax,1),%ymm5
  vmovdqu64 (%r14,%rax,1),%ymm6
  vmovdqu64 (%r15,%rax,1),%ymm7

.altmacro
# load_inputs: load one vector's worth of data from (data_shred[ reg ] +
# shred_position) into ymm_reg
.macro load_inputs reg
    mov (\reg* 8)(%rsi), %rbx
    vmovdqu64 (%rbx, %rax, 1), %ymm\reg
.endm

  load_inputs  8
  load_inputs  9
  load_inputs 10
  load_inputs 11
  load_inputs 12
  load_inputs 13
  load_inputs 14
  load_inputs 15
  load_inputs 16
  load_inputs 17
  load_inputs 18
  load_inputs 19
  load_inputs 20
  load_inputs 21
  load_inputs 22
  load_inputs 23
  load_inputs 24
  load_inputs 25
  load_inputs 26
  load_inputs 27
  load_inputs 28
  load_inputs 29
  load_inputs 30
  load_inputs 31 # 31 is our scratch right now

  # {i}fft_butterfly{_c0}: emit a butterfly operator on reg0 and reg1
  # that with a constant scalar of const (or 0 if _c0).  Use scratch_reg
  # for scratch, clobbering it.  reg0 and reg1 are modified in place.
  .macro ifft_butterfly reg0, reg1, const, scratch_reg
    vpxord %ymm\reg0, %ymm\reg1, %ymm\reg1
    vgf2p8affineqb $0x00, (gfni_const_tbl+32*(\const))(%rip), %ymm\reg1, %ymm\scratch_reg
    vpxord %ymm\reg0, %ymm\scratch_reg, %ymm\reg0
  .endm
  .macro ifft_butterfly_c0 reg0, reg1, scratch_reg
    vpxord %ymm\reg0, %ymm\reg1, %ymm\reg1
  .endm

  .macro fft_butterfly reg0, reg1, const, scratch_reg
    vgf2p8affineqb $0x00, (gfni_const_tbl+32*(\const))(%rip), %ymm\reg1, %ymm\scratch_reg
    vpxord %ymm\reg0, %ymm\scratch_reg, %ymm\reg0
    vpxord %ymm\reg1, %ymm\reg0, %ymm\reg1
  .endm
  .macro fft_butterfly_c0 reg0, reg1, scratch_reg
    vpxord %ymm\reg1, %ymm\reg0, %ymm\reg1
  .endm

  # spill_reload: spill register ymm\spill to its spot in scratch memory
  # and reload ymm\reload from its spot
  .macro spill_reload spill, reload
    vmovdqa64 %ymm\spill, (32*(\spill))(%rcx)
    vmovdqa64 (32*(\reload))(%rcx), %ymm\reload
  .endm

  # parity_store: store generated parity data in ymm\reg to
  # parity_shred[ reg ] + shred_position
  .macro parity_store reg
    mov ((\reg )* 8)(%rdx), %rbx
    vmovdqu64 %ymm\reg, (%rbx, %rax, 1)
  .endm

  # Spill ymm31 to its spot so we can use it as scratch and reload it using the spill_reload macro later
  vmovdqa64 %ymm31, (32*(31))(%rcx)

  ifft_butterfly_c0  0,  1,      31 # (0, 0, 0) and (0, 0, 1) => (0, 1, 0) and (1, 1, 0)
  ifft_butterfly     2,  3,   2, 31 # (0, 0, 2) and (0, 0, 3) => (0, 1, 2) and (1, 1, 2)
  ifft_butterfly     4,  5,   4, 31 # (0, 0, 4) and (0, 0, 5) => (0, 1, 4) and (1, 1, 4)
  ifft_butterfly     6,  7,   6, 31 # (0, 0, 6) and (0, 0, 7) => (0, 1, 6) and (1, 1, 6)
  ifft_butterfly     8,  9,   8, 31 # (0, 0, 8) and (0, 0, 9) => (0, 1, 8) and (1, 1, 8)
  ifft_butterfly    10, 11,  10, 31 # (0, 0, 10) and (0, 0, 11) => (0, 1, 10) and (1, 1, 10)
  ifft_butterfly    12, 13,  12, 31 # (0, 0, 12) and (0, 0, 13) => (0, 1, 12) and (1, 1, 12)
  ifft_butterfly    14, 15,  14, 31 # (0, 0, 14) and (0, 0, 15) => (0, 1, 14) and (1, 1, 14)
  ifft_butterfly    16, 17,  16, 31 # (0, 0, 16) and (0, 0, 17) => (0, 1, 16) and (1, 1, 16)
  ifft_butterfly    18, 19,  18, 31 # (0, 0, 18) and (0, 0, 19) => (0, 1, 18) and (1, 1, 18)
  ifft_butterfly    20, 21,  20, 31 # (0, 0, 20) and (0, 0, 21) => (0, 1, 20) and (1, 1, 20)
  ifft_butterfly    22, 23,  22, 31 # (0, 0, 22) and (0, 0, 23) => (0, 1, 22) and (1, 1, 22)
  ifft_butterfly    24, 25,  24, 31 # (0, 0, 24) and (0, 0, 25) => (0, 1, 24) and (1, 1, 24)
  ifft_butterfly    26, 27,  26, 31 # (0, 0, 26) and (0, 0, 27) => (0, 1, 26) and (1, 1, 26)
  ifft_butterfly    28, 29,  28, 31 # (0, 0, 28) and (0, 0, 29) => (0, 1, 28) and (1, 1, 28)
  ifft_butterfly_c0  0,  2,      31 # (0, 1, 0) and (0, 1, 2) => (0, 2, 0) and (2, 2, 0)
  ifft_butterfly     4,  6,   6, 31 # (0, 1, 4) and (0, 1, 6) => (0, 2, 4) and (2, 2, 4)
  ifft_butterfly     8, 10,  28, 31 # (0, 1, 8) and (0, 1, 10) => (0, 2, 8) and (2, 2, 8)
  ifft_butterfly    12, 14,  26, 31 # (0, 1, 12) and (0, 1, 14) => (0, 2, 12) and (2, 2, 12)
  ifft_butterfly    16, 18, 120, 31 # (0, 1, 16) and (0, 1, 18) => (0, 2, 16) and (2, 2, 16)
  ifft_butterfly    20, 22, 126, 31 # (0, 1, 20) and (0, 1, 22) => (0, 2, 20) and (2, 2, 20)
  ifft_butterfly    24, 26, 100, 31 # (0, 1, 24) and (0, 1, 26) => (0, 2, 24) and (2, 2, 24)
  ifft_butterfly_c0  0,  4,      31 # (0, 2, 0) and (0, 2, 4) => (0, 3, 0) and (4, 3, 0)
  ifft_butterfly     8, 12,  22, 31 # (0, 2, 8) and (0, 2, 12) => (0, 3, 8) and (4, 3, 8)
  ifft_butterfly    16, 20,  97, 31 # (0, 2, 16) and (0, 2, 20) => (0, 3, 16) and (4, 3, 16)
  ifft_butterfly_c0  0,  8,      31 # (0, 3, 0) and (0, 3, 8) => (0, 4, 0) and (8, 4, 0)
  ifft_butterfly_c0  4, 12,      31 # (4, 3, 0) and (4, 3, 8) => (4, 4, 0) and (12, 4, 0)
  ifft_butterfly_c0  2,  6,      31 # (2, 2, 0) and (2, 2, 4) => (2, 3, 0) and (6, 3, 0)
  ifft_butterfly    10, 14,  22, 31 # (2, 2, 8) and (2, 2, 12) => (2, 3, 8) and (6, 3, 8)
  ifft_butterfly    18, 22,  97, 31 # (2, 2, 16) and (2, 2, 20) => (2, 3, 16) and (6, 3, 16)
  ifft_butterfly_c0  2, 10,      31 # (2, 3, 0) and (2, 3, 8) => (2, 4, 0) and (10, 4, 0)
  ifft_butterfly_c0  6, 14,      31 # (6, 3, 0) and (6, 3, 8) => (6, 4, 0) and (14, 4, 0)
  ifft_butterfly_c0  1,  3,      31 # (1, 1, 0) and (1, 1, 2) => (1, 2, 0) and (3, 2, 0)
  ifft_butterfly     5,  7,   6, 31 # (1, 1, 4) and (1, 1, 6) => (1, 2, 4) and (3, 2, 4)
  ifft_butterfly     9, 11,  28, 31 # (1, 1, 8) and (1, 1, 10) => (1, 2, 8) and (3, 2, 8)
  ifft_butterfly    13, 15,  26, 31 # (1, 1, 12) and (1, 1, 14) => (1, 2, 12) and (3, 2, 12)
  ifft_butterfly    17, 19, 120, 31 # (1, 1, 16) and (1, 1, 18) => (1, 2, 16) and (3, 2, 16)
  ifft_butterfly    21, 23, 126, 31 # (1, 1, 20) and (1, 1, 22) => (1, 2, 20) and (3, 2, 20)
  ifft_butterfly    25, 27, 100, 31 # (1, 1, 24) and (1, 1, 26) => (1, 2, 24) and (3, 2, 24)
  ifft_butterfly_c0  1,  5,      31 # (1, 2, 0) and (1, 2, 4) => (1, 3, 0) and (5, 3, 0)
  ifft_butterfly     9, 13,  22, 31 # (1, 2, 8) and (1, 2, 12) => (1, 3, 8) and (5, 3, 8)
  ifft_butterfly    17, 21,  97, 31 # (1, 2, 16) and (1, 2, 20) => (1, 3, 16) and (5, 3, 16)
  ifft_butterfly_c0  1,  9,      31 # (1, 3, 0) and (1, 3, 8) => (1, 4, 0) and (9, 4, 0)
  ifft_butterfly_c0  5, 13,      31 # (5, 3, 0) and (5, 3, 8) => (5, 4, 0) and (13, 4, 0)
  ifft_butterfly_c0  3,  7,      31 # (3, 2, 0) and (3, 2, 4) => (3, 3, 0) and (7, 3, 0)
  ifft_butterfly    11, 15,  22, 31 # (3, 2, 8) and (3, 2, 12) => (3, 3, 8) and (7, 3, 8)
  ifft_butterfly    19, 23,  97, 31 # (3, 2, 16) and (3, 2, 20) => (3, 3, 16) and (7, 3, 16)
  ifft_butterfly_c0  3, 11,      31 # (3, 3, 0) and (3, 3, 8) => (3, 4, 0) and (11, 4, 0)
  ifft_butterfly_c0  7, 15,      31 # (7, 3, 0) and (7, 3, 8) => (7, 4, 0) and (15, 4, 0)
  spill_reload      14, 31          # spilling (14, 4, 0), reloading (0, 0, 31)
  ifft_butterfly    30, 31,  30, 14 # (0, 0, 30) and (0, 0, 31) => (0, 1, 30) and (1, 1, 30)
  ifft_butterfly    28, 30,  98, 14 # (0, 1, 28) and (0, 1, 30) => (0, 2, 28) and (2, 2, 28)
  ifft_butterfly    24, 28, 119, 14 # (0, 2, 24) and (0, 2, 28) => (0, 3, 24) and (4, 3, 24)
  ifft_butterfly    16, 24,  11, 14 # (0, 3, 16) and (0, 3, 24) => (0, 4, 16) and (8, 4, 16)
  ifft_butterfly_c0  0, 16,      14 # (0, 4, 0) and (0, 4, 16) => (0, 5, 0) and (16, 5, 0)
  ifft_butterfly_c0  8, 24,      14 # (8, 4, 0) and (8, 4, 16) => (8, 5, 0) and (24, 5, 0)
  ifft_butterfly    20, 28,  11, 14 # (4, 3, 16) and (4, 3, 24) => (4, 4, 16) and (12, 4, 16)
  ifft_butterfly_c0  4, 20,      14 # (4, 4, 0) and (4, 4, 16) => (4, 5, 0) and (20, 5, 0)
  ifft_butterfly_c0 12, 28,      14 # (12, 4, 0) and (12, 4, 16) => (12, 5, 0) and (28, 5, 0)
  ifft_butterfly    26, 30, 119, 14 # (2, 2, 24) and (2, 2, 28) => (2, 3, 24) and (6, 3, 24)
  ifft_butterfly    18, 26,  11, 14 # (2, 3, 16) and (2, 3, 24) => (2, 4, 16) and (10, 4, 16)
  ifft_butterfly_c0  2, 18,      14 # (2, 4, 0) and (2, 4, 16) => (2, 5, 0) and (18, 5, 0)
  ifft_butterfly_c0 10, 26,      14 # (10, 4, 0) and (10, 4, 16) => (10, 5, 0) and (26, 5, 0)
  ifft_butterfly    22, 30,  11, 14 # (6, 3, 16) and (6, 3, 24) => (6, 4, 16) and (14, 4, 16)
  ifft_butterfly_c0  6, 22,      14 # (6, 4, 0) and (6, 4, 16) => (6, 5, 0) and (22, 5, 0)
  ifft_butterfly    29, 31,  98, 14 # (1, 1, 28) and (1, 1, 30) => (1, 2, 28) and (3, 2, 28)
  ifft_butterfly    25, 29, 119, 14 # (1, 2, 24) and (1, 2, 28) => (1, 3, 24) and (5, 3, 24)
  ifft_butterfly    17, 25,  11, 14 # (1, 3, 16) and (1, 3, 24) => (1, 4, 16) and (9, 4, 16)
  ifft_butterfly_c0  1, 17,      14 # (1, 4, 0) and (1, 4, 16) => (1, 5, 0) and (17, 5, 0)
  ifft_butterfly_c0  9, 25,      14 # (9, 4, 0) and (9, 4, 16) => (9, 5, 0) and (25, 5, 0)
  ifft_butterfly    21, 29,  11, 14 # (5, 3, 16) and (5, 3, 24) => (5, 4, 16) and (13, 4, 16)
  ifft_butterfly_c0  5, 21,      14 # (5, 4, 0) and (5, 4, 16) => (5, 5, 0) and (21, 5, 0)
  ifft_butterfly_c0 13, 29,      14 # (13, 4, 0) and (13, 4, 16) => (13, 5, 0) and (29, 5, 0)
  ifft_butterfly    27, 31, 119, 14 # (3, 2, 24) and (3, 2, 28) => (3, 3, 24) and (7, 3, 24)
  ifft_butterfly    19, 27,  11, 14 # (3, 3, 16) and (3, 3, 24) => (3, 4, 16) and (11, 4, 16)
  ifft_butterfly_c0  3, 19,      14 # (3, 4, 0) and (3, 4, 16) => (3, 5, 0) and (19, 5, 0)
  ifft_butterfly_c0 11, 27,      14 # (11, 4, 0) and (11, 4, 16) => (11, 5, 0) and (27, 5, 0)
  ifft_butterfly    23, 31,  11, 14 # (7, 3, 16) and (7, 3, 24) => (7, 4, 16) and (15, 4, 16)
  ifft_butterfly_c0  7, 23,      14 # (7, 4, 0) and (7, 4, 16) => (7, 5, 0) and (23, 5, 0)
  ifft_butterfly_c0 15, 31,      14 # (15, 4, 0) and (15, 4, 16) => (15, 5, 0) and (31, 5, 0)
  spill_reload      31, 14          # spilling (31, 5, 0), reloading (14, 4, 0)
  ifft_butterfly_c0 14, 30,      31 # (14, 4, 0) and (14, 4, 16) => (14, 5, 0) and (30, 5, 0)
  fft_butterfly      0, 16,  71, 31 # (0, 5, 0) and (16, 5, 0) => (0, 4, 0) and (0, 4, 16)
  fft_butterfly      8, 24,  71, 31 # (8, 5, 0) and (24, 5, 0) => (8, 4, 0) and (8, 4, 16)
  fft_butterfly      0,  8, 174, 31 # (0, 4, 0) and (8, 4, 0) => (0, 3, 0) and (0, 3, 8)
  fft_butterfly     16, 24, 165, 31 # (0, 4, 16) and (8, 4, 16) => (0, 3, 16) and (0, 3, 24)
  fft_butterfly      4, 20,  71, 31 # (4, 5, 0) and (20, 5, 0) => (4, 4, 0) and (4, 4, 16)
  fft_butterfly     12, 28,  71, 31 # (12, 5, 0) and (28, 5, 0) => (12, 4, 0) and (12, 4, 16)
  fft_butterfly      4, 12, 174, 31 # (4, 4, 0) and (12, 4, 0) => (4, 3, 0) and (4, 3, 8)
  fft_butterfly     20, 28, 165, 31 # (4, 4, 16) and (12, 4, 16) => (4, 3, 16) and (4, 3, 24)
  fft_butterfly      0,  4,  38, 31 # (0, 3, 0) and (4, 3, 0) => (0, 2, 0) and (0, 2, 4)
  fft_butterfly      8, 12,  48, 31 # (0, 3, 8) and (4, 3, 8) => (0, 2, 8) and (0, 2, 12)
  fft_butterfly     16, 20,  71, 31 # (0, 3, 16) and (4, 3, 16) => (0, 2, 16) and (0, 2, 20)
  fft_butterfly     24, 28,  81, 31 # (0, 3, 24) and (4, 3, 24) => (0, 2, 24) and (0, 2, 28)
  fft_butterfly      2, 18,  71, 31 # (2, 5, 0) and (18, 5, 0) => (2, 4, 0) and (2, 4, 16)
  fft_butterfly     10, 26,  71, 31 # (10, 5, 0) and (26, 5, 0) => (10, 4, 0) and (10, 4, 16)
  fft_butterfly      2, 10, 174, 31 # (2, 4, 0) and (10, 4, 0) => (2, 3, 0) and (2, 3, 8)
  fft_butterfly     18, 26, 165, 31 # (2, 4, 16) and (10, 4, 16) => (2, 3, 16) and (2, 3, 24)
  fft_butterfly      6, 22,  71, 31 # (6, 5, 0) and (22, 5, 0) => (6, 4, 0) and (6, 4, 16)
  fft_butterfly     14, 30,  71, 31 # (14, 5, 0) and (30, 5, 0) => (14, 4, 0) and (14, 4, 16)
  fft_butterfly      6, 14, 174, 31 # (6, 4, 0) and (14, 4, 0) => (6, 3, 0) and (6, 3, 8)
  fft_butterfly     22, 30, 165, 31 # (6, 4, 16) and (14, 4, 16) => (6, 3, 16) and (6, 3, 24)
  fft_butterfly      2,  6,  38, 31 # (2, 3, 0) and (6, 3, 0) => (2, 2, 0) and (2, 2, 4)
  fft_butterfly     10, 14,  48, 31 # (2, 3, 8) and (6, 3, 8) => (2, 2, 8) and (2, 2, 12)
  fft_butterfly     18, 22,  71, 31 # (2, 3, 16) and (6, 3, 16) => (2, 2, 16) and (2, 2, 20)
  fft_butterfly     26, 30,  81, 31 # (2, 3, 24) and (6, 3, 24) => (2, 2, 24) and (2, 2, 28)
  fft_butterfly      0,  2, 237, 31 # (0, 2, 0) and (2, 2, 0) => (0, 1, 0) and (0, 1, 2)
  fft_butterfly      4,  6, 235, 31 # (0, 2, 4) and (2, 2, 4) => (0, 1, 4) and (0, 1, 6)
  fft_butterfly      8, 10, 241, 31 # (0, 2, 8) and (2, 2, 8) => (0, 1, 8) and (0, 1, 10)
  fft_butterfly     12, 14, 247, 31 # (0, 2, 12) and (2, 2, 12) => (0, 1, 12) and (0, 1, 14)
  fft_butterfly     16, 18, 149, 31 # (0, 2, 16) and (2, 2, 16) => (0, 1, 16) and (0, 1, 18)
  fft_butterfly     20, 22, 147, 31 # (0, 2, 20) and (2, 2, 20) => (0, 1, 20) and (0, 1, 22)
  fft_butterfly     24, 26, 137, 31 # (0, 2, 24) and (2, 2, 24) => (0, 1, 24) and (0, 1, 26)
  fft_butterfly     28, 30, 143, 31 # (0, 2, 28) and (2, 2, 28) => (0, 1, 28) and (0, 1, 30)
  fft_butterfly      1, 17,  71, 31 # (1, 5, 0) and (17, 5, 0) => (1, 4, 0) and (1, 4, 16)
  fft_butterfly      9, 25,  71, 31 # (9, 5, 0) and (25, 5, 0) => (9, 4, 0) and (9, 4, 16)
  fft_butterfly      1,  9, 174, 31 # (1, 4, 0) and (9, 4, 0) => (1, 3, 0) and (1, 3, 8)
  fft_butterfly     17, 25, 165, 31 # (1, 4, 16) and (9, 4, 16) => (1, 3, 16) and (1, 3, 24)
  fft_butterfly      5, 21,  71, 31 # (5, 5, 0) and (21, 5, 0) => (5, 4, 0) and (5, 4, 16)
  fft_butterfly     13, 29,  71, 31 # (13, 5, 0) and (29, 5, 0) => (13, 4, 0) and (13, 4, 16)
  fft_butterfly      5, 13, 174, 31 # (5, 4, 0) and (13, 4, 0) => (5, 3, 0) and (5, 3, 8)
  fft_butterfly     21, 29, 165, 31 # (5, 4, 16) and (13, 4, 16) => (5, 3, 16) and (5, 3, 24)
  fft_butterfly      1,  5,  38, 31 # (1, 3, 0) and (5, 3, 0) => (1, 2, 0) and (1, 2, 4)
  fft_butterfly      9, 13,  48, 31 # (1, 3, 8) and (5, 3, 8) => (1, 2, 8) and (1, 2, 12)
  fft_butterfly     17, 21,  71, 31 # (1, 3, 16) and (5, 3, 16) => (1, 2, 16) and (1, 2, 20)
  fft_butterfly     25, 29,  81, 31 # (1, 3, 24) and (5, 3, 24) => (1, 2, 24) and (1, 2, 28)
  fft_butterfly      3, 19,  71, 31 # (3, 5, 0) and (19, 5, 0) => (3, 4, 0) and (3, 4, 16)
  fft_butterfly     11, 27,  71, 31 # (11, 5, 0) and (27, 5, 0) => (11, 4, 0) and (11, 4, 16)
  fft_butterfly      3, 11, 174, 31 # (3, 4, 0) and (11, 4, 0) => (3, 3, 0) and (3, 3, 8)
  fft_butterfly     19, 27, 165, 31 # (3, 4, 16) and (11, 4, 16) => (3, 3, 16) and (3, 3, 24)
  fft_butterfly      7, 23,  71, 31 # (7, 5, 0) and (23, 5, 0) => (7, 4, 0) and (7, 4, 16)
  spill_reload      14, 31          # spilling (0, 1, 14), reloading (31, 5, 0)
  fft_butterfly     15, 31,  71, 14 # (15, 5, 0) and (31, 5, 0) => (15, 4, 0) and (15, 4, 16)
  fft_butterfly      7, 15, 174, 14 # (7, 4, 0) and (15, 4, 0) => (7, 3, 0) and (7, 3, 8)
  fft_butterfly     23, 31, 165, 14 # (7, 4, 16) and (15, 4, 16) => (7, 3, 16) and (7, 3, 24)
  fft_butterfly      3,  7,  38, 14 # (3, 3, 0) and (7, 3, 0) => (3, 2, 0) and (3, 2, 4)
  fft_butterfly     11, 15,  48, 14 # (3, 3, 8) and (7, 3, 8) => (3, 2, 8) and (3, 2, 12)
  fft_butterfly     19, 23,  71, 14 # (3, 3, 16) and (7, 3, 16) => (3, 2, 16) and (3, 2, 20)
  fft_butterfly     27, 31,  81, 14 # (3, 3, 24) and (7, 3, 24) => (3, 2, 24) and (3, 2, 28)
  fft_butterfly      1,  3, 237, 14 # (1, 2, 0) and (3, 2, 0) => (1, 1, 0) and (1, 1, 2)
  fft_butterfly      5,  7, 235, 14 # (1, 2, 4) and (3, 2, 4) => (1, 1, 4) and (1, 1, 6)
  fft_butterfly      9, 11, 241, 14 # (1, 2, 8) and (3, 2, 8) => (1, 1, 8) and (1, 1, 10)
  fft_butterfly     13, 15, 247, 14 # (1, 2, 12) and (3, 2, 12) => (1, 1, 12) and (1, 1, 14)
  fft_butterfly     17, 19, 149, 14 # (1, 2, 16) and (3, 2, 16) => (1, 1, 16) and (1, 1, 18)
  fft_butterfly     21, 23, 147, 14 # (1, 2, 20) and (3, 2, 20) => (1, 1, 20) and (1, 1, 22)
  fft_butterfly     25, 27, 137, 14 # (1, 2, 24) and (3, 2, 24) => (1, 1, 24) and (1, 1, 26)
  fft_butterfly     29, 31, 143, 14 # (1, 2, 28) and (3, 2, 28) => (1, 1, 28) and (1, 1, 30)
  fft_butterfly      0,  1,  32, 14 # (0, 1, 0) and (1, 1, 0) => (0, 0, 0) and (0, 0, 1)
  parity_store       0              # storing (0, 0, 0)
  parity_store       1              # storing (0, 0, 1)
  fft_butterfly      2,  3,  34, 14 # (0, 1, 2) and (1, 1, 2) => (0, 0, 2) and (0, 0, 3)
  parity_store       2              # storing (0, 0, 2)
  parity_store       3              # storing (0, 0, 3)
  fft_butterfly      4,  5,  36, 14 # (0, 1, 4) and (1, 1, 4) => (0, 0, 4) and (0, 0, 5)
  parity_store       4              # storing (0, 0, 4)
  parity_store       5              # storing (0, 0, 5)
  fft_butterfly      6,  7,  38, 14 # (0, 1, 6) and (1, 1, 6) => (0, 0, 6) and (0, 0, 7)
  parity_store       6              # storing (0, 0, 6)
  parity_store       7              # storing (0, 0, 7)
  fft_butterfly      8,  9,  40, 14 # (0, 1, 8) and (1, 1, 8) => (0, 0, 8) and (0, 0, 9)
  parity_store       8              # storing (0, 0, 8)
  parity_store       9              # storing (0, 0, 9)
  fft_butterfly     10, 11,  42, 14 # (0, 1, 10) and (1, 1, 10) => (0, 0, 10) and (0, 0, 11)
  parity_store      10              # storing (0, 0, 10)
  parity_store      11              # storing (0, 0, 11)
  fft_butterfly     12, 13,  44, 14 # (0, 1, 12) and (1, 1, 12) => (0, 0, 12) and (0, 0, 13)
  parity_store      12              # storing (0, 0, 12)
  parity_store      13              # storing (0, 0, 13)
  fft_butterfly     16, 17,  48, 14 # (0, 1, 16) and (1, 1, 16) => (0, 0, 16) and (0, 0, 17)
  parity_store      16              # storing (0, 0, 16)
  parity_store      17              # storing (0, 0, 17)
  fft_butterfly     18, 19,  50, 14 # (0, 1, 18) and (1, 1, 18) => (0, 0, 18) and (0, 0, 19)
  parity_store      18              # storing (0, 0, 18)
  parity_store      19              # storing (0, 0, 19)
  fft_butterfly     20, 21,  52, 14 # (0, 1, 20) and (1, 1, 20) => (0, 0, 20) and (0, 0, 21)
  parity_store      20              # storing (0, 0, 20)
  parity_store      21              # storing (0, 0, 21)
  fft_butterfly     22, 23,  54, 14 # (0, 1, 22) and (1, 1, 22) => (0, 0, 22) and (0, 0, 23)
  parity_store      22              # storing (0, 0, 22)
  parity_store      23              # storing (0, 0, 23)
  fft_butterfly     24, 25,  56, 14 # (0, 1, 24) and (1, 1, 24) => (0, 0, 24) and (0, 0, 25)
  parity_store      24              # storing (0, 0, 24)
  parity_store      25              # storing (0, 0, 25)
  fft_butterfly     26, 27,  58, 14 # (0, 1, 26) and (1, 1, 26) => (0, 0, 26) and (0, 0, 27)
  parity_store      26              # storing (0, 0, 26)
  parity_store      27              # storing (0, 0, 27)
  fft_butterfly     28, 29,  60, 14 # (0, 1, 28) and (1, 1, 28) => (0, 0, 28) and (0, 0, 29)
  parity_store      28              # storing (0, 0, 28)
  parity_store      29              # storing (0, 0, 29)
  fft_butterfly     30, 31,  62, 14 # (0, 1, 30) and (1, 1, 30) => (0, 0, 30) and (0, 0, 31)
  parity_store      30              # storing (0, 0, 30)
  parity_store      31              # storing (0, 0, 31)
  spill_reload      31, 14          # spilling (0, 0, 31), reloading (0, 1, 14)
  fft_butterfly     14, 15,  46, 31 # (0, 1, 14) and (1, 1, 14) => (0, 0, 14) and (0, 0, 15)
  parity_store      14              # storing (0, 0, 14)
  parity_store      15              # storing (0, 0, 15)

  # Advance shred position.  Normally it increases by 32, but if the shred size
  # is not a multiple of 32, then we clamp it down.  E.g. suppose rdi==33.  We
  # first run through the loop with rax==0.  Then we add 32 to rax and test
  # 32==33.  That's false, so then we reset rax=min(rax, rdi-32), e.g. rax=1.
  # We run through the loop again.  The second time, we add 32, getting
  # rax==33, so then we break.
  add   $0x20, %rax
  cmp   %rdi, %rax
  je    done
  lea   -0x20(%rdi), %rbx
  cmp   %rax, %rbx
  cmovb %rbx, %rax
  jmp   outer_loop

done:
popq    %rbx
.cfi_def_cfa_offset 40
popq    %r12
.cfi_def_cfa_offset 32
popq    %r13
.cfi_def_cfa_offset 24
popq    %r14
.cfi_def_cfa_offset 16
popq    %r15
.cfi_def_cfa_offset 8
ret
.align 16

.cfi_endproc
