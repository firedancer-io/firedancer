# The kernels in this file all use this base calling convention:
#   fn( ulong                 shred_sz,     (rdi)
#       uchar const * const * input,        (rsi)
#       uchar       * const * output,       (rdx)
#       uchar       *         scratch,      (rcx)
#       uchar const *         erased )      (r8, mixed recovery only)
.section .rodata,"a",@progbits
gfni_const_tbl:
.align 64
.incbin "src/ballet/reedsol/constants/gfni_constants_avx512.bin"
.previous

# Make stack non-executable
.section .note.GNU-stack,"",@progbits

.text

/* The AVX-512 implementation uses 32 vector registers.  Keeping both lane
   widths in one template makes the carefully scheduled transform identical
   between the YMM and ZMM variants.  verify selects store (0), compare (1),
   or mixed store/compare (2).  reverse swaps the input and output domains. */
.macro fd_reedsol_private_32_32_impl name, vec, width, bcst, verify, reverse, prefetch, masked

.globl \name
\name:
.cfi_startproc
endbr64

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
# Recovery of all data from all parity uses the inverse pair: IFFT shifted by
# 32 followed by an unshifted FFT.
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
# vgf2p8affineqb requires encoding constants in a bizarre format, but
# we can just build a table that has these pre-encoded, so it's not a
# deal-breaker.
#
#
# AVX-512 supplies 32 vector registers.  The transform keeps 31 values in
# registers and spills one of values 14 and 31 when its register is needed as
# butterfly scratch.
#
# Register mapping:
#   * rax: position within each shred
#   * rbx: Temporary scalar variable, used for loading addresses
#   * r_i (for i in [8, 15]): Stores data_shred[ i-8 ]
#   * vec_i for i in [0, 14) and [15, 31): data from the ith transform line
#   * vec14 and vec31: transform data or butterfly scratch, depending on phase

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

# Load some values from data_shred into scalar registers to save loads later on.
# The mixed recover variant keeps its erased mask in r8 and reloads data_shred[0].
.if \verify!=2
mov        (%rsi),%r8
.endif
mov    0x08(%rsi),%r9
mov    0x10(%rsi),%r10
mov    0x18(%rsi),%r11
mov    0x20(%rsi),%r12
mov    0x28(%rsi),%r13
mov    0x30(%rsi),%r14
mov    0x38(%rsi),%r15

mov $0, %rax # Init shred_position
.if \masked
mov $-1, %rbx
bzhiq %rdi, %rbx, %rbx
kmovq %rbx, %k2
.endif
.if \verify
kxorq %k1, %k1, %k1
.endif

.altmacro
.macro input_load reg, ptr
.if \masked
  vmovdqu8 (%\ptr,%rax,1),%\vec\()\reg{%k2}{z}
.else
  vmovdqu64 (%\ptr,%rax,1),%\vec\()\reg
.endif
.if \prefetch
  prefetcht0 (2*\width)(%\ptr,%rax,1)
.endif
.endm

.align 16
outer_loop\@:
  # First handle the ones that we don't need to load from data_shred
.if \verify==2
  mov        (%rsi),%rbx
  input_load 0, rbx
.else
  input_load 0, r8
.endif
  input_load 1, r9
  input_load 2, r10
  input_load 3, r11
  input_load 4, r12
  input_load 5, r13
  input_load 6, r14
  input_load 7, r15

# load_inputs: load one vector's worth of data from (data_shred[ reg ] +
# shred_position) into the corresponding vector register.
.macro load_inputs reg
    mov (\reg* 8)(%rsi), %rbx
    input_load \reg, rbx
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
    vpxord %\vec\()\reg0, %\vec\()\reg1, %\vec\()\reg1
    vgf2p8affineqb $0x00, (gfni_const_tbl+8*(\const))(%rip){\bcst}, %\vec\()\reg1, %\vec\()\scratch_reg
    vpxord %\vec\()\reg0, %\vec\()\scratch_reg, %\vec\()\reg0
  .endm
  .macro ifft_butterfly_c0 reg0, reg1, scratch_reg
    vpxord %\vec\()\reg0, %\vec\()\reg1, %\vec\()\reg1
  .endm

  .macro fft_butterfly reg0, reg1, const, scratch_reg
    vgf2p8affineqb $0x00, (gfni_const_tbl+8*(\const))(%rip){\bcst}, %\vec\()\reg1, %\vec\()\scratch_reg
    vpxord %\vec\()\reg0, %\vec\()\scratch_reg, %\vec\()\reg0
    vpxord %\vec\()\reg1, %\vec\()\reg0, %\vec\()\reg1
  .endm
  .macro fft_butterfly_c0 reg0, reg1, scratch_reg
    vpxord %\vec\()\reg1, %\vec\()\reg0, %\vec\()\reg1
  .endm

  # Only registers 14 and 31 are spilled.  Two cache-line-aligned slots keep
  # the ZMM variant within the existing 1 KiB scratch allocation.
  .macro spill_reload spill, reload
    .if \spill==14
      vmovdqa64 %\vec\()\spill,   0(%rcx)
    .else
      vmovdqa64 %\vec\()\spill,  64(%rcx)
    .endif
    .if \reload==14
      vmovdqa64   0(%rcx), %\vec\()\reload
    .else
      vmovdqa64  64(%rcx), %\vec\()\reload
    .endif
  .endm

  # Store one generated output vector.  rdx names the parity array for the
  # forward transform and the data array for the reverse transform.
  .macro store_output reg
    .if \masked
      vmovdqu8 %\vec\()\reg, (%rbx, %rax, 1){%k2}
    .else
      vmovdqu64 %\vec\()\reg, (%rbx, %rax, 1)
    .endif
  .endm
  .macro compare_output reg, scratch_reg
    .if \masked
      vmovdqu8 (%rbx, %rax, 1), %\vec\()\scratch_reg{%k2}{z}
      vpcmpneqb %\vec\()\scratch_reg, %\vec\()\reg, %k0
    .else
      vpcmpneqb (%rbx, %rax, 1), %\vec\()\reg, %k0
    .endif
    korq %k0, %k1, %k1
  .endm
  .macro output_store reg, scratch_reg
    mov ((\reg )* 8)(%rdx), %rbx
    .if \verify==2
      cmpb $0, \reg(%r8)
      je 1f
      store_output \reg
      jmp 2f
1:
      compare_output \reg, \scratch_reg
2:
    .elseif \verify==1
      compare_output \reg, \scratch_reg
    .else
      store_output \reg
    .endif
  .endm

  # Spill vector 31 so it can serve as the initial butterfly scratch register.
  vmovdqa64 %\vec\()31, 64(%rcx)

.if \reverse
.include "src/ballet/reedsol/generated/fd_reedsol_gfni_32_reverse.inc"
.else
.include "src/ballet/reedsol/generated/fd_reedsol_gfni_32_encode.inc"
.endif

  # Advance by a vector, clamping the final unaligned block to the end of each
  # shred.  The masked short-vector variant completes in a single iteration.
.if \masked
  jmp   done\@
.else
  add   $\width, %rax
  cmp   %rdi, %rax
  je    done\@
  lea   -\width(%rdi), %rbx
  cmp   %rax, %rbx
  cmovb %rbx, %rax
  jmp   outer_loop\@
.endif

done\@:
.if \verify
xor     %eax, %eax
kortestq %k1, %k1
setne   %al
.endif
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

.purgem load_inputs
.purgem input_load
.purgem ifft_butterfly
.purgem ifft_butterfly_c0
.purgem fft_butterfly
.purgem fft_butterfly_c0
.purgem spill_reload
.purgem store_output
.purgem compare_output
.purgem output_store
.endm

fd_reedsol_private_32_32_impl fd_reedsol_private_encode_32_32,                    ymm, 32, 1to4, 0, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_encode_32_32_zmm,                zmm, 64, 1to8, 0, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_encode_32_32_zmm_prefetch,       zmm, 64, 1to8, 0, 0, 1, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_verify_32_32,                    ymm, 32, 1to4, 1, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_verify_32_32_zmm_mask,           zmm, 64, 1to8, 1, 0, 0, 1
fd_reedsol_private_32_32_impl fd_reedsol_private_verify_32_32_zmm,                zmm, 64, 1to8, 1, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_verify_32_32_zmm_prefetch,       zmm, 64, 1to8, 1, 0, 1, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_first_32_32,             ymm, 32, 1to4, 2, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_first_32_32_zmm,         zmm, 64, 1to8, 2, 0, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_first_32_32_zmm_prefetch, zmm, 64, 1to8, 2, 0, 1, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_data_32_32,              ymm, 32, 1to4, 0, 1, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_data_32_32_zmm,          zmm, 64, 1to8, 0, 1, 0, 0
fd_reedsol_private_32_32_impl fd_reedsol_private_recover_data_32_32_zmm_prefetch, zmm, 64, 1to8, 0, 1, 1, 0

# Advertise IBT, SHSTK compliance
.section ".note.gnu.property", "a"
.p2align 3
.long 1f - 0f
.long 4f - 1f
.long 5
0:
.byte 0x47, 0x4e, 0x55, 0
1:
.p2align 3
.long 0xc0000002
.long 3f - 2f
2:
.long 3
3:
.p2align 3
4:
