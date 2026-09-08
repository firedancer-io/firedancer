/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Derived from Folly's folly/memcpy.S at commit
   b12621520bceb89e6d48abc10d655f9582d0c043.  Unlike __folly_memcpy,
   fd_memcpy_avx does not implement memmove semantics: fd_memcpy's
   restrict-qualified contract makes overlap undefined. */

#if FD_HAS_AVX

#define REP_MOVSB_THRESHOLD $1024

        .file       "fd_memcpy.S"
        .section    .text,"ax"

        .type       fd_memcpy_avx_short, @function
fd_memcpy_avx_short:
        .cfi_startproc

.L_ge_1_le_7:
        cmp         $1, %rdx
        je          .L_eq_1
        cmp         $4, %rdx
        jae         .L_ge_4_le_7

.L_ge_2_le_3:
        movw        (%rsi), %r8w
        movw        -2(%rsi,%rdx), %r9w
        movw        %r8w, (%rdi)
        movw        %r9w, -2(%rdi,%rdx)
        ret

        .align      2
.L_eq_1:
        movb        (%rsi), %r8b
        movb        %r8b, (%rdi)
        ret

        /* Aligning a jump target to an even address has a measurable
           speedup in microbenchmarks. */
        .align      2
.L_ge_4_le_7:
        movl        (%rsi), %r8d
        movl        -4(%rsi,%rdx), %r9d
        movl        %r8d, (%rdi)
        movl        %r9d, -4(%rdi,%rdx)
        ret

        .cfi_endproc
        .size       fd_memcpy_avx_short, .-fd_memcpy_avx_short

        .align      64
        .globl      fd_memcpy_avx
        .hidden     fd_memcpy_avx
        .type       fd_memcpy_avx, @function
fd_memcpy_avx:
        .cfi_startproc

        mov         %rdi, %rax
        test        %rdx, %rdx
        je          .L_eq_0
        cmp         $8, %rdx
        jb          .L_ge_1_le_7
        cmp         $32, %rdx
        ja          .L_ge_33
        cmp         $16, %rdx
        ja          .L_ge_17_le_32

.L_ge_8_le_16:
        mov         (%rsi), %r8
        mov         -8(%rsi,%rdx), %r9
        mov         %r8, (%rdi)
        mov         %r9, -8(%rdi,%rdx)
.L_eq_0:
        ret

        .align      2
.L_ge_17_le_32:
        movdqu      (%rsi), %xmm0
        movdqu      -16(%rsi,%rdx), %xmm1
        movdqu      %xmm0, (%rdi)
        movdqu      %xmm1, -16(%rdi,%rdx)
        ret

        .align      2
.L_ge_193_le_256:
        vmovdqu     %ymm3, 96(%rdi)
        vmovdqu     %ymm4, -128(%rdi,%rdx)
.L_ge_129_le_192:
        vmovdqu     %ymm2, 64(%rdi)
        vmovdqu     %ymm5, -96(%rdi,%rdx)
.L_ge_65_le_128:
        vmovdqu     %ymm1, 32(%rdi)
        vmovdqu     %ymm6, -64(%rdi,%rdx)
.L_ge_33_le_64:
        vmovdqu     %ymm0, (%rdi)
        vmovdqu     %ymm7, -32(%rdi,%rdx)
        vzeroupper
        ret

        .align      2
.L_ge_33:
        cmp         $256, %rdx
        ja          .L_ge_257

.L_ge_33_le_256:
        vmovdqu     (%rsi), %ymm0
        vmovdqu     -32(%rsi,%rdx), %ymm7
        cmp         $64, %rdx
        jbe         .L_ge_33_le_64
        vmovdqu     32(%rsi), %ymm1
        vmovdqu     -64(%rsi,%rdx), %ymm6
        cmp         $128, %rdx
        jbe         .L_ge_65_le_128
        vmovdqu     64(%rsi), %ymm2
        vmovdqu     -96(%rsi,%rdx), %ymm5
        cmp         $192, %rdx
        jbe         .L_ge_129_le_192
        vmovdqu     96(%rsi), %ymm3
        vmovdqu     -128(%rsi,%rdx), %ymm4
        jmp         .L_ge_193_le_256

.L_ge_257:
        mov         %rdx, %rcx
        cmp         REP_MOVSB_THRESHOLD, %rdx
        jae         .L_copy_with_rep_movsb

.L_copy_with_loop:
        /* Fetch the final vector early; it is reused by the short-tail
           path after the unrolled loop. */
        vmovdqu     -32(%rsi,%rdx), %ymm4
        xor         %r8, %r8
        and         $-128, %rcx

        .align      16
.L_copy_loop_body:
        vmovdqu     (%rsi,%r8), %ymm0
        vmovdqu     32(%rsi,%r8), %ymm1
        vmovdqu     64(%rsi,%r8), %ymm2
        vmovdqu     96(%rsi,%r8), %ymm3
        vmovdqu     %ymm0, (%rdi,%r8)
        vmovdqu     %ymm1, 32(%rdi,%r8)
        vmovdqu     %ymm2, 64(%rdi,%r8)
        vmovdqu     %ymm3, 96(%rdi,%r8)
        add         $128, %r8
        cmp         %rcx, %r8
        jb          .L_copy_loop_body

        mov         %rdx, %rcx
        sub         %r8, %rdx
        cmp         $32, %rdx
        jbe         .L_tail_le_32
        add         %r8, %rsi
        add         %r8, %rdi
        jmp         .L_ge_33_le_256

.L_tail_le_32:
        vmovdqu     %ymm4, -32(%rdi,%rcx)
        vzeroupper
        ret

.L_copy_with_rep_movsb:
        rep movsb
        ret

        .cfi_endproc
        .size       fd_memcpy_avx, .-fd_memcpy_avx

#endif

#ifdef __linux__
        .section .note.GNU-stack,"",@progbits
#endif
