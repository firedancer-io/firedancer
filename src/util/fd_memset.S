/*
 * Copyright (c) Facebook, Inc. and its affiliates.
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

/* Derived from Folly's folly/memset.S at commit
   0b150f5ba5d441042f682bf8375f6692cd3f7225. */

#if FD_HAS_AVX

        .file       "fd_memset.S"
        .section    .text,"ax"
        .p2align    5, 0x90
        .globl      fd_memset_avx
        .hidden     fd_memset_avx
        .type       fd_memset_avx, @function
fd_memset_avx:
        .cfi_startproc

        /* RDI is the buffer, RSI is the value, and RDX is the length. */
        vmovd       %esi, %xmm0
        vpbroadcastb %xmm0, %ymm0
        mov         %rdi, %rax
        cmp         $64, %rdx
        jae         .L_ms_above_64
        cmp         $32, %rdx
        jb          .L_ms_below_32
        vmovdqu     %ymm0, (%rdi)
        vmovdqu     %ymm0, -32(%rdi,%rdx)
        vzeroupper
        ret

        .align      32
.L_ms_below_32:
        cmp         $16, %rdx
        jae         .L_ms_16_to_32
        cmp         $4, %rdx
        jbe         .L_ms_below_4
        vmovq       %xmm0, %rsi
        cmp         $7, %rdx
        jbe         .L_ms_4_to_8
        mov         %rsi, -8(%rdi,%rdx)
        mov         %rsi, (%rdi)
        vzeroupper
        ret

        .align      32
.L_ms_below_4:
        vmovq       %xmm0, %rsi
        vzeroupper
        cmp         $1, %rdx
        jbe         .L_ms_none_or_one
        mov         %si, (%rdi)
        mov         %si, -2(%rdi,%rdx)
.L_ms_exit:
        ret

        .align      16
.L_ms_4_to_8:
        mov         %esi, -4(%rdi,%rdx)
        mov         %esi, (%rdi)
        vzeroupper
        ret

        .align      32
.L_ms_16_to_32:
        vmovups     %xmm0, (%rdi)
        vmovups     %xmm0, -16(%rdi,%rdx)
        vzeroupper
        ret

.L_ms_above_64:
        cmp         $176, %rdx
        ja          .L_ms_above_192
        cmp         $128, %rdx
        jbe         .L_ms_64_to_128

        lea         -32(%rdi,%rdx), %rsi
        vmovdqu     %ymm0, (%rdi)
        vmovdqu     %ymm0, 32(%rdi)
        vmovdqu     %ymm0, 64(%rdi)
        add         $96, %rdi

        .align      32
.L_ms_fill_32:
        vmovdqu     %ymm0, (%rdi)
        add         $32, %rdi
        cmp         %rdi, %rsi
        ja          .L_ms_fill_32
        vmovdqu     %ymm0, (%rsi)
        vzeroupper
        ret

        .align      32
.L_ms_64_to_128:
        vmovdqu     %ymm0, (%rdi)
        vmovdqu     %ymm0, 32(%rdi)
        vmovdqu     %ymm0, -64(%rdi,%rdx)
        vmovdqu     %ymm0, -32(%rdi,%rdx)
        vzeroupper
        ret

        .align      32
.L_ms_above_192:
        cmp         $4096, %rdx
        jae         .L_ms_large_stosq
        vmovdqu     %ymm0, (%rdi)
        mov         %rdi, %rsi
        mov         %rdi, %rax
        and         $-32, %rsi
        lea         32(%rsi), %rsi
        lea         -32(%rdx), %rdx
        add         %rdx, %rdi
        lea         160(%rsi), %rcx
        cmp         %rcx, %rdi
        jb          .L_ms_stamp_4

.L_ms_fill_192:
        vmovdqa     %ymm0, (%rsi)
        vmovdqa     %ymm0, 32(%rsi)
        vmovdqa     %ymm0, 64(%rsi)
        vmovdqa     %ymm0, 96(%rsi)
        vmovdqa     %ymm0, 128(%rsi)
        add         $160, %rsi
        lea         160(%rsi), %rcx
        cmp         %rcx, %rdi
        ja          .L_ms_fill_192

.L_ms_fill_192_tail:
        cmp         %rsi, %rdi
        jb          .L_ms_fill_192_done
        vmovdqa     %ymm0, (%rsi)
        lea         32(%rsi), %rcx
        cmp         %rcx, %rdi
        jb          .L_ms_fill_192_done
        vmovdqa     %ymm0, 32(%rsi)
        lea         64(%rsi), %rcx
        cmp         %rcx, %rdi
        jb          .L_ms_fill_192_done
        vmovdqa     %ymm0, 64(%rsi)
        lea         96(%rsi), %rcx
        cmp         %rcx, %rdi
        jb          .L_ms_fill_192_done
        vmovdqa     %ymm0, 96(%rsi)

.L_ms_last_wide_store:
        lea         128(%rsi), %rcx
        cmp         %rcx, %rdi
        jb          .L_ms_fill_192_done
        vmovdqa     %ymm0, 128(%rsi)

        .align      16
.L_ms_fill_192_done:
        vmovdqu     %ymm0, (%rdi)
        vzeroupper
        ret

.L_ms_stamp_4:
        vmovdqa     %ymm0, (%rsi)
        vmovdqa     %ymm0, 32(%rsi)
        vmovdqa     %ymm0, 64(%rsi)
        vmovdqa     %ymm0, 96(%rsi)
        jmp         .L_ms_last_wide_store

.L_ms_large_stosq:
        vmovq       %xmm0, %rax
        mov         %rax, (%rdi)
        mov         %rdi, %rsi
        and         $-8, %rdi
        lea         8(%rdi), %rdi
        mov         %rdx, %rcx
        sub         $8, %rcx
        shr         $3, %rcx
        rep stosq
        vmovdqu     %xmm0, -16(%rsi,%rdx)
        vzeroupper
        mov         %rsi, %rax
        ret

        .align      16
.L_ms_none_or_one:
        test        %rdx, %rdx
        je          .L_ms_exit
        mov         %sil, (%rdi)
        ret

        .cfi_endproc
        .size       fd_memset_avx, .-fd_memset_avx

#endif

#ifdef __linux__
        .section .note.GNU-stack,"",@progbits
#endif
