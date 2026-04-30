# Auto-generated from gcc-15.1.0's compiled asm for fd_k8eo_perm.
# Do not edit by hand; rerun gen_keccak8_eo_inc_from_gcc.py.
#
# Macro: _fd_keccak256_avx2_keccak8_eo_f1600_raw \state \rc_eo
# Args:  \state=%rdi (state in EO SoA, 50 ymm = 1600 B), \rc_eo=%rsi (48 u32)
# Clobbers: ymm0..ymm15, rax, rcx, rdx, rsi, flags, ~1032 B stack scratch
# Caller must save rbp.

.macro _fd_keccak256_avx2_keccak8_eo_f1600_raw state, rc_eo
   /* C wrapper pins \state=%rdi (= ae base) and \rc_eo=%rdx. */
   /* Compute ao = state + 800 in %rsi as gcc's body expects. */
   leaq 800(\state), %rsi

   /* === Begin gcc-15 compiled body of fd_k8eo_perm === */
	pushq	%rbp
	leaq	192(%rdx), %rax
	movq	%rsp, %rbp
	andq	$-32, %rsp
	subq	$1032, %rsp
	vmovdqa	(%rsi), %ymm15
	.p2align 4
	.p2align 3
9999:
	vmovdqa	96(%rdi), %ymm6
	vpxor	256(%rdi), %ymm6, %ymm10
	vmovdqa	320(%rsi), %ymm6
	addq	$8, %rdx
	vpxor	160(%rsi), %ymm6, %ymm0
	vmovdqa	(%rdi), %ymm7
	vpxor	416(%rdi), %ymm10, %ymm10
	vpxor	160(%rdi), %ymm7, %ymm9
	vpxor	576(%rdi), %ymm10, %ymm10
	vmovdqa	32(%rdi), %ymm7
	vpxor	736(%rdi), %ymm10, %ymm10
	vpxor	192(%rdi), %ymm7, %ymm13
	vpxor	320(%rdi), %ymm9, %ymm9
	vmovdqa	64(%rdi), %ymm7
	vpxor	480(%rdi), %ymm9, %ymm9
	vpxor	224(%rdi), %ymm7, %ymm12
	vpxor	640(%rdi), %ymm9, %ymm9
	vmovdqa	128(%rdi), %ymm7
	vpxor	352(%rdi), %ymm13, %ymm13
	vpxor	288(%rdi), %ymm7, %ymm11
	vpxor	512(%rdi), %ymm13, %ymm13
	vmovdqa	32(%rsi), %ymm7
	vpxor	672(%rdi), %ymm13, %ymm13
	vpxor	192(%rsi), %ymm7, %ymm3
	vpxor	384(%rdi), %ymm12, %ymm12
	vpxor	%ymm15, %ymm0, %ymm0
	vpxor	544(%rdi), %ymm12, %ymm12
	vpxor	448(%rdi), %ymm11, %ymm11
	vpxor	704(%rdi), %ymm12, %ymm12
	vpxor	608(%rdi), %ymm11, %ymm11
	vpxor	480(%rsi), %ymm0, %ymm0
	vpxor	768(%rdi), %ymm11, %ymm11
	vpxor	640(%rsi), %ymm0, %ymm0
	vpxor	352(%rsi), %ymm3, %ymm3
	vpxor	512(%rsi), %ymm3, %ymm3
	vmovdqa	64(%rsi), %ymm6
	vpxor	672(%rsi), %ymm3, %ymm3
	vpxor	224(%rsi), %ymm6, %ymm4
	vpxor	384(%rsi), %ymm4, %ymm4
	vpxor	544(%rsi), %ymm4, %ymm4
	vpxor	704(%rsi), %ymm4, %ymm4
	vmovdqa	96(%rsi), %ymm7
	vpxor	256(%rsi), %ymm7, %ymm2
	vpxor	416(%rsi), %ymm2, %ymm2
	vpxor	576(%rsi), %ymm2, %ymm2
	vpxor	736(%rsi), %ymm2, %ymm2
	vmovdqa	128(%rsi), %ymm5
	vpxor	288(%rsi), %ymm5, %ymm1
	vpxor	448(%rsi), %ymm1, %ymm1
	vpxor	608(%rsi), %ymm1, %ymm1
	vpxor	%ymm12, %ymm0, %ymm14
	vpxor	768(%rsi), %ymm1, %ymm1
	vpsrld	$31, %ymm3, %ymm5
	vpslld	$1, %ymm3, %ymm7
	vpor	%ymm5, %ymm7, %ymm7
	vmovdqa	%ymm14, 1000(%rsp)
	vpsrld	$31, %ymm4, %ymm6
	vpslld	$1, %ymm4, %ymm5
	vpor	%ymm6, %ymm5, %ymm5
	vpxor	%ymm11, %ymm7, %ymm7
	vpxor	%ymm9, %ymm5, %ymm5
	vpxor	%ymm11, %ymm4, %ymm4
	vpsrld	$31, %ymm0, %ymm11
	vpslld	$1, %ymm0, %ymm0
	vpsrld	$31, %ymm2, %ymm14
	vpslld	$1, %ymm2, %ymm6
	vpxor	%ymm9, %ymm2, %ymm2
	vpor	%ymm14, %ymm6, %ymm6
	vmovdqa	1000(%rsp), %ymm14
	vpxor	32(%rsi), %ymm14, %ymm9
	vpor	%ymm11, %ymm0, %ymm0
	vpxor	%ymm10, %ymm3, %ymm3
	vpxor	%ymm13, %ymm1, %ymm8
	vpxor	%ymm10, %ymm0, %ymm0
	vpxor	%ymm13, %ymm6, %ymm6
	vpsrld	$31, %ymm1, %ymm13
	vpslld	$1, %ymm1, %ymm1
	vpor	%ymm13, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpxor	32(%rdi), %ymm5, %ymm12
	vpxor	(%rdi), %ymm7, %ymm13
	vpxor	%ymm15, %ymm8, %ymm15
	vpsrld	$31, %ymm9, %ymm10
	vpslld	$1, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm11
	vpxor	320(%rsi), %ymm8, %ymm9
	vmovdqa	%ymm11, -88(%rsp)
	vmovdqa	%ymm12, -120(%rsp)
	vmovdqa	%ymm13, 904(%rsp)
	vpsrld	$30, %ymm9, %ymm10
	vpslld	$2, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm10
	vpxor	320(%rdi), %ymm7, %ymm9
	vmovdqa	%ymm10, -56(%rsp)
	vpsrld	$31, %ymm9, %ymm10
	vpslld	$1, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, -24(%rsp)
	vpxor	224(%rdi), %ymm6, %ymm9
	vpsrld	$29, %ymm9, %ymm10
	vpslld	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm12
	vpxor	224(%rsi), %ymm3, %ymm9
	vmovdqa	%ymm12, 8(%rsp)
	vpsrld	$29, %ymm9, %ymm10
	vpslld	$3, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm11
	vmovdqa	%ymm11, 40(%rsp)
	vpxor	352(%rdi), %ymm5, %ymm9
	vpsrld	$27, %ymm9, %ymm10
	vpslld	$5, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm10
	vpxor	352(%rsi), %ymm14, %ymm9
	vmovdqa	%ymm10, 72(%rsp)
	vpsrld	$27, %ymm9, %ymm10
	vpslld	$5, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, 104(%rsp)
	vpxor	544(%rsi), %ymm3, %ymm9
	vpsrld	$24, %ymm9, %ymm10
	vpslld	$8, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm12
	vpxor	544(%rdi), %ymm6, %ymm9
	vmovdqa	%ymm12, 136(%rsp)
	vpsrld	$25, %ymm9, %ymm10
	vpslld	$7, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm11
	vpxor	576(%rsi), %ymm4, %ymm9
	vmovdqa	%ymm11, 168(%rsp)
	vpsrld	$21, %ymm9, %ymm10
	vpslld	$11, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm10
	vpxor	576(%rdi), %ymm1, %ymm9
	vmovdqa	%ymm10, 968(%rsp)
	vpsrld	$22, %ymm9, %ymm10
	vpslld	$10, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, 936(%rsp)
	vpxor	96(%rdi), %ymm1, %ymm9
	vpsrld	$18, %ymm9, %ymm10
	vpslld	$14, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm12
	vpxor	96(%rsi), %ymm4, %ymm9
	vmovdqa	%ymm12, 200(%rsp)
	vpsrld	$18, %ymm9, %ymm10
	vpslld	$14, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm13
	vpxor	160(%rdi), %ymm7, %ymm9
	vmovdqa	%ymm13, 232(%rsp)
	vpsrld	$14, %ymm9, %ymm10
	vpslld	$18, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm11
	vpxor	160(%rsi), %ymm8, %ymm9
	vmovdqa	%ymm11, 264(%rsp)
	vpsrld	$14, %ymm9, %ymm10
	vpslld	$18, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm10
	vpxor	512(%rsi), %ymm14, %ymm9
	vmovdqa	%ymm10, 296(%rsp)
	vpsrld	$9, %ymm9, %ymm10
	vpslld	$23, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm9
	vmovdqa	%ymm9, 328(%rsp)
	vpxor	512(%rdi), %ymm5, %ymm9
	vpsrld	$10, %ymm9, %ymm10
	vpslld	$22, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm10
	vpxor	256(%rsi), %ymm4, %ymm9
	vmovdqa	%ymm10, 360(%rsp)
	vpsrld	$4, %ymm9, %ymm10
	vpslld	$28, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm12
	vpxor	256(%rdi), %ymm1, %ymm9
	vmovdqa	%ymm12, 392(%rsp)
	vpsrld	$5, %ymm9, %ymm10
	vpslld	$27, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm13
	vpxor	672(%rdi), %ymm5, %ymm9
	vmovdqa	%ymm13, 424(%rsp)
	vpsrld	$31, %ymm9, %ymm10
	vpslld	$1, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm11
	vpxor	672(%rsi), %ymm14, %ymm9
	vmovdqa	%ymm11, 456(%rsp)
	vpsrld	$31, %ymm9, %ymm10
	vpslld	$1, %ymm9, %ymm9
	vpor	%ymm10, %ymm9, %ymm14
	vmovdqa	%ymm14, 488(%rsp)
	vpxor	768(%rdi), %ymm0, %ymm10
	vpsrld	$25, %ymm10, %ymm9
	vpslld	$7, %ymm10, %ymm10
	vpor	%ymm9, %ymm10, %ymm10
	vpxor	768(%rsi), %ymm2, %ymm9
	vpsrld	$25, %ymm9, %ymm11
	vpslld	$7, %ymm9, %ymm9
	vpor	%ymm11, %ymm9, %ymm9
	vpxor	128(%rsi), %ymm2, %ymm11
	vpsrld	$18, %ymm11, %ymm12
	vpslld	$14, %ymm11, %ymm11
	vpor	%ymm12, %ymm11, %ymm14
	vpxor	128(%rdi), %ymm0, %ymm11
	vmovdqa	%ymm14, 520(%rsp)
	vpsrld	$19, %ymm11, %ymm12
	vpslld	$13, %ymm11, %ymm11
	vpor	%ymm12, %ymm11, %ymm12
	vpxor	480(%rsi), %ymm8, %ymm11
	vmovdqa	%ymm12, 552(%rsp)
	vpxor	640(%rsi), %ymm8, %ymm8
	vpsrld	$11, %ymm11, %ymm12
	vpslld	$21, %ymm11, %ymm11
	vpor	%ymm12, %ymm11, %ymm13
	vpxor	480(%rdi), %ymm7, %ymm11
	vmovdqa	%ymm13, 584(%rsp)
	vpsrld	$12, %ymm11, %ymm12
	vpslld	$20, %ymm11, %ymm11
	vpor	%ymm12, %ymm11, %ymm11
	vmovdqa	%ymm11, 616(%rsp)
	vpxor	736(%rdi), %ymm1, %ymm11
	vpxor	416(%rdi), %ymm1, %ymm1
	vpsrld	$4, %ymm11, %ymm12
	vpslld	$28, %ymm11, %ymm11
	vpor	%ymm11, %ymm12, %ymm14
	vpxor	736(%rsi), %ymm4, %ymm11
	vmovdqa	%ymm14, 776(%rsp)
	vpxor	416(%rsi), %ymm4, %ymm4
	vpsrld	$4, %ymm11, %ymm12
	vpslld	$28, %ymm11, %ymm11
	vpor	%ymm11, %ymm12, %ymm12
	vpxor	608(%rdi), %ymm0, %ymm11
	vmovdqa	%ymm12, 808(%rsp)
	vpsrld	$28, %ymm11, %ymm12
	vpslld	$4, %ymm11, %ymm11
	vpor	%ymm11, %ymm12, %ymm13
	vpxor	608(%rsi), %ymm2, %ymm11
	vmovdqa	%ymm13, 840(%rsp)
	vpsrld	$28, %ymm11, %ymm12
	vpslld	$4, %ymm11, %ymm11
	vpor	%ymm12, %ymm11, %ymm11
	vpsrld	$19, %ymm4, %ymm12
	vmovdqa	%ymm11, 872(%rsp)
	vpsrld	$20, %ymm1, %ymm11
	vpslld	$12, %ymm1, %ymm1
	vpor	%ymm1, %ymm11, %ymm11
	vpxor	384(%rsi), %ymm3, %ymm1
	vpslld	$13, %ymm4, %ymm4
	vpor	%ymm4, %ymm12, %ymm12
	vpsrld	$10, %ymm1, %ymm14
	vpslld	$22, %ymm1, %ymm1
	vpor	%ymm1, %ymm14, %ymm14
	vpxor	384(%rdi), %ymm6, %ymm1
	vpsrld	$11, %ymm1, %ymm13
	vpslld	$21, %ymm1, %ymm1
	vpor	%ymm1, %ymm13, %ymm13
	vpxor	64(%rdi), %ymm6, %ymm1
	vpsrld	$1, %ymm1, %ymm4
	vpslld	$31, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm1
	vmovdqa	%ymm1, 744(%rsp)
	vpxor	64(%rsi), %ymm3, %ymm1
	vpsrld	$1, %ymm1, %ymm4
	vpslld	$31, %ymm1, %ymm1
	vpor	%ymm1, %ymm4, %ymm4
	vpxor	640(%rdi), %ymm7, %ymm1
	vmovdqa	%ymm4, 712(%rsp)
	vpslld	$9, %ymm1, %ymm7
	vpsrld	$23, %ymm1, %ymm4
	vpxor	448(%rsi), %ymm2, %ymm1
	vpor	%ymm7, %ymm4, %ymm7
	vpsrld	$23, %ymm8, %ymm4
	vpslld	$9, %ymm8, %ymm8
	vpor	%ymm8, %ymm4, %ymm4
	vpsrld	$12, %ymm1, %ymm8
	vpslld	$20, %ymm1, %ymm1
	vpor	%ymm1, %ymm8, %ymm8
	vpxor	448(%rdi), %ymm0, %ymm1
	vmovdqa	%ymm8, 680(%rsp)
	vpsrld	$13, %ymm1, %ymm8
	vpslld	$19, %ymm1, %ymm1
	vpor	%ymm1, %ymm8, %ymm1
	vmovdqa	%ymm1, 648(%rsp)
	vpxor	704(%rsi), %ymm3, %ymm3
	vpxor	288(%rsi), %ymm2, %ymm2
	vpxor	704(%rdi), %ymm6, %ymm6
	vpxor	288(%rdi), %ymm0, %ymm0
	vpsrld	$1, %ymm3, %ymm1
	vpslld	$31, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsrld	$2, %ymm6, %ymm3
	vpslld	$30, %ymm6, %ymm6
	vpor	%ymm6, %ymm3, %ymm3
	vpsrld	$22, %ymm0, %ymm6
	vpslld	$10, %ymm0, %ymm0
	vpor	%ymm0, %ymm6, %ymm6
	vpsrld	$22, %ymm2, %ymm0
	vpslld	$10, %ymm2, %ymm2
	vpor	%ymm2, %ymm0, %ymm2
	vpxor	192(%rdi), %ymm5, %ymm0
	vpsrld	$10, %ymm0, %ymm8
	vpslld	$22, %ymm0, %ymm5
	vmovdqa	1000(%rsp), %ymm0
	vpxor	192(%rsi), %ymm0, %ymm0
	vpor	%ymm5, %ymm8, %ymm5
	vpsrld	$10, %ymm0, %ymm8
	vpslld	$22, %ymm0, %ymm0
	vpor	%ymm0, %ymm8, %ymm0
	vpandn	%ymm14, %ymm5, %ymm8
	vpxor	904(%rsp), %ymm8, %ymm8
	vmovdqa	%ymm8, (%rdi)
	vpandn	%ymm13, %ymm0, %ymm8
	vpxor	%ymm15, %ymm8, %ymm8
	vmovdqa	%ymm8, (%rsi)
	vpandn	968(%rsp), %ymm14, %ymm8
	vpxor	%ymm5, %ymm8, %ymm8
	vmovdqa	%ymm8, 32(%rdi)
	vpandn	936(%rsp), %ymm13, %ymm8
	vpxor	%ymm0, %ymm8, %ymm8
	vpandn	%ymm0, %ymm15, %ymm0
	vmovdqa	%ymm8, 32(%rsi)
	vmovdqa	968(%rsp), %ymm8
	vpxor	%ymm9, %ymm0, %ymm0
	vpandn	%ymm10, %ymm8, %ymm8
	vpxor	%ymm14, %ymm8, %ymm8
	vmovdqa	936(%rsp), %ymm14
	vmovdqa	%ymm8, 64(%rdi)
	vpandn	%ymm9, %ymm14, %ymm8
	vpxor	%ymm13, %ymm8, %ymm8
	vmovdqa	904(%rsp), %ymm13
	vmovdqa	%ymm8, 64(%rsi)
	vpandn	%ymm13, %ymm10, %ymm8
	vpxor	968(%rsp), %ymm8, %ymm8
	vpandn	%ymm5, %ymm13, %ymm5
	vmovdqa	-24(%rsp), %ymm13
	vpxor	%ymm10, %ymm5, %ymm5
	vmovdqa	%ymm8, 96(%rdi)
	vpandn	%ymm15, %ymm9, %ymm8
	vmovdqa	-56(%rsp), %ymm15
	vmovdqa	328(%rsp), %ymm9
	vpxor	%ymm14, %ymm8, %ymm8
	vmovdqa	200(%rsp), %ymm14
	vmovdqa	%ymm8, 96(%rsi)
	vmovdqa	232(%rsp), %ymm8
	vmovdqa	%ymm5, 128(%rdi)
	vmovdqa	%ymm0, 128(%rsi)
	vpandn	%ymm15, %ymm6, %ymm0
	vpxor	%ymm14, %ymm0, %ymm0
	vmovdqa	%ymm0, 160(%rdi)
	vpandn	%ymm13, %ymm2, %ymm0
	vpxor	%ymm8, %ymm0, %ymm0
	vmovdqa	%ymm0, 160(%rsi)
	vpandn	%ymm9, %ymm15, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm0, 192(%rdi)
	vmovdqa	360(%rsp), %ymm10
	vmovdqa	-120(%rsp), %ymm5
	vpandn	%ymm10, %ymm13, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 192(%rsi)
	vpandn	%ymm1, %ymm9, %ymm0
	vpxor	%ymm15, %ymm0, %ymm0
	vmovdqa	872(%rsp), %ymm15
	vmovdqa	%ymm0, 224(%rdi)
	vpandn	%ymm3, %ymm10, %ymm0
	vpxor	%ymm13, %ymm0, %ymm0
	vmovdqa	%ymm0, 224(%rsi)
	vpandn	%ymm14, %ymm1, %ymm0
	vpxor	%ymm9, %ymm0, %ymm0
	vmovdqa	%ymm0, 256(%rdi)
	vpandn	%ymm8, %ymm3, %ymm0
	vpxor	%ymm10, %ymm0, %ymm0
	vmovdqa	%ymm0, 256(%rsi)
	vpandn	%ymm6, %ymm14, %ymm0
	vmovdqa	-88(%rsp), %ymm6
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	840(%rsp), %ymm1
	vmovdqa	%ymm0, 288(%rdi)
	vpandn	%ymm2, %ymm8, %ymm0
	vmovdqa	8(%rsp), %ymm2
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	40(%rsp), %ymm3
	vmovdqa	%ymm0, 288(%rsi)
	vpandn	%ymm12, %ymm2, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm0, 320(%rdi)
	vpandn	%ymm11, %ymm3, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	%ymm0, 320(%rsi)
	vpandn	%ymm1, %ymm12, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 352(%rdi)
	vpandn	%ymm15, %ymm11, %ymm0
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, 352(%rsi)
	vpandn	%ymm7, %ymm1, %ymm0
	vpxor	%ymm12, %ymm0, %ymm0
	vmovdqa	%ymm0, 384(%rdi)
	vpandn	%ymm4, %ymm15, %ymm0
	vpxor	%ymm11, %ymm0, %ymm0
	vmovdqa	%ymm0, 384(%rsi)
	vpandn	%ymm6, %ymm7, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	520(%rsp), %ymm1
	vmovdqa	%ymm0, 416(%rdi)
	vpandn	%ymm5, %ymm4, %ymm0
	vpxor	%ymm15, %ymm0, %ymm0
	vmovdqa	552(%rsp), %ymm15
	vmovdqa	%ymm0, 416(%rsi)
	vpandn	%ymm2, %ymm6, %ymm0
	vmovdqa	264(%rsp), %ymm2
	vpxor	%ymm7, %ymm0, %ymm0
	vmovdqa	72(%rsp), %ymm7
	vmovdqa	%ymm0, 448(%rdi)
	vpandn	%ymm3, %ymm5, %ymm0
	vmovdqa	296(%rsp), %ymm3
	vpxor	%ymm4, %ymm0, %ymm0
	vmovdqa	104(%rsp), %ymm4
	vmovdqa	%ymm0, 448(%rsi)
	vpandn	%ymm7, %ymm2, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 480(%rdi)
	vpandn	%ymm4, %ymm3, %ymm0
	vpxor	%ymm15, %ymm0, %ymm0
	vmovdqa	%ymm0, 480(%rsi)
	vmovdqa	136(%rsp), %ymm5
	vmovdqa	168(%rsp), %ymm6
	vmovdqa	776(%rsp), %ymm8
	vmovdqa	808(%rsp), %ymm10
	vmovdqa	648(%rsp), %ymm13
	vmovdqa	712(%rsp), %ymm12
	vpandn	%ymm5, %ymm7, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 512(%rdi)
	vpandn	%ymm6, %ymm4, %ymm0
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, 512(%rsi)
	vpandn	%ymm8, %ymm5, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vmovdqa	392(%rsp), %ymm7
	vmovdqa	%ymm0, 544(%rdi)
	vpandn	%ymm10, %ymm6, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vmovdqa	456(%rsp), %ymm4
	vmovdqa	%ymm0, 544(%rsi)
	vpandn	%ymm1, %ymm8, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	488(%rsp), %ymm5
	vmovdqa	%ymm0, 576(%rdi)
	vpandn	%ymm15, %ymm10, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vmovdqa	424(%rsp), %ymm6
	vmovdqa	%ymm0, 576(%rsi)
	vpandn	%ymm2, %ymm1, %ymm0
	vmovdqa	744(%rsp), %ymm1
	vmovdqa	584(%rsp), %ymm2
	vpxor	%ymm8, %ymm0, %ymm0
	vmovdqa	%ymm0, 608(%rdi)
	vpandn	%ymm3, %ymm15, %ymm0
	vmovdqa	680(%rsp), %ymm15
	vmovdqa	616(%rsp), %ymm3
	vpxor	%ymm10, %ymm0, %ymm0
	vmovdqa	%ymm0, 608(%rsi)
	vpandn	%ymm15, %ymm7, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 640(%rdi)
	vpandn	%ymm13, %ymm6, %ymm0
	vpxor	%ymm12, %ymm0, %ymm0
	vmovdqa	%ymm0, 640(%rsi)
	vpandn	%ymm2, %ymm15, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vmovdqa	%ymm0, 672(%rdi)
	vpandn	%ymm3, %ymm13, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vmovdqa	%ymm0, 672(%rsi)
	vpandn	%ymm4, %ymm2, %ymm0
	vpxor	%ymm15, %ymm0, %ymm0
	vmovdqa	%ymm0, 704(%rdi)
	vpandn	%ymm5, %ymm3, %ymm0
	vpxor	%ymm13, %ymm0, %ymm0
	vmovdqa	%ymm0, 704(%rsi)
	vpandn	%ymm1, %ymm4, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 736(%rdi)
	vpandn	%ymm12, %ymm5, %ymm0
	vpxor	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, 736(%rsi)
	vpandn	%ymm7, %ymm1, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vmovdqa	%ymm0, 768(%rdi)
	vpandn	%ymm6, %ymm12, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	%ymm0, 768(%rsi)
	vpbroadcastd	-8(%rdx), %ymm0
	vpxor	(%rdi), %ymm0, %ymm0
	vmovdqa	%ymm0, (%rdi)
	vpbroadcastd	-4(%rdx), %ymm15
	vpxor	(%rsi), %ymm15, %ymm15
	vmovdqa	%ymm15, (%rsi)
	cmpq	%rax, %rdx
	jne	9999b
	vzeroupper
	leave
   /* === End gcc-15 compiled body === */
.endm
