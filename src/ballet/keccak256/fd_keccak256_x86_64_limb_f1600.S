/* Keccak-f[1600] for x86_64: BMI andn + BMI2 rorx, logical u64 lanes.
   LE qword layout matches two uint32 limbs (lo,hi) per lane — same bits as
   fd_keccak256_interleaved.c / plonky2-crypto state [[U32Target;2];25].

   void fd_keccak256_x86_64_limb_f1600( ulong * state, ulong const * rc );
   SysV AMD64: rdi=state, rsi=rc (24 round constants). */

.section .note.GNU-stack,"",@progbits

.text

.globl	fd_keccak256_x86_64_limb_f1600
.type	fd_keccak256_x86_64_limb_f1600,@function
.align	16
fd_keccak256_x86_64_limb_f1600:
.cfi_startproc
	pushq	%rbx
	.cfi_adjust_cfa_offset 8
	pushq	%r12
	.cfi_adjust_cfa_offset 8
	pushq	%r13
	.cfi_adjust_cfa_offset 8
	pushq	%r14
	.cfi_adjust_cfa_offset 8
	pushq	%r15
	.cfi_adjust_cfa_offset 8

	movq	%rsi, %r13		/* rc table */
	xorl	%r12d, %r12d		/* round */

.align	16
1:	/* ---- Theta: column parities in rax,rbx,rcx,rdx,r8 ---- */
	movq	0(%rdi), %rax
	xorq	40(%rdi), %rax
	xorq	80(%rdi), %rax
	xorq	120(%rdi), %rax
	xorq	160(%rdi), %rax

	movq	8(%rdi), %rbx
	xorq	48(%rdi), %rbx
	xorq	88(%rdi), %rbx
	xorq	128(%rdi), %rbx
	xorq	168(%rdi), %rbx

	movq	16(%rdi), %rcx
	xorq	56(%rdi), %rcx
	xorq	96(%rdi), %rcx
	xorq	136(%rdi), %rcx
	xorq	176(%rdi), %rcx

	movq	24(%rdi), %rdx
	xorq	64(%rdi), %rdx
	xorq	104(%rdi), %rdx
	xorq	144(%rdi), %rdx
	xorq	184(%rdi), %rdx

	movq	32(%rdi), %r8
	xorq	72(%rdi), %r8
	xorq	112(%rdi), %r8
	xorq	152(%rdi), %r8
	xorq	192(%rdi), %r8

	/* D0 = C4 ^ rol(C1,1); xor into column 0 */
	movq	%rbx, %r9
	rolq	$1, %r9
	xorq	%r8, %r9
	xorq	%r9, 0(%rdi)
	xorq	%r9, 40(%rdi)
	xorq	%r9, 80(%rdi)
	xorq	%r9, 120(%rdi)
	xorq	%r9, 160(%rdi)

	/* D1 = C0 ^ rol(C2,1); column 1 */
	movq	%rcx, %r9
	rolq	$1, %r9
	xorq	%rax, %r9
	xorq	%r9, 8(%rdi)
	xorq	%r9, 48(%rdi)
	xorq	%r9, 88(%rdi)
	xorq	%r9, 128(%rdi)
	xorq	%r9, 168(%rdi)

	/* D2 = C1 ^ rol(C3,1); column 2 */
	movq	%rdx, %r9
	rolq	$1, %r9
	xorq	%rbx, %r9
	xorq	%r9, 16(%rdi)
	xorq	%r9, 56(%rdi)
	xorq	%r9, 96(%rdi)
	xorq	%r9, 136(%rdi)
	xorq	%r9, 176(%rdi)

	/* D3 = C2 ^ rol(C4,1); column 3 */
	movq	%r8, %r9
	rolq	$1, %r9
	xorq	%rcx, %r9
	xorq	%r9, 24(%rdi)
	xorq	%r9, 64(%rdi)
	xorq	%r9, 104(%rdi)
	xorq	%r9, 144(%rdi)
	xorq	%r9, 184(%rdi)

	/* D4 = C3 ^ rol(C0,1); column 4 */
	movq	%rax, %r9
	rolq	$1, %r9
	xorq	%rdx, %r9
	xorq	%r9, 32(%rdi)
	xorq	%r9, 72(%rdi)
	xorq	%r9, 112(%rdi)
	xorq	%r9, 152(%rdi)
	xorq	%r9, 192(%rdi)

	/* ---- Rho + Pi (rorx = rotate right = rol left by (64-r)) ---- */
	movq	8(%rdi), %rax		/* cur = state[1] */
	/* rho step 0: j=10 r=1 */
	movq	80(%rdi),%rbx
	rorx	$63,%rax,%rcx
	movq	%rcx,80(%rdi)
	movq	%rbx,%rax
	/* rho step 1: j=7 r=3 */
	movq	56(%rdi),%rbx
	rorx	$61,%rax,%rcx
	movq	%rcx,56(%rdi)
	movq	%rbx,%rax
	/* rho step 2: j=11 r=6 */
	movq	88(%rdi),%rbx
	rorx	$58,%rax,%rcx
	movq	%rcx,88(%rdi)
	movq	%rbx,%rax
	/* rho step 3: j=17 r=10 */
	movq	136(%rdi),%rbx
	rorx	$54,%rax,%rcx
	movq	%rcx,136(%rdi)
	movq	%rbx,%rax
	/* rho step 4: j=18 r=15 */
	movq	144(%rdi),%rbx
	rorx	$49,%rax,%rcx
	movq	%rcx,144(%rdi)
	movq	%rbx,%rax
	/* rho step 5: j=3 r=21 */
	movq	24(%rdi),%rbx
	rorx	$43,%rax,%rcx
	movq	%rcx,24(%rdi)
	movq	%rbx,%rax
	/* rho step 6: j=5 r=28 */
	movq	40(%rdi),%rbx
	rorx	$36,%rax,%rcx
	movq	%rcx,40(%rdi)
	movq	%rbx,%rax
	/* rho step 7: j=16 r=36 */
	movq	128(%rdi),%rbx
	rorx	$28,%rax,%rcx
	movq	%rcx,128(%rdi)
	movq	%rbx,%rax
	/* rho step 8: j=8 r=45 */
	movq	64(%rdi),%rbx
	rorx	$19,%rax,%rcx
	movq	%rcx,64(%rdi)
	movq	%rbx,%rax
	/* rho step 9: j=21 r=55 */
	movq	168(%rdi),%rbx
	rorx	$9,%rax,%rcx
	movq	%rcx,168(%rdi)
	movq	%rbx,%rax
	/* rho step 10: j=24 r=2 */
	movq	192(%rdi),%rbx
	rorx	$62,%rax,%rcx
	movq	%rcx,192(%rdi)
	movq	%rbx,%rax
	/* rho step 11: j=4 r=14 */
	movq	32(%rdi),%rbx
	rorx	$50,%rax,%rcx
	movq	%rcx,32(%rdi)
	movq	%rbx,%rax
	/* rho step 12: j=15 r=27 */
	movq	120(%rdi),%rbx
	rorx	$37,%rax,%rcx
	movq	%rcx,120(%rdi)
	movq	%rbx,%rax
	/* rho step 13: j=23 r=41 */
	movq	184(%rdi),%rbx
	rorx	$23,%rax,%rcx
	movq	%rcx,184(%rdi)
	movq	%rbx,%rax
	/* rho step 14: j=19 r=56 */
	movq	152(%rdi),%rbx
	rorx	$8,%rax,%rcx
	movq	%rcx,152(%rdi)
	movq	%rbx,%rax
	/* rho step 15: j=13 r=8 */
	movq	104(%rdi),%rbx
	rorx	$56,%rax,%rcx
	movq	%rcx,104(%rdi)
	movq	%rbx,%rax
	/* rho step 16: j=12 r=25 */
	movq	96(%rdi),%rbx
	rorx	$39,%rax,%rcx
	movq	%rcx,96(%rdi)
	movq	%rbx,%rax
	/* rho step 17: j=2 r=43 */
	movq	16(%rdi),%rbx
	rorx	$21,%rax,%rcx
	movq	%rcx,16(%rdi)
	movq	%rbx,%rax
	/* rho step 18: j=20 r=62 */
	movq	160(%rdi),%rbx
	rorx	$2,%rax,%rcx
	movq	%rcx,160(%rdi)
	movq	%rbx,%rax
	/* rho step 19: j=14 r=18 */
	movq	112(%rdi),%rbx
	rorx	$46,%rax,%rcx
	movq	%rcx,112(%rdi)
	movq	%rbx,%rax
	/* rho step 20: j=22 r=39 */
	movq	176(%rdi),%rbx
	rorx	$25,%rax,%rcx
	movq	%rcx,176(%rdi)
	movq	%rbx,%rax
	/* rho step 21: j=9 r=61 */
	movq	72(%rdi),%rbx
	rorx	$3,%rax,%rcx
	movq	%rcx,72(%rdi)
	movq	%rbx,%rax
	/* rho step 22: j=6 r=20 */
	movq	48(%rdi),%rbx
	rorx	$44,%rax,%rcx
	movq	%rcx,48(%rdi)
	movq	%rbx,%rax
	/* rho step 23: j=1 r=44 */
	movq	8(%rdi),%rbx
	rorx	$20,%rax,%rcx
	movq	%rcx,8(%rdi)
	movq	%rbx,%rax

	/* ---- Chi (BMI andn): five rows; andn op1,op2,dst => dst = op1 & NOT(op2).
	   Masks use row originals (r10,r11,r14,r15,r8), not partially updated lanes. */
	movq	0(%rdi), %r10
	movq	8(%rdi), %r11
	movq	16(%rdi), %r14
	movq	24(%rdi), %r15
	movq	32(%rdi), %r8
	andn	%r14, %r11, %r9
	movq	%r10, %rax
	xorq	%r9, %rax
	andn	%r15, %r14, %r9
	movq	%r11, %rbx
	xorq	%r9, %rbx
	andn	%r8, %r15, %r9
	movq	%r14, %rcx
	xorq	%r9, %rcx
	andn	%r10, %r8, %r9
	movq	%r15, %rdx
	xorq	%r9, %rdx
	andn	%r11, %r10, %r9
	xorq	%r9, %r8
	movq	%rax, 0(%rdi)
	movq	%rbx, 8(%rdi)
	movq	%rcx, 16(%rdi)
	movq	%rdx, 24(%rdi)
	movq	%r8, 32(%rdi)

	movq	40(%rdi), %r10
	movq	48(%rdi), %r11
	movq	56(%rdi), %r14
	movq	64(%rdi), %r15
	movq	72(%rdi), %r8
	andn	%r14, %r11, %r9
	movq	%r10, %rax
	xorq	%r9, %rax
	andn	%r15, %r14, %r9
	movq	%r11, %rbx
	xorq	%r9, %rbx
	andn	%r8, %r15, %r9
	movq	%r14, %rcx
	xorq	%r9, %rcx
	andn	%r10, %r8, %r9
	movq	%r15, %rdx
	xorq	%r9, %rdx
	andn	%r11, %r10, %r9
	xorq	%r9, %r8
	movq	%rax, 40(%rdi)
	movq	%rbx, 48(%rdi)
	movq	%rcx, 56(%rdi)
	movq	%rdx, 64(%rdi)
	movq	%r8, 72(%rdi)

	movq	80(%rdi), %r10
	movq	88(%rdi), %r11
	movq	96(%rdi), %r14
	movq	104(%rdi), %r15
	movq	112(%rdi), %r8
	andn	%r14, %r11, %r9
	movq	%r10, %rax
	xorq	%r9, %rax
	andn	%r15, %r14, %r9
	movq	%r11, %rbx
	xorq	%r9, %rbx
	andn	%r8, %r15, %r9
	movq	%r14, %rcx
	xorq	%r9, %rcx
	andn	%r10, %r8, %r9
	movq	%r15, %rdx
	xorq	%r9, %rdx
	andn	%r11, %r10, %r9
	xorq	%r9, %r8
	movq	%rax, 80(%rdi)
	movq	%rbx, 88(%rdi)
	movq	%rcx, 96(%rdi)
	movq	%rdx, 104(%rdi)
	movq	%r8, 112(%rdi)

	movq	120(%rdi), %r10
	movq	128(%rdi), %r11
	movq	136(%rdi), %r14
	movq	144(%rdi), %r15
	movq	152(%rdi), %r8
	andn	%r14, %r11, %r9
	movq	%r10, %rax
	xorq	%r9, %rax
	andn	%r15, %r14, %r9
	movq	%r11, %rbx
	xorq	%r9, %rbx
	andn	%r8, %r15, %r9
	movq	%r14, %rcx
	xorq	%r9, %rcx
	andn	%r10, %r8, %r9
	movq	%r15, %rdx
	xorq	%r9, %rdx
	andn	%r11, %r10, %r9
	xorq	%r9, %r8
	movq	%rax, 120(%rdi)
	movq	%rbx, 128(%rdi)
	movq	%rcx, 136(%rdi)
	movq	%rdx, 144(%rdi)
	movq	%r8, 152(%rdi)

	movq	160(%rdi), %r10
	movq	168(%rdi), %r11
	movq	176(%rdi), %r14
	movq	184(%rdi), %r15
	movq	192(%rdi), %r8
	andn	%r14, %r11, %r9
	movq	%r10, %rax
	xorq	%r9, %rax
	andn	%r15, %r14, %r9
	movq	%r11, %rbx
	xorq	%r9, %rbx
	andn	%r8, %r15, %r9
	movq	%r14, %rcx
	xorq	%r9, %rcx
	andn	%r10, %r8, %r9
	movq	%r15, %rdx
	xorq	%r9, %rdx
	andn	%r11, %r10, %r9
	xorq	%r9, %r8
	movq	%rax, 160(%rdi)
	movq	%rbx, 168(%rdi)
	movq	%rcx, 176(%rdi)
	movq	%rdx, 184(%rdi)
	movq	%r8, 192(%rdi)

	/* Iota */
	movq	(%r13,%r12,8), %rax
	xorq	%rax, 0(%rdi)

	incq	%r12
#if defined(FD_KECCAK256_X86_64_LIMB_ASM_DBG_ROUNDS)
	cmpq	$FD_KECCAK256_X86_64_LIMB_ASM_DBG_ROUNDS, %r12
	je	.Ldbg_exit
#endif
	cmpq	$24, %r12
	jb	1b

#if defined(FD_KECCAK256_X86_64_LIMB_ASM_DBG_ROUNDS)
.Ldbg_exit:
#endif

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	ret
.cfi_endproc
.size	fd_keccak256_x86_64_limb_f1600, .-fd_keccak256_x86_64_limb_f1600
