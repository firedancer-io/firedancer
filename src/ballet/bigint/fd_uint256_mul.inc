# fd_uint256_mul_mod_p
#
# CIOS Montgomery multiplication using BMI2 (mulx) and ADX (adcx/adox).
# Computes r = inverse_mod(2^256, p) * a * b  (mod p).
#
# Parameters (must be pinned to specific registers, see fd_uint256_mul.h):
#   \r      - rdi, pointer to output fd_uint256_t (preserved)
#   \a      - rsi, pointer to first multiplicand (4 limbs, destroyed)
#   \b      - rdx, pointer to second multiplicand (4 limbs, moved to rax)
#   \p      - rcx, pointer to modulus (4 limbs, must be odd, < 2^256, preserved)
#   \p_inv  - r8,  Montgomery inverse: (p_inv * p[0]) ≡ -1 (mod 2^64, destroyed)
#
# Saves/restores: rbp, r15, r14, r13, r12, rbx.
# Clobbers: rax, rdx, r9-r11, \a (rsi), \p_inv (r8), flags, memory.

.macro _fd_uint256_mul_mod_p r, a, b, p, p_inv

    push    %rbp
    push    %r15
    push    %r14
    push    %r13
    push    %r12
    push    %rbx

    mov     \b, %rax

    xor     %r9d, %r9d
    xor     %r10d, %r10d
    xor     %r11d, %r11d
    xor     %ebx, %ebx
    xor     %r14d, %r14d

    /* Iteration 0: b[0] */
    mov     (%rax), %rdx
    xor     %r9d, %r9d
    mulx    (\a), %r12, %r15
    adcx    %r12, %r10
    mulx    0x8(\a), %r12, %rbp
    adox    %r15, %r11
    adcx    %r12, %r11
    mulx    0x10(\a), %r12, %r15
    adox    %rbp, %rbx
    adcx    %r12, %rbx
    mulx    0x18(\a), %r12, %rbp
    adox    %r15, %r14
    adcx    %r12, %r14
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r10, %rdx
    imul    \p_inv, %rdx
    xor     %r9d, %r9d
    mulx    (\p), %r12, %r15
    adcx    %r10, %r12
    mulx    0x8(\p), %r12, %r13
    adox    %r15, %r11
    adcx    %r12, %r11
    mulx    0x10(\p), %r12, %r15
    adox    %r13, %rbx
    adcx    %r12, %rbx
    mulx    0x18(\p), %r12, %r13
    adox    %r15, %r14
    adcx    %r12, %r14
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r10

    /* Iteration 1: b[1] */
    mov     0x8(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (\a), %r12, %r15
    adcx    %r12, %r11
    mulx    0x8(\a), %r12, %rbp
    adox    %r15, %rbx
    adcx    %r12, %rbx
    mulx    0x10(\a), %r12, %r15
    adox    %rbp, %r14
    adcx    %r12, %r14
    mulx    0x18(\a), %r12, %rbp
    adox    %r15, %r10
    adcx    %r12, %r10
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r11, %rdx
    imul    \p_inv, %rdx
    xor     %r9d, %r9d
    mulx    (\p), %r12, %r15
    adcx    %r11, %r12
    mulx    0x8(\p), %r12, %r13
    adox    %r15, %rbx
    adcx    %r12, %rbx
    mulx    0x10(\p), %r12, %r15
    adox    %r13, %r14
    adcx    %r12, %r14
    mulx    0x18(\p), %r12, %r13
    adox    %r15, %r10
    adcx    %r12, %r10
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r11

    /* Iteration 2: b[2] */
    mov     0x10(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (\a), %r12, %r15
    adcx    %r12, %rbx
    mulx    0x8(\a), %r12, %rbp
    adox    %r15, %r14
    adcx    %r12, %r14
    mulx    0x10(\a), %r12, %r15
    adox    %rbp, %r10
    adcx    %r12, %r10
    mulx    0x18(\a), %r12, %rbp
    adox    %r15, %r11
    adcx    %r12, %r11
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %rbx, %rdx
    imul    \p_inv, %rdx
    xor     %r9d, %r9d
    mulx    (\p), %r12, %r15
    adcx    %rbx, %r12
    mulx    0x8(\p), %r12, %r13
    adox    %r15, %r14
    adcx    %r12, %r14
    mulx    0x10(\p), %r12, %r15
    adox    %r13, %r10
    adcx    %r12, %r10
    mulx    0x18(\p), %r12, %r13
    adox    %r15, %r11
    adcx    %r12, %r11
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %rbx

    /* Iteration 3: b[3] */
    mov     0x18(%rax), %rdx
    xor     %r9d, %r9d
    mulx    (\a), %r12, %r15
    adcx    %r12, %r14
    mulx    0x8(\a), %r12, %rbp
    adox    %r15, %r10
    adcx    %r12, %r10
    mulx    0x10(\a), %r12, %r15
    adox    %rbp, %r11
    adcx    %r12, %r11
    mulx    0x18(\a), %r12, %rbp
    adox    %r15, %rbx
    adcx    %r12, %rbx
    adox    %r9, %rbp
    adcx    %r9, %rbp

    mov     %r14, %rdx
    imul    \p_inv, %rdx
    xor     %r9d, %r9d
    mulx    (\p), %r12, %r15
    adcx    %r14, %r12
    mulx    0x8(\p), %r12, %r13
    adox    %r15, %r10
    adcx    %r12, %r10
    mulx    0x10(\p), %r12, %r15
    adox    %r13, %r11
    adcx    %r12, %r11
    mulx    0x18(\p), %r12, %r13
    adox    %r15, %rbx
    adcx    %r12, %rbx
    adox    %r9, %r13
    adcx    %r9, %r13
    add     %r13, %rbp
    mov     %rbp, %r14

    /* Conditional subtraction: result = min(t, t - p)
       Result in r10, r11, rbx, r14.  Reuse \a, \p_inv as scratch. */
    mov     %r10, %rax
    sub     (\p), %rax
    mov     %r11, %rdx
    sbb     0x8(\p), %rdx
    mov     %rbx, \a
    sbb     0x10(\p), \a
    mov     %r14, \p_inv
    sbb     0x18(\p), \p_inv
    cmovb   %r10, %rax
    cmovb   %r11, %rdx
    cmovb   %rbx, \a
    cmovb   %r14, \p_inv

    mov     %rax, (\r)
    mov     %rdx, 0x8(\r)
    mov     \a, 0x10(\r)
    mov     \p_inv, 0x18(\r)

    pop     %rbx
    pop     %r12
    pop     %r13
    pop     %r14
    pop     %r15
    pop     %rbp

.endm
