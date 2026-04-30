#!/usr/bin/env python3
"""Generate fd_keccak256_avx2_keccak8_eo.inc.

Keccak-f[1600] x8 batched on AVX2 with EVEN/ODD bit-interleaved limbs.
Sequential fused (B on stack), Chi reads B from stack, writes A to caller mem.

Round structure (mirrors fd_k8eo_perm in the C version):
  1) Theta col parities C[0..4].e+.o, stored to stack scratch.
  2) Theta D[0..4].e+.o, kept in ymm6..ymm15 across the fused phase.
  3) Fused Theta-XOR + Rho + Pi: walk the pi cycle, write B[pi(x,y)] to stack.
  4) Chi: read B from stack, write new A to caller mem.
  5) Iota fold: rc XOR'd into A_E[0] / A_O[0] at the END of chi-row-0
     (saves the trailing separate iota XOR+store pair).

Stack frame: 50 ymm (B) + 10 ymm (C) = 1920 bytes.

ABI: \\state in %rdi, \\rc_eo in %rsi.  Clobbers ymm0..ymm15, rax, rcx, rbp.
"""

# Standard Keccak schedule.
RHO = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
PI  = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]

def src_xy_per_step():
    """List of (x_src, y_src, dst_idx, rho) for each fused step.
       Step 0 source is (1,0); subsequent step's source is the previous dst."""
    out = []
    src_idx = 1
    for i in range(24):
        out.append((src_idx % 5, src_idx // 5, PI[i], RHO[i]))
        src_idx = PI[i]
    return out

# Stack offsets.
B_E_OFF = lambda z: 32*z
B_O_OFF = lambda z: 32*(25+z)
C_E_OFF = lambda x: 1600 + 32*x
C_O_OFF = lambda x: 1600 + 32*(5+x)

# Caller state offsets.
A_E_OFF = lambda z: 32*z
A_O_OFF = lambda z: 32*(25+z)

STACK_BYTES = 1920

def emit_theta_col(lines, e_or_o, x, dst):
    A_OFF = A_E_OFF if e_or_o == 'e' else A_O_OFF
    lines.append(f"   /* C_{e_or_o}[{x}] = XOR_y A_{e_or_o}[{x}+5y] */")
    lines.append(f"   vmovdqa {A_OFF(x)}(\\state), {dst}")
    lines.append(f"   vpxor {A_OFF(x+5)}(\\state), {dst}, {dst}")
    lines.append(f"   vpxor {A_OFF(x+10)}(\\state), {dst}, {dst}")
    lines.append(f"   vpxor {A_OFF(x+15)}(\\state), {dst}, {dst}")
    lines.append(f"   vpxor {A_OFF(x+20)}(\\state), {dst}, {dst}")

def emit_theta_d(lines, x, d_e_dst, d_o_dst, tmp1, tmp2):
    """D[x].E = C_e[(x+4)%5] XOR rol32(C_o[(x+1)%5], 1)
       D[x].O = C_o[(x+4)%5] XOR C_e[(x+1)%5]
    """
    xm = (x+4) % 5
    xp = (x+1) % 5
    lines.append(f"   /* D[{x}] = C[{xm}] ^ rotl1(C[{xp}]) */")
    lines.append(f"   vpslld $1, {C_O_OFF(xp)}(%rsp), {tmp1}")
    lines.append(f"   vpsrld $31, {C_O_OFF(xp)}(%rsp), {tmp2}")
    lines.append(f"   vpor {tmp2}, {tmp1}, {tmp1}")
    lines.append(f"   vpxor {C_E_OFF(xm)}(%rsp), {tmp1}, {d_e_dst}")
    lines.append(f"   vmovdqa {C_O_OFF(xm)}(%rsp), {d_o_dst}")
    lines.append(f"   vpxor {C_E_OFF(xp)}(%rsp), {d_o_dst}, {d_o_dst}")

def emit_fused_step(lines, x, y, pi_xy, d, t1, t2, t3, d_e_x, d_o_x):
    """Fused Theta-XOR + Rho + Pi step.  D in registers, B written to stack."""
    z = x + 5*y
    lines.append(f"   /* fused: src ({x},{y})=A[{z}] -> B[{pi_xy}]  rol={d} */")
    lines.append(f"   vpxor {A_E_OFF(z)}(\\state), {d_e_x}, {t1}")
    lines.append(f"   vpxor {A_O_OFF(z)}(\\state), {d_o_x}, {t2}")
    if d == 0:
        lines.append(f"   vmovdqa {t1}, {B_E_OFF(pi_xy)}(%rsp)")
        lines.append(f"   vmovdqa {t2}, {B_O_OFF(pi_xy)}(%rsp)")
    elif d % 2 == 0:
        k = d // 2
        lines.append(f"   vpsrld ${32-k}, {t1}, {t3}")
        lines.append(f"   vpslld ${k}, {t1}, {t1}")
        lines.append(f"   vpor {t3}, {t1}, {t1}")
        lines.append(f"   vmovdqa {t1}, {B_E_OFF(pi_xy)}(%rsp)")
        lines.append(f"   vpsrld ${32-k}, {t2}, {t3}")
        lines.append(f"   vpslld ${k}, {t2}, {t2}")
        lines.append(f"   vpor {t3}, {t2}, {t2}")
        lines.append(f"   vmovdqa {t2}, {B_O_OFF(pi_xy)}(%rsp)")
    else:
        k = (d - 1) // 2
        kp = (k + 1) % 32
        if kp == 0:
            lines.append(f"   vmovdqa {t2}, {B_E_OFF(pi_xy)}(%rsp)")
        else:
            lines.append(f"   vpsrld ${32-kp}, {t2}, {t3}")
            lines.append(f"   vpslld ${kp}, {t2}, {t2}")
            lines.append(f"   vpor {t3}, {t2}, {t2}")
            lines.append(f"   vmovdqa {t2}, {B_E_OFF(pi_xy)}(%rsp)")
        if k == 0:
            lines.append(f"   vmovdqa {t1}, {B_O_OFF(pi_xy)}(%rsp)")
        else:
            lines.append(f"   vpsrld ${32-k}, {t1}, {t3}")
            lines.append(f"   vpslld ${k}, {t1}, {t1}")
            lines.append(f"   vpor {t3}, {t1}, {t1}")
            lines.append(f"   vmovdqa {t1}, {B_O_OFF(pi_xy)}(%rsp)")

def emit_chi_row(lines, y, regs, fold_iota=False):
    """Chi for row y.  regs = 11 ymm names: 5 for B_E, 5 for B_O, 1 tmp.
       fold_iota: if True, XOR rc_eo[2*round]/[2*round+1] into A[0,0] result
       (only valid for y==0)."""
    base_e = [B_E_OFF(5*y + x) for x in range(5)]
    base_o = [B_O_OFF(5*y + x) for x in range(5)]
    a_e = [A_E_OFF(5*y + x) for x in range(5)]
    a_o = [A_O_OFF(5*y + x) for x in range(5)]
    rE = regs[0:5]
    rO = regs[5:10]
    tmp = regs[10]
    lines.append(f"   /* Chi row y={y}{'  (with iota fold for cell 0)' if fold_iota else ''} */")
    for x in range(5):
        lines.append(f"   vmovdqa {base_e[x]}(%rsp), {rE[x]}")
        lines.append(f"   vmovdqa {base_o[x]}(%rsp), {rO[x]}")
    for x in range(5):
        i1 = (x+1) % 5
        i2 = (x+2) % 5
        # E side
        lines.append(f"   vpandn {rE[i2]}, {rE[i1]}, {tmp}")
        lines.append(f"   vpxor {tmp}, {rE[x]}, {tmp}")
        if fold_iota and x == 0:
            # Use ymm11/12 (free during chi — these were D values, no longer needed)
            lines.append(f"   vpbroadcastd (\\rc_eo, %rcx, 8), %ymm11")
            lines.append(f"   vpxor %ymm11, {tmp}, {tmp}")
        lines.append(f"   vmovdqa {tmp}, {a_e[x]}(\\state)")
        # O side
        lines.append(f"   vpandn {rO[i2]}, {rO[i1]}, {tmp}")
        lines.append(f"   vpxor {tmp}, {rO[x]}, {tmp}")
        if fold_iota and x == 0:
            lines.append(f"   vpbroadcastd 4(\\rc_eo, %rcx, 8), %ymm12")
            lines.append(f"   vpxor %ymm12, {tmp}, {tmp}")
        lines.append(f"   vmovdqa {tmp}, {a_o[x]}(\\state)")

def emit_round_body(lines):
    # ===== Theta column parities =====
    lines.append("   /* ===== Theta column parities ===== */")
    for x in range(5):
        emit_theta_col(lines, 'e', x, "%ymm0")
        lines.append(f"   vmovdqa %ymm0, {C_E_OFF(x)}(%rsp)")
    for x in range(5):
        emit_theta_col(lines, 'o', x, "%ymm0")
        lines.append(f"   vmovdqa %ymm0, {C_O_OFF(x)}(%rsp)")

    # ===== Theta D ===== (D in ymm6..ymm15)
    lines.append("   /* ===== Theta D (D[0..4] -> ymm6..ymm10 .e, ymm11..ymm15 .o) ===== */")
    for x in range(5):
        emit_theta_d(lines, x, f"%ymm{6+x}", f"%ymm{11+x}", "%ymm0", "%ymm1")

    # ===== Fused Theta-XOR + Rho + Pi =====
    lines.append("   /* ===== Fused Theta-XOR + Rho + Pi ===== */")
    emit_fused_step(lines, 0, 0, 0, 0, "%ymm0", "%ymm1", "%ymm2", "%ymm6", "%ymm11")
    for (x, y, pi_xy, d) in src_xy_per_step():
        emit_fused_step(lines, x, y, pi_xy, d, "%ymm0", "%ymm1", "%ymm2",
                        f"%ymm{6+x}", f"%ymm{11+x}")

    # ===== Chi (rows 0..4); iota folded into row 0 =====
    lines.append("   /* ===== Chi + folded Iota for row 0 ===== */")
    chi_regs = [f"%ymm{i}" for i in range(11)]
    for y in range(5):
        emit_chi_row(lines, y, chi_regs, fold_iota=(y == 0))

def main():
    out = []
    out.append("# Auto-generated by gen_keccak8_eo_inc.py.  Do not edit by hand.")
    out.append("# Keccak-f[1600] x8 batched on AVX2, EVEN/ODD bit-interleaved limbs.")
    out.append("# Sequential fused (B on stack) + Chi with folded Iota.")
    out.append("#")
    out.append("# Macro: _fd_keccak256_avx2_keccak8_eo_f1600_raw \\state \\rc_eo")
    out.append("# Args:  \\state=%rdi (50 ymm SoA EO state), \\rc_eo=%rsi (48 u32 RCs)")
    out.append("# Clobbers: ymm0..ymm15, rax, rcx, flags, [%rsp+0..1919] memory.")
    out.append("# Caller must save rbp.")
    out.append("")
    out.append(".macro _fd_keccak256_avx2_keccak8_eo_f1600_raw state, rc_eo")
    out.append("   /* Stack frame: 50 ymm B + 10 ymm C = 1920 B (32B aligned). */")
    out.append("   push %rbp")
    out.append("   mov %rsp, %rbp")
    out.append("   and $-32, %rsp")
    out.append(f"   sub ${STACK_BYTES}, %rsp")
    out.append("")
    out.append("   xor %rcx, %rcx")
    out.append("   .balign 32")
    out.append("9999:")
    emit_round_body(out)
    out.append("")
    out.append("   inc %rcx")
    out.append("   cmp $24, %rcx")
    out.append("   jne 9999b")
    out.append("")
    out.append("   mov %rbp, %rsp")
    out.append("   pop %rbp")
    out.append(".endm")
    out.append("")

    print("\n".join(out))

if __name__ == "__main__":
    main()
