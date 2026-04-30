#!/usr/bin/env python3
"""Generate fd_keccak256_keccak1eo.inc.

Scalar Keccak-f[1600] for ONE state with EVEN/ODD bit-interleaved limbs.
Mirrors gen_keccak8_eo_inc.py line-by-line, replacing ymm ops with 32-bit GP
ops (one logical 'lane' instead of 8).  Same Theta+D+Fused+Chi+Iota structure.
Same stack layout (just 1/8th the size).

Goal: provide a scalar reference implementation whose data flow is identical
to keccak8 EO, so the HOL Light proof of keccak1eo (phase 2) carries over to
keccak8 (phase 3) by a parallelism argument.

State (caller-owned, 200 bytes total):
  state[ 0.. 24]  : E limb of each Keccak lane (25 u32)
  state[25.. 49]  : O limb of each Keccak lane (25 u32)
  Each limb = 32 bits packed: E_bit_k = w[2k], O_bit_k = w[2k+1] for the
  logical 64-bit Keccak lane w.

Instruction mapping (literal):
  vmovdqa src,dst    -> mov  src,dst        (32-bit move/load/store)
  vpxor src1,src2,dst -> mov src2,dst (if dst!=src2) + xor src1,dst
  vpand               -> mov + and
  vpor                -> mov + or
  vpandn src1,src2,dst -> andn src2,src1,dst   (BMI1, 3-op)
  vpslld $n,src,dst   -> mov src,dst (if dst!=src) + shl $n,dst
  vpsrld $n,src,dst   -> mov src,dst (if dst!=src) + shr $n,dst
  vpbroadcastd mem,*  -> mov mem,reg          (32-bit load)

For 64-bit logical rotations on (E,O) limbs we keep the ymm 3-op idiom
expressed scalarly: shrl + shll + orl with the source loaded into a tmp.
We do NOT collapse to a single rorx — keeping the instruction count
parallel to keccak8 makes side-by-side proof correspondence cleaner.

ABI / register convention:
  rdi = \\state pointer  (preserved through round body)
  rsi = \\rc_eo pointer  (used as cursor; advanced inside the loop)
  rax,rcx = working scratch
  rbx (callee-save, push/pop) = additional scratch
  rbp = saved rsp
"""

# Keccak schedule (same as keccak8 EO).
RHO = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
PI  = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]

def src_xy_per_step():
    """Walk the pi cycle starting at (1,0)."""
    out = []
    src_idx = 1
    for i in range(24):
        out.append((src_idx % 5, src_idx // 5, PI[i], RHO[i]))
        src_idx = PI[i]
    return out

# Stack layout — 1/8th the keccak8 frame.
# B values: 50 u32 = 200 bytes at offsets 0..199.
# C scratch: 10 u32 = 40 bytes at offsets 200..239.
B_E_OFF = lambda z: 4*z              # 0..96
B_O_OFF = lambda z: 4*(25+z)         # 100..196
C_E_OFF = lambda x: 200 + 4*x        # 200..216
C_O_OFF = lambda x: 200 + 4*(5+x)    # 220..236

# Caller state offsets (analogous to keccak8 with stride 4 instead of 32).
A_E_OFF = lambda z: 4*z              # 0..96
A_O_OFF = lambda z: 4*(25+z)         # 100..196

STACK_BYTES = 240  # 60 u32

# AT&T syntax: `xor src, dst` means dst ^= src.
#              `andn src1, src2, dst` (BMI1) means dst = NOT(src2) & src1.

def emit_theta_col(lines, e_or_o, x, dst):
    """C[x] (E or O) = XOR over y of A[x+5y].  dst is a 32-bit GP reg name (%eax)."""
    A_OFF = A_E_OFF if e_or_o == 'e' else A_O_OFF
    lines.append(f"   /* C_{e_or_o}[{x}] = XOR_y A_{e_or_o}[{x}+5y] */")
    lines.append(f"   movl {A_OFF(x)}(\\state), {dst}")
    lines.append(f"   xorl {A_OFF(x+5)}(\\state), {dst}")
    lines.append(f"   xorl {A_OFF(x+10)}(\\state), {dst}")
    lines.append(f"   xorl {A_OFF(x+15)}(\\state), {dst}")
    lines.append(f"   xorl {A_OFF(x+20)}(\\state), {dst}")

def emit_theta_d(lines, x, tmp_a, tmp_b, tmp_c):
    """Compute D[x].e and D[x].o using tmp_a, tmp_b, tmp_c as scratch regs.
       Writes both to stack (overwriting C slots: D_E[x] -> C_E[x], D_O[x] -> C_O[x]).
       Reads C from stack.
       D[x].E = C_e[(x+4)%5] XOR rol32(C_o[(x+1)%5], 1)
       D[x].O = C_o[(x+4)%5] XOR C_e[(x+1)%5]

       We split the rotation into shr+shl+or like the ymm version (3 logical
       steps); using a separate tmp to preserve the source.
    """
    xm = (x+4) % 5
    xp = (x+1) % 5
    lines.append(f"   /* D[{x}] = C[{xm}] ^ rotl1(C[{xp}]) */")
    # Compute rol32(C_o[xp], 1) into tmp_a, using tmp_b as scratch.
    # ymm idiom: vpslld $1; vpsrld $31; vpor.  Scalar: load src, shift two
    # ways, or together.  Need src preserved for second shift.
    lines.append(f"   movl {C_O_OFF(xp)}(%rsp), {tmp_a}")  # tmp_a = C_o[xp]
    lines.append(f"   movl {tmp_a}, {tmp_b}")              # tmp_b = src
    lines.append(f"   shll $1, {tmp_a}")                    # tmp_a <<= 1
    lines.append(f"   shrl $31, {tmp_b}")                   # tmp_b >>= 31
    lines.append(f"   orl {tmp_b}, {tmp_a}")                # tmp_a = rol32(C_o[xp], 1)
    # D_E[x] = C_e[xm] XOR tmp_a; store to stack.
    lines.append(f"   xorl {C_E_OFF(xm)}(%rsp), {tmp_a}")
    # Note: stack slots for C_E[x] / D_E[x] coincide; OK to overwrite since the
    # dependency analysis above shows xm != x and xp != x in mod 5.
    lines.append(f"   movl {tmp_a}, {C_E_OFF(x)}(%rsp)")
    # D_O[x] = C_o[xm] XOR C_e[xp].
    lines.append(f"   movl {C_O_OFF(xm)}(%rsp), {tmp_a}")
    lines.append(f"   xorl {C_E_OFF(xp)}(%rsp), {tmp_a}")
    lines.append(f"   movl {tmp_a}, {C_O_OFF(x)}(%rsp)")

def emit_fused_step(lines, x, y, pi_xy, d, t1, t2, t3):
    """Fused Theta-XOR + Rho + Pi step.  D loaded from stack each step.
       Mirrors keccak8 fused step but D is in stack (not in regs) for
       scalar simplicity."""
    z = x + 5*y
    lines.append(f"   /* fused: src ({x},{y})=A[{z}] -> B[{pi_xy}]  rol={d} */")
    # T_E = A_e[z] XOR D_e[x]
    lines.append(f"   movl {C_E_OFF(x)}(%rsp), {t1}")     # t1 = D_e[x] (from stack — was overwritten over C_e[x])
    lines.append(f"   xorl {A_E_OFF(z)}(\\state), {t1}")  # t1 = A_e[z] XOR D_e[x] = T_E
    # T_O = A_o[z] XOR D_o[x]
    lines.append(f"   movl {C_O_OFF(x)}(%rsp), {t2}")     # t2 = D_o[x]
    lines.append(f"   xorl {A_O_OFF(z)}(\\state), {t2}")  # t2 = T_O

    # Rotate (T_E, T_O) by d into B_E[pi_xy], B_O[pi_xy].
    if d == 0:
        # B_E = T_E, B_O = T_O.
        lines.append(f"   movl {t1}, {B_E_OFF(pi_xy)}(%rsp)")
        lines.append(f"   movl {t2}, {B_O_OFF(pi_xy)}(%rsp)")
    elif d % 2 == 0:
        # Even d=2k: B_E = rol32(T_E, k); B_O = rol32(T_O, k).
        k = d // 2
        # B_E = rol32(T_E, k):  shl k + shr (32-k) | or
        lines.append(f"   movl {t1}, {t3}")
        lines.append(f"   shll ${k}, {t1}")
        lines.append(f"   shrl ${32-k}, {t3}")
        lines.append(f"   orl {t3}, {t1}")
        lines.append(f"   movl {t1}, {B_E_OFF(pi_xy)}(%rsp)")
        # B_O = rol32(T_O, k)
        lines.append(f"   movl {t2}, {t3}")
        lines.append(f"   shll ${k}, {t2}")
        lines.append(f"   shrl ${32-k}, {t3}")
        lines.append(f"   orl {t3}, {t2}")
        lines.append(f"   movl {t2}, {B_O_OFF(pi_xy)}(%rsp)")
    else:
        # Odd d=2k+1: B_E = rol32(T_O, k+1); B_O = rol32(T_E, k).
        k = (d - 1) // 2
        kp = (k + 1) % 32
        # B_E = rol32(T_O, kp)
        if kp == 0:
            lines.append(f"   movl {t2}, {B_E_OFF(pi_xy)}(%rsp)")
        else:
            lines.append(f"   movl {t2}, {t3}")
            lines.append(f"   shll ${kp}, {t2}")
            lines.append(f"   shrl ${32-kp}, {t3}")
            lines.append(f"   orl {t3}, {t2}")
            lines.append(f"   movl {t2}, {B_E_OFF(pi_xy)}(%rsp)")
        # B_O = rol32(T_E, k)
        if k == 0:
            lines.append(f"   movl {t1}, {B_O_OFF(pi_xy)}(%rsp)")
        else:
            lines.append(f"   movl {t1}, {t3}")
            lines.append(f"   shll ${k}, {t1}")
            lines.append(f"   shrl ${32-k}, {t3}")
            lines.append(f"   orl {t3}, {t1}")
            lines.append(f"   movl {t1}, {B_O_OFF(pi_xy)}(%rsp)")

def emit_chi_row(lines, y, b_e_regs, b_o_regs, tmp):
    """Chi for one row.  Loads 5 B_E + 5 B_O into regs, computes A, writes back."""
    base_e = [B_E_OFF(5*y + x) for x in range(5)]
    base_o = [B_O_OFF(5*y + x) for x in range(5)]
    a_e = [A_E_OFF(5*y + x) for x in range(5)]
    a_o = [A_O_OFF(5*y + x) for x in range(5)]
    lines.append(f"   /* Chi row y={y} */")
    # Load B values for this row.
    for x in range(5):
        lines.append(f"   movl {base_e[x]}(%rsp), {b_e_regs[x]}")
        lines.append(f"   movl {base_o[x]}(%rsp), {b_o_regs[x]}")
    # Compute A and write back.
    for x in range(5):
        i1 = (x+1) % 5
        i2 = (x+2) % 5
        # E side: tmp = NOT(B_E[i1]) AND B_E[i2]; A_E = B_E[x] XOR tmp.
        lines.append(f"   andnl {b_e_regs[i2]}, {b_e_regs[i1]}, {tmp}")
        lines.append(f"   xorl {b_e_regs[x]}, {tmp}")
        lines.append(f"   movl {tmp}, {a_e[x]}(\\state)")
        # O side
        lines.append(f"   andnl {b_o_regs[i2]}, {b_o_regs[i1]}, {tmp}")
        lines.append(f"   xorl {b_o_regs[x]}, {tmp}")
        lines.append(f"   movl {tmp}, {a_o[x]}(\\state)")

def emit_round_body(lines):
    # ===== Theta column parities =====
    lines.append("   /* ===== Theta column parities ===== */")
    for x in range(5):
        emit_theta_col(lines, 'e', x, "%eax")
        lines.append(f"   movl %eax, {C_E_OFF(x)}(%rsp)")
    for x in range(5):
        emit_theta_col(lines, 'o', x, "%eax")
        lines.append(f"   movl %eax, {C_O_OFF(x)}(%rsp)")

    # ===== Theta D (overwrite C slots with D) =====
    lines.append("   /* ===== Theta D (overwrites C slots with D) ===== */")
    # Compute all D values, spilling each to stack.  We must compute D_E[x] /
    # D_O[x] BEFORE overwriting the C slot at index x (since other D's may
    # still need C[x]).  Within emit_theta_d we write slot x at the END.
    # Adjacency: D[x] reads C[xm=(x+4)%5] and C[xp=(x+1)%5].  Writing slot x
    # is safe if no later D read uses C[x].  D[x+1] reads C[x] (its xm).
    # So we'd clobber.  Solution: compute all D values first (in a temp area
    # or in regs), then store.  We don't have 10 free regs, so use a separate
    # 10-slot scratch and copy back.  OR: compute D[x] in a fixed loop order
    # that avoids the clobber.
    #
    # Order x=0,2,4,1,3 means:
    #   x=0 reads xm=4, xp=1, writes 0.   4,1 not yet written.
    #   x=2 reads xm=1, xp=3, writes 2.   1,3 not yet written (1 hasn't).
    #   x=4 reads xm=3, xp=0, writes 4.   3 not written; 0 IS written -> bad.
    # So that order doesn't work either.  Just use scratch and copy.
    #
    # Simpler: compute D values into a separate stack region, then memcpy.
    # But we only have a 240-byte stack.  Add 40 more bytes.  OR be more
    # clever: compute D[x] and store immediately to a TEMPORARY location
    # (offsets 240..279).  Then after all 5 D's computed, copy temp -> C slots.
    #
    # For now, use the temp area approach (cleanest).  Stack already padded.
    for x in range(5):
        xm = (x+4) % 5
        xp = (x+1) % 5
        lines.append(f"   /* D[{x}] = C[{xm}] ^ rotl1(C[{xp}]) */")
        # rol32(C_o[xp], 1) into eax, using ecx as scratch.
        lines.append(f"   movl {C_O_OFF(xp)}(%rsp), %eax")
        lines.append(f"   movl %eax, %ecx")
        lines.append(f"   shll $1, %eax")
        lines.append(f"   shrl $31, %ecx")
        lines.append(f"   orl %ecx, %eax")
        lines.append(f"   xorl {C_E_OFF(xm)}(%rsp), %eax")  # eax = D_E[x]
        lines.append(f"   movl %eax, {STACK_BYTES + 4*x}(%rsp)")   # tmp slot for D_E
        # D_O[x] = C_O[xm] XOR C_E[xp]
        lines.append(f"   movl {C_O_OFF(xm)}(%rsp), %eax")
        lines.append(f"   xorl {C_E_OFF(xp)}(%rsp), %eax")
        lines.append(f"   movl %eax, {STACK_BYTES + 4*(5+x)}(%rsp)")  # tmp slot for D_O
    # Copy temp area to C slots.
    for x in range(5):
        lines.append(f"   movl {STACK_BYTES + 4*x}(%rsp), %eax")
        lines.append(f"   movl %eax, {C_E_OFF(x)}(%rsp)")
        lines.append(f"   movl {STACK_BYTES + 4*(5+x)}(%rsp), %eax")
        lines.append(f"   movl %eax, {C_O_OFF(x)}(%rsp)")

    # ===== Fused Theta-XOR + Rho + Pi =====
    lines.append("   /* ===== Fused Theta-XOR + Rho + Pi ===== */")
    # Use eax, ecx as T_E/T_O scratch; ebx as rotation tmp.
    emit_fused_step(lines, 0, 0, 0, 0, "%eax", "%ecx", "%ebx")
    for (x, y, pi_xy, d) in src_xy_per_step():
        emit_fused_step(lines, x, y, pi_xy, d, "%eax", "%ecx", "%ebx")

    # ===== Chi: 10 B regs per row + tmp =====
    lines.append("   /* ===== Chi (rows 0..4) ===== */")
    # B_E[0..4]: %r8d..%r12d
    # B_O[0..4]: %r13d, %r14d, %r15d, %ebx, %ecx
    # tmp:      %eax
    b_e_regs = ["%r8d", "%r9d", "%r10d", "%r11d", "%r12d"]
    b_o_regs = ["%r13d", "%r14d", "%r15d", "%ebx", "%ecx"]
    for y in range(5):
        emit_chi_row(lines, y, b_e_regs, b_o_regs, "%eax")

    # ===== Iota =====
    lines.append("   /* ===== Iota ===== */")
    # rsi is rc_eo pointer (advanced 8 bytes per round below).
    # Read 4 bytes each for E and O components of rc[round].
    lines.append("   movl (\\rc_eo), %eax")
    lines.append(f"   xorl %eax, {A_E_OFF(0)}(\\state)")
    lines.append("   movl 4(\\rc_eo), %eax")
    lines.append(f"   xorl %eax, {A_O_OFF(0)}(\\state)")

def main():
    out = []
    out.append("# Auto-generated by gen_keccak1eo_inc.py.  Do not edit by hand.")
    out.append("# Scalar Keccak-f[1600] for ONE state (E,O bit-interleaved limbs).")
    out.append("# Mirrors keccak8 EO line by line for proof-correspondence purposes.")
    out.append("#")
    out.append("# Macro: _fd_keccak256_keccak1eo_f1600_raw \\state \\rc_eo")
    out.append("# Args:  \\state=%rdi (50 u32 SoA EO state, 200 B), \\rc_eo=%rsi (48 u32 RCs)")
    out.append("# Clobbers: rax, rcx, rdx, rsi, r8-r15, flags, ~280 B stack scratch")
    out.append("# Caller must save rbx, rbp.")
    out.append("")
    out.append(".macro _fd_keccak256_keccak1eo_f1600_raw state, rc_eo")
    out.append("   /* Stack: 50 u32 B + 10 u32 C + 10 u32 D-tmp = 280 B (32B aligned). */")
    out.append("   pushq %rbp")
    out.append("   pushq %rbx")
    out.append("   movq %rsp, %rbp")
    out.append("   andq $-32, %rsp")
    out.append(f"   subq ${STACK_BYTES + 40}, %rsp   /* B + C + 10-slot D tmp */")
    out.append("")
    out.append("   /* Loop end pointer = rc_eo + 24*8. */")
    out.append("   leaq 192(\\rc_eo), %rdx")
    out.append("   .balign 32")
    out.append("9999:")
    emit_round_body(out)
    out.append("")
    out.append("   addq $8, \\rc_eo")
    out.append("   cmpq %rdx, \\rc_eo")
    out.append("   jne 9999b")
    out.append("")
    out.append("   movq %rbp, %rsp")
    out.append("   popq %rbx")
    out.append("   popq %rbp")
    out.append(".endm")
    out.append("")

    print("\n".join(out))

if __name__ == "__main__":
    main()
