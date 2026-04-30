# =============================================================================
# PROOF-ONLY variant of fd_keccak256_keccak1eo.inc.
# =============================================================================
# Generated from the production .inc by replacing each BMI1
#   andnl src1, src2, %eax    (eax = ~src1 & src2, BMI1, 1 op)
# with the equivalent 3-op baseline sequence
#   movl src1, %eax           (eax = src1)
#   notl %eax                 (eax = ~src1)
#   andl src2, %eax           (eax = ~src1 & src2)
# so HOL Light's x86 decoder (which doesn't implement scalar BMI1 ANDN) can
# verify the bytes.  Do NOT use for performance — use the production .inc.
# =============================================================================
# =============================================================================
# Keccak-f[1600] permutation, 1-state scalar, 32-bit EO bit-interleaved.
# =============================================================================
#
# Computes one full Keccak-f[1600] permutation (24 rounds) on a single state
# encoded in 50 32-bit "halves", using only x86_64 baseline scalar ops + BMI1
# `andnl`.  Throughput is ~1/8th of the AVX2 keccak8 EO path; the scalar
# encoding exists primarily as a structured cousin of the vector code suitable
# for HOL Light verification (one round at a time, no SIMD reasoning).
#
# Macro:
#   _fd_keccak256_keccak1eo_f1600_raw \state \rc_eo
#
# Args (System V x86_64 ABI; the C wrapper pins them):
#   \state   = %rdi  pointer to 50 u32 EO state, 200 B, 32-byte aligned
#   \rc_eo   = %rsi  pointer to 48 u32 EO round constants (24 rounds * 2)
#
# Clobbers:  %rax, %rcx, %rdx, %rsi, %r8..%r15, flags, ~280 B stack scratch
# Caller must save %rbx and %rbp (we touch both).
#
# -----------------------------------------------------------------------------
# Even/Odd (EO) bit-interleaving trick.
# -----------------------------------------------------------------------------
# Each 64-bit Keccak lane w decomposes as a pair of 32-bit halves:
#
#     E_k = w[2k]      for k in 0..31      (the even bits of w)
#     O_k = w[2k+1]    for k in 0..31      (the odd  bits of w)
#
# All Keccak ops except theta-D and rho act bitwise on 64-bit lanes, so they
# distribute through EO trivially: pack(a OP b) = (E_a OP E_b, O_a OP O_b)
# for OP in {XOR, AND, NOT}.  Theta-D and rho involve 64-bit rotations, which
# in the EO encoding are:
#
#     rotl64(w, n) for n EVEN  (n = 2m):
#       E' = rotl32(E, m)     O' = rotl32(O, m)
#
#     rotl64(w, n) for n ODD   (n = 2m+1):
#       E' = rotl32(O, m+1)   O' = rotl32(E, m)            <-- swap halves!
#
# The "swap-then-rotate by half" pattern is the entire EO win: where AVX2
# would need a vrolq it doesn't have, EO turns each rotation into one or two
# 32-bit rotations.  In particular the theta-D rotation by 1 collapses to:
#
#     D[x].E = C[xm].E ^ rotl32(C[xp].O, 1)
#     D[x].O = C[xm].O ^         C[xp].E
#
# (xm = (x+4)%5, xp = (x+1)%5).  Notice D[x].O has NO rotation — saves 4 ops.
#
# -----------------------------------------------------------------------------
# State layout (50 u32 = 200 B at \state).
# -----------------------------------------------------------------------------
# Standard 5x5 row-major lane layout (z = x + 5*y):
#
#     A_E[z] at offset 4*z          (    0 .. 96)   25 even halves
#     A_O[z] at offset 4*(25+z)     (  100 ..196)   25 odd  halves
#
# -----------------------------------------------------------------------------
# Stack scratch (280 B at %rsp, 32-byte aligned by the prologue).
# -----------------------------------------------------------------------------
#     B_E[z] at  4*z                (    0 .. 96)   theta-rho-pi destination
#     B_O[z] at  4*(25+z)           (  100 ..196)
#     C_E[x] at 200 + 4*x           (  200 ..216)   theta column parities
#     C_O[x] at 200 + 4*(5+x)       (  220 ..236)
#     D-tmp  at 240 .. 276                          briefly holds D before
#                                                   it's copied over C slots
#
# -----------------------------------------------------------------------------
# Round constants layout (48 u32 = 192 B at \rc_eo).
# -----------------------------------------------------------------------------
# Interleaved (E, O) pairs, 8 B per round:
#
#     rc_eo[2i]   = E half of round-constant i
#     rc_eo[2i+1] = O half of round-constant i
#
# The loop reads two u32s at the end of each round body and advances by 8.
# %rdx holds the loop end pointer = \rc_eo + 192.
#
# -----------------------------------------------------------------------------
# Idiomatic 32-bit rotate: rotl32(x, n) by an amount n in 1..31.
# -----------------------------------------------------------------------------
# Implemented in 4 destructive ops (legacy x86 has no 3-operand shift):
#
#     movl  src,    %tmp        # tmp = src copy (preserved)
#     shll  $n,     %dst        # dst = src << n   (destroys src in dst)
#     shrl  $(32-n),%tmp        # tmp = src >> (32-n)
#     orl   %tmp,   %dst        # dst = (src<<n) | (src>>(32-n))
#
# x86 has a single-op `roll $n, %reg` that would compress this to 1 op; we
# keep the 4-op shape to mirror the AVX2 keccak8 (which is forced into
# vpsrld+vpslld+vpor since AVX2 has no vector rotate).
# =============================================================================

.macro _fd_keccak256_keccak1eo_f1600_raw state, rc_eo

   # ---- Prologue: save callee-saves, align rsp, reserve scratch, ---------
   # ---- set up the loop end pointer.                            ---------
   pushq %rbp
   pushq %rbx
   movq %rsp, %rbp
   andq $-32, %rsp
   subq $280, %rsp

   leaq 192(\rc_eo), %rdx               # %rdx = loop end (rc_eo + 24*8)
   .balign 32
9999:

   # =====================================================================
   # Theta column parities: C[x] = XOR over y of A[x + 5y].
   # =====================================================================
   # Five even, then five odd parities, each XORs five state lanes into a
   # working register and spills to the C scratch slot.

   /* C_e[0] */
   movl 0(\state), %eax
   xorl 20(\state), %eax
   xorl 40(\state), %eax
   xorl 60(\state), %eax
   xorl 80(\state), %eax
   movl %eax, 200(%rsp)

   /* C_e[1] */
   movl 4(\state), %eax
   xorl 24(\state), %eax
   xorl 44(\state), %eax
   xorl 64(\state), %eax
   xorl 84(\state), %eax
   movl %eax, 204(%rsp)

   /* C_e[2] */
   movl 8(\state), %eax
   xorl 28(\state), %eax
   xorl 48(\state), %eax
   xorl 68(\state), %eax
   xorl 88(\state), %eax
   movl %eax, 208(%rsp)

   /* C_e[3] */
   movl 12(\state), %eax
   xorl 32(\state), %eax
   xorl 52(\state), %eax
   xorl 72(\state), %eax
   xorl 92(\state), %eax
   movl %eax, 212(%rsp)

   /* C_e[4] */
   movl 16(\state), %eax
   xorl 36(\state), %eax
   xorl 56(\state), %eax
   xorl 76(\state), %eax
   xorl 96(\state), %eax
   movl %eax, 216(%rsp)

   /* C_o[0] */
   movl 100(\state), %eax
   xorl 120(\state), %eax
   xorl 140(\state), %eax
   xorl 160(\state), %eax
   xorl 180(\state), %eax
   movl %eax, 220(%rsp)

   /* C_o[1] */
   movl 104(\state), %eax
   xorl 124(\state), %eax
   xorl 144(\state), %eax
   xorl 164(\state), %eax
   xorl 184(\state), %eax
   movl %eax, 224(%rsp)

   /* C_o[2] */
   movl 108(\state), %eax
   xorl 128(\state), %eax
   xorl 148(\state), %eax
   xorl 168(\state), %eax
   xorl 188(\state), %eax
   movl %eax, 228(%rsp)

   /* C_o[3] */
   movl 112(\state), %eax
   xorl 132(\state), %eax
   xorl 152(\state), %eax
   xorl 172(\state), %eax
   xorl 192(\state), %eax
   movl %eax, 232(%rsp)

   /* C_o[4] */
   movl 116(\state), %eax
   xorl 136(\state), %eax
   xorl 156(\state), %eax
   xorl 176(\state), %eax
   xorl 196(\state), %eax
   movl %eax, 236(%rsp)

   # =====================================================================
   # Theta D, EO-encoded:  D[x] = C[(x+4)%5] ^ rotl1(C[(x+1)%5]).
   # =====================================================================
   # In the EO encoding this becomes:
   #     D[x].E = C_e[xm] ^ rotl32(C_o[xp], 1)
   #     D[x].O = C_o[xm] ^         C_e[xp]
   # We compute each D into temp slots 240..276, then copy back over the
   # C slots at 200..236 (so subsequent steps can read D from the same
   # offsets used to write C).  The two-stage write is needed because
   # D[x].E reads C[(x-1)%5] = C[xm], which would still be needed by a
   # later D[x'].E reading C[(x'-1)%5] if we wrote in place.

   /* D[0] = C[4] ^ rotl1(C[1]) */
   movl 224(%rsp), %eax                  # eax = C_o[1]
   movl %eax, %ecx
   shll $1, %eax                         # eax = C_o[1] << 1
   shrl $31, %ecx                        # ecx = C_o[1] >> 31
   orl %ecx, %eax                        # eax = rotl32(C_o[1], 1)
   xorl 216(%rsp), %eax                  # eax ^= C_e[4]   = D[0].E
   movl %eax, 240(%rsp)
   movl 236(%rsp), %eax                  # eax = C_o[4]
   xorl 204(%rsp), %eax                  # eax ^= C_e[1]   = D[0].O
   movl %eax, 260(%rsp)

   /* D[1] = C[0] ^ rotl1(C[2]) */
   movl 228(%rsp), %eax
   movl %eax, %ecx
   shll $1, %eax
   shrl $31, %ecx
   orl %ecx, %eax
   xorl 200(%rsp), %eax
   movl %eax, 244(%rsp)
   movl 220(%rsp), %eax
   xorl 208(%rsp), %eax
   movl %eax, 264(%rsp)

   /* D[2] = C[1] ^ rotl1(C[3]) */
   movl 232(%rsp), %eax
   movl %eax, %ecx
   shll $1, %eax
   shrl $31, %ecx
   orl %ecx, %eax
   xorl 204(%rsp), %eax
   movl %eax, 248(%rsp)
   movl 224(%rsp), %eax
   xorl 212(%rsp), %eax
   movl %eax, 268(%rsp)

   /* D[3] = C[2] ^ rotl1(C[4]) */
   movl 236(%rsp), %eax
   movl %eax, %ecx
   shll $1, %eax
   shrl $31, %ecx
   orl %ecx, %eax
   xorl 208(%rsp), %eax
   movl %eax, 252(%rsp)
   movl 228(%rsp), %eax
   xorl 216(%rsp), %eax
   movl %eax, 272(%rsp)

   /* D[4] = C[3] ^ rotl1(C[0]) */
   movl 220(%rsp), %eax
   movl %eax, %ecx
   shll $1, %eax
   shrl $31, %ecx
   orl %ecx, %eax
   xorl 212(%rsp), %eax
   movl %eax, 256(%rsp)
   movl 232(%rsp), %eax
   xorl 200(%rsp), %eax
   movl %eax, 276(%rsp)

   /* Copy D back over the C slots. */
   movl 240(%rsp), %eax
   movl %eax, 200(%rsp)
   movl 260(%rsp), %eax
   movl %eax, 220(%rsp)
   movl 244(%rsp), %eax
   movl %eax, 204(%rsp)
   movl 264(%rsp), %eax
   movl %eax, 224(%rsp)
   movl 248(%rsp), %eax
   movl %eax, 208(%rsp)
   movl 268(%rsp), %eax
   movl %eax, 228(%rsp)
   movl 252(%rsp), %eax
   movl %eax, 212(%rsp)
   movl 272(%rsp), %eax
   movl %eax, 232(%rsp)
   movl 256(%rsp), %eax
   movl %eax, 216(%rsp)
   movl 276(%rsp), %eax
   movl %eax, 236(%rsp)

   # =====================================================================
   # Fused Theta-XOR + Rho + Pi (24 lanes, walking the pi cycle).
   # =====================================================================
   # For each non-(0,0) lane (x,y), starting at (1,0) and following pi:
   #   At[x,y] = A[x,y] XOR D[x]                   (theta XOR)
   #   B[pi(x,y)] = rotl64(At[x,y], rho(x,y))      (rho + pi to dest slot)
   #
   # In EO: rho amounts split by parity.  Even amounts (n = 2m) rotate E by
   # m and O by m independently.  Odd amounts (n = 2m+1) SWAP halves and
   # rotate the SWAPPED E by m+1 and the SWAPPED O by m.
   #
   # Each step loads (At.E, At.O), applies the parity-appropriate rotation,
   # writes both halves to the B slots at offsets 4*pi(x,y) and 4*(25+pi(x,y)).

   /* (0,0) -> B[ 0]  rol=0  (identity, no rotation) */
   movl 200(%rsp), %eax
   xorl 0(\state), %eax
   movl 220(%rsp), %ecx
   xorl 100(\state), %ecx
   movl %eax, 0(%rsp)
   movl %ecx, 100(%rsp)

   /* (1,0) -> B[10]  rol=1   (odd, m=0: B.E = rotl32(O,1), B.O = E) */
   movl 204(%rsp), %eax
   xorl 4(\state), %eax
   movl 224(%rsp), %ecx
   xorl 104(\state), %ecx
   movl %ecx, %ebx
   shll $1, %ecx
   shrl $31, %ebx
   orl %ebx, %ecx                       # ecx = rotl32(At.O, 1) = B.E
   movl %ecx, 40(%rsp)
   movl %eax, 140(%rsp)                 # B.O = At.E

   /* (0,2) -> B[ 7]  rol=3   (odd, m=1: B.E = rotl32(O,2), B.O = rotl32(E,1)) */
   movl 200(%rsp), %eax
   xorl 40(\state), %eax
   movl 220(%rsp), %ecx
   xorl 140(\state), %ecx
   movl %ecx, %ebx
   shll $2, %ecx
   shrl $30, %ebx
   orl %ebx, %ecx                       # ecx = rotl32(At.O, 2) = B.E
   movl %ecx, 28(%rsp)
   movl %eax, %ebx
   shll $1, %eax
   shrl $31, %ebx
   orl %ebx, %eax                       # eax = rotl32(At.E, 1) = B.O
   movl %eax, 128(%rsp)

   /* (2,1) -> B[11]  rol=6   (even, m=3: B.E = rotl32(E,3), B.O = rotl32(O,3)) */
   movl 208(%rsp), %eax
   xorl 28(\state), %eax
   movl 228(%rsp), %ecx
   xorl 128(\state), %ecx
   movl %eax, %ebx
   shll $3, %eax
   shrl $29, %ebx
   orl %ebx, %eax                       # eax = rotl32(At.E, 3) = B.E
   movl %eax, 44(%rsp)
   movl %ecx, %ebx
   shll $3, %ecx
   shrl $29, %ebx
   orl %ebx, %ecx                       # ecx = rotl32(At.O, 3) = B.O
   movl %ecx, 144(%rsp)

   /* (1,2) -> B[17]  rol=10  (even, m=5) */
   movl 204(%rsp), %eax
   xorl 44(\state), %eax
   movl 224(%rsp), %ecx
   xorl 144(\state), %ecx
   movl %eax, %ebx
   shll $5, %eax
   shrl $27, %ebx
   orl %ebx, %eax
   movl %eax, 68(%rsp)
   movl %ecx, %ebx
   shll $5, %ecx
   shrl $27, %ebx
   orl %ebx, %ecx
   movl %ecx, 168(%rsp)

   /* (2,3) -> B[18]  rol=15  (odd, m=7: B.E = rotl32(O,8), B.O = rotl32(E,7)) */
   movl 208(%rsp), %eax
   xorl 68(\state), %eax
   movl 228(%rsp), %ecx
   xorl 168(\state), %ecx
   movl %ecx, %ebx
   shll $8, %ecx
   shrl $24, %ebx
   orl %ebx, %ecx
   movl %ecx, 72(%rsp)
   movl %eax, %ebx
   shll $7, %eax
   shrl $25, %ebx
   orl %ebx, %eax
   movl %eax, 172(%rsp)

   /* (3,3) -> B[ 3]  rol=21  (odd, m=10) */
   movl 212(%rsp), %eax
   xorl 72(\state), %eax
   movl 232(%rsp), %ecx
   xorl 172(\state), %ecx
   movl %ecx, %ebx
   shll $11, %ecx
   shrl $21, %ebx
   orl %ebx, %ecx
   movl %ecx, 12(%rsp)
   movl %eax, %ebx
   shll $10, %eax
   shrl $22, %ebx
   orl %ebx, %eax
   movl %eax, 112(%rsp)

   /* (3,0) -> B[ 5]  rol=28  (even, m=14) */
   movl 212(%rsp), %eax
   xorl 12(\state), %eax
   movl 232(%rsp), %ecx
   xorl 112(\state), %ecx
   movl %eax, %ebx
   shll $14, %eax
   shrl $18, %ebx
   orl %ebx, %eax
   movl %eax, 20(%rsp)
   movl %ecx, %ebx
   shll $14, %ecx
   shrl $18, %ebx
   orl %ebx, %ecx
   movl %ecx, 120(%rsp)

   /* (0,1) -> B[16]  rol=36  (even, m=18) */
   movl 200(%rsp), %eax
   xorl 20(\state), %eax
   movl 220(%rsp), %ecx
   xorl 120(\state), %ecx
   movl %eax, %ebx
   shll $18, %eax
   shrl $14, %ebx
   orl %ebx, %eax
   movl %eax, 64(%rsp)
   movl %ecx, %ebx
   shll $18, %ecx
   shrl $14, %ebx
   orl %ebx, %ecx
   movl %ecx, 164(%rsp)

   /* (1,3) -> B[ 8]  rol=45  (odd, m=22) */
   movl 204(%rsp), %eax
   xorl 64(\state), %eax
   movl 224(%rsp), %ecx
   xorl 164(\state), %ecx
   movl %ecx, %ebx
   shll $23, %ecx
   shrl $9, %ebx
   orl %ebx, %ecx
   movl %ecx, 32(%rsp)
   movl %eax, %ebx
   shll $22, %eax
   shrl $10, %ebx
   orl %ebx, %eax
   movl %eax, 132(%rsp)

   /* (3,1) -> B[21]  rol=55  (odd, m=27) */
   movl 212(%rsp), %eax
   xorl 32(\state), %eax
   movl 232(%rsp), %ecx
   xorl 132(\state), %ecx
   movl %ecx, %ebx
   shll $28, %ecx
   shrl $4, %ebx
   orl %ebx, %ecx
   movl %ecx, 84(%rsp)
   movl %eax, %ebx
   shll $27, %eax
   shrl $5, %ebx
   orl %ebx, %eax
   movl %eax, 184(%rsp)

   /* (1,4) -> B[24]  rol=2   (even, m=1) */
   movl 204(%rsp), %eax
   xorl 84(\state), %eax
   movl 224(%rsp), %ecx
   xorl 184(\state), %ecx
   movl %eax, %ebx
   shll $1, %eax
   shrl $31, %ebx
   orl %ebx, %eax
   movl %eax, 96(%rsp)
   movl %ecx, %ebx
   shll $1, %ecx
   shrl $31, %ebx
   orl %ebx, %ecx
   movl %ecx, 196(%rsp)

   /* (4,4) -> B[ 4]  rol=14  (even, m=7) */
   movl 216(%rsp), %eax
   xorl 96(\state), %eax
   movl 236(%rsp), %ecx
   xorl 196(\state), %ecx
   movl %eax, %ebx
   shll $7, %eax
   shrl $25, %ebx
   orl %ebx, %eax
   movl %eax, 16(%rsp)
   movl %ecx, %ebx
   shll $7, %ecx
   shrl $25, %ebx
   orl %ebx, %ecx
   movl %ecx, 116(%rsp)

   /* (4,0) -> B[15]  rol=27  (odd, m=13) */
   movl 216(%rsp), %eax
   xorl 16(\state), %eax
   movl 236(%rsp), %ecx
   xorl 116(\state), %ecx
   movl %ecx, %ebx
   shll $14, %ecx
   shrl $18, %ebx
   orl %ebx, %ecx
   movl %ecx, 60(%rsp)
   movl %eax, %ebx
   shll $13, %eax
   shrl $19, %ebx
   orl %ebx, %eax
   movl %eax, 160(%rsp)

   /* (0,3) -> B[23]  rol=41  (odd, m=20) */
   movl 200(%rsp), %eax
   xorl 60(\state), %eax
   movl 220(%rsp), %ecx
   xorl 160(\state), %ecx
   movl %ecx, %ebx
   shll $21, %ecx
   shrl $11, %ebx
   orl %ebx, %ecx
   movl %ecx, 92(%rsp)
   movl %eax, %ebx
   shll $20, %eax
   shrl $12, %ebx
   orl %ebx, %eax
   movl %eax, 192(%rsp)

   /* (3,4) -> B[19]  rol=56  (even, m=28) */
   movl 212(%rsp), %eax
   xorl 92(\state), %eax
   movl 232(%rsp), %ecx
   xorl 192(\state), %ecx
   movl %eax, %ebx
   shll $28, %eax
   shrl $4, %ebx
   orl %ebx, %eax
   movl %eax, 76(%rsp)
   movl %ecx, %ebx
   shll $28, %ecx
   shrl $4, %ebx
   orl %ebx, %ecx
   movl %ecx, 176(%rsp)

   /* (4,3) -> B[13]  rol=8   (even, m=4) */
   movl 216(%rsp), %eax
   xorl 76(\state), %eax
   movl 236(%rsp), %ecx
   xorl 176(\state), %ecx
   movl %eax, %ebx
   shll $4, %eax
   shrl $28, %ebx
   orl %ebx, %eax
   movl %eax, 52(%rsp)
   movl %ecx, %ebx
   shll $4, %ecx
   shrl $28, %ebx
   orl %ebx, %ecx
   movl %ecx, 152(%rsp)

   /* (3,2) -> B[12]  rol=25  (odd, m=12) */
   movl 212(%rsp), %eax
   xorl 52(\state), %eax
   movl 232(%rsp), %ecx
   xorl 152(\state), %ecx
   movl %ecx, %ebx
   shll $13, %ecx
   shrl $19, %ebx
   orl %ebx, %ecx
   movl %ecx, 48(%rsp)
   movl %eax, %ebx
   shll $12, %eax
   shrl $20, %ebx
   orl %ebx, %eax
   movl %eax, 148(%rsp)

   /* (2,2) -> B[ 2]  rol=43  (odd, m=21) */
   movl 208(%rsp), %eax
   xorl 48(\state), %eax
   movl 228(%rsp), %ecx
   xorl 148(\state), %ecx
   movl %ecx, %ebx
   shll $22, %ecx
   shrl $10, %ebx
   orl %ebx, %ecx
   movl %ecx, 8(%rsp)
   movl %eax, %ebx
   shll $21, %eax
   shrl $11, %ebx
   orl %ebx, %eax
   movl %eax, 108(%rsp)

   /* (2,0) -> B[20]  rol=62  (even, m=31) */
   movl 208(%rsp), %eax
   xorl 8(\state), %eax
   movl 228(%rsp), %ecx
   xorl 108(\state), %ecx
   movl %eax, %ebx
   shll $31, %eax
   shrl $1, %ebx
   orl %ebx, %eax
   movl %eax, 80(%rsp)
   movl %ecx, %ebx
   shll $31, %ecx
   shrl $1, %ebx
   orl %ebx, %ecx
   movl %ecx, 180(%rsp)

   /* (0,4) -> B[14]  rol=18  (even, m=9) */
   movl 200(%rsp), %eax
   xorl 80(\state), %eax
   movl 220(%rsp), %ecx
   xorl 180(\state), %ecx
   movl %eax, %ebx
   shll $9, %eax
   shrl $23, %ebx
   orl %ebx, %eax
   movl %eax, 56(%rsp)
   movl %ecx, %ebx
   shll $9, %ecx
   shrl $23, %ebx
   orl %ebx, %ecx
   movl %ecx, 156(%rsp)

   /* (4,2) -> B[22]  rol=39  (odd, m=19) */
   movl 216(%rsp), %eax
   xorl 56(\state), %eax
   movl 236(%rsp), %ecx
   xorl 156(\state), %ecx
   movl %ecx, %ebx
   shll $20, %ecx
   shrl $12, %ebx
   orl %ebx, %ecx
   movl %ecx, 88(%rsp)
   movl %eax, %ebx
   shll $19, %eax
   shrl $13, %ebx
   orl %ebx, %eax
   movl %eax, 188(%rsp)

   /* (2,4) -> B[ 9]  rol=61  (odd, m=30) */
   movl 208(%rsp), %eax
   xorl 88(\state), %eax
   movl 228(%rsp), %ecx
   xorl 188(\state), %ecx
   movl %ecx, %ebx
   shll $31, %ecx
   shrl $1, %ebx
   orl %ebx, %ecx
   movl %ecx, 36(%rsp)
   movl %eax, %ebx
   shll $30, %eax
   shrl $2, %ebx
   orl %ebx, %eax
   movl %eax, 136(%rsp)

   /* (4,1) -> B[ 6]  rol=20  (even, m=10) */
   movl 216(%rsp), %eax
   xorl 36(\state), %eax
   movl 236(%rsp), %ecx
   xorl 136(\state), %ecx
   movl %eax, %ebx
   shll $10, %eax
   shrl $22, %ebx
   orl %ebx, %eax
   movl %eax, 24(%rsp)
   movl %ecx, %ebx
   shll $10, %ecx
   shrl $22, %ebx
   orl %ebx, %ecx
   movl %ecx, 124(%rsp)

   /* (1,1) -> B[ 1]  rol=44  (even, m=22) */
   movl 204(%rsp), %eax
   xorl 24(\state), %eax
   movl 224(%rsp), %ecx
   xorl 124(\state), %ecx
   movl %eax, %ebx
   shll $22, %eax
   shrl $10, %ebx
   orl %ebx, %eax
   movl %eax, 4(%rsp)
   movl %ecx, %ebx
   shll $22, %ecx
   shrl $10, %ebx
   orl %ebx, %ecx
   movl %ecx, 104(%rsp)

   # =====================================================================
   # Chi: A[x,y] = B[x,y] XOR (NOT B[x+1,y] AND B[x+2,y])
   # =====================================================================
   # Five rows of five lanes.  Each row loads its 10 B halves into named
   # GP regs (5 even into r8-r12, 5 odd into r13-r15+ebx+ecx), then writes
   # the chi result back into the caller state slots A[x,y].
   #
   # `andnl src1, src2, dst` (BMI1) computes dst = NOT(src1) AND src2 in
   # one op; saves a `notl` per chi step (50 chi steps per round = 50 ops
   # saved).  This is the only BMI1 dependency in the macro.

   /* Chi row y=0 */
   movl 0(%rsp), %r8d
   movl 100(%rsp), %r13d
   movl 4(%rsp), %r9d
   movl 104(%rsp), %r14d
   movl 8(%rsp), %r10d
   movl 108(%rsp), %r15d
   movl 12(%rsp), %r11d
   movl 112(%rsp), %ebx
   movl 16(%rsp), %r12d
   movl 116(%rsp), %ecx
   movl %r9d, %eax
   notl %eax
   andl %r10d, %eax
   xorl %r8d, %eax                      # eax = B_E[0] ^ above   = A_E[0]
   movl %eax, 0(\state)
   movl %r14d, %eax
   notl %eax
   andl %r15d, %eax
   xorl %r13d, %eax
   movl %eax, 100(\state)
   movl %r10d, %eax
   notl %eax
   andl %r11d, %eax
   xorl %r9d, %eax
   movl %eax, 4(\state)
   movl %r15d, %eax
   notl %eax
   andl %ebx, %eax
   xorl %r14d, %eax
   movl %eax, 104(\state)
   movl %r11d, %eax
   notl %eax
   andl %r12d, %eax
   xorl %r10d, %eax
   movl %eax, 8(\state)
   movl %ebx, %eax
   notl %eax
   andl %ecx, %eax
   xorl %r15d, %eax
   movl %eax, 108(\state)
   movl %r12d, %eax
   notl %eax
   andl %r8d, %eax
   xorl %r11d, %eax
   movl %eax, 12(\state)
   movl %ecx, %eax
   notl %eax
   andl %r13d, %eax
   xorl %ebx, %eax
   movl %eax, 112(\state)
   movl %r8d, %eax
   notl %eax
   andl %r9d, %eax
   xorl %r12d, %eax
   movl %eax, 16(\state)
   movl %r13d, %eax
   notl %eax
   andl %r14d, %eax
   xorl %ecx, %eax
   movl %eax, 116(\state)

   /* Chi row y=1 */
   movl 20(%rsp), %r8d
   movl 120(%rsp), %r13d
   movl 24(%rsp), %r9d
   movl 124(%rsp), %r14d
   movl 28(%rsp), %r10d
   movl 128(%rsp), %r15d
   movl 32(%rsp), %r11d
   movl 132(%rsp), %ebx
   movl 36(%rsp), %r12d
   movl 136(%rsp), %ecx
   movl %r9d, %eax
   notl %eax
   andl %r10d, %eax
   xorl %r8d, %eax
   movl %eax, 20(\state)
   movl %r14d, %eax
   notl %eax
   andl %r15d, %eax
   xorl %r13d, %eax
   movl %eax, 120(\state)
   movl %r10d, %eax
   notl %eax
   andl %r11d, %eax
   xorl %r9d, %eax
   movl %eax, 24(\state)
   movl %r15d, %eax
   notl %eax
   andl %ebx, %eax
   xorl %r14d, %eax
   movl %eax, 124(\state)
   movl %r11d, %eax
   notl %eax
   andl %r12d, %eax
   xorl %r10d, %eax
   movl %eax, 28(\state)
   movl %ebx, %eax
   notl %eax
   andl %ecx, %eax
   xorl %r15d, %eax
   movl %eax, 128(\state)
   movl %r12d, %eax
   notl %eax
   andl %r8d, %eax
   xorl %r11d, %eax
   movl %eax, 32(\state)
   movl %ecx, %eax
   notl %eax
   andl %r13d, %eax
   xorl %ebx, %eax
   movl %eax, 132(\state)
   movl %r8d, %eax
   notl %eax
   andl %r9d, %eax
   xorl %r12d, %eax
   movl %eax, 36(\state)
   movl %r13d, %eax
   notl %eax
   andl %r14d, %eax
   xorl %ecx, %eax
   movl %eax, 136(\state)

   /* Chi row y=2 */
   movl 40(%rsp), %r8d
   movl 140(%rsp), %r13d
   movl 44(%rsp), %r9d
   movl 144(%rsp), %r14d
   movl 48(%rsp), %r10d
   movl 148(%rsp), %r15d
   movl 52(%rsp), %r11d
   movl 152(%rsp), %ebx
   movl 56(%rsp), %r12d
   movl 156(%rsp), %ecx
   movl %r9d, %eax
   notl %eax
   andl %r10d, %eax
   xorl %r8d, %eax
   movl %eax, 40(\state)
   movl %r14d, %eax
   notl %eax
   andl %r15d, %eax
   xorl %r13d, %eax
   movl %eax, 140(\state)
   movl %r10d, %eax
   notl %eax
   andl %r11d, %eax
   xorl %r9d, %eax
   movl %eax, 44(\state)
   movl %r15d, %eax
   notl %eax
   andl %ebx, %eax
   xorl %r14d, %eax
   movl %eax, 144(\state)
   movl %r11d, %eax
   notl %eax
   andl %r12d, %eax
   xorl %r10d, %eax
   movl %eax, 48(\state)
   movl %ebx, %eax
   notl %eax
   andl %ecx, %eax
   xorl %r15d, %eax
   movl %eax, 148(\state)
   movl %r12d, %eax
   notl %eax
   andl %r8d, %eax
   xorl %r11d, %eax
   movl %eax, 52(\state)
   movl %ecx, %eax
   notl %eax
   andl %r13d, %eax
   xorl %ebx, %eax
   movl %eax, 152(\state)
   movl %r8d, %eax
   notl %eax
   andl %r9d, %eax
   xorl %r12d, %eax
   movl %eax, 56(\state)
   movl %r13d, %eax
   notl %eax
   andl %r14d, %eax
   xorl %ecx, %eax
   movl %eax, 156(\state)

   /* Chi row y=3 */
   movl 60(%rsp), %r8d
   movl 160(%rsp), %r13d
   movl 64(%rsp), %r9d
   movl 164(%rsp), %r14d
   movl 68(%rsp), %r10d
   movl 168(%rsp), %r15d
   movl 72(%rsp), %r11d
   movl 172(%rsp), %ebx
   movl 76(%rsp), %r12d
   movl 176(%rsp), %ecx
   movl %r9d, %eax
   notl %eax
   andl %r10d, %eax
   xorl %r8d, %eax
   movl %eax, 60(\state)
   movl %r14d, %eax
   notl %eax
   andl %r15d, %eax
   xorl %r13d, %eax
   movl %eax, 160(\state)
   movl %r10d, %eax
   notl %eax
   andl %r11d, %eax
   xorl %r9d, %eax
   movl %eax, 64(\state)
   movl %r15d, %eax
   notl %eax
   andl %ebx, %eax
   xorl %r14d, %eax
   movl %eax, 164(\state)
   movl %r11d, %eax
   notl %eax
   andl %r12d, %eax
   xorl %r10d, %eax
   movl %eax, 68(\state)
   movl %ebx, %eax
   notl %eax
   andl %ecx, %eax
   xorl %r15d, %eax
   movl %eax, 168(\state)
   movl %r12d, %eax
   notl %eax
   andl %r8d, %eax
   xorl %r11d, %eax
   movl %eax, 72(\state)
   movl %ecx, %eax
   notl %eax
   andl %r13d, %eax
   xorl %ebx, %eax
   movl %eax, 172(\state)
   movl %r8d, %eax
   notl %eax
   andl %r9d, %eax
   xorl %r12d, %eax
   movl %eax, 76(\state)
   movl %r13d, %eax
   notl %eax
   andl %r14d, %eax
   xorl %ecx, %eax
   movl %eax, 176(\state)

   /* Chi row y=4 */
   movl 80(%rsp), %r8d
   movl 180(%rsp), %r13d
   movl 84(%rsp), %r9d
   movl 184(%rsp), %r14d
   movl 88(%rsp), %r10d
   movl 188(%rsp), %r15d
   movl 92(%rsp), %r11d
   movl 192(%rsp), %ebx
   movl 96(%rsp), %r12d
   movl 196(%rsp), %ecx
   movl %r9d, %eax
   notl %eax
   andl %r10d, %eax
   xorl %r8d, %eax
   movl %eax, 80(\state)
   movl %r14d, %eax
   notl %eax
   andl %r15d, %eax
   xorl %r13d, %eax
   movl %eax, 180(\state)
   movl %r10d, %eax
   notl %eax
   andl %r11d, %eax
   xorl %r9d, %eax
   movl %eax, 84(\state)
   movl %r15d, %eax
   notl %eax
   andl %ebx, %eax
   xorl %r14d, %eax
   movl %eax, 184(\state)
   movl %r11d, %eax
   notl %eax
   andl %r12d, %eax
   xorl %r10d, %eax
   movl %eax, 88(\state)
   movl %ebx, %eax
   notl %eax
   andl %ecx, %eax
   xorl %r15d, %eax
   movl %eax, 188(\state)
   movl %r12d, %eax
   notl %eax
   andl %r8d, %eax
   xorl %r11d, %eax
   movl %eax, 92(\state)
   movl %ecx, %eax
   notl %eax
   andl %r13d, %eax
   xorl %ebx, %eax
   movl %eax, 192(\state)
   movl %r8d, %eax
   notl %eax
   andl %r9d, %eax
   xorl %r12d, %eax
   movl %eax, 96(\state)
   movl %r13d, %eax
   notl %eax
   andl %r14d, %eax
   xorl %ecx, %eax
   movl %eax, 196(\state)

   # =====================================================================
   # Iota: XOR the round constant into A[0,0] (lane 0 = both halves).
   # =====================================================================
   movl (\rc_eo), %eax
   xorl %eax, 0(\state)                 # A_E[0] ^= RC.E
   movl 4(\rc_eo), %eax
   xorl %eax, 100(\state)               # A_O[0] ^= RC.O

   # ---- Loop ----
   addq $8, \rc_eo
   cmpq %rdx, \rc_eo
   jne 9999b

   # ---- Epilogue ----
   movq %rbp, %rsp
   popq %rbx
   popq %rbp
.endm
