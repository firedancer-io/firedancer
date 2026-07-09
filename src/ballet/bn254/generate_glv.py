"""
Generates the constants used in BN254 GLV, including the basis vector
elements, beta in montgomery domain, and the g1/g2 fixed-pointer inverses.
https://www.iacr.org/archive/crypto2001/21390189.pdf
"""

import math

# BN parameter
u = 0x44e992b44a6909f1

p = 36*u**4 + 36*u**3 + 24*u**2 + 6*u + 1
assert p == 21888242871839275222246405745257275088696311157297823662689037894645226208583

r = 36*u**4 + 36*u**3 + 18*u**2 + 6*u + 1
assert r == 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Primitive cube root of unity in Fp
beta = 21888242871839275220042445260109153167277707414472061641714758635765020556616
assert pow(beta, 3, p) == 1 and beta != 1

# Endomorphism eigenvalue in Fr
lam = 4407920970296243842393367215006156084916469457145843978461
assert (lam**2 + lam + 1) % r == 0

# L = { (a, b) in Z^2 : a + b*lambda = 0 (mod r) }
# We run the half-GCD on (r, lambda) and take the two vectors
# between the sqrt(r) boundary.

threshold = math.isqrt(r)
r_prev, r_curr = r, lam
t_prev, t_curr = 0, 1
while r_curr >= threshold:
    q = r_prev // r_curr
    r_prev, r_curr = r_curr, r_prev - q * r_curr
    t_prev, t_curr = t_curr, t_prev - q * t_curr
v_above = (r_prev, -t_prev)
v_below = (r_curr, -t_curr)

assert (v_above[0] + v_above[1] * lam) % r == 0
assert (v_below[0] + v_below[1] * lam) % r == 0
assert abs(v_above[0] * v_below[1] - v_above[1] * v_below[0]) == r

# The three magnitudes used in the lattice matrix
N_A = abs(v_below[1])   # = |n11| in G1 notation
N_B = abs(v_above[1])   # = |n12| = |n21|
N_C = abs(v_above[0])   # = |n22|
assert N_B == abs(v_below[0])

# --- Babai fixed-point inverses ---
#
# G1: g1 = round(2^256 * N_C / r)   (encodes N_C/r)
# G2: g1 = round(2^256 * N_A / r)   (encodes N_A/r)
# Both: g2 = round(2^256 * N_B / r)
g1_for_g1 = (2**256 * N_C + r // 2) // r
g1_for_g2 = (2**256 * N_A + r // 2) // r
g2        = (2**256 * N_B + r // 2) // r

R = 2**256
beta_mont = (beta * R) % p

for s in [1, r - 1, 2**256 - 1, lam, 0xdeadbeefcafebabe]:
    # G1
    b1 = (s * g1_for_g1) >> 256
    b2 = (s * g2) >> 256
    k1 = s - b1 * N_A - b2 * N_B
    k2 =     b1 * N_B - b2 * N_C
    assert abs(k1).bit_length() <= 129
    assert abs(k2).bit_length() <= 129

    # G2
    b1 = (s * g1_for_g2) >> 256
    b2 = (s * g2) >> 256
    k1 = s - b1 * N_C - b2 * N_B
    k2 =     b2 * N_A - b1 * N_B
    assert abs(k1).bit_length() <= 129
    assert abs(k2).bit_length() <= 129

def to_limbs(val, n):
    out = []
    for _ in range(n):
        out.append(val & ((1 << 64) - 1))
        val >>= 64
    assert val == 0
    return out

def fmt(vals):
    return ", ".join(f"0x{v:016x}UL" for v in vals)

print("/* Lattice constants */")
print(f"na[ 2 ] = {{ {fmt(to_limbs(N_A, 2))} }};")
print(f"nb[ 1 ] = {{ {fmt(to_limbs(N_B, 1))} }};")
print(f"nc[ 2 ] = {{ {fmt(to_limbs(N_C, 2))} }};")

print()
print("/* Babai fixed-point inverses */")
print(f"g1 for G1 (N_C/r)[ 3 ] = {{ {fmt(to_limbs(g1_for_g1, 3))} }};")
print(f"g1 for G2 (N_A/r)[ 3 ] = {{ {fmt(to_limbs(g1_for_g2, 3))} }};")
print(f"g2        (N_B/r)[ 2 ] = {{ {fmt(to_limbs(g2, 2))} }};")

print()
print("/* beta in Montgomery form */")
print(f"beta_mont[ 4 ] = {{ {fmt(to_limbs(beta_mont, 4))} }};")
