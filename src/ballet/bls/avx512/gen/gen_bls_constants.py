#!/usr/bin/env python3
"""Generate the fixed BLS12-381 RNS constants (fd_bls_constants.h) used
by the AVX-512 backend.

This generator intentionally uses only the Python standard library.  The
generated header is committed, so Python is not needed to build or run
Firedancer.  Re-running this file provides an auditable derivation of every
large RNS table used by the C implementation.
"""

from __future__ import annotations

from math import prod
from pathlib import Path


P = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
    "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)
R = 1 << 52
MASK52 = R - 1
PRECISION = 64

# These are the deterministic IntRNS4 bases selected for BLS12-381.  Keeping
# the basis explicit makes regeneration independent of a prime-search package.
M1_MOD = [
    1125899906842615, 1125899906842609, 1125899906842591,
    1125899906842559, 1125899906842553, 1125899906842549,
    1125899906842541, 1125899906842511,
]
M2_MOD = [
    1125899906842623, 1125899906842621, 1125899906842619,
    1125899906842613, 1125899906842607, 1125899906842603,
    1125899906842597, 1125899906842589,
]

# Fixed square root selected when the bases were designed.  It is validated
# below, rather than requiring a symbolic-number package to rediscover it.
QR_PREMULT = int(
    "1764464526391023609719698959639504118661371030573300677125606932387184635588659624517358062862068369090674362610896848484"
)

# Fixed field constants (Frobenius coefficients for the flattened
# Fp[u]/(u^2+1), Fp2[v]/(v^3-(u+1)), Fp6[w]/(w^2-v) tower, plus the
# SSWU/isogeny and small rational constants).  They are canonical field
# elements here and are encoded into both fixed RNS bases below.
FIELD_CONSTANTS = {
    "one_third": "011560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71d",
    "neg_two_thirds": "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
    "frob1_2":  "1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
    "frob1_3":  "1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad",
    "frob1_4":  "05f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
    "frob1_5":  "1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8",
    "frob1_6":  "0fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3",
    "frob1_7":  "06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09",
    "frob1_8":  "135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2",
    "frob1_9":  "05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116",
    "frob1_10": "144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995",
    "frob2_1":  "05f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
    "frob2_2":  "1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
    "frob2_3":  "05f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff",
    "frob2_5":  "1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad",
    "frob3_2":  "135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2",
    "frob3_3":  "06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09",
    # RFC 9380 sqrt_ratio constants for Fp2 (q = p^2 = 9 mod 16, c1 = 3):
    # c7 = Z^((c2+1)/2) with c2 = (q-1)/8 and Z = -(2+u).  (c6 = Z^c2 equals
    # (frob3_3, frob3_3), whose square is -u and fourth power is -1.)
    "sswu_c7_re": "13dc0969311e2ba565924cb0b6f7bb9857f157e17f0c8db4e484fcb27b8be0b36dfa0340c422fb7efe9d9a3234336d5e",
    "sswu_c7_im": "71d42ac9c54001a21acf9187d469d919a830a2c969128d22659dc2f8263f1ca73c5b0e02c05ec381b8684a676a81381",
    # G1 endomorphism sigma(x,y) = (beta*x, y), beta^3 = 1 (blst e1.c beta,
    # canonical form), used by the Scott G1 subgroup test
    # sigma^2(P) == [-z^2]P.
    "g1_beta": "1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
    # SSWU domain parameters on the isogenous curve E': A' = 240u and
    # B' = 1012(1+u) apply through full fd_bls_fp_mul by these encoded
    # small scalars (a raw small-multiple accumulation would scale the
    # redundant RNS bound past what the lazy reduction tolerates);
    # zxa_im = -480 covers the xd==0 substitute Z*A' = 240-480u.
    "c240":  "f0",
    "c1012": "3f4",
    "sswu_zxa_im": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8cb",
    # 3-isogeny map E' -> E2 coefficients (canonical forms of blst
    # map_to_g2.c iso_x_num/iso_x_den/iso_y_num/iso_y_den; index [k] is
    # the degree-k coefficient; zero components are omitted and the
    # leading x_den/y_den coefficients are monic).
    "iso_xn0":    "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
    "iso_xn1_im": "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a",
    "iso_xn2_re": "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
    "iso_xn2_im": "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d",
    "iso_xn3_re": "171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
    "iso_xd0_im": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63",
    "iso_xd1_re": "c",
    "iso_xd1_im": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f",
    "iso_yn0":    "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
    "iso_yn1_im": "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be",
    "iso_yn2_re": "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
    "iso_yn2_im": "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f",
    "iso_yn3_re": "124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
    "iso_yd0":    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
    "iso_yd1_im": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3",
    "iso_yd2_re": "12",
    "iso_yd2_im": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99",
}

NEG_G1_X = int("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16)
NEG_G1_Y = int("114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca", 16)
FIELD_CONSTANTS.update({
    "neg_g1_x": f"{NEG_G1_X:x}",
    "neg_g1_y": f"{NEG_G1_Y:x}",
    "neg_g1_3x": f"{(3 * NEG_G1_X) % P:x}",
    "neg_g1_minus_2y": f"{(-2 * NEG_G1_Y) % P:x}",
})


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def icrt_factors(moduli: list[int]) -> list[int]:
    modulus = prod(moduli)
    out = []
    for m in moduli:
        rest = modulus // m
        out.append((rest * pow(rest, -1, m)) % modulus)
    return out


def crt(residues: list[int], moduli: list[int]) -> int:
    modulus = prod(moduli)
    return sum(r * f for r, f in zip(residues, icrt_factors(moduli))) % modulus


def small_factor(moduli: list[int]) -> int:
    modulus = prod(moduli)
    return crt([modulus // m for m in moduli], moduli)


def matrix(
    moduli_in: list[int],
    moduli_out: list[int],
    premult: int,
    postmult: int,
    *,
    target: int | None = None,
    input_bits: int = 52,
    input_digits: int = 1,
    output_bits: int = 52,
    output_digits: int = 1,
    floor_quotient: bool = False,
) -> tuple[list[list[int]], list[int], list[int]]:
    """Derive Appendix A's fixed-point CRNS map.

    A row holds (((ICRT_i*premult) mod B)*postmult) mod n_j.  ``sqe``
    estimates the CRT quotient k and ``correction`` contributes k*(-B).
    """
    modulus_in = prod(moduli_in)
    modulus_out = prod(moduli_out)
    if target is None:
        target = modulus_out
    rows: list[list[int]] = []
    sqe: list[int] = []
    for digit in range(input_digits):
        for factor in icrt_factors(moduli_in):
            shifted = (premult * (1 << (input_bits * digit)) * factor) % modulus_in
            transformed = ((shifted % target) * postmult) % modulus_out
            row = []
            for m in moduli_out:
                residue = transformed % m
                row.extend((residue >> (output_bits * j)) & ((1 << output_bits) - 1)
                           for j in range(output_digits))
            rows.append(row)
            num = shifted << PRECISION
            sqe.append(num // modulus_in if floor_quotient else ceil_div(num, modulus_in))
    correction_value = (((-modulus_in) % target) * postmult) % modulus_out
    correction = []
    for m in moduli_out:
        residue = correction_value % m
        correction.extend((residue >> (output_bits * j)) & ((1 << output_bits) - 1)
                          for j in range(output_digits))
    return rows, correction, sqe


def exact_rns(value: int, total_rotation: int, *, wide: bool = False) -> tuple[list[int], list[int]]:
    """Encode a value in the rotated RNS Montgomery representation."""
    m1 = prod(M1_MOD)
    m12 = m1 * prod(M2_MOD)
    redundance = value // P
    encoded = (value * m1) % P
    if wide:
        encoded = (encoded * m1) % P
    encoded += redundance * P
    encoded = (encoded * total_rotation) % m12
    if wide:
        encoded = (encoded * total_rotation) % m12
    return ([encoded % m for m in M1_MOD], [encoded % m for m in M2_MOD])


def wide_zero_offset(total_rotation: int, element_bound: int = 128, rns_bound: int = 2048) -> tuple[list[int], list[int], list[int], list[int]]:
    """A large zero modulo p, shaped for borrow-free signed IFMA sums."""
    desired = 40 * 40 * rns_bound * P * P
    desired_m1, desired_m2 = exact_rns(desired, total_rotation, wide=True)
    high1, low1, high2, low2 = [], [], [], []
    minimum_low = R * element_bound
    for mod, residue, highs, lows in (
        (M1_MOD, desired_m1, high1, low1),
        (M2_MOD, desired_m2, high2, low2),
    ):
        for m, rns in zip(mod, residue):
            value = element_bound * m * m
            low = (value & MASK52) + rns + m * element_bound
            while low < minimum_low:
                low += m
            lows.append(low)
            highs.append(value >> 52)
    return high1, low1, high2, low2


def c_u64(value: int) -> str:
    return f"{value}UL"


def emit_array(name: str, values: list[int], align: bool = True) -> str:
    prefix = "static ulong const __attribute__((aligned(64)))" if align else "static ulong const"
    body = ", ".join(c_u64(v) for v in values)
    return f"{prefix} {name}[8] = {{ {body} }};"


def emit_fp(name: str, m1: list[int], m2: list[int]) -> str:
    lanes1 = ", ".join(c_u64(v) for v in m1)
    lanes2 = ", ".join(c_u64(v) for v in m2)
    return (
        f"static fd_bls_fp_t const {name} = {{\n"
        f"  .m1 = {{ {lanes1} }},\n"
        f"  .m2 = {{ {lanes2} }}\n"
        f"}};"
    )


def emit_limbs(name: str, value: int) -> str:
    limbs = [(value >> (64 * i)) & ((1 << 64) - 1) for i in range(6)]
    body = ", ".join(c_u64(v) for v in limbs)
    return f"static ulong const {name}[6] = {{ {body} }};"


def emit_khi_table(name: str, shift: list[int]) -> str:
    assert max(shift) < (1 << 50) and 3 * max(shift) < R
    assert sum(2 * m * q for m, q in zip(M2_MOD, matrix_r2_sqe())) >> 64 < (4 << 52)
    rows = [[k * v for v in shift] for k in range(4)]
    body = ",\n  ".join("{ " + ", ".join(c_u64(v) for v in row) + " }" for row in rows)
    return (
        f"static ulong const __attribute__((aligned(64))) {name}[4][8] = {{\n"
        f"  {body}\n}};"
    )


def matrix_r2_sqe() -> list[int]:
    m1 = prod(M1_MOD)
    r2_pre = m1 * pow(R, -1, prod(M2_MOD))
    r2_post = R * R * QR_PREMULT
    return matrix(M2_MOD, M1_MOD, r2_pre, r2_post)[2]


def emit_matrix(name: str, rows: list[list[int]]) -> str:
    body = ",\n  ".join("{ " + ", ".join(c_u64(v) for v in row) + " }" for row in rows)
    return (
        f"static ulong const __attribute__((aligned(64))) {name}[8][8] = {{\n"
        f"  {body}\n}};"
    )


def generate() -> str:
    m1 = prod(M1_MOD)
    m2 = prod(M2_MOD)
    m12 = m1 * m2
    inv_factor = pow(m1, -1, m2)
    m1_opt = small_factor(M1_MOD)

    initial_r1 = (pow(-P, -1, m1) * pow(R, -1, m1)) % m1
    assert pow(QR_PREMULT, 2, m1) == (initial_r1 * pow(m1_opt, -1, m1)) % m1

    # These fixed pre/post factors absorb both Algorithm 2 CRNS scales and
    # the per-lane IFMA Montgomery radix R.  QR_PREMULT additionally makes the
    # M1->M2 matrix cyclic, allowing its quotient correction to be omitted.
    r1_post = P * inv_factor * inv_factor * R * R
    r2_pre = m1 * pow(R, -1, m2)
    r2_post = R * R * QR_PREMULT
    convert_to_pre = m1
    convert_to_post = inv_factor * R * R
    convert_from_pre = m1 * pow(R, -1, m2)
    convert_from_post = pow(m1, -1, P)

    r1, r1_corr, r1_sqe = matrix(M1_MOD, M2_MOD, m1_opt, r1_post)
    r2, r2_corr, r2_sqe = matrix(M2_MOD, M1_MOD, r2_pre, r2_post)
    r2_corr_shift = [(x * R) % m for x, m in zip(r2_corr, M1_MOD)]

    # N->M expansion maps with an extra small output scale folded in: the
    # CRT reconstruction is linear, so scaling every row and both
    # corrections by c (mod each M lane) yields c*X directly, letting the
    # cyclotomic square apply its 3x/6x post-scale without delaying the
    # N->M stage behind an extra normalize.
    def scaled(rows, c):
        return [[(v * c) % m for v, m in zip(row, M1_MOD)] for row in rows]
    def scaled_vec(vec, c):
        return [(v * c) % m for v, m in zip(vec, M1_MOD)]
    to, to_corr, to_sqe = matrix(
        [P], M2_MOD, convert_to_pre, convert_to_post,
        input_bits=50, input_digits=8, floor_quotient=True,
    )
    from_, from_corr, from_sqe = matrix(
        M2_MOD, [P], convert_from_pre, convert_from_post,
        output_bits=52, output_digits=8,
    )

    # Fused blst-Montgomery entry: the radix entry with the premult scaled
    # by 2^-384, so raw blst_fp Montgomery limbs (x*2^384 mod p) load as
    # the same RNS value the canonical entry produces for x -- zero
    # per-coordinate blst_uint64_from_fp cost.
    to_mont_pre = convert_to_pre * pow(2, -384, P) % P
    to_mont, to_mont_corr, to_mont_sqe = matrix(
        [P], M2_MOD, to_mont_pre, convert_to_post,
        input_bits=50, input_digits=8, floor_quotient=True,
    )

    # Diagonal/cyclic form used by the no-k r1 kernel.
    r1_perm = [[r1[(lane - step) % 8][lane] for lane in range(8)] for step in range(8)]

    icrt1 = m2 * pow(m2, -1, m1)
    icrt2 = m1 * pow(m1, -1, m2)
    rotation_factor = (QR_PREMULT * icrt1 + inv_factor * icrt2) % m12
    total_rotation = (R * rotation_factor) % m12
    total_inv_rotation = pow(total_rotation, -1, m12)
    assert (total_rotation * total_inv_rotation) % m12 == 1

    one1, one2 = exact_rns(1, total_rotation)
    field_modulus1, field_modulus2 = exact_rns(P, total_rotation)
    modulus1, modulus2 = exact_rns(40 * P, total_rotation)
    off_h1, off_l1, off_h2, off_l2 = wide_zero_offset(total_rotation)

    # Cross-check the independently generated tables against stable fingerprints.
    assert r1_perm[0][0] == 886867229688280
    assert r2[7][7] == 784951846279279
    assert to[0][0] == 290478324782867
    assert total_rotation == int(
        "5881397703986423586738056925019616038552027747594522937097178750184176071923803030770538968388725152827125341295010255075994388068925816525968197753350298954327581318719414042035475052303312391760507171730138296916639553249310927514857701009"
    )

    sections = [
        "/* Generated by gen_bls_constants.py.  Do not edit. */",
        "#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_constants_h",
        "#define HEADER_fd_src_ballet_bls_avx512_fd_bls_constants_h",
        "/* M1 and M2 are the two 8x50-bit RNS bases; R=2^52 is the\n"
        "   independent Montgomery radix used inside each IFMA lane. */",
        emit_array("fd_bls_m1", M1_MOD),
        emit_array("fd_bls_m2", M2_MOD),
        "/* m_i=2^50-t_i supports one-fold pseudo-Mersenne normalization;\n"
        "   mont_i=m_i^-1 mod R supports elementwise Montgomery reduction. */",
        emit_array("fd_bls_m1_t", [(1 << 50) - m for m in M1_MOD]),
        emit_array("fd_bls_m2_t", [(1 << 50) - m for m in M2_MOD]),
        emit_array("fd_bls_m1_mont", [pow(m, -1, R) for m in M1_MOD]),
        emit_array("fd_bls_m2_mont", [pow(m, -1, R) for m in M2_MOD]),
        "/* Algorithm 2's M1->M2 quotient map and M2->M1 expansion map.\n"
        "   correction and sqe encode Appendix A's k*(-base) term. */",
        emit_matrix("fd_bls_r1_perm", r1_perm),
        "/* The same M1->M2 map in row form (row i = source residue i), for\n"
        "   broadcast-operand evaluation. */",
        emit_matrix("fd_bls_r1_mat", r1),
        emit_matrix("fd_bls_r2_mat", r2),
        emit_array("fd_bls_r2_correction", r2_corr),
        emit_array("fd_bls_r2_correction_shift", r2_corr_shift),
        emit_array("fd_bls_r2_sqe", r2_sqe),
        "/* k_hi*correction_shift for k_hi=floor(k/2^52) in [0,4).  Inputs are\n"
        "   normalized residues (< 2^51) and sqe < 2^64, so k < 2^54; with\n"
        "   correction_shift < 2^50 every product is below 2^52, i.e. it has no\n"
        "   high IFMA digit and is added as a plain lane sum. */",
        emit_khi_table("fd_bls_r2_khi", r2_corr_shift),
        emit_khi_table("fd_bls_r2_khi3", scaled_vec(r2_corr_shift, 3)),
        emit_khi_table("fd_bls_r2_khi6", scaled_vec(r2_corr_shift, 6)),
        "/* r2 maps scaled by 3 and by 6 (cyclotomic squaring post-scales). */",
        emit_matrix("fd_bls_r2_mat3", scaled(r2, 3)),
        emit_array("fd_bls_r2_correction3", scaled_vec(r2_corr, 3)),
        emit_matrix("fd_bls_r2_mat6", scaled(r2, 6)),
        emit_array("fd_bls_r2_correction6", scaled_vec(r2_corr, 6)),
        "/* Appendix F radix<->rotated-RNS change-of-base tables. */",
        emit_matrix("fd_bls_to_mat", to),
        emit_array("fd_bls_to_correction", to_corr),
        emit_array("fd_bls_to_sqe", to_sqe),
        "/* Fused blst-Montgomery entry (premult scaled by 2^-384). */",
        emit_matrix("fd_bls_to_mont_mat", to_mont),
        emit_array("fd_bls_to_mont_correction", to_mont_corr),
        emit_array("fd_bls_to_mont_sqe", to_mont_sqe),
        emit_matrix("fd_bls_from_mat", from_),
        emit_array("fd_bls_from_correction", from_corr),
        emit_array("fd_bls_from_sqe", from_sqe),
        "/* Encodings of 1, p (zero in Fp), and the redundant bound 40p. */",
        emit_fp("fd_bls_one", one1, one2),
        emit_fp("fd_bls_field_modulus", field_modulus1, field_modulus2),
        emit_fp("fd_bls_modulus", modulus1, modulus2),
        emit_limbs("fd_bls_neg_g1_x_normal", NEG_G1_X),
        emit_limbs("fd_bls_neg_g1_y_normal", NEG_G1_Y),
        "/* Positive multiple of p^2 used to offset signed lazy products. */",
        emit_array("fd_bls_wide_offset_m1_hi", off_h1),
        emit_array("fd_bls_wide_offset_m1_lo", off_l1),
        emit_array("fd_bls_wide_offset_m2_hi", off_h2),
        emit_array("fd_bls_wide_offset_m2_lo", off_l2),
        "/* Canonical field constants encoded in the same rotated RNS form. */",
    ]
    for name, value_hex in FIELD_CONSTANTS.items():
        value = int(value_hex, 16)
        assert 0 <= value < P
        c1, c2 = exact_rns(value, total_rotation)
        sections.append(emit_fp(f"fd_bls_{name}", c1, c2))
    # Exact zero/equality test tables.  The redundant integer E behind a
    # value is recovered from canonical residues; E == k*p (mod M1*M2) for
    # k in [-40,40] is exactly the old 40p-window zero test.  Entry order
    # 0,1,-1,2,-2,... puts the common small-|k| representatives first.
    order = [0]
    for k in range(1, 41):
        order += [k, -k]
    zero1, zero2 = [], []
    for k in order:
        e = (k * P) % m12
        enc = (e * total_rotation) % m12
        zero1.append([enc % m for m in M1_MOD])
        zero2.append([enc % m for m in M2_MOD])
    lane0 = [z[0] for z in zero1]
    assert len(set(lane0)) == len(lane0)        # lane 0 identifies k uniquely
    assert zero1[0] == [0] * 8 and zero2[0] == [0] * 8
    pad = (-len(lane0)) % 8
    lane0_padded = lane0 + [(1 << 64) - 1] * pad  # never equal to a canonical residue
    sections.append("/* Exact zero test: canonical residues of k*p for k = 0,1,-1,...,40,-40\n"
                    "   (lane-0 index table plus full M/N rows).  The old 40p-window\n"
                    "   comparison accepted exactly these representatives. */")
    sections.append(f"#define FD_BLS_ZERO_CNT ({len(order)})")
    body = ",\n  ".join("{ " + ", ".join(c_u64(v) for v in lane0_padded[8*i:8*i+8]) + " }"
                         for i in range(len(lane0_padded)//8))
    sections.append(f"static ulong const __attribute__((aligned(64))) fd_bls_zero_lane0[{len(lane0_padded)//8}][8] = {{\n  {body}\n}};")
    for name, rows in (("fd_bls_zero_m1", zero1), ("fd_bls_zero_m2", zero2)):
        body = ",\n  ".join("{ " + ", ".join(c_u64(v) for v in row) + " }" for row in rows)
        sections.append(f"static ulong const __attribute__((aligned(64))) {name}[{len(rows)}][8] = {{\n  {body}\n}};")
    # Verify the sqrt_ratio constants from first principles.
    q = P * P
    def f2mul(a, b): return ((a[0]*b[0] - a[1]*b[1]) % P, (a[0]*b[1] + a[1]*b[0]) % P)
    def f2pow(a, n):
        r = (1, 0)
        while n:
            if n & 1: r = f2mul(r, a)
            a = f2mul(a, a); n >>= 1
        return r
    zsswu = ((-2) % P, (-1) % P)
    c2 = (q - 1) // 8
    frob33 = int(FIELD_CONSTANTS["frob3_3"], 16)
    assert f2pow(zsswu, c2) == (frob33, frob33)
    assert f2pow(zsswu, (c2 + 1) // 2) == (int(FIELD_CONSTANTS["sswu_c7_re"], 16), int(FIELD_CONSTANTS["sswu_c7_im"], 16))
    assert (q - 9) // 16 == ((P - 11) // 16) * P + 11 * ((P - 11) // 16) + 7
    gb = int(FIELD_CONSTANTS["g1_beta"], 16)
    assert pow(gb, 3, P) == 1 and gb != 1
    sections.append("#endif")
    # r1 correction/SQE are deliberately unused by the MatrixNoK kernel.
    assert len(r1_corr) == 8 and len(r1_sqe) == 8
    return "\n\n".join(sections) + "\n"


if __name__ == "__main__":
    output = Path(__file__).parent.parent / "fd_bls_constants.h"
    output.write_text(generate())
    print(output)
