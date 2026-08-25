#!/usr/bin/env python3
"""Generate the fixed BLS12-381 constants used by fd_vroom_rns.c.

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

# Frobenius coefficients for the flattened
# Fp[u]/(u^2+1), Fp2[v]/(v^3-(u+1)), Fp6[w]/(w^2-v) tower.  They are
# canonical field elements here and are encoded into both fixed RNS bases
# below, so the runtime never enters BLST's Montgomery representation.
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
    """Derive the fixed-point CRT change-base matrix used by IFMA."""
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


def emit_limbs(name: str, value: int) -> str:
    limbs = [(value >> (64 * i)) & ((1 << 64) - 1) for i in range(6)]
    body = ", ".join(c_u64(v) for v in limbs)
    return f"static ulong const {name}[6] = {{ {body} }};"


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
    to, to_corr, to_sqe = matrix(
        [P], M2_MOD, convert_to_pre, convert_to_post,
        input_bits=50, input_digits=8, floor_quotient=True,
    )
    from_, from_corr, from_sqe = matrix(
        M2_MOD, [P], convert_from_pre, convert_from_post,
        output_bits=52, output_digits=8,
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
        "/* Generated by gen_vroom_constants.py.  Do not edit. */",
        "#ifndef HEADER_fd_src_ballet_bls_vroom_fd_vroom_constants_h",
        "#define HEADER_fd_src_ballet_bls_vroom_fd_vroom_constants_h",
        emit_array("fd_vroom_m1", M1_MOD),
        emit_array("fd_vroom_m2", M2_MOD),
        emit_array("fd_vroom_m1_t", [(1 << 50) - m for m in M1_MOD]),
        emit_array("fd_vroom_m2_t", [(1 << 50) - m for m in M2_MOD]),
        emit_array("fd_vroom_m1_mont", [pow(m, -1, R) for m in M1_MOD]),
        emit_array("fd_vroom_m2_mont", [pow(m, -1, R) for m in M2_MOD]),
        emit_matrix("fd_vroom_r1_perm", r1_perm),
        emit_matrix("fd_vroom_r2_mat", r2),
        emit_array("fd_vroom_r2_correction", r2_corr),
        emit_array("fd_vroom_r2_correction_shift", r2_corr_shift),
        emit_array("fd_vroom_r2_sqe", r2_sqe),
        emit_matrix("fd_vroom_to_mat", to),
        emit_array("fd_vroom_to_correction", to_corr),
        emit_array("fd_vroom_to_sqe", to_sqe),
        emit_matrix("fd_vroom_from_mat", from_),
        emit_array("fd_vroom_from_correction", from_corr),
        emit_array("fd_vroom_from_sqe", from_sqe),
        emit_array("fd_vroom_one_m1", one1),
        emit_array("fd_vroom_one_m2", one2),
        emit_array("fd_vroom_field_modulus_m1", field_modulus1),
        emit_array("fd_vroom_field_modulus_m2", field_modulus2),
        emit_array("fd_vroom_modulus_m1", modulus1),
        emit_array("fd_vroom_modulus_m2", modulus2),
        emit_limbs("fd_vroom_neg_g1_x_normal", NEG_G1_X),
        emit_limbs("fd_vroom_neg_g1_y_normal", NEG_G1_Y),
        emit_array("fd_vroom_wide_offset_m1_hi", off_h1),
        emit_array("fd_vroom_wide_offset_m1_lo", off_l1),
        emit_array("fd_vroom_wide_offset_m2_hi", off_h2),
        emit_array("fd_vroom_wide_offset_m2_lo", off_l2),
    ]
    for name, value_hex in FIELD_CONSTANTS.items():
        value = int(value_hex, 16)
        assert 0 <= value < P
        c1, c2 = exact_rns(value, total_rotation)
        sections.append(emit_array(f"fd_vroom_{name}_m1", c1))
        sections.append(emit_array(f"fd_vroom_{name}_m2", c2))
    sections.extend(("#endif", ""))
    # r1 correction/SQE are deliberately unused by the MatrixNoK kernel.
    assert len(r1_corr) == 8 and len(r1_sqe) == 8
    return "\n\n".join(sections)


if __name__ == "__main__":
    output = Path(__file__).with_name("fd_vroom_constants.h")
    output.write_text(generate())
    print(output)
