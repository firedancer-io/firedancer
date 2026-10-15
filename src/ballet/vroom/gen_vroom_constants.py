#!/usr/bin/env python3
"""Generate the fixed RNS constants headers for the VROOM AVX-512 engine,
one per curve (BLS12-381, BN254).

This generator intentionally uses only the Python standard library.  The
generated headers are committed, so Python is not needed to build or run
Firedancer.  Re-running this file provides an auditable derivation of
every large RNS table used by the C implementation.

Representation (IntRNS4): two 8x50-bit RNS bases M and N with a 2^52
per-lane Montgomery radix.  The M1 base must admit a square root of
(-p)^-1 * R^-1 * m1_opt^-1 (mod M1) -- the "QR premult" that makes the
M1->M2 change-of-base matrix cyclic so its quotient correction can be
skipped.  BLS12-381 ships its historical bases and root; for other
curves find_bases() searches deterministically over prime 2^50-t moduli
with t odd and m = 3 (mod 4) (so the square root is a single pow and
unique up to sign; the smaller root is chosen).
"""

from __future__ import annotations

import itertools
import sys
from math import gcd, prod
from pathlib import Path

R = 1 << 52
MASK52 = R - 1
PRECISION = 64

SRC = Path(__file__).resolve().parent.parent


# --- shared number theory ----------------------------------------------------


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


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    # Deterministic Miller-Rabin for n < 3.3e24 with these witnesses.
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def find_bases(p: int) -> tuple[list[int], list[int], int]:
    """Deterministic IntRNS4 base search for target modulus p.

    M2 is the 8 largest primes 2^50-t with t odd and m = 3 (mod 4); M1 is
    the first (in itertools.combinations order over the next candidates)
    8-subset whose QR-premult square root exists.  Primality makes the
    bases automatically pairwise coprime, and m = 3 (mod 4) makes the
    root computable with one pow and canonical (smaller root chosen)."""
    cands = []
    t = 1
    while len(cands) < 48:
        m = (1 << 50) - t
        if m % 4 == 3 and is_prime(m):
            cands.append(m)
        t += 2
    m2 = cands[:8]
    pool = cands[8:]
    for combo in itertools.combinations(range(len(pool)), 8):
        m1_mod = [pool[i] for i in combo]
        m1 = prod(m1_mod)
        m1_opt = small_factor(m1_mod)
        target = (pow(-p, -1, m1) * pow(R, -1, m1) * pow(m1_opt, -1, m1)) % m1
        roots = []
        for m in m1_mod:
            tm = target % m
            r = pow(tm, (m + 1) // 4, m)
            if r * r % m != tm:
                break
            roots.append(min(r, m - r))
        else:
            return sorted(m1_mod, reverse=True), sorted(m2, reverse=True), crt(
                roots, m1_mod
            )
    raise ValueError("no base set found")


# --- Fp2 arithmetic for tower-constant derivation -----------------------------


def fp2_mul(a: tuple[int, int], b: tuple[int, int], p: int) -> tuple[int, int]:
    return ((a[0] * b[0] - a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)


def fp2_pow(a: tuple[int, int], e: int, p: int) -> tuple[int, int]:
    r = (1, 0)
    while e:
        if e & 1:
            r = fp2_mul(r, a, p)
        a = fp2_mul(a, a, p)
        e >>= 1
    return r


def fp2_inv(a: tuple[int, int], p: int) -> tuple[int, int]:
    norm = (a[0] * a[0] + a[1] * a[1]) % p
    ninv = pow(norm, -1, p)
    return (a[0] * ninv % p, (-a[1]) * ninv % p)


# --- CRNS table derivation (Appendix A) ---------------------------------------


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


# --- emission ------------------------------------------------------------------


def c_u64(value: int) -> str:
    return f"{value}UL"


def emit_array(name: str, values: list[int]) -> str:
    prefix = "static ulong const __attribute__((aligned(64)))"
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


class Curve:
    def __init__(self, *, name, guard, out, p, mont_bits, m1=None, m2=None,
                 qr_premult=None, field_constants=None, limb_constants=None,
                 fingerprints=None):
        self.name = name
        self.guard = guard
        self.out = out
        self.p = p
        self.mont_bits = mont_bits      # foreign Montgomery radix for the fused entry
        self.m1 = m1
        self.m2 = m2
        self.qr_premult = qr_premult
        self.field_constants = field_constants or {}
        self.limb_constants = limb_constants or {}
        self.fingerprints = fingerprints or {}

    def generate(self) -> str:
        p = self.p
        if self.m1 is None:
            self.m1, self.m2, self.qr_premult = find_bases(p)
        m1_mods, m2_mods = self.m1, self.m2
        m1 = prod(m1_mods)
        m2 = prod(m2_mods)
        m12 = m1 * m2
        inv_factor = pow(m1, -1, m2)
        m1_opt = small_factor(m1_mods)

        initial_r1 = (pow(-p, -1, m1) * pow(R, -1, m1)) % m1
        assert pow(self.qr_premult, 2, m1) == (initial_r1 * pow(m1_opt, -1, m1)) % m1

        # These fixed pre/post factors absorb both Algorithm 2 CRNS scales and
        # the per-lane IFMA Montgomery radix R.  qr_premult additionally makes
        # the M1->M2 matrix cyclic, allowing its quotient correction to be
        # omitted.
        r1_post = p * inv_factor * inv_factor * R * R
        r2_pre = m1 * pow(R, -1, m2)
        r2_post = R * R * self.qr_premult
        convert_to_pre = m1
        convert_to_post = inv_factor * R * R
        convert_from_pre = m1 * pow(R, -1, m2)
        convert_from_post = pow(m1, -1, p)

        r1, r1_corr, r1_sqe = matrix(m1_mods, m2_mods, m1_opt, r1_post)
        r2, r2_corr, r2_sqe = matrix(m2_mods, m1_mods, r2_pre, r2_post)
        r2_corr_shift = [(x * R) % m for x, m in zip(r2_corr, m1_mods)]
        to, to_corr, to_sqe = matrix(
            [p], m2_mods, convert_to_pre, convert_to_post,
            input_bits=50, input_digits=8, floor_quotient=True,
        )
        from_, from_corr, from_sqe = matrix(
            m2_mods, [p], convert_from_pre, convert_from_post,
            output_bits=52, output_digits=8,
        )

        # Fused foreign-Montgomery entry: the radix entry with the premult
        # scaled by 2^-mont_bits, so raw Montgomery limbs (x*2^mont_bits
        # mod p) load as the same RNS value the canonical entry produces
        # for x -- zero per-coordinate de-Montgomery cost.
        to_mont_pre = convert_to_pre * pow(2, -self.mont_bits, p) % p
        to_mont, to_mont_corr, to_mont_sqe = matrix(
            [p], m2_mods, to_mont_pre, convert_to_post,
            input_bits=50, input_digits=8, floor_quotient=True,
        )

        # Diagonal/cyclic form used by the no-k r1 kernel.
        r1_perm = [[r1[(lane - step) % 8][lane] for lane in range(8)] for step in range(8)]

        icrt1 = m2 * pow(m2, -1, m1)
        icrt2 = m1 * pow(m1, -1, m2)
        rotation_factor = (self.qr_premult * icrt1 + inv_factor * icrt2) % m12
        total_rotation = (R * rotation_factor) % m12
        total_inv_rotation = pow(total_rotation, -1, m12)
        assert (total_rotation * total_inv_rotation) % m12 == 1

        def exact_rns(value: int, *, wide: bool = False) -> tuple[list[int], list[int]]:
            """Encode a value in the rotated RNS Montgomery representation."""
            redundance = value // p
            encoded = (value * m1) % p
            if wide:
                encoded = (encoded * m1) % p
            encoded += redundance * p
            encoded = (encoded * total_rotation) % m12
            if wide:
                encoded = (encoded * total_rotation) % m12
            return ([encoded % m for m in m1_mods], [encoded % m for m in m2_mods])

        def wide_zero_offset(element_bound: int = 128, rns_bound: int = 2048):
            """A large zero modulo p, shaped for borrow-free signed IFMA sums."""
            desired = 40 * 40 * rns_bound * p * p
            desired_m1, desired_m2 = exact_rns(desired, wide=True)
            high1, low1, high2, low2 = [], [], [], []
            minimum_low = R * element_bound
            for mod, residue, highs, lows in (
                (m1_mods, desired_m1, high1, low1),
                (m2_mods, desired_m2, high2, low2),
            ):
                for m, rns in zip(mod, residue):
                    value = element_bound * m * m
                    low = (value & MASK52) + rns + m * element_bound
                    while low < minimum_low:
                        low += m
                    lows.append(low)
                    highs.append(value >> 52)
            return high1, low1, high2, low2

        one1, one2 = exact_rns(1)
        field_modulus1, field_modulus2 = exact_rns(p)
        modulus1, modulus2 = exact_rns(40 * p)
        off_h1, off_l1, off_h2, off_l2 = wide_zero_offset()

        # Cross-check independently generated tables against fingerprints.
        for expr, want in self.fingerprints.items():
            got = eval(expr)  # noqa: S307 - fixed expressions over locals
            assert got == want, (self.name, expr, got, want)

        p0 = (-pow(p, -1, 1 << 64)) % (1 << 64)
        rr2 = pow(2, 768, p)

        sections = [
            f"/* Generated by gen_vroom_constants.py ({self.name}).  Do not edit. */",
            f"#ifndef {self.guard}",
            f"#define {self.guard}",
            "/* M1 and M2 are the two 8x50-bit RNS bases; R=2^52 is the\n"
            "   independent Montgomery radix used inside each IFMA lane. */",
            emit_array("vroom_m1", m1_mods),
            emit_array("vroom_m2", m2_mods),
            "/* m_i=2^50-t_i supports one-fold pseudo-Mersenne normalization;\n"
            "   mont_i=m_i^-1 mod R supports elementwise Montgomery reduction. */",
            emit_array("vroom_m1_t", [(1 << 50) - m for m in m1_mods]),
            emit_array("vroom_m2_t", [(1 << 50) - m for m in m2_mods]),
            emit_array("vroom_m1_mont", [pow(m, -1, R) for m in m1_mods]),
            emit_array("vroom_m2_mont", [pow(m, -1, R) for m in m2_mods]),
            "/* Algorithm 2's M1->M2 quotient map and M2->M1 expansion map.\n"
            "   correction and sqe encode Appendix A's k*(-base) term. */",
            emit_matrix("vroom_r1_perm", r1_perm),
            emit_matrix("vroom_r2_mat", r2),
            emit_array("vroom_r2_correction", r2_corr),
            emit_array("vroom_r2_correction_shift", r2_corr_shift),
            emit_array("vroom_r2_sqe", r2_sqe),
            "/* Appendix F radix<->rotated-RNS change-of-base tables. */",
            emit_matrix("vroom_to_mat", to),
            emit_array("vroom_to_correction", to_corr),
            emit_array("vroom_to_sqe", to_sqe),
            f"/* Fused foreign-Montgomery entry (premult scaled by 2^-{self.mont_bits}). */",
            emit_matrix("vroom_to_mont_mat", to_mont),
            emit_array("vroom_to_mont_correction", to_mont_corr),
            emit_array("vroom_to_mont_sqe", to_mont_sqe),
            emit_matrix("vroom_from_mat", from_),
            emit_array("vroom_from_correction", from_corr),
            emit_array("vroom_from_sqe", from_sqe),
            "/* Encodings of 1, p (zero in Fp), and the redundant bound 40p. */",
            emit_array("vroom_one_m1", one1),
            emit_array("vroom_one_m2", one2),
            emit_array("vroom_field_modulus_m1", field_modulus1),
            emit_array("vroom_field_modulus_m2", field_modulus2),
            emit_array("vroom_modulus_m1", modulus1),
            emit_array("vroom_modulus_m2", modulus2),
        ]
        for name, value in self.limb_constants.items():
            sections.append(emit_limbs(f"vroom_{name}", value))
        sections += [
            "/* Positive multiple of p^2 used to offset signed lazy products. */",
            emit_array("vroom_wide_offset_m1_hi", off_h1),
            emit_array("vroom_wide_offset_m1_lo", off_l1),
            emit_array("vroom_wide_offset_m2_hi", off_h2),
            emit_array("vroom_wide_offset_m2_lo", off_l2),
            "/* Canonical field constants encoded in the same rotated RNS form. */",
        ]
        for name, value in self.field_constants.items():
            assert 0 <= value < p, name
            c1, c2 = exact_rns(value)
            sections.append(emit_array(f"vroom_{name}_m1", c1))
            sections.append(emit_array(f"vroom_{name}_m2", c2))
        sections += [
            "/* Scalar canonical-reduction constants: p, -p^-1 mod 2^64, 2^768 mod p. */",
            emit_limbs("vroom_p_limbs", p),
            f"#define VROOM_P0 ({c_u64(p0)})",
            emit_limbs("vroom_rr2", rr2),
            "#endif",
        ]
        # r1 correction/SQE are deliberately unused by the MatrixNoK kernel.
        assert len(r1_corr) == 8 and len(r1_sqe) == 8
        return "\n\n".join(sections) + "\n"


# --- BLS12-381 -----------------------------------------------------------------

BLS_P = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
    "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)

# Historical bases and square root; kept pinned so the generated tables
# stay byte-identical (find_bases would pick a different valid set).
BLS_M1 = [
    1125899906842615, 1125899906842609, 1125899906842591,
    1125899906842559, 1125899906842553, 1125899906842549,
    1125899906842541, 1125899906842511,
]
BLS_M2 = [
    1125899906842623, 1125899906842621, 1125899906842619,
    1125899906842613, 1125899906842607, 1125899906842603,
    1125899906842597, 1125899906842589,
]
BLS_QR_PREMULT = int(
    "1764464526391023609719698959639504118661371030573300677125606932387184635588659624517358062862068369090674362610896848484"
)

BLS_FIELD_CONSTANTS = {
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
    # SSWU recip-sqrt support (canonical forms of blst map_to_g2.c /
    # sqrt.c Montgomery constants).  recip_zzz = 1/Z^3 in Fp2 for the
    # non-QR branch, magic_zzz adjusts (aa, cc) for that branch, and
    # inv2 = 1/2 replaces blst's div_by_2_fp.  The sqrt_align rotation
    # constants need no new entries: sqrt(sqrt(-1)) = (frob3_2, frob3_3)
    # and sqrt(-sqrt(-1)) = (frob3_3, frob3_3) in canonical form.
    "sswu_recip_zzz_re": "ec5373b4fc387140dfd46af348f55e2ca7901ef5b371b085d6da6bdbb39819171ad78d43fdbbe76a0f1189374bc3a07",
    "sswu_recip_zzz_im": "9c70eed928c402db9efc63a4a7484928607fdacdea2acefe74fcc1fd9af14de7a1fe76c0d6d687295ce78d4fdf39630",
    "sswu_magic_zzz_0":  "59ded5774de2fc31e8f3083875e2b7a4cff24cacc26fbdb84e195f19dbbba49567f439538bc20c48c86f3b645a1b852",
    "sswu_magic_zzz_1":  "810e5a23cbb86fd12ded1af502287a397ed25c1d6fe0444e38c48e9c7ddb3c27cfebdd464e90f201fda0eb6983f2533",
    "inv2":              "d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556",
    # SSWU domain parameters on the isogenous curve E': A' = 240u and
    # B' = 1012(1+u) apply through full vroom_fp_mul by these encoded
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

BLS_NEG_G1_X = int("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16)
BLS_NEG_G1_Y = int("114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca", 16)


def bls_curve() -> Curve:
    fc = {k: int(v, 16) for k, v in BLS_FIELD_CONSTANTS.items()}
    fc["neg_g1_x"] = BLS_NEG_G1_X
    fc["neg_g1_y"] = BLS_NEG_G1_Y
    fc["neg_g1_3x"] = (3 * BLS_NEG_G1_X) % BLS_P
    fc["neg_g1_minus_2y"] = (-2 * BLS_NEG_G1_Y) % BLS_P
    return Curve(
        name="bls12_381",
        guard="HEADER_fd_src_ballet_bls_avx512_fd_bls_constants_h",
        out=SRC / "bls" / "avx512" / "fd_bls_constants.h",
        p=BLS_P,
        mont_bits=384,
        m1=BLS_M1,
        m2=BLS_M2,
        qr_premult=BLS_QR_PREMULT,
        field_constants=fc,
        limb_constants={
            "neg_g1_x_normal": BLS_NEG_G1_X,
            "neg_g1_y_normal": BLS_NEG_G1_Y,
        },
        fingerprints={
            "r1_perm[0][0]": 886867229688280,
            "r2[7][7]": 784951846279279,
            "to[0][0]": 290478324782867,
            "total_rotation": int(
                "5881397703986423586738056925019616038552027747594522937097178750184176071923803030770538968388725152827125341295010255075994388068925816525968197753350298954327581318719414042035475052303312391760507171730138296916639553249310927514857701009"
            ),
        },
    )


# --- BN254 -----------------------------------------------------------------------

BN_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
BN_X = 0x44E992B44A6909F1  # BN parameter: p = 36x^4+36x^3+24x^2+6x+1


def bn254_curve() -> Curve:
    p = BN_P
    xi = (9, 1)  # v^3 = 9+u

    # Frobenius gammas: gamma1_i = xi^(i*(p-1)/6) in Fp2,
    # gamma2_i = Norm(gamma1_i) = gamma1_i^(p+1) in Fp.
    g1 = [fp2_pow(xi, i * (p - 1) // 6, p) for i in range(1, 6)]
    g2 = []
    for v in g1:
        n = (v[0] * v[0] + v[1] * v[1]) % p  # Norm(a+bu) = a^2+b^2 since u^2=-1
        g2.append(n)

    # Twist: y^2 = x^3 + b' with b' = 3/xi (D-type), so 3b' = 9/xi.
    b3 = fp2_mul((9, 0), fp2_inv(xi, p), p)

    # GLV endomorphism beta: the canonical primitive cube root of unity
    # matching fd_bn254_const_beta_mont (derived, then asserted).
    beta = 1
    g = 2
    while beta == 1:
        beta = pow(g, (p - 1) // 3, p)
        g += 1
    if beta != max(beta, (beta * beta) % p):  # pick the root the ref code uses
        beta = (beta * beta) % p
    assert pow(beta, 3, p) == 1 and beta != 1
    assert beta == 0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48

    fc = {
        "one_third": pow(3, -1, p),
        "neg_two_thirds": (-2 * pow(3, -1, p)) % p,
        "inv2": pow(2, -1, p),
        "twist_b3_re": b3[0],
        "twist_b3_im": b3[1],
        "glv_beta": beta,
        "curve_b": 3,
    }
    for i, (re, im) in enumerate(g1, start=1):
        fc[f"gamma1_{i}_re"] = re
        fc[f"gamma1_{i}_im"] = im
    for i, v in enumerate(g2, start=1):
        fc[f"gamma2_{i}"] = v

    return Curve(
        name="bn254",
        guard="HEADER_fd_src_ballet_bn254_avx512_fd_bn254_constants_h",
        out=SRC / "bn254" / "avx512" / "fd_bn254_constants.h",
        p=p,
        mont_bits=256,  # fd_bn254 scalar backend uses 4x64 Montgomery
        field_constants=fc,
    )


CURVES = {"bls12_381": bls_curve, "bn254": bn254_curve}


def main() -> None:
    names = sys.argv[1:] or list(CURVES)
    for name in names:
        curve = CURVES[name]()
        curve.out.parent.mkdir(parents=True, exist_ok=True)
        curve.out.write_text(curve.generate())
        print(curve.out)


if __name__ == "__main__":
    main()
