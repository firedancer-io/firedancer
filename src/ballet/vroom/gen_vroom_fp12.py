#!/usr/bin/env python3
"""Emit fixed Fp12 kernels (multiply, square, cyclotomic square, sparse
multiply) as straight-line C over the VROOM RNS engine, parametrized by
the curve's tower and twist type.

The tower is Fp[u]/(u^2+1), Fp2[v]/(v^3-xi), Fp6[w]/(w^2-v) with
xi = XI_A + XI_B*u.  Python is only a source generator; the shipped
backend is C.

Coefficients other than +-1 (e.g. the 9's of BN254's xi = 9+u) are
handled by emitting precomputed small multiples of the inputs: a
coefficient c*x[i]*y[j] becomes xN[i]*y[j] with xN = c*x computed by a
raw double-and-add plus one normalize (vroom_fp_mul_small's bound
analysis: n <= 2^8 keeps raw lanes below 2^60).
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path


# --- curve configurations ---------------------------------------------------

CURVES = {
    "bls12_381": dict(
        xi=(1, 1),                    # v^3 = 1 + u
        sparse_slots=(0, 1, 2, 3, 8, 9),  # M-type twist line: c + x*v + y*w*v
        out=Path(__file__).resolve().parent.parent
            / "bls" / "avx512" / "fd_bls_fp12_generated.inc",
        guard="gen_vroom_fp12.py (bls12_381)",
    ),
    "bn254": dict(
        xi=(9, 1),                    # v^3 = 9 + u
        sparse_slots=(0, 1, 6, 7, 8, 9),  # D-type twist line: c + x*w + y*w*v
        out=Path(__file__).resolve().parent.parent
            / "bn254" / "avx512" / "fd_bn254_fp12_generated.inc",
        guard="gen_vroom_fp12.py (bn254)",
    ),
}


def decode(i: int) -> tuple[int, int, int]:
    return i // 6, (i % 6) // 2, i & 1


def index(w: int, v: int, u: int) -> int:
    return 6 * w + 2 * v + u


def make_basis_product(xi: tuple[int, int]):
    xi_a, xi_b = xi

    def basis_product(i: int, j: int) -> dict[int, int]:
        w1, v1, u1 = decode(i)
        w2, v2, u2 = decode(j)
        pending = {(w1 + w2, v1 + v2, u1 + u2): 1}
        result: defaultdict[int, int] = defaultdict(int)
        while pending:
            (w, v, u), coeff = pending.popitem()
            if u >= 2:  # u^2 = -1
                pending[(w, v, u - 2)] = pending.get((w, v, u - 2), 0) - coeff
            elif w >= 2:  # w^2 = v
                pending[(w - 2, v + 1, u)] = pending.get((w - 2, v + 1, u), 0) + coeff
            elif v >= 3:  # v^3 = xi = xi_a + xi_b*u
                if xi_a:
                    pending[(w, v - 3, u)] = pending.get((w, v - 3, u), 0) + coeff * xi_a
                if xi_b:
                    pending[(w, v - 3, u + 1)] = pending.get((w, v - 3, u + 1), 0) + coeff * xi_b
            else:
                result[index(w, v, u)] += coeff
        return {k: c for k, c in result.items() if c}

    return basis_product


class Emitter:
    """Shared emission machinery for one curve configuration."""

    def __init__(self, xi: tuple[int, int], sparse_slots: tuple[int, ...]):
        self.xi = xi
        self.sparse_slots = sparse_slots
        self.basis_product = make_basis_product(xi)

    # --- term collection -----------------------------------------------

    def products(self, y_indices: tuple[int, ...]) -> list[list[tuple[int, int, int]]]:
        out: list[list[tuple[int, int, int]]] = [[] for _ in range(12)]
        for i in range(12):
            for j in y_indices:
                for k, coeff in self.basis_product(i, j).items():
                    out[k].append((coeff, i, j))
        return out

    def square_products(self) -> list[list[tuple[int, int, int, int]]]:
        """Consolidate the symmetric terms of x*x.

        Off-diagonal products use a precomputed multiple of x[j] (2x for
        coefficient +-2, 2c*x for +-2c), so each cross product needs one
        IFMA pair instead of evaluating both (i,j) and (j,i).  The last
        tuple element is the small multiple applied to the right operand
        (1 for the plain input).
        """
        out: list[list[tuple[int, int, int, int]]] = [[] for _ in range(12)]
        for i in range(12):
            for j in range(i, 12):
                for k, coeff in self.basis_product(i, j).items():
                    mult = abs(coeff) * (2 if i != j else 1)
                    sign = 1 if coeff > 0 else -1
                    out[k].append((sign, i, j, mult))
        return out

    # --- multiplier-operand management -----------------------------------

    @staticmethod
    def split_pair(even: dict, odd: dict):
        """Split adjacent complex outputs into shared, flipped, and unique
        terms.  An overlapping key whose coefficients are neither equal
        nor opposite (possible when xi has unequal components) lands in
        both unique lists."""
        shared, flipped = [], []
        even_unique, odd_unique = [], []
        for key in sorted(set(even) | set(odd), key=str):
            e, o = even.get(key, 0), odd.get(key, 0)
            if e and o and e == o:
                shared.append((key, e))
            elif e and o and e == -o:
                flipped.append((key, e))
            else:
                if e:
                    even_unique.append((key, e))
                if o:
                    odd_unique.append((key, o))
        return shared, flipped, even_unique, odd_unique

    # --- kernels ----------------------------------------------------------

    def emit_mul_paired(self, name: str, sparse: bool) -> str:
        """Emit a multiply using the shared real/imaginary pair schedule.

        Each adjacent output pair is one complex coefficient.  Factoring
        its common and sign-flipped terms minimizes base-field products.
        Negative terms subtract their raw product (wide_submul): the wide
        offset keeps every accumulator borrow-free, so no operand negation
        is needed.  Coefficients with |c| > 1 multiply against an emitted
        c*y[j] (or c*x[i] for squares) small multiple.
        """
        y_indices = self.sparse_slots if sparse else tuple(range(12))
        terms = self.products(y_indices)

        # Collect needed small multiples of y operands: (j, mult) for mult>1.
        mults: set[tuple[int, int]] = set()
        for k in range(12):
            for coeff, i, j in terms[k]:
                if abs(coeff) > 1:
                    mults.add((j, abs(coeff)))

        def y_expr(j: int, mult: int) -> str:
            if mult > 1:
                return f"ym{mult}_{j}"
            if sparse:
                return f"line[{self.sparse_slots.index(j)}]"
            return f"y->c[{j}]"

        def y_name(j: int, mult: int) -> str:
            base = f"l{self.sparse_slots.index(j)}" if sparse else f"y{j}"
            return f"{mult}*{base}" if mult > 1 else base

        signature = (
            f"static void\n{name}( vroom_fp12_t * out, vroom_fp12_t const * x, "
            + ("vroom_fp_t const line[6]" if sparse else "vroom_fp12_t const * y")
            + " ) {"
        )
        lines = [signature, "  vroom_fp_wide_t w[12], common, flipped;"]
        for (j, mult) in sorted(mults):
            src = f"line[{self.sparse_slots.index(j)}]" if sparse else f"y->c[{j}]"
            lines.append(f"  vroom_fp_t ym{mult}_{j};")
            lines.append(
                f"  vroom_fp_mul_small( &ym{mult}_{j}, &{src}, {mult}U );"
                f" /* ym{mult}_{j} = {mult}*{y_name(j,1)}. */" )

        def add_product(target: str, term) -> None:
            (i, j), coeff = term
            mult = abs(coeff)
            fn = "vroom_fp_wide_addmul" if coeff > 0 else "vroom_fp_wide_submul"
            op = "+=" if coeff > 0 else "-="
            lines.append(
                f"  {fn}( &{target}, &x->c[{i}], &{y_expr(j, mult)} );"
                f" /* {target} {op} x{i}*{y_name(j, mult)}. */"
            )

        for k in range(0, 12, 2):
            even = {(i, j): coeff for coeff, i, j in terms[k]}
            odd = {(i, j): coeff for coeff, i, j in terms[k + 1]}
            shared, opposite, even_unique, odd_unique = self.split_pair(even, odd)

            lines.append("  vroom_fp_wide_offset( &common ); /* common = 0 mod p. */")
            for term in shared:
                add_product("common", term)

            lines.append(f"  w[{k}] = common; /* w{k} starts with terms shared by c{k} and c{k+1}. */")
            lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same shared terms. */")
            if opposite:
                first = True
                for (i, j), coeff in opposite:
                    assert coeff < 0  # flipped holds -(even side)
                    mult = abs(coeff)
                    fn = "vroom_fp_wide_mul_raw" if first else "vroom_fp_wide_addmul"
                    cm = "=" if first else "+="
                    lines.append(
                        f"  {fn}( &flipped, &x->c[{i}], &{y_expr(j, mult)} );"
                        f" /* flipped {cm} x{i}*{y_name(j, mult)}. */"
                    )
                    first = False
                lines.append(f"  vroom_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
                lines.append(f"  vroom_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
            for term in even_unique:
                add_product(f"w[{k}]", term)
            for term in odd_unique:
                add_product(f"w[{k+1}]", term)

        # Two 6-slot reduces for the 12 wide elements: the batch reduce has a
        # large fixed per-invocation cost, so 2x batch6 beats 3x batch4; a
        # single batch12 spills past the 32-entry register file.
        lines.append("  vroom_fp_reduce_wide_batch6( &out->c[0], &w[0] ); /* out.c0:6 = w0:6 mod p. */")
        lines.append("  vroom_fp_reduce_wide_batch6( &out->c[6], &w[6] ); /* out.c6:12 = w6:12 mod p. */")
        lines.append("}")
        return "\n".join(lines)

    def emit_square(self) -> str:
        terms = self.square_products()

        # Needed small multiples of x operands.
        mults: set[tuple[int, int]] = set()
        for k in range(12):
            for sign, i, j, mult in terms[k]:
                if mult > 1:
                    mults.add((j, mult))

        lines = [
            "static void",
            "fp12_sqr_generated( vroom_fp12_t * out, vroom_fp12_t const * x ) {",
            "  vroom_fp_wide_t w[12], common, flipped;",
        ]
        # Inputs are bounded by 2*m and every RNS modulus has two IFMA
        # headroom bits, so a raw 2x is still a valid 52-bit IFMA digit and
        # needs no normalization.  Larger multiples go through
        # vroom_fp_mul_small (raw double-and-add + one trailing normalize).
        for (j, mult) in sorted(mults):
            lines.append(f"  vroom_fp_t xm{mult}_{j};")
            if mult == 2:
                lines.append(f"  xm2_{j}.m1 = wwv_add( x->c[{j}].m1, x->c[{j}].m1 ); /* xm2_{j}=2x{j}, base M. */")
                lines.append(f"  xm2_{j}.m2 = wwv_add( x->c[{j}].m2, x->c[{j}].m2 ); /* xm2_{j}=2x{j}, base N. */")
            else:
                lines.append(f"  vroom_fp_mul_small( &xm{mult}_{j}, &x->c[{j}], {mult}U ); /* xm{mult}_{j}={mult}x{j}. */")

        def operand(j: int, mult: int) -> str:
            return f"xm{mult}_{j}" if mult > 1 else f"x->c[{j}]"

        def add_product(target: str, term) -> None:
            (i, j, mult), sign = term
            fn = "vroom_fp_wide_addmul" if sign > 0 else "vroom_fp_wide_submul"
            op = "+=" if sign > 0 else "-="
            lines.append(
                f"  {fn}( &{target}, &x->c[{i}], &{operand(j, mult)} );"
                f" /* {target} {op} {mult if mult != 1 else ''}x{i}*x{j}. */"
            )

        for k in range(0, 12, 2):
            even = {(i, j, mult): sign for sign, i, j, mult in terms[k]}
            odd = {(i, j, mult): sign for sign, i, j, mult in terms[k + 1]}
            shared, opposite, even_unique, odd_unique = self.split_pair(even, odd)

            lines.append("  vroom_fp_wide_offset( &common ); /* common = 0 mod p. */")
            for term in shared:
                add_product("common", term)
            lines.append(f"  w[{k}] = common; /* w{k} starts with terms shared by c{k} and c{k+1}. */")
            lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same shared terms. */")
            if opposite:
                first = True
                for (i, j, mult), sign in opposite:
                    assert sign < 0
                    fn = "vroom_fp_wide_mul_raw" if first else "vroom_fp_wide_addmul"
                    cm = "=" if first else "+="
                    lines.append(
                        f"  {fn}( &flipped, &x->c[{i}], &{operand(j, mult)} );"
                        f" /* flipped {cm} {mult if mult != 1 else ''}x{i}*x{j}. */"
                    )
                    first = False
                lines.append(f"  vroom_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
                lines.append(f"  vroom_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
            for term in even_unique:
                add_product(f"w[{k}]", term)
            for term in odd_unique:
                add_product(f"w[{k+1}]", term)
        # Two 6-slot reduces (see emit_mul_paired).
        lines.append("  vroom_fp_reduce_wide_batch6( &out->c[0], &w[0] ); /* out.c0:6 = w0:6 mod p. */")
        lines.append("  vroom_fp_reduce_wide_batch6( &out->c[6], &w[6] ); /* out.c6:12 = w6:12 mod p. */")
        lines.append("}")
        return "\n".join(lines)

    # --- cyclotomic squaring ---------------------------------------------

    def cyclotomic_table(self) -> list[list[tuple[int, int, int | None]]]:
        """Derive the Granger-Scott cyclotomic-square coefficient table.

        Flat Fp2 components (re, im): a00=(0,1) a01=(2,3) a02=(4,5)
        a10=(6,7) a11=(8,9) a12=(10,11).  Granger-Scott (eprint 2009/565,
        as in the gnark/bn254 scalar code):

          out(a00) = 3*(xi*a11^2 + a00^2)  - 2*a00
          out(a01) = 3*(xi*a02^2 + a10^2)  - 2*a01
          out(a02) = 3*(xi*a12^2 + a01^2)  - 2*a02
          out(a10) = 3*(2*xi*a01*a12)      + 2*a10
          out(a11) = 3*(2*a00*a11)         + 2*a11
          out(a12) = 3*(2*a02*a10)         + 2*a12

        Only u^2 = -1 and the value of xi enter, so the same template
        serves every curve; the integer table below is its expansion
        into (coeff, i, j) basis products per flat output slot. """
        xi_a, xi_b = self.xi
        A00, A01, A02 = (0, 1), (2, 3), (4, 5)
        A10, A11, A12 = (6, 7), (8, 9), (10, 11)

        def fp2_sqr(a):
            # (re+im*u)^2 -> [(coeff,i,j) for real], [(...) for imag]
            r, i = a
            return [(1, r, r), (-1, i, i)], [(2, r, i)]

        def fp2_mul(a, b):
            ar, ai = a
            br, bi = b
            re = [(1, ar, br), (-1, ai, bi)]
            im = [(1, ar, bi), (1, ai, br)]
            return re, im

        def xi_mul(rei):
            # (a+bu)*(xi_a+xi_b*u) = (xi_a*a - xi_b*b) + (xi_b*a + xi_a*b)u
            re, im = rei
            nre = [(xi_a * c, i, j) for c, i, j in re] + [(-xi_b * c, i, j) for c, i, j in im]
            nim = [(xi_b * c, i, j) for c, i, j in re] + [(xi_a * c, i, j) for c, i, j in im]
            return nre, nim

        def scale(rei, k):
            re, im = rei
            return [(k * c, i, j) for c, i, j in re], [(k * c, i, j) for c, i, j in im]

        def add(x, y):
            return x[0] + y[0], x[1] + y[1]

        rows = {
            A00: (scale(add(xi_mul(fp2_sqr(A11)), fp2_sqr(A00)), 3), -2),
            A01: (scale(add(xi_mul(fp2_sqr(A02)), fp2_sqr(A10)), 3), -2),
            A02: (scale(add(xi_mul(fp2_sqr(A12)), fp2_sqr(A01)), 3), -2),
            A10: (scale(xi_mul(scale(fp2_mul(A01, A12), 2)), 3), 2),
            A11: (scale(scale(fp2_mul(A00, A11), 2), 3), 2),
            A12: (scale(scale(fp2_mul(A02, A10), 2), 3), 2),
        }

        table: list[list[tuple[int, int, int | None]]] = [[] for _ in range(12)]
        for (kre, kim), ((re, im), lin) in rows.items():
            acc_re: dict[tuple[int, int], int] = {}
            acc_im: dict[tuple[int, int], int] = {}
            for c, i, j in re:
                key = (min(i, j), max(i, j))
                acc_re[key] = acc_re.get(key, 0) + c
            for c, i, j in im:
                key = (min(i, j), max(i, j))
                acc_im[key] = acc_im.get(key, 0) + c
            table[kre] = [(c, i, j) for (i, j), c in acc_re.items() if c]
            table[kre].append((lin, kre, None))
            table[kim] = [(c, i, j) for (i, j), c in acc_im.items() if c]
            table[kim].append((lin, kim, None))
        return table

    def emit_cyclotomic(self) -> str:
        table = self.cyclotomic_table()
        lines = [
            "static void",
            "fp12_cyclotomic_sqr_generated( vroom_fp12_t * out, vroom_fp12_t const * x ) {",
            "  vroom_fp_t const one_third = {",
            "    .m1 = wwv_ld( vroom_one_third_m1 ),",
            "    .m2 = wwv_ld( vroom_one_third_m2 ) };",
            "  vroom_fp_t const neg_two_thirds = {",
            "    .m1 = wwv_ld( vroom_neg_two_thirds_m1 ),",
            "    .m2 = wwv_ld( vroom_neg_two_thirds_m2 ) };",
            "  vroom_fp_wide_t w[12], common, flipped;",
        ]

        # The first and second Fp6 halves are factored by 3 and 6
        # respectively, then rescaled after their shared wide reductions.
        # Scaled product coefficients (coeff/scale) may exceed 2 for
        # xi with large components; emit small multiples for those.
        mults: set[tuple[int, int]] = set()
        for k in range(12):
            scale = 3 if k < 6 else 6
            for coeff, i, j in table[k]:
                if j is None:
                    continue
                assert coeff % scale == 0, (k, coeff, scale)
                m = abs(coeff // scale)
                if m > 1:
                    mults.add((max(i, j), m))
        for (j, m) in sorted(mults):
            lines.append(f"  vroom_fp_t xm{m}_{j};")
            if m == 2:
                # raw doubling: two headroom bits make 2x a valid IFMA digit
                lines.append(f"  xm2_{j}.m1 = wwv_add( x->c[{j}].m1, x->c[{j}].m1 ); /* xm2_{j}=2x{j}, base M. */")
                lines.append(f"  xm2_{j}.m2 = wwv_add( x->c[{j}].m2, x->c[{j}].m2 ); /* xm2_{j}=2x{j}, base N. */")
            else:
                lines.append(f"  vroom_fp_mul_small( &xm{m}_{j}, &x->c[{j}], {m}U ); /* xm{m}_{j}={m}x{j}. */")

        def normalized(k: int) -> dict:
            scale = 3 if k < 6 else 6
            result: dict = {}
            for coeff, i, j in table[k]:
                if j is None:
                    result[("linear", i)] = 1
                else:
                    scaled = coeff // scale
                    assert scaled * scale == coeff
                    key = ("product", min(i, j), max(i, j), abs(scaled))
                    result[key] = result.get(key, 0) + (1 if scaled > 0 else -1)
            return {k2: v for k2, v in result.items() if v}

        def product_operands(key, k: int) -> tuple[str, str]:
            if key[0] == "linear":
                return f"x->c[{key[1]}]", "neg_two_thirds" if k < 6 else "one_third"
            _, i, j, m = key
            rhs = f"xm{m}_{j}" if m > 1 else f"x->c[{j}]"
            return f"x->c[{i}]", rhs

        def add_product(target: str, term, k: int) -> None:
            key, coeff = term
            lhs, rhs = product_operands(key, k)
            if key[0] == "linear":
                term_math = f"{'-2/3' if k < 6 else '1/3'}*x{key[1]}"
                fn, op = "vroom_fp_wide_addmul", "+="
            else:
                _, i, j, m = key
                term_math = f"{m if m != 1 else ''}x{i}*x{j}"
                fn = "vroom_fp_wide_addmul" if coeff > 0 else "vroom_fp_wide_submul"
                op = "+=" if coeff > 0 else "-="
            lines.append(f"  {fn}( &{target}, &{lhs}, &{rhs} ); /* {target} {op} {term_math}. */")

        for k in range(0, 12, 2):
            even = normalized(k)
            odd = normalized(k + 1)
            shared, opposite, even_unique, odd_unique = self.split_pair(even, odd)

            lines.append("  vroom_fp_wide_offset( &common ); /* common = 0 mod p before the final scale. */")
            for term in shared:
                add_product("common", term, k)
            lines.append(f"  w[{k}] = common; /* w{k} starts with normalized terms shared by c{k} and c{k+1}. */")
            lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same normalized terms. */")
            if opposite:
                first = True
                for key, coeff in opposite:
                    assert coeff == -1 and key[0] == "product"
                    lhs, rhs = product_operands(key, k)
                    _, i, j, m = key
                    term_math = f"{m if m != 1 else ''}x{i}*x{j}"
                    fn = "vroom_fp_wide_mul_raw" if first else "vroom_fp_wide_addmul"
                    cm = "=" if first else "+="
                    lines.append(f"  {fn}( &flipped, &{lhs}, &{rhs} ); /* flipped {cm} {term_math}. */")
                    first = False
                lines.append(f"  vroom_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
                lines.append(f"  vroom_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
            for term in even_unique:
                add_product(f"w[{k}]", term, k)
            for term in odd_unique:
                add_product(f"w[{k+1}]", term, k + 1)
        lines.append("  vroom_fp_reduce_wide_scaled_batch6( &out->c[0], &w[0], 3U ); /* out.c0:6 = 3*w0:6 mod p. */")
        lines.append("  vroom_fp_reduce_wide_scaled_batch6( &out->c[6], &w[6], 6U ); /* out.c6:12 = 6*w6:12 mod p. */")
        lines.append("}")
        return "\n".join(lines)

    def generate(self, guard: str) -> str:
        xi_a, xi_b = self.xi
        slots = self.sparse_slots
        return (
            f"/* Generated by {guard}.  Do not edit.\n"
            "   c[6*i+2*j+k] is the coefficient of w^i*v^j*u^k in\n"
            f"   Fp[u]/(u^2+1), v^3={xi_a}+{xi_b}u, w^2=v. */\n\n"
            "/* Tower product with one lazy RNS reduction per output coefficient. */\n"
            + self.emit_mul_paired("fp12_mul_generated", False)
            + "\n\n/* Symmetric cross terms are consolidated before lazy reduction. */\n"
            + self.emit_square()
            + "\n\n/* Multiply by the sparse line at slots "
            + ",".join(str(s) for s in slots) + ". */\n"
            + self.emit_mul_paired("fp12_mul_sparse_generated", True)
            + "\n\n/* Squaring specialized to the cyclotomic subgroup. */\n"
            + self.emit_cyclotomic()
            + "\n"
        )


def main() -> None:
    curves = sys.argv[1:] or list(CURVES)
    for name in curves:
        cfg = CURVES[name]
        em = Emitter(cfg["xi"], cfg["sparse_slots"])
        out = cfg["out"]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(em.generate(cfg["guard"]))
        print(out)


if __name__ == "__main__":
    main()
