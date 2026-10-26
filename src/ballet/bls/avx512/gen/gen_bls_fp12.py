#!/usr/bin/env python3
"""Emit the fixed BLS12-381 Fp12 kernels (multiply, square, cyclotomic
square, sparse multiply) as straight-line C.

The tower is Fp[u]/(u^2+1), Fp2[v]/(v^3-(u+1)), and
Fp6[w]/(w^2-v).  Python is only a source generator; the shipped backend is C.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path


def decode(i: int) -> tuple[int, int, int]:
    return i // 6, (i % 6) // 2, i & 1


def index(w: int, v: int, u: int) -> int:
    return 6 * w + 2 * v + u


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
        elif v >= 3:  # v^3 = u + 1
            pending[(w, v - 3, u)] = pending.get((w, v - 3, u), 0) + coeff
            pending[(w, v - 3, u + 1)] = pending.get((w, v - 3, u + 1), 0) + coeff
        else:
            result[index(w, v, u)] += coeff
    return dict(result)


def products(y_indices: tuple[int, ...]) -> list[list[tuple[int, int, int]]]:
    out: list[list[tuple[int, int, int]]] = [[] for _ in range(12)]
    for i in range(12):
        for j in y_indices:
            for k, coeff in basis_product(i, j).items():
                if coeff:
                    out[k].append((coeff, i, j))
    return out


def square_products() -> list[list[tuple[int, int, int, bool]]]:
    """Consolidate the symmetric terms of x*x.

    Off-diagonal products use a precomputed 2*x[j], so each cross product
    needs one IFMA pair instead of evaluating both (i,j) and (j,i).
    """
    out: list[list[tuple[int, int, int, bool]]] = [[] for _ in range(12)]
    for i in range(12):
        for j in range(i, 12):
            for k, coeff in basis_product(i, j).items():
                assert abs(coeff) == 1
                out[k].append((coeff, i, j, i != j))
    return out


def split_pair(
    even: dict[tuple[object, ...], int],
    odd: dict[tuple[object, ...], int],
) -> tuple[
    list[tuple[tuple[object, ...], int]],
    list[tuple[tuple[object, ...], int]],
    list[tuple[tuple[object, ...], int]],
    list[tuple[tuple[object, ...], int]],
]:
    """Split adjacent complex outputs into shared, flipped, and unique terms."""
    overlap = even.keys() & odd.keys()
    shared = [(key, even[key]) for key in sorted(overlap) if even[key] == odd[key]]
    flipped = [(key, even[key]) for key in sorted(overlap) if even[key] == -odd[key]]
    even_unique = [(key, coeff) for key, coeff in even.items() if key not in odd]
    odd_unique = [(key, coeff) for key, coeff in odd.items() if key not in even]
    assert len(shared) + len(flipped) == len(overlap)
    return shared, flipped, even_unique, odd_unique


def emit_mul_paired(name: str, y_indices: tuple[int, ...], sparse: bool) -> str:
    """Emit a multiply using the shared real/imaginary pair schedule.

    Each adjacent output pair is one complex coefficient.  Factoring its
    common and sign-flipped terms reduces the full kernel from 204 to the
    optimal 144 base-field products (and the sparse kernel from 92 to 72).
    Negative terms subtract their raw product (wide_submul): the wide
    offset keeps every accumulator borrow-free, so no operand negation is
    needed.
    """
    terms = products(y_indices)
    y_expr = {j: (f"line[{(0,1,2,3,8,9).index(j)}]" if sparse else f"y->c[{j}]") for j in y_indices}
    signature = (
        f"static void\n{name}( fd_bls_fp12_t * out, fd_bls_fp12_t const * x, "
        + ("fd_bls_fp_t const line[6]" if sparse else "fd_bls_fp12_t const * y")
        + " ) {"
    )
    lines = [
        signature,
        "  fd_bls_fp_wide_t w[12], common, flipped;",
    ]

    def add_product(target: str, term: tuple[tuple[int, int], int]) -> None:
        (i, j), coeff = term
        assert abs(coeff) == 1
        y_name = f"l{(0,1,2,3,8,9).index(j)}" if sparse else f"y{j}"
        fn = "fd_bls_fp_wide_addmul" if coeff > 0 else "fd_bls_fp_wide_submul"
        op = "+=" if coeff > 0 else "-="
        lines.append(
            f"  {fn}( &{target}, &x->c[{i}], &{y_expr[j]} );"
            f" /* {target} {op} x{i}*{y_name}. */"
        )

    for k in range(0, 12, 2):
        even = {(i, j): coeff for coeff, i, j in terms[k]}
        odd = {(i, j): coeff for coeff, i, j in terms[k + 1]}
        shared, opposite, even_unique, odd_unique = split_pair(even, odd)

        lines.append("  fd_bls_fp_wide_offset( &common ); /* common = 0 mod p. */")
        for term in shared:
            add_product("common", term)

        lines.append(f"  w[{k}] = common; /* w{k} starts with terms shared by c{k} and c{k+1}. */")
        lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same shared terms. */")
        if opposite:
            (i, j), coeff = opposite[0]
            assert coeff == -1
            y_name = f"l{(0,1,2,3,8,9).index(j)}" if sparse else f"y{j}"
            lines.append(f"  fd_bls_fp_wide_mul_raw( &flipped, &x->c[{i}], &{y_expr[j]} ); /* flipped = x{i}*{y_name}. */")
            for (i, j), coeff in opposite[1:]:
                assert coeff == -1
                y_name = f"l{(0,1,2,3,8,9).index(j)}" if sparse else f"y{j}"
                lines.append(f"  fd_bls_fp_wide_addmul( &flipped, &x->c[{i}], &{y_expr[j]} ); /* flipped += x{i}*{y_name}. */")
            lines.append(f"  fd_bls_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
            lines.append(f"  fd_bls_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
        for term in even_unique:
            add_product(f"w[{k}]", term)
        for term in odd_unique:
            add_product(f"w[{k+1}]", term)

    # Two 6-slot reduces for the 12 wide elements: the batch reduce has a
    # large fixed per-invocation cost, so 2x batch6 beats 3x batch4; a single
    # batch12 was measured slower (36 live vectors spill past the 32-entry
    # register file).
    lines.append("  fd_bls_fp_reduce_wide_batch6( &out->c[0], &w[0] ); /* out.c0:6 = w0:6 mod p. */")
    lines.append("  fd_bls_fp_reduce_wide_batch6( &out->c[6], &w[6] ); /* out.c6:12 = w6:12 mod p. */")
    lines.append("}")
    return "\n".join(lines)


def emit_square() -> str:
    terms = square_products()
    lines = [
        "static void",
        "fp12_sqr_generated( fd_bls_fp12_t * out, fd_bls_fp12_t const * x ) {",
        "  fd_bls_fp_t x2[12];",
        "  fd_bls_fp_wide_t w[12], common, flipped;",
    ]
    # Inputs are bounded by 2*m and every RNS modulus has two IFMA headroom
    # bits.  Therefore 2*x is still a valid 52-bit IFMA digit.  Keeping this
    # as a raw doubled operand avoids 24 needless modular normalizations per
    # Fp12 square; the wide-expression bound remains far below MAX_ADD.
    for i in range(12):
        lines.append(f"  x2[{i}].m1 = wwv_add( x->c[{i}].m1, x->c[{i}].m1 ); /* x2_{i}=2x{i}, base M. */")
        lines.append(f"  x2[{i}].m2 = wwv_add( x->c[{i}].m2, x->c[{i}].m2 ); /* x2_{i}=2x{i}, base N. */")

    def operand(j: int, doubled: bool) -> str:
        return f"x2[{j}]" if doubled else f"x->c[{j}]"

    def add_product(target: str, term: tuple[tuple[int, int, bool], int]) -> None:
        (i, j, doubled), coeff = term
        factor = 2 if doubled else 1
        fn = "fd_bls_fp_wide_addmul" if coeff > 0 else "fd_bls_fp_wide_submul"
        op = "+=" if coeff > 0 else "-="
        lines.append(
            f"  {fn}( &{target}, &x->c[{i}], &{operand(j, doubled)} );"
            f" /* {target} {op} {factor if factor != 1 else ''}x{i}*x{j}. */"
        )

    for k in range(0, 12, 2):
        even = {(i, j, doubled): coeff for coeff, i, j, doubled in terms[k]}
        odd = {(i, j, doubled): coeff for coeff, i, j, doubled in terms[k + 1]}
        shared, opposite, even_unique, odd_unique = split_pair(even, odd)

        lines.append("  fd_bls_fp_wide_offset( &common ); /* common = 0 mod p. */")
        for term in shared:
            add_product("common", term)
        lines.append(f"  w[{k}] = common; /* w{k} starts with terms shared by c{k} and c{k+1}. */")
        lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same shared terms. */")
        if opposite:
            (i, j, doubled), coeff = opposite[0]
            assert coeff == -1
            rhs = f"x2[{j}]" if doubled else f"x->c[{j}]"
            factor = 2 if doubled else 1
            lines.append(f"  fd_bls_fp_wide_mul_raw( &flipped, &x->c[{i}], &{rhs} ); /* flipped = {factor if factor != 1 else ''}x{i}*x{j}. */")
            for (i, j, doubled), coeff in opposite[1:]:
                assert coeff == -1
                rhs = f"x2[{j}]" if doubled else f"x->c[{j}]"
                factor = 2 if doubled else 1
                lines.append(f"  fd_bls_fp_wide_addmul( &flipped, &x->c[{i}], &{rhs} ); /* flipped += {factor if factor != 1 else ''}x{i}*x{j}. */")
            lines.append(f"  fd_bls_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
            lines.append(f"  fd_bls_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
        for term in even_unique:
            add_product(f"w[{k}]", term)
        for term in odd_unique:
            add_product(f"w[{k+1}]", term)
    # Two 6-slot reduces (see emit_mul_paired).
    lines.append("  fd_bls_fp_reduce_wide_batch6( &out->c[0], &w[0] ); /* out.c0:6 = w0:6 mod p. */")
    lines.append("  fd_bls_fp_reduce_wide_batch6( &out->c[6], &w[6] ); /* out.c6:12 = w6:12 mod p. */")
    lines.append("}")
    return "\n".join(lines)


# Direct coefficient formulas for cyclotomic squaring.  The first and second
# Fp6 halves are factored by 3 and 6 respectively, then rescaled after their
# shared wide reductions.
CYCLOTOMIC = [
    [(3,0,0),(-2,0,None),(-3,1,1),(3,8,8),(-3,9,9),(-6,8,9)],
    [(-2,1,None),(3,8,8),(-3,9,9),(6,0,1),(6,8,9)],
    [(-2,2,None),(3,4,4),(-3,5,5),(3,6,6),(-3,7,7),(-6,4,5)],
    [(-2,3,None),(3,4,4),(-3,5,5),(6,4,5),(6,6,7)],
    [(3,2,2),(-3,3,3),(-2,4,None),(3,10,10),(-3,11,11),(-6,10,11)],
    [(-2,5,None),(3,10,10),(-3,11,11),(6,2,3),(6,10,11)],
    [(2,6,None),(6,2,10),(-6,2,11),(-6,3,10),(-6,3,11)],
    [(2,7,None),(6,2,10),(6,2,11),(6,3,10),(-6,3,11)],
    [(2,8,None),(6,0,8),(-6,1,9)],
    [(2,9,None),(6,0,9),(6,1,8)],
    [(2,10,None),(6,4,6),(-6,5,7)],
    [(2,11,None),(6,4,7),(6,5,6)],
]


def emit_cyclotomic() -> str:
    lines = [
        "static void",
        "fp12_cyclotomic_sqr_generated( fd_bls_fp12_t * out, fd_bls_fp12_t const * x ) {",
        "  fd_bls_fp_t x2[12];",
        "  fd_bls_fp_t const one_third     = fd_bls_one_third;",
        "  fd_bls_fp_t const neg_two_thirds = fd_bls_neg_two_thirds;",
        "  fd_bls_fp_wide_t w[12], common, flipped;",
    ]
    # Same headroom argument as the general square above.  These doubled
    # operands are consumed only by a wide product before reduction.
    for i in range(12):
        lines.append(f"  x2[{i}].m1 = wwv_add( x->c[{i}].m1, x->c[{i}].m1 ); /* x2_{i}=2x{i}, base M. */")
        lines.append(f"  x2[{i}].m2 = wwv_add( x->c[{i}].m2, x->c[{i}].m2 ); /* x2_{i}=2x{i}, base N. */")

    def normalized(k: int) -> dict[tuple[object, ...], int]:
        scale = 3 if k < 6 else 6
        result: dict[tuple[object, ...], int] = {}
        for coeff, i, j in CYCLOTOMIC[k]:
            if j is None:
                result[("linear", i)] = 1
            else:
                scaled = coeff // scale
                assert scaled * scale == coeff and abs(scaled) in (1, 2)
                result[("product", min(i, j), max(i, j), abs(scaled))] = 1 if scaled > 0 else -1
        return result

    def product_operands(key: tuple[object, ...], k: int) -> tuple[str, str]:
        if key[0] == "linear":
            return f"x->c[{key[1]}]", "neg_two_thirds" if k < 6 else "one_third"
        _, i, j, doubled = key
        rhs = f"x2[{j}]" if doubled == 2 else f"x->c[{j}]"
        return f"x->c[{i}]", rhs

    def add_product(target: str, term: tuple[tuple[object, ...], int], k: int) -> None:
        key, coeff = term
        lhs, rhs = product_operands(key, k)
        if key[0] == "linear":
            term_math = f"{'-2/3' if k < 6 else '1/3'}*x{key[1]}"
            fn, op = "fd_bls_fp_wide_addmul", "+="
        else:
            _, i, j, doubled = key
            term_math = f"{int(doubled) if int(doubled) != 1 else ''}x{i}*x{j}"
            fn = "fd_bls_fp_wide_addmul" if coeff > 0 else "fd_bls_fp_wide_submul"
            op = "+=" if coeff > 0 else "-="
        lines.append(f"  {fn}( &{target}, &{lhs}, &{rhs} ); /* {target} {op} {term_math}. */")

    for k in range(0, 12, 2):
        even = normalized(k)
        odd = normalized(k + 1)
        shared, opposite, even_unique, odd_unique = split_pair(even, odd)

        lines.append("  fd_bls_fp_wide_offset( &common ); /* common = 0 mod p before the final scale. */")
        for term in shared:
            add_product("common", term, k)
        lines.append(f"  w[{k}] = common; /* w{k} starts with normalized terms shared by c{k} and c{k+1}. */")
        lines.append(f"  w[{k+1}] = common; /* w{k+1} starts with the same normalized terms. */")
        if opposite:
            key, coeff = opposite[0]
            assert coeff == -1 and key[0] == "product"
            lhs, rhs = product_operands(key, k)
            _, i, j, doubled = key
            term_math = f"{int(doubled) if int(doubled) != 1 else ''}x{i}*x{j}"
            lines.append(f"  fd_bls_fp_wide_mul_raw( &flipped, &{lhs}, &{rhs} ); /* flipped = {term_math}. */")
            for key, coeff in opposite[1:]:
                assert coeff == -1 and key[0] == "product"
                lhs, rhs = product_operands(key, k)
                _, i, j, doubled = key
                term_math = f"{int(doubled) if int(doubled) != 1 else ''}x{i}*x{j}"
                lines.append(f"  fd_bls_fp_wide_addmul( &flipped, &{lhs}, &{rhs} ); /* flipped += {term_math}. */")
            lines.append(f"  fd_bls_fp_wide_sub_raw( &w[{k}], &flipped ); /* w{k} -= flipped. */")
            lines.append(f"  fd_bls_fp_wide_add_raw( &w[{k+1}], &flipped ); /* w{k+1} += flipped. */")
        for term in even_unique:
            add_product(f"w[{k}]", term, k)
        for term in odd_unique:
            add_product(f"w[{k+1}]", term, k + 1)
    lines.append("  fd_bls_fp_reduce_wide_scaled_batch6( &out->c[0], &w[0], 3U ); /* out.c0:6 = 3*w0:6 mod p. */")
    lines.append("  fd_bls_fp_reduce_wide_scaled_batch6( &out->c[6], &w[6], 6U ); /* out.c6:12 = 6*w6:12 mod p. */")
    lines.append("}")
    return "\n".join(lines)


def generate() -> str:
    all_terms = products(tuple(range(12)))
    assert [len(x) for x in all_terms] == [22, 22, 18, 18, 14, 14, 20, 20, 16, 16, 12, 12]
    return (
        "/* Generated by gen_bls_fp12.py.  Do not edit.\n"
        "   c[6*i+2*j+k] is the coefficient of w^i*v^j*u^k in\n"
        "   Fp[u]/(u^2+1), v^3=u+1, w^2=v. */\n\n"
        "/* Tower product with one lazy RNS reduction per output coefficient. */\n"
        + emit_mul_paired("fp12_mul_generated", tuple(range(12)), False)
        + "\n\n/* Symmetric cross terms are consolidated before lazy reduction. */\n"
        + emit_square()
        + "\n\n/* Multiply by l0+l1*u+(l2+l3*u)*v+(l4+l5*u)*w*v. */\n"
        + emit_mul_paired("fp12_mul_sparse_generated", (0, 1, 2, 3, 8, 9), True)
        + "\n\n/* Squaring specialized to the cyclotomic subgroup. */\n"
        + emit_cyclotomic()
        + "\n"
    )


if __name__ == "__main__":
    output = Path(__file__).parent.parent / "fd_bls_fp12_generated.inc"
    output.write_text(generate())
    print(output)
