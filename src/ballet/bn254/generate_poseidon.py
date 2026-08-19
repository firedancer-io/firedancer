#!/usr/bin/env python3

import pathlib
import sys


FIELD_BITS = 254
FULL_ROUNDS = 8
HALF_ROUNDS = FULL_ROUNDS // 2
P = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
R = pow(2, 256, P)
R_INV = pow(R, -1, P)

PARTIAL_ROUNDS = {
    2: 56,
    3: 57,
    4: 56,
    5: 60,
    6: 60,
    7: 63,
    8: 64,
    9: 63,
    10: 60,
    11: 66,
    12: 60,
    13: 65,
}


class GrainLFSR:
    def __init__(self, field, sbox, field_bits, width, full_rounds, partial_rounds):
        bits = []
        for value, bit_cnt in (
            (field, 2),
            (sbox, 4),
            (field_bits, 12),
            (width, 12),
            (full_rounds, 10),
            (partial_rounds, 10),
        ):
            bits.extend(int(bit) for bit in bin(value)[2:].zfill(bit_cnt))
        bits.extend([1] * 30)

        self.state = bits
        for _ in range(160):
            self.clock()

    def clock(self):
        bit = (
            self.state[62]
            ^ self.state[51]
            ^ self.state[38]
            ^ self.state[23]
            ^ self.state[13]
            ^ self.state[0]
        )
        self.state.pop(0)
        self.state.append(bit)
        return bit

    def next_bit(self):
        bit = self.clock()
        while bit == 0:
            self.clock()
            bit = self.clock()
        return self.clock()

    def random_bits(self, bit_cnt):
        out = 0
        for _ in range(bit_cnt):
            out = (out << 1) | self.next_bit()
        return out


def generate_round_constants(grain, width, partial_rounds):
    constants = []
    target = (FULL_ROUNDS + partial_rounds) * width
    while len(constants) < target:
        candidate = grain.random_bits(FIELD_BITS)
        if candidate < P:
            constants.append(candidate)
    return constants


def generate_mds(grain, width):
    while True:
        elems = [grain.random_bits(FIELD_BITS) % P for _ in range(2 * width)]
        if len(elems) != len(set(elems)):
            continue

        xs = elems[:width]
        ys = elems[width:]
        mds = []
        ok = True

        for i in range(width):
            row = []
            for j in range(width):
                denom = (xs[i] + ys[j]) % P
                if denom == 0:
                    ok = False
                    break
                row.append(pow(denom, -1, P))
            if not ok:
                break
            mds.append(row)

        if ok:
            return mds


def generate_base_params(width, partial_rounds):
    grain = GrainLFSR(
        field=1,
        sbox=0,
        field_bits=FIELD_BITS,
        width=width,
        full_rounds=FULL_ROUNDS,
        partial_rounds=partial_rounds,
    )
    return generate_round_constants(grain, width, partial_rounds), generate_mds(
        grain, width
    )


def vec_add(a, b):
    return [(x + y) % P for x, y in zip(a, b)]


def mat_vec(m, v):
    return [sum(m[i][j] * v[j] for j in range(len(v))) % P for i in range(len(m))]


def mat_mul(a, b):
    rows = len(a)
    cols = len(b[0])
    inner = len(b)
    return [
        [sum(a[i][k] * b[k][j] for k in range(inner)) % P for j in range(cols)]
        for i in range(rows)
    ]


def transpose(m):
    return [list(row) for row in zip(*m)]


def mat_inv(m):
    n = len(m)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(m)]

    for col in range(n):
        pivot = next(row for row in range(col, n) if aug[row][col] % P)
        aug[col], aug[pivot] = aug[pivot], aug[col]

        inv = pow(aug[col][col], -1, P)
        aug[col] = [(x * inv) % P for x in aug[col]]

        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            if factor:
                aug[row] = [
                    (aug[row][j] - factor * aug[col][j]) % P for j in range(2 * n)
                ]

    return [row[n:] for row in aug]


def factor_mds(m):
    """Return M', M'' such that m = M' M'' and M'' is sparse."""

    n = len(m)
    sub = [row[1:] for row in m[1:]]
    sub_inv = mat_inv(sub)
    col = [row[0] for row in m[1:]]
    hat = mat_vec(sub_inv, col)

    m_prime = [[0] * n for _ in range(n)]
    m_prime[0][0] = 1
    for i in range(1, n):
        for j in range(1, n):
            m_prime[i][j] = sub[i - 1][j - 1]

    sparse = [[0] * n for _ in range(n)]
    sparse[0] = m[0][:]
    for i in range(1, n):
        sparse[i][0] = hat[i - 1]
        sparse[i][i] = 1

    if mat_mul(m_prime, sparse) != [[x % P for x in row] for row in m]:
        raise AssertionError("invalid sparse MDS factorization")

    return m_prime, sparse


def optimized_constants(constants, mds, partial_rounds):
    width = len(mds)
    mds_inv = mat_inv(mds)

    rounds = [
        constants[i * width : (i + 1) * width]
        for i in range(FULL_ROUNDS + partial_rounds)
    ]

    start = [[0] * width for _ in range(HALF_ROUNDS)]
    start[0] = rounds[0]
    for i in range(1, HALF_ROUNDS):
        start[i] = mat_vec(mds_inv, rounds[i])

    acc = rounds[HALF_ROUNDS + partial_rounds][:]
    partial = [0] * partial_rounds
    for out_idx, const_idx in zip(
        range(partial_rounds - 1, -1, -1),
        range(HALF_ROUNDS + partial_rounds - 1, HALF_ROUNDS - 1, -1),
    ):
        tmp = mat_vec(mds_inv, acc)
        partial[out_idx] = tmp[0]
        tmp[0] = 0
        acc = vec_add(tmp, rounds[const_idx])

    start.append(mat_vec(mds_inv, acc))

    end = [
        mat_vec(mds_inv, rounds[i])
        for i in range(HALF_ROUNDS + partial_rounds + 1, FULL_ROUNDS + partial_rounds)
    ]

    return start, partial, end


def optimized_mds(mds, partial_rounds):
    base = transpose(mds)
    acc = [row[:] for row in base]
    sparse = []

    for _ in range(partial_rounds):
        m_prime, m_prime_prime = factor_mds(acc)
        acc = mat_mul(base, m_prime)
        sparse.append(m_prime_prime)

    sparse.reverse()
    pre_sparse = transpose(acc)
    sparse = [transpose(s) for s in sparse]

    return pre_sparse, sparse


def original_permute(state, constants, mds, partial_rounds):
    width = len(state)
    rounds = [
        constants[i * width : (i + 1) * width]
        for i in range(FULL_ROUNDS + partial_rounds)
    ]
    state = state[:]

    for r in range(HALF_ROUNDS):
        state = vec_add(state, rounds[r])
        state = [pow(x, 5, P) for x in state]
        state = mat_vec(mds, state)

    for r in range(HALF_ROUNDS, HALF_ROUNDS + partial_rounds):
        state = vec_add(state, rounds[r])
        state[0] = pow(state[0], 5, P)
        state = mat_vec(mds, state)

    for r in range(HALF_ROUNDS + partial_rounds, FULL_ROUNDS + partial_rounds):
        state = vec_add(state, rounds[r])
        state = [pow(x, 5, P) for x in state]
        state = mat_vec(mds, state)

    return state


def sparse_mat_vec(sparse, state):
    old_s0 = state[0]
    out = state[:]
    out[0] = sum(sparse[0][j] * state[j] for j in range(len(state))) % P
    for i in range(1, len(state)):
        out[i] = (state[i] + sparse[i][0] * old_s0) % P
    return out


def optimized_permute(state, mds, start, partial, end, pre_sparse, sparse):
    state = vec_add(state, start[0])
    state = [pow(x, 5, P) for x in state]

    for r in range(1, HALF_ROUNDS):
        state = vec_add(state, start[r])
        state = mat_vec(mds, state)
        state = [pow(x, 5, P) for x in state]

    state = vec_add(state, start[HALF_ROUNDS])
    state = mat_vec(pre_sparse, state)

    for r, constant in enumerate(partial):
        state[0] = pow(state[0], 5, P)
        state[0] = (state[0] + constant) % P
        state = sparse_mat_vec(sparse[r], state)

    state = [pow(x, 5, P) for x in state]
    for constant in end:
        state = vec_add(state, constant)
        state = mat_vec(mds, state)
        state = [pow(x, 5, P) for x in state]

    return mat_vec(mds, state)


def verify(width, constants, mds, start, partial, end, pre_sparse, sparse):
    tests = [
        [0] * width,
        list(range(width)),
        [(17 + 31 * i) % P for i in range(width)],
        [(0x123456789ABCDEF + i * 0xDEADBEEF) % P for i in range(width)],
    ]

    for state in tests:
        want = original_permute(state, constants, mds, len(partial))
        got = optimized_permute(state, mds, start, partial, end, pre_sparse, sparse)
        if got != want:
            raise AssertionError(f"optimized Poseidon mismatch for width {width}")


def int_to_mont(x):
    x = (x * R) % P
    return [(x >> (64 * i)) & ((1 << 64) - 1) for i in range(4)]


def c_scalar(x):
    limbs = int_to_mont(x)
    return "{{ " + ", ".join(f"0x{limb:016x}" for limb in limbs) + ", }}"


def c_array(name, values):
    lines = [f"static const fd_bn254_scalar_t {name}[] = {{"]
    for value in values:
        lines.append(f"  {c_scalar( value )},")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def flatten(matrix):
    return [x for row in matrix for x in row]


def render():
    chunks = [
        "/* Poseidon parameters, to compute Poseidon with 2 <= width <= 13.",
        "",
        "   Generated by generate_poseidon.py.",
        "",
        "   All elements are in Montgomery form to avoid unnecessary conversions.",
        "   fd_poseidon_ark_w is a vector of w x number of rounds.",
        "   fd_poseidon_mds_w is a matrix of w x w elements, flattened as a vector. */",
        "",
    ]

    optimized = [
        "",
    ]

    for width, partial_rounds in PARTIAL_ROUNDS.items():
        ark, mds = generate_base_params(width, partial_rounds)
        start, partial, end = optimized_constants(ark, mds, partial_rounds)
        pre_sparse, sparse = optimized_mds(mds, partial_rounds)
        verify(width, ark, mds, start, partial, end, pre_sparse, sparse)

        sparse_row = []
        sparse_col = []
        for matrix in sparse:
            sparse_row.extend(matrix[0])
            sparse_col.extend(matrix[i][0] for i in range(1, width))

        chunks.append(c_array(f"fd_poseidon_ark_{width}", ark))
        chunks.append(c_array(f"fd_poseidon_mds_{width}", flatten(mds)))

        optimized.append(c_array(f"fd_poseidon_ark_start_{width}", flatten(start)))
        optimized.append(c_array(f"fd_poseidon_ark_partial_{width}", partial))
        optimized.append(c_array(f"fd_poseidon_ark_end_{width}", flatten(end)))
        optimized.append(
            c_array(f"fd_poseidon_pre_sparse_mds_{width}", flatten(pre_sparse))
        )
        optimized.append(c_array(f"fd_poseidon_sparse_mds_row_{width}", sparse_row))
        optimized.append(c_array(f"fd_poseidon_sparse_mds_col_{width}", sparse_col))

    chunks.extend(optimized)
    return "\n".join(chunks).rstrip() + "\n"


def main():
    if len(sys.argv) > 2:
        print("usage: gen_poseidon_params.py [fd_poseidon_params.c]", file=sys.stderr)
        return 1

    path = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) == 2
        else pathlib.Path(__file__).with_name("fd_poseidon_params.c")
    )
    path.write_text(render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
