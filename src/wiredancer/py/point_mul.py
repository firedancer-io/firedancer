import random

import ref_ed25519
from ref_ed25519 import modp_sqrt_m1
from ref_ed25519 import d
from ref_ed25519 import p
from ref_ed25519 import q
from ref_ed25519 import point_decompress
from ref_ed25519 import point_add
from ref_ed25519 import point_mul

from ed25519_lib import mul_modp
from ed25519_lib import kpow
from ed25519_lib import Expr
from ed25519_lib import ternary
from ed25519_lib import rand_int

def kpoint_add(P, Q, d, p):
    A0 = Expr(func='sub_modp', args=(P[1], P[0], p))
    B0 = Expr(func='add_modp', args=(P[1], P[0], p))

    A1 = Expr(func='sub_modp', args=(Q[1], Q[0], p))
    B1 = Expr(func='add_modp', args=(Q[1], Q[0], p))

    A = Expr(func='mul_modp', args=(A0, A1, p))
    B = Expr(func='mul_modp', args=(B0, B1, p))

    # A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;

    C = Expr(func='mul_modp', args=(P[3], Q[3], p))
    C = Expr(func='mul_modp', args=(C, d, p))
    C = Expr(func='add_modp', args=(C, C, p))

    D = Expr(func='mul_modp', args=(P[2], Q[2], p))
    D = Expr(func='add_modp', args=(D, D, p))

    # C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;

    F = Expr(func='sub_modp', args=(D, C, p))
    G = Expr(func='add_modp', args=(D, C, p))
    E = Expr(func='sub_modp', args=(B, A, p))
    H = Expr(func='add_modp', args=(B, A, p))
    # E, F, G, H = B-A, D-C, D+C, B+A;

    x = Expr(func='mul_modp', args=(E, F, p), out=True)
    y = Expr(func='mul_modp', args=(G, H, p), out=True)
    z = Expr(func='mul_modp', args=(F, G, p), out=True)
    t = Expr(func='mul_modp', args=(E, H, p), out=True)
    # return (E*F, G*H, F*G, E*H);

    return (x, y, z, t)


def kpoint_mul(P, s, d, p):

    Q = (Expr(0), Expr(1), Expr(1), Expr(0)) # Neutral element
    for i in range(256):
        a = s & 1
        s >>= 1
        Q2 = kpoint_add(Q, P, d, p)
        P = kpoint_add(P, P, d, p)
        x = ternary(a, Q2[0], Q[0])
        y = ternary(a, Q2[1], Q[1])
        z = ternary(a, Q2[2], Q[2])
        t = ternary(a, Q2[3], Q[3])
        Q = (x, y, z, t)
    return Q




if __name__ == '__main__':

    Expr.reset()
    kpoint_mul(
        (
            Expr(0, var=True),
            Expr(0, var=True),
            Expr(0, var=True),
            Expr(0, var=True),
        ),
        Expr(0, var=True),
        Expr(d), Expr(p)
    )
    # Expr.dump_instrs()
    Expr.shrink_trace()
    # Expr.dump_instrs()

    # print (Expr.get_io_addrs())
    # print (Expr.dump_const_hex(32, 16))
    # print (Expr.dump_instr_hex())

    while True:

        rstr = ""
        for _ in range(64):
            rstr += random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'])
        keyP = bytes.fromhex(rstr)
        keyP = ref_ed25519.secret_to_public(keyP)

        s = rand_int(256)
        a = point_decompress(keyP)
        if a == None:
            continue

        aa = point_mul(s, a)

        b = Expr.eval_trace([
            a[0],
            a[1],
            a[2],
            a[3],
            s,
        ])[-4:]

        bb = tuple(b)
        for _, __ in zip(aa, bb):
            print ('{:x} =?=\n{:x}'.format(_, __))
        print ('{} {}'.format(len(Expr.trace_q), Expr.max_mem))

        if aa != bb:
            WTF

