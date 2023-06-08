import random

import ref_ed25519
from ref_ed25519 import modp_sqrt_m1
from ref_ed25519 import d
from ref_ed25519 import p
from ref_ed25519 import q
from ref_ed25519 import G
from ref_ed25519 import point_decompress

from ed25519_lib import mul_modp
from ed25519_lib import kpow
from ed25519_lib import Expr
from ed25519_lib import ternary
from ed25519_lib import ed25519_dsdp_mul

from point_decomp import kpoint_decomp
from point_mul import kpoint_add
from point_mul import kpoint_mul

def kpoint_equal(P, Q, p):
	# x1 / z1 == x2 / z2 <==> x1 * z2 == x2 * z1
    x1z2 = Expr(func='mul_modp', args=(P[0], Q[2], p))
    x2z1 = Expr(func='mul_modp', args=(P[2], Q[0], p))
    y1z2 = Expr(func='mul_modp', args=(P[1], Q[2], p))
    y2z1 = Expr(func='mul_modp', args=(P[2], Q[1], p))
    r = 1
    r = ternary(x1z2 != x2z1, 0, r)
    r = ternary(y1z2 != y2z1, 0, r)
    return r

def ksigverify(public, sl, sh, h, d, p, q):
    Ax = kpoint_decomp(public, d, p, q)
    Ay = public & ((1 << 255) - 1)
    At = Expr(func='mul_modp', args=(Ax, Ay, p))
    A = (Ax, Ay, 1, At)

    Rx = kpoint_decomp(sl, d, p, q)
    Ry = sl & ((1 << 255) - 1)
    Rt = Expr(func='mul_modp', args=(Rx, Ry, p))
    R = (Rx, Ry, 1, Rt)

    shG = kpoint_mul(G, sh, d, p)
    hA = kpoint_mul(A, h, d, p)

    RhA = kpoint_add(R, hA, d, p)

    r = kpoint_equal(shG, RhA, p)
    r = ternary(sh >= q, 0, r)
    r = ternary(Ax == p, 0, r)
    r = ternary(Rx == p, 0, r)

    return r

def ksigverify2(public, sl, sh, h, d, p, q):
    Ax = kpoint_decomp(public, d, p, q)
    Axn = Expr(func='sub_modp', args=(p, Ax, p))
    Ay = public & ((1 << 255) - 1)
    At = Expr(func='mul_modp', args=(Axn, Ay, p))
    A = (Axn, Ay, 1, At)

    # double scalar, double point
    T = kpoint_add(G, A, d, p)
    Z = (0, 1, 1, 0)
    sh2 = sh
    for i in range(256):

        # taking advantage of the fact
        # ternary only checks LSB
        sel = Expr(func='dsdp_sel', args=(sh2, h))
        # b0 = sh2 >> 255
        # b1 = h >> 255
        # b0b1 = b0 & b1

        sh2 = sh2 << 1
        h = h << 1

        qx = Expr(func='ternary_dsdp_x', args=(sel, A[0], T[0]))
        qy = Expr(func='ternary_dsdp_y', args=(sel, A[1], T[1]))
        qz = Expr(func='ternary_dsdp_z', args=(sel, A[2], T[2]))
        qt = Expr(func='ternary_dsdp_t', args=(sel, A[3], T[3]))

        # qx = ternary(b0, G[0], 0)
        # qx = ternary(b1, A[0], qx)
        # qx = ternary(b0b1, T[0], qx)

        # qy = ternary(b0, G[1], 1)
        # qy = ternary(b1, A[1], qy)
        # qy = ternary(b0b1, T[1], qy)

        # qz = ternary(b0, G[2], 1)
        # qz = ternary(b1, A[2], qz)
        # qz = ternary(b0b1, T[2], qz)

        # qt = ternary(b0, G[3], 0)
        # qt = ternary(b1, A[3], qt)
        # qt = ternary(b0b1, T[3], qt)

        Q = (qx, qy, qz, qt)

        if i > 0:
            Z = kpoint_add(Z, Z, d, p)
        Z = kpoint_add(Z, Q, d, p)

    Rx = kpoint_decomp(sl, d, p, q)
    Ry = sl & ((1 << 255) - 1)
    R = (Rx, Ry, 1, 0)

    # checks
    r = kpoint_equal(Z, R, p)
    r = ternary(sh >= q, 0, r)
    r = ternary(Ax == p, 0, r)
    r = ternary(Rx == p, 0, r)

    return r


def ksigverify_split0(public, sl, sh, d, p, q):
    Ax = kpoint_decomp(public, d, p, q)
    Axn = Expr(func='sub_modp', args=(p, Ax, p))
    Ay = public & ((1 << 255) - 1)
    At = Expr(func='mul_modp', args=(Axn, Ay, p))
    A = (Axn, Ay, 1, At)

    Rx = kpoint_decomp(sl, d, p, q)

    T = kpoint_add(A, G, d, p)

    # checks
    r = 1
    r = ternary(sh >= q, 0, r)
    r = ternary(Ax == p, 0, r)
    r = ternary(Rx == p, 0, r)

    return r, Axn, At, Rx, T[0], T[1], T[2], T[3]

def ksigverify_split1(r, Ax, At, Rx, Tx, Ty, Tz, Tt, public, sl, sh, h):
    if r == 0:
        return 0

    Ay = public & ((1 << 255) - 1)
    A = (Ax, Ay, 1, At)

    Ry = sl & ((1 << 255) - 1)
    R = (Rx, Ry, 1, None)

    Z = ed25519_dsdp_mul(A, h, sh)

    RxZz = mul_modp(R[0], Z[2], p)
    RzZx = Z[0] # Rz == 1
    RyZz = mul_modp(R[1], Z[2], p)
    RzZy = Z[1] # Rz == 1

    if RxZz != RzZx:
        return 0
    if RyZz != RzZy:
        return 0
    return 1



if __name__ == '__main__':

    if False:
        Expr.reset()
        outs = ksigverify_split0(
            Expr(0, var=True),
            Expr(0, var=True),
            Expr(0, var=True),
            Expr(d), Expr(p), Expr(q),
        )
        Expr.outputs(outs)

        hex_const = Expr.dump_const_hex(1, 16, format='mif')
        hex_instr = Expr.dump_instr_hex(format='mif')

        with open('sig_hex_const.mif', 'w') as f:
            f.write(hex_const)
        with open('sig_hex_instr.mif', 'w') as f:
            f.write(hex_instr)
        
        END

    if True:
        sec = ''.join([random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']) for i in range(32)]).encode('utf-8')
        pub = ref_ed25519.secret_to_public(sec)
        ml = 0#random.randint(0, 1024)
        msg = ''.join([chr(random.randint(0, 255)) for i in range(ml)]).encode('utf-8')
        sig = ref_ed25519.sign(sec, msg)

        public = int.from_bytes(pub, 'little')
        sl = int.from_bytes(sig[:32], 'little')
        sh = int.from_bytes(sig[32:], 'little')

        h = ref_ed25519.sha512_modq(sig[:32] + pub + msg)
        outs = ksigverify_split0(
            Expr(public),
            Expr(sl),
            Expr(sh),
            Expr(d), Expr(p), Expr(q),
        )
        outs = [_.eval() for _ in outs]

        s = list()
        for i in range(64):
            s.append('0x{:02x}'.format(sig[i]))
        for i in range(32):
            s.append('0x{:02x}'.format(pub[i]))
        print (','.join(s))

        print ('{:x}'.format(h))
        for o in outs:
            print ('{:x}'.format(o))


        Axn = outs[1]
        At = outs[2]
        Rx = outs[3]
        Ay = public & ((1 << 255) - 1)
        A = (Axn, Ay, 1, At)

        Ry = sl & ((1 << 255) - 1)
        R = (Rx, Ry, 1, None)

        Z = ed25519_dsdp_mul(A, h, sh)
        for o in Z:
            print ('{:x}'.format(o))

        END

    while True:

        sec = ''.join([random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']) for i in range(32)]).encode('utf-8')
        pub = ref_ed25519.secret_to_public(sec)
        ml = random.randint(0, 1024)
        msg = ''.join([chr(random.randint(0, 255)) for i in range(ml)]).encode('utf-8')
        sig = ref_ed25519.sign(sec, msg)

        err = random.randint(0, 100)
        if err < 10:
            msg = msg + b' '
        elif err < 20:
            sig = sig[::-1]
        elif err < 30:
            pub = pub[::-1]

        h = ref_ed25519.sha512_modq(sig[:32] + pub + msg)
        v0 = ref_ed25519.verify(pub, msg, sig, h)
        v0 = int(v0)

        public = int.from_bytes(pub, 'little')
        sl = int.from_bytes(sig[:32], 'little')
        sh = int.from_bytes(sig[32:], 'little')

        inputs = [public, sl, sh, d, p, q]
        ret = Expr.eval_hex(hex_const, hex_instr, inputs)
        r, Ax, At, Rx, Tx, Ty, Tz, Tt = ret

        print ('inputs:')
        for i in range(3):
            print ('{:x}'.format(inputs[i]))
        print ('outputs:')
        for i in range(8):
            print ('{:x}'.format(ret[i]))

        v1 = ksigverify_split1(r, Ax, At, Rx, Tx, Ty, Tz, Tt, public, sl, sh, h)

        print ('{} =?= {:x}, {} {}'.format(v0, v1, len(Expr.trace_q), Expr.max_mem))

        if v0 != v1:
            WTF
