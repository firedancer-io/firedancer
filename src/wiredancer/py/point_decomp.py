import random

from ref_ed25519 import modp_sqrt_m1
from ref_ed25519 import d
from ref_ed25519 import p
from ref_ed25519 import q
from ref_ed25519 import point_decompress

from ed25519_lib import mul_modp
from ed25519_lib import kpow_ed255192
from ed25519_lib import kpow_ed2551938
from ed25519_lib import Expr
from ed25519_lib import ternary

PM1 = p-1

def kpoint_decomp(y, d, p, ERR):

    sign    = y >> 255
    y       = y & ((1 << 255) - 1)

    yy      = Expr(func='mul_modp', args=(d, y, p))
    yy      = Expr(func='mul_modp', args=(yy, y, p))
    yy      = ternary(yy == PM1, 0, yy+1)
    yy      = kpow_ed255192(yy, p)

    x2      = Expr(func='mul_modp', args=(y, y, p))
    x2      = ternary(x2 == 0, PM1, x2-1)
    x2      = Expr(func='mul_modp', args=(x2, yy, p))
    x       = kpow_ed2551938(x2, p)
    xx      = Expr(func='mul_modp', args=(x, x, p))
    xp      = Expr(func='mul_modp', args=(x, modp_sqrt_m1, p))
    x       = ternary(xx != x2, xp, x)
    x       = ternary((x & 1) != sign, p - x, x)
    xx      = Expr(func='mul_modp', args=(x, x, p))

    x2z     = x2 == 0
    sz      = sign == 0
    snz     = sign != 0
    x2zsz   = x2z & sz
    x2zsnz  = x2z & snz

    r       = ternary(xx != x2, ERR, x)
    r       = ternary(x2zsz, ERR, r)
    r       = ternary(x2zsnz, 0, r)
    r       = ternary(y >= p, ERR, r)

    return r





if __name__ == '__main__':


    if False:

        Expr.reset()
        os = kpoint_decomp(Expr(0, var=True), Expr(d), Expr(p), Expr(p))
        Expr.outputs(os)
        
        # print (Expr.get_io_addrs())
        hex_const = Expr.dump_const_hex(1, 16, format='coe')
        hex_instr = Expr.dump_instr_hex(format='coe')

        with open('hex_const.coe', 'w') as f:
            f.write(hex_const)
        with open('hex_instr.coe', 'w') as f:
            f.write(hex_instr)

    while True:

        rstr = ""
        for _ in range(64):
            rstr += random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'])
        keyP = bytes.fromhex(rstr)
        inputs = [int.from_bytes(keyP, 'little')]

        a = point_decompress(keyP)
        if a == None:
            a = p
        else:
            a = a[0]

        # b = Expr.eval_trace(inputs)[-1]
        # b = Expr.eval_hex(hex_const, hex_instr, inputs)[-1]
        # print ('\nf({:x}): \n{:x} =?=\n{:x}, {} {}'.format(inputs[0], a, b, len(Expr.trace_q), Expr.max_mem))

        b = kpoint_decomp(Expr(inputs[0]), Expr(d), Expr(p), Expr(p)).eval()
        print ('\nf({:x}): \n{:x} =?=\n{:x}'.format(inputs[0], a, b))

        if a != b:
            WTF
