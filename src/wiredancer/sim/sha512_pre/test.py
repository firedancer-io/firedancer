
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import wd_cocotil

@cocotb.test()
async def test(dut):

    dut.i_w.value = 0
    dut.i_v.value = 0

    q_o_sha_pre = list()

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(wd_cocotil.mon_sha_pre(dut, dut, clk, q_i=None, q_o=q_o_sha_pre, do_log=True))

    # wait for xpm post reset
    for i in range(1024):
        await RisingEdge(clk)

    W = int(dut.W_D)
    M = sum(wd_cocotil.meta2)
    min_l = 32+32
    max_l = 128*3
    mlens = list()

    for _ in range(max_l * 2):

        if len(mlens) == 0:
            mlens = list(range(min_l, max_l+1))
        mlen = random.choice(mlens)
        mlens.remove(mlen)

        tr = wd_cocotil.random_tr(
            mlen = mlen,
            src = wd_cocotil.random_int(16),
        )

        q_o_sha_pre.append(tr)

        msg = tr['sha_msg']
        sop = 1
        size = len(msg)

        while len(msg) > 0:

            # backpressured
            while str(dut.i_v.value) == '1' and str(dut.i_r.value) != '1':
                await RisingEdge(clk)

            # random gap
            while random.randint(0, 100) > 80:
                dut.i_v.value = 0
                await RisingEdge(clk)

            eop = len(msg) <= (W//8)
            e = (W//8) - len(msg)
            e = 0 if e < 0 else e
            b_m = BinaryValue(n_bits=M, bigEndian=False)
            b_m[16                        -1:0                          ] = tr['src']
            b_m[16+64                     -1:16                         ] = tr['tid']
            b_m[16+64+256                 -1:16+64                      ] = tr['sig_l']
            b_m[16+64+256+256             -1:16+64+256                  ] = tr['sig_h']
            b_m[16+64+256+256+256         -1:16+64+256+256              ] = tr['pub']
            b_m[16+64+256+256+256+16      -1:16+64+256+256+256          ] = size
            b_m[16+64+256+256+256+16+6    -1:16+64+256+256+256+16       ] = e
            b_m[16+64+256+256+256+16+6+1  -1:16+64+256+256+256+16+6     ] = sop
            off = M-W
            for i in range(W//8):
                if len(msg) == 0:
                    b_m[off+i*8+8-1:off+i*8] = 0xff#random.randint(0, 255)
                else:
                    b_m[off+i*8+8-1:off+i*8] = msg[0]
                    msg = msg[1:]

            dut.i_v.value = 1
            dut.i_e.value = eop
            dut.i_m.value = b_m

            sop = 0

            await RisingEdge(clk)

    dut.i_v.value = 0

    while len(q_o_sha_pre) > 0:
        await RisingEdge(clk)
