
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import wd_cocotil

@cocotb.test()
async def test(dut):

    dut.i_v = 0
    dut.o_r = 0
    dut.max_pending = 100

    q_i_sha_modq_meta = list()
    q_o_sha_modq_meta = dict()

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(wd_cocotil.random_toggle(dut.clk, dut.o_r, 50))
    await cocotb.start(wd_cocotil.mon_sha_modq_meta(dut, dut, clk, q_i=q_i_sha_modq_meta, q_o=q_o_sha_modq_meta, do_log=True))

    M = int(dut.META_W)

    # wait for xpm post reset
    # then wait more for key-store to initialize
    for i in range(1024+1024):
        await RisingEdge(clk)

    min_l = 0
    max_l = 1280
    mlens = list()

    tid = wd_cocotil.random_int(64)

    for _ in range(max_l * 2):

        # backpressured
        while str(dut.i_v) == '1' and str(dut.i_r) != '1':
            await RisingEdge(clk)

        tid += 1

        # random gap
        while random.randint(0, 100) > 50:
            dut.i_v = 0
            await RisingEdge(clk)

        if len(mlens) == 0:
            mlens = list(range(min_l, max_l+1))
        mlen = random.choice(mlens)
        mlens.remove(mlen)

        tr = wd_cocotil.random_tr(
            tid = tid,
            mlen = mlen,
            sha_modq_meta = wd_cocotil.random_int(M)
        )

        q_i_sha_modq_meta.append(tr)
        q_o_sha_modq_meta[tr['tid']] = tr

        blks = wd_cocotil.build_sha_modq_meta_i(tr)
        for f, l, c, t, m, d in blks:

            # backpressured
            while str(dut.i_v) == '1' and str(dut.i_r) != '1':
                await RisingEdge(clk)

            b_m = BinaryValue(bits=M, bigEndian=False)
            b_d = BinaryValue(bits=1024, bigEndian=False)
            b_m[M-1:0] = m
            b_d[1023:0] = d
            dut.i_v = 1
            dut.i_f = f
            dut.i_l = l
            dut.i_c = c
            dut.i_t = t
            dut.i_m = b_m
            dut.i_d = b_d

            await RisingEdge(clk)

    while True:
        if len(q_o_sha_modq_meta) == 0:
            break
        await RisingEdge(clk)
