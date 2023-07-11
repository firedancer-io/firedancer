
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import wd_cocotil

@cocotb.test()
async def test(dut):

    dut.i_valid = 0
    dut.o_r = 0
    dut.max_pending = 10

    q_o_sha_pre = list()

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(wd_cocotil.random_toggle(dut.clk, dut.o_r, 50))
    await cocotb.start(wd_cocotil.mon_sha_pre(dut, dut, clk, q_i=None, q_o=q_o_sha_pre, do_log=True))

    # wait for xpm post reset
    for i in range(1024):
        await RisingEdge(clk)

    W = int(dut.W_D)
    M = int(dut.W_M)
    min_l = 32+32
    max_l = 1280
    mlens = list()

    for _ in range(max_l * 2):

        if len(mlens) == 0:
            mlens = list(range(min_l, max_l+1))
        mlen = random.choice(mlens)
        mlens.remove(mlen)

        tr = wd_cocotil.random_tr(
            mlen = mlen,
            sha_pre_meta = wd_cocotil.random_int(M),
        )

        q_o_sha_pre.append(tr)

        msg = tr['sha_msg']
        sop = 1
        size = len(msg)

        while len(msg) > 0:

            # backpressured
            while str(dut.i_valid) == '1' and str(dut.i_ready) != '1':
                await RisingEdge(clk)

            # random gap
            while random.randint(0, 100) > 80:
                dut.i_valid = 0
                await RisingEdge(clk)

            eop = len(msg) <= (W//8)
            e = (W//8) - len(msg)
            e = 0 if e < 0 else e
            b_d = BinaryValue(bits=W, bigEndian=False)
            b_m = BinaryValue(bits=M, bigEndian=False)
            b_m[M-1:0] = tr['sha_pre_meta']
            for i in range(W//8):
                if len(msg) == 0:
                    b_d[i*8+8-1:i*8] = 0xff#random.randint(0, 255)
                else:
                    b_d[i*8+8-1:i*8] = msg[0]
                    msg = msg[1:]

            dut.i_valid = 1
            dut.i_startofpacket = sop
            dut.i_endofpacket = eop
            dut.i_empty = e
            dut.i_meta = b_m
            dut.i_size = size
            dut.i_data = b_d

            sop = 0

            await RisingEdge(clk)

    dut.i_valid = 0

    while len(q_o_sha_pre) > 0:
        await RisingEdge(clk)
