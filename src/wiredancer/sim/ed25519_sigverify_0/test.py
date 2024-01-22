
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import wd_cocotil

@cocotb.test()
async def test(dut):

    dut.i_v.value = 0
    dut.i_m.value = 0
    dut.o_r.value = 0
    dut.max_pending.value = 2

    q_o_ed25519_sigverify_0 = dict()

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(wd_cocotil.random_toggle(dut.clk, dut.o_r, 50))
    await cocotb.start(wd_cocotil.mon_ed25519_sigverify_0(dut, dut, clk, q_o=q_o_ed25519_sigverify_0, do_log=True))

    # wait for xpm post reset
    for i in range(1024):
        await RisingEdge(clk)

    W_M = int(dut.W_M)
    tid = wd_cocotil.random_int(64)

    for i in range(4):

        # backpressured
        while str(dut.i_v) == '1' and str(dut.i_r) != '1':
            await RisingEdge(clk)

        # random gap
        while random.randint(0, 100) > 50:
            dut.i_v = 0
            await RisingEdge(clk)

        tid += 1

        tr = wd_cocotil.random_tr(
            src = wd_cocotil.random_int(32),
            tid = tid,
        )

        q_o_ed25519_sigverify_0[tr['tid']] = tr

        b_i_m               = BinaryValue(bits=W_M, bigEndian=False)
        b_i_pub             = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_l           = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_h           = BinaryValue(bits=256, bigEndian=False)
        b_i_h               = BinaryValue(bits=256, bigEndian=False)

        b_i_m     [W_M-1:0] = wd_cocotil.build_ecc_meta(tr)
        b_i_pub   [256-1:0] = tr['pub']
        b_i_sig_l [256-1:0] = tr['sig_l']
        b_i_sig_h [256-1:0] = tr['sig_h']
        b_i_h     [256-1:0] = tr['sha_modq']

        dut.i_v             = 1
        dut.i_t             = tid
        dut.i_m             = b_i_m
        dut.i_pub           = b_i_pub
        dut.i_sig_l         = b_i_sig_l
        dut.i_sig_h         = b_i_sig_h
        dut.i_h             = b_i_h

        await RisingEdge(clk)

    # backpressured
    while str(dut.i_v) == '1' and str(dut.i_r) != '1':
        await RisingEdge(clk)
    dut.i_v = 0

    while len(q_o_ed25519_sigverify_0) > 0:
        await RisingEdge(clk)
