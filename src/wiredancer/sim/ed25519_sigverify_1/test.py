
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

    q_o_ed25519_sigverify_1 = dict()

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(wd_cocotil.random_toggle(dut.clk, dut.o_r, 50))
    await cocotb.start(wd_cocotil.mon_ed25519_sigverify_1(dut, dut, clk, q_o=q_o_ed25519_sigverify_1, do_log=True))

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

        q_o_ed25519_sigverify_1[tr['tid']] = tr

        b_i_m               = BinaryValue(bits=W_M, bigEndian=False)
        b_i_pub             = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_l           = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_h           = BinaryValue(bits=256, bigEndian=False)
        b_i_h               = BinaryValue(bits=256, bigEndian=False)

        b_i_t               = BinaryValue(bits= 64, bigEndian=False)
        b_i_m               = BinaryValue(bits=W_M, bigEndian=False)
        b_i_pub             = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_l           = BinaryValue(bits=256, bigEndian=False)
        b_i_sig_h           = BinaryValue(bits=256, bigEndian=False)
        b_i_h               = BinaryValue(bits=256, bigEndian=False)
        b_i_res             = BinaryValue(bits=  1, bigEndian=False)
        b_i_Rx              = BinaryValue(bits=256, bigEndian=False)
        b_i_Ax              = BinaryValue(bits=256, bigEndian=False)
        b_i_At              = BinaryValue(bits=256, bigEndian=False)
        b_i_Tx              = BinaryValue(bits=256, bigEndian=False)
        b_i_Ty              = BinaryValue(bits=256, bigEndian=False)
        b_i_Tz              = BinaryValue(bits=256, bigEndian=False)
        b_i_Tt              = BinaryValue(bits=256, bigEndian=False)

        b_i_t      [64-1:0] = tid
        b_i_m     [W_M-1:0] = i_m
        b_i_pub     [255:0] = i_pub
        b_i_sig_l   [255:0] = i_sig_l
        b_i_sig_h   [255:0] = i_sig_h
        b_i_h       [255:0] = i_h
        b_i_res     [  0:0] = i_res
        b_i_Rx      [255:0] = i_Rx
        b_i_Ax      [255:0] = i_Ax
        b_i_At      [255:0] = i_At
        b_i_Tx      [255:0] = i_Tx
        b_i_Ty      [255:0] = i_Ty
        b_i_Tz      [255:0] = i_Tz
        b_i_Tt      [255:0] = i_Tt

        dut.i_v             = 1
        dut.i_t             = b_i_t
        dut.i_m             = b_i_m
        dut.i_pub           = b_i_pub
        dut.i_sig_l         = b_i_sig_l
        dut.i_sig_h         = b_i_sig_h
        dut.i_h             = b_i_h
        dut.i_res           = b_i_res
        dut.i_Rx            = b_i_Rx
        dut.i_Ax            = b_i_Ax
        dut.i_At            = b_i_At
        dut.i_Tx            = b_i_Tx
        dut.i_Ty            = b_i_Ty
        dut.i_Tz            = b_i_Tz
        dut.i_Tt            = b_i_Tt

        await RisingEdge(clk)

    # backpressured
    while str(dut.i_v) == '1' and str(dut.i_r) != '1':
        await RisingEdge(clk)
    dut.i_v = 0

    while len(q_o_ed25519_sigverify_1) > 0:
        await RisingEdge(clk)
