
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly

from cocotb.binary import BinaryValue

import wd_cocotil

@cocotb.test()
async def test(dut):

    c = Clock(dut.clk, 1, 'ns')
    await cocotb.start(c.start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    clk = dut.clk

    W = int(dut.W)
    if hasattr(dut, 'W0'):
        W0 = int(dut.W0)
    else:
        W0 = W
    if hasattr(dut, 'W1'):
        W1 = int(dut.W1)
    else:
        W1 = W
    T = int(dut.T) & 0xff

    o_rs = list()

    D = 0

    for i in range(1024):
        await RisingEdge(dut.clk)

    for i in range(1024):

        m_i = wd_cocotil.random_int(31)
        i0 = wd_cocotil.random_int(b=W0)
        if T in [0x1F, 0x2F, 0x3F]:
            i1 = L0
        else:
            i1 = wd_cocotil.random_int(b=W1)
        o_rs.append((i0, i1, i0 * i1, m_i))

        dut.in0.value = i0
        dut.in1.value = i1
        dut.m_i.value = 1 | (m_i << 1)

        await RisingEdge(dut.clk)

        if str(dut.m_o[0]) != '1':
            D += 1
            assert D < 100
            continue

        i0, i1, e_d, e_m = o_rs.pop(0)
        o_d = int(dut.out0)
        o_m = int(dut.m_o) >> 1

        dut._log.info ('{:x} x {:x} = \n{:x} =?= \n{:x}\nD.{}, {:x} =?= {:x}'.format(i0, i1, e_d, o_d, D, e_m, o_m))
        assert e_d == o_d
        assert e_m == o_m
