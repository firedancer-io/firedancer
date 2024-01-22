
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import wd_cocotil
import ref_ed25519

@cocotb.test()
async def test(dut):

    clk = dut.clk
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))

    for i in range(1024):
        await RisingEdge(clk)

    W_M = int(dut.M)
    es = list()
    D = 0

    for i in range(1024):

        m_i = wd_cocotil.random_int(W_M-1)

        P0 = random.choice([
            (0, 1, 1, 0),
            ref_ed25519.point_mul(wd_cocotil.random_int(100), ref_ed25519.G)
        ])

        P2 = ref_ed25519.point_add(P0, P0)

        es.append((P2, m_i))

        p0_x = BinaryValue(bits=255, bigEndian=False)
        p0_y = BinaryValue(bits=255, bigEndian=False)
        p0_z = BinaryValue(bits=255, bigEndian=False)
        p0_t = BinaryValue(bits=255, bigEndian=False)

        p0_x[255-1:0] = P0[0]
        p0_y[255-1:0] = P0[1]
        p0_z[255-1:0] = P0[2]
        p0_t[255-1:0] = P0[3]

        dut.in0_x = p0_x
        dut.in0_y = p0_y
        dut.in0_z = p0_z
        dut.in0_t = p0_t

        dut.m_i = 1 | (m_i << 1)

        await RisingEdge(dut.clk)

        if str(dut.m_o[0]) != '1':
            D += 1
            assert D < 100
            continue

        P2, m_i = es.pop(0)
        o_x = int(dut.out0_x)
        o_y = int(dut.out0_y)
        o_z = int(dut.out0_z)
        o_t = int(dut.out0_t)
        m_o = int(dut.m_o) >> 1

        dut._log.info ('D: {}, {}'.format(i, D))
        dut._log.info ('m: \n{:x} =?= \n{:x}'.format(m_i, m_o))
        dut._log.info ('x: \n{:x} =?= \n{:x}'.format(P2[0], o_x))
        dut._log.info ('y: \n{:x} =?= \n{:x}'.format(P2[1], o_y))
        dut._log.info ('z: \n{:x} =?= \n{:x}'.format(P2[2], o_z))
        dut._log.info ('t: \n{:x} =?= \n{:x}'.format(P2[3], o_t))

        assert P2[0] == o_x
        assert P2[1] == o_y
        assert P2[2] == o_z
        assert P2[3] == o_t
        assert m_i == m_o
