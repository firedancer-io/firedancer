
import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue

import ref_ed25519
import wd_cocotil
import pcap

@cocotb.test()
async def test(dut):

    dut.avmm_read.value = 0
    dut.avmm_write.value = 0
    dut.dma_f.value = 0
    dut.pcie_v.value = 0
    dut.send_fails = 1

    q_i_pcie_tr_ext = list()
    q_o_pcie_tr_ext = list()
    q_o_sha_pre = list()
    q_o_sha_modq_meta = dict()
    q_o_ed25519_sigverify_0 = dict()
    q_o_ed25519_sigverify_1 = dict()
    q_o_ed25519_sigverify_2 = dict()
    q_o_res_dma = list()

    clk = dut.clk
    clk_f = dut.clk_f
    await cocotb.start(Clock(dut.clk, 1, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk, dut.rst, 32, active_high=True))
    await cocotb.start(Clock(dut.clk_f, .9, 'ns').start())
    await cocotb.start(wd_cocotil.toggle_reset(dut.clk_f, dut.rst_f, 32, active_high=True))
    await cocotb.start(wd_cocotil.random_toggle(dut.clk, dut.dma_r, 50))

    await cocotb.start(wd_cocotil.mon_pcie_tr_ext(dut, dut.P_IN[0].tr_ext_inst, clk, q_i=q_i_pcie_tr_ext, q_o=q_o_pcie_tr_ext, do_log=True))
    await cocotb.start(wd_cocotil.mon_sha_pre(dut, dut.sha512_pre_inst, clk, q_o=q_o_sha_pre, do_log=True))
    await cocotb.start(wd_cocotil.mon_sha_modq_meta(dut, dut.sha512_modq_meta_inst, clk, q_o=q_o_sha_modq_meta, do_log=True))
    await cocotb.start(wd_cocotil.mon_ed25519_sigverify_0(dut, dut.ed25519_sigverify_0_inst, clk, q_o=q_o_ed25519_sigverify_0, do_log=True))
    await cocotb.start(wd_cocotil.mon_ed25519_sigverify_1(dut, dut.ed25519_sigverify_1_inst, clk_f, q_o=q_o_ed25519_sigverify_1, do_log=True))
    await cocotb.start(wd_cocotil.mon_ed25519_sigverify_2(dut, dut.ed25519_sigverify_2_inst, clk, q_o=q_o_ed25519_sigverify_2, do_log=True))
    await cocotb.start(wd_cocotil.mon_dma(dut, dut, clk, q_o=q_o_res_dma, do_log=True))

    for i in range(int(dut.N_SCH)):
        await cocotb.start(wd_cocotil.model_schl_cpu(dut, dut.ed25519_sigverify_0_inst.G_SCH[i].schl_cpu_inst, clk, do_log=True))
    await cocotb.start(wd_cocotil.model_dsdp(dut, dut.ed25519_sigverify_1_inst.ed25519_sigverify_dsdp_mul_inst, clk_f, do_log=True))

    # wait for xpm post reset
    for i in range(1024):
        await RisingEdge(clk)
    # wait for key_stores post reset
    for i in range(1024):
        await RisingEdge(clk)

    tid = 0xabcd0000 - 1
    pcie_a = 0
    pcie_b = 1 << 32
    min_sz = 32+32
    max_sz = 1280
    mls = list()

    pc = pcap.kpcap(r='../../pcaps/val4ni_flood-1653425338.pcap')

    for i in range(1024):

        for i in range(random.randint(10, 250)):
            await RisingEdge(clk)

        # backpressure for PCIe fifo
        while int(dut.pcie_il[0]) > 2:
            await RisingEdge(clk)

        if False:
        # if True:
        # if random.randint(0, 100) > 50:
            S, P, M = pc.read()

            sig     = S[0]
            pub     = P[0]
            msg     = M
            err     = random.randint(0, 100)
        else:
            if len(mls) == 0:
                mls = list(range(min_sz, max_sz+1))
            ml = random.choice(mls)
            mls.remove(ml)

            sec     = bytes([random.randint(0, 255) for i in range(32)])
            pub     = ref_ed25519.secret_to_public(sec)
            msg     = bytes([random.randint(0, 255) for i in range(ml)])
            sig     = ref_ed25519.sign(sec, msg)
            err     = random.randint(0, 100)

        if err < 10:
            msg = wd_cocotil.random_byte_error(msg)
        elif err < 20:
            sig = wd_cocotil.random_byte_error(sig)
        elif err < 30:
            pub = wd_cocotil.random_byte_error(pub)

        tid += 1

        tr = wd_cocotil.random_tr(
            src = wd_cocotil.random_int(16-4) << 4, # LSBs == src
            tid = tid,
            sig = wd_cocotil.bytes_to_little(sig),
            pub = wd_cocotil.bytes_to_little(pub),
            msg = msg,
        )

        q_i_pcie_tr_ext.append(tr)
        q_o_pcie_tr_ext.append(tr)
        q_o_sha_pre.append(tr)
        q_o_sha_modq_meta[tr['tid']] = tr
        q_o_ed25519_sigverify_0[tr['tid']] = tr
        q_o_ed25519_sigverify_1[tr['tid']] = tr
        q_o_ed25519_sigverify_2[tr['tid']] = tr
        q_o_res_dma.append(tr)

        for blk in tr['pcie_tr']:
            await wd_cocotil.f1_write_32x16(dut, clk, pcie_b | pcie_a, blk)
            pcie_a += 64
            pcie_a &= (1 << wd_cocotil.PCIE_ADDR_W)-1

        await RisingEdge(clk)

    while len(q_o_res_dma) > 0:
        await RisingEdge(clk)
