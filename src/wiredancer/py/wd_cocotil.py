
import random
import hashlib

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.binary import BinaryValue
from cocotb.utils import get_sim_time

# import sha512_lib
import ed25519_lib
import ref_ed25519
import sigverify

PCIE_MAGIC = 0xACE0FBAC
PCIE_ADDR_W = 20

meta0 = [16, 64]
meta1 = meta0 + [256, 256, 256]
meta2 = meta1 + [16, 6, 1, 512]
meta3 = meta1 + [1, 4, 1024]
meta4 = meta1 + [256]
meta5 = meta4 + ([256]*8)
meta6 = meta0 + ([256]*5) + [1]
meta7 = meta0 + [1]

def get_cycle():
    return get_sim_time('ns')

async def f1_write_32x16(dut, clk, addr, data):

    split = 0#random.randint(0, 1)
    b = BinaryValue(bits=512, bigEndian=False)
    b[511:0] = data

    if split == 0:
        dut.pcie_v = 0x3
        dut.pcie_a = addr
        dut.pcie_d[0] = b[256*1-1:256*0]
        dut.pcie_d[1] = b[256*2-1:256*1]
        await RisingEdge(clk)
        dut.pcie_v = 0x0
    else:
        dut.pcie_v = 0x1
        dut.pcie_a = addr
        dut.pcie_d[0] = b[256*1-1:256*0]
        await RisingEdge(clk)
        dut.pcie_v = 0x2
        dut.pcie_a = addr + 32
        dut.pcie_d[1] = b[256*2-1:256*1]
        await RisingEdge(clk)
        dut.pcie_v = 0x0

def sha512_modq_from_bytes(s):
    h = hashlib.sha512(s).digest()
    q = 2**252 + 27742317777372353535851937790883648493
    return bytes_to_little(h) % ref_ed25519.q

def sha512_modq_from_ints(s):
    return sha512_modq_from_bytes(bytearray(s))

def bytes_to_little(s):
    n = 0
    for i in range(len(s)):
        n += s[i] << (i*8)
    return n

def str_to_little(s):
    n = 0
    for i in range(len(s)):
        n += ord(s[i]) << (i*8)
    return n

def little_to_str(n, bs):
    s = ''
    for i in range(bs):
        s += chr(bits(n, 8, i*8))
    return s

def little_to_ints(n, bs):
    return [bits(n, 8, i*8) for i in range(bs)]

def lfsr_32(lfsr):
    fb = bits(lfsr, 1, 0) ^ bits(lfsr, 1, 1) ^ bits(lfsr, 1, 21) ^ bits(lfsr, 1, 31)
    return (bits(lfsr, 31, 0) << 1) | fb

def log2(n):
    return int(math.log(n) / math.log(2))

def bits(n, b, s):
    return (n >> s) & ((1<<b)-1)

def random_int(b=32):
    n = 0
    for i in range(b):
        n <<= 1
        n |= random.randint(0, 1)
    return n

def gen_blocks_from_msg_str(m_str):
    # message is supposed to be in string format, each character is 1 byte
    m = "".join(["{:02x}".format(ord(c) if type(c) == 'str' else c) for c in m_str])
    # process the message as hex-string from now on
    mlen_c = len(m)
    # padding (adding msb 1 is compulsory!, irrespective of msg len)
    # -- granularity here is byte-level, so add "80"
    m     += "80"
    plen_c =  1 * 2
    # size len is 16 bytes (here is a string in hex, so * 2)
    slen_c = 16 * 2
    # current length of block
    blen_c = mlen_c + plen_c
    # calculate addition padding length of zeros
    b1024len_c = (1024//8)*2 # hex format, 2 chars per byte
    modlen_c   = blen_c % b1024len_c
    need_space = int((b1024len_c - modlen_c) < slen_c)
    zlen_c     = (b1024len_c - slen_c) + (need_space * b1024len_c) - modlen_c
    # add extra zeros
    for _ in range(zlen_c):
        m += "0"
    # append the size (it must be in bits, so divide by 2 to get bytes, then multiply by 8)
    m += "{:032x}".format(mlen_c//2*8)
    # generate blocks
    assert ( len(m) % b1024len_c ) == 0, "!"
    B = list()
    for b_i in range( len(m) // b1024len_c ):
        b_str = m[b1024len_c*b_i : b1024len_c*(b_i+1)]
        B.append( int( b_str, 16 ) )
    return B

def random_tr(
    src = 0,
    sha_pre_meta = None,
    sha_modq_meta = None,
    tid = None,
    mlen = None,
    sig = None,
    pub = None,
    msg = None,
):
    mlen = random.randint(0, 1280) if mlen==None else mlen
    msg = [random.randint(0, 255) for i in range(mlen)] if msg == None else msg
    tr                  = dict()
    tr['dma_addr']      = random_int(64-5) << 5
    tr['dma_seq']       = random_int(64)
    tr['dma_ctrl']      = random_int(16) & 0xFFFB # leave error bit clear
    tr['dma_size']      = random_int(16)
    tr['dma_chunk']     = random_int(32)
    tr['time_0']        = 0
    tr['time_1']        = 0
    tr['time_2']        = 0
    tr['time_3']        = 0
    tr['err']           = 100
    tr['src']           = src
    tr['tid']           = random_int(64) if tid == None else tid
    tr['sig_l']         = random_int(256) if sig == None else bits(sig, 256,   0)
    tr['sig_h']         = random_int(256) if sig == None else bits(sig, 256, 256)
    tr['pub']           = random_int(256) if pub == None else pub
    tr['msg_sz']        = len(msg)
    tr['msg_s']         = msg
    tr['sha_msg']       = little_to_ints(tr['sig_l'], 256//8)
    tr['sha_msg']       += little_to_ints(tr['pub'], 256//8)
    tr['sha_msg']       += tr['msg_s']
    tr['sha_modq']      = sha512_modq_from_ints(tr['sha_msg'])
    tr['sha_pre_meta']  = sha_pre_meta if sha_pre_meta != None else build_sha_pre_meta(tr)
    tr['sha_modq_meta'] = sha_modq_meta if sha_modq_meta != None else build_sha_modq_meta(tr)
    tr['pcie_tr']       = build_pcie_tr_i(tr)
    tr['sigverify']     = int(ref_ed25519.verify(
        little_to_ints(tr['pub'], 256//8),
        msg,
        little_to_ints(tr['sig_l'], 256//8) + little_to_ints(tr['sig_h'], 256//8),
        tr['sha_modq']
    ))

    print ('tr_sigverify: {}'.format(tr['sigverify']))

    return tr

async def toggle_reset(clk, reset, n, active_high=True):
    reset.value = int(active_high)
    for i in range(n):
        await RisingEdge(clk)
    reset.value = int(not active_high)
    for i in range(n):
        await RisingEdge(clk)

async def random_toggle(clk, s, p):
    while True:
        await RisingEdge(clk)
        s.value = int(random.randint(0, 99) < p)

def build_meta0(tr):
    m = 0
    m |= tr['src']      << (0)
    m |= tr['tid']      << (0+32)
    return m

def extr_meta(m, n):
    s = 0
    l = list()
    for b in m:
        l.append(bits(n, b, s))
        s += b
    return tuple(l)

def random_byte_error(bs):
    l = list(bs)
    i = random.randint(0, len(bs)-1)
    j = random.randint(0, 7)
    if l[i] & (1 << j):
        l[i] -= 1 << j
    else:
        l[i] += 1 << j
    return l























def build_pcie_tr_i(tr):
    blks = list()

    blk = 0
    blk |= PCIE_MAGIC << 0
    blk |= tr['src'] << (0+32)
    blk |= (len(tr['msg_s']) + (256//8) + (256//8)) << (0+32+16)

    blk |= tr['dma_size']   << (0+32+16+16)
    blk |= tr['dma_ctrl']   << (0+32+16+16+16)
    blk |= tr['dma_addr']   << (0+32+16+16+16+16)
    blk |= tr['dma_seq']    << (0+32+16+16+16+16+64)
    blk |= tr['dma_chunk']  << (0+32+16+16+16+16+64+64)

    blk |= tr['sig_l']      << 256
    blks.append(blk)

    blk = 0
    blk |= tr['sig_h'] << 0
    blk |= tr['pub'] << 256
    blks.append(blk)

    blk = 0
    bi = 0
    s = tr['msg_s']
    while len(s) > 0:
        c = (s[0])
        s = s[1:]
        blk |= c << (bi*8)
        bi += 1
        if bi == (512//8):
            blks.append(blk)
            blk = 0
            bi = 0
    if bi != 0:
        blks.append(blk)

    return blks

def build_pcie_tr_o(tr):
    blks = list()

    blk = 0
    blk |= tr['sig_l'] << 0
    blk |= tr['pub'] << 256
    blks.append(blk)

    blk = 0
    bi = 0
    s = tr['msg_s']
    while len(s) > 0:
        c = (s[0])
        s = s[1:]
        blk |= c << (bi*8)
        bi += 1
        if bi == (512//8):
            blks.append(blk)
            blk = 0
            bi = 0
    if bi != 0:
        blks.append(blk)

    return blks

async def mon_pcie_tr_ext(ddut, dut, clk, q_i=None, q_o=None, do_log=False):

    refs_i = list()
    refs_o = list()

    while True:

        await RisingEdge(clk)

        if q_i != None and str(dut.pcie_v) == '1':

            if len(refs_i) == 0:
                tr = q_i.pop(0)
                refs_i.extend(build_pcie_tr_i(tr))

            i_d = int(dut.pcie_d)
            e_d = refs_i.pop(0)

            if do_log:
                ddut._log.info ('mon_pcie_tr_ext_i: \n{:x} =?= \n{:x}'.format(e_d, i_d))

            assert str(dut.pcie_f) != '1'
            assert e_d == i_d

        if str(dut.o_v) == '1' and str(dut.o_r) == '1' and q_o != None:

            o_m0     = int(dut.o_m0)
            o_m1     = int(dut.o_m1)
            o_e     = int(dut.o_e)

            (
                o_src,
                o_tid,
                o_sig_l,
                o_sig_h,
                o_pub,
                o_size,
                o_emp,
                o_sop,
                o_data,
            ) = extr_meta(meta2, o_m0)

            if len(refs_o) == 0:
                tr = q_o.pop(0)
                blks = build_pcie_tr_o(tr)

                # first blk is pcie header
                for i in range(len(blks)):

                    e_src       = tr['src']
                    e_tid       = tr['tid']
                    e_sig_l     = tr['sig_l']
                    e_sig_h     = tr['sig_h']
                    e_pub       = tr['pub']
                    e_size      = len(tr['sha_msg'])
                    e_emp       = bits((512//8) - bits(len(tr['sha_msg']), 6, 0), 6, 0)
                    e_sop       = int(i == 0)
                    e_e         = int(i == len(blks)-1)
                    e_data      = blks[i]

                    refs_o.append((
                        e_e,
                        e_src,
                        e_tid,
                        e_sig_l,
                        e_sig_h,
                        e_pub,
                        e_size,
                        e_emp,
                        e_sop,
                        e_data,
                    ))

            (
                e_e,
                e_src,
                e_tid,
                e_sig_l,
                e_sig_h,
                e_pub,
                e_size,
                e_emp,
                e_sop,
                e_data,
            ) = refs_o.pop(0)

            e_m1 = build_pcie_tr_i(tr)[0]

            if do_log:
                ddut._log.info ('mon_pcie_tr_ext_o: e    : \n{:x} =?=\n{:x}'.format(e_e      , o_e))
                ddut._log.info ('mon_pcie_tr_ext_o: src  : \n{:x} =?=\n{:x}'.format(e_src    , o_src))
                ddut._log.info ('mon_pcie_tr_ext_o: tid  : \n{:x} =?=\n{:x}'.format(e_tid    , o_tid))
                ddut._log.info ('mon_pcie_tr_ext_o: sig_l: \n{:x} =?=\n{:x}'.format(e_sig_l  , o_sig_l))
                ddut._log.info ('mon_pcie_tr_ext_o: sig_h: \n{:x} =?=\n{:x}'.format(e_sig_h  , o_sig_h))
                ddut._log.info ('mon_pcie_tr_ext_o: pub  : \n{:x} =?=\n{:x}'.format(e_pub    , o_pub))
                ddut._log.info ('mon_pcie_tr_ext_o: size : \n{:x} =?=\n{:x}'.format(e_size   , o_size))
                ddut._log.info ('mon_pcie_tr_ext_o: emp  : \n{:x} =?=\n{:x}'.format(e_emp    , o_emp))
                ddut._log.info ('mon_pcie_tr_ext_o: sop  : \n{:x} =?=\n{:x}'.format(e_sop    , o_sop))
                ddut._log.info ('mon_pcie_tr_ext_o: data : \n{:x} =?=\n{:x}'.format(e_data   , o_data))
                ddut._log.info ('mon_pcie_tr_ext_o: m1   : \n{:x} =?=\n{:x}'.format(e_m1     , o_m1))

            assert e_e      == o_e
            assert e_src    == o_src
            assert e_tid    == o_tid
            assert e_sig_l  == o_sig_l
            assert e_sig_h  == o_sig_h
            assert e_pub    == o_pub
            assert e_size   == o_size
            assert e_emp    == o_emp
            assert e_sop    == o_sop
            assert e_data   == o_data
            assert e_m1     == o_m1


















def build_sha_pre_meta(tr):
    m = 0
    m |= tr['src']      << (0)
    m |= tr['tid']      << (0+32)
    m |= tr['sig_h']    << (0+32+64)
    m |= tr['sig_l']    << (0+32+64+256)
    m |= tr['pub']      << (0+32+64+256+256)
    return m

def build_sha_pre_o(tr):
    sha_pre_o = gen_blocks_from_msg_str(tr['sha_msg'])
    return [(
            tr['src'],
            tr['tid'],
            tr['sig_l'],
            tr['sig_h'],
            tr['pub'],
            int(i == 0),
            int(i == len(sha_pre_o)-1),
            len(sha_pre_o),
            sha_pre_o[i],
        ) for i in range(len(sha_pre_o))]

async def mon_sha_pre(ddut, dut, clk, q_i=None, q_o=None, do_log=False):

    q_bo = list()

    while True:

        await RisingEdge(clk)

        if str(dut.o_v) == '1':

            if q_o != None:

                if len(q_bo) == 0:
                    tr = q_o.pop(0)
                    tr['time_1'] = get_cycle()
                    q_bo.extend(build_sha_pre_o(tr))
                    ddut._log.info ('mon_sha_pre_o: tid.{:x} sz.{} err.{} {} {}'.format(
                        tr['tid'],
                        len(tr['msg_s']),
                        tr['err'],
                        tr['time_0'],
                        tr['time_1'],
                    ))

                o_m = int(dut.o_m)
                o_e = int(dut.o_e)

                (
                    o_src,
                    o_tid,
                    o_sig_l,
                    o_sig_h,
                    o_pub,
                    o_f,
                    o_c,
                    o_d,
                ) = extr_meta(meta3, o_m)

                (
                    e_src,
                    e_tid,
                    e_sig_l,
                    e_sig_h,
                    e_pub,
                    e_f,
                    e_e,
                    e_c,
                    e_d,
                ) = q_bo.pop(0)

                if do_log:
                    ddut._log.info ('mon_sha_pre_o: src:   \n{:x} =?=\n{:x}'.format(e_src,    o_src))
                    ddut._log.info ('mon_sha_pre_o: tid:   \n{:x} =?=\n{:x}'.format(e_tid,    o_tid))
                    ddut._log.info ('mon_sha_pre_o: sig_l: \n{:x} =?=\n{:x}'.format(e_sig_l,  o_sig_l))
                    ddut._log.info ('mon_sha_pre_o: sig_h: \n{:x} =?=\n{:x}'.format(e_sig_h,  o_sig_h))
                    ddut._log.info ('mon_sha_pre_o: pub:   \n{:x} =?=\n{:x}'.format(e_pub,    o_pub))
                    ddut._log.info ('mon_sha_pre_o: f:     \n{:x} =?=\n{:x}'.format(e_f,      o_f))
                    ddut._log.info ('mon_sha_pre_o: e:     \n{:x} =?=\n{:x}'.format(e_e,      o_e))
                    ddut._log.info ('mon_sha_pre_o: c:     \n{:x} =?=\n{:x}'.format(e_c,      o_c))
                    ddut._log.info ('mon_sha_pre_o: d:     \n{:x} =?=\n{:x}'.format(e_d,      o_d))

                assert e_src    == o_src
                assert e_tid    == o_tid
                assert e_sig_l  == o_sig_l
                assert e_sig_h  == o_sig_h
                assert e_pub    == o_pub
                assert e_f      == o_f
                assert e_e      == o_e
                assert e_c      == o_c
                assert e_d      == o_d

























def build_sha_modq_o(tr):
    return (
        tr['src'],
        tr['tid'],
        tr['sig_l'],
        tr['sig_h'],
        tr['pub'],
        tr['sha_modq'],
    )

def build_sha_modq_meta(tr):
    m = 0
    m |= tr['src']      << (0)
    m |= tr['tid']      << (0+32)
    m |= tr['sig_h']    << (0+32+64)
    m |= tr['sig_l']    << (0+32+64+256)
    m |= tr['pub']      << (0+32+64+256+256)
    return m

def build_sha_modq_meta_i(tr):
    blks = gen_blocks_from_msg_str(tr['sha_msg'])

    return [(
        int(i==0),
        int(i==len(blks)-1),
        len(blks),
        tr['tid'],
        tr['sha_modq_meta'],
        blks[i],
    ) for i in range(len(blks))]

async def mon_sha_modq_meta(ddut, dut, clk, q_i=None, q_o=None, do_log=False):

    i_cnt = 0
    q_bi = list()

    while True:

        await RisingEdge(clk)

        # no gaps allowed
        assert i_cnt == 0 or str(dut.i_v) == '1', 'i_cnt: {}'.format(i_cnt)

        if str(dut.i_v) == '1' and str(dut.i_r) == '1':

            i_e = int(dut.i_e)
            i_m = int(dut.i_m)

            (
                i_src,
                i_tid,
                i_sig_l,
                i_sig_h,
                i_pub,
                i_f,
                i_c,
                i_d,
            ) = extr_meta(meta3, i_m)

            if i_f == 1:
                i_cnt = i_c
            i_cnt -= 1

            if q_i != None:

                # if first, q_bi should have drained by now
                assert (len(q_bi) == 0 and i_f == 1) or (i_f == 0)

                if i_f:
                    tr = q_i.pop(0)
                    q_bi = build_sha_modq_meta_i(tr)

                (e_f,
                e_l,
                e_c,
                e_t,
                e_m,
                e_d) = q_bi.pop(0)

                if do_log:
                    ddut._log.info ('mon_sha_modq_meta: i_f: \n{:x} =?= \n{:x}'.format(e_f, i_f))
                    ddut._log.info ('mon_sha_modq_meta: i_l: \n{:x} =?= \n{:x}'.format(e_l, i_l))
                    ddut._log.info ('mon_sha_modq_meta: i_c: \n{:x} =?= \n{:x}'.format(e_c, i_c))
                    ddut._log.info ('mon_sha_modq_meta: i_t: \n{:x} =?= \n{:x}'.format(e_t, i_t))
                    ddut._log.info ('mon_sha_modq_meta: i_m: \n{:x} =?= \n{:x}'.format(e_m, i_m))
                    ddut._log.info ('mon_sha_modq_meta: i_d: \n{:x} =?= \n{:x}'.format(e_d, i_d))

                assert e_f == i_f
                assert e_c == i_c
                assert e_t == i_t
                assert e_m == i_m
                assert e_d == i_d

        if str(dut.o_v) == '1':

            if q_o != None:

                o_m = int(dut.o_m)

                (
                    o_src,
                    o_tid,
                    o_sig_l,
                    o_sig_h,
                    o_pub,
                    o_h,
                ) = extr_meta(meta4, o_m)

                tr = q_o[o_tid]
                del q_o[o_tid]

                tr['time_2'] = get_cycle()
                ddut._log.info ('mon_sha_modq_meta_o: tid.{:x} sz.{} err.{} {} {} {}'.format(
                    tr['tid'],
                    len(tr['msg_s']),
                    tr['err'],
                    tr['time_0'],
                    tr['time_1'],
                    tr['time_2'],
                ))

                (
                    e_src,
                    e_tid,
                    e_sig_l,
                    e_sig_h,
                    e_pub,
                    e_h,
                ) = build_sha_modq_o(tr)

                if do_log:
                    ddut._log.info ('mon_sha_modq_o: src:   \n{:x} =?=\n{:x}'.format(e_src,    o_src))
                    ddut._log.info ('mon_sha_modq_o: tid:   \n{:x} =?=\n{:x}'.format(e_tid,    o_tid))
                    ddut._log.info ('mon_sha_modq_o: sig_l: \n{:x} =?=\n{:x}'.format(e_sig_l,  o_sig_l))
                    ddut._log.info ('mon_sha_modq_o: sig_h: \n{:x} =?=\n{:x}'.format(e_sig_h,  o_sig_h))
                    ddut._log.info ('mon_sha_modq_o: pub:   \n{:x} =?=\n{:x}'.format(e_pub,    o_pub))
                    ddut._log.info ('mon_sha_modq_o: h:     \n{:x} =?=\n{:x}'.format(e_h,      o_h))

                assert e_src    == o_src
                assert e_tid    == o_tid
                assert e_sig_l  == o_sig_l
                assert e_sig_h  == o_sig_h
                assert e_pub    == o_pub
                assert e_h      == o_h









































@cocotb.coroutine
def mon_ed25519_sigverify_dsdp_mul(dut, clk, q_i=None, q_o=None, do_print=False, self_test=False):

    while True:

        yield RisingEdge(clk)

        if str(dut.i_v) == '1' and str(dut.i_r) == '1':

            if q_i != None:

                i_m     = int(dut.i_m)

                i_Ax    = int(dut.i_Ax)
                i_Ay    = int(dut.i_Ay)
                i_Az    = int(dut.i_Az)
                i_At    = int(dut.i_At)

                i_ApGx  = int(dut.i_ApGx)
                i_ApGy  = int(dut.i_ApGy)
                i_ApGz  = int(dut.i_ApGz)
                i_ApGt  = int(dut.i_ApGt)

                i_As    = int(dut.i_As)
                i_Gs    = int(dut.i_Gs)

                tr = q_i[i_m]
                del q_i[i_m]

                (
                    e_pub,
                    e_sig_l,
                    e_sig_h,
                    e_h,
                    e_m,
                    (
                        e_res,
                        e_Ax,
                        e_At,
                        e_Rx,
                        e_ApGx,
                        e_ApGy,
                        e_ApGz,
                        e_ApGt,
                    )
                ) = build_ed25519_sigverify_0_o(tr)

                e_Ay = bits(e_pub, 255, 0)
                e_Az = 1
                e_As = e_h
                e_Gs = e_sig_h

                if do_print:
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_Ax:\n{:x} =?=\n{:x}'.format(e_Ax, i_Ax))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_Ay:\n{:x} =?=\n{:x}'.format(e_Ay, i_Ay))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_Az:\n{:x} =?=\n{:x}'.format(e_Az, i_Az))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_At:\n{:x} =?=\n{:x}'.format(e_At, i_At))

                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_ApGx:\n{:x} =?=\n{:x}'.format(e_ApGx, i_ApGx))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_ApGy:\n{:x} =?=\n{:x}'.format(e_ApGy, i_ApGy))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_ApGz:\n{:x} =?=\n{:x}'.format(e_ApGz, i_ApGz))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_ApGt:\n{:x} =?=\n{:x}'.format(e_ApGt, i_ApGt))

                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_As:\n{:x} =?=\n{:x}'.format(e_As, i_As))
                    print ('mon_ed25519_sigverify_dsdp_mul_i: i_Gs:\n{:x} =?=\n{:x}'.format(e_Gs, i_Gs))

                assert e_Ax == i_Ax
                assert e_Ay == i_Ay
                assert e_Az == i_Az
                assert e_At == i_At

                assert e_ApGx == i_ApGx
                assert e_ApGy == i_ApGy
                assert e_ApGz == i_ApGz
                assert e_ApGt == i_ApGt

                assert e_As == i_As
                assert e_Gs == i_Gs



        if str(dut.o_v) == '1':

            if q_o != None:

                o_m = int(dut.o_m)
                o_d = [0]*4
                o_d[0] = int(dut.o_Cx)
                o_d[1] = int(dut.o_Cy)
                o_d[2] = int(dut.o_Cz)
                o_d[3] = int(dut.o_Ct)

                e_d = q_o[o_m]
                del q_o[o_m]

                if do_print:
                    print ('ed25519_sigverify_dsdp_mul: ox: \n{:x} =?= \n{:x}'.format(e_d[0], o_d[0]))
                    print ('ed25519_sigverify_dsdp_mul: oy: \n{:x} =?= \n{:x}'.format(e_d[1], o_d[1]))
                    print ('ed25519_sigverify_dsdp_mul: oz: \n{:x} =?= \n{:x}'.format(e_d[2], o_d[2]))
                    print ('ed25519_sigverify_dsdp_mul: ot: \n{:x} =?= \n{:x}'.format(e_d[3], o_d[3]))

                assert ref_ed25519.point_equal(e_d, o_d)

                # t =?= (x*y)/z
                xy = ed25519_lib.mul_modp(o_d[0], o_d[1], ref_ed25519.p)
                zi = ref_ed25519.modp_inv(o_d[2])
                xyzi = ed25519_lib.mul_modp(xy, zi, ref_ed25519.p)
                assert xyzi == o_d[3]





























def build_ed25519_sigverify_0_o(tr):
    os = sigverify.ksigverify_split0(
        ed25519_lib.Expr(tr['pub']),
        ed25519_lib.Expr(tr['sig_l']),
        ed25519_lib.Expr(tr['sig_h']),
        ed25519_lib.Expr(ref_ed25519.d),
        ed25519_lib.Expr(ref_ed25519.p),
        ed25519_lib.Expr(ref_ed25519.q),
    )

    os = tuple(_.eval() for _ in os)

    return (
        tr['src'],
        tr['tid'],
        tr['sig_l'],
        tr['sig_h'],
        tr['pub'],
        tr['sha_modq'],
        os,
    )

async def mon_ed25519_sigverify_0(ddut, dut, clk, q_i=None, q_o=None, do_log=False):

    N_SCH_O = 8

    while True:

        await RisingEdge(clk)

        if str(dut.i_v) == '1' and str(dut.i_r) == '1':
            ddut._log.info ('mon_ed25519_sigverify_0_i')

        if str(dut.o_v) == '1':

            o_m = int(dut.o_m)

            o_os = [None]*8

            (
                o_src,
                o_tid,
                o_sig_l,
                o_sig_h,
                o_pub,
                o_h,
                o_os[0],
                o_os[1],
                o_os[2],
                o_os[3],
                o_os[4],
                o_os[5],
                o_os[6],
                o_os[7],
            ) = extr_meta(meta5, o_m)

            if q_o != None:
                tr = q_o[o_tid]
                del q_o[o_tid]

                tr['time_3'] = get_cycle()
                ddut._log.info ('mon_ed25519_sigverify_0_o: tid.{:x} sz.{} err.{} {} {} {} {}'.format(
                    tr['tid'],
                    len(tr['msg_s']),
                    tr['err'],
                    tr['time_0'],
                    tr['time_1'],
                    tr['time_2'],
                    tr['time_3'],
                ))

                (
                    e_src,
                    e_tid,
                    e_sig_l,
                    e_sig_h,
                    e_pub,
                    e_h,
                    e_os,
                ) = build_ed25519_sigverify_0_o(tr)

                if do_log:
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_src   : \n{:x} =?= \n{:x}'.format(e_src,   o_src))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_tid   : \n{:x} =?= \n{:x}'.format(e_tid,   o_tid))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_sig_l : \n{:x} =?= \n{:x}'.format(e_sig_l, o_sig_l))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_sig_h : \n{:x} =?= \n{:x}'.format(e_sig_h, o_sig_h))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_pub   : \n{:x} =?= \n{:x}'.format(e_pub,   o_pub))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_h     : \n{:x} =?= \n{:x}'.format(e_h,     o_h))
                    for i in range(N_SCH_O):
                        ddut._log.info ('mon_ed25519_sigverify_0_o: e_os[{}]: \n{:x} =?= \n{:x}'.format(i, e_os[i], o_os[i]))

                assert e_src    == o_src
                assert e_tid    == o_tid
                assert e_sig_l  == o_sig_l
                assert e_sig_h  == o_sig_h
                assert e_pub    == o_pub
                assert e_h      == o_h
                for i in range(N_SCH_O):
                    assert e_os[i] == o_os[i]






































































def build_ed25519_sigverify_1_o(tr, DSDP_WS=256):

    (
        i_src,
        i_tid,
        i_sig_l,
        i_sig_h,
        i_pub,
        i_h,
        (
            i_res,
            i_Ax,
            i_At,
            i_Rx,
            i_Tx,
            i_Ty,
            i_Tz,
            i_Tt,
        )
    ) = build_ed25519_sigverify_0_o(tr)

    A = (i_Ax, bits(i_pub, 255, 0), 1, i_At)

    As = i_h
    Gs = i_sig_h

    Z = ed25519_lib.ed25519_dsdp_mul(A, As, Gs, W_S=DSDP_WS)

    return (
        tr['src'],
        tr['tid'],
        tr['sig_l'],
        Z[2],
        Z[1],
        Z[0],
        i_Rx,
        i_res,
    )

async def mon_ed25519_sigverify_1(ddut, dut, clk, q_i=None, q_o=None, do_log=False, self_test=False):

    q_self = list()
    DSDP_WS = int(dut.DSDP_WS)

    while True:

        await RisingEdge(clk)

        # if str(dut.i_r) == '1':
        #     print ('mon_ed25519_sigverify_1_i_r')

        if str(dut.i_v) == '1' and str(dut.i_r) == '1':

            ddut._log.info ('mon_ed25519_sigverify_1_i')

            if self_test:
                i_m         = int(dut.i_m)
                i_sig_l     = int(dut.i_sig_l)
                i_sig_h     = int(dut.i_sig_h)
                i_pub       = int(dut.i_pub)
                i_h         = int(dut.i_h)
                i_res       = int(dut.i_res)
                i_Rx        = int(dut.i_Rx)
                i_Ax        = int(dut.i_Ax)
                i_At        = int(dut.i_At)
                i_Tx        = int(dut.i_Tx)
                i_Ty        = int(dut.i_Ty)
                i_Tz        = int(dut.i_Tz)
                i_Tt        = int(dut.i_Tt)

                A = (i_Ax, bits(int(dut.i_pub), 255, 0), 1, i_At)

                As = i_h
                Gs = i_sig_h

                Z = ed25519_lib.ed25519_dsdp_mul(A, As, Gs, W_S=DSDP_WS)

                q_self.append((
                    i_m,
                    i_sig_l,
                    i_res,
                    i_Rx,
                    Z[0],
                    Z[1],
                    Z[2],
                ))

        if str(dut.o_v) == '1':

            o_m = int(dut.o_m)

            (
                o_src,
                o_tid,
                o_sig_l,
                o_Zz,
                o_Zy,
                o_Zx,
                o_Rx,
                o_res,
            ) = extr_meta(meta6, o_m)

            if q_o != None:
                tr = q_o[o_tid]
                del q_o[o_tid]

                tr['time_4'] = get_cycle()
                ddut._log.info ('mon_ed25519_sigverify_1_o: tid.{:x} sz.{} err.{} {} {} {} {} {}'.format(
                    tr['tid'],
                    len(tr['msg_s']),
                    tr['err'],
                    tr['time_0'],
                    tr['time_1'],
                    tr['time_2'],
                    tr['time_3'],
                    tr['time_4'],
                ))

                (
                    e_src,
                    e_tid,
                    e_sig_l,
                    e_Zz,
                    e_Zy,
                    e_Zx,
                    e_Rx,
                    e_res,
                ) = build_ed25519_sigverify_1_o(tr)

                if do_log:
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_src   : \n{:x} =?= \n{:x}'.format(e_src,   o_src))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_tid   : \n{:x} =?= \n{:x}'.format(e_tid,   o_tid))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_sig_l : \n{:x} =?= \n{:x}'.format(e_sig_l, o_sig_l))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_Zx    : \n{:x} =?= \n{:x}'.format(e_Zx,    o_Zx))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_Zy    : \n{:x} =?= \n{:x}'.format(e_Zy,    o_Zy))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_Zz    : \n{:x} =?= \n{:x}'.format(e_Zz,    o_Zz))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_Rx    : \n{:x} =?= \n{:x}'.format(e_Rx,    o_Rx))
                    ddut._log.info ('mon_ed25519_sigverify_0_o: e_res   : \n{:x} =?= \n{:x}'.format(e_res,   o_res))

                assert e_src    == o_src
                assert e_tid    == o_tid
                assert e_sig_l  == o_sig_l
                assert e_Zz     == o_Zz
                assert e_Zy     == o_Zy
                assert e_Zx     == o_Zx
                assert e_Rx     == o_Rx
                assert e_res    == o_res













































































async def mon_ed25519_sigverify_2(ddut, dut, clk, q_i=None, q_o=None, do_log=False, self_test=False):

    while True:

        await RisingEdge(clk)

        if str(dut.o_v) == '1':

            o_m = int(dut.o_m)

            (
                o_src,
                o_tid,
                o_res,
            ) = extr_meta(meta7, o_m)

            if q_o != None:
                tr = q_o[o_tid]
                del q_o[o_tid]

                tr['time_5'] = get_cycle()
                print ('mon_ed25519_sigverify_2_o: tid.{:x} sz.{} err.{} {} {} {} {} {} {}'.format(
                    tr['tid'],
                    len(tr['msg_s']),
                    tr['err'],
                    tr['time_0'],
                    tr['time_1'],
                    tr['time_2'],
                    tr['time_3'],
                    tr['time_4'],
                    tr['time_5'],
                ))

                e_src = tr['src']
                e_tid = tr['tid']
                e_res = tr['sigverify']

                if do_log:
                    ddut._log.info ('mon_ed25519_sigverify_2_o: src:\n{:x} =?=\n{:x}'.format(e_src, o_src))
                    ddut._log.info ('mon_ed25519_sigverify_2_o: tid:\n{:x} =?=\n{:x}'.format(e_tid, o_tid))
                    ddut._log.info ('mon_ed25519_sigverify_2_o: res:\n{:x} =?=\n{:x}'.format(e_res, o_res))

                assert e_src == o_src
                assert e_tid == o_tid
                assert e_res == o_res

































































































async def mon_dma(ddut, dut, clk, q_o=None, do_log=False):

    while True:

        await RisingEdge(clk)

        if str(dut.dma_v) == '1' and str(dut.dma_r) == '1':

            ddut._log.info ('mon_dma_o')

            if q_o != None:

                tr = q_o.pop(0)

                o_a = int(dut.dma_a)
                o_b = int(dut.dma_b)
                o_d = int(dut.dma_d)

                e_a = bits(tr['dma_addr'], 64-6, 6) << 6
                e_b = 0xFFFFFFFF00000000 if bits(tr['dma_addr'], 1, 5) else 0x00000000FFFFFFFF
                e_ctrl = tr['dma_ctrl']
                e_ctrl |= (0 if tr['sigverify'] else 1) << 2

                e_d = 0
                e_d |= tr['dma_seq']                << (0)
                e_d |= bits(tr['sig_l'], 64, 0)     << (0+64)
                e_d |= tr['dma_chunk']              << (0+64+64)
                e_d |= tr['dma_size']               << (0+64+64+32)
                e_d |= e_ctrl                       << (0+64+64+32+16)

                if do_log:
                    ddut._log.info ('mon_dma: o_a: \n{:x} =?= \n{:x}'.format(e_a, o_a))
                    ddut._log.info ('mon_dma: o_b: \n{:x} =?= \n{:x}'.format(e_b, o_b))
                    ddut._log.info ('mon_dma: o_d: \n{:x} =?= \n{:x}'.format(e_d, o_d))

                assert e_a == o_a
                assert e_b == o_b
                assert e_d == o_d










































async def model_schl_cpu(ddut, dut, clk, do_log=False):

    D = 1024
    W_HASH = int(dut.W_HASH)
    W_T = int(dut.W_T)
    W_IN_MEM = int(dut.W_IN_MEM)
    MAX_INFLIGHT = int(dut.MAX_INFLIGHT)

    await cocotb.start(random_toggle(clk, dut.in_hash_ready, 50))

    ins = list()
    outs = list()

    dut.out_hash_valid.value = 0

    while True:
        await RisingEdge(clk)

        if str(dut.in_hash_valid) == '1' and str(dut.in_hash_ready) == '1':

            i_r = int(dut.in_hash_ref)
            i_d = int(dut.in_hash_data)

            ddut._log.info ('model_schl_cpu_i: {:x} {:x}'.format(i_r, i_d))

            ins.append(i_d)

            if len(ins) == 3:
                os = sigverify.ksigverify_split0(
                    ed25519_lib.Expr(ins.pop(0)),
                    ed25519_lib.Expr(ins.pop(0)),
                    ed25519_lib.Expr(ins.pop(0)),
                    ed25519_lib.Expr(ref_ed25519.d),
                    ed25519_lib.Expr(ref_ed25519.p),
                    ed25519_lib.Expr(ref_ed25519.q),
                )
                os = tuple(_.eval() for _ in os)

                outs.append((
                    get_cycle() + D,
                    i_r,
                    os,
                    0
                ))

        dut.out_hash_valid.value = 0

        for out in outs:
            if out[0] < get_cycle():

                (
                    _,
                    ref,
                    os,
                    oa,
                ) = out

                outs.remove(out)

                ddut._log.info ('model_schl_cpu_o: {:x} {:x} {:x}'.format(ref, oa, os[oa]))

                b_d = BinaryValue(bits=W_HASH, bigEndian=False)
                b_r = BinaryValue(bits=W_T, bigEndian=False)
                b_a = BinaryValue(bits=W_IN_MEM, bigEndian=False)

                b_d[W_HASH-1:0] = os[oa]
                b_r[W_T-1:0] = ref
                b_a[W_IN_MEM-1:0] = oa

                dut.out_hash_valid.value = 1
                dut.out_hash_data.value = b_d
                dut.out_ref.value = b_r
                dut.out_d_addr.value = b_a

                oa += 1

                if oa < len(os):
                    outs.append((
                        _ + MAX_INFLIGHT,
                        ref,
                        os,
                        oa
                    ))

                break
































async def model_dsdp(ddut, dut, clk, do_log=False):
    N_TH = int(dut.N_TH)
    W_M = int(dut.W_M)
    W_S = int(dut.W_S)

    await cocotb.start(random_toggle(clk, dut.i_r, 50))

    outs = list()

    while True:
        await RisingEdge(clk)

        if str(dut.i_v) == '1' and str(dut.i_r) == '1':

            i_m = int(dut.i_m)

            A = (
                int(dut.i_Ax),
                int(dut.i_Ay),
                int(dut.i_Az),
                int(dut.i_At),
            )

            As = int(dut.i_As)
            Gs = int(dut.i_Gs)

            Z = ed25519_lib.ed25519_dsdp_mul(A, As, Gs, W_S=W_S)

            outs.append((
                get_cycle() + (W_S * N_TH // 10),
                i_m,
                Z[0],
                Z[1],
                Z[2],
                Z[3],
            ))


        dut.o_v.value = 0

        for out in outs:
            if out[0] < get_cycle():

                (
                    _,
                    i_m,
                    Zx,
                    Zy,
                    Zz,
                    Zt,
                ) = out

                outs.remove(out)
        
                b_m = BinaryValue(bits=W_M, bigEndian=False)
                b_zx = BinaryValue(bits=255, bigEndian=False)
                b_zy = BinaryValue(bits=255, bigEndian=False)
                b_zz = BinaryValue(bits=255, bigEndian=False)
                b_zt = BinaryValue(bits=255, bigEndian=False)

                b_m[W_M-1:0] = i_m
                b_zx[255-1:0] = Zx
                b_zy[255-1:0] = Zy
                b_zz[255-1:0] = Zz
                b_zt[255-1:0] = Zt

                dut.o_v.value = 1
                dut.o_m.value = b_m
                dut.o_Cx.value = b_zx
                dut.o_Cy.value = b_zy
                dut.o_Cz.value = b_zz
                dut.o_Ct.value = b_zt

                break
