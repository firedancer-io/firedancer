import cocotb
import os
import copy
import sys
import struct 

import hashlib
import random

from cocotb.clock import Clock
from cocotb.triggers import Timer, RisingEdge, ReadOnly
from cocotb.regression import TestFactory
from cocotb.binary import BinaryValue

import ref_ed25519
from ref_ed25519 import point_decompress
from ed25519_lib import Expr

sent_in   = []

def FAIL( ):
  assert False

def clamp(val):
  return int(val) & ((1<<256)-1)

def getTern(val):
  return int(val >> 28)

def getOP(val):
  return int(val >> 24 & 0xF)

def getMemAAddr(val):
  return int(val >> 18 & 0x3F)

def getMemBAddr(val):
  return int(val >> 12 & 0x3F)

def getMemTAddr(val):
  return int(val >> 6 & 0x3F)

def getMemOAddr(val):
  return int(val & 0x3F)

def scratch_offset(tag):
  a = [0x000, 0x018, 0x030, 0x048, 0x060, 0x078, 0x090, 0x0A8, 0x0C0, 0x0D8, 0x0F0, 0x108, 0x120, 0x138, 0x150, 0x168,
       0x180, 0x198, 0x1B0, 0x1C8, 0x1E0, 0x1F8, 0x210, 0x228, 0x240, 0x258, 0x270, 0x288, 0x2A0, 0x2B8, 0x2D0, 0x2E8]
  return a[tag] 

def get_const(addr):
  const = [
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
            0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3,
            0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3,
            0x6666666666666666666666666666666666666666666666666666666666666658,
            0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a,
            0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0,
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec,
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
            0x00000000000000000000000000000000000000000000000000000000000000ff ]
  # print("LOOKUP: {}".format(addr))
  return const[addr]

def evalOp(op, valA, valB, valT):
  if (op == 0):  return clamp(valA & valB )
  if (op == 1):  return clamp(valA == valB)
  if (op == 2):  return clamp(valA != valB)
  if (op == 3):  return clamp(valA >= valB)
  if (op == 4):  return clamp(valA << 1)
  if (op == 5):  return clamp((valA >> 255) & 0x1)
  if (op == 6):  return clamp(valA + valB )
  if (op == 7):  return clamp(valA - valB )
  if (op == 8):  return clamp( (valA + valB) % ref_ed25519.p )
  if (op == 9):  return clamp( (valA - valB) % ref_ed25519.p )
  if (op == 10): return clamp( (valA * valB) % ref_ed25519.p )
  if (op == 11):
    if( valT ): return valA
    else:       return valB
  if (op == 12):
    return 0
  return 0

class MathMonitor:

  def __init__(self, dut):
    self.dut = dut
    self.total_tags = int(self.dut.cpu0.NUM_TAGS)
    self.mem = {}
    self.verbose = True
    for i in range(0x3FF):
      self.mem[i] = 0
    for i in range(12):
      self.setMem(0, i+0x04, get_const(i))
    
  def check( self, tag, errstr, expected, observed  ):
    if( int(expected) == int(observed) ): 
      #print("SUCCESS! [{}]".format(errstr))
      return
    self.dut._log.info("[{}] FAILED! {}- exp: {:X} vs obs: {:X}".format(tag, errstr, expected, observed))
    FAIL()

  def setIn(self, tag, addr, val):
    wr_addr = self.getPhyAddr(tag, addr)
    self.mem[wr_addr] = val
    if self.verbose: self.dut._log.info("[{}] Writing Input to Mem [{:X}] = {:X}".format(tag, wr_addr, val))


  def setMem(self, tag, addr, val):
    wr_addr = self.getPhyAddr(tag, addr)
    self.mem[wr_addr] = int(val)
    if self.verbose: self.dut._log.info("[{}] Writing to Mem [{:X}] = {:X}".format(tag, wr_addr, val))

  def getPhyAddr(self, tag, addr):
    if   (addr == 0x00): return int(tag + 0x000)
    elif (addr == 0x01): return int(tag + 0x020)
    elif (addr == 0x02): return int(tag + 0x040)
    elif (addr == 0x03): return int(tag + 0x060)
    elif (addr >= 0x04 and addr <= 0x23 ): return int(0x080 + addr - 0x04)
    else: return int(0x0A0 + scratch_offset(tag) + addr - 0x24)

  def getMem(self, tag, addr):
    rd_addr = self.getPhyAddr(tag, addr)
    res = self.mem[ rd_addr ]
    if self.verbose: self.dut._log.info("[{}] Reading from Mem [{:X}] = {:X}".format(tag, rd_addr, res))
    return res

  async def run(self):
    next_tag = 0
    init_vals = 0
    instr   = []
    addrA   = []
    addrB   = []
    addrT   = []
    valA    = []
    valB    = []
    valT    = []
    addrO   = []
    expRslt = []
    resultChecked = []
    for _ in range(self.total_tags):
      instr.append(0)
      addrA.append(0)
      addrB.append(0)
      addrT.append(0)
      valA.append(0)
      valB.append(0)
      valT.append(0)
      addrO.append(0)
      expRslt.append(0)
      resultChecked.append(False)
    while True:
      inserted = False
      await RisingEdge(self.dut.clk)
      for t in range(self.total_tags):
        cpu = self.dut.cpu0
        state = int(cpu.curr_state[t])
        if (int(cpu.calc_next) == t and state == 1 and int(cpu.in_hash_valid) == 1 and not inserted):
          self.setIn( int(cpu.calc_next), init_vals, int(cpu.in_hash_data) )
          inserted = True
          if init_vals == 2: 
            init_vals = 0
            if (next_tag == 31):
              next_tag = 0
            else:
              next_tag += 1
          else:
            init_vals += 1
        if (state == 3): # SEND0
          resultChecked[t] = False
          instr[t] = int(cpu.next_instr[t])
          addrA[t] = getMemAAddr(instr[t])
          addrB[t] = getMemBAddr(instr[t])
          addrT[t] = getMemTAddr(instr[t])
          addrO[t] = getMemOAddr(instr[t])
          valA[t] = self.getMem(t, addrA[t])
          valB[t] = self.getMem(t, addrB[t])
          valT[t] = self.getMem(t, addrT[t])
          valT[t] = valT[t] & 0x1
          expRslt[t] = evalOp(getOP(instr[t]), valA[t], valB[t], valT[t])
          if self.verbose: self.dut._log.info("[{}] EXPECTED: A[{:X}:{:X}] OP: {} B[{:X}:{:X}] T[{:X}:{:X}] OUT:{:X}".format(t, addrA[t], valA[t], getOP(instr[t]), addrB[t], valB[t], addrT[t], valT[t], expRslt[t]))
        if (state == 5): # BLOCK
          if int(cpu.mem_man_tag) == t and int(cpu.block_valid[t]) == 1 and not resultChecked[t]: 
            if getOP(instr[t]) != 12:
              self.check(t, "Result", expRslt[t], int(cpu.mem_man_data))
              self.check(t, "OutAddr", self.getPhyAddr(t, addrO[t]), int(cpu.mem_man_addr))
              self.setMem(t, getMemOAddr(instr[t]), expRslt[t])
            resultChecked[t] = True
            # print("Out Addr- a: {:X} vs e: {:X}".format(, ))

class OutMonitor:
  def __init__(self, dut):
    self.dut = dut
    self.done = False

  async def is_done(self):
    while not self.done:
      await RisingEdge(self.dut.clk)

  async def run(self, total=3):
    tic   = 0
    start = 0
    self.in_vals  = []
    self.out_vals = []
    self.expected = []

    self.inout_match = {} 
    start = []
    i_cnt = 0

    while True:
      await RisingEdge(self.dut.clk)
      tic += 1
      if (int(self.dut.i_valid) == 1):
        if (i_cnt == 0):
          in_val = int(self.dut.i_hash)
          self.in_vals.append(in_val)
          start.append(tic)

        if (i_cnt == 2): i_cnt = 0
        else:            i_cnt += 1

      if (int(self.dut.o_valid) == 1):
        self.out_vals.append(int(self.dut.o_hash))
        t = len(self.out_vals)-1
        u = int(t/8)

        self.dut._log.info("RESULT Output: [{}/{}] {:x}".format( len(self.out_vals), (total*8), self.out_vals[t] ) )
        self.dut._log.info("-- start tic: {}".format(start[u]))
        self.dut._log.info("-- stop tick: {}".format(tic))
        self.dut._log.info("-- elapsed:   {}ns".format( ((tic-start[u])*4)))
      if len(self.out_vals) >= total*8: break #8 outs per input set
    self.done = True

async def send_rand_input(dut, i=0):
  #in_vals = ( (random.getrandbits(int(dut.W_HASH)) % p), (random.getrandbits(int(dut.W_HASH)) % p), (random.getrandbits(int(dut.W_HASH)) % p), (random.getrandbits(int(dut.W_HASH)) % p ))
  from ref_ed25519 import p

  in_tmp = [0xf94f19db1a86d8574bc885068848db78a886b6a96537c1b442e8b9402c4a341d,
            0xc9e8131bf9cf7c67479f7589949c8241be3581537f9724b611464bcbe2b1f30b,
            0x013e4a41676acaed06ac560dfe46283e77a1ccbc919cb8a08ddbd36134ad9a4d, ]
  in_vals = ( in_tmp[0], in_tmp[1], in_tmp[2])

  total = 3
  i=0
  while i < total:
    if int(dut.i_ready) == 1:
      dut.i_hash  .value = in_vals[i]
      dut.i_valid .value = 1
      i+=1
    else:
      dut.i_hash  .value = 0
      dut.i_valid .value = 0
    await RisingEdge(dut.clk)
  dut.i_hash  .value = 0
  dut.i_valid .value = 0

  sent_in.append( in_vals )

@cocotb.test()
async def run_test(dut):
  num_sent   = 0
  num_inputs = 64

  om = OutMonitor(dut)
  im = MathMonitor(dut)
  await cocotb.start(Clock(dut.clk, 4000).start())
  await cocotb.start(om.run(num_inputs))
  await cocotb.start(im.run())
  dut.i_hash  .value = 0
  dut.i_valid .value = 0
  await RisingEdge(dut.clk)
  dut.rst .value = 1
  await RisingEdge(dut.clk)
  await RisingEdge(dut.clk)
  dut.rst .value = 0
  await RisingEdge(dut.clk)
  while( int(dut.i_ready) == 0):
    await RisingEdge(dut.clk)

  # allow DSPs to warm up
  for _ in range(2048):
    await RisingEdge(dut.clk)


  while num_sent < num_inputs:
    if ( int(dut.i_ready) == 1 ):
      await send_rand_input(dut, num_sent)
      num_sent += 1 
      for _ in range(random.randint(0,10)):
        await RisingEdge(dut.clk)
    else:
      await RisingEdge(dut.clk)
    
  await RisingEdge(dut.clk)
  dut.i_hash  .value = 0
  dut.i_valid .value = 0
  for _ in range(100):
    await RisingEdge(dut.clk)

  await om.is_done()

  await RisingEdge(dut.clk)
