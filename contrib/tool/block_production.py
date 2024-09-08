from solders.message import Message
from solders.keypair import Keypair
# from solders.instruction import Instruction
# from solders.hash import Hash
from solana.transaction import Transaction
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey

import datetime
import sys
import socket
import time
import tqdm
import itertools
from multiprocessing import Pool, TimeoutError
from functools import partial
from pqdm.processes import pqdm

from solana.rpc.api import Client
import random

def usage():
  print("contrib/tool/block_production.py <rpc_url> <pubkey> <n>")
  exit(1)

def main():
  if len(sys.argv) < 4:
    usage()
  
  client = Client(sys.argv[1])
  pubkey = Pubkey.from_string(sys.argv[2])
  slot_cnt = int(sys.argv[3])

  epoch_info = client.get_epoch_info().value
  leader_schedule = client.get_leader_schedule(epoch_info.absolute_slot)
  leader_slot_idxs = leader_schedule.value[pubkey]
  upcoming_slot_idxs = list(filter(lambda s: s > epoch_info.slot_index, leader_slot_idxs))[:4*slot_cnt]
  epoch_start_slot = epoch_info.absolute_slot-epoch_info.slot_index

  prev_slot = epoch_info.absolute_slot
  for slot_idx in upcoming_slot_idxs:
    slot = epoch_start_slot+slot_idx
    rel = slot-prev_slot
    if prev_slot+1==slot:
      prev_slot = slot  
      continue
    dist = slot-epoch_info.absolute_slot
    prev_slot = slot
    rel_td = datetime.timedelta(milliseconds=rel*400)
    dist_td = datetime.timedelta(milliseconds=dist*400)
    print("slot: {:<10}| rel: {:>8}| dist: {:>8}| time(s): {:<16} ({})".format(slot, rel, dist, str(dist_td), str(rel_td)))


if __name__ == '__main__':
  main()