import argparse
import logging
import json
import time
import random
import socket
import math
import multiprocessing
import threading
import requests
from functools import partial
from typing import List
from multiprocessing.sharedctypes import SynchronizedBase
from multiprocessing import Event, Value, Array

import tqdm
from pqdm.processes import pqdm

from solana.transaction import Transaction

from solana.rpc.api import Client
from solders.hash import Hash
from solana.rpc.commitment import Commitment
from solana.rpc.types import TxOpts
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.message import Message

TXN_TYPE_EMPTY = 0
TXN_TYPE_SYSTEM_TRANSFER = 1
TXN_TYPE_TOKEN_TRANSFER = 2

def get_recent_blockhash(rpc: str) -> Hash:
  data="{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getLatestBlockhash\",\"params\":[]}"
  resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
  return Hash.from_string(resp.json()["result"]["value"]["blockhash"])

def get_balance(rpc: str, acc: Pubkey) -> int:
  for i in range(10):
    try:
      acc_str = str(acc)
      data = f"{{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getBalance\",\"params\":[\"{acc_str}\",{{\"commitment\":\"confirmed\"}}]}}"
      resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
      if resp.status_code != 200:
        return 0
      else:
        return resp.json()["result"]["value"]
    except:
      time.sleep(0.1)
      continue
  return 0

def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser()
  parser.add_argument(
    "-t",
    "--tpus",
    required=True,
    type=str,
    nargs='+',
    help="TPU UDP endpoints to send transactions to",
  )
  parser.add_argument(
    "-r",
    "--rpc",
    required=True,
    type=str
  )
  parser.add_argument(
    "-n",
    "--nkeys",
    required=True,
    type=int
  )
  parser.add_argument(
    "-s",
    "--seed",
    required=True,
    type=str,
  )
  parser.add_argument(
    "-f",
    "--funder",
    required=True,
    type=str,
  )
  parser.add_argument(
    "-w",
    "--workers",
    required=True,
    type=int,
  )
  parser.add_argument(
    "-x",
    "--txn-type",
    required=True,
    type=str
  )
  args = parser.parse_args()
  return args

def send_round_of_txs(txs, sock, tpus, rpc, funder):
    client = Client(rpc)
    for tx in tqdm.tqdm(txs, desc="send"):
        message = bytes(tx.to_solders())
        #client.send_raw_transaction(message, opts=TxOpts(skip_confirmation=True))
        for tpu in tpus:
          sock.sendto(message, tpu)
        time.sleep(0.001)

def create_accounts_tx(funder, lamports, recent_blockhash, accs):
    tx = Transaction(recent_blockhash, None, funder.pubkey(), [])
    tx.add(set_compute_unit_price(1))
    for acc in accs:
        tx = tx.add(transfer(TransferParams(from_pubkey=funder.pubkey(), to_pubkey=acc.pubkey(), lamports=lamports)))
    tx.sign(funder)
    return tx
    # client.send_transaction(tx, funder, opts=TxOpts(skip_confirmation=True))

def get_balance_sufficient(lamports, rpc: str, acc):
    bal = get_balance(rpc, acc.pubkey())
    if bal >= lamports:
        return acc
    else:
        return None

def create_accounts(funder, rpc, num_accs, lamports, seed, sock, tpus, txn_type):
    accs = []
    for i in tqdm.trange(num_accs, desc="keypairs"):
        acc = Keypair.from_seed_and_derivation_path(seed, f"m/44'/42'/0'/{i}'")
        accs.append(acc)
    remaining_accs = set(accs)       

    while len(remaining_accs) > 0:
        done_accs = pqdm(remaining_accs, partial(get_balance_sufficient, lamports, rpc), desc="check bal", n_jobs=256)
        for acc in done_accs:
            if acc is not None:
                remaining_accs.remove(acc)
        print(len(remaining_accs))
        if len(remaining_accs) == 0:
            break
        chunk_size = 8
        rem_accs_list = list(remaining_accs)
        acc_chunks = [rem_accs_list[i:i+chunk_size] for i in range(0, len(rem_accs_list), chunk_size) ]
        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash), desc="fund accounts", n_jobs=256)
        #send_round_of_txs(txs, sock, tpus, rpc, funder)
        send_round_of_txs(txs, sock, tpus, rpc, funder)
    return accs

def gen_tx_empty(recent_blockhash, key, acc, cu_price):
  #msg = Message.new_with_blockhash([set_compute_unit_price(cu_price), set_compute_unit_limit(300)], acc, recent_blockhash)
  tx = Transaction(recent_blockhash, None, acc, [set_compute_unit_price(cu_price), set_compute_unit_limit(300)])
  tx.sign(key)
  #tx = Transaction.populate(msg, [Signature(random.randbytes(64))])
  # tx.populate()
  return tx

def gen_tx_system_transfer(recent_blockhash, key, acc, cu_price):
  msg = Message.new_with_blockhash([set_compute_unit_price(cu_price), set_compute_unit_limit(300+300+150), 
                                    transfer(TransferParams(from_pubkey=acc,to_pubkey=acc,lamports=1))], acc, recent_blockhash)
  # tx = Transaction(recent_blockhash, None, acc, )
  tx = Transaction.populate(msg, [Signature(random.randbytes(64))])
  # tx.populate()
  return tx

def send_txs(rpc: str, tpus: List[str], keys: List[Keypair], tx_idx, mult, idx, stop_event, rbh, txn_type: int):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  accs = [key.pubkey() for key in keys]
  recent_blockhash = Hash.from_bytes(rbh)
  prev_recent_blockhash = recent_blockhash
  cu_price = 1
  while not stop_event.is_set():
    recent_blockhash = Hash.from_bytes(rbh)
    if recent_blockhash == prev_recent_blockhash:
      cu_price += 1
    else:
      print("new rbh:", cu_price)
      cu_price = 1
    prev_recent_blockhash = recent_blockhash
    x = -time.time()
    for i in range(len(keys)):
      if txn_type == TXN_TYPE_EMPTY:
        tx = gen_tx_empty(recent_blockhash, keys[i], accs[i], cu_price)
      elif txn_type == TXN_TYPE_SYSTEM_TRANSFER:
        tx = gen_tx_system_transfer(recent_blockhash, keys[i], accs[i], cu_price)
      elif txn_type == TXN_TYPE_TOKEN_TRANSFER:
        tx = gen_tx_system_transfer(recent_blockhash, keys[i], accs[i], cu_price)
      message = bytes(tx.to_solders())
      for tpu in tpus:
        sock.sendto(message, tpu)
    with tx_idx.get_lock():
      tx_idx.value += len(keys)
    x+=time.time()
  print("stopping:", idx)

def monitor_send_tps(tx_idx, stop_event, interval: int = 1) -> None:
    prev_count = 0
    prev_time = time.time()
    while interval < 10 and not stop_event.is_set():
        time.sleep(interval)
        with tx_idx.get_lock():
            current_count = tx_idx.value
        curr_time = time.time()
        tps = (current_count - prev_count) / interval
        prev_count = current_count
        elapsed = curr_time - prev_time
        print(f"tps={tps} elapsed={elapsed}")
        if tps == 0:
            interval += 1
        prev_time = curr_time

def fetch_recent_blockhash(rbh, rpc, stop_event) -> None:
  prev_recent_blockhash = get_recent_blockhash(rpc)
  while not stop_event.is_set():
    time.sleep(0.1)
    try:
      recent_blockhash = get_recent_blockhash(rpc)
      if recent_blockhash == prev_recent_blockhash:
        continue
      rbh[:] = bytes(recent_blockhash)
      prev_recent_blockhash = recent_blockhash
      print(recent_blockhash)
    except:
      print("bad RBH")
  

def main():
  args = parse_args()
  client = Client(args.rpc)
  seed_file = open(args.seed, "r")
  seed = bytes(json.load(seed_file))
  funder_file = open(args.funder, "r")
  funder_key_raw = bytes(json.load(funder_file))
  funder = Keypair.from_bytes(funder_key_raw)
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  tpus = map(lambda t: t.split(":", 1), args.tpus)
  tpus = list(map(lambda t: (t[0], int(t[1])), tpus))
  print(tpus)
  
  if args.txn_type == "empty":
    txn_type = TXN_TYPE_EMPTY
  elif args.txn_type == "system-transfer":
    txn_type = TXN_TYPE_SYSTEM_TRANSFER
  elif args.txn_type == "token-transfer":
    txn_type = TXN_TYPE_TOKEN_TRANSFER
  else:
    print("unknown txn type")
    exit(1)

  accs = create_accounts(funder, args.rpc, args.nkeys, 10_000_000, seed, sock, tpus, txn_type)

  chunk_size = math.ceil(len(accs)/args.workers)
  acc_chunks = [accs[i:i+chunk_size] for i in range(0, len(accs), chunk_size)]

  rbh = Array('B', 32)
  stop_event = Event()
  tx_idx = multiprocessing.Value("i", 0)
  monitor_thread = threading.Thread(target=monitor_send_tps, args=(tx_idx, stop_event))
  monitor_thread.start()
  fetch_thread = threading.Thread(target=fetch_recent_blockhash, args=(rbh, args.rpc, stop_event))
  fetch_thread.start()

  workers = []
  for i in range(args.workers):
    worker_process = multiprocessing.Process(
        target=send_txs,
        name=f"worker{i}",
        args=(
            args.rpc,
            tpus,
            acc_chunks[i],
            tx_idx,
            128,
            i,
            stop_event,
            rbh,
            txn_type,
        ),
    )
    workers.append(worker_process)
    worker_process.start()

  try:
    while True:
      time.sleep(0.1)
  finally:
    stop_event.set()

  for worker in workers:
    worker.join()

if __name__ == "__main__":
  main()