import argparse
import logging
import json
import time
import random
import socket
import math
import multiprocessing
import threading
from functools import partial
from typing import List
from multiprocessing.sharedctypes import SynchronizedBase
from multiprocessing.synchronize import Event

import tqdm
from pqdm.processes import pqdm

from solana.transaction import Transaction

from solana.rpc.api import Client
from solana.rpc.commitment import Commitment
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer

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
  args = parser.parse_args()
  return args

def send_round_of_txs(txs, sock, tpus):
    for tx in tqdm.tqdm(txs, desc="send"):
        message = bytes(tx.to_solders())
        for tpu in tpus:
            sock.sendto(message, tpu)

def create_accounts_tx(funder, lamports, recent_blockhash, accs):
    tx = Transaction(recent_blockhash, None, funder.pubkey(), [])
    for acc in accs:
        tx = tx.add(transfer(TransferParams(from_pubkey=funder.pubkey(), to_pubkey=acc.pubkey(), lamports=lamports)))
    tx.sign(funder)
    return tx
    # client.send_transaction(tx, funder, opts=TxOpts(skip_confirmation=True))

def get_balance(lamports, client: Client, acc):
    bal = client.get_balance(acc.pubkey(), commitment="confirmed").value
    if bal >= lamports:
        return acc
    else:
        return None

def create_accounts(funder, client: Client, num_accs, lamports, seed, sock, tpus):
    accs = []
    for i in tqdm.trange(num_accs, desc="keypairs"):
        acc = Keypair.from_seed_and_derivation_path(seed, f"m/44'/42'/0'/{i}'")
        accs.append(acc)
    remaining_accs = set(accs)

    # while len(remaining_accs) > 0:
    #     done_accs = pqdm(remaining_accs, partial(get_balance, lamports, client), desc="check bal", n_jobs=32)

    #     for acc in done_accs:
    #         if acc is not None:
    #             remaining_accs.remove(acc)
    #     print(len(remaining_accs))
    #     if len(remaining_accs) == 0:
    #         break
    #     chunk_size = 8
    #     rem_accs_list = list(remaining_accs)
    #     acc_chunks = [rem_accs_list[i:i+chunk_size] for i in range(0, len(rem_accs_list), chunk_size) ]
    #     recent_blockhash = client.get_latest_blockhash().value.blockhash
    #     txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash), desc="fund accounts", n_jobs=32)
    #     send_round_of_txs(txs, sock, tpus)
    #     time.sleep(1)

    return accs

def gen_tx(recent_blockhash, key, acc):
  tx = Transaction(recent_blockhash, None, acc, [])
  tx.sign(key)
  return tx

def send_txs(client: Client, tpus: List[str], keys: List[Keypair], tx_idx):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  accs = [key.pubkey() for key in keys]
  recent_blockhash = client.get_latest_blockhash().value.blockhash
  prev_recent_blockhash = recent_blockhash
  while True:
    recent_blockhash = client.get_latest_blockhash().value.blockhash
    if recent_blockhash == prev_recent_blockhash:
       time.sleep(0.01)
       continue
    prev_recent_blockhash = recent_blockhash
    for i in range(len(keys)):
      with tx_idx.get_lock():
        tx_idx.value += 1
      tx = gen_tx(recent_blockhash, keys[i], accs[i])
      message = bytes(tx.to_solders())
      for tpu in tpus:
        sock.sendto(message, tpu)


def monitor_send_tps(tx_idx: int, interval: int = 1) -> None:
    prev_count = 0
    while interval < 10:
        time.sleep(interval)
        with tx_idx.get_lock():
            current_count = tx_idx.value
        tps = (current_count - prev_count) / interval
        prev_count = current_count
        print(f"tps={tps}")
        if tps == 0:
            interval += 1

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
  accs = create_accounts(funder, client, args.nkeys, 10_000_000, seed, sock, tpus)
  
  chunk_size = math.ceil(len(accs)/args.workers)
  acc_chunks = [accs[i:i+chunk_size] for i in range(0, len(accs), chunk_size)]

  tx_idx = multiprocessing.Value("i", 0)
  monitor_thread = threading.Thread(target=monitor_send_tps, args=(tx_idx,))
  monitor_thread.start()

  workers = []
  for i in range(args.workers):
    worker_process = multiprocessing.Process(
        target=send_txs,
        name=f"worker{i}",
        args=(
            client,
            tpus,
            acc_chunks[i],
            tx_idx
        ),
    )
    workers.append(worker_process)
    worker_process.start()

  for worker in workers:
    worker.join()

if __name__ == "__main__":
  main()