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
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer, create_account, CreateAccountParams
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.message import Message

from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT, MULTISIG_LAYOUT  # type: ignore
from spl.token.instructions import initialize_mint, get_associated_token_address, create_associated_token_account, InitializeMintParams, mint_to, MintToParams, decode_initialize_mint
from spl.token.instructions import transfer as spl_transfer
from spl.token.instructions import TransferParams as SplTransferParams


TXN_TYPE_EMPTY = 0
TXN_TYPE_SYSTEM_TRANSFER = 1
TXN_TYPE_TOKEN_TRANSFER = 2

seed_file = open("../test-ledger/faucet-keypair.json", "r")
top_seed = bytes(json.load(seed_file))
fd_mint = Keypair.from_seed_and_derivation_path(top_seed, f"m/44'/45'/30'/99999'")
print("fd mint address: " + str(fd_mint.pubkey()))

def get_recent_blockhash(rpc: str) -> Hash:
  data="{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getLatestBlockhash\",\"params\":[{\"commitment\":\"processed\"}]}"
  resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
  return Hash.from_string(resp.json()["result"]["value"]["blockhash"])

def get_balance(rpc: str, acc: Pubkey) -> int:
  try:
    acc_str = str(acc)
    data = f"{{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getBalance\",\"params\":[\"{acc_str}\",{{\"commitment\":\"confirmed\"}}]}}"
    resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
    if resp.status_code != 200:
      return 0
    else:
      return resp.json()["result"]["value"]
  except:
    return 0
  
def get_account_info(rpc: str, acc: str):
    data = f"{{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getAccountInfo\",\"params\":[\"{acc}\",{{\"commitment\":\"confirmed\",\"encoding\":\"base58\"}}]}}"
    resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
    if resp.status_code != 200:
        return 0
    elif resp.json()["result"]["value"] is None:
        print(resp.json())
        return 0
    else:
        print(resp.json())
        return 1

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

def send_round_of_txs(txs: List[Transaction], sock, tpus):
    for tx in tqdm.tqdm(txs, desc="send"):
        message = bytes(tx.to_solders())
        for tpu in tpus:
            sock.sendto(message, tpu)
        time.sleep(0.001)

def fund_token_account(funder, lamports, recent_blockhash, is_print, range ):
    tx = Transaction(recent_blockhash, None, funder.pubkey(),[set_compute_unit_price(3), set_compute_unit_limit(300_000)])
    tx = tx.add(create_account(CreateAccountParams(from_pubkey=funder.pubkey(), to_pubkey=fd_mint.pubkey(), 
                                                   lamports=lamports+range, space=MINT_LAYOUT.sizeof(), owner=TOKEN_PROGRAM_ID)))

    params = InitializeMintParams(
        decimals=9,
        mint=fd_mint.pubkey(),
        mint_authority=funder.pubkey(),
        program_id=TOKEN_PROGRAM_ID
    )
    tx = tx.add(initialize_mint( params ))
    tx.sign(funder, fd_mint ) 

    return tx


def create_accounts_tx(funder, lamports, recent_blockhash, accs):
    tx = Transaction(recent_blockhash, None, funder.pubkey(), [set_compute_unit_price(3), set_compute_unit_limit(300_000)])
    for acc in accs:
        associated_token_address = get_associated_token_address(acc.pubkey(), fd_mint.pubkey())

        tx = tx.add(transfer(TransferParams(from_pubkey=funder.pubkey(), to_pubkey=acc.pubkey(), lamports=lamports)))
        tx = tx.add(create_associated_token_account(payer=funder.pubkey(), owner=acc.pubkey(), mint=fd_mint.pubkey()))

    tx.sign(funder) 
    return tx

def mint_to_tx(funder, lamports, recent_blockhash, accs):
    tx = Transaction(recent_blockhash, None, funder.pubkey(), [set_compute_unit_price(3), set_compute_unit_limit(300_000)])
    for acc in accs:
        ata = get_associated_token_address(acc.pubkey(), fd_mint.pubkey())
        tx = tx.add( mint_to( MintToParams( mint=fd_mint.pubkey(), 
                                            dest=ata, 
                                            mint_authority=funder.pubkey(), 
                                            amount=100,
                                            program_id=TOKEN_PROGRAM_ID, 
                                            signers=[funder.pubkey()] ) ) )


    tx.sign(funder) 
    return tx




def get_balance_sufficient(lamports, rpc: str, acc):
    bal = get_balance(rpc, acc.pubkey())
    if bal:
        print( bal)

    ata = get_associated_token_address(acc.pubkey(), fd_mint.pubkey())
    ata_bal = get_balance(rpc, ata)

    if bal >= lamports:# and ata_bal >= lamports:
        return acc
    return None

def create_accounts(funder, rpc, num_accs, lamports, seed, sock, tpus, txn_type):
    get_account_info(rpc, fd_mint.pubkey())
    print(get_balance( rpc, Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")))

    accs = []
    for i in tqdm.trange(num_accs, desc="keypairs"):
        acc = Keypair.from_seed_and_derivation_path(seed, f"m/44'/75'/352'/{i}'")
        accs.append(acc)
    remaining_accs = set(accs)

    chunk_size = 8
    rem_accs_list = list(remaining_accs)
    acc_chunks = [rem_accs_list[i:i+chunk_size] for i in range(0, len(rem_accs_list), chunk_size) ]

    recent_blockhash = get_recent_blockhash(rpc)
    txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash), desc="fund accounts", n_jobs=32)
    send_round_of_txs(txs, sock, tpus)

    # fund_token_account( funder, lamports, get_recent_blockhash(rpc), 1, 0 )

    if not get_account_info(rpc, fd_mint.pubkey()):
        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm([i for i in range(2000)], partial(fund_token_account, funder, lamports, recent_blockhash, 0), desc="fund token", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

    while len(remaining_accs) > 0:
        get_account_info(rpc, fd_mint.pubkey())

        done_accs = pqdm(remaining_accs, partial(get_balance_sufficient, 10, rpc), desc="check bal", n_jobs=32)

        for acc in done_accs:
            if acc is not None:
                remaining_accs.remove(acc)
        print(len(remaining_accs))
        if len(remaining_accs) == 0:
            break
        chunk_size = 4
        rem_accs_list = list(remaining_accs)
        acc_chunks = [rem_accs_list[i:i+chunk_size] for i in range(0, len(rem_accs_list), chunk_size) ]

        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash), desc="fund accounts", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

        if not get_account_info(rpc, fd_mint.pubkey()):
            recent_blockhash = get_recent_blockhash(rpc)
            txs = pqdm([i for i in range(2000)], partial(fund_token_account, funder, lamports, recent_blockhash, 0), desc="fund token", n_jobs=32)
            send_round_of_txs(txs, sock, tpus)

        time.sleep(5)

    print(str(accs[0].pubkey()))
    print(accs[0].pubkey())
    get_account_info(rpc, fd_mint.pubkey())
    

    print("DONE WITH PREVIOUS ********************")
    # Mint to a bunch of times
    #mint_to_tx(funder, lamports, get_recent_blockhash(rpc), accs[:5])

    for _ in range(30):
        break
        chunk_size = 4
        acc_chunks = [accs[i:i+chunk_size] for i in range(0, len(accs), chunk_size) ]
        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm(acc_chunks, partial(mint_to_tx, funder, lamports, recent_blockhash), desc="mint to", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

    print("*****************************")
    return accs

def gen_tx_empty(recent_blockhash, key, acc, cu_price):
  tx = Transaction(recent_blockhash, None, acc, [set_compute_unit_price(cu_price), set_compute_unit_limit(300)] )
  tx.sign(key)
  return tx

def gen_tx_system_transfer(recent_blockhash, key, acc, cu_price):
  tx = Transaction(recent_blockhash, None, acc, [set_compute_unit_price(cu_price), set_compute_unit_limit(300+300+150)] )
  tx = tx.add( transfer(TransferParams(from_pubkey=acc,to_pubkey=acc,lamports=1)) )

  tx.sign(key)
  return tx

def gen_tx_token_transfer(recent_blockhash, key, acc, cu_price):
  tx = Transaction(recent_blockhash, None, acc, [set_compute_unit_price(cu_price), set_compute_unit_limit(10_000)] )
  ata = get_associated_token_address(key.pubkey(), fd_mint.pubkey())
  params = SplTransferParams( program_id=TOKEN_PROGRAM_ID,
                              source=ata,
                              dest=ata, 
                              owner=key.pubkey(),
                              amount=1 )
  tx = tx.add( spl_transfer(params) )
  #tx = tx.add( transfer(TransferParams(from_pubkey=acc,to_pubkey=acc,lamports=1)) )

  tx.sign(key)
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
        tx = gen_tx_token_transfer(recent_blockhash, keys[i], accs[i], cu_price)
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

  accs = create_accounts(funder, args.rpc, args.nkeys, 100_000_000, seed, sock, tpus, txn_type)
  #create_token(funder, sock, tpus, args.rpc)

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