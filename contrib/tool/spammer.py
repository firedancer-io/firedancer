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
from solders.instruction import AccountMeta, Instruction
from solders.system_program import ID as SYS_PROGRAM_ID

from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT, MULTISIG_LAYOUT  # type: ignore
from spl.token.instructions import initialize_mint, get_associated_token_address, create_associated_token_account, InitializeMintParams, mint_to, MintToParams
from spl.token.instructions import transfer as spl_transfer
from spl.token.instructions import TransferParams as SplTransferParams
from solders.rent import Rent;
from solana.rpc.types import TxOpts


TXN_TYPE_EMPTY               = 0
TXN_TYPE_SYSTEM_TRANSFER     = 1
TXN_TYPE_TOKEN_TRANSFER      = 2
TXN_TYPE_NANO_TOKEN_TRANSFER = 3

NANO_TOKEN_ID            = Pubkey.from_string("GjyKyRCSygSaszrjJFu43jkAshFc1sWs45HqKEDXhvwx")

seed_file = open("../keygrinds/bench-tps.json", "r")
top_seed = bytes(json.load(seed_file))
fd_mint = Keypair.from_seed_and_derivation_path(top_seed, f"m/44'/45'/30'/9999'")
print("fd mint address: " + str(fd_mint.pubkey()))
config_acc = Keypair.from_bytes(bytes(json.load(open("../keygrinds/config.json", "r"))))
print("config acc address: " + str(config_acc.pubkey()))
nano_mint = Keypair.from_seed_and_derivation_path(top_seed, f"m/44'/45'/30'/9992'")
print("nano mint address: " + str(nano_mint.pubkey()))

def get_recent_blockhash(rpc: str) -> Hash:
  data="{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getLatestBlockhash\",\"params\":[{\"commitment\":\"processed\"}]}"
  resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
  print(resp.text)
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


def fund_config_account( funder, lamports, recent_blockhash, range ):
    tx = Transaction(recent_blockhash, None, funder.pubkey(),[set_compute_unit_price(3), set_compute_unit_limit(300_000)])
    tx = tx.add(create_account(CreateAccountParams(from_pubkey=funder.pubkey(), to_pubkey=config_acc.pubkey(), 
                                                   lamports=lamports+range, space=16, owner=NANO_TOKEN_ID)))
    zero = 0
    data = zero.to_bytes(length=8, byteorder="little", signed=False) # 0 discrim
    keys = [
        AccountMeta(pubkey=config_acc.pubkey(), is_signer=False, is_writable=True ),
        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False ),
        AccountMeta(pubkey=funder.pubkey(), is_signer=False, is_writable=False)
    ]
    insn = Instruction(accounts=keys, program_id=NANO_TOKEN_ID, data=data)
    tx = tx.add(insn)
    tx.sign( funder, config_acc )
    return tx

def fund_nano_mint_account( funder, lamports, recent_blockhash, range ):
    tx = Transaction(recent_blockhash, None, funder.pubkey(),[set_compute_unit_price(100), set_compute_unit_limit(300_000)])
    tx = tx.add(create_account(CreateAccountParams(from_pubkey=funder.pubkey(), to_pubkey=nano_mint.pubkey(), 
                                                   lamports=lamports+range, space=64, owner=NANO_TOKEN_ID)))
    one   = 1 
    dec   = 9
    data1 = one.to_bytes(length=8, byteorder="little", signed=False) # 0 discrim
    data2 = bytes(funder.pubkey())
    data3 = dec.to_bytes(length=8, byteorder="little", signed=False)
    data  = data1 + data2 + data3
    keys  = [ 
        AccountMeta(pubkey=nano_mint.pubkey(),  is_signer=False, is_writable=True),
        AccountMeta(pubkey=config_acc.pubkey(), is_signer=False, is_writable=True),
        AccountMeta(pubkey=SYS_PROGRAM_ID,      is_signer=False, is_writable=False),
        AccountMeta(pubkey=funder.pubkey(),     is_signer=False, is_writable=True)
    ]

    insn = Instruction(accounts=keys, program_id=NANO_TOKEN_ID, data=data)
    tx = tx.add(insn)
    tx.sign( funder, nano_mint )
    return tx


def fund_token_account(funder, lamports, recent_blockhash, is_print, range ):
    tx = Transaction(recent_blockhash, None, funder.pubkey(),[set_compute_unit_price(random.randint(1,8)), set_compute_unit_limit(200_000)])
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


def create_accounts_tx(funder, lamports, recent_blockhash, txn_type, accs):
    cu_limit = 200_000
    if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER:
      cu_limit = 15_000
    tx = Transaction(recent_blockhash, None, funder.pubkey(), [set_compute_unit_price(10), set_compute_unit_limit(cu_limit)])
    for acc in accs:

        tx = tx.add(transfer(TransferParams(from_pubkey=funder.pubkey(), to_pubkey=acc.pubkey(), lamports=lamports)))
        # Regular Token Program Setup ******************************************
        if txn_type == TXN_TYPE_TOKEN_TRANSFER:
            tx = tx.add(create_associated_token_account(payer=funder.pubkey(), owner=acc.pubkey(), mint=fd_mint.pubkey()))
            ata = get_associated_token_address(acc.pubkey(), fd_mint.pubkey())
            tx = tx.add( mint_to( MintToParams( mint=fd_mint.pubkey(), 
                                                dest=ata, 
                                                mint_authority=funder.pubkey(), 
                                                amount=100,
                                                program_id=TOKEN_PROGRAM_ID, 
                                                signers=[funder.pubkey()] ) ) )
      
        # Nano Token Program Setup *********************************************
        if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER:
            # Create nano token ATA
            rent =  Rent.default().minimum_balance(56)
           
            # First derive the token address using the mint id and the account pubkey
            zero   = 1
            seeds1 = zero.to_bytes(8, byteorder="little", signed=False) # mint
            seeds2 = bytes(acc.pubkey()) # owner
            seeds  = [seeds2, seeds1]
            nano_ata, nano_ata_bump = Pubkey.find_program_address( seeds=seeds, program_id=NANO_TOKEN_ID )
            # data sz = owner + mint + bump (32 + 8 + 8 = 48) + 8 = 56
            tag   = 2
            data1 = tag.to_bytes(8, byteorder="little", signed=False) 
            data2 = bytes(acc.pubkey())
            data3 = seeds1
            data4 = nano_ata_bump.to_bytes(8, byteorder="little", signed=False)
            data  = data1 + data2 + data3 + data4
            keys  = [
              AccountMeta( pubkey=nano_ata,            is_signer=False, is_writable=True  ),
              AccountMeta( pubkey=config_acc.pubkey(),          is_signer=False, is_writable=True  ),
              AccountMeta( pubkey=SYS_PROGRAM_ID,      is_signer=False, is_writable=False ),
              AccountMeta( pubkey=funder.pubkey(),     is_signer=True,  is_writable=True  )
            ]
            insn = Instruction(accounts=keys, program_id=NANO_TOKEN_ID, data=data)
            tx.add(insn)

            # mint to the token account
            tag  = 4
            amt  = 100000
            # 8 + (amount 8)
            data1 = tag.to_bytes(8, byteorder="little", signed=False)
            data2 = amt.to_bytes(8, byteorder="little", signed=False)
            data = data1 + data2
            keys = [
              AccountMeta( pubkey=nano_ata,           is_signer=False, is_writable=True ),
              AccountMeta( pubkey=nano_mint.pubkey(), is_signer=False, is_writable=True ),
              AccountMeta( pubkey=funder.pubkey(),    is_signer=True,  is_writable=False )
            ]
            insn = Instruction(accounts=keys, program_id=NANO_TOKEN_ID, data=data)
            tx.add(insn)
    tx.sign(funder) 
    return tx

def get_balance_sufficient(lamports, rpc: str, acc):
    bal = get_balance(rpc, acc.pubkey())
    if bal:
        print("SUFF BAL:", acc.pubkey(), bal)

    if bal >= lamports:
        return acc
    return None

def create_accounts(funder, rpc, num_accs, lamports, seed, sock, tpus, txn_type):
    get_account_info(rpc, fd_mint.pubkey())
    print(get_balance( rpc, Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")))

    accs = []
    for i in tqdm.trange(num_accs, desc="keypairs"):
        acc = Keypair.from_seed_and_derivation_path(seed, f"m/44'/75'/{351+txn_type}'/{i}'")
        accs.append(acc)
    remaining_accs = set(accs)

    chunk_size = 4
    rem_accs_list = list(remaining_accs)
    acc_chunks = [rem_accs_list[i:i+chunk_size] for i in range(0, len(rem_accs_list), chunk_size) ]

    recent_blockhash = get_recent_blockhash(rpc)
    # send_round_of_txs([create_accounts_tx(funder, lamports, recent_blockhash, txn_type, acc_chunks[0])], sock, tpus)
    # exit(1)
    txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash, txn_type), desc="fund accounts", n_jobs=32)
    send_round_of_txs(txs, sock, tpus)

    if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER and not get_account_info(rpc, config_acc.pubkey()):
        recent_blockhash = get_recent_blockhash(rpc)
        fund_config_account(funder, lamports, recent_blockhash, 0)
        txs = pqdm([i for i in range(10)], partial(fund_config_account, funder, lamports, recent_blockhash), desc="fund config", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

    if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER and not get_account_info(rpc, nano_mint.pubkey()):
        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm([i for i in range(10)], partial(fund_nano_mint_account, funder, lamports, recent_blockhash), desc="fund mint", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

    if txn_type == TXN_TYPE_TOKEN_TRANSFER and not get_account_info(rpc, fd_mint.pubkey()):
        recent_blockhash = get_recent_blockhash(rpc)
        txs = pqdm([i for i in range(10)], partial(fund_token_account, funder, lamports, recent_blockhash, 0), desc="fund token", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

    while len(remaining_accs) > 0:
        print("MINT:", fd_mint.pubkey())
        get_account_info(rpc, fd_mint.pubkey())

        done_accs = pqdm(remaining_accs, partial(get_balance_sufficient, lamports/2, rpc), desc="check bal", n_jobs=32)

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
        txs = pqdm(acc_chunks, partial(create_accounts_tx, funder, lamports, recent_blockhash, txn_type), desc="fund accounts", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)

        if txn_type == TXN_TYPE_TOKEN_TRANSFER and not get_account_info(rpc, fd_mint.pubkey()):
            recent_blockhash = get_recent_blockhash(rpc)
            txs = pqdm([i for i in range(100)], partial(fund_token_account, funder, lamports, recent_blockhash, 0), desc="fund token", n_jobs=32)
            send_round_of_txs(txs, sock, tpus)

        if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER and not get_account_info(rpc, config_acc.pubkey()):
            recent_blockhash = get_recent_blockhash(rpc)
            txs = pqdm([i for i in range(100)], partial(fund_config_account, funder, lamports, recent_blockhash), desc="fund config", n_jobs=32)
            send_round_of_txs(txs, sock, tpus) 

        if txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER and not get_account_info(rpc, nano_mint.pubkey()):
            recent_blockhash = get_recent_blockhash(rpc)
            txs = pqdm([i for i in range(100)], partial(fund_nano_mint_account, funder, lamports, recent_blockhash), desc="fund mint", n_jobs=32)
            send_round_of_txs(txs, sock, tpus)

        time.sleep(0.1)

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
  tx = Transaction(recent_blockhash, None, acc, [set_compute_unit_price(cu_price), set_compute_unit_limit(4374+300)] )
  ata = get_associated_token_address(key.pubkey(), fd_mint.pubkey())
  params = SplTransferParams( program_id=TOKEN_PROGRAM_ID,
                              source=ata,
                              dest=ata, 
                              owner=key.pubkey(),
                              amount=1 )
  tx = tx.add( spl_transfer(params) )
  tx.sign(key)
  return tx

def gen_tx_nano_token_transfer(recent_blockhash, src_key, dst_key, src_acc, dst_acc, cu_price):
  tx = Transaction(recent_blockhash, None, src_acc, [set_compute_unit_limit(150+48)] )

  # Derive the nano token address associated with the account. Derive the token
  # address using the mint id (0), the nano token program id, and the account pubkey
  zero   = 1
  seeds1 = zero.to_bytes(8, byteorder="little", signed=False) # mint
  src_seeds2 = bytes(src_acc) # owner
  dst_seeds2 = bytes(dst_acc) # owner
  src_seeds  = [src_seeds2, seeds1]
  dst_seeds  = [dst_seeds2, seeds1]
  src_nano_ata, _ = Pubkey.find_program_address( seeds=src_seeds, program_id=NANO_TOKEN_ID )
  dst_nano_ata, _ = Pubkey.find_program_address( seeds=dst_seeds, program_id=NANO_TOKEN_ID )

  # Construct the instruction data 
  tag   = 6 # Transfer discriminant
  amt   = 1 # Token `transfer` amount
  # data1 = tag.to_bytes(8, byteorder="little", signed=False)
  data2 = amt.to_bytes(8, byteorder="little", signed=False)
  data  =  data2
  keys = [
    AccountMeta( pubkey=src_nano_ata,     is_signer=False, is_writable=True ),
    AccountMeta( pubkey=dst_nano_ata,     is_signer=False, is_writable=True ),
    AccountMeta( pubkey=src_acc, is_signer=True, is_writable=False )
  ]

  insn = Instruction( program_id=NANO_TOKEN_ID, accounts=keys, data=data )
  tx = tx.add( insn )
  tx.sign( src_key )

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
      elif txn_type == TXN_TYPE_NANO_TOKEN_TRANSFER:
        j = (i + (len(keys) // 2)) % len(keys)
        tx = gen_tx_nano_token_transfer(recent_blockhash, keys[i], keys[j], accs[i], accs[j], cu_price)
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
  elif args.txn_type == "nano-token-transfer":
    txn_type = TXN_TYPE_NANO_TOKEN_TRANSFER
  else:
    print("unknown txn type")
    exit(1)

  accs = create_accounts(funder, args.rpc, args.nkeys, 10_000_000, seed, sock, tpus, txn_type)
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
