from solders.message import Message
from solders.keypair import Keypair
# from solders.instruction import Instruction
# from solders.hash import Hash
from solana.transaction import Transaction
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey

import socket
import time
import tqdm
import itertools
from multiprocessing import Pool, TimeoutError
from functools import partial
from pqdm.processes import pqdm

from solana.rpc.api import Client
from solana.rpc.types import TxOpts
import random

def send_round_of_txs(txs, sock, tpus):
    for tx in tqdm.tqdm(txs, desc="send"):
        message = bytes(tx.to_solders())
        for tpu in tpus:
            sock.sendto(message, tpu)

def create_account_tx(lamports, recent_blockhash, acc):
    client = Client("http://127.0.0.1:8899")
    tx = Transaction(recent_blockhash, None, funder.pubkey(), []).add(
        transfer(TransferParams(from_pubkey=funder.pubkey(), to_pubkey=acc.pubkey(), lamports=lamports)))
    tx.sign(funder)
    return tx
    # client.send_transaction(tx, funder, opts=TxOpts(skip_confirmation=True))

def get_balance(lamports, client: Client, acc):
    bal = client.get_balance(acc.pubkey()).value
    if bal >= lamports/2:
        return acc
    else:
        return None

def create_accounts(funder, client: Client, num_accs, lamports, seed, sock, tpus):
    rng = random.Random(seed)
    accs = []
    for _ in tqdm.trange(num_accs, desc="keypairs"):
        acc = Keypair.from_seed(bytes([rng.randint(0, 255) for _ in range(0, 32)]))
        accs.append(acc)
    remaining_accs = set(accs)

    while len(remaining_accs) > 0:
        done_accs = pqdm(remaining_accs, partial(get_balance, lamports, client), desc="check bal", n_jobs=32)
           
        for acc in done_accs:
            if acc is not None:
                remaining_accs.remove(acc)
        print(len(remaining_accs))
        if len(remaining_accs) == 0:
            break
        recent_blockhash = client.get_latest_blockhash().value.blockhash
        txs = pqdm(remaining_accs, partial(create_account_tx, lamports, recent_blockhash), desc="fund accounts", n_jobs=32)
        send_round_of_txs(txs, sock, tpus)
        time.sleep(10)

    return accs

def gen_tx(recent_blockhash, acc):
    tx = Transaction(recent_blockhash, None, acc.pubkey(), [])
    tx.sign(acc)
    return tx

def gen_round_of_txs(accs, client, mults):
    txs = []
    recent_blockhash = client.get_latest_blockhash().value.blockhash
    txs = pqdm(accs, partial(gen_tx, recent_blockhash), desc="gen", n_jobs=32)
    return txs

f = open('../test-ledger/faucet-keypair.json', 'r' )
b = f.read()
funder = Keypair.from_json(b)
client = Client("http://127.0.0.1:8899")

tpus = [("103.219.170.91", 9001), ("103.219.170.91", 8102)]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

accs = create_accounts(funder, client, 100000, 10_000_000, 42, sock, tpus)
time.sleep(1)

while True:
    txs = gen_round_of_txs(accs, client, 10)
    send_round_of_txs(txs, sock, tpus)